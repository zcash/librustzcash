//! End-to-end, real-proving chain simulation of a whole migration over a genuine wallet.
//!
//! This drives a real (in-memory) `zcash_client_sqlite` `WalletDb` through the
//! `zcash_client_backend` testing framework, exercising the migration engine's proving path against
//! the wallet's OWN Orchard commitment tree instead of a hand-built one:
//!
//! 1. fund an account with a spendable Orchard note and commit a migration over the
//!    [`WalletMigration`] adapter (so the plan, the prep transactions, and the transfers all come
//!    from the real wallet);
//! 2. prove each PREPARATION transaction against the chain tip (installing the source anchor and its
//!    spends' witnesses through the PCZT `Updater` role), extract it, mine it, and scan it — so its
//!    minted funding notes become genuinely scanned received notes with real tree positions;
//! 3. advance the chain to each TRANSFER's drawn anchor boundary and prove it (resolving the funding
//!    note's witness from the wallet's tree by the nullifier its spend reveals), extract it, and
//!    assert both its Orchard and Ironwood bundles verify.
//!
//! [`WalletMigrationProver`] resolves every spend's tree position from the wallet's own note store
//! (no hand-supplied map), so this test also covers that production lookup path. It keeps each
//! transfer's boundary within `zcash_client_sqlite`'s checkpoint pruning window (100 blocks of the
//! tip), so it needs no migration anchor-checkpoint retention, which is a wallet backend concern
//! out of the migration crate's control.
#![cfg(all(feature = "wallet", feature = "test-dependencies"))]

use std::convert::Infallible;

use rand_chacha::ChaCha8Rng;
use rand_core::SeedableRng;

use pczt::roles::tx_extractor::TransactionExtractor;

use zcash_client_backend::data_api::testing::{
    AddressType, TestBuilder, TestState, orchard::OrchardPoolTester, pool::ShieldedPoolTester,
};
use zcash_client_backend::data_api::{Account, WalletRead};
// The wallet, block cache, DB factory, and Orchard-checkpoint helper come from
// `zcash_client_sqlite`'s own test harness, exposed under its `test-dependencies` feature.
use zcash_client_sqlite::testing::db::{TestDb, TestDbFactory};
use zcash_client_sqlite::testing::{BlockCache, highest_rooted_orchard_checkpoint};
use zcash_keys::keys::UnifiedSpendingKey;

use zcash_primitives::block::BlockHash;
use zcash_protocol::consensus::BlockHeight;
use zcash_protocol::local_consensus::LocalNetwork;
use zcash_protocol::value::testing::zats;
use zcash_protocol::value::{COIN, Zatoshis};

use zcash_pool_migration_backend::engine::{
    self, MigrationState, MigrationTxId, MigrationTxKind, MigrationTxState, PoolMigrationRead,
    PoolMigrationWrite,
};
use zcash_pool_migration_backend::wallet::{WalletMigration, WalletMigrationProver};

/// Every network upgrade (through NU6.3, which activates the Ironwood pool) is active from this
/// height, so a migration built at or above it is post-NU6.3 and its transfers cross into Ironwood.
const ACTIVATION: u32 = 100_000;
/// Empty blocks scanned after a note is received so its commitment-tree shard completes and an
/// anchor at that height is available.
const SHARD_COMPLETION_BLOCKS: usize = 5;

/// A network with every upgrade through NU6.3 active at [`ACTIVATION`].
fn nu63_network() -> LocalNetwork {
    let h = BlockHeight::from_u32(ACTIVATION);
    LocalNetwork {
        nu6: Some(h),
        nu6_1: Some(h),
        nu6_2: Some(h),
        nu6_3: Some(h),
        ..TestBuilder::<(), ()>::DEFAULT_NETWORK
    }
}

/// A trivial in-memory migration store for the [`WalletMigration`] adapter. The chain simulation
/// drives proving through the engine's free functions (which mutate the in-memory
/// [`MigrationState`] directly), so only `replace_migration` (used by commit) is exercised.
#[derive(Default)]
struct MigrationTestStore {
    state: Option<MigrationState>,
}

impl PoolMigrationRead for MigrationTestStore {
    type Error = Infallible;

    fn get_migration(&self) -> Result<Option<MigrationState>, Self::Error> {
        Ok(self.state.clone())
    }
}

impl PoolMigrationWrite for MigrationTestStore {
    fn replace_migration(&mut self, state: &MigrationState) -> Result<(), Self::Error> {
        self.state = Some(state.clone());
        Ok(())
    }

    fn update_transaction(
        &mut self,
        _id: MigrationTxId,
        _state: MigrationTxState,
    ) -> Result<(), Self::Error> {
        // Not exercised: the chain simulation advances proving state through the engine's
        // `prove_preparation` / `prove_transfer` on the in-memory `MigrationState`, not the store.
        Ok(())
    }
}

/// An end-to-end migration proving scenario, built fluently: [`Scenario::funded`] /
/// [`Scenario::funded_notes`] set the source note shape, the `expect_*` setters declare the
/// observable outcomes, and [`Scenario::prove_end_to_end`] funds a real wallet, runs the whole
/// migration, and asserts those outcomes phase by phase. Each new balance or note shape is a new
/// builder in the test below.
struct Scenario {
    label: &'static str,
    funding: Vec<Zatoshis>,
    expected_preparations: usize,
    expected_transfers: usize,
    expected_migrated: Zatoshis,
}

impl Scenario {
    /// Starts a scenario whose account is funded with a single Orchard note worth `funding`.
    fn funded(label: &'static str, funding: Zatoshis) -> Self {
        Self::funded_notes(label, vec![funding])
    }

    /// Starts a scenario whose account is funded with several source Orchard notes (the "exchange" /
    /// dusty shapes whose consolidation drives multi-layer preparation).
    fn funded_notes(label: &'static str, funding: Vec<Zatoshis>) -> Self {
        Self {
            label,
            funding,
            expected_preparations: 0,
            expected_transfers: 0,
            expected_migrated: Zatoshis::ZERO,
        }
    }

    /// Declares the number of preparation transactions the migration should produce.
    fn expect_preparations(mut self, n: usize) -> Self {
        self.expected_preparations = n;
        self
    }

    /// Declares the number of pool-crossing transfers (one per prepared funding note).
    fn expect_transfers(mut self, n: usize) -> Self {
        self.expected_transfers = n;
        self
    }

    /// Declares the total value that should cross into Ironwood (the sum of the crossings).
    fn expect_migrated(mut self, migrated: Zatoshis) -> Self {
        self.expected_migrated = migrated;
        self
    }

    /// Runs the whole migration for this scenario, phase by phase, asserting every declared
    /// expectation as it goes: setup, plan-and-commit, prove-preparations, prove-transfers.
    fn prove_end_to_end(self) {
        let mut run = Run::setup(&self);
        let mut committed = run.plan_and_commit(&self);
        run.prove_preparations(&mut committed, &self);
        run.prove_transfers(&mut committed, &self);
    }
}

/// The running harness of one [`Scenario`]: a funded wallet plus the account identity, carried
/// across the proving phases.
struct Run {
    network: LocalNetwork,
    st: TestState<BlockCache, TestDb, LocalNetwork>,
    account_id: <TestDb as WalletRead>::AccountId,
    usk: UnifiedSpendingKey,
    fvk: <OrchardPoolTester as ShieldedPoolTester>::Fvk,
}

/// The committed migration produced by [`Run::plan_and_commit`] and advanced by the proving phases,
/// with the planned amounts those phases hold the real chain state to.
struct Committed {
    state: MigrationState,
    funding_notes: Vec<Zatoshis>,
    change: u64,
}

impl Run {
    /// Phase 1 (setup): builds an NU6.3 wallet, funds the account with the scenario's source Orchard
    /// notes (one per block), and completes their shards so an anchor is available at the tip.
    fn setup(scenario: &Scenario) -> Self {
        let network = nu63_network();

        let mut st = TestBuilder::new()
            .with_network(network)
            .with_data_store_factory(TestDbFactory::default())
            .with_block_cache(BlockCache::new())
            .with_account_from_sapling_activation(BlockHash([0; 32]))
            .build();

        let account = st.test_account().cloned().expect("the test account exists");
        let account_id = account.id();
        let usk = account.usk().clone();
        let fvk = OrchardPoolTester::test_account_fvk(&st);

        for &note in &scenario.funding {
            let (h, _, _) = st.generate_next_block(&fvk, AddressType::DefaultExternal, note);
            st.scan_cached_blocks(h, 1);
        }
        let funded_total: Zatoshis = scenario
            .funding
            .iter()
            .copied()
            .sum::<Option<Zatoshis>>()
            .expect("the funded total is a valid amount");
        assert_eq!(
            st.get_total_balance(account_id),
            funded_total,
            "{}: funded balance",
            scenario.label
        );
        for _ in 0..SHARD_COMPLETION_BLOCKS {
            let (h, _) = st.generate_empty_block();
            st.scan_cached_blocks(h, 1);
        }

        Self {
            network,
            st,
            account_id,
            usk,
            fvk,
        }
    }

    /// Phase 2 (plan and commit): plans and commits the migration over the wallet adapter (its plan,
    /// preparations, and transfers all drawn from the real wallet's notes), checks the planned
    /// funding-note count and migrated value against the scenario, and returns the committed
    /// migration (every transaction Signed, with anchors and witnesses deferred).
    fn plan_and_commit(&mut self, scenario: &Scenario) -> Committed {
        let tip = self
            .st
            .wallet()
            .chain_height()
            .expect("reads the chain height")
            .expect("the wallet has a chain tip");
        let mut rng = ChaCha8Rng::seed_from_u64(0);
        let (state, funding_notes, migrated, change) = {
            let adapter = WalletMigration::new(
                self.st.wallet(),
                self.account_id,
                self.usk.clone(),
                MigrationTestStore::default(),
            );
            let plan = engine::plan_migration(&self.network, &adapter, &mut rng)
                .expect("plans the migration");
            let funding_notes = plan.funding_notes();
            let migrated = plan.note_split().total_migratable();
            let change = plan.note_split().change().map(u64::from).unwrap_or(0);
            let mut adapter = adapter;
            let (state, _) = engine::commit_preparation_with_funding(
                &self.network,
                tip,
                &mut adapter,
                &plan,
                &mut rng,
            )
            .expect("commits the migration");
            (state, funding_notes, migrated, change)
        };

        // The observable amounts match what this balance is expected to migrate: one funding note
        // (and one transfer) per crossing denomination, and the whole value carried into Ironwood.
        assert_eq!(
            funding_notes.len(),
            scenario.expected_transfers,
            "{}: prepared funding notes",
            scenario.label
        );
        assert_eq!(
            migrated, scenario.expected_migrated,
            "{}: total migrated value",
            scenario.label
        );
        for tx in state.transactions() {
            assert!(matches!(tx.state(), MigrationTxState::Signed));
        }

        Committed {
            state,
            funding_notes,
            change,
        }
    }

    /// Phase 3 (prove preparations): proves each preparation against the current tip, extracts it
    /// (asserting it is Orchard-only), then mines and scans it so its minted funding notes become
    /// spendable; finally checks the wallet balance is the funding less the reserved preparation fees.
    fn prove_preparations(&mut self, committed: &mut Committed, scenario: &Scenario) {
        let prep_ids: Vec<MigrationTxId> = committed
            .state
            .transactions()
            .iter()
            .filter(|t| matches!(t.kind(), MigrationTxKind::Preparation { .. }))
            .map(|t| t.id())
            .collect();
        assert_eq!(
            prep_ids.len(),
            scenario.expected_preparations,
            "{}: preparation transactions",
            scenario.label
        );

        for prep_id in prep_ids {
            let tip = self
                .st
                .wallet()
                .chain_height()
                .expect("reads the chain height")
                .expect("the wallet has a chain tip");
            let anchor = highest_rooted_orchard_checkpoint(self.st.wallet_mut(), tip)
                .expect("a rooted Orchard checkpoint exists");
            {
                let mut prover = WalletMigrationProver::new(
                    self.st.wallet_mut(),
                    self.account_id,
                    self.fvk.clone(),
                );
                engine::prove_preparation(&mut prover, &mut committed.state, prep_id, anchor)
                    .expect("proves the preparation transaction");
            }
            let proven = committed
                .state
                .transactions()
                .iter()
                .find(|t| t.id() == prep_id)
                .expect("the preparation transaction is present");
            assert!(matches!(proven.state(), MigrationTxState::Proved));
            let tx = TransactionExtractor::new(
                pczt::Pczt::parse(proven.pczt()).expect("parses the proven preparation PCZT"),
            )
            .extract()
            .expect("extracts and verifies the preparation transaction");
            // A preparation transaction is Orchard-only: no Ironwood bundle.
            assert!(
                tx.orchard_bundle().is_some(),
                "the preparation has an Orchard bundle"
            );
            assert!(
                tx.ironwood_bundle().is_none(),
                "the preparation has no Ironwood bundle"
            );

            let (prep_height, _) = self.st.generate_next_block_from_tx(1, &tx);
            self.st.scan_cached_blocks(prep_height, 1);
        }

        let funding_notes_total: u64 = committed.funding_notes.iter().map(|&v| u64::from(v)).sum();
        assert_eq!(
            self.st.get_total_balance(self.account_id),
            Zatoshis::from_u64(funding_notes_total + committed.change).expect("a valid balance"),
            "{}: balance after preparations",
            scenario.label
        );
    }

    /// Phase 4 (prove transfers): advances the chain to each transfer's drawn anchor boundary (so
    /// that checkpoint is settled and holds the funding note, within the pruning window), proves the
    /// transfer, extracts it, and asserts both its Orchard and Ironwood bundles verify. Finally
    /// checks the destination pool: the migration created exactly one Ironwood note per transfer,
    /// together holding the whole migrated value.
    fn prove_transfers(&mut self, committed: &mut Committed, scenario: &Scenario) {
        let mut transfers: Vec<(MigrationTxId, BlockHeight)> = committed
            .state
            .transactions()
            .iter()
            .filter(|t| matches!(t.kind(), MigrationTxKind::Transfer { .. }))
            .map(|t| {
                (
                    t.id(),
                    t.anchor_boundary()
                        .expect("a transfer carries a drawn boundary"),
                )
            })
            .collect();
        transfers.sort_by_key(|(_, boundary)| *boundary);
        assert_eq!(
            transfers.len(),
            scenario.expected_transfers,
            "{}: transfers",
            scenario.label
        );

        // The Ironwood output note each transfer creates, collected to check the destination pool.
        let mut ironwood_notes: Vec<Zatoshis> = Vec::new();

        for (transfer_id, boundary) in transfers {
            loop {
                let tip = self
                    .st
                    .wallet()
                    .chain_height()
                    .expect("reads the chain height")
                    .expect("the wallet has a chain tip");
                if tip > boundary {
                    break;
                }
                let (h, _) = self.st.generate_empty_block();
                self.st.scan_cached_blocks(h, 1);
            }

            {
                let mut prover = WalletMigrationProver::new(
                    self.st.wallet_mut(),
                    self.account_id,
                    self.fvk.clone(),
                );
                engine::prove_transfer(&mut prover, &mut committed.state, transfer_id)
                    .expect("proves the transfer against its drawn boundary");
            }
            let proven = committed
                .state
                .transactions()
                .iter()
                .find(|t| t.id() == transfer_id)
                .expect("the transfer is present");
            assert!(matches!(proven.state(), MigrationTxState::Proved));
            let tx = TransactionExtractor::new(
                pczt::Pczt::parse(proven.pczt()).expect("parses the proven transfer PCZT"),
            )
            .extract()
            .expect("extracts and verifies the transfer's Orchard and Ironwood proofs");
            assert!(
                tx.orchard_bundle().is_some(),
                "the transfer has an Orchard bundle"
            );
            let ironwood = tx
                .ironwood_bundle()
                .expect("the transfer has an Ironwood bundle");
            // A transfer creates exactly one Ironwood output: the migrated crossing note. Its value
            // is the magnitude of the (output-only) bundle's value balance.
            assert_eq!(
                ironwood.actions().len(),
                1,
                "{}: Ironwood outputs per transfer",
                scenario.label
            );
            ironwood_notes.push(
                Zatoshis::from_u64(i64::from(ironwood.value_balance()).unsigned_abs())
                    .expect("a valid Ironwood note value"),
            );
        }

        // The destination pool holds exactly one Ironwood note per crossing, together carrying the
        // whole migrated value.
        assert_eq!(
            ironwood_notes.len(),
            scenario.expected_transfers,
            "{}: Ironwood notes",
            scenario.label
        );
        let ironwood_total: u64 = ironwood_notes.iter().map(|&v| u64::from(v)).sum();
        assert_eq!(
            Zatoshis::from_u64(ironwood_total).expect("a valid balance"),
            scenario.expected_migrated,
            "{}: Ironwood balance",
            scenario.label
        );
    }
}

/// Every proving scenario, spanning the migration personas exercised across the codebase (the Python
/// integration-test suite and the note-split golden vectors): single small / medium / large
/// balances, the minimum-denomination and buffer-pruned edges, and the many-note "exchange" / dust /
/// whale shapes whose consolidation drives multi-layer preparation.
fn scenarios() -> Vec<Scenario> {
    // 0.02 ZEC dust notes.
    let dust = zats(COIN / 50);
    let dust_heavy: Vec<Zatoshis> = std::iter::once(zats(COIN))
        .chain(std::iter::repeat(dust).take(12))
        .collect();
    // The migrated total is the balance less the reserved transfer buffers and preparation fees, so
    // it is a multiple of the 0.01-ZEC minimum denomination; expressed here in hundredths of a ZEC.
    let hundredths = COIN / 100;
    vec![
        // Single-note balances.
        Scenario::funded("small holder, 2 ZEC", zats(2 * COIN))
            .expect_preparations(1)
            .expect_transfers(7)
            .expect_migrated(zats(199 * hundredths)),
        Scenario::funded("retail, 15 ZEC", zats(15 * COIN))
            .expect_preparations(1)
            .expect_transfers(9)
            .expect_migrated(zats(1_499 * hundredths)),
        Scenario::funded("denominations, 60 ZEC", zats(60 * COIN))
            .expect_preparations(1)
            .expect_transfers(10)
            .expect_migrated(zats(5_999 * hundredths)),
        Scenario::funded("78 ZEC in a single note", zats(78 * COIN))
            .expect_preparations(1)
            .expect_transfers(10)
            .expect_migrated(zats(7_799 * hundredths)),
        Scenario::funded(
            "Gwen, 0.0152 ZEC (a single minimum-denomination note)",
            zats(1_520_000),
        )
        .expect_preparations(1)
        .expect_transfers(1)
        .expect_migrated(zats(hundredths)),
        Scenario::funded(
            "Priya, 7.1101 ZEC (the buffer prunes the trailing crossing)",
            zats(711_010_000),
        )
        .expect_preparations(1)
        .expect_transfers(3)
        .expect_migrated(zats(710 * hundredths)),
        // Many-note shapes, consolidated across preparation layers.
        Scenario::funded_notes("exchange, ten 5 ZEC notes", vec![zats(5 * COIN); 10])
            .expect_preparations(2)
            .expect_transfers(3)
            .expect_migrated(zats(4_500 * hundredths)),
        Scenario::funded_notes("monotonic, ten 12 ZEC notes", vec![zats(12 * COIN); 10])
            .expect_preparations(5)
            .expect_transfers(11)
            .expect_migrated(zats(11_999 * hundredths)),
        Scenario::funded_notes("dust-heavy, 1 ZEC and twelve 0.02 ZEC notes", dust_heavy)
            .expect_preparations(4)
            .expect_transfers(4)
            .expect_migrated(zats(123 * hundredths)),
        Scenario::funded_notes(
            "whale plus dust, 40 ZEC and a six-note dust tail",
            vec![
                zats(40 * COIN),
                zats(COIN / 50),
                zats(COIN / 50),
                zats(COIN / 20),
                zats(COIN / 20),
                zats(COIN / 10),
                zats(COIN / 10),
            ],
        )
        .expect_preparations(4)
        .expect_transfers(6)
        .expect_migrated(zats(4_033 * hundredths)),
    ]
}

#[test]
fn migration_proves_end_to_end_against_a_funded_wallet() {
    for scenario in scenarios() {
        scenario.prove_end_to_end();
    }
}
