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

/// An end-to-end migration proving scenario, built fluently: [`Scenario::funded`] sets the source
/// note, the `expect_*` setters declare the observable outcomes, and [`Scenario::prove_end_to_end`]
/// funds a real wallet, runs the whole migration, and asserts those outcomes phase by phase. Each new
/// balance or note shape is a new builder in the test below.
struct Scenario {
    label: &'static str,
    funding: Zatoshis,
    expected_preparations: usize,
    expected_transfers: usize,
    expected_migrated: Zatoshis,
}

impl Scenario {
    /// Starts a scenario whose account is funded with a single Orchard note worth `funding`.
    fn funded(label: &'static str, funding: Zatoshis) -> Self {
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
    /// Phase 1 (setup): builds an NU6.3 wallet, funds the account with the scenario's single Orchard
    /// note, and completes the note's shard so an anchor is available at the tip.
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

        let (fund_height, _, _) =
            st.generate_next_block(&fvk, AddressType::DefaultExternal, scenario.funding);
        st.scan_cached_blocks(fund_height, 1);
        assert_eq!(
            st.get_total_balance(account_id),
            scenario.funding,
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
    /// transfer, extracts it, and asserts both its Orchard and Ironwood bundles verify.
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
            assert!(
                tx.ironwood_bundle().is_some(),
                "the transfer has an Ironwood bundle"
            );
        }
    }
}

#[test]
fn migration_proves_end_to_end_against_a_funded_wallet() {
    // 78 ZEC decomposes into ten canonical crossings and migrates 77.99 ZEC (the balance less the
    // reserved transfer buffers and preparation fee, leaving 0.0077 ZEC of source-pool change) via a
    // single preparation transaction.
    Scenario::funded(
        "78 ZEC in a single note",
        Zatoshis::const_from_u64(78 * COIN),
    )
    .expect_preparations(1)
    .expect_transfers(10)
    .expect_migrated(Zatoshis::const_from_u64(7_799 * (COIN / 100)))
    .prove_end_to_end();
}
