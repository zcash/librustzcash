//! End-to-end, real-proving chain simulation of a whole migration over a genuine wallet.
//!
//! This drives a real (in-memory) [`WalletDb`] through the `zcash_client_backend` testing
//! framework, exercising the `zcash_pool_migration` engine against the wallet's OWN Orchard
//! commitment tree and its OWN pool-migration store instead of hand-built stand-ins:
//!
//! 1. fund an account with spendable Orchard notes and commit a migration over the
//!    [`WalletMigration`] adapter (so the plan, the prep transactions, and the transfers all come
//!    from the real wallet), then persist it into [`PoolMigrations`], the SQLite store;
//! 2. drive the committed migration through [`advance_migration`] — the API a consuming
//!    application uses — performing each step it names against the simulated chain: proving
//!    installs the source anchor and its spends' witnesses through the PCZT `Updater` role, and
//!    broadcasting extracts the transaction, mines it, and scans it.
//!
//! Driving through `advance_migration` rather than hand-sequencing the steps is what puts the
//! SQLite satisfiability oracle in the loop: every step is verified against the wallet's live view
//! before it is performed, so a migration whose inputs the wallet has seen spent surfaces as a
//! replan instead of wasted proving work. [`WalletMigrationProver`] resolves every spend's tree
//! position from the wallet's own note store (no hand-supplied map), so this also covers that
//! production lookup path.
//!
//! [`WalletDb`]: zcash_client_sqlite::WalletDb
//! [`PoolMigrations`]: zcash_client_sqlite::pool_migration::orchard_ironwood::PoolMigrations
//! [`advance_migration`]: zcash_pool_migration::satisfiability::advance_migration
#![cfg(all(
    feature = "orchard",
    feature = "pczt-tests",
    feature = "test-dependencies",
    feature = "expensive-tests"
))]

use std::collections::BTreeSet;
use std::convert::Infallible;

use rand_chacha::ChaCha8Rng;
use rand_core::SeedableRng;

use pczt::roles::tx_extractor::TransactionExtractor;

use zcash_client_backend::data_api::locking::{LockOwner, OutputLockStore};
use zcash_client_backend::data_api::testing::{
    AddressType, TestBuilder, TestState, orchard::OrchardPoolTester, pool::ShieldedPoolTester,
};
use zcash_client_backend::data_api::wallet::TargetHeight;
use zcash_client_backend::data_api::wallet::input_selection::{
    LockFilter, LockedInputPolicy, NonEmptyBTreeSet,
};
use zcash_client_backend::data_api::{Account, InputSource, WalletRead, WalletTest};
use zcash_client_backend::wallet::OutputRef;
// The wallet, block cache, DB factory, and Orchard-checkpoint helper come from this crate's own
// test harness, exposed under its `test-dependencies` feature.
use zcash_client_sqlite::pool_migration::orchard_ironwood::PoolMigrations;
use zcash_client_sqlite::testing::db::{TestDb, TestDbFactory};
use zcash_client_sqlite::testing::{BlockCache, highest_rooted_orchard_checkpoint};
use zcash_client_sqlite::util::SystemClock;
use zcash_keys::keys::UnifiedSpendingKey;

use zcash_primitives::block::BlockHash;
use zcash_primitives::transaction::Transaction;
use zcash_protocol::consensus::BlockHeight;
use zcash_protocol::local_consensus::LocalNetwork;
use zcash_protocol::value::testing::zats;
use zcash_protocol::value::{COIN, ZatBalance, Zatoshis};
use zcash_protocol::{PoolType, ShieldedPool, TxId};

use zcash_pool_migration::engine::{
    self, MigrationState, MigrationStatus, MigrationTransferId, MigrationTxKind, MigrationTxState,
    PoolMigrationRead, PoolMigrationWrite,
};
use zcash_pool_migration::satisfiability::{
    self, AdvanceConfig, DuenessTargets, ReorgSettleDepth, ReplanThreshold,
};
use zcash_pool_migration::state::{AdvanceStep, Blocker};
use zcash_pool_migration::wallet::{WalletMigration, WalletMigrationProver, WalletProveError};

/// The drive policy every scenario here uses: a ten-block reorg settle depth, the caller policy
/// the satisfiability oracle judges anchor displacements under.
const ADVANCE: AdvanceConfig = AdvanceConfig::new(ReorgSettleDepth::new(10));

/// A cap on the empty blocks a drive loop will mine waiting for the migration's schedule, so a
/// migration that can never make progress fails the test rather than spinning. The privacy
/// schedule spreads a migration's broadcasts over a few hundred blocks at the ZIP 318 grid.
const MAX_WAITING_BLOCKS: u32 = 5_000;

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

/// The store the [`WalletMigration`] adapter is handed for PLANNING and COMMITTING, holding one
/// migration state in memory.
///
/// The drive itself runs against the real SQLite store ([`PoolMigrations`]); this exists only
/// because the adapter borrows the wallet immutably for its whole lifetime while a `PoolMigrations`
/// over the same wallet database needs that database's connection mutably, and one `TestDb` handle
/// cannot lend both at once. What the adapter actually reads from its store is the COMMIT GUARD's
/// question — is a non-terminal migration already in progress? — so a commit whose guard must see
/// persisted state seeds this with exactly what the SQLite store holds
/// ([`Self::holding`]), and the committed result is written straight back there.
#[derive(Default)]
struct MigrationTestStore {
    state: Option<MigrationState>,
}

impl MigrationTestStore {
    /// A store presenting `state` — what the SQLite store was last read to hold — so the commit
    /// guard is put to the migration a wallet has actually persisted.
    fn holding(state: Option<MigrationState>) -> Self {
        Self { state }
    }
}

impl PoolMigrationRead for MigrationTestStore {
    type Error = Infallible;

    fn get_migration(&self) -> Result<Option<MigrationState>, Self::Error> {
        Ok(self.state.clone())
    }

    fn check_step_satisfiability(
        &self,
        _tx: &engine::MigrationTransaction,
        _settle: satisfiability::ReorgSettleDepth,
    ) -> Result<satisfiability::StepSatisfiability, Self::Error> {
        // Not exercised: this store is only ever handed to the plan-and-commit path, which never
        // consults the oracle. Every drive in this file runs against the SQLite store, whose
        // oracle answers from the wallet's own tables.
        Ok(satisfiability::StepSatisfiability::Satisfiable {
            as_of_height: BlockHeight::from_u32(0),
        })
    }

    /// Not exercised, for the same reason as the oracle above: the drives in this file promote
    /// mined transactions through the SQLite store, which reads the wallet's `transactions` table.
    fn mined_height(&self, _txid: TxId) -> Result<Option<BlockHeight>, Self::Error> {
        Ok(None)
    }
}

impl PoolMigrationWrite for MigrationTestStore {
    fn replace_migration(&mut self, state: &MigrationState) -> Result<(), Self::Error> {
        self.state = Some(state.clone());
        Ok(())
    }

    fn update_transaction(
        &mut self,
        _id: MigrationTransferId,
        _state: MigrationTxState,
    ) -> Result<(), Self::Error> {
        // Not exercised: the commit path replaces the whole migration; per-transaction lifecycle
        // updates all happen against the SQLite store during the drive.
        Ok(())
    }

    /// The contract's no-wallet-tables form; not exercised, for the same reason as
    /// `update_transaction` — every prove in this file discharges its proof through the SQLite
    /// store.
    fn store_proved_transaction(
        &mut self,
        state: &mut MigrationState,
        proven: engine::ProvedTransaction,
    ) -> Result<(), Self::Error> {
        proven.apply(state);
        self.replace_migration(state)
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
    /// Starts a scenario whose account is funded with the given source Orchard notes.
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

    /// Runs the whole migration for this scenario, asserting every declared expectation as it
    /// goes: setup, plan-and-commit, then the drive to completion through `advance_migration`.
    fn prove_end_to_end(self) {
        let mut run = Run::setup(&self);
        let mut committed = run.plan_and_commit(&self);
        run.drive_to_completion(&mut committed, &self);
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

/// [`Run::perform_prove`]'s summary of the engine's `ProveOutcome`, with a successful proof's
/// `ProvedTransaction` already discharged through the store (the engine's own outcome carries the
/// proof by value, so it cannot survive the persistence the helper performs).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProveStepOutcome {
    Proved,
    NotYetProvable,
    MarkedUnsatisfiable {
        #[allow(dead_code)]
        replan_required: bool,
    },
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

    /// The account's pool-migration store, over the wallet database's own connection — the same
    /// borrow an application holding that connection would construct it from, with the wallet
    /// context (parameters and clock) `store_proved_transaction` finalizes under.
    fn store(&mut self) -> PoolMigrations<&mut rusqlite::Connection, LocalNetwork, SystemClock> {
        let params = *self.st.network();
        PoolMigrations::for_account(
            params,
            SystemClock,
            self.st.wallet_mut().conn_mut(),
            self.account_id,
        )
        .expect("the account has a pool-migration store")
    }

    /// Write `state` through to the SQLite store, as a consumer does after performing a step.
    fn persist(&mut self, state: &MigrationState) {
        self.store()
            .replace_migration(state)
            .expect("persists the migration state");
    }

    /// The migration the SQLite store holds, read back through the store's own reader.
    fn stored_migration(&mut self) -> Option<MigrationState> {
        self.store().get_migration().expect("reads the migration")
    }

    /// The height of the next block a transaction could be mined in, which is what
    /// `advance_migration` plans against.
    fn target_height(&self) -> BlockHeight {
        self.st
            .wallet()
            .chain_height()
            .expect("reads the chain height")
            .expect("the wallet has a chain tip")
            + 1
    }

    /// The dueness targets the simulation drives at. The simulated wallet scans every block it
    /// mines, so its chain view IS its scanned frontier and the pair is degenerate: these
    /// scenarios exercise the migration flow, not the estimate/scan divergence (the kernel's own
    /// tests cover that).
    fn targets(&self) -> DuenessTargets {
        DuenessTargets::at(self.target_height())
    }

    /// Ask `advance_migration` for the next step, against the SQLite store and the simulated
    /// chain's current tip.
    fn advance(&mut self, state: &mut MigrationState) -> AdvanceStep {
        let targets = self.targets();
        let mut store = self.store();
        // A seeded RNG per drive call (only the overdue shift's anchor redraw consumes it), so
        // the simulation stays deterministic.
        let mut rng = ChaCha8Rng::seed_from_u64(0x318);
        satisfiability::advance_migration(&mut store, state, targets, &ADVANCE, &mut rng)
            .expect("the store and its satisfiability oracle answer")
            .step()
            .clone()
    }

    /// Mine one empty block and scan it, so the chain reaches the migration's next scheduled
    /// height.
    fn mine_empty_block(&mut self) {
        let (h, _) = self.st.generate_empty_block();
        self.st.scan_cached_blocks(h, 1);
    }

    /// Perform an [`AdvanceStep::Prove`] step: install the transaction's deferred anchor and
    /// witnesses against the wallet's commitment trees, prove it, and persist. A PREPARATION
    /// anchors to a fresh checkpoint at the tip (the caller's choice, as for an ordinary
    /// transaction); a TRANSFER to the boundary its schedule drew. Returns [`ProveStepOutcome`]
    /// rather than the engine's own outcome because a successful proof's `ProvedTransaction` is
    /// consumed by the persistence this helper performs.
    ///
    /// A successful proof is persisted through [`PoolMigrations::store_proved_transaction`]: the
    /// migration state and the finalized transaction's wallet record (its `transactions` row,
    /// sent outputs, and input-spend marks) are written as one atomic update, which is the
    /// moment the wallet's own view starts protecting the migration's inputs from its other
    /// spends. Any other outcome persists the migration state alone.
    ///
    /// The engine's outcome is returned rather than asserted: a prove attempt whose input the
    /// wallet no longer holds unspent is not an error but a determination, and persisting is
    /// exactly as necessary then as it is after a successful proof.
    fn perform_prove(
        &mut self,
        state: &mut MigrationState,
        id: MigrationTransferId,
        kind: MigrationTxKind,
    ) -> ProveStepOutcome {
        let anchor = matches!(kind, MigrationTxKind::Preparation { .. }).then(|| {
            let tip = self.target_height() - 1;
            highest_rooted_orchard_checkpoint(self.st.wallet_mut(), tip)
                .expect("a rooted Orchard checkpoint exists")
        });
        let outcome = {
            // The proving-time boundary re-draw's inputs: the network (for the NU6.3 floor), the
            // scanned tip (blocks are scanned as they are mined here, so the chain tip IS the
            // scanned tip), and an rng for the ZIP 318 age draw.
            let params = *self.st.network();
            let scanned_tip = self.target_height() - 1;
            let mut redraw_rng = ChaCha8Rng::seed_from_u64(97);
            let mut prover =
                WalletMigrationProver::new(self.st.wallet_mut(), self.account_id, self.fvk.clone());
            match anchor {
                Some(anchor) => engine::prove_preparation(&mut prover, state, id, anchor)
                    .expect("the prover answers for the preparation transaction"),
                None => engine::prove_transfer(
                    &params,
                    &mut prover,
                    state,
                    id,
                    scanned_tip,
                    &mut redraw_rng,
                )
                .expect("the prover answers for the transfer"),
            }
        };
        match outcome {
            engine::ProveOutcome::Proved(proven) => {
                self.store()
                    .store_proved_transaction(state, proven)
                    .expect("finalizes and persists the proved transaction");
                ProveStepOutcome::Proved
            }
            engine::ProveOutcome::NotYetProvable => {
                self.persist(state);
                ProveStepOutcome::NotYetProvable
            }
            engine::ProveOutcome::MarkedUnsatisfiable { replan_required } => {
                self.persist(state);
                ProveStepOutcome::MarkedUnsatisfiable { replan_required }
            }
        }
    }

    /// Perform an [`AdvanceStep::Broadcast`] step: obtain the broadcastable transaction through
    /// the store's broadcast seam — which finalizes the stored proven PCZT and records the
    /// wallet-side transaction in the same atomic step — and submit it, which in this simulation
    /// means mining and scanning it, then record both lifecycle transitions a consumer records
    /// (broadcast, then mined) and persist. Returns the extracted transaction and the height it
    /// mined at.
    fn perform_broadcast(
        &mut self,
        state: &mut MigrationState,
        id: MigrationTransferId,
    ) -> (Transaction, BlockHeight) {
        let stored_txid = state
            .transactions()
            .iter()
            .find(|t| t.id() == id)
            .expect("the broadcast candidate is present")
            .txid();
        let tx = self
            .store()
            .take_transaction_for_broadcast(state, id)
            .expect("finalizes and records the broadcastable transaction");
        // The id the engine derived from the PCZT when it BUILT this transaction, against the id
        // the real extracted transaction actually has. This is the claim the stored txid rests
        // on — that deriving before signing and proving gives the same answer as extracting
        // afterwards — checked here against a genuinely proven artifact.
        assert_eq!(
            stored_txid,
            tx.txid(),
            "the stored id must be the extracted transaction's own",
        );
        let (height, _) = self.st.generate_next_block_from_tx(1, &tx);
        self.st.scan_cached_blocks(height, 1);
        state.mark_broadcast(id);
        state.mark_mined(id, height);
        self.persist(state);
        (tx, height)
    }

    /// Drive only the PREPARATION phase: perform every step the migration names until every
    /// preparation transaction is mined, mining empty blocks while its schedule has not come due.
    ///
    /// This stops with the transfers' anchor boundaries still ahead of the tip — every crossing
    /// depends on a preparation, so none is provable until the last one mines — which is where a
    /// test can interpose chain events of its own.
    fn drive_preparations(&mut self, committed: &mut Committed) {
        let unmined_preparation = |state: &MigrationState| {
            state.transactions().iter().any(|t| {
                matches!(t.kind(), MigrationTxKind::Preparation { .. })
                    && !matches!(t.state(), MigrationTxState::Mined { .. })
            })
        };
        let mut waited = 0u32;
        while unmined_preparation(&committed.state) {
            match self.advance(&mut committed.state) {
                AdvanceStep::Prove { transactions } => {
                    for target in transactions {
                        let (id, kind) = (target.id(), target.kind());
                        if matches!(kind, MigrationTxKind::Transfer { .. }) {
                            // The batch may carry a crossing alongside the preparations, but
                            // only once the preparation minting its funding note has mined.
                            let deps = committed
                                .state
                                .transactions()
                                .iter()
                                .find(|t| t.id() == id)
                                .expect("the step names stored transactions")
                                .depends_on()
                                .to_vec();
                            assert!(
                                committed.state.deps_mined(&deps),
                                "no crossing is provable while a preparation it depends on is unmined",
                            );
                        }
                        assert_eq!(
                            self.perform_prove(&mut committed.state, id, kind),
                            ProveStepOutcome::Proved,
                        );
                    }
                }
                AdvanceStep::Broadcast { id } => {
                    self.perform_broadcast(&mut committed.state, id);
                }
                AdvanceStep::Waiting => {
                    assert!(
                        waited < MAX_WAITING_BLOCKS,
                        "no preparation came due within {MAX_WAITING_BLOCKS} blocks",
                    );
                    waited += 1;
                    self.mine_empty_block();
                }
                other => panic!("a healthy migration never needs {other:?} while preparing"),
            }
        }
    }

    /// Drive until `advance_migration` first names a TRANSFER for proving, performing every
    /// preparation step along the way, and return that transfer's id without performing the step.
    ///
    /// This is the state a migration sits in for most of its life: its preparations mined, its
    /// funding notes spendable, and its crossings still to be proved and broadcast on a schedule
    /// spread over weeks — which is exactly the window in which an ordinary wallet spend can
    /// consume the notes it allocated.
    fn drive_to_first_transfer_step(&mut self, committed: &mut Committed) -> MigrationTransferId {
        let mut waited = 0u32;
        loop {
            self.drive_preparations(committed);
            match self.advance(&mut committed.state) {
                AdvanceStep::Prove { transactions } => {
                    // `drive_preparations` has just proved and broadcast every due
                    // preparation, so what the batch carries here is transfers, earliest
                    // anchor boundary first.
                    assert!(
                        matches!(transactions[0].kind(), MigrationTxKind::Transfer { .. }),
                        "only transfers await proving once the preparations are driven"
                    );
                    return transactions[0].id();
                }
                AdvanceStep::Waiting => {
                    assert!(
                        waited < MAX_WAITING_BLOCKS,
                        "no transfer became provable within {MAX_WAITING_BLOCKS} blocks",
                    );
                    waited += 1;
                    self.mine_empty_block();
                }
                other => panic!("a healthy migration never needs {other:?} before its transfers"),
            }
        }
    }

    /// Drive until `advance_migration` offers a TRANSFER's broadcast, performing every step it
    /// names along the way (the preparations in full, each transfer's proof), and return that
    /// transfer's id WITHOUT broadcasting it.
    ///
    /// This is the moment a wallet wakes for a broadcast-only session: a proven crossing is due,
    /// and submitting it is the whole of the work.
    fn drive_to_first_transfer_broadcast(
        &mut self,
        committed: &mut Committed,
    ) -> MigrationTransferId {
        let mut waited = 0u32;
        loop {
            match self.advance(&mut committed.state) {
                AdvanceStep::Prove { transactions } => {
                    for target in transactions {
                        assert_eq!(
                            self.perform_prove(&mut committed.state, target.id(), target.kind()),
                            ProveStepOutcome::Proved,
                        );
                    }
                }
                AdvanceStep::Broadcast { id } => {
                    let kind = committed
                        .state
                        .transactions()
                        .iter()
                        .find(|t| t.id() == id)
                        .expect("the broadcast candidate is present")
                        .kind();
                    match kind {
                        MigrationTxKind::Transfer { .. } => return id,
                        MigrationTxKind::Preparation { .. } => {
                            self.perform_broadcast(&mut committed.state, id);
                        }
                    }
                }
                AdvanceStep::Waiting => {
                    assert!(
                        waited < MAX_WAITING_BLOCKS,
                        "no transfer came due within {MAX_WAITING_BLOCKS} blocks",
                    );
                    waited += 1;
                    self.mine_empty_block();
                }
                other => panic!("a healthy migration never needs {other:?} before its transfers"),
            }
        }
    }

    /// The chain tip the wallet has seen.
    fn tip(&self) -> BlockHeight {
        self.target_height() - 1
    }

    /// Sweep every spendable note in the account to an EXTERNAL address through the wallet's own
    /// send-max machinery, then mine and scan the sweep so the spends are recorded exactly as the
    /// scanner records them.
    ///
    /// This is the ordinary user action a migration has to survive: a "send max" consumes the very
    /// notes the migration's pre-signed transfers were built to spend, and nothing tells the
    /// migration about it. The wallet's own proposal, transaction builder, and scanner are used
    /// throughout, so the spend evidence the satisfiability oracle later reads is genuine.
    fn sweep_to_external(&mut self) {
        let height = self.sweep_to_external_unscanned();
        self.st.scan_cached_blocks(height, 1);
        assert_eq!(
            self.st.get_total_balance(self.account_id),
            Zatoshis::ZERO,
            "the send-max sweep leaves the account empty",
        );
    }

    /// [`Self::sweep_to_external`] stopping one step short: the sweep is built and MINED, and the
    /// wallet has not scanned the block that carries it. Returns that block's height.
    ///
    /// This is the state a wallet is in when it wakes to broadcast without syncing (ZIP 318): the
    /// chain holds a spend of its notes, its own tables do not know about it yet, and the only
    /// thing that can tell it otherwise is the node it talks to.
    fn sweep_to_external_unscanned(&mut self) -> BlockHeight {
        use core::num::NonZeroU32;
        use zcash_client_backend::data_api::MaxSpendMode;
        use zcash_client_backend::data_api::wallet::ConfirmationsPolicy;
        use zcash_client_backend::fees::StandardFeeRule;
        use zcash_client_backend::wallet::OvkPolicy;
        use zcash_keys::address::Address;

        let recipient: Address =
            OrchardPoolTester::sk_default_address(&OrchardPoolTester::sk(&[0xf5; 32]));
        let recipient = recipient.to_zcash_address(self.st.network());
        let confirmations = ConfirmationsPolicy::new_symmetrical(
            NonZeroU32::new(1).expect("1 is not zero"),
            #[cfg(feature = "transparent-inputs")]
            false,
        );
        let proposal = self
            .st
            .propose_send_max_transfer(
                self.account_id,
                &StandardFeeRule::Zip317,
                recipient,
                None,
                MaxSpendMode::MaxSpendable,
                confirmations,
            )
            .expect("proposes a send-max sweep of the account's spendable notes");
        // The wallet's own builder, with the testing harness's mock provers: nothing here
        // verifies the sweep's proofs, and what the migration must react to is the SPENDS the
        // scanner records, which are as real as any other transaction's.
        let txids = self
            .st
            .create_proposed_transactions::<Infallible, _, Infallible, _>(
                &self.usk.clone(),
                OvkPolicy::Sender,
                &proposal,
            )
            .expect("builds the sweep");
        assert_eq!(txids.len(), 1, "the sweep is a single transaction");
        let txid = txids.head;

        let tx = self
            .st
            .wallet()
            .get_transaction(txid)
            .expect("reads the swept transaction")
            .expect("the sweep was stored");
        let (height, _) = self.st.generate_next_block_from_tx(1, &tx);
        height
    }

    /// Forget the wallet-side spend marks of a proved-but-unbroadcast migration transaction, so
    /// this wallet's own selection can play the role of a SIBLING wallet on the same seed: the
    /// sibling shares every note but holds no record of this wallet's unbroadcast crossing, so
    /// nothing excludes the crossing's inputs from ITS selection. Since
    /// `take_transaction_for_broadcast` records those marks at the broadcast seam — which is
    /// exactly what keeps this wallet's own sweeps off a migration input, the protection under
    /// test in `broadcast_persists_the_finalized_transaction_to_the_wallet` — simulating the
    /// sibling's independent view requires lifting them.
    fn forget_pending_spend_marks(&mut self, txid: TxId) {
        let conn = self.st.wallet_mut().conn_mut();
        conn.execute(
            "DELETE FROM orchard_received_note_spends
             WHERE transaction_id IN (SELECT id_tx FROM transactions WHERE txid = :txid)",
            rusqlite::named_params![":txid": txid.as_ref()],
        )
        .expect("lifts the pending spend marks");
        // The sibling also knows nothing of THIS wallet's advisory note locks — they are local
        // database state, not chain state — so simulating its spend through this wallet's own
        // machinery must lift them too.
        conn.execute_batch(
            "UPDATE orchard_received_notes
                SET lock_expiry_height = NULL, lock_owner = NULL
              WHERE lock_owner IS NOT NULL",
        )
        .expect("lifts the advisory locks a sibling would not see");
    }

    /// The wallet's fully-scanned height: the chain state every satisfiability observation the
    /// oracle and the prove seam make rests on.
    fn fully_scanned_height(&self) -> BlockHeight {
        self.st
            .wallet()
            .block_fully_scanned()
            .expect("reads the fully-scanned block")
            .expect("the wallet is fully scanned")
            .block_height()
    }

    /// Phase 2 (plan and commit): plans and commits the migration over the wallet adapter (its plan,
    /// preparations, and transfers all drawn from the real wallet's notes), checks the planned
    /// funding-note count and migrated value against the scenario, persists it into the SQLite
    /// store, and returns the committed migration (every transaction Signed, with anchors and
    /// witnesses deferred).
    fn plan_and_commit(&mut self, scenario: &Scenario) -> Committed {
        let tip = self
            .st
            .wallet()
            .chain_height()
            .expect("reads the chain height")
            .expect("the wallet has a chain tip");
        let stored = self.stored_migration();
        let mut rng = ChaCha8Rng::seed_from_u64(0);
        let (state, funding_notes, migrated, change) = {
            let adapter = WalletMigration::new(
                self.st.wallet(),
                self.account_id,
                self.usk.to_unified_full_viewing_key(),
                MigrationTestStore::holding(stored),
            );
            let plan = engine::plan_migration(&self.network, &adapter, &mut rng)
                .expect("plans the migration");
            let funding_notes = plan.funding_notes();
            let migrated = plan.denominations().total_migratable();
            let change = plan.denominations().change().map(u64::from).unwrap_or(0);
            let mut adapter = adapter;
            // The adapter holds viewing authority only; the spending key is the commit's own
            // argument, live for that call (and checked against the account's viewing key there).
            let sk = self.usk.orchard();
            let (state, _) = engine::commit_preparation_with_funding(
                &self.network,
                tip,
                &mut adapter,
                sk,
                &plan,
                &mut rng,
                ReplanThreshold::DEFAULT,
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

        // The committed migration becomes the store's: everything after this point is driven from
        // persisted state, exactly as a wallet resuming after a restart would.
        self.persist(&state);

        Committed {
            state,
            funding_notes,
            change,
        }
    }

    /// Phase 3 (drive): advances the committed migration to completion through
    /// [`satisfiability::advance_migration`], performing each step it names against the simulated
    /// chain, and asserts what the chain and the wallet should show at each one.
    ///
    /// A `Prove` step installs the transaction's deferred anchor and witnesses and proves it: a
    /// PREPARATION anchors to a fresh checkpoint at the tip (the caller's choice, as for an
    /// ordinary transaction), a TRANSFER to the boundary its schedule drew. A `Broadcast` step
    /// extracts the proven PCZT — asserting the bundle shape the kind implies, and for a transfer
    /// checking the wallet's own view of the mined crossing — and submits it, which in this
    /// simulation means mining and scanning it. `Waiting` means the migration's privacy schedule
    /// has not come due, so the chain advances a block. Nothing else may be named: a healthy
    /// migration over a wallet whose notes nothing else touches never needs a rebuild or a replan.
    ///
    /// The step-verifying oracle is the SQLite store's, so every step performed here was first
    /// checked against the wallet's live note and note-spend tables.
    fn drive_to_completion(&mut self, committed: &mut Committed, scenario: &Scenario) {
        // The Ironwood output note each transfer creates, collected to check the destination pool.
        let mut ironwood_notes: Vec<Zatoshis> = Vec::new();
        let mut preparations_mined = 0usize;
        let mut transfers_mined = 0usize;
        let mut waited = 0u32;

        loop {
            match self.advance(&mut committed.state) {
                AdvanceStep::Prove { transactions } => {
                    for target in transactions {
                        let (id, kind) = (target.id(), target.kind());
                        assert_eq!(
                            self.perform_prove(&mut committed.state, id, kind),
                            ProveStepOutcome::Proved,
                            "{}: proving {id:?}",
                            scenario.label
                        );
                        let proven = committed
                            .state
                            .transactions()
                            .iter()
                            .find(|t| t.id() == id)
                            .expect("the proved transaction is present");
                        assert!(matches!(proven.state(), MigrationTxState::Proved));
                    }
                }

                AdvanceStep::Broadcast { id } => {
                    let kind = committed
                        .state
                        .transactions()
                        .iter()
                        .find(|t| t.id() == id)
                        .expect("the broadcast candidate is present")
                        .kind();
                    let (tx, _) = self.perform_broadcast(&mut committed.state, id);
                    assert!(
                        tx.orchard_bundle().is_some(),
                        "{}: every migration transaction spends Orchard notes",
                        scenario.label
                    );

                    match kind {
                        MigrationTxKind::Preparation { .. } => {
                            // A preparation transaction is Orchard-only: no Ironwood bundle.
                            assert!(
                                tx.ironwood_bundle().is_none(),
                                "{}: a preparation has no Ironwood bundle",
                                scenario.label
                            );
                            preparations_mined += 1;
                            if preparations_mined == scenario.expected_preparations {
                                // Every preparation is now mined and scanned, so its minted
                                // funding notes are spendable: the balance is the funding notes
                                // plus the plan's change, the source balance less the reserved
                                // preparation fees.
                                let funding_notes_total: u64 =
                                    committed.funding_notes.iter().map(|&v| u64::from(v)).sum();
                                assert_eq!(
                                    self.st.get_total_balance(self.account_id),
                                    Zatoshis::from_u64(funding_notes_total + committed.change)
                                        .expect("a valid balance"),
                                    "{}: balance after preparations",
                                    scenario.label
                                );
                            }
                        }
                        MigrationTxKind::Transfer { .. } => {
                            transfers_mined += 1;
                            ironwood_notes.push(self.assert_mined_crossing(&tx, scenario));
                        }
                    }
                }

                AdvanceStep::Waiting => {
                    assert!(
                        waited < MAX_WAITING_BLOCKS,
                        "{}: the migration made no progress within {MAX_WAITING_BLOCKS} blocks",
                        scenario.label
                    );
                    waited += 1;
                    self.mine_empty_block();
                }

                AdvanceStep::Complete => break,

                other => panic!(
                    "{}: a healthy migration never needs {other:?}",
                    scenario.label
                ),
            }
        }

        assert_eq!(
            preparations_mined, scenario.expected_preparations,
            "{}: preparation transactions",
            scenario.label
        );
        assert_eq!(
            transfers_mined, scenario.expected_transfers,
            "{}: transfers",
            scenario.label
        );
        assert_eq!(
            committed.state.status(),
            MigrationStatus::Complete,
            "{}: a fully mined migration is complete",
            scenario.label
        );
        // The drive's determinations are durable: what the store holds agrees with what the drive
        // returned.
        assert_eq!(
            self.store()
                .latest_migration()
                .expect("the history reads back")
                .expect("the migration is in the store")
                .status(),
            MigrationStatus::Complete,
            "{}: the store agrees the migration is complete (as retained history: a terminal \
             migration leaves the pending-only read)",
            scenario.label
        );

        // After every transfer is mined and scanned, the wallet holds the migrated value (now in
        // the Ironwood pool) plus the plan's change.
        assert_eq!(
            self.st.get_total_balance(self.account_id),
            (scenario.expected_migrated
                + Zatoshis::from_u64(committed.change).expect("a valid change amount"))
            .expect("a valid final balance"),
            "{}: balance after transfers",
            scenario.label
        );

        // The destination pool holds exactly one Ironwood note per crossing, together carrying the
        // whole migrated value.
        let ironwood_total: u64 = ironwood_notes.iter().map(|&v| u64::from(v)).sum();
        assert_eq!(
            Zatoshis::from_u64(ironwood_total).expect("a valid balance"),
            scenario.expected_migrated,
            "{}: Ironwood balance",
            scenario.label
        );
    }

    /// Asserts everything a MINED transfer should show, and returns the value that crossed: its
    /// Ironwood bundle carries exactly one output (the crossing note), and the wallet's own
    /// transaction history reports the funding note spent, the crossing note received, a balance
    /// change of only the fee, and the transaction classified as a pool crossing carrying the
    /// crossing value — which is the amount a wallet should display for it.
    fn assert_mined_crossing(
        &mut self,
        tx: &zcash_primitives::transaction::Transaction,
        scenario: &Scenario,
    ) -> Zatoshis {
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
        let crossing_value = Zatoshis::from_u64(i64::from(ironwood.value_balance()).unsigned_abs())
            .expect("a valid Ironwood note value");

        // The transfer's Orchard bundle is spend-only, so its value balance is the spent funding
        // note's value; the Ironwood bundle is output-only, so its value balance magnitude is the
        // crossing value. Their difference is the transfer's fee.
        let funding_value = Zatoshis::from_u64(
            i64::from(
                *tx.orchard_bundle()
                    .expect("the transfer has an Orchard bundle")
                    .value_balance(),
            )
            .unsigned_abs(),
        )
        .expect("a valid funding note value");
        let transfer_fee =
            (funding_value - crossing_value).expect("the funding note covers the crossing");

        let history = self
            .st
            .wallet()
            .get_tx_history()
            .expect("reads the transaction history");
        let entry = history
            .iter()
            .find(|t| t.txid() == tx.txid())
            .expect("the mined transfer appears in the transaction history");
        assert_eq!(
            entry.total_spent(),
            funding_value,
            "{}: transfer total_spent",
            scenario.label
        );
        assert_eq!(
            entry.total_received(),
            crossing_value,
            "{}: transfer total_received",
            scenario.label
        );
        assert_eq!(
            entry.account_value_delta(),
            -ZatBalance::from(transfer_fee),
            "{}: transfer balance delta is only the fee",
            scenario.label
        );
        assert!(
            entry.is_pool_crossing(),
            "{}: the transfer is a pool crossing",
            scenario.label
        );
        assert_eq!(
            entry.pool_crossing_value(),
            Some(crossing_value),
            "{}: transfer pool_crossing_value",
            scenario.label
        );

        crossing_value
    }
}

/// Every proving scenario, spanning the migration personas exercised across the codebase (the Python
/// integration-test suite and the denomination golden vectors): single small / medium / large
/// balances, the minimum-denomination and buffer-pruned edges, and the many-note "exchange" / dust /
/// whale shapes whose consolidation drives multi-layer preparation.
fn scenarios() -> Vec<Scenario> {
    // The source balances and their fee-aware expected outputs are defined ONCE in the reusable
    // `testing::MIGRATION_SCENARIOS` (shared with the signing-round end-to-end test); this builds a
    // proving `Scenario` from each.
    zcash_pool_migration::testing::MIGRATION_SCENARIOS
        .iter()
        .map(|sc| {
            Scenario::funded_notes(sc.label, sc.source_notes.iter().map(|&z| zats(z)).collect())
                .expect_preparations(sc.expected_preparations)
                .expect_transfers(sc.expected_transfers)
                .expect_migrated(zats(sc.expected_migrated))
        })
        .collect()
}

#[test]
#[cfg_attr(
    feature = "ignore-expensive-tests",
    ignore = "covered by the expensive-test CI matrix"
)]
fn migration_proves_end_to_end_against_a_funded_wallet() {
    // Proving dominates this test's cost: each preparation proves an Orchard bundle, and each
    // transfer proves both an Orchard AND an Ironwood bundle, so proving every scenario in
    // `MIGRATION_SCENARIOS` is ~149 real Halo2 proofs in a single test. The per-scenario
    // accounting (preparations, transfers, migrated value, signing rounds) is already asserted for
    // ALL scenarios without any proving by `migration_scenarios_end_to_end` in
    // `signing_rounds_e2e.rs`; the only thing this test adds is exercising the real proving path.
    // We therefore prove ONE representative scenario end to end. The "exchange" shape is the
    // cheapest that still spans multi-layer preparation (2 preparations) and multiple transfers
    // (3), so every proving code path runs exactly as it would for the larger shapes.
    const REPRESENTATIVE: &str = "exchange, ten 5 ZEC notes";
    let scenario = scenarios()
        .into_iter()
        .find(|scenario| scenario.label == REPRESENTATIVE)
        .expect("the representative proving scenario exists");
    scenario.prove_end_to_end();
}

/// Proving a migration transaction persists its FINALIZED form to the wallet database, atomically
/// with the migration state that records it proved.
///
/// The wallet-side record is the one `store_transactions_to_be_sent` writes for the standard
/// spend flows: the raw transaction (queryable for broadcast), its outputs as sent notes — here
/// the Ironwood crossing output carrying the migrated value — and its input notes marked spent,
/// which is what stops the wallet's OWN later spends from consuming a migration input during the
/// deliberately long window between proving and broadcast. Atomicity is exercised from the
/// failure side: with the wallet-side half made to fail, the migration-store half must roll back
/// with it, so a transaction is never durably `Proved` without the wallet record.
#[test]
#[cfg_attr(
    feature = "ignore-expensive-tests",
    ignore = "covered by the expensive-test CI matrix"
)]
fn broadcast_persists_the_finalized_transaction_to_the_wallet() {
    use zcash_client_backend::data_api::InputSource;
    use zcash_client_backend::data_api::wallet::TargetHeight;
    use zcash_client_backend::data_api::wallet::input_selection::LockFilter;
    use zcash_protocol::ShieldedPool;

    // The cheapest scenario with both a preparation and a crossing: one funding note, one
    // transfer, so the wallet-side record under test is a single transaction's.
    const SINGLE: &str = "Gwen, 0.0152 ZEC (a single minimum-denomination note)";
    let scenario = scenarios()
        .into_iter()
        .find(|scenario| scenario.label == SINGLE)
        .expect("the single-crossing scenario exists");

    let mut run = Run::setup(&scenario);
    let mut committed = run.plan_and_commit(&scenario);
    let transfer_id = run.drive_to_first_transfer_step(&mut committed);

    let spendable_values = |run: &mut Run| -> Vec<Zatoshis> {
        let target = TargetHeight::from(u32::from(run.target_height()));
        run.st
            .wallet()
            .select_unspent_notes(
                run.account_id,
                &[ShieldedPool::Orchard],
                target,
                &[],
                LockFilter::Unfiltered,
            )
            .expect("selects unspent notes")
            .orchard()
            .iter()
            .map(|note| {
                Zatoshis::from_u64(note.note().value().inner()).expect("a valid note value")
            })
            .collect()
    };
    let funding_value = committed.funding_notes[0];
    assert!(
        spendable_values(&mut run).contains(&funding_value),
        "premise: the funding note is spendable before the transfer is proved",
    );

    // Prove through the engine seam alone, so persistence can be exercised separately below. The
    // engine returns the proof as a value — nothing has moved the state to `Proved` yet.
    let outcome = {
        let params = *run.st.network();
        let scanned_tip = run.fully_scanned_height();
        let mut redraw_rng = ChaCha8Rng::seed_from_u64(29);
        let mut prover =
            WalletMigrationProver::new(run.st.wallet_mut(), run.account_id, run.fvk.clone());
        engine::prove_transfer(
            &params,
            &mut prover,
            &mut committed.state,
            transfer_id,
            scanned_tip,
            &mut redraw_rng,
        )
        .expect("the prover answers for the transfer")
    };
    let engine::ProveOutcome::Proved(proven) = outcome else {
        panic!("expected a proof, got {outcome:?}");
    };
    let txid = committed
        .state
        .transactions()
        .iter()
        .find(|t| t.id() == transfer_id)
        .expect("the transfer is present")
        .txid();

    // PROVE persists the migration store's half ONLY: the transfer is durably `Proved`, and the
    // wallet's transaction tables know nothing — the user's balance is untouched by a
    // transaction that is in no mempool, and the never-broadcast txid enters no retrieval
    // queue. The prove-to-broadcast reservation is the advisory lock, exercised by the locking
    // tests above.
    run.store()
        .store_proved_transaction(&mut committed.state, proven)
        .expect("records the proof in the migration store");
    assert!(
        matches!(
            run.stored_migration()
                .expect("the store holds the migration")
                .transactions()
                .iter()
                .find(|t| t.id() == transfer_id)
                .expect("the transfer is present")
                .state(),
            MigrationTxState::Proved
        ),
        "the store records the transfer proved",
    );
    assert!(
        run.st
            .wallet()
            .get_transaction(txid)
            .expect("queries the wallet")
            .is_none(),
        "proving leaves no record in the wallet's transaction tables",
    );

    // FAILURE SIDE of the BROADCAST seam: with the wallet-side half unable to write, no
    // broadcastable bytes are handed out and no partial record survives — the bytes bind to the
    // record, so there is no crash prefix in which the consumer holds a transaction the wallet
    // does not know about.
    run.st
        .wallet_mut()
        .conn_mut()
        .execute_batch("ALTER TABLE sent_notes RENAME TO sent_notes_hidden")
        .expect("hides the sent-notes table");
    assert!(
        run.store()
            .take_transaction_for_broadcast(&committed.state, transfer_id)
            .is_err(),
        "the wallet-side write cannot succeed without its table",
    );
    assert!(
        run.st
            .wallet()
            .get_transaction(txid)
            .expect("queries the wallet")
            .is_none(),
        "no wallet transaction record survives the rollback",
    );
    run.st
        .wallet_mut()
        .conn_mut()
        .execute_batch("ALTER TABLE sent_notes_hidden RENAME TO sent_notes")
        .expect("restores the sent-notes table");

    // SUCCESS SIDE: one atomic step records the wallet-side half and returns the transaction.
    let extracted = run
        .store()
        .take_transaction_for_broadcast(&committed.state, transfer_id)
        .expect("finalizes, records, and returns the broadcastable transaction");
    assert_eq!(extracted.txid(), txid);

    // The wallet holds the raw finalized transaction under the txid the engine derived at build
    // time, with its Ironwood crossing bundle intact.
    let tx = run
        .st
        .wallet()
        .get_transaction(txid)
        .expect("queries the wallet")
        .expect("the finalized transaction is stored");
    assert_eq!(tx.txid(), txid);
    assert!(
        tx.ironwood_bundle().is_some(),
        "the crossing carries an Ironwood bundle",
    );

    // Its sent-output record is exactly the transfer's REAL outputs: the Ironwood crossing
    // output carrying the migrated value, plus the Orchard change returning the unspent share of
    // the funding note's fee buffer — together the funding note minus the fee. The padding
    // dummies decrypt under no key and are exactly what must NOT be recorded.
    let sent_values: Vec<Zatoshis> = {
        let conn = run.st.wallet_mut().conn_mut();
        let mut stmt = conn
            .prepare(
                "SELECT sent_notes.value
                 FROM sent_notes
                 JOIN transactions ON transactions.id_tx = sent_notes.transaction_id
                 WHERE transactions.txid = :txid",
            )
            .expect("prepares the sent-outputs query");
        let values = stmt
            .query_map(rusqlite::named_params![":txid": txid.as_ref()], |row| {
                row.get::<_, i64>(0)
            })
            .expect("queries the sent outputs")
            .collect::<Result<Vec<_>, _>>()
            .expect("reads the sent outputs");
        values
            .into_iter()
            .map(|v| Zatoshis::from_nonnegative_i64(v).expect("a valid recorded value"))
            .collect()
    };
    let fee = tx
        .fee_paid(|_| Ok::<_, zcash_protocol::value::BalanceError>(None))
        .expect("computes the fee")
        .expect("a migration transaction has no transparent inputs");
    assert!(
        sent_values.contains(&scenario.expected_migrated),
        "the Ironwood crossing output is recorded, carrying the migrated value",
    );
    assert_eq!(
        sent_values
            .iter()
            .try_fold(Zatoshis::ZERO, |acc, v| acc + *v)
            .expect("a valid total"),
        (funding_value - fee).expect("the fee is covered by the funding note"),
        "the recorded outputs account for the funding note minus the fee",
    );

    // RE-ENTRY: a consumer that crashed between obtaining the bytes and submitting them left the
    // transaction `Proved`, so the drive loop offers its broadcast again and it arrives back
    // here. The same bytes come out, and the record it left is neither duplicated nor disturbed.
    let sent_note_count = |run: &mut Run| -> i64 {
        run.st
            .wallet_mut()
            .conn_mut()
            .query_row(
                "SELECT COUNT(*)
                 FROM sent_notes
                 JOIN transactions ON transactions.id_tx = sent_notes.transaction_id
                 WHERE transactions.txid = :txid",
                rusqlite::named_params![":txid": txid.as_ref()],
                |row| row.get(0),
            )
            .expect("counts the recorded sent outputs")
    };
    let recorded_outputs = sent_note_count(&mut run);
    let re_extracted = run
        .store()
        .take_transaction_for_broadcast(&committed.state, transfer_id)
        .expect("re-entering after a crashed submission returns the transaction again");
    assert_eq!(re_extracted.txid(), txid);
    assert_eq!(
        sent_note_count(&mut run),
        recorded_outputs,
        "re-entering records no second copy of the transaction's outputs",
    );

    // The funding note is now marked spent, so the wallet's own input selection no longer offers
    // it: the double-spend window between proving and broadcast is closed.
    assert!(
        !spendable_values(&mut run).contains(&funding_value),
        "the funding note is spent in the wallet's view from the moment the proof is persisted",
    );

    // The stored row carries its ZIP 318 classification from this same atomic write — while the
    // transaction is still UNMINED. The enhance path only stamps classifications for transactions
    // the wallet learns about by scanning, i.e. after they mine; a scheduled transfer sits stored
    // and unmined until its broadcast height, and a wallet labeling (or holding back) its own
    // migration traffic during that window must not read "not classified" there.
    let (zip318_kind, mined_height): (i64, Option<i64>) = run
        .st
        .wallet_mut()
        .conn_mut()
        .query_row(
            "SELECT zip318_kind, mined_height FROM transactions WHERE txid = :txid",
            rusqlite::named_params![":txid": txid.as_ref()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("reads the stored transaction's classification");
    assert_eq!(
        mined_height, None,
        "premise: the transfer is still unmined when the classification must already be present",
    );
    assert_eq!(
        zip318_kind,
        zcash_protocol::zip318::Zip318Classification::Conforms(
            zcash_protocol::zip318::Zip318TxKind::Transfer
        )
        .to_code(),
        "the stored transfer is classified as a ZIP 318 transfer at store time",
    );
}

/// Recording a PREPARATION transaction at the broadcast seam classifies it against ZIP 318 too,
/// and that classification survives the transaction being mined and scanned.
///
/// The transfer's case is covered by `broadcast_persists_the_finalized_transaction_to_the_wallet`;
/// the preparation is the other half, and it is not the same assertion twice. A preparation takes
/// the OTHER branch of the classifier — it carries no destination-pool action at all, so it is
/// judged as a padded Orchard-only send-to-self rather than as a crossing carrying a canonical
/// denomination — and nothing in the transfer's case would notice that branch answering wrongly
/// (or answering `Nonconforming` because the built transaction's action count drifted from the
/// specified padding).
///
/// The post-mining half pins what the write's durability actually rests on: the classification is
/// written by a plain `UPDATE` of a column that `put_tx_data` does not mention, and scanning the
/// mined transaction re-upserts that very row. The re-upsert must not reset it.
///
/// Note what this does NOT cover: nothing here runs the enhance path, so the record written at the
/// broadcast seam is the only thing that ever classifies these transactions in this simulation.
/// That is the point rather than a gap — it is why recording must classify at all — but it means
/// the commit-time claim that the enhance path later re-stamps the same value is pinned by
/// `store_decrypted_tx`'s own tests, not by this one.
#[test]
#[cfg_attr(
    feature = "ignore-expensive-tests",
    ignore = "covered by the expensive-test CI matrix"
)]
fn broadcast_persists_a_preparations_zip318_classification() {
    // The same single-crossing scenario the transfer's case uses, for the same reason: it is the
    // cheapest shape that has a preparation at all.
    const SINGLE: &str = "Gwen, 0.0152 ZEC (a single minimum-denomination note)";
    let scenario = scenarios()
        .into_iter()
        .find(|scenario| scenario.label == SINGLE)
        .expect("the single-crossing scenario exists");

    let mut run = Run::setup(&scenario);
    let mut committed = run.plan_and_commit(&scenario);

    // The first step a healthy migration names is a preparation's proof: no crossing is provable
    // while a preparation it depends on is unmined. The batch is earliest-ready first, so its
    // head is that preparation; proving the one is all this test needs.
    let mut waited = 0u32;
    let (prep_id, kind) = loop {
        match run.advance(&mut committed.state) {
            AdvanceStep::Prove { transactions } => {
                break (transactions[0].id(), transactions[0].kind());
            }
            AdvanceStep::Waiting => {
                assert!(
                    waited < MAX_WAITING_BLOCKS,
                    "no preparation came due within {MAX_WAITING_BLOCKS} blocks",
                );
                waited += 1;
                run.mine_empty_block();
            }
            other => panic!("a healthy migration never needs {other:?} before its preparations"),
        }
    };
    assert!(
        matches!(kind, MigrationTxKind::Preparation { .. }),
        "premise: the first provable transaction is a preparation, not a crossing",
    );
    assert_eq!(
        run.perform_prove(&mut committed.state, prep_id, kind),
        ProveStepOutcome::Proved,
    );

    let txid = committed
        .state
        .transactions()
        .iter()
        .find(|t| t.id() == prep_id)
        .expect("the preparation is present")
        .txid();
    let stored_classification = |run: &mut Run| -> (i64, Option<i64>) {
        run.st
            .wallet_mut()
            .conn_mut()
            .query_row(
                "SELECT zip318_kind, mined_height FROM transactions WHERE txid = :txid",
                rusqlite::named_params![":txid": txid.as_ref()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("reads the stored transaction's classification")
    };
    let expected = zcash_protocol::zip318::Zip318Classification::Conforms(
        zcash_protocol::zip318::Zip318TxKind::Preparation,
    )
    .to_code();

    // Proving alone leaves no wallet-side record to classify: the migration store's half is all
    // that is written, and the transaction enters the wallet's view at the broadcast seam.
    assert!(
        run.st
            .wallet()
            .get_transaction(txid)
            .expect("queries the wallet")
            .is_none(),
        "premise: proving leaves no record in the wallet's transaction tables",
    );

    // Taking the transaction for broadcast is the write under test, and it is called here rather
    // than through `perform_broadcast` so that the record can be observed in the window the seam
    // opens: recorded, but not yet submitted and so still UNMINED.
    let tx = run
        .store()
        .take_transaction_for_broadcast(&committed.state, prep_id)
        .expect("finalizes and records the broadcastable preparation");

    let (zip318_kind, mined_height) = stored_classification(&mut run);
    assert_eq!(
        mined_height, None,
        "premise: the preparation is still unmined when the classification must already be present",
    );
    assert_eq!(
        zip318_kind, expected,
        "the recorded preparation is classified as a ZIP 318 preparation before it mines",
    );

    // Submitting mines and scans the transaction, so the wallet now re-learns it the way it learns
    // about any transaction: through `put_tx_data` and the enhance path. This is the tail of
    // `perform_broadcast`, the transaction having already been taken above.
    let (height, _) = run.st.generate_next_block_from_tx(1, &tx);
    run.st.scan_cached_blocks(height, 1);
    committed.state.mark_broadcast(prep_id);
    committed.state.mark_mined(prep_id, height);
    run.persist(&committed.state);

    let (zip318_kind, mined_height) = stored_classification(&mut run);
    assert!(
        mined_height.is_some(),
        "premise: the preparation is mined once it has been broadcast and scanned",
    );
    assert_eq!(
        zip318_kind, expected,
        "mining and rescanning the preparation leaves its recorded classification intact",
    );
}

/// The adapter reports the WALLET's anchor retention interval as its anchor bucket interval, and
/// every anchor a committed migration draws lands on that grid.
///
/// This is the property that makes the two grids incapable of disagreeing: the interval is never
/// configured on the migration side, so a wallet configured with a non-default retention interval
/// automatically schedules its migration against the boundaries it actually retains.
#[test]
#[cfg_attr(
    feature = "ignore-expensive-tests",
    ignore = "covered by the expensive-test CI matrix"
)]
fn migration_anchors_to_the_wallets_configured_retention_grid() {
    use core::num::NonZeroU32;
    use zcash_client_backend::data_api::anchor_retention::AnchorRetentionInterval;
    use zcash_pool_migration::engine::{MigrationBackend, MigrationTransferId, MigrationTxKind};
    use zcash_pool_migration::scheduling::{AnchorBucketInterval, SchedulingParams};

    // A short grid, so a migration reaches anchor viability without waiting out 144-block buckets.
    let retention = AnchorRetentionInterval::custom(NonZeroU32::new(12).expect("nonzero"));
    let network = nu63_network();

    let mut st = TestBuilder::new()
        .with_network(network)
        .with_data_store_factory(TestDbFactory::default())
        .with_block_cache(BlockCache::new())
        .with_anchor_retention_interval(retention)
        .with_account_from_sapling_activation(BlockHash([0; 32]))
        .build();

    let account = st.test_account().cloned().expect("the test account exists");
    let account_id = account.id();
    let usk = account.usk().clone();
    let fvk = OrchardPoolTester::test_account_fvk(&st);

    let (h, _, _) = st.generate_next_block(&fvk, AddressType::DefaultExternal, zats(4 * COIN));
    st.scan_cached_blocks(h, 1);
    for _ in 0..SHARD_COMPLETION_BLOCKS {
        let (h, _) = st.generate_empty_block();
        st.scan_cached_blocks(h, 1);
    }

    let tip = st
        .wallet()
        .chain_height()
        .expect("reads the chain height")
        .expect("the wallet has a chain tip");
    let mut rng = ChaCha8Rng::seed_from_u64(0);
    let mut adapter = WalletMigration::new(
        st.wallet(),
        account_id,
        usk.to_unified_full_viewing_key(),
        MigrationTestStore::default(),
    );

    // The adapter reports the wallet's grid, not the ZIP 318 default, and scales the delays to it
    // rather than crossing a 12-block grid with three-hour ZIP 318 delays.
    let sched_params = adapter.scheduling_params();
    let interval = sched_params.anchor_bucket_interval();
    assert_eq!(interval, retention);
    assert_ne!(interval, AnchorBucketInterval::ZIP_318);
    assert_eq!(
        sched_params,
        SchedulingParams::new_with_default_distributions(interval),
        "the adapter derives its delays from the wallet's interval",
    );

    let plan = engine::plan_migration(&network, &adapter, &mut rng).expect("plans the migration");
    let sk = usk.orchard();
    let (state, _) = engine::commit_preparation_with_funding(
        &network,
        tip,
        &mut adapter,
        sk,
        &plan,
        &mut rng,
        ReplanThreshold::DEFAULT,
    )
    .expect("commits the migration");

    // Every transfer anchors to a boundary of the WALLET's grid; nothing lands off it, and the
    // migration records that grid so a later reconfiguration is detectable.
    assert_eq!(state.anchor_bucket_interval(), interval);
    let mut transfer_boundaries = Vec::new();
    for tx in state.transactions() {
        if matches!(tx.kind(), MigrationTxKind::Transfer { .. }) {
            let boundary = tx
                .anchor_boundary()
                .expect("every committed transfer carries its boundary");
            assert!(
                interval.is_boundary(boundary),
                "anchor {boundary:?} is not on the wallet's {}-block retention grid",
                interval.block_count(),
            );
            transfer_boundaries.push((tx.id(), boundary));
        }
    }
    assert!(
        !transfer_boundaries.is_empty(),
        "the migration commits at least one transfer"
    );

    // Now the part that ties the two grids together for real: mine the preparations so the funding
    // notes exist, then bury each transfer's boundary far enough behind the chain tip that its
    // checkpoint survives only because the wallet RETAINED it, and prove against it. Without
    // retention on the wallet's configured grid this fails with `AnchorNotFound`.
    let mut state = state;
    let prep_ids: Vec<MigrationTransferId> = state
        .transactions()
        .iter()
        .filter(|t| matches!(t.kind(), MigrationTxKind::Preparation { .. }))
        .map(|t| t.id())
        .collect();
    for prep_id in prep_ids {
        let tip = st
            .wallet()
            .chain_height()
            .expect("reads the chain height")
            .expect("the wallet has a chain tip");
        let anchor = highest_rooted_orchard_checkpoint(st.wallet_mut(), tip)
            .expect("a rooted Orchard checkpoint exists");
        {
            let mut prover = WalletMigrationProver::new(st.wallet_mut(), account_id, fvk.clone());
            match engine::prove_preparation(&mut prover, &mut state, prep_id, anchor)
                .expect("proves the preparation transaction")
            {
                // This test drives raw state with no store; applying the proof directly is the
                // minimal discharge that puts the proven bytes where the extraction below reads.
                engine::ProveOutcome::Proved(proven) => proven.apply(&mut state),
                other => panic!("expected a proof, got {other:?}"),
            }
        }
        let proven = state
            .transactions()
            .iter()
            .find(|t| t.id() == prep_id)
            .expect("the preparation is present");
        let tx = TransactionExtractor::new(
            pczt::Pczt::parse(proven.pczt()).expect("parses the proven preparation PCZT"),
        )
        .extract()
        .expect("extracts the preparation transaction");
        let (prep_height, _) = st.generate_next_block_from_tx(1, &tx);
        st.scan_cached_blocks(prep_height, 1);
    }

    // `zcash_client_sqlite` keeps only the most recent 100 checkpoints, so burying the boundary
    // deeper than that is what makes the proof depend on retention rather than on ordinary
    // checkpoint survival.
    const PRUNING_DEPTH: u32 = 100;
    transfer_boundaries.sort_by_key(|(_, boundary)| *boundary);
    let deepest = transfer_boundaries
        .last()
        .map(|(_, boundary)| *boundary)
        .expect("there is at least one transfer");
    loop {
        let tip = st
            .wallet()
            .chain_height()
            .expect("reads the chain height")
            .expect("the wallet has a chain tip");
        if u32::from(tip) > u32::from(deepest) + PRUNING_DEPTH + 10 {
            break;
        }
        let (h, _) = st.generate_empty_block();
        st.scan_cached_blocks(h, 1);
    }

    for (transfer_id, boundary) in transfer_boundaries {
        // In this simulation every preparation mines before its transfers' drawn boundaries, so
        // the proving-time boundary re-draw never fires and each proof genuinely exercises the
        // RETAINED boundary recorded above (were that untrue, proving would have failed here
        // before the re-draw existed: an out-mined boundary has no witness to resolve).
        let params = *st.network();
        let scanned_tip = st
            .wallet()
            .chain_height()
            .expect("reads the chain height")
            .expect("the wallet has a chain tip");
        let mut redraw_rng = ChaCha8Rng::seed_from_u64(11);
        let mut prover = WalletMigrationProver::new(st.wallet_mut(), account_id, fvk.clone());
        let outcome = engine::prove_transfer(
            &params,
            &mut prover,
            &mut state,
            transfer_id,
            scanned_tip,
            &mut redraw_rng,
        )
        .unwrap_or_else(|e| {
            panic!(
                "proving against the retained boundary {boundary:?} on the wallet's configured \
                 grid failed: {e}"
            )
        });
        let engine::ProveOutcome::Proved(proven) = outcome else {
            panic!("expected a proof, got {outcome:?}");
        };
        proven.apply(&mut state);
    }
}

/// The cheapest scenario that still exercises the whole shape: one preparation and one transfer,
/// so a test that only needs a proved transaction pays for exactly one Orchard proof. Drawn from
/// the shared `MIGRATION_SCENARIOS` so its expected counts stay in sync with the planner.
const SMALLEST: &str = "Gwen, 0.0152 ZEC (a single minimum-denomination note)";

/// The named scenario from the shared list.
fn scenario_named(label: &str) -> Scenario {
    scenarios()
        .into_iter()
        .find(|scenario| scenario.label == label)
        .expect("the named scenario exists")
}

/// Proving a migration transaction RESERVES the notes it spends, and the reservation is advisory:
/// the account's own spending is steered away from those notes by default, but a caller that names
/// the migration's lock owner still reaches them.
///
/// This is the property that lets a wallet schedule a migration without taking the user's money
/// hostage. A migration transaction that is signed and proved is a broadcastable artifact
/// committing to specific notes, so by default nothing else should select them; but the user must
/// remain able to pay, swap, or send at any moment, which they do by passing the migration's own
/// owners in a [`LockedInputPolicy`] override. Locking is a DEFAULT, never a veto.
#[test]
fn proving_locks_the_spent_notes_without_taking_them_from_the_user() {
    // One source note keeps the migration to a single preparation layer, so the first prove is the
    // one that reserves the account's only spendable note.
    let scenario = scenario_named(SMALLEST);
    let mut run = Run::setup(&scenario);
    let mut committed = run.plan_and_commit(&scenario);

    let prep_id = committed
        .state
        .transactions()
        .iter()
        .find(|t| matches!(t.kind(), MigrationTxKind::Preparation { .. }))
        .expect("the migration has a preparation transaction")
        .id();

    let account_id = run.account_id;
    let target = {
        let tip = run
            .st
            .wallet()
            .chain_height()
            .expect("reads the chain height")
            .expect("the wallet has a chain tip");
        TargetHeight::from(u32::from(tip) + 1)
    };

    // Before proving, nothing is reserved and the account's notes are selectable by default.
    assert!(
        run.st
            .wallet()
            .get_locked_outputs(account_id)
            .expect("reads the locked outputs")
            .is_empty(),
        "a committed but unproved migration reserves nothing"
    );
    let selectable_before = run
        .st
        .wallet()
        .select_unspent_notes(
            account_id,
            &[ShieldedPool::Orchard],
            target,
            &[],
            LockFilter::Policy(&LockedInputPolicy::Exclude),
        )
        .expect("selects the account's unspent notes")
        .orchard()
        .len();
    assert!(
        selectable_before > 0,
        "the funded account has selectable Orchard notes before proving"
    );

    let anchor = {
        let tip = run
            .st
            .wallet()
            .chain_height()
            .expect("reads the chain height")
            .expect("the wallet has a chain tip");
        highest_rooted_orchard_checkpoint(run.st.wallet_mut(), tip)
            .expect("a rooted Orchard checkpoint exists")
    };
    let outcome = {
        let mut prover =
            WalletMigrationProver::new(run.st.wallet_mut(), account_id, run.fvk.clone());
        engine::prove_preparation(&mut prover, &mut committed.state, prep_id, anchor)
            .expect("proves the preparation transaction")
    };
    // The proof — and the lock-owner token it was reserved under — travel as a value; the state
    // records both through the store seam.
    let engine::ProveOutcome::Proved(proven) = outcome else {
        panic!("expected a proof, got {outcome:?}");
    };
    run.store()
        .store_proved_transaction(&mut committed.state, proven)
        .expect("records the proof");

    let proved = committed
        .state
        .transactions()
        .iter()
        .find(|t| t.id() == prep_id)
        .expect("the preparation transaction is present");
    assert!(matches!(proved.state(), MigrationTxState::Proved));

    // The transaction records the token its notes were reserved under, so the reservation can be
    // named (and released) later from the persisted migration alone.
    let owner = proved
        .lock_owner()
        .expect("a proved transaction records the lock owner its notes were reserved under");

    // The notes the transaction spends are now reserved.
    let locked = run
        .st
        .wallet()
        .get_locked_outputs(account_id)
        .expect("reads the locked outputs");
    assert!(
        !locked.is_empty(),
        "proving reserves the notes the transaction spends"
    );

    // Reserved notes drop out of DEFAULT selection: another flow will not pick them by accident.
    let selectable_after = run
        .st
        .wallet()
        .select_unspent_notes(
            account_id,
            &[ShieldedPool::Orchard],
            target,
            &[],
            LockFilter::Policy(&LockedInputPolicy::Exclude),
        )
        .expect("selects the account's unspent notes")
        .orchard()
        .len();
    assert_eq!(
        selectable_after,
        selectable_before - locked.len(),
        "exactly the reserved notes leave the default candidate set"
    );

    // ...but the user is NOT locked out. Naming the migration's owner brings them back, which is
    // how a wallet lets a payment spend through a migration in flight.
    let owners = NonEmptyBTreeSet::from_set(BTreeSet::from([LockOwner::new(*owner.as_bytes())]))
        .expect("the migration holds at least one lock owner");
    let policy = LockedInputPolicy::PreferUnlocked(owners);
    let selectable_with_override = run
        .st
        .wallet()
        .select_unspent_notes(
            account_id,
            &[ShieldedPool::Orchard],
            target,
            &[],
            LockFilter::Policy(&policy),
        )
        .expect("selects the account's unspent notes")
        .orchard()
        .len();
    assert_eq!(
        selectable_with_override, selectable_before,
        "naming the migration's lock owner restores every reserved note to the candidate set, so \
         a user payment is never blocked by a migration in flight"
    );
}

/// A note already reserved by ANOTHER flow is not stolen by the migration: proving reports the
/// conflict and the transaction stays `Signed` rather than becoming a `Proved` artifact whose
/// inputs the wallet has already promised elsewhere.
///
/// This is the losing side of the same rule as the test above. The user's in-flight payment holds
/// the note; the migration transaction's spends were fixed by its signature, so it cannot select
/// around the conflict and must wait (or die at its expiry) instead.
#[test]
fn proving_refuses_to_take_a_note_another_flow_has_reserved() {
    let scenario = scenario_named(SMALLEST);
    let mut run = Run::setup(&scenario);
    let mut committed = run.plan_and_commit(&scenario);

    let prep_id = committed
        .state
        .transactions()
        .iter()
        .find(|t| matches!(t.kind(), MigrationTxKind::Preparation { .. }))
        .expect("the migration has a preparation transaction")
        .id();

    let account_id = run.account_id;
    let tip = run
        .st
        .wallet()
        .chain_height()
        .expect("reads the chain height")
        .expect("the wallet has a chain tip");
    let anchor = highest_rooted_orchard_checkpoint(run.st.wallet_mut(), tip)
        .expect("a rooted Orchard checkpoint exists");

    // Another flow gets there first and reserves every note in the account, well past the
    // migration transaction's own expiry.
    let rival = LockOwner::new([0x5Au8; 32]);
    let rival_outputs: Vec<OutputRef> = {
        let notes = run
            .st
            .wallet()
            .select_unspent_notes(
                account_id,
                &[ShieldedPool::Orchard],
                TargetHeight::from(u32::from(tip) + 1),
                &[],
                LockFilter::Unfiltered,
            )
            .expect("enumerates the account's unspent Orchard notes");
        let refs: Vec<OutputRef> = notes
            .orchard()
            .iter()
            .map(|rn| {
                OutputRef::new(
                    *rn.txid(),
                    PoolType::Shielded(ShieldedPool::Orchard),
                    rn.output_index().into(),
                )
            })
            .collect();
        assert!(!refs.is_empty(), "the funded account holds Orchard notes");
        refs
    };
    run.st
        .wallet_mut()
        .lock_outputs(&rival_outputs, rival, tip + 10_000)
        .expect("the rival flow reserves the notes first");

    let result = {
        let mut prover =
            WalletMigrationProver::new(run.st.wallet_mut(), account_id, run.fvk.clone());
        engine::prove_preparation(&mut prover, &mut committed.state, prep_id, anchor)
    };
    assert!(
        matches!(
            result,
            Err(engine::ProveError::Prover(WalletProveError::Lock(_)))
        ),
        "proving must report the reservation conflict, got {result:?}"
    );

    let unchanged = committed
        .state
        .transactions()
        .iter()
        .find(|t| t.id() == prep_id)
        .expect("the preparation transaction is present");
    assert!(
        matches!(unchanged.state(), MigrationTxState::Signed),
        "a transaction that could not reserve its inputs stays Signed"
    );
    assert_eq!(
        unchanged.lock_owner(),
        None,
        "a transaction that could not reserve its inputs records no lock owner"
    );
}

/// The whole cancel affordance, end to end against a funded wallet: a committed-and-proved
/// migration is cancelled at the user's request, its reservation is released so the account's
/// notes return to DEFAULT selection immediately, the record is terminal-but-retained, and a
/// replacement migration plans over the FULL spendable balance — the assertion that fails for
/// the wrong reason if any cleanup is skipped (a plan over a shrunken balance still "succeeds").
#[test]
#[cfg_attr(
    feature = "ignore-expensive-tests",
    ignore = "covered by the expensive-test CI matrix"
)]
fn cancel_returns_the_balance_and_retains_the_record() {
    let scenario = scenario_named(SMALLEST);
    let mut run = Run::setup(&scenario);
    let mut committed = run.plan_and_commit(&scenario);

    // Prove the (single) preparation, taking the reservation on the account's only note.
    let prep_id = committed
        .state
        .transactions()
        .iter()
        .find(|t| matches!(t.kind(), MigrationTxKind::Preparation { .. }))
        .expect("the migration has a preparation transaction")
        .id();
    let account_id = run.account_id;
    let anchor = {
        let tip = run
            .st
            .wallet()
            .chain_height()
            .expect("reads the chain height")
            .expect("the wallet has a chain tip");
        highest_rooted_orchard_checkpoint(run.st.wallet_mut(), tip)
            .expect("a rooted Orchard checkpoint exists")
    };
    let outcome = {
        let mut prover =
            WalletMigrationProver::new(run.st.wallet_mut(), account_id, run.fvk.clone());
        engine::prove_preparation(&mut prover, &mut committed.state, prep_id, anchor)
            .expect("proves the preparation transaction")
    };
    let engine::ProveOutcome::Proved(proven) = outcome else {
        panic!("expected a proof, got {outcome:?}");
    };
    run.store()
        .store_proved_transaction(&mut committed.state, proven)
        .expect("records the proof");
    assert!(
        !run.st
            .wallet()
            .get_locked_outputs(account_id)
            .expect("reads the locked outputs")
            .is_empty(),
        "premise: the proved preparation holds a reservation"
    );

    // CANCEL. One call: reservations released, record terminal, outcome reported.
    let outcome = run.store().cancel_migration().expect("cancel succeeds");
    let never_broadcast: Vec<_> = committed
        .state
        .transactions()
        .iter()
        .map(|t| t.id())
        .collect();
    assert_eq!(
        outcome.released(),
        never_broadcast.as_slice(),
        "every never-broadcast transaction — the proved preparation and the still-signed \
         transfer alike — is released"
    );
    assert!(outcome.in_flight().is_empty());

    // The reservation is gone NOW — not at lock expiry — so default selection sees every note.
    assert!(
        run.st
            .wallet()
            .get_locked_outputs(account_id)
            .expect("reads the locked outputs")
            .is_empty(),
        "cancel released the reservation"
    );
    let target = {
        let tip = run
            .st
            .wallet()
            .chain_height()
            .expect("reads the chain height")
            .expect("the wallet has a chain tip");
        TargetHeight::from(u32::from(tip) + 1)
    };
    let default_selectable: u64 = run
        .st
        .wallet()
        .select_unspent_notes(
            account_id,
            &[ShieldedPool::Orchard],
            target,
            &[],
            LockFilter::Policy(&LockedInputPolicy::Exclude),
        )
        .expect("selects under the DEFAULT lock policy")
        .orchard()
        .iter()
        .map(|note| note.note().value().inner())
        .sum();
    assert!(
        default_selectable > 0,
        "the account's notes are back in default selection"
    );

    // The record is terminal-but-retained; the drive read has moved on.
    {
        let store = run.store();
        assert_eq!(store.get_migration().expect("read"), None);
        assert_eq!(
            store
                .latest_migration()
                .expect("history reads back")
                .map(|s| s.status()),
            Some(MigrationStatus::Cancelled),
        );
    }

    // A replacement migration plans over the FULL balance — not a shrunken one. Planning reads
    // the wallet's spendable notes, so this is the assertion that fails for the wrong reason if
    // any cleanup were skipped: a plan over a shrunken balance still "succeeds".
    let migratable = {
        let stored = run.store().latest_migration().expect("history reads back");
        let adapter = WalletMigration::new(
            run.st.wallet(),
            run.account_id,
            run.usk.to_unified_full_viewing_key(),
            MigrationTestStore::holding(stored),
        );
        let mut rng = ChaCha8Rng::seed_from_u64(0xCA);
        let plan = engine::plan_migration(&run.network, &adapter, &mut rng)
            .expect("a replacement migration plans over the released balance");
        plan.denominations().total_migratable()
    };
    assert!(
        migratable > Zatoshis::ZERO,
        "the replacement plan migrates a nonzero balance"
    );
    assert_eq!(
        migratable, scenario.expected_migrated,
        "the replacement plan covers exactly what the original planned — the full balance, \
         not the fraction a stranded reservation would leave"
    );
}

/// The scenario the unsatisfiability machinery exists for: while a committed migration waits out
/// its privacy schedule, the user spends the whole balance — a "send max" to an external address —
/// consuming the very funding notes the pre-signed crossings were built to spend.
///
/// Nothing tells the migration. What it has instead is the wallet's own view, and this drives that
/// view through both seams that read it, over a real chain and a real store:
///
/// 1. the PROVE seam. Proving a crossing whose funding note the wallet no longer holds unspent is
///    not an error: the prover reports the note absent from the account's unspent set, the engine
///    sharpens that membership observation into positive spend evidence (every dependency of this
///    transfer is mined at a height the wallet has scanned past), and the transfer is marked at the
///    height the observation rests on.
/// 2. the DRIVE seam. `advance_migration` puts the same transfer to the SQLite satisfiability
///    oracle, which recognizes the spend in the wallet's own note-spend tables, records it, and —
///    the whole of the planned crossing value now unsatisfiable, far above the committed
///    threshold — reports `Replan` with every mark durably persisted.
///
/// The consumer's contracted response to `Replan` then completes the loop: supersede, and the
/// commit guard that refused a replacement a moment earlier accepts one for the remaining balance.
#[test]
#[cfg_attr(
    feature = "ignore-expensive-tests",
    ignore = "covered by the expensive-test CI matrix"
)]
fn a_send_max_sweep_marks_the_migration_and_forces_a_replan() {
    // The cheapest scenario that still has both a preparation and a crossing: one funding note,
    // one transfer, so the swept share is the whole planned crossing value.
    const SWEPT: &str = "Gwen, 0.0152 ZEC (a single minimum-denomination note)";
    let scenario = scenarios()
        .into_iter()
        .find(|scenario| scenario.label == SWEPT)
        .expect("the single-crossing scenario exists");

    let mut run = Run::setup(&scenario);
    let mut committed = run.plan_and_commit(&scenario);
    let transfer_id = run.drive_to_first_transfer_step(&mut committed);

    // The user sweeps the account. The transfer's funding note is now spent by a mined
    // transaction the wallet has scanned; the migration still believes it is spendable.
    run.sweep_to_external();
    let as_of_height = run.fully_scanned_height();

    // (1) The PROVE seam, on a copy of the state, so the drive seam below is exercised from the
    // same starting point rather than from this determination's marks.
    let mut probe = committed.state.clone();
    let outcome = {
        let params = *run.st.network();
        let mut redraw_rng = ChaCha8Rng::seed_from_u64(13);
        let mut prover =
            WalletMigrationProver::new(run.st.wallet_mut(), run.account_id, run.fvk.clone());
        engine::prove_transfer(
            &params,
            &mut prover,
            &mut probe,
            transfer_id,
            as_of_height,
            &mut redraw_rng,
        )
        .expect("an unavailable input is answered, never raised as an error")
    };
    assert_eq!(
        outcome,
        engine::ProveOutcome::MarkedUnsatisfiable {
            replan_required: true
        },
        "a swept funding note with every dependency mined and scanned is positive spend evidence",
    );
    assert_eq!(
        probe
            .transactions()
            .iter()
            .find(|t| t.id() == transfer_id)
            .expect("the transfer is present")
            .unsatisfiable_at(),
        Some(as_of_height),
        "the mark carries the fully-scanned height the observation rests on",
    );

    // (2) The DRIVE seam. The oracle reads the same spend out of the wallet's tables, the whole
    // planned crossing value is unsatisfiable, and the committed threshold is exceeded.
    assert_eq!(
        run.advance(&mut committed.state),
        AdvanceStep::Replan,
        "a fully swept migration is re-planned rather than retried",
    );
    for tx in committed.state.transactions() {
        if matches!(tx.kind(), MigrationTxKind::Transfer { .. }) {
            assert_eq!(
                tx.unsatisfiable_at(),
                Some(as_of_height),
                "every affected transfer is marked at the observation's height",
            );
        }
    }

    // The marks are DURABLE: `advance_migration` wrote them back before returning the step, so a
    // wallet that stops here and resumes later re-reads them rather than re-deriving them.
    let stored = run
        .stored_migration()
        .expect("the store holds the migration");
    for tx in stored.transactions() {
        if matches!(tx.kind(), MigrationTxKind::Transfer { .. }) {
            assert_eq!(
                tx.unsatisfiable_at(),
                Some(as_of_height),
                "the mark survives the round trip through the store",
            );
        }
    }
    assert!(
        stored.replan_required(),
        "the persisted migration still reports the replan",
    );

    // Nothing is left to migrate right now: the sweep took the whole balance.
    {
        let stored = run.stored_migration();
        let mut rng = ChaCha8Rng::seed_from_u64(1);
        let adapter = WalletMigration::new(
            run.st.wallet(),
            run.account_id,
            run.usk.to_unified_full_viewing_key(),
            MigrationTestStore::holding(stored),
        );
        assert!(
            matches!(
                engine::plan_migration(&run.network, &adapter, &mut rng),
                Err(engine::MigrationError::NothingToMigrate),
            ),
            "the sweep left no migratable balance",
        );
    }

    // Fund the account afresh, so a replacement migration has something to plan over. Enough
    // blocks follow for the new note to become spendable and its shard to complete.
    let (h, _, _) = run.st.generate_next_block(
        &run.fvk.clone(),
        AddressType::DefaultExternal,
        zats(2 * COIN),
    );
    run.st.scan_cached_blocks(h, 1);
    for _ in 0..(SHARD_COMPLETION_BLOCKS + 10) {
        run.mine_empty_block();
    }

    // The commit guard REFUSES while the superseded-but-not-yet-marked migration is in progress:
    // a committed migration is resumed from the store, never rebuilt over.
    let tip = run.target_height() - 1;
    {
        let stored = run.stored_migration();
        let mut rng = ChaCha8Rng::seed_from_u64(2);
        let mut adapter = WalletMigration::new(
            run.st.wallet(),
            run.account_id,
            run.usk.to_unified_full_viewing_key(),
            MigrationTestStore::holding(stored),
        );
        let plan = engine::plan_migration(&run.network, &adapter, &mut rng)
            .expect("plans the fresh balance");
        let sk = run.usk.orchard();
        assert!(
            matches!(
                engine::commit_preparation_with_funding(
                    &run.network,
                    tip,
                    &mut adapter,
                    sk,
                    &plan,
                    &mut rng,
                    ReplanThreshold::DEFAULT,
                ),
                Err(engine::CommitError::MigrationInProgress),
            ),
            "an in-progress migration is never committed over",
        );
    }

    // The consumer's contracted response to `Replan`: supersede, and persist.
    committed.state.mark_superseded();
    run.persist(&committed.state);
    assert!(
        run.store()
            .latest_migration()
            .expect("the history reads back")
            .expect("the store retains the migration")
            .is_terminal(),
        "the persisted migration is terminal (retained history, gone from the pending-only \
         read), so a replacement may take its place",
    );

    // Now the guard accepts, and the remaining balance is committed to a fresh migration.
    let stored = run.stored_migration();
    let mut rng = ChaCha8Rng::seed_from_u64(3);
    let mut adapter = WalletMigration::new(
        run.st.wallet(),
        run.account_id,
        run.usk.to_unified_full_viewing_key(),
        MigrationTestStore::holding(stored),
    );
    let plan =
        engine::plan_migration(&run.network, &adapter, &mut rng).expect("plans the fresh balance");
    let sk = run.usk.orchard();
    let (replanned, _) = engine::commit_preparation_with_funding(
        &run.network,
        tip,
        &mut adapter,
        sk,
        &plan,
        &mut rng,
        ReplanThreshold::DEFAULT,
    )
    .expect("the commit guard accepts a replacement for a superseded migration");
    assert!(
        !replanned.is_terminal(),
        "the replacement migration is live",
    );
    assert!(
        replanned
            .transactions()
            .iter()
            .any(|t| matches!(t.kind(), MigrationTxKind::Transfer { .. })),
        "the replacement migration carries crossings for the remaining balance",
    );
    assert!(
        replanned
            .transactions()
            .iter()
            .all(|t| t.unsatisfiable_at().is_none()),
        "the replacement carries none of the superseded migration's marks",
    );
}

/// The scenario a broadcast-failure report exists for: the wallet wakes to BROADCAST without
/// syncing (ZIP 318 keeps sync traffic out of a broadcast session), the node refuses the
/// transaction, and the wallet's own tables still show its inputs unspent. The node's rejection is
/// testimony from another observer, so it can never mark; what it does is withhold the transaction
/// and hold the drive loop at `Reevaluate` until the wallet has scanned the chain state the
/// rejection could rest on.
///
/// Both adjudications are driven here, over a real chain and a real store, in the order a wallet
/// could meet them:
///
/// 1. TRANSIENT. A rejection with nothing behind it (the node was out of sync, a mempool
///    conflict). The wallet syncs past the reported tip, the oracle finds the crossing's inputs
///    exactly where they were, the report is discharged, and the broadcast is offered again — in
///    the same call that adjudicated it.
/// 2. REAL. Another wallet on the same seed has spent the funding notes in a block this wallet has
///    not scanned. The same sync turns the same rejection into an ordinary evidence-backed
///    `InputsSpent` mark, and — the whole planned crossing value now unsatisfiable — a `Replan`.
///
/// The distinction is never taken from the node: both rejections are reported identically, and the
/// wallet's own view is what separates them.
#[test]
#[cfg_attr(
    feature = "ignore-expensive-tests",
    ignore = "covered by the expensive-test CI matrix"
)]
fn a_rejected_broadcast_is_withheld_until_the_wallet_can_adjudicate_it() {
    const SINGLE_CROSSING: &str = "Gwen, 0.0152 ZEC (a single minimum-denomination note)";
    let scenario = scenarios()
        .into_iter()
        .find(|scenario| scenario.label == SINGLE_CROSSING)
        .expect("the single-crossing scenario exists");

    let mut run = Run::setup(&scenario);
    let mut committed = run.plan_and_commit(&scenario);
    let transfer_id = run.drive_to_first_transfer_broadcast(&mut committed);

    let transfer = |state: &MigrationState| {
        state
            .transactions()
            .iter()
            .find(|t| t.id() == transfer_id)
            .expect("the crossing is present")
            .clone()
    };

    // (1) THE TRANSIENT REJECTION. A block is mined that this wallet has not scanned — nothing in
    // it touches the account — and the node the wallet submits to reports that tip when it
    // refuses the transaction.
    let (node_tip, _) = run.st.generate_empty_block();
    assert!(
        run.fully_scanned_height() < node_tip,
        "the broadcast session did not sync, so the node knows a chain the wallet does not",
    );
    committed
        .state
        .report_broadcast_failure(transfer_id, node_tip);
    run.persist(&committed.state);

    assert_eq!(
        run.advance(&mut committed.state),
        AdvanceStep::Reevaluate,
        "an unadjudicated rejection outranks every other step",
    );
    assert!(
        committed
            .state
            .transactions()
            .iter()
            .all(|t| t.unsatisfiable_at().is_none()),
        "testimony from another observer never marks",
    );
    assert_eq!(
        committed
            .state
            .transaction_statuses(run.targets())
            .iter()
            .find(|s| s.id() == transfer_id)
            .expect("the crossing is present")
            .blocked_on(),
        Some(Blocker::AwaitingReevaluation),
    );

    // The wallet syncs at its next wake-up, and the oracle can now answer about the chain the
    // node named. Nothing obstructs the crossing, so the rejection was transient.
    run.st.scan_cached_blocks(node_tip, 1);
    assert_eq!(
        run.advance(&mut committed.state),
        AdvanceStep::Broadcast { id: transfer_id },
        "a discharged report returns the crossing to the broadcast queue in the same call",
    );
    assert_eq!(transfer(&committed.state).broadcast_failure_at(), None);
    assert_eq!(
        transfer(
            &run.stored_migration()
                .expect("the store holds the migration")
        )
        .broadcast_failure_at(),
        None,
        "the discharge is durable before the step is surfaced",
    );

    // (2) THE REAL REJECTION. Another wallet on the same seed sweeps the account; the spend is
    // mined in a block this wallet has not scanned, so its own tables still show the funding note
    // unspent — and the node refuses the crossing that spends it. The sibling holds no record of
    // this wallet's proved-but-unbroadcast crossing, so its selection is free to take the funding
    // note this wallet's own selection would refuse; lifting the pending spend marks is what
    // lets this wallet's machinery enact the sibling's sweep.
    run.forget_pending_spend_marks(transfer(&committed.state).txid());
    let sweep_tip = run.sweep_to_external_unscanned();
    assert!(run.fully_scanned_height() < sweep_tip);
    committed
        .state
        .report_broadcast_failure(transfer_id, sweep_tip);
    run.persist(&committed.state);

    assert_eq!(
        run.advance(&mut committed.state),
        AdvanceStep::Reevaluate,
        "the second rejection is reported exactly like the first",
    );
    assert_eq!(
        transfer(&committed.state).unsatisfiable(),
        None,
        "and is no more evidence than the first was",
    );

    // The same sync, the opposite verdict: the wallet now sees its own note spent by a mined
    // transaction, which is evidence, and the ordinary marking machinery takes over.
    run.st.scan_cached_blocks(sweep_tip, 1);
    let as_of_height = run.fully_scanned_height();
    assert_eq!(
        run.advance(&mut committed.state),
        AdvanceStep::Replan,
        "the whole planned crossing value is unsatisfiable, past the committed threshold",
    );
    let adjudicated = transfer(&committed.state);
    assert_eq!(
        adjudicated.unsatisfiable(),
        Some((as_of_height, satisfiability::UnsatisfiableKind::InputsSpent)),
        "the rejection is adjudicated into a mark resting on the wallet's own scanned evidence",
    );
    assert_eq!(
        adjudicated.broadcast_failure_at(),
        None,
        "and the testimony that raised the question is discharged",
    );
    let stored = transfer(
        &run.stored_migration()
            .expect("the store holds the migration"),
    );
    assert_eq!(
        (stored.unsatisfiable(), stored.broadcast_failure_at()),
        (
            Some((as_of_height, satisfiability::UnsatisfiableKind::InputsSpent)),
            None
        ),
        "both survive the round trip through the SQLite store",
    );
    assert!(committed.state.replan_required());
}

/// The transaction the stored proven PCZT for `id` extracts to.
fn extract_proven(state: &MigrationState, id: MigrationTransferId) -> Transaction {
    let proven = state
        .transactions()
        .iter()
        .find(|t| t.id() == id)
        .expect("the transaction is present");
    TransactionExtractor::new(pczt::Pczt::parse(proven.pczt()).expect("parses the proven PCZT"))
        .extract()
        .expect("extracts and verifies the transaction's proofs")
}

/// A settled reorg that reaches BELOW a broadcast crossing's anchor boundary: the chain state its
/// proof was made over is gone, so as proven it can never be mined, and no amount of waiting or
/// re-broadcasting will change that.
///
/// This is the anchor-validity arm of the satisfiability oracle, driven over a real chain. The
/// setup makes the displacement genuine rather than incidental: a wallet note arrives BELOW the
/// crossing's boundary, so the tree the crossing anchors to contains a commitment the reorg
/// discards, and the replacement chain never commits it. The installed anchor is therefore the
/// root of no block of the chain the wallet now holds — which is exactly the condition the oracle
/// must establish before marking, since consensus accepts an anchor that is the root of ANY
/// previous block and a reorg that merely re-arranges the same outputs leaves the old root live.
///
/// `advance_migration`'s in-flight sweep is what finds it. A broadcast-but-unmined transaction is
/// never named as a step, so no candidate check would ever reach it; the sweep asks after exactly
/// this one question, for exactly this set of transactions.
#[test]
#[cfg_attr(
    feature = "ignore-expensive-tests",
    ignore = "covered by the expensive-test CI matrix"
)]
fn a_settled_reorg_below_a_broadcast_crossings_anchor_marks_it() {
    const SINGLE_CROSSING: &str = "Gwen, 0.0152 ZEC (a single minimum-denomination note)";
    let scenario = scenarios()
        .into_iter()
        .find(|scenario| scenario.label == SINGLE_CROSSING)
        .expect("the single-crossing scenario exists");

    let mut run = Run::setup(&scenario);
    let mut committed = run.plan_and_commit(&scenario);
    run.drive_preparations(&mut committed);

    let (transfer_id, boundary) = {
        let transfer = committed
            .state
            .transactions()
            .iter()
            .find(|t| matches!(t.kind(), MigrationTxKind::Transfer { .. }))
            .expect("the migration has a crossing");
        (
            transfer.id(),
            transfer
                .anchor_boundary()
                .expect("a committed transfer carries its boundary"),
        )
    };

    // A wallet note arrives just BELOW the crossing's anchor boundary, so the tree state the
    // crossing anchors to contains a commitment that exists only on this chain. Without it, a
    // reorg below the boundary would leave the boundary's root unchanged — the empty blocks in
    // between add nothing to the tree — and the installed anchor would still be live, which is
    // the answer the oracle should give and not the one under test here.
    //
    // It sits just below the boundary on purpose: the fork must stay inside the wallet's rewind
    // window (this crate retains the most recent hundred checkpoints), and a deeper fork could
    // not be truncated to at all.
    assert!(
        run.tip() + 2 < boundary,
        "the preparations mined well below the crossing's boundary",
    );
    while run.tip() + 2 < boundary {
        run.mine_empty_block();
    }
    let fvk = run.fvk.clone();
    let (note_height, _, _) =
        run.st
            .generate_next_block(&fvk, AddressType::DefaultExternal, zats(COIN / 10));
    run.st.scan_cached_blocks(note_height, 1);
    assert_eq!(note_height + 1, boundary);

    // Prove the crossing against that boundary, then record its submission. The privacy schedule
    // would put the broadcast step many blocks further on, and driving there would carry the chain
    // past the point where the reorg below the boundary is still a rewind the wallet can perform;
    // what is under test is the judgment made on a transaction ALREADY in flight, so the
    // submission is recorded through the same mutator a consumer calls after submitting.
    let mut waited = 0u32;
    loop {
        match run.advance(&mut committed.state) {
            AdvanceStep::Prove { transactions } => {
                assert_eq!(
                    transactions.iter().map(|t| t.id()).collect::<Vec<_>>(),
                    vec![transfer_id]
                );
                assert_eq!(
                    run.perform_prove(&mut committed.state, transfer_id, transactions[0].kind()),
                    ProveStepOutcome::Proved,
                );
                break;
            }
            AdvanceStep::Waiting => {
                assert!(
                    waited < MAX_WAITING_BLOCKS,
                    "the crossing never became provable"
                );
                waited += 1;
                run.mine_empty_block();
            }
            other => panic!("a healthy migration never needs {other:?}"),
        }
    }
    assert_eq!(
        extract_proven(&committed.state, transfer_id).txid(),
        committed
            .state
            .transactions()
            .iter()
            .find(|t| t.id() == transfer_id)
            .expect("the transfer is stored")
            .txid(),
        "the stored id must be the extracted transaction's own",
    );
    committed.state.mark_broadcast(transfer_id);
    run.persist(&committed.state);

    // The reorg. The wallet truncates to below the interposed note and re-scans a chain whose
    // replacement blocks carry no notes at all, and the consumer's reorg hook rolls the migration
    // back with it (nothing to roll back yet: the crossing is in flight and unmarked).
    let fork = note_height - 1;
    run.st.truncate_to_height(fork);
    committed.state.truncate_to_height(fork);
    run.persist(&committed.state);

    // Rebuild the chain past the boundary, and then past it by the settle depth: only then is the
    // displacement definitive.
    while run.tip() < boundary + ADVANCE.reorg_settle_depth().blocks() - 1 {
        run.mine_empty_block();
    }
    let unsettled = run.fully_scanned_height();
    assert_eq!(
        unsettled,
        boundary + (ADVANCE.reorg_settle_depth().blocks() - 1),
        "the chain sits one block short of the settle depth",
    );
    assert_eq!(
        run.advance(&mut committed.state),
        AdvanceStep::Waiting,
        "one block short of the settle depth, the displacement concludes nothing",
    );
    assert!(
        committed
            .state
            .transactions()
            .iter()
            .all(|t| t.unsatisfiable_at().is_none()),
        "nothing is marked before the displacement settles",
    );

    // One more block, and the displacement is settled: the in-flight sweep marks the crossing at
    // the height the observation rests on, the whole planned crossing value is unsatisfiable, and
    // the migration is re-planned.
    run.mine_empty_block();
    let as_of_height = run.fully_scanned_height();
    assert_eq!(
        run.advance(&mut committed.state),
        AdvanceStep::Replan,
        "a crossing whose anchor a settled reorg destroyed is re-planned, not retried",
    );
    assert_eq!(
        committed
            .state
            .transactions()
            .iter()
            .find(|t| t.id() == transfer_id)
            .expect("the crossing is present")
            .unsatisfiable_at(),
        Some(as_of_height),
        "the mark carries the fully-scanned height the observation rests on",
    );
    assert_eq!(
        run.stored_migration()
            .expect("the store holds the migration")
            .transactions()
            .iter()
            .find(|t| t.id() == transfer_id)
            .expect("the crossing is present")
            .unsatisfiable_at(),
        Some(as_of_height),
        "the in-flight sweep's mark is persisted before the step is surfaced",
    );

    // And it is exactly as revocable as the chain it rests on: a rewind below the mark's stamp
    // clears it, because the state that displaced the anchor no longer exists either.
    committed.state.truncate_to_height(as_of_height - 1);
    assert!(
        committed
            .state
            .transactions()
            .iter()
            .all(|t| t.unsatisfiable_at().is_none()),
        "reorg truncation below the mark's stamp clears it",
    );
}
