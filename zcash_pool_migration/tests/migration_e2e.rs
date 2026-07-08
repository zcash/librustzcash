//! Seeded-wallet end-to-end integration tests for the migration engine (spec Task 13).
//!
//! These exercise the REAL pipelines — input selection, PCZT construction, the first genuine
//! Ironwood proof, software signing, finalization, extraction, broadcast-result handling, and
//! on-launch reconciliation — against a wallet database that has been seeded with spendable
//! Orchard notes and scanned by the upstream `data_api::testing` harness, closing the prototype's
//! "backend compile-verified only" gap (spec D10).
//!
//! ## Harness mechanism
//!
//! `MigrationContext` re-opens the wallet database at a path on every call, so the fixture must be
//! a real file. The `zcash_client_sqlite` binding of the upstream harness (`TestDbFactory`/
//! `TestDb`) is `#[cfg(test)]`-private and therefore unavailable here, so this test supplies its
//! own [`DataStoreFactory`] ([`FileDbFactory`]) that opens a `WalletDb` at a path we control (kept
//! alive by a `TempDir`) and an in-memory [`TestCache`] ([`MemCache`], a `BlockSource` over
//! `CompactBlock`s — no `prost` needed). The upstream `TestBuilder`/`TestScenario` then create the
//! account, generate blocks funding it with Orchard notes, and scan them; afterwards a
//! `MigrationContext` opens the same file and drives the migration.

use std::collections::BTreeMap;
use std::convert::Infallible;
use std::path::{Path, PathBuf};

use rand::rngs::OsRng;
use rusqlite::Connection;
use tempfile::TempDir;

use zcash_client_backend::data_api::Account as _;
use zcash_client_backend::data_api::chain::BlockSource;
use zcash_client_backend::data_api::chain::error::Error as ChainError;
use zcash_client_backend::data_api::testing::orchard::OrchardPoolTester;
use zcash_client_backend::data_api::testing::pool::dsl::{TestDsl, TestScenario};
use zcash_client_backend::data_api::testing::{
    CacheInsertionResult, DataStoreFactory, TestBuilder, TestCache,
};
use zcash_client_backend::proto::compact_formats::CompactBlock;
use zcash_client_sqlite::error::SqliteClientError;
use zcash_client_sqlite::util::SystemClock;
use zcash_client_sqlite::wallet::Account;
use zcash_client_sqlite::wallet::init::WalletMigrator;
use zcash_client_sqlite::{AccountUuid, WalletDb};
use zcash_keys::keys::transparent::gap_limits::GapLimits;
use zcash_primitives::block::BlockHash;
use zcash_primitives::transaction::{Transaction, TxVersion};
use zcash_protocol::TxId;
use zcash_protocol::consensus::{BlockHeight, BranchId};
use zcash_protocol::local_consensus::LocalNetwork;
use zcash_protocol::value::Zatoshis;

use zcash_pool_migration::MigrationContext;
use zcash_pool_migration::types::{MigrationState, TransferResult};

// ======================================================================================
// In-memory block cache (a `TestCache` whose `BlockSource` holds `CompactBlock`s directly, so no
// serialization dependency is needed — the sqlite `BlockCache` is `#[cfg(test)]`-private).
// ======================================================================================

#[derive(Default)]
struct MemBlockSource {
    blocks: BTreeMap<u32, CompactBlock>,
}

impl BlockSource for MemBlockSource {
    type Error = Infallible;

    fn with_blocks<F, WalletErrT>(
        &self,
        from_height: Option<BlockHeight>,
        limit: Option<usize>,
        mut with_block: F,
    ) -> Result<(), ChainError<WalletErrT, Infallible>>
    where
        F: FnMut(CompactBlock) -> Result<(), ChainError<WalletErrT, Infallible>>,
    {
        let start = from_height.map_or(0u32, u32::from);
        for (_, cb) in self.blocks.range(start..).take(limit.unwrap_or(usize::MAX)) {
            with_block(cb.clone())?;
        }
        Ok(())
    }
}

struct MemInsert {
    txids: Vec<TxId>,
}

impl CacheInsertionResult for MemInsert {
    fn txids(&self) -> &[TxId] {
        &self.txids
    }
}

struct MemCache {
    source: MemBlockSource,
}

impl MemCache {
    fn new() -> Self {
        MemCache {
            source: MemBlockSource::default(),
        }
    }
}

impl TestCache for MemCache {
    type BsError = Infallible;
    type BlockSource = MemBlockSource;
    type InsertResult = MemInsert;

    fn block_source(&self) -> &Self::BlockSource {
        &self.source
    }

    fn insert(&mut self, cb: &CompactBlock) -> Self::InsertResult {
        let txids = cb.vtx.iter().map(|tx| tx.txid()).collect();
        self.source
            .blocks
            .insert(u32::from(cb.height()), cb.clone());
        MemInsert { txids }
    }

    fn truncate_to_height(&mut self, height: BlockHeight) {
        let h = u32::from(height);
        self.source.blocks.retain(|&k, _| k <= h);
    }
}

// ======================================================================================
// File-backed data store factory: creates the wallet DB at a caller-controlled path (so a
// `MigrationContext` can re-open the same file), then runs the wallet migrations.
// ======================================================================================

type FileWalletDb = WalletDb<Connection, LocalNetwork, SystemClock, OsRng>;

struct FileDbFactory {
    path: PathBuf,
}

impl DataStoreFactory for FileDbFactory {
    type Error = ();
    type AccountId = AccountUuid;
    type Account = Account;
    type DsError = SqliteClientError;
    type DataStore = FileWalletDb;

    fn new_data_store(
        &self,
        network: LocalNetwork,
        gap_limits: Option<GapLimits>,
    ) -> Result<Self::DataStore, Self::Error> {
        let mut db = WalletDb::for_path(&self.path, network, SystemClock, OsRng).unwrap();
        if let Some(gap_limits) = gap_limits {
            db = db.with_gap_limits(gap_limits);
        }
        WalletMigrator::new()
            .init_or_migrate(&mut db)
            .expect("wallet migration succeeds for the e2e fixture");
        Ok(db)
    }
}

// ======================================================================================
// Fixture helpers
// ======================================================================================

/// A `LocalNetwork` on which NU6.3 — and thus the version-6 transaction format and the Ironwood
/// value pool — is active from height 100_000 (the harness's default Sapling activation), so the
/// seeded Orchard notes and the migration transfers all live in the post-NU6.3 regime.
fn ironwood_active_network() -> LocalNetwork {
    let activation = BlockHeight::from_u32(100_000);
    LocalNetwork {
        nu6: Some(activation),
        nu6_1: Some(activation),
        nu6_2: Some(activation),
        nu6_3: Some(activation),
        ..TestBuilder::<(), ()>::DEFAULT_NETWORK
    }
}

type Scenario = TestDsl<TestScenario<OrchardPoolTester, MemCache, FileDbFactory>>;

/// Builds a seeded, scanned wallet fixture: an account funded with one Orchard note per value in
/// `note_values`, plus `extra_confirmations` empty blocks so the notes are spendable under
/// `ConfirmationsPolicy::default()` (trusted 3 / untrusted 10). Returns the temp dir (kept alive
/// for the DB file's lifetime), the live harness scenario, the DB path, and the account uuid.
fn seed_wallet(
    note_values: &[u64],
    extra_confirmations: usize,
) -> (TempDir, Scenario, PathBuf, AccountUuid) {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("wallet.sqlite");
    let mut st: Scenario = TestDsl::from(
        TestBuilder::new()
            .with_network(ironwood_active_network())
            .with_data_store_factory(FileDbFactory {
                path: db_path.clone(),
            })
            .with_block_cache(MemCache::new())
            .with_account_from_sapling_activation(BlockHash([0; 32])),
    )
    .build::<OrchardPoolTester>();

    for &value in note_values {
        st.add_a_single_note_checking_balance(Zatoshis::const_from_u64(value));
    }
    if extra_confirmations > 0 {
        st.add_empty_blocks(extra_confirmations);
    }

    let account_uuid = st.get_account().id();
    (dir, st, db_path, account_uuid)
}

/// Reads the single migration run's persisted phase directly from the engine's own table (the
/// public API deliberately hides terminal runs, so completion must be asserted on the raw row).
fn read_run_phase(db_path: &Path) -> String {
    let conn = Connection::open(db_path).unwrap();
    conn.query_row(
        "SELECT phase FROM ext_ironwood_migration_runs ORDER BY created_at_ms DESC LIMIT 1",
        [],
        |row| row.get::<_, String>(0),
    )
    .unwrap()
}

/// Net zatoshi crossing into the Ironwood pool carried by a transfer's Ironwood bundle (the bundle
/// only ever has outputs on a migration transfer, so its value balance is negative and its
/// magnitude is the value that crosses).
fn ironwood_value_in(tx: &Transaction) -> i64 {
    let bundle = tx
        .ironwood_bundle()
        .expect("migration tx carries an Ironwood bundle");
    -i64::from(*bundle.value_balance())
}

/// Net zatoshi leaving the Orchard pool carried by a transfer's Orchard bundle (spends minus any
/// same-pool change).
fn orchard_value_out(tx: &Transaction) -> i64 {
    let bundle = tx
        .orchard_bundle()
        .expect("migration tx carries an Orchard bundle");
    i64::from(*bundle.value_balance())
}

// ======================================================================================
// Test 2 (written first): the transfer pipeline produces a V6 tx carrying an Ironwood crossing.
// ======================================================================================

/// The migration-transfer pipeline, end to end against a seeded wallet: propose a schedule, sign
/// and persist it (the first REAL Ironwood proof), pull the due transfer, extract its consensus
/// transaction, and assert it is a version-6 transaction that spends Orchard and crosses value
/// into Ironwood with the scheduled expiry. Records the observed change-routing pool (spec §10.1).
#[test]
fn transfer_pipeline_produces_a_v6_ironwood_crossing_tx() {
    // D = 1 ZEC crosses. Seed 1e8 + 100_000: `plan_denominations` reserves a 10_000 prep-fee
    // estimate then decomposes, so budget 100_090_000 yields exactly one 1-ZEC crossing (a bare
    // D + 20_000 note would instead decompose to a 0.1-ZEC crossing, since the reserved estimate
    // pushes it below the 1-ZEC + buffer threshold). The residual funds the transfer's own fee.
    const D: u64 = 100_000_000;
    let (_dir, st, db_path, account) = seed_wallet(&[D + 100_000], 10);
    let usk = st.get_account().usk().clone();
    // Release the harness's wallet connection before the context opens the same file.
    drop(st);

    let ctx = MigrationContext::new(&db_path, ironwood_active_network(), account).unwrap();

    let start = std::time::Instant::now();
    let schedule = ctx.propose_migration_transfers().unwrap();
    assert_eq!(
        schedule.transfers().len(),
        1,
        "one crossing for a 1-ZEC plan"
    );
    let transfer = &schedule.transfers()[0];
    assert_eq!(
        u64::from(transfer.amount()),
        D,
        "the scheduled crossing is exactly D"
    );
    let expected_expiry = u32::from(transfer.expiry_height());
    assert_eq!(
        expected_expiry,
        u32::from(transfer.next_executable_after_height()) + 288,
        "expiry is the send window + 288 blocks"
    );

    ctx.sign_and_store_migration_schedule(&schedule, &usk)
        .unwrap();
    let elapsed = start.elapsed();
    eprintln!("IRONWOOD-PROOF transfer sign+prove took {elapsed:?}");

    let due = ctx.next_due_transfer().unwrap().expect("a transfer is due");
    let raw_tx = ctx.extract_broadcast_tx(due.pczt_bytes()).unwrap();
    let tx = Transaction::read(&raw_tx[..], BranchId::Nu6_3).expect("extracted tx parses as V6");

    // §10.1 evidence: a version-6 transaction that spends Orchard and crosses value into Ironwood.
    assert!(matches!(tx.version(), TxVersion::V6), "tx is version 6");
    assert!(
        !tx.orchard_bundle()
            .expect("orchard bundle present")
            .actions()
            .is_empty(),
        "the Orchard bundle spends the note"
    );
    assert!(
        !tx.ironwood_bundle()
            .expect("ironwood bundle present")
            .actions()
            .is_empty(),
        "the Ironwood bundle carries the crossing output"
    );
    assert_eq!(
        u32::from(tx.expiry_height()),
        expected_expiry,
        "the pre-signed transfer's consensus expiry matches the schedule"
    );

    // §10.1 change routing (the observation this test exists to make): the transfer spends a
    // note worth D + 100_000, crosses exactly D into Ironwood, and pays a 20_000 fee, leaving an
    // 80_000 residual. OBSERVED: `ironwood_value_in == D` exactly — the residual did NOT cross
    // into Ironwood; it stayed in the Orchard pool as change. This validates `backend.rs`'s change
    // fallback (`ShieldedPool::Orchard`): a V6 migration transfer routes its crossing (payment) to
    // Ironwood while returning change to Orchard, rather than sweeping change across the turnstile.
    let iw_in = ironwood_value_in(&tx);
    let orch_out = orchard_value_out(&tx);
    let fee = orch_out - iw_in;
    assert_eq!(
        iw_in, D as i64,
        "exactly the crossing D lands in Ironwood; change did NOT route to Ironwood"
    );
    assert_eq!(
        orch_out,
        D as i64 + fee,
        "the Orchard bundle nets out only the crossing + fee, keeping the residual as Orchard change"
    );
    assert_eq!(
        fee, 20_000,
        "the ZIP-317 transfer fee (2 Orchard + 2 Ironwood actions)"
    );
}

// ======================================================================================
// Test 1: the note split plans and signs against the seeded wallet.
// ======================================================================================

/// The denomination note-split, end to end: plan the split for a seeded multi-ZEC balance, assert
/// the plan matches the hand-computed power-of-ten decomposition, sign it (a real Orchard proof),
/// and assert the extracted transaction is an Orchard-only split with one action per spend and per
/// change output, and that the run is persisted in `preparing_denominations` and advances on a
/// recorded broadcast.
#[test]
fn note_split_plans_and_signs_against_a_seeded_wallet() {
    // 12.0007 ZEC decomposes (after the 10_000 prep-fee reserve) into exactly [10, 1, 1] ZEC
    // crossings, i.e. three self-funding output notes.
    let seed_value = 1_200_070_000u64;
    let (_dir, st, db_path, account) = seed_wallet(&[seed_value], 10);
    let usk = st.get_account().usk().clone();
    drop(st);

    let ctx = MigrationContext::new(&db_path, ironwood_active_network(), account).unwrap();

    let proposal = ctx.prepare_note_split().unwrap();
    // Expected plan: each crossing power-of-ten + the 20_000 self-funding buffer.
    let expected: Vec<Zatoshis> = [1_000_020_000u64, 100_020_000, 100_020_000]
        .into_iter()
        .map(Zatoshis::const_from_u64)
        .collect();
    assert_eq!(
        proposal.output_values(),
        &expected[..],
        "the split plan is the hand-computed power-of-ten decomposition"
    );
    let n_denoms = proposal.output_values().len();

    let prepared = ctx.sign_note_split(&proposal, &usk).unwrap();
    assert!(
        prepared.id().as_str().starts_with("prep:"),
        "the split is the run's prep transaction"
    );

    let raw_tx = ctx.extract_broadcast_tx(prepared.pczt_bytes()).unwrap();
    let tx = Transaction::read(&raw_tx[..], BranchId::Nu6_3).expect("split tx parses");
    // The split is a same-pool consolidation: an Orchard bundle only, no Ironwood crossing.
    let orchard = tx.orchard_bundle().expect("orchard bundle present");
    assert_eq!(
        orchard.actions().len(),
        1 + n_denoms,
        "one action per spend (1) plus one per change output (denominations)"
    );
    assert!(
        tx.ironwood_bundle().is_none_or(|b| b.actions().is_empty()),
        "a note split never crosses into Ironwood"
    );

    // The run is persisted in the split phase, and a recorded broadcast advances it.
    assert_eq!(read_run_phase(&db_path), "preparing_denominations");
    ctx.record_transfer_result(prepared.id(), TransferResult::Success(prepared.txid()))
        .unwrap();
    assert_eq!(
        read_run_phase(&db_path),
        "waiting_denom_confirmations",
        "recording the split broadcast advances the run"
    );
    assert_eq!(
        ctx.migration_state().unwrap(),
        MigrationState::SplitPendingConfirmation
    );
}

// ======================================================================================
// Test 3: a recorded broadcast + scan advances the run to a persisted completion.
// ======================================================================================

/// Drives a real migration to completion: an immediate (single-transfer, whole-balance) migration
/// is proposed, signed, and its broadcast recorded (→ `InProgress`); then the extracted transaction
/// is mined and scanned by the harness, so the Orchard note drains and the Ironwood balance
/// appears. `migration_state()` then detects completion and PERSISTS `Phase::Complete` (spec Part
/// B), which is asserted on the raw run row.
#[test]
fn record_transfer_result_advances_to_complete() {
    let (_dir, mut st, db_path, account) = seed_wallet(&[100_000_000], 10);
    let usk = st.get_account().usk().clone();

    let ctx = MigrationContext::new(&db_path, ironwood_active_network(), account).unwrap();

    // Immediate migration: the whole balance crosses in one transfer, leaving no Orchard change,
    // so the Orchard pool fully drains once the transfer is scanned.
    let schedule = ctx.propose_immediate_migration_transfers().unwrap();
    assert_eq!(schedule.transfers().len(), 1);
    ctx.sign_and_store_migration_schedule(&schedule, &usk)
        .unwrap();

    let due = ctx.next_due_transfer().unwrap().expect("a transfer is due");
    let raw_tx = ctx.extract_broadcast_tx(due.pczt_bytes()).unwrap();
    let tx = Transaction::read(&raw_tx[..], BranchId::Nu6_3).expect("transfer tx parses");
    let txid = due.txid();

    // Record the broadcast: the run is in progress, the transfer marked broadcasted-not-confirmed.
    ctx.record_transfer_result(due.id(), TransferResult::Success(txid))
        .unwrap();
    assert!(
        matches!(
            ctx.migration_state().unwrap(),
            MigrationState::InProgress(_)
        ),
        "a broadcast-but-unmined transfer is in progress"
    );

    // Mine and scan the transfer for real: the Orchard spend drains the note and the Ironwood
    // output is credited to the account.
    let (h, _) = st.generate_next_block_from_tx(0, &tx);
    st.scan_cached_blocks(h, 1);
    st.add_empty_blocks(1);

    // Completion is detected and persisted.
    assert_eq!(
        ctx.migration_state().unwrap(),
        MigrationState::Complete,
        "orchard drained + ironwood credited => complete"
    );
    assert_eq!(
        read_run_phase(&db_path),
        "complete",
        "completion is persisted as the terminal phase (spec Part B)"
    );
}

// ======================================================================================
// Test 4: transfer execution is height-gated.
// ======================================================================================

/// A two-transfer schedule is height-gated: only the first transfer is due at the current tip; the
/// second becomes due only after the chain advances by the 288-block cadence.
#[test]
fn next_due_transfer_is_height_gated() {
    // Two separate 1-ZEC-fundable notes so each transfer spends its own (a single large note would
    // be reserved by the first transfer, starving the second).
    let (_dir, mut st, db_path, account) = seed_wallet(&[100_030_000, 100_030_000], 10);
    let usk = st.get_account().usk().clone();

    let ctx = MigrationContext::new(&db_path, ironwood_active_network(), account).unwrap();

    let schedule = ctx.propose_migration_transfers().unwrap();
    assert_eq!(schedule.transfers().len(), 2, "two 1-ZEC crossings");
    ctx.sign_and_store_migration_schedule(&schedule, &usk)
        .unwrap();

    // Only the first transfer is due at the current tip.
    let first = ctx
        .next_due_transfer()
        .unwrap()
        .expect("first transfer due");
    ctx.record_transfer_result(first.id(), TransferResult::Success(first.txid()))
        .unwrap();
    assert!(
        ctx.next_due_transfer().unwrap().is_none(),
        "the second transfer is gated one cadence (288 blocks) into the future"
    );

    // Advance the chain tip past the second transfer's send window.
    st.add_empty_blocks(289);

    let second = ctx
        .next_due_transfer()
        .unwrap()
        .expect("second transfer due after advancing 288 blocks");
    assert_ne!(
        first.txid(),
        second.txid(),
        "the newly-due transfer is the second one"
    );
}
