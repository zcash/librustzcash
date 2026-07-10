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

use zcash_client_backend::data_api::chain::BlockSource;
use zcash_client_backend::data_api::chain::error::Error as ChainError;
use zcash_client_backend::data_api::testing::orchard::OrchardPoolTester;
use zcash_client_backend::data_api::testing::pool::dsl::{TestDsl, TestScenario};
use zcash_client_backend::data_api::testing::{
    CacheInsertionResult, DataStoreFactory, TestBuilder, TestCache,
};
use zcash_client_backend::data_api::wallet::ConfirmationsPolicy;
use zcash_client_backend::data_api::{Account as _, WalletRead as _};
use zcash_client_backend::proto::compact_formats::CompactBlock;
use zcash_client_sqlite::error::SqliteClientError;
use zcash_client_sqlite::util::SystemClock;
use zcash_client_sqlite::wallet::Account;
use zcash_client_sqlite::wallet::init::WalletMigrator;
use zcash_client_sqlite::{AccountUuid, WalletDb};
use zcash_keys::keys::transparent::gap_limits::GapLimits;
use zcash_primitives::block::BlockHash;
use zcash_primitives::transaction::builder::DEFAULT_TX_EXPIRY_DELTA;
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

    // §10.2 evidence: `sign_and_store_migration_schedule` below performs this crate's first real
    // Ironwood proof (spec risk item 2 — confirming the Orchard-bundle vs Ironwood-bundle
    // proving-key/circuit-version pairing against upstream orchard 0.15 at the first proving
    // test).
    let schedule = ctx.propose_migration_transfers(false).unwrap();
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

/// The direct-builder counterpart of the test above: when the spent note is *exactly*
/// self-funding (`D + TRANSFER_FEE_BUFFER_ZATOSHI`, the shape a note split always mints), the
/// transfer pipeline builds it directly (no wallet fee/change-selection logic) rather than falling
/// back to the high-level input-selection pipeline — and produces no Orchard change output at all,
/// since the note's value covers the crossing plus fee exactly.
#[test]
fn transfer_pipeline_builds_self_funding_notes_directly_with_no_change() {
    const D: u64 = 100_000_000;
    const SELF_FUNDING_VALUE: u64 = D + 20_000; // TRANSFER_FEE_BUFFER_ZATOSHI
    let (_dir, st, db_path, account) = seed_wallet(&[SELF_FUNDING_VALUE], 10);
    let usk = st.get_account().usk().clone();
    drop(st);

    let ctx = MigrationContext::new(&db_path, ironwood_active_network(), account).unwrap();

    let schedule = ctx.propose_migration_transfers(false).unwrap();
    assert_eq!(
        schedule.transfers().len(),
        1,
        "one crossing for a 1-ZEC plan"
    );
    ctx.sign_and_store_migration_schedule(&schedule, &usk)
        .unwrap();

    let due = ctx.next_due_transfer().unwrap().expect("a transfer is due");
    let raw_tx = ctx.extract_broadcast_tx(due.pczt_bytes()).unwrap();
    let tx = Transaction::read(&raw_tx[..], BranchId::Nu6_3).expect("extracted tx parses as V6");

    let orchard = tx.orchard_bundle().expect("orchard bundle present");
    assert_eq!(
        orchard.actions().len(),
        2,
        "exactly one real spend plus the padded minimum — no real change output was added"
    );

    let iw_in = ironwood_value_in(&tx);
    let orch_out = orchard_value_out(&tx);
    assert_eq!(iw_in, D as i64, "exactly the crossing D lands in Ironwood");
    assert_eq!(
        orch_out, SELF_FUNDING_VALUE as i64,
        "the whole self-funding note's value leaves the Orchard pool — none of it comes back as \
         change"
    );
    assert_eq!(
        orch_out - iw_in,
        20_000,
        "the fee is exactly the self-funding buffer"
    );

    // The persisted pending row's fee/selected-note fields come from the direct-builder path
    // (`self_funding_pending_row`), not a `Proposal`'s shielded inputs.
    let conn = Connection::open(&db_path).unwrap();
    let (fee_zatoshi, selected_note_value): (i64, i64) = conn
        .query_row(
            "SELECT fee_zatoshi, selected_note_value FROM ext_ironwood_migration_pending_txs \
             WHERE txid_hex = ?1",
            [due.txid().to_string()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(fee_zatoshi, 20_000);
    assert_eq!(selected_note_value, SELF_FUNDING_VALUE as i64);
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
    // 12.0008 ZEC decomposes into exactly [10, 1, 1] ZEC crossings (three self-funding output
    // notes) with zero leftover, once the plan reserves the *real* split fee for 1 spend + 3
    // change outputs (20_000 zatoshi) rather than the flat prep-fee estimate — see
    // `note_split_leaves_a_genuine_leftover_as_plain_change` for the (much more common) case where
    // the balance does not divide evenly.
    let seed_value = 1_200_080_000u64;
    let (_dir, st, db_path, account) = seed_wallet(&[seed_value], 10);
    let usk = st.get_account().usk().clone();
    // Captured before the split is built: `build_split_pczt` (via `Builder::new`) computes this
    // same target height internally, and — absent an explicit override, which the split never
    // supplies — the builder's default `DEFAULT_TX_EXPIRY_DELTA` sets the split transaction's
    // expiry to `target + 40`.
    let target_height = u32::from(
        st.wallet()
            .get_target_and_anchor_heights(ConfirmationsPolicy::default().trusted())
            .unwrap()
            .unwrap()
            .0,
    );
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
    assert_eq!(
        u32::from(tx.expiry_height()),
        target_height + DEFAULT_TX_EXPIRY_DELTA,
        "the split never overrides the builder's default expiry (target + 40)"
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

/// The full pipeline, split through to transfer: once the note split's own self-funding notes are
/// mined and spendable, `propose_migration_transfers` must re-derive the exact same crossing
/// values the split minted, and `sign_and_store_migration_schedule` must spend each one directly
/// (no wallet change output) rather than falling back to the ordinary input-selection pipeline —
/// proving the two halves of the pipeline actually agree with each other, not just each in
/// isolation.
#[test]
fn split_then_transfer_pipeline_spends_self_funding_notes_directly() {
    // Same seed as `note_split_plans_and_signs_against_a_seeded_wallet`: divides evenly into
    // [10, 1, 1] ZEC crossings (three self-funding notes), zero leftover.
    let seed_value = 1_200_080_000u64;
    let (_dir, mut st, db_path, account) = seed_wallet(&[seed_value], 10);
    let usk = st.get_account().usk().clone();

    let ctx = MigrationContext::new(&db_path, ironwood_active_network(), account).unwrap();

    // --- Phase 1: split, then mine + scan it for real ---
    let split_proposal = ctx.prepare_note_split().unwrap();
    let prepared_split = ctx.sign_note_split(&split_proposal, &usk).unwrap();
    let split_raw_tx = ctx
        .extract_broadcast_tx(prepared_split.pczt_bytes())
        .unwrap();
    let split_tx = Transaction::read(&split_raw_tx[..], BranchId::Nu6_3).expect("split tx parses");
    ctx.record_transfer_result(
        prepared_split.id(),
        TransferResult::Success(prepared_split.txid()),
    )
    .unwrap();

    let (h, _) = st.generate_next_block_from_tx(0, &split_tx);
    st.scan_cached_blocks(h, 1);
    // The split's own change outputs are "trusted" (wallet-produced), needing
    // `ConfirmationsPolicy::default()`'s 3 confirmations before they count as spendable — the
    // mined block is the first, so five more blocks leaves a comfortable margin.
    st.add_empty_blocks(5);

    assert_eq!(
        ctx.migration_state().unwrap(),
        MigrationState::ReadyToPropose,
        "the split's notes are mined and spendable"
    );

    // --- Phase 2: propose + sign the schedule against the now-real self-funding notes ---
    let schedule = ctx.propose_migration_transfers(false).unwrap();
    let mut crossings: Vec<u64> = schedule
        .transfers()
        .iter()
        .map(|t| u64::from(t.amount()))
        .collect();
    crossings.sort_unstable();
    assert_eq!(
        crossings,
        vec![100_000_000u64, 100_000_000, 1_000_000_000],
        "propose_migration_transfers reproduces exactly the split's own crossing values"
    );
    ctx.sign_and_store_migration_schedule(&schedule, &usk)
        .unwrap();

    // Every persisted transfer must have gone through the direct-builder path: exactly one real
    // spend plus the padded minimum, no Orchard change, and the self-funding fee — checked against
    // every pending row directly (order doesn't matter; the assertions are identical per row).
    let conn = Connection::open(&db_path).unwrap();
    let mut stmt = conn
        .prepare("SELECT raw_pczt, fee_zatoshi FROM ext_ironwood_migration_pending_txs")
        .unwrap();
    let rows: Vec<(Vec<u8>, i64)> = stmt
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(rows.len(), 3, "one persisted transfer per crossing");

    let mut observed_crossings: Vec<i64> = Vec::new();
    for (raw_pczt, fee_zatoshi) in rows {
        let raw_tx = ctx.extract_broadcast_tx(&raw_pczt).unwrap();
        let tx = Transaction::read(&raw_tx[..], BranchId::Nu6_3).expect("transfer tx parses");
        let orchard = tx.orchard_bundle().expect("orchard bundle present");
        assert_eq!(
            orchard.actions().len(),
            2,
            "direct-builder transfer: one real spend plus the padded minimum, no change"
        );
        assert_eq!(
            fee_zatoshi, 20_000,
            "direct-builder fee is the self-funding buffer"
        );
        observed_crossings.push(ironwood_value_in(&tx));
    }
    observed_crossings.sort_unstable();
    assert_eq!(
        observed_crossings,
        vec![100_000_000i64, 100_000_000, 1_000_000_000],
        "the same crossing values land in Ironwood as were scheduled"
    );
}

/// The much more common case: the spendable balance does not divide evenly into self-funding
/// notes plus the real split fee. The leftover must surface as its own plain, **unlocked** Orchard
/// change output — never folded into the last migration note's value (which would leak the
/// leftover amount when that note later crosses into Ironwood) and never tracked as a
/// migration-locked prepared note (it is ordinary balance, left for the wallet/user, not reserved
/// for a scheduled transfer).
#[test]
fn note_split_leaves_a_genuine_leftover_as_plain_change() {
    // 12.0007 ZEC: under the *real* fee for 1 spend + 3 change outputs (20_000 zatoshi), a third
    // 1-ZEC denomination would need 100_020_000 zatoshi but only 100_010_000 remains once two
    // notes are set aside — so the plan settles on two notes, and the ~1.0001 ZEC left over
    // becomes a real (unlocked) change output at signing time.
    let seed_value = 1_200_070_000u64;
    let (_dir, st, db_path, account) = seed_wallet(&[seed_value], 10);
    let usk = st.get_account().usk().clone();
    drop(st);

    let ctx = MigrationContext::new(&db_path, ironwood_active_network(), account).unwrap();

    let proposal = ctx.prepare_note_split().unwrap();
    let expected: Vec<Zatoshis> = [1_000_020_000u64, 100_020_000]
        .into_iter()
        .map(Zatoshis::const_from_u64)
        .collect();
    assert_eq!(
        proposal.output_values(),
        &expected[..],
        "the plan settles on two notes rather than force-fitting a third"
    );
    let n_denoms = proposal.output_values().len();

    let prepared = ctx.sign_note_split(&proposal, &usk).unwrap();
    let raw_tx = ctx.extract_broadcast_tx(prepared.pczt_bytes()).unwrap();
    let tx = Transaction::read(&raw_tx[..], BranchId::Nu6_3).expect("split tx parses");
    let orchard = tx.orchard_bundle().expect("orchard bundle present");
    assert_eq!(
        orchard.actions().len(),
        1 + n_denoms + 1,
        "one action per spend (1), one per migration note (denominations), plus one for the \
         genuine leftover change output"
    );

    // Only the two migration notes are migration-locked; the leftover change output is not
    // tracked in the engine's own tables at all — it is ordinary, unlocked Orchard balance.
    let conn = Connection::open(&db_path).unwrap();
    let locked: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM ext_ironwood_migration_prepared_notes \
             WHERE txid_hex = ?1 AND lock_state = 'locked'",
            [prepared.txid().to_string()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        locked, 2,
        "only the two self-funding migration notes are locked, not the leftover change"
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

/// The opt-in "also migrate the residual" toggle: a balance that leaves a genuine (non-dust)
/// residual is reported by `residual_after_migration`, excluded from the schedule by default, and
/// included as one extra non-round transfer when `include_residual` is set.
///
/// Seeds two *separate* notes — a self-funding 10-ZEC note plus a small change-shaped note — to
/// simulate a post-split wallet: the split's own note-split transaction is what actually produces
/// this shape (self-funding notes plus one plain, real leftover Orchard note), not a single raw
/// balance decomposed from scratch (which the round crossing's direct-builder spend would fully
/// consume before a residual transfer could exist to spend anything separately).
#[test]
fn residual_after_migration_is_opt_in() {
    const SELF_FUNDING_NOTE: u64 = 1_000_020_000; // 10 ZEC crossing + TRANSFER_FEE_BUFFER_ZATOSHI
    const RESIDUAL_NOTE: u64 = 130_000; // above RESIDUAL_MIGRATION_MIN_ZATOSHI (100_000)
    let (_dir, st, db_path, account) = seed_wallet(&[SELF_FUNDING_NOTE, RESIDUAL_NOTE], 10);
    let usk = st.get_account().usk().clone();
    drop(st);

    let ctx = MigrationContext::new(&db_path, ironwood_active_network(), account).unwrap();

    assert_eq!(
        ctx.residual_after_migration().unwrap(),
        Some(Zatoshis::const_from_u64(RESIDUAL_NOTE)),
        "the residual is reported since it clears the dust threshold"
    );

    // Default (opted out): only the round-number crossing is scheduled.
    let without_residual = ctx.propose_migration_transfers(false).unwrap();
    assert_eq!(
        without_residual.transfers().len(),
        1,
        "just the 10-ZEC crossing"
    );
    assert_eq!(
        u64::from(without_residual.transfers()[0].amount()),
        1_000_000_000
    );

    // Opted in: the residual is appended as one extra, non-round transfer, net of an estimated fee
    // (a residual has no self-funding buffer to pay its own fee from, unlike a split note).
    let with_residual = ctx.propose_migration_transfers(true).unwrap();
    let mut amounts: Vec<u64> = with_residual
        .transfers()
        .iter()
        .map(|t| u64::from(t.amount()))
        .collect();
    amounts.sort_unstable();
    assert_eq!(
        amounts,
        vec![RESIDUAL_NOTE - 20_000, 1_000_000_000],
        "the residual (net of the fee estimate) is scheduled alongside the round crossing"
    );

    // The round crossing spends the self-funding note directly (no change); the residual transfer
    // doesn't match any self-funding note, so it spends the separate residual note via the
    // ordinary input-selection pipeline instead.
    ctx.sign_and_store_migration_schedule(&with_residual, &usk)
        .unwrap();
    let conn = Connection::open(&db_path).unwrap();
    let mut stmt = conn
        .prepare("SELECT value_zatoshi, fee_zatoshi FROM ext_ironwood_migration_pending_txs")
        .unwrap();
    let rows: Vec<(i64, i64)> = stmt
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(rows.len(), 2);
    let residual_row = rows
        .iter()
        .find(|(value, _)| *value != 1_000_000_000)
        .expect("the residual transfer's pending row");
    assert_eq!(residual_row.0, (RESIDUAL_NOTE - 20_000) as i64);
    assert_eq!(
        residual_row.1, 20_000,
        "the fallback pipeline's own ZIP-317 computation pads to the same 2 Orchard + 2 Ironwood \
         actions as the direct-builder path, landing on the same fee here — but it was computed \
         independently by the wallet's own fee rule, not copied from TRANSFER_FEE_BUFFER_ZATOSHI"
    );
}

// ======================================================================================
// Test 4: transfer execution is height-gated.
// ======================================================================================

/// A two-transfer schedule is height-gated: only the first transfer is due at the current tip; the
/// second becomes due only once the chain has advanced far enough. The gap to the second
/// transfer's send height is now an independently sampled exponential (see `scheduling.rs`), not a
/// fixed cadence, so this test only relies on its documented hard cap
/// (`scheduling::MAX_CADENCE_BLOCKS`) rather than an exact block count — the height-gating query
/// itself (`next_executable_after_height <= target`) is already covered precisely by
/// `store::tests`.
#[test]
fn next_due_transfer_is_height_gated() {
    // Two separate 1-ZEC-fundable notes so each transfer spends its own (a single large note would
    // be reserved by the first transfer, starving the second).
    let (_dir, mut st, db_path, account) = seed_wallet(&[100_030_000, 100_030_000], 10);
    let usk = st.get_account().usk().clone();

    let ctx = MigrationContext::new(&db_path, ironwood_active_network(), account).unwrap();

    let schedule = ctx.propose_migration_transfers(false).unwrap();
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

    // Mine past the hard cap on any single sampled gap (`scheduling::MAX_CADENCE_BLOCKS`, a
    // crate-private constant — duplicated here as a plain literal since it isn't part of the
    // public API), guaranteeing the second transfer's send height has been reached regardless of
    // what its particular gap was sampled as.
    const MAX_CADENCE_BLOCKS: usize = 1152;
    st.add_empty_blocks(MAX_CADENCE_BLOCKS + 1);

    let second = ctx
        .next_due_transfer()
        .unwrap()
        .expect("second transfer due once its (capped) sampled gap has elapsed");
    assert_ne!(
        first.txid(),
        second.txid(),
        "the newly-due transfer is the second one"
    );
}
