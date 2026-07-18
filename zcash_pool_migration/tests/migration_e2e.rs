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

use incrementalmerkletree::Hashable;
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
use zcash_client_backend::data_api::wallet::{ConfirmationsPolicy, TargetHeight};
use zcash_client_backend::data_api::{
    Account as _, InputSource, WalletRead as _, WalletWrite as _,
};
use zcash_client_backend::proto::compact_formats::CompactBlock;
use zcash_client_sqlite::error::SqliteClientError;
use zcash_client_sqlite::util::SystemClock;
use zcash_client_sqlite::wallet::Account;
use zcash_client_sqlite::wallet::init::WalletMigrator;
use zcash_client_sqlite::{AccountUuid, WalletDb};
use zcash_keys::keys::transparent::gap_limits::GapLimits;
use zcash_primitives::block::BlockHash;
use zcash_primitives::transaction::builder::{BuildConfig, Builder, DEFAULT_TX_EXPIRY_DELTA};
use zcash_primitives::transaction::fees::zip317::FeeRule as Zip317FeeRule;
use zcash_primitives::transaction::{Transaction, TxVersion};
use zcash_protocol::ShieldedPool;
use zcash_protocol::TxId;
use zcash_protocol::consensus::{BlockHeight, BranchId};
use zcash_protocol::local_consensus::LocalNetwork;
use zcash_protocol::memo::MemoBytes;
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
    // Design spec §4.2: the self-funding note is spent directly, but via the placeholder-witness
    // path, so it is signed but not yet provable (`SignedAwaitingProof`) until
    // `finalize_ready_transfers` attaches its (already-witnessed, since the fixture mined 10
    // confirmations before the context ever opened the wallet) real witness/anchor and proves it.
    assert_eq!(
        ctx.finalize_ready_transfers().unwrap(),
        1,
        "the note is already witnessed, so finalize completes it in this same call"
    );

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
/// the plan matches the hand-computed `{1,2,5}x10^n` decomposition, sign it (a real Orchard proof),
/// and assert the extracted transaction is an Orchard-only split with one action per spend, per
/// migration note, and per genuine leftover change output, and that the run is persisted in
/// `preparing_denominations` and advances on a recorded broadcast.
#[test]
fn note_split_plans_and_signs_against_a_seeded_wallet() {
    // 12.0008 ZEC decomposes into exactly [10, 2] ZEC crossings (two self-funding output notes,
    // under the `{1,2,5}x10^n` denomination set) plus a small (25_000 zatoshi) genuine leftover,
    // once the plan reserves the *real* split fee for 1 spend + 2 change outputs (15_000 zatoshi)
    // rather than the flat prep-fee estimate — see
    // `note_split_leaves_a_genuine_leftover_as_plain_change` for a case where the leftover is
    // large enough to matter on its own.
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
    // Expected plan: each `{1,2,5}x10^n` crossing + the 20_000 self-funding buffer.
    let expected: Vec<Zatoshis> = [1_000_020_000u64, 200_020_000]
        .into_iter()
        .map(Zatoshis::const_from_u64)
        .collect();
    assert_eq!(
        proposal.output_values(),
        &expected[..],
        "the split plan is the hand-computed [1,2,5]x10^n decomposition"
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
        1 + n_denoms + 1,
        "one action per spend (1), one per migration note (denominations), plus one for the \
         genuine leftover change output"
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
    // Same seed as `note_split_plans_and_signs_against_a_seeded_wallet`: decomposes into
    // [10, 2] ZEC crossings (two self-funding notes) plus a small genuine leftover, which stays
    // below `MIGRATION_THRESHOLD_ZATOSHI` and is never scheduled for a transfer.
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
    // The split's own change outputs are "trusted" (wallet-produced), needing only
    // `ConfirmationsPolicy::default()`'s 3 confirmations to be spendable — but the anchor
    // `native_target_and_anchor` picks is pinned at the more conservative `untrusted()` depth (10),
    // since the same anchor is reused by the fallback ordinary-input-selection path, which may
    // spend untrusted-origin notes. Mine enough blocks to comfortably clear that 10-confirmation
    // anchor depth too, not just the trusted one.
    st.add_empty_blocks(10);

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
        vec![200_000_000u64, 1_000_000_000],
        "propose_migration_transfers reproduces exactly the split's own crossing values"
    );
    ctx.sign_and_store_migration_schedule(&schedule, &usk)
        .unwrap();
    // Design spec §4.2: both transfers are signed via the placeholder-witness path and start out
    // `SignedAwaitingProof`; both funding notes are already mined/witnessed (Phase 1 above), so
    // one `finalize_ready_transfers` call completes both, reusing the same anchor (§5).
    assert_eq!(
        ctx.finalize_ready_transfers().unwrap(),
        2,
        "both self-funding notes are already witnessed"
    );

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
    assert_eq!(rows.len(), 2, "one persisted transfer per crossing");

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
        vec![200_000_000i64, 1_000_000_000],
        "the same crossing values land in Ironwood as were scheduled"
    );
}

// ======================================================================================
// Test 5 (design spec `2026-07-17-migration-sign-now-prove-later-design.md`, §4): the two-stage
// `SignedAwaitingProof` -> `ReadyToBroadcast` flow. Unlike
// `split_then_transfer_pipeline_spends_self_funding_notes_directly` above (which mines a full 10
// confirmations for the split's own notes *before* signing the transfer schedule, so every
// self-funding note is already witnessed at sign time), this test signs the schedule while the
// split's own notes have only 3 confirmations — enough for `pool_balances`/`select_unspent_notes`
// to see them (their trusted-origin threshold), but nowhere near the untrusted 10-confirmation
// depth `native_target_and_anchor` pins the wallet's natural anchor at. This is exactly the shape
// of the live-device root cause spec §1 diagnoses: signing must not require the note to already be
// witnessable at the (deeper, untrusted) anchor height.
// ======================================================================================

/// Signs a migration schedule against self-funding notes that are confirmed but not yet witnessed
/// at the wallet's natural anchor, asserts the transfers are `SignedAwaitingProof` (not due, not
/// broadcastable), mines the split's outputs the rest of the way to being witnessed, calls
/// `finalize_ready_transfers`, and asserts the transfers are now `ReadyToBroadcast` and extract to
/// valid, correctly-shaped transactions.
#[test]
fn sign_now_prove_later_transfer_awaits_proof_until_funding_note_is_witnessed() {
    // Same seed as the note-split tests: decomposes into [10, 2] ZEC self-funding notes plus a
    // small genuine leftover (below `MIGRATION_THRESHOLD_ZATOSHI`, never scheduled).
    let seed_value = 1_200_080_000u64;
    let (_dir, mut st, db_path, account) = seed_wallet(&[seed_value], 10);
    let usk = st.get_account().usk().clone();

    let ctx = MigrationContext::new(&db_path, ironwood_active_network(), account).unwrap();

    // --- Phase 1: split, then mine it only up to 3 confirmations (trusted-origin spendable, but
    // far short of the untrusted 10-confirmation anchor depth) ---
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
    st.add_empty_blocks(2); // 3 confirmations total: enough for trusted-origin spendable balance.

    // --- Phase 2: propose + sign the schedule while the notes are confirmed but not yet
    // witnessable at the (deeper) natural anchor ---
    let schedule = ctx.propose_migration_transfers(false).unwrap();
    let mut crossings: Vec<u64> = schedule
        .transfers()
        .iter()
        .map(|t| u64::from(t.amount()))
        .collect();
    crossings.sort_unstable();
    assert_eq!(
        crossings,
        vec![200_000_000u64, 1_000_000_000],
        "the schedule reproduces the split's own crossing values even though the notes are not \
         witnessed at the natural anchor yet"
    );
    ctx.sign_and_store_migration_schedule(&schedule, &usk)
        .unwrap();

    // Both transfers are signed but must not be due yet: `SignedAwaitingProof`, not
    // `ReadyToBroadcast`.
    assert!(
        ctx.next_due_transfer().unwrap().is_none(),
        "a signed-but-unproven transfer is never due"
    );
    let conn = Connection::open(&db_path).unwrap();
    let awaiting: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM ext_ironwood_migration_pending_txs WHERE proof_status = 'awaiting_proof'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        awaiting, 2,
        "both self-funding transfers are persisted as SignedAwaitingProof"
    );

    // Finalizing now is a no-op: the notes are confirmed but not yet witnessable at the natural
    // (untrusted, 10-confirmation-deep) anchor.
    assert_eq!(
        ctx.finalize_ready_transfers().unwrap(),
        0,
        "not witnessed yet is a transient no-op, not an error (design spec §6)"
    );
    assert!(ctx.next_due_transfer().unwrap().is_none());

    // --- Phase 3: mine the rest of the way to a witnessable anchor, then finalize for real ---
    st.add_empty_blocks(10);
    assert_eq!(
        ctx.finalize_ready_transfers().unwrap(),
        2,
        "both notes are witnessed now, and finalizing reuses one anchor for both (design spec §5)"
    );

    // Every pending row is now ready, with a real (extractable, provable) PCZT.
    let mut stmt = conn
        .prepare("SELECT raw_pczt, proof_status FROM ext_ironwood_migration_pending_txs")
        .unwrap();
    let rows: Vec<(Vec<u8>, String)> = stmt
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(rows.len(), 2);

    let mut observed_crossings: Vec<i64> = Vec::new();
    for (raw_pczt, proof_status) in rows {
        assert_eq!(proof_status, "ready");
        let raw_tx = ctx.extract_broadcast_tx(&raw_pczt).unwrap();
        let tx = Transaction::read(&raw_tx[..], BranchId::Nu6_3).expect("finalized tx parses");
        assert!(matches!(tx.version(), TxVersion::V6));
        let orchard = tx.orchard_bundle().expect("orchard bundle present");
        assert_eq!(
            orchard.actions().len(),
            2,
            "direct-builder transfer: one real spend plus the padded minimum, no change"
        );
        assert!(
            !tx.ironwood_bundle()
                .expect("ironwood bundle present")
                .actions()
                .is_empty()
        );
        observed_crossings.push(ironwood_value_in(&tx));
    }
    observed_crossings.sort_unstable();
    assert_eq!(
        observed_crossings,
        vec![200_000_000i64, 1_000_000_000],
        "the finalized transactions carry exactly the scheduled crossings"
    );

    // And now due at the current tip (both transfers' send height is at-or-before the current
    // target — first_delay is 0, and the second transfer's independently sampled gap is bounded
    // by `scheduling::MAX_CADENCE_BLOCKS`; mine past it to be tip-independent of the exact draw).
    const MAX_CADENCE_BLOCKS: usize = 1152;
    st.add_empty_blocks(MAX_CADENCE_BLOCKS + 1);
    let first = ctx
        .next_due_transfer()
        .unwrap()
        .expect("first transfer due");
    ctx.record_transfer_result(first.id(), TransferResult::Success(first.txid()))
        .unwrap();
    let second = ctx
        .next_due_transfer()
        .unwrap()
        .expect("second transfer due");
    assert_ne!(first.txid(), second.txid());
}

/// The external-signer (Keystone) counterpart of
/// `sign_now_prove_later_transfer_awaits_proof_until_funding_note_is_witnessed`: proves that
/// `create_unsigned_transfer_pczts`/`store_signed_schedule_pczts` produce the exact same
/// `SignedAwaitingProof` outcome as the software-signing path for a self-funding transfer, built
/// entirely without touching the commitment tree (works before the funding note is witnessed) and
/// completed later by the same, unmodified `finalize_ready_transfers()`.
#[test]
fn external_signer_schedule_awaits_proof_until_funding_note_is_witnessed() {
    use zcash_pool_migration::types::SignedTransferPczt;

    // Same seed as the software-signing variant: decomposes into [10, 2] ZEC self-funding notes.
    let seed_value = 1_200_080_000u64;
    let (_dir, mut st, db_path, account) = seed_wallet(&[seed_value], 10);
    let usk = st.get_account().usk().clone();
    let ask = orchard::keys::SpendAuthorizingKey::from(usk.orchard());

    let ctx = MigrationContext::new(&db_path, ironwood_active_network(), account).unwrap();

    // --- Phase 1: split, mined to only 3 confirmations (same as the software-signing variant) ---
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
    st.add_empty_blocks(2);

    // --- Phase 2: propose, build UNSIGNED PCZTs for an external signer, "sign" them exactly the
    // way `placeholder_witness_synthetic_anchor_then_redacted_signs_successfully` signs a
    // hand-built one (mirrors what a real device would return), then store the signed set ---
    let schedule = ctx.propose_migration_transfers(false).unwrap();
    let mut crossings: Vec<u64> = schedule
        .transfers()
        .iter()
        .map(|t| u64::from(t.amount()))
        .collect();
    crossings.sort_unstable();
    assert_eq!(crossings, vec![200_000_000u64, 1_000_000_000]);

    let unsigned = ctx.create_unsigned_transfer_pczts(&schedule).unwrap();
    assert_eq!(unsigned.len(), 2);

    let signed: Vec<SignedTransferPczt> = unsigned
        .iter()
        .map(|u| {
            let pczt = pczt::Pczt::parse(u.pczt_bytes()).expect("unsigned pczt parses");
            let mut signer = pczt::roles::signer::Signer::new(pczt)
                .expect("signer inits fine with a placeholder witness/synthetic anchor");
            for index in 0.. {
                match signer.sign_orchard(index, &ask) {
                    Err(pczt::roles::signer::Error::InvalidIndex) => break,
                    Ok(())
                    | Err(pczt::roles::signer::Error::OrchardSign(
                        orchard::pczt::SignerError::WrongSpendAuthorizingKey,
                    )) => {}
                    Err(e) => panic!("sign orchard: {e:?}"),
                }
            }
            let signed_bytes = signer.finish().serialize().expect("serialize signed pczt");
            SignedTransferPczt::from_parts(u.id().clone(), signed_bytes)
        })
        .collect();
    ctx.store_signed_schedule_pczts(&signed).unwrap();

    // Same assertions as the software-signing variant: signed but not due, both awaiting proof.
    assert!(
        ctx.next_due_transfer().unwrap().is_none(),
        "a signed-but-unproven transfer is never due"
    );
    let conn = Connection::open(&db_path).unwrap();
    let awaiting: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM ext_ironwood_migration_pending_txs WHERE proof_status = 'awaiting_proof'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        awaiting, 2,
        "both externally-signed self-funding transfers are persisted as SignedAwaitingProof"
    );
    assert_eq!(
        ctx.finalize_ready_transfers().unwrap(),
        0,
        "not witnessed yet is a transient no-op, not an error (design spec §6)"
    );

    // --- Phase 3: mine to a witnessable anchor — the same unmodified `finalize_ready_transfers()`
    // completes both, exactly like the software-signing path ---
    st.add_empty_blocks(10);
    assert_eq!(
        ctx.finalize_ready_transfers().unwrap(),
        2,
        "both notes are witnessed now, and finalizing reuses one anchor for both (design spec §5)"
    );
    let ready: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM ext_ironwood_migration_pending_txs WHERE proof_status = 'ready'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(ready, 2, "both transfers are now proved and broadcastable");
}

/// The much more common case: the spendable balance does not divide evenly into self-funding
/// notes plus the real split fee. The leftover must surface as its own plain, **unlocked** Orchard
/// change output — never folded into the last migration note's value (which would leak the
/// leftover amount when that note later crosses into Ironwood) and never tracked as a
/// migration-locked prepared note (it is ordinary balance, left for the wallet/user, not reserved
/// for a scheduled transfer).
#[test]
fn note_split_leaves_a_genuine_leftover_as_plain_change() {
    // 12.0007 ZEC: under the *real* fee for 1 spend + 2 change outputs (15_000 zatoshi), the plan
    // settles on a [10, 2] ZEC pair of self-funding notes (same denominations as
    // `note_split_plans_and_signs_against_a_seeded_wallet`'s 12.0008 ZEC seed, since both budgets
    // land in the same {1,2,5}x10^n bracket after the split fee is reserved), and the ~0.0001 ZEC
    // left over becomes a real (unlocked) change output at signing time.
    let seed_value = 1_200_070_000u64;
    let (_dir, st, db_path, account) = seed_wallet(&[seed_value], 10);
    let usk = st.get_account().usk().clone();
    drop(st);

    let ctx = MigrationContext::new(&db_path, ironwood_active_network(), account).unwrap();

    let proposal = ctx.prepare_note_split().unwrap();
    let expected: Vec<Zatoshis> = [1_000_020_000u64, 200_020_000]
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
    // Design spec §4.2: this sweep transfer's crossing happens to match a self-funding note's
    // shape too (the whole balance minus the direct-builder's assumed fee), so it also signs via
    // the placeholder-witness path and needs finalizing before it is due. The seeded note is
    // already witnessed (10 confirmations mined before the context ever opened the wallet), so
    // one call completes it.
    assert_eq!(ctx.finalize_ready_transfers().unwrap(), 1);

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
    // Above MIGRATION_THRESHOLD_ZATOSHI (1_000_000, so it clears the dust floor and is reported),
    // but below MIGRATION_THRESHOLD_ZATOSHI + TRANSFER_FEE_BUFFER_ZATOSHI (1_020_000, so it can't
    // self-fund its own {1,2,5}x10^n note and instead surfaces as plain leftover change).
    const RESIDUAL_NOTE: u64 = 1_010_000;
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

    // Both transfers go through the direct-builder path and spend their own note with no change:
    // the round crossing matches the self-funding note, and the residual transfer's netted-out
    // crossing value (RESIDUAL_NOTE - TRANSFER_FEE_BUFFER_ZATOSHI) plus that same buffer is, by
    // construction, exactly RESIDUAL_NOTE — the residual note's real value.
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
        "the direct-builder fee, derived from spent-note-value minus crossing-value \
         (self_funding_pending_row) rather than hardcoded, still comes out to \
         TRANSFER_FEE_BUFFER_ZATOSHI for the residual note exactly as for a planned one"
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
    // Two separate self-funding notes at two *different* `{1,2,5}x10^n` denominations — 1 ZEC and
    // 0.5 ZEC — so each transfer spends its own note directly (no wallet change/re-selection
    // across the pair, which would otherwise let signing the first transfer starve the second).
    // Two notes at the *same* denomination would instead collapse into a single, larger crossing
    // under the greedy decomposition (e.g. two 1-ZEC notes summing to one 2-ZEC crossing).
    let (_dir, mut st, db_path, account) = seed_wallet(&[100_020_000, 50_020_000], 10);
    let usk = st.get_account().usk().clone();

    let ctx = MigrationContext::new(&db_path, ironwood_active_network(), account).unwrap();

    let schedule = ctx.propose_migration_transfers(false).unwrap();
    assert_eq!(
        schedule.transfers().len(),
        2,
        "two crossings: 1 ZEC and 0.5 ZEC"
    );
    ctx.sign_and_store_migration_schedule(&schedule, &usk)
        .unwrap();
    // Design spec §4.2: both self-funding notes are signed via the placeholder-witness path; both
    // are already witnessed (10 confirmations mined before the context ever opened the wallet), so
    // finalize_ready_transfers completes both before either can be due.
    assert_eq!(ctx.finalize_ready_transfers().unwrap(), 2);

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

/// Regression test for the root cause behind a live-device `InsufficientFunds` failure: a live
/// wallet's `CompactBlockProcessor` calls `update_chain_tip` on every sync tick, even when zero new
/// blocks arrived. `update_chain_tip` unconditionally re-marks the still-open shard's
/// already-scanned range as `ScanPriority::ChainTip` (see
/// `zcash_client_sqlite::wallet::scanning::update_chain_tip`) *whenever an earlier shard has
/// already completed* (`min_shard_tip.is_some()`), overwriting whatever `Scanned` marking
/// `scan_complete` had just set. On a real device this precondition holds (its own
/// `WalletSummary` logged `nextOrchardSubtreeIndex=2`, i.e. two prior shards were already
/// complete), so `select_spendable_notes`'s "fully scanned" branch could never observe `Scanned`
/// for a note in the currently-open shard, and `witness_stabilized` is *by design* never true for
/// an open shard either — every note there was permanently unselectable.
///
/// This fixture is a brand-new account whose only shard (index 0) is the first one ever, so
/// `min_shard_tip` is `None` and the `update_chain_tip` downgrade this test simulates never
/// actually fires here — faithfully reproducing the "prior complete shard" precondition would
/// require genuinely filling a whole shard (65536 note commitments) or hand-editing
/// `orchard_tree_shards`/shard-tree data, both too fragile/expensive for this test. So this does
/// not prove the *original bug* reproduces; it proves the *fix* — routing migration's fallback
/// input selection through `select_spendable_notes_deferred_witness` (`reserved_source.rs`)
/// instead of the strict `select_spendable_notes` — tolerates an extra steady-state
/// `update_chain_tip` call (a second poll tick at the same height, finding no new blocks, exactly
/// what `CompactBlockProcessor` does every ~20s per the observed device logcat cadence) without
/// regressing. The root-cause mechanism itself is confirmed by direct source inspection of
/// `update_chain_tip`, not by this test.
#[test]
fn steady_state_chain_tip_polling_does_not_block_deferred_witness_selection() {
    const D: u64 = 100_000_000;
    let (_dir, st, db_path, account) = seed_wallet(&[D + 100_000], 10);

    let tip_height = {
        let conn = Connection::open(&db_path).unwrap();
        conn.query_row("SELECT MAX(height) FROM blocks", [], |row| {
            row.get::<_, u32>(0)
        })
        .unwrap()
    };
    drop(st);

    // Simulate a second live sync tick at the same chain tip (no new blocks found) — exactly what
    // `CompactBlockProcessor` does every ~20s per the observed device logcat cadence.
    {
        let mut db =
            WalletDb::for_path(&db_path, ironwood_active_network(), SystemClock, OsRng).unwrap();
        db.update_chain_tip(BlockHeight::from_u32(tip_height))
            .unwrap();
    }

    let ctx = MigrationContext::new(&db_path, ironwood_active_network(), account).unwrap();
    let schedule = ctx
        .propose_migration_transfers(false)
        .expect("deferred-witness selection tolerates an extra steady-state chain-tip poll");
    assert_eq!(schedule.transfers().len(), 1);
}

// ======================================================================================
// Spike (design spec `2026-07-17-migration-sign-now-prove-later-design.md`, §4.2's "Open
// verification item"): can the `orchard` crate's own builder construct, finalize, and SIGN a
// valid PCZT for a spend of a REAL note using a *placeholder* `MerklePath` (not the note's real
// witness) while the enclosing `BuildConfig`'s `orchard_anchor` is left entirely `None` (not a
// placeholder anchor value)? This must hold without ever touching the wallet's commitment tree
// (no `witness_at_checkpoint_id_caching`, no `root_at_checkpoint_id` call anywhere in these
// tests) — the whole point of §4.2 is that signing does not need real witness/anchor data at all.
//
// RESULT: the literal approach described in §4.2 does **not** work — see
// `transaction_level_builder_rejects_orchard_anchor_none` below, which documents exactly where
// and why it fails. A working alternative exists and is demonstrated by
// `placeholder_witness_synthetic_anchor_then_redacted_signs_successfully`: build with a
// *synthetic, self-consistent* anchor (the placeholder path's own root, not the note's real
// anchor), sign, then use the (previously unused by this crate) `pczt::roles::redactor::Redactor`
// role to erase the anchor and witness back down to `None` post-signing. The end state — a
// validly SIGNED PCZT with `anchor: None` and no real witness, ready for a later
// `set_orchard_anchor`/`set_orchard_spend_witnesses` call — is identical to what §4.2 wanted;
// only the path to get there differs from what the spec assumed.
//
// Both tests deliberately stop after the Signer role: proving is explicitly out of scope (a
// `None` anchor is meaningless to the Prover — that's expected and is not what's being verified
// here).
// ======================================================================================

/// Documents the actual blocker: `zcash_primitives::transaction::builder::BuildConfig::Standard`'s
/// `orchard_anchor: None` does not mean "defer the anchor for later PCZT-level filling" — it means
/// "do not build an Orchard bundle at all". `BuildConfig::orchard_builder` (private to
/// `zcash_primitives`, `zcash_primitives/src/transaction/builder.rs`'s
/// `impl BuildConfig::orchard_builder`) only constructs the underlying `orchard::builder::Builder`
/// when `orchard_anchor` is `Some`:
///
/// ```ignore
/// BuildConfig::Standard { orchard_anchor, orchard_bundle_type, .. } => orchard_anchor
///     .as_ref()
///     .map(|a| orchard::builder::Builder::new(*orchard_bundle_type, bundle_version, ..., *a).expect(..)),
/// ```
///
/// so with `orchard_anchor: None`, `Builder::new`'s `orchard_builder` field is `None`, and
/// `add_orchard_spend` immediately returns `Error::OrchardBuilderNotAvailable` before even looking
/// at the supplied `MerklePath` — the placeholder-witness content is never reached.
///
/// This is not merely a `zcash_primitives`-level wrapper limitation, either: even bypassing it and
/// calling `orchard::builder::Builder::new` directly still requires a non-optional
/// `anchor: orchard::Anchor` parameter, and `Builder::add_spend`
/// (`orchard-0.15.0/src/builder.rs`) performs a live anchor/path consistency check —
/// `SpendInfo::has_matching_anchor` — that rejects any `merkle_path` whose own computed root does
/// not equal the builder's anchor. There is no "no anchor" mode at the orchard-crate builder level
/// at all; every spend-adding API demands *some* anchor value that the supplied path is consistent
/// with.
#[test]
fn transaction_level_builder_rejects_orchard_anchor_none() {
    let (_dir, st, db_path, account) = seed_wallet(&[100_000_000], 10);
    let usk = st.get_account().usk().clone();
    drop(st);

    let network = ironwood_active_network();
    let db: FileWalletDb =
        WalletDb::for_path(&db_path, network, SystemClock, OsRng).unwrap();
    let (target, _unused_anchor): (TargetHeight, BlockHeight) = db
        .get_target_and_anchor_heights(ConfirmationsPolicy::default().trusted())
        .unwrap()
        .unwrap();
    let note = db
        .select_unspent_notes(account, &[ShieldedPool::Orchard], target, &[])
        .unwrap()
        .take_orchard()
        .into_iter()
        .next()
        .expect("the seeded wallet has one spendable Orchard note");
    let orchard_fvk = orchard::keys::FullViewingKey::from(usk.orchard());
    let placeholder_path = orchard::tree::MerklePath::from_parts(
        0,
        [orchard::tree::MerkleHashOrchard::empty_leaf(); orchard::NOTE_COMMITMENT_TREE_DEPTH],
    );

    let mut builder = Builder::new(
        network,
        BlockHeight::from(target),
        BuildConfig::Standard {
            sapling_anchor: None,
            orchard_anchor: None,
            ironwood_anchor: None,
            orchard_bundle_type: orchard::builder::BundleType::DEFAULT,
            ironwood_bundle_type: orchard::builder::BundleType::DEFAULT,
        },
    );

    let result =
        builder.add_orchard_spend::<Infallible>(orchard_fvk, *note.note(), placeholder_path);
    assert!(
        matches!(
            result,
            Err(zcash_primitives::transaction::builder::Error::OrchardBuilderNotAvailable)
        ),
        "orchard_anchor: None means \"no Orchard bundle\", not \"defer the anchor\" — got {result:?}"
    );
}

/// The working alternative: build the spend against a **synthetic, self-consistent** anchor (the
/// placeholder `MerklePath`'s own computed root, not the note's real anchor — so
/// `orchard::builder::Builder::add_spend`'s internal anchor/path consistency check is satisfied),
/// sign normally, and then use `pczt::roles::redactor::Redactor::redact_orchard_with` to erase
/// both the anchor and the spend witness back down to `None`/absent. `Redactor` is not currently
/// used anywhere else in this crate (`zcash_pool_migration`) or referenced by the design spec, but
/// requires no new Cargo feature — `pczt/src/roles.rs` gates it behind no `#[cfg(feature = ...)]`
/// at all, unlike `prover`/`signer`/`spend-finalizer`/`tx-extractor`.
///
/// This produces exactly the end state design spec §4.2's `SignedAwaitingProof` sub-state wants:
/// a fully, validly SIGNED PCZT (`spend_auth_sig` present) whose Orchard-bundle `anchor` is `None`
/// and whose spend has no witness — ready for a later `set_orchard_anchor(real_anchor)` (a legal
/// `None -> Some` transition) and `set_orchard_spend_witnesses` call, without ever having computed
/// the note's real witness or anchor in this test.
///
/// Asserts:
/// - Every step (build, `Creator`, `IoFinalizer`, `Signer`, `Redactor`) succeeds with no error.
/// - Before redaction, the PCZT's anchor is `Some` (the synthetic value) — proving the anchor slot
///   really was populated, not accidentally already `None` for some unrelated reason.
/// - After redaction, `pczt.orchard().anchor()` is `None`, verified directly via `pczt::Pczt`'s
///   public accessors, and this survives a serialize/parse round trip.
/// - After redaction, at least one action's `spend_auth_sig` is STILL `Some` — proving redaction
///   only cleared the anchor/witness fields and did not invalidate the signature (consistent with
///   the design spec's ZIP 244 premise: the anchor is committed as authorizing data, not under the
///   v6 signature hash, so clearing it post-signing does not touch `spend_auth_sig`).
/// - This test never calls `WalletCommitmentTrees::with_orchard_tree_mut`,
///   `witness_at_checkpoint_id_caching`, or `root_at_checkpoint_id` — the note's REAL witness and
///   anchor are never computed anywhere in this test, only the synthetic placeholder's own
///   self-consistent root.
#[test]
fn placeholder_witness_synthetic_anchor_then_redacted_signs_successfully() {
    let (_dir, st, db_path, account) = seed_wallet(&[100_000_000], 10);
    let usk = st.get_account().usk().clone();
    // Release the harness's wallet connection before we re-open the same file directly (mirrors
    // every other test in this file).
    drop(st);

    let network = ironwood_active_network();
    let db: FileWalletDb =
        WalletDb::for_path(&db_path, network, SystemClock, OsRng).unwrap();

    // Only the target height is used — deliberately never touch `get_target_and_anchor_heights`'s
    // anchor half, nor any commitment-tree accessor, anywhere in this test.
    let (target, _unused_anchor): (TargetHeight, BlockHeight) = db
        .get_target_and_anchor_heights(ConfirmationsPolicy::default().trusted())
        .unwrap()
        .unwrap();

    // A real, wallet-owned Orchard note — fetched via the note-selection API, never via the
    // commitment tree.
    let note = db
        .select_unspent_notes(account, &[ShieldedPool::Orchard], target, &[])
        .unwrap()
        .take_orchard()
        .into_iter()
        .next()
        .expect("the seeded wallet has one spendable Orchard note");
    let note_value = note.note().value().inner();
    assert_eq!(note_value, 100_000_000, "sanity: the seeded note's value");

    let orchard_fvk = orchard::keys::FullViewingKey::from(usk.orchard());

    // The placeholder witness (§4.2): a synthetic position/auth-path, NOT the note's real witness
    // (which would require `db.with_orchard_tree_mut(..).witness_at_checkpoint_id_caching(..)` —
    // never called in this test).
    let placeholder_path = orchard::tree::MerklePath::from_parts(
        0,
        [orchard::tree::MerkleHashOrchard::empty_leaf(); orchard::NOTE_COMMITMENT_TREE_DEPTH],
    );
    // The synthetic anchor: this placeholder path's OWN computed root — not the note's real
    // anchor (never computed anywhere in this test) and not `Anchor::empty_tree()` either (which
    // would not match this path and would trip `add_spend`'s consistency check just the same).
    // `orchard::builder::Builder::add_spend` requires `merkle_path.root(note.commitment()) ==
    // builder.anchor`, so the two must be constructed together.
    let synthetic_anchor = placeholder_path.root(note.note().commitment().into());

    // ZIP-317: 1 spend + 1 (same-pool) change output = 2 actions, at/above the 2-action grace
    // floor, so fee = 5_000 * 2 = 10_000 (matches `split.rs::split_fee(1, 1)`, which is
    // `pub(crate)` and therefore not reusable from this external integration test).
    const FEE: u64 = 10_000;
    let change_value = note_value - FEE;

    let mut builder = Builder::new(
        network,
        BlockHeight::from(target),
        BuildConfig::Standard {
            sapling_anchor: None,
            // NOT `None` (see `transaction_level_builder_rejects_orchard_anchor_none`) — a
            // synthetic anchor self-consistent with `placeholder_path`, so the orchard builder's
            // own anchor/path check is satisfied without ever touching the note's real anchor.
            orchard_anchor: Some(synthetic_anchor),
            // No Ironwood actions exist in this bundle at all, so this bundle needs no anchor
            // either.
            ironwood_anchor: None,
            orchard_bundle_type: orchard::builder::BundleType::DEFAULT,
            ironwood_bundle_type: orchard::builder::BundleType::DEFAULT,
        },
    );

    builder
        .add_orchard_spend::<Infallible>(orchard_fvk.clone(), *note.note(), placeholder_path)
        .expect("orchard builder accepts a placeholder MerklePath paired with its own root");

    let change_address = orchard_fvk.address_at(0u32, orchard::keys::Scope::Internal);
    let internal_ovk = orchard_fvk.to_ovk(orchard::keys::Scope::Internal);
    builder
        .add_orchard_change_output::<Infallible>(
            orchard_fvk.clone(),
            Some(internal_ovk),
            change_address,
            Zatoshis::const_from_u64(change_value),
            MemoBytes::empty(),
        )
        .unwrap();

    let build_result = builder
        .build_for_pczt(OsRng, &Zip317FeeRule::standard())
        .expect("build_for_pczt succeeds with a placeholder witness and a synthetic anchor");

    let created = pczt::roles::creator::Creator::build_from_parts(build_result.pczt_parts)
        .expect("pczt creation succeeds");
    let finalized = pczt::roles::io_finalizer::IoFinalizer::new(created)
        .finalize_io()
        .expect("io finalization succeeds with a synthetic anchor and a placeholder witness");

    assert_eq!(
        finalized.orchard().anchor(),
        &Some(synthetic_anchor.to_bytes()),
        "the anchor slot holds the synthetic anchor right after construction — proving it really \
         was populated, not accidentally already None for some unrelated reason"
    );
    assert_eq!(
        finalized.orchard().actions().len(),
        2,
        "one real spend plus the one change output — no padding needed at the 2-action default"
    );

    // Sign every Orchard spend belonging to the wallet (mirrors
    // `backend.rs::sign_all_orchard_spends`'s index-probing loop, since that function is
    // `pub(crate)` in `zcash_pool_migration` and unreachable here).
    let mut signer = pczt::roles::signer::Signer::new(finalized)
        .expect("pczt signer inits fine with a synthetic anchor and a placeholder witness");
    let ask = orchard::keys::SpendAuthorizingKey::from(usk.orchard());
    for index in 0.. {
        match signer.sign_orchard(index, &ask) {
            Err(pczt::roles::signer::Error::InvalidIndex) => break,
            Ok(())
            | Err(pczt::roles::signer::Error::OrchardSign(
                orchard::pczt::SignerError::WrongSpendAuthorizingKey,
            )) => {}
            Err(e) => panic!("sign orchard: {e:?}"),
        }
    }
    let signed = signer.finish();
    assert!(
        signed
            .orchard()
            .actions()
            .iter()
            .any(|a| a.spend().spend_auth_sig().is_some()),
        "the Signer role actually produced a spend authorization signature for the real spend, \
         proving signing succeeded — not just that the loop ran to completion"
    );

    // The redaction step (not currently used anywhere else in this crate): erase the anchor and
    // the spend witness back down to None/absent, post-signing — the `SignedAwaitingProof` shape
    // design spec §4.2 wants, reached via a different route than the spec assumed.
    let redacted = pczt::roles::redactor::Redactor::new(signed)
        .redact_orchard_with(|mut orchard| {
            orchard.clear_anchor();
            orchard.redact_actions(|mut action| {
                action.clear_spend_witness();
            });
        })
        .finish();

    assert_eq!(
        redacted.orchard().anchor(),
        &None,
        "post-redaction, the Orchard bundle's anchor is None — exactly the `SignedAwaitingProof` \
         shape §4.2 wants, ready for a later `set_orchard_anchor` (a legal None -> Some \
         transition)"
    );
    assert!(
        redacted
            .orchard()
            .actions()
            .iter()
            .any(|a| a.spend().spend_auth_sig().is_some()),
        "redaction cleared only the anchor/witness fields — the spend authorization signature \
         survives untouched, consistent with the design spec's ZIP 244 premise that the anchor \
         is committed as authorizing data, not under the v6 signature hash"
    );

    // Round-trip through serialization: the PCZT is genuinely, structurally anchor-less, not just
    // in this process's in-memory `Bundle` value. (`Pczt::serialize` always emits the v2 wire
    // format, whose `anchor` field is `Option<[u8; 32]>` — unlike v1, which requires `Some` — so
    // this is not expected to fail.)
    let bytes = redacted
        .clone()
        .serialize()
        .expect("a signed, anchor-less, witness-redacted PCZT still serializes (v2 encoding)");
    let reparsed = pczt::Pczt::parse(&bytes).expect("the serialized PCZT parses back");
    assert_eq!(
        reparsed.orchard().anchor(),
        &None,
        "anchor is still None after a full serialize/parse round trip"
    );

    // Deliberately NOT run: `pczt::roles::prover::Prover` (proving needs the real anchor and is
    // out of scope for this spike — see the design spec's §4.2 open item), `SpendFinalizer`, and
    // `TransactionExtractor` (both would require a proof to already exist). Construction through
    // signing (and redaction back to the anchor-less/witness-less shape) succeeding is the entire
    // claim this test verifies.
}
