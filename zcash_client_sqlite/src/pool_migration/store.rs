//! The generic, pool-agnostic SQLite pool-migration store.
//!
//! This module is entirely crate-internal: it holds the machinery shared by every pool migration
//! (the DDL builders and the [`Store`] type that carries the [`PoolMigrationRead`] /
//! [`PoolMigrationWrite`] SQL logic), parameterized over the table names in [`Tables`]. The schema is
//! fully NORMALIZED: every structured value is stored in typed columns and child-table rows, so the
//! store maps the engine types to and from columns directly. The `BLOB` columns are the pre-signed
//! transaction (`pczt`), which is genuinely unstructured, already-versioned bytes; each
//! transaction's `lock_owner`, an opaque fixed-size token read and written directly as
//! `Option<[u8; 32]>` (no codec: `rusqlite`'s fixed-size-array `FromSql`/`ToSql` impls handle it,
//! and reject a non-NULL blob that is not exactly 32 bytes); and each cached real-spend
//! `nullifier`, one per row of the spend-nullifier child table, held to its 32-byte width by a
//! `CHECK` and read back through those same fixed-size impls. All amounts are zatoshi `INTEGER`
//! columns; the `txid` is stored as the transaction id's raw internal bytes (`TxId::as_ref`).
//!
//! The preparation plan's layers/transactions grid has no tables of its own: each input and output
//! row carries its transaction's `(layer, tx_index)` coordinate, and every transaction a real plan
//! produces has at least one input and one output (and no layer is empty), so the store
//! reconstructs the grid from those rows (and rejects a state it could not reconstruct with
//! [`Error::Unrepresentable`]). Likewise the funding-note values have no table: the engine derives
//! them from the denomination plan (each crossing value plus the fee buffer).
//!
//! The column set is the same for every pool; only the table and index names change (plus, for
//! the wallet-owned source-pool note and commitment-tree tables the satisfiability oracle queries,
//! the per-pool name of the note-spends junction's note-reference column). The one thing table
//! names cannot reach is the source pool's SHARD TREE, which is typed by its hash and shard
//! height; the oracle's anchor-validity judgment therefore takes root resolution as a capability
//! from the concrete pool facade (see [`SourceRootAt`]).
//!
//! [`PoolMigrationRead`]: zcash_pool_migration::engine::PoolMigrationRead
//! [`PoolMigrationWrite`]: zcash_pool_migration::engine::PoolMigrationWrite

use std::borrow::{Borrow, BorrowMut};
use std::collections::BTreeSet;
use std::num::NonZeroU32;

use rusqlite::{Connection, OptionalExtension, named_params, params};

use zcash_client_backend::wallet::LockOwner;
use zcash_pool_migration::denomination::DenominationPlan;
use zcash_pool_migration::engine::{
    MigrationLockOwner, MigrationState, MigrationStatus, MigrationTransaction, MigrationTransferId,
    MigrationTxKind, MigrationTxState,
};
use zcash_pool_migration::preparation::{PrepInput, PrepOutput, PrepTransaction, PreparationPlan};
use zcash_pool_migration::satisfiability::{
    InputObservation, ReorgSettleDepth, ReplanThreshold, StepSatisfiability, UnsatisfiableCause,
    UnsatisfiableKind, classify_input_observations,
};
use zcash_pool_migration::scheduling::AnchorBucketInterval;
use zcash_protocol::TxId;
use zcash_protocol::consensus::BlockHeight;
use zcash_protocol::value::Zatoshis;

use crate::AccountRef;

use super::error::Error;

/// The per-pool table and index names a [`Store`] operates over. A concrete migration submodule
/// supplies a `'static` value of this for its own pool; the generic store interpolates these into
/// every DDL and query, so one implementation serves every pool.
pub(crate) struct Tables {
    /// The migration-state table (one row per account; holds the denomination scalars).
    pub migrations: &'static str,
    /// The denomination crossing values (an ordered list).
    pub crossing_values: &'static str,
    /// The inputs of each preparation transaction, keyed by the transaction's `(layer, tx_index)`
    /// grid coordinate.
    pub prep_inputs: &'static str,
    /// The outputs of each preparation transaction, keyed like the inputs.
    pub prep_outputs: &'static str,
    /// The preparation plan's direct-funding wallet notes (an ordered list).
    pub prep_direct_funding: &'static str,
    /// The per-migration-transaction table.
    pub transactions: &'static str,
    /// The dependency edges between migration transactions.
    pub transaction_deps: &'static str,
    /// The cached real-spend nullifiers of each migration transaction (an ordered list per
    /// transaction, one nullifier per row).
    pub spend_nullifiers: &'static str,
    /// The index over `(state, scheduled_height)` on the transactions table.
    pub tx_due_index: &'static str,
    /// The unique index over `account_id` on the migrations table, enforcing at most one
    /// migration per account.
    pub account_index: &'static str,
    /// The WALLET's received-note table for the migration's SOURCE pool — the pool whose notes
    /// the pre-signed transactions spend — holding each scanned note's nullifier in its `nf`
    /// column. Not created by [`init`]: unlike the tables above, this one belongs to the wallet
    /// schema, and the store only queries it (for
    /// [`check_step_satisfiability`](Store::check_step_satisfiability)'s spent-input
    /// observations).
    pub source_notes: &'static str,
    /// The wallet's junction table recording spends of source-pool received notes, joining note
    /// rows to the wallet's `transactions` table. Like `source_notes`, queried but never created
    /// here.
    pub source_note_spends: &'static str,
    /// The `source_note_spends` column referencing a `source_notes` row's `id` (the wallet
    /// schema names it per pool, so it cannot be interpolated from the table name).
    pub source_note_spends_note_fk: &'static str,
    /// The WALLET's note-commitment-tree checkpoint table for the migration's SOURCE pool, whose
    /// `checkpoint_id` column is a block height and whose `position` column is that checkpoint's
    /// tree state. Like `source_notes`, queried but never created here: the anchor-validity
    /// judgment enumerates the checkpoints whose roots it must rule an installed anchor out of.
    pub source_tree_checkpoints: &'static str,
}

/// Resolve the SOURCE pool's note-commitment-tree root at the checkpoint `height`, as a concrete
/// pool facade supplies it; `Ok(None)` when the tree can produce no root there (no checkpoint at
/// that height, or the retained shard data cannot complete one).
///
/// This is a CAPABILITY the caller passes in rather than something the generic store reconstructs:
/// a shard tree is typed by its hash and shard height, both pool-specific, so table names — the
/// only per-pool knowledge [`Tables`] carries — cannot reach it. A facade whose build cannot read
/// its source pool's tree at all passes `None` for the capability, and every anchor-validity
/// judgment then declines, exactly as it does for a boundary whose checkpoint is gone.
pub(crate) type SourceRootAt =
    fn(&rusqlite::Transaction<'_>, BlockHeight) -> Result<Option<[u8; 32]>, Error>;

/// The largest number of distinct source-tree states an anchor-validity judgment will probe before
/// declining to conclude; see [`anchor_displaced`].
///
/// The judgment marks only on an EXHAUSTIVE negative — the installed anchor is the root at none of
/// the checkpoints the wallet retains — so a probe set too large to walk is answered "cannot
/// conclude" rather than "invalidated". The bound is what keeps a rare path from becoming an
/// unbounded one: each probe recomputes a tree root from shard data.
///
/// This is a HORIZON, not headroom. Nothing in a production release ever releases a retained
/// checkpoint (`remove_retained_checkpoints_below` has test callers only), so the retained set
/// grows monotonically by one per anchor-grid boundary: at the ZIP 318 grid of 144 blocks, this
/// limit is reached after roughly 147,000 blocks — some months of chain — after which every
/// anchor-validity judgment on that wallet declines permanently. Raising the limit moves the date;
/// only bounding the retained set removes it.
const ANCHOR_PROBE_LIMIT: usize = 1024;

// ---------------------------------------------------------------------------
// DDL
// ---------------------------------------------------------------------------

/// The terminal statuses as a parenthesizable SQL literal list (`'complete', 'failed', ...`),
/// generated from [`MigrationStatus::terminal`] so the database's notion of terminal cannot drift
/// from the crate's. Used wherever terminality must appear in SQL TEXT rather than as bound
/// parameters — the partial unique index's predicate, which SQLite stores as DDL — and by the
/// pending-only read queries, so every site derives from the one decision in `is_terminal`.
pub(crate) fn terminal_status_sql_list() -> String {
    MigrationStatus::terminal()
        .map(|s| format!("'{}'", s.wire_name()))
        .collect::<Vec<_>>()
        .join(", ")
}

fn create_migrations_sql(t: &Tables) -> String {
    // Column semantics are documented on the golden copy,
    // `crate::wallet::db::TABLE_ORCHARD_IRONWOOD_MIGRATIONS`. Constraints shaping this DDL:
    //
    // - `account_id` references the wallet's `accounts` table directly (its name is the same for
    //   every pool), so an account's migrations and their child rows are removed with it.
    // - The `DEFAULT`s on `anchor_bucket_interval`, `replan_threshold`, and `uuid` exist only so
    //   this DDL and the corresponding schema migrations' `ADD COLUMN`s produce identical stored
    //   schema text (SQLite cannot add a `NOT NULL` column without one); the store binds all
    //   three explicitly.
    format!(
        "CREATE TABLE IF NOT EXISTS {} (
            id INTEGER PRIMARY KEY,
            account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
            status TEXT NOT NULL,
            note_split_fee_buffer INTEGER NOT NULL,
            note_split_change INTEGER,
            note_split_prep_fees INTEGER NOT NULL,
            note_split_total_input INTEGER NOT NULL,
            note_split_total_migratable INTEGER NOT NULL,
            anchor_bucket_interval INTEGER NOT NULL DEFAULT {},
            replan_threshold INTEGER NOT NULL DEFAULT {},
            uuid BLOB NOT NULL DEFAULT X'',
            committed_height INTEGER
        )",
        t.migrations,
        AnchorBucketInterval::ZIP_318.block_count(),
        ReplanThreshold::DEFAULT.percent()
    )
}

fn create_crossing_values_sql(t: &Tables) -> String {
    format!(
        "CREATE TABLE IF NOT EXISTS {} (
            migration_id INTEGER NOT NULL REFERENCES {}(id) ON DELETE CASCADE,
            ordinal INTEGER NOT NULL,
            value INTEGER NOT NULL,
            PRIMARY KEY (migration_id, ordinal)
        )",
        t.crossing_values, t.migrations
    )
}

fn create_prep_inputs_sql(t: &Tables) -> String {
    format!(
        "CREATE TABLE IF NOT EXISTS {} (
            migration_id INTEGER NOT NULL REFERENCES {}(id) ON DELETE CASCADE,
            layer INTEGER NOT NULL,
            tx_index INTEGER NOT NULL,
            ordinal INTEGER NOT NULL,
            source TEXT NOT NULL,
            wallet_index INTEGER,
            prior_layer INTEGER,
            prior_transaction INTEGER,
            prior_output INTEGER,
            value INTEGER NOT NULL,
            PRIMARY KEY (migration_id, layer, tx_index, ordinal)
        )",
        t.prep_inputs, t.migrations
    )
}

fn create_prep_outputs_sql(t: &Tables) -> String {
    format!(
        "CREATE TABLE IF NOT EXISTS {} (
            migration_id INTEGER NOT NULL REFERENCES {}(id) ON DELETE CASCADE,
            layer INTEGER NOT NULL,
            tx_index INTEGER NOT NULL,
            ordinal INTEGER NOT NULL,
            role TEXT NOT NULL,
            value INTEGER NOT NULL,
            PRIMARY KEY (migration_id, layer, tx_index, ordinal)
        )",
        t.prep_outputs, t.migrations
    )
}

fn create_prep_direct_funding_sql(t: &Tables) -> String {
    format!(
        "CREATE TABLE IF NOT EXISTS {} (
            migration_id INTEGER NOT NULL REFERENCES {}(id) ON DELETE CASCADE,
            ordinal INTEGER NOT NULL,
            wallet_index INTEGER NOT NULL,
            value INTEGER NOT NULL,
            PRIMARY KEY (migration_id, ordinal)
        )",
        t.prep_direct_funding, t.migrations
    )
}

pub(crate) fn create_transactions_sql(t: &Tables) -> String {
    // `unsatisfiable_at` and `unsatisfiable_kind` are one value in two columns — the height an
    // unsatisfiability observation rests on, and which observation it was — so they are `NULL`
    // together or non-`NULL` together, and the read path rejects a row where they disagree.
    //
    // `broadcast_failure_at` is independent of both: the tip an application observed from a node
    // that REJECTED a broadcast, standing until the engine adjudicates the rejection against the
    // wallet's own view. The three columns that migration adds are listed here in the order it adds
    // them, so the created and repaired schemas stay comparable.
    format!(
        "CREATE TABLE IF NOT EXISTS {} (
            migration_id INTEGER NOT NULL REFERENCES {}(id) ON DELETE CASCADE,
            transfer_id INTEGER NOT NULL,
            kind TEXT NOT NULL,
            kind_layer INTEGER,
            kind_index INTEGER,
            kind_crossing INTEGER,
            pczt BLOB NOT NULL,
            scheduled_height INTEGER NOT NULL,
            expiry_height INTEGER NOT NULL,
            anchor_boundary INTEGER,
            state TEXT NOT NULL,
            txid BLOB,
            mined_height INTEGER,
            lock_owner BLOB,
            unsatisfiable_at INTEGER,
            unsatisfiable_kind TEXT,
            broadcast_failure_at INTEGER,
            PRIMARY KEY (migration_id, transfer_id)
        )",
        t.transactions, t.migrations
    )
}

fn create_transaction_deps_sql(t: &Tables) -> String {
    format!(
        "CREATE TABLE IF NOT EXISTS {} (
            migration_id INTEGER NOT NULL,
            transfer_id INTEGER NOT NULL,
            ordinal INTEGER NOT NULL,
            depends_on_transfer_id INTEGER NOT NULL,
            PRIMARY KEY (migration_id, transfer_id, ordinal),
            FOREIGN KEY (migration_id, transfer_id)
                REFERENCES {}(migration_id, transfer_id) ON DELETE CASCADE
        )",
        t.transaction_deps, t.transactions
    )
}

fn create_spend_nullifiers_sql(t: &Tables) -> String {
    // The nullifiers of a transaction's REAL spends, cached from its stored PCZT so the pool
    // migration's state machine never has to parse one. Ordered, because the engine holds them as
    // a `Vec` and compares migration states for equality: `ordinal` is the position in that list,
    // exactly as it is for the dependency edges beside it.
    //
    // The `CHECK` is the store's stride guard, stated where the data lives rather than enforced on
    // the way out: a nullifier is 32 bytes, so anything else was not written by this store and
    // cannot become one on the read path. Reading a row back through `rusqlite`'s fixed-size-array
    // impl rejects the same shape a second time, which is what makes the guard total.
    format!(
        "CREATE TABLE IF NOT EXISTS {} (
            migration_id INTEGER NOT NULL,
            transfer_id INTEGER NOT NULL,
            ordinal INTEGER NOT NULL,
            nullifier BLOB NOT NULL CHECK (length(nullifier) = 32),
            PRIMARY KEY (migration_id, transfer_id, ordinal),
            FOREIGN KEY (migration_id, transfer_id)
                REFERENCES {}(migration_id, transfer_id) ON DELETE CASCADE
        )",
        t.spend_nullifiers, t.transactions
    )
}

pub(crate) fn create_tx_due_index_sql(t: &Tables) -> String {
    format!(
        "CREATE INDEX IF NOT EXISTS {} ON {} (state, scheduled_height)",
        t.tx_due_index, t.transactions
    )
}

/// The `v_migration_transactions` view DDL: one row per SCHEDULED migration transaction — a
/// transaction of a non-terminal migration that has not yet been broadcast (and so has no row in
/// the wallet's `transactions` table). Values are projected from the migration store's typed
/// columns: a transfer spends its funding note (crossing value plus the per-note fee buffer,
/// which IS the canonical transfer's ZIP-317 fee) and receives the crossing; a preparation's
/// values are the sums of its input and output rows. Every wire name, classification code, and
/// the terminal-status list are generated from their defining types.
pub(crate) fn create_migration_tx_view_sql(t: &Tables) -> String {
    use zcash_pool_migration::engine::{MigrationTxKind, MigrationTxState};
    use zcash_protocol::zip318::{Zip318Classification, Zip318TxKind};

    let transfer = MigrationTxKind::Transfer { crossing: 0 };
    let pending_states = [
        MigrationTxState::AwaitingSignature,
        MigrationTxState::Signed,
        MigrationTxState::Proved,
    ]
    .iter()
    .map(|st| format!("'{}'", st.as_ref()))
    .collect::<Vec<_>>()
    .join(", ");
    format!(
        "CREATE VIEW v_migration_transactions AS
        SELECT accounts.uuid AS account_uuid,
               m.uuid AS migration_uuid,
               mt.txid AS txid,
               mt.kind AS kind,
               mt.state AS state,
               mt.scheduled_height AS scheduled_height,
               mt.expiry_height AS expiry_height,
               CASE mt.kind WHEN '{transfer}' THEN cv.value + m.note_split_fee_buffer
                    ELSE pin.value_in END AS value_spent,
               CASE mt.kind WHEN '{transfer}' THEN cv.value
                    ELSE pout.value_out END AS value_received,
               CASE mt.kind WHEN '{transfer}' THEN m.note_split_fee_buffer
                    ELSE pin.value_in - pout.value_out END AS fee,
               CASE mt.kind WHEN '{transfer}' THEN cv.value END AS pool_crossing_value,
               CASE mt.kind WHEN '{transfer}' THEN 1 ELSE pin.input_count END AS spent_note_count,
               CASE mt.kind WHEN '{transfer}' THEN 1
                    ELSE pout.output_count - pout.change_count END AS received_note_count,
               CASE mt.kind WHEN '{transfer}' THEN 0
                    ELSE pout.change_count > 0 END AS has_change,
               CASE mt.kind WHEN '{transfer}' THEN {transfer_code}
                    ELSE {prep_code} END AS zip318_kind
        FROM {tx} mt
        JOIN {migrations} m ON m.id = mt.migration_id
        JOIN accounts ON accounts.id = m.account_id
        LEFT JOIN {cv} cv
               ON cv.migration_id = mt.migration_id AND cv.ordinal = mt.kind_crossing
        LEFT JOIN (SELECT migration_id, layer, tx_index,
                          SUM(value) AS value_in, COUNT(*) AS input_count
                     FROM {pin} GROUP BY migration_id, layer, tx_index) pin
               ON pin.migration_id = mt.migration_id
              AND pin.layer = mt.kind_layer AND pin.tx_index = mt.kind_index
        LEFT JOIN (SELECT migration_id, layer, tx_index,
                          SUM(value) AS value_out, COUNT(*) AS output_count,
                          SUM(role = '{change}') AS change_count
                     FROM {pout} GROUP BY migration_id, layer, tx_index) pout
               ON pout.migration_id = mt.migration_id
              AND pout.layer = mt.kind_layer AND pout.tx_index = mt.kind_index
        WHERE m.status NOT IN ({terminal})
          AND mt.state IN ({pending_states})
          AND NOT EXISTS (SELECT 1 FROM transactions tt WHERE tt.txid = mt.txid)",
        transfer = transfer.as_ref(),
        transfer_code = Zip318Classification::Conforms(Zip318TxKind::Transfer).to_code(),
        prep_code = Zip318Classification::Conforms(Zip318TxKind::Preparation).to_code(),
        change = "change",
        tx = t.transactions,
        migrations = t.migrations,
        cv = t.crossing_values,
        pin = t.prep_inputs,
        pout = t.prep_outputs,
        terminal = terminal_status_sql_list(),
        pending_states = pending_states,
    )
}

/// The at-most-one-PENDING-migration-per-account invariant, as a database constraint: a PARTIAL
/// unique index over the non-terminal rows. An account accumulates terminal migrations without
/// limit — they are the history the store retains — while the engine's commit guard admits a new
/// migration only once the outstanding one is terminal, and this index makes the database uphold
/// the same rule, so a logic bug surfaces as a constraint violation rather than as two live
/// migrations racing. The predicate is generated from [`MigrationStatus::terminal`]
/// ([`terminal_status_sql_list`]), never restated as literals.
///
/// `pub(crate)` because the `orchard_ironwood_migration_history` schema migration creates the
/// index from this same generator, so the migration path and the canonical DDL cannot disagree
/// about the predicate.
pub(crate) fn create_account_index_sql(t: &Tables) -> String {
    format!(
        "CREATE UNIQUE INDEX IF NOT EXISTS {} ON {} (account_id)
            WHERE status NOT IN ({})",
        t.account_index,
        t.migrations,
        terminal_status_sql_list()
    )
}

/// Create the pool-migration tables (and the due-transaction and account indexes) named by `t` on
/// `conn`, in their CURRENT shape. Idempotent (`IF NOT EXISTS`), and ordered so each foreign-key
/// target is created before the table referencing it.
///
/// This states what the tables look like once every schema migration has run; it is not how an
/// existing wallet got there. A published schema migration's effect cannot follow an evolving DDL,
/// so `orchard_ironwood_migration_tables` carries a frozen copy of the text it shipped with and the
/// migrations after it evolve that into this shape — which is why the transfer ordinal is created
/// as `transfer_id` here but renamed into it there. The two are held together by
/// `canonical_pool_migration_ddl_matches_the_migration_path`; a pool whose tables have no released
/// creating migration yet can be created from this directly.
pub(crate) fn init(conn: &Connection, t: &Tables) -> rusqlite::Result<()> {
    conn.execute_batch(&format!(
        "{};\n{};\n{};\n{};\n{};\n{};\n{};\n{};\n{};\n{};",
        create_migrations_sql(t),
        create_crossing_values_sql(t),
        create_prep_inputs_sql(t),
        create_prep_outputs_sql(t),
        create_prep_direct_funding_sql(t),
        create_transactions_sql(t),
        create_transaction_deps_sql(t),
        create_spend_nullifiers_sql(t),
        create_tx_due_index_sql(t),
        create_account_index_sql(t),
    ))
}

// ---------------------------------------------------------------------------
// The store
// ---------------------------------------------------------------------------

/// The generic pool-migration store: it carries the [`PoolMigrationRead`] / [`PoolMigrationWrite`]
/// logic over a `rusqlite::Connection`, parameterized by the [`Tables`] names for a given pool and
/// scoped to a single account's migration. Construct it with a connection borrow (`&Connection` for
/// read-only access, `&mut Connection` to also write) plus the pool's table names and the account;
/// a concrete facade wraps it so the generic type never appears in the public API.
///
/// [`PoolMigrationRead`]: zcash_pool_migration::engine::PoolMigrationRead
/// [`PoolMigrationWrite`]: zcash_pool_migration::engine::PoolMigrationWrite
pub(crate) struct Store<C> {
    conn: C,
    tables: &'static Tables,
    account_id: AccountRef,
}

impl<C> Store<C> {
    pub(crate) fn new(conn: C, tables: &'static Tables, account_id: AccountRef) -> Self {
        Self {
            conn,
            tables,
            account_id,
        }
    }

    pub(crate) fn into_inner(self) -> C {
        self.conn
    }
}

impl<C: Borrow<Connection>> Store<C> {
    /// The wallet database connection this store operates over, for reads a pool facade makes
    /// outside the store's own tables (for example resolving the account's viewing key when
    /// finalizing a proved migration transaction — an `orchard`-gated capability, hence the
    /// feature-conditional dead-code allowance).
    #[cfg_attr(not(feature = "orchard"), allow(dead_code))]
    pub(crate) fn connection(&self) -> &Connection {
        self.conn.borrow()
    }

    pub(crate) fn get_migration(&self) -> Result<Option<MigrationState>, Error> {
        read_migration(self.conn.borrow(), self.tables, self.account_id)
    }

    /// The account's most recent migration WHATEVER its status — the record a UI renders, where a
    /// finished migration must remain visible after [`get_migration`](Self::get_migration) (the
    /// pending-only drive read) has moved on to `None`. Recency is row order: rows are only ever
    /// inserted, and the identity-preserving rewrite re-inserts a migration in place of itself,
    /// so a later row id is a later migration.
    pub(crate) fn latest_migration(&self) -> Result<Option<MigrationState>, Error> {
        let conn = self.conn.borrow();
        let row: Option<i64> = conn
            .query_row(
                &format!(
                    "SELECT id FROM {} WHERE account_id = ? ORDER BY id DESC LIMIT 1",
                    self.tables.migrations
                ),
                params![self.account_id.0],
                |row| row.get(0),
            )
            .optional()?;
        row.map(|id| read_migration_row(conn, self.tables, id))
            .transpose()
    }

    /// The full state of the account's migration identified by `uuid` — historical or pending —
    /// or `None` when the account has no such migration.
    pub(crate) fn get_migration_by_id(
        &self,
        id: crate::pool_migration::MigrationUuid,
    ) -> Result<Option<MigrationState>, Error> {
        let conn = self.conn.borrow();
        let row: Option<i64> = conn
            .query_row(
                &format!(
                    "SELECT id FROM {} WHERE account_id = ? AND uuid = ?",
                    self.tables.migrations
                ),
                params![self.account_id.0, id.expose_uuid()],
                |row| row.get(0),
            )
            .optional()?;
        row.map(|id| read_migration_row(conn, self.tables, id))
            .transpose()
    }

    /// Every migration the account has run, newest first, PROJECTED IN SQL: the aggregate counts
    /// and mined value are computed by the database over the typed columns, and no stored PCZT is
    /// ever read, let alone parsed — a full [`MigrationState`] runs to megabytes of proofs, and a
    /// history listing must render without deserializing any of them.
    pub(crate) fn list_migrations(
        &self,
    ) -> Result<Vec<crate::pool_migration::MigrationSummary>, Error> {
        let conn = self.conn.borrow();
        let t = self.tables;
        // The lifecycle discriminants and the transfer kind are the engine's wire names, written
        // through `AsRef<str>` on the way in; stated here via the same constants' values rather
        // than re-derived per row.
        let mut stmt = conn.prepare(&format!(
            "SELECT m.uuid, m.status, m.committed_height,
                    m.note_split_total_input, m.note_split_total_migratable, m.note_split_change,
                    (SELECT COUNT(*) FROM {tx} t WHERE t.migration_id = m.id),
                    (SELECT COUNT(*) FROM {tx} t
                      WHERE t.migration_id = m.id AND t.state = 'mined'),
                    (SELECT COUNT(*) FROM {tx} t
                      WHERE t.migration_id = m.id AND t.state = 'broadcast'),
                    (SELECT COUNT(*) FROM {tx} t
                      WHERE t.migration_id = m.id AND t.unsatisfiable_at IS NOT NULL),
                    (SELECT IFNULL(SUM(cv.value), 0)
                       FROM {tx} t
                       JOIN {cv} cv
                         ON cv.migration_id = t.migration_id AND cv.ordinal = t.kind_crossing
                      WHERE t.migration_id = m.id AND t.kind = 'transfer' AND t.state = 'mined')
               FROM {m} m
              WHERE m.account_id = ?
              ORDER BY m.id DESC",
            m = t.migrations,
            tx = t.transactions,
            cv = t.crossing_values,
        ))?;
        let rows = stmt.query_map(params![self.account_id.0], |row| {
            Ok((
                row.get::<_, uuid::Uuid>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<u32>>(2)?,
                row.get::<_, u64>(3)?,
                row.get::<_, u64>(4)?,
                row.get::<_, Option<u64>>(5)?,
                row.get::<_, u64>(6)?,
                row.get::<_, u64>(7)?,
                row.get::<_, u64>(8)?,
                row.get::<_, u64>(9)?,
                row.get::<_, u64>(10)?,
            ))
        })?;
        rows.map(|row| {
            let (
                uuid,
                status,
                committed_height,
                total_input,
                total_migratable,
                change,
                total,
                mined,
                in_flight,
                unsatisfiable,
                value_migrated,
            ) = row?;
            Ok(crate::pool_migration::MigrationSummary {
                id: crate::pool_migration::MigrationUuid::from_uuid(uuid),
                status: MigrationStatus::try_from(status.as_str())
                    .map_err(|_| Error::Corrupt("status"))?,
                committed_height: committed_height.map(BlockHeight::from_u32),
                total_input: Zatoshis::from_u64(total_input)?,
                total_migratable: Zatoshis::from_u64(total_migratable)?,
                change: change.map(Zatoshis::from_u64).transpose()?,
                transaction_count: total as usize,
                mined_count: mined as usize,
                in_flight_count: in_flight as usize,
                unsatisfiable_count: unsatisfiable as usize,
                value_migrated: Zatoshis::from_u64(value_migrated)?,
            })
        })
        .collect()
    }

    /// Returns the set of [`LockOwner`]s under which this account's in-progress migration has
    /// locked notes (empty if the account has no migration, or none of its transactions hold a
    /// lock).
    pub(crate) fn migration_lock_owners(&self) -> Result<BTreeSet<LockOwner>, Error> {
        read_lock_owners(self.conn.borrow(), self.tables, self.account_id)
    }

    /// Report whether the wallet's chain view obstructs `tx`, per
    /// [`PoolMigrationRead::check_step_satisfiability`]'s contract. `source_root_at` is the
    /// source-pool tree access the anchor-validity judgment needs (see [`SourceRootAt`]).
    ///
    /// [`PoolMigrationRead::check_step_satisfiability`]:
    ///     zcash_pool_migration::engine::PoolMigrationRead::check_step_satisfiability
    pub(crate) fn check_step_satisfiability(
        &self,
        tx: &MigrationTransaction,
        settle: ReorgSettleDepth,
        source_root_at: Option<SourceRootAt>,
    ) -> Result<StepSatisfiability, Error> {
        check_step_satisfiability(
            self.conn.borrow(),
            self.tables,
            self.account_id,
            tx,
            settle,
            source_root_at,
        )
    }

    /// The height at which the wallet's scan has observed `txid` mined, per
    /// [`PoolMigrationRead::mined_height`]'s contract.
    ///
    /// [`PoolMigrationRead::mined_height`]: zcash_pool_migration::engine::PoolMigrationRead::mined_height
    pub(crate) fn mined_height(&self, txid: TxId) -> Result<Option<BlockHeight>, Error> {
        mined_height(self.conn.borrow(), txid)
    }
}

impl<C: BorrowMut<Connection>> Store<C> {
    pub(crate) fn replace_migration(&mut self, state: &MigrationState) -> Result<(), Error> {
        self.replace_migration_with(state, |_| Ok(()))
    }

    /// Cancel the account's migration: release every note reservation its never-broadcast
    /// transactions hold, then move its record to the terminal `cancelled` status — in that
    /// order, in one database transaction, so every crash prefix leaves a still-pending
    /// migration that a retried cancel finishes (the reverse order could leave a terminal
    /// record nothing will revisit while its reservations stand).
    ///
    /// Deliberately performed WITHOUT deserializing the migration state: the primary use case is
    /// an unrecoverable wallet, and a record that will not parse is one of the ways to get
    /// there. Everything needed — each transaction's lifecycle state and lock-owner token — is
    /// readable from typed columns.
    ///
    /// When the account has no PENDING migration, the latest retained record (if any) gets the
    /// REPAIR half only: its never-broadcast transactions' reservations are released, and its
    /// terminal status is left exactly as recorded — cancel never rewrites history, but a
    /// stranded reservation is not history, and the field contains terminal records (the mobile
    /// SDK's hand-rolled cancel persisted `failed`) whose locks nothing else will release before
    /// they expire.
    pub(crate) fn cancel_migration(
        &mut self,
    ) -> Result<crate::pool_migration::CancelOutcome, Error> {
        let tables = self.tables;
        let account_id = self.account_id;
        let tx = self.conn.borrow_mut().transaction()?;
        let outcome = cancel_migration(&tx, tables, account_id)?;
        tx.commit()?;
        Ok(outcome)
    }

    /// Replace the migration as [`replace_migration`](Self::replace_migration) does, then run
    /// `and_then` inside the SAME database transaction, so the store update and whatever the
    /// caller must record alongside it commit or roll back as one atomic write. This is the seam a
    /// pool facade uses to persist a finalized migration transaction into the wallet's own
    /// transaction tables atomically with the migration state that says it is proved.
    pub(crate) fn replace_migration_with<F>(
        &mut self,
        state: &MigrationState,
        and_then: F,
    ) -> Result<(), Error>
    where
        F: FnOnce(&rusqlite::Transaction<'_>) -> Result<(), Error>,
    {
        let tables = self.tables;
        let account_id = self.account_id;
        let tx = self.conn.borrow_mut().transaction()?;
        replace_migration(&tx, tables, account_id, state)?;
        and_then(&tx)?;
        tx.commit()?;
        Ok(())
    }

    pub(crate) fn update_transaction(
        &mut self,
        id: MigrationTransferId,
        state: MigrationTxState,
    ) -> Result<(), Error> {
        let tables = self.tables;
        let account_id = self.account_id;
        let conn = self.conn.borrow_mut();
        let migration_id = resolve_migration_id(conn, tables, account_id)?
            .ok_or(Error::Corrupt("update_transaction: no such transaction"))?;
        let updated = conn.execute(
            &format!(
                "UPDATE {}
                    SET state = :state, mined_height = :mined_height
                  WHERE migration_id = :migration_id AND transfer_id = :transfer_id",
                tables.transactions
            ),
            named_params! {
                ":state": state.as_ref(),
                // The row's id never changes with its lifecycle state, so the single-row
                // lifecycle update leaves the column alone.
                ":mined_height": state.mined_height().map(u32::from),
                ":migration_id": migration_id,
                ":transfer_id": u32::from(id),
            },
        )?;
        if updated == 0 {
            return Err(Error::Corrupt("update_transaction: no such transaction"));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Read
// ---------------------------------------------------------------------------

/// Resolve the primary key of `account_id`'s row in `t.migrations`, if one exists. Every child table
/// is addressed by this key rather than by `account_id` directly, so a write operation resolves
/// it once and reuses it for every subsequent query.
fn resolve_migration_id(
    conn: &Connection,
    t: &Tables,
    account_id: AccountRef,
) -> Result<Option<i64>, Error> {
    // PENDING-ONLY: terminal migrations are retained history, and every operation that addresses
    // "the account's migration" means the one still in progress. The partial unique index on
    // `(account_id) WHERE status NOT IN (terminal)` is what keeps this `query_row` well-defined
    // now that an account accumulates terminal rows.
    Ok(conn
        .query_row(
            &format!(
                "SELECT id FROM {} WHERE account_id = ? AND status NOT IN ({})",
                t.migrations,
                terminal_status_sql_list()
            ),
            params![account_id.0],
            |row| row.get(0),
        )
        .optional()?)
}

/// The distinct anchor bucket intervals, in blocks, of every migration in `t.migrations` that has
/// not reached a terminal status — the grids the wallet still owes anchor-checkpoint retention to.
///
/// This is read from the database rather than from any in-memory configuration on purpose. A
/// migration's transfers are anchored to boundaries of the grid it was COMMITTED under, and are
/// provable only while those boundaries' checkpoints survive pruning. Were retention driven by a
/// setting the application had to reapply on every open, forgetting to do so would let a scan pass
/// a boundary the migration still needs without retaining it — unrecoverably, since the checkpoint
/// is gone by the time anything notices.
///
/// A TERMINAL migration has no transfer left to prove, so its grid is dropped. For `complete` that
/// is because every transfer mined; for the policy determinations (`failed`, `superseded`,
/// `cancelled`) it is because nothing will drive the migration further, so retaining checkpoints
/// for proofs that will never be requested costs storage to no purpose — and, since a terminal
/// migration is never revisited, costs it forever.
///
/// The excluded set is [`MigrationStatus::terminal`], not a list of literals written out here: a
/// second list is a second place for a new status to be forgotten, and forgetting it here fails
/// silently, as unbounded retention rather than as an error.
pub(crate) fn active_anchor_bucket_intervals(
    conn: &Connection,
    t: &Tables,
) -> Result<BTreeSet<NonZeroU32>, Error> {
    let terminal: Vec<MigrationStatus> = MigrationStatus::terminal().collect();
    let placeholders = vec!["?"; terminal.len()].join(", ");
    let mut stmt = conn.prepare(&format!(
        "SELECT DISTINCT anchor_bucket_interval FROM {} WHERE status NOT IN ({placeholders})",
        t.migrations
    ))?;
    let rows = stmt.query_map(
        rusqlite::params_from_iter(terminal.iter().map(AsRef::<str>::as_ref)),
        |row| row.get::<_, u32>(0),
    )?;
    rows.map(|blocks| NonZeroU32::new(blocks?).ok_or(Error::Corrupt("anchor_bucket_interval")))
        .collect()
}

/// Roll every stored migration in `t` back to `height`, as the wallet's own truncation does to the
/// state it derives from the chain: marks resting on rolled-back chain state are cleared, mined
/// transactions above `height` are demoted to broadcast, and a `Complete` status a demotion
/// unsettles reverts (see [`MigrationState::truncate_to_height`], which defines all three).
///
/// This is driven from the wallet's truncation rather than left to the consumer because the two
/// must not be able to disagree: a migration whose marks and mined heights outlive the chain state
/// they were derived from would strand live value behind observations nothing will revisit, and a
/// wallet that truncates without telling its migration has no other moment at which to notice.
/// Runs inside the caller's transaction, so the wallet's truncation and the migration's are one
/// atomic step; a migration the truncation does not change is left untouched rather than rewritten.
pub(crate) fn truncate_to_height(
    tx: &rusqlite::Transaction,
    t: &Tables,
    height: BlockHeight,
) -> Result<(), Error> {
    // The walk visits every migration ROW whose determinations chain state can still revise: the
    // pending rows, and the `Complete` ones — `Complete` is chain-derived and exactly as revocable
    // as the chain it was derived from, so a reorg can un-mine a PREVIOUS migration's transfers
    // and must demote it. The policy determinations (`failed`, `superseded`, `cancelled`) record
    // decisions, not chain state, and stay put. Iterating rows rather than accounts is what
    // reaches retained history at all; each row is rewritten in place by id, preserving its
    // identity.
    //
    // Known sharp edge, deliberate for now: demoting a `Complete` row whose account has since
    // committed a NEW pending migration would violate the one-pending-per-account partial index,
    // and this walk lets that surface as a constraint error rather than silently skipping the
    // demotion — at that point two migrations genuinely claim liveness, and suppressing either
    // record would be worse than failing loudly. The resolution (how a revived historical
    // migration should coexist with its successor) is the history read API's problem, not the
    // truncation walk's.
    let policy_terminal = MigrationStatus::terminal()
        .filter(|s| !matches!(s, MigrationStatus::Complete))
        .map(|s| format!("'{}'", s.wire_name()))
        .collect::<Vec<_>>()
        .join(", ");
    let rows: Vec<(i64, i64)> = {
        let mut stmt = tx.prepare(&format!(
            "SELECT id, account_id FROM {} WHERE status NOT IN ({})",
            t.migrations, policy_terminal
        ))?;
        let rows = stmt.query_map([], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)))?;
        rows.collect::<Result<_, _>>()?
    };
    for (migration_id, account_id) in rows {
        let before = read_migration_row(tx, t, migration_id)?;
        let mut truncated = before.clone();
        truncated.truncate_to_height(height);
        if truncated != before {
            replace_migration_row(
                tx,
                t,
                AccountRef(account_id),
                Some(migration_id),
                &truncated,
            )?;
        }
    }
    Ok(())
}

/// What [`classify_for_cancel`] hands back: the outcome to report to the caller, paired with the
/// lock-owner tokens whose reservations the cancel must then release. The two travel together
/// because one pass over the transaction rows produces both.
type CancelClassification = (
    crate::pool_migration::CancelOutcome,
    Vec<MigrationLockOwner>,
);

/// The classification a cancel makes of one migration transaction, straight off its lifecycle
/// column: everything before broadcast is releasable (its reservation can be cleared and it will
/// never be submitted), everything at or past broadcast is chain reality to report, not undo.
fn classify_for_cancel(
    conn: &Connection,
    t: &Tables,
    migration_id: i64,
) -> Result<CancelClassification, Error> {
    let mut outcome = crate::pool_migration::CancelOutcome::default();
    let mut owners: Vec<MigrationLockOwner> = Vec::new();
    let mut stmt = conn.prepare(&format!(
        "SELECT transfer_id, state, lock_owner FROM {} WHERE migration_id = ? ORDER BY transfer_id",
        t.transactions
    ))?;
    let rows = stmt.query_map(params![migration_id], |row| {
        Ok((
            row.get::<_, u32>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, Option<[u8; 32]>>(2)?,
        ))
    })?;
    for row in rows {
        let (transfer_id, state, lock_owner) = row?;
        let id = MigrationTransferId::new(transfer_id);
        match state.as_str() {
            "broadcast" => outcome.in_flight.push(id),
            "mined" => outcome.mined.push(id),
            // `awaiting_signature`, `signed`, `proved` — and, defensively, anything a future
            // release might add before broadcast: never submitted, so releasable.
            _ => {
                outcome.released.push(id);
                if let Some(owner) = lock_owner {
                    owners.push(MigrationLockOwner::from_bytes(owner));
                }
            }
        }
    }
    Ok((outcome, owners))
}

/// Release the note reservations held under `owners` on the migration's SOURCE pool: the lock
/// columns note locking records on the received-note rows are cleared wherever they name one of
/// these tokens. Scoped strictly by owner token — which the prover derived from each
/// transaction's own spent notes — so no other flow's reservation can be touched.
///
/// Returns the number of note rows actually unlocked, which is informational only: it is NOT the
/// number of owners, since one token may hold several notes and a token whose notes have already
/// expired or been released holds none. Callers must not treat a zero here as a failure.
fn release_lock_owners(
    conn: &Connection,
    t: &Tables,
    owners: &[MigrationLockOwner],
) -> Result<usize, Error> {
    let mut stmt = conn.prepare(&format!(
        "UPDATE {} SET lock_expiry_height = NULL, lock_owner = NULL WHERE lock_owner = ?",
        t.source_notes
    ))?;
    let mut released = 0;
    for owner in owners {
        released += stmt.execute(params![owner.as_bytes()])?;
    }
    Ok(released)
}

/// The body of [`Store::cancel_migration`]; see its documentation for the contract, the ordering
/// argument, and the no-pending repair behavior.
fn cancel_migration(
    tx: &rusqlite::Transaction,
    t: &Tables,
    account_id: AccountRef,
) -> Result<crate::pool_migration::CancelOutcome, Error> {
    let (migration_id, is_pending) = match resolve_migration_id(tx, t, account_id)? {
        Some(id) => (Some(id), true),
        None => {
            // No pending migration: the repair half only, on the latest retained record.
            let latest: Option<i64> = tx
                .query_row(
                    &format!(
                        "SELECT id FROM {} WHERE account_id = ? ORDER BY id DESC LIMIT 1",
                        t.migrations
                    ),
                    params![account_id.0],
                    |row| row.get(0),
                )
                .optional()?;
            (latest, false)
        }
    };
    let Some(migration_id) = migration_id else {
        return Ok(crate::pool_migration::CancelOutcome::default());
    };

    let (outcome, owners) = classify_for_cancel(tx, t, migration_id)?;
    // Release BEFORE the status flip (and in the same transaction): a crash between the two
    // leaves a still-pending migration a retried cancel finishes.
    let released = release_lock_owners(tx, t, &owners)?;
    tracing::debug!(
        "cancel released {released} note reservation(s) across {} never-broadcast transaction(s); \
         {} in flight, {} already mined",
        outcome.released.len(),
        outcome.in_flight.len(),
        outcome.mined.len()
    );
    if is_pending {
        tx.execute(
            &format!("UPDATE {} SET status = ? WHERE id = ?", t.migrations),
            params![MigrationStatus::Cancelled.wire_name(), migration_id],
        )?;
    }
    Ok(outcome)
}

/// The account's migration IN PROGRESS, if any: resolves the pending row (see
/// [`resolve_migration_id`] for why the read is pending-only) and reads it back. Terminal rows are
/// retained history, addressed by row through [`read_migration_row`] instead.
fn read_migration(
    conn: &Connection,
    t: &Tables,
    account_id: AccountRef,
) -> Result<Option<MigrationState>, Error> {
    match resolve_migration_id(conn, t, account_id)? {
        Some(migration_id) => read_migration_row(conn, t, migration_id).map(Some),
        None => Ok(None),
    }
}

/// Read the migration stored as row `migration_id`, whatever its status: the row-addressed reader
/// that pending-only resolution and the truncation walk (which must revisit `Complete` rows —
/// chain-derived, and exactly as revocable as the chain they were derived from) share. Erring on
/// an absent row rather than returning an `Option`, because every caller has just SELECTed the id.
fn read_migration_row(
    conn: &Connection,
    t: &Tables,
    migration_id: i64,
) -> Result<MigrationState, Error> {
    let row = conn
        .query_row(
            &format!(
                "SELECT id, status, note_split_fee_buffer, note_split_change, note_split_prep_fees,
                        note_split_total_input, note_split_total_migratable, anchor_bucket_interval,
                        replan_threshold
                   FROM {} WHERE id = ?",
                t.migrations,
            ),
            params![migration_id],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, u64>(2)?,
                    row.get::<_, Option<u64>>(3)?,
                    row.get::<_, u64>(4)?,
                    row.get::<_, u64>(5)?,
                    row.get::<_, u64>(6)?,
                    row.get::<_, u32>(7)?,
                    row.get::<_, u8>(8)?,
                ))
            },
        )
        .optional()?;

    let Some((
        migration_id,
        status,
        fee_buffer,
        change,
        prep_fees,
        total_input,
        total_migratable,
        anchor_bucket_interval,
        replan_threshold,
    )) = row
    else {
        return Err(Error::Corrupt("read_migration_row: no such migration"));
    };
    let anchor_bucket_interval = NonZeroU32::new(anchor_bucket_interval)
        .map(AnchorBucketInterval::custom)
        .ok_or(Error::Corrupt("anchor_bucket_interval"))?;
    let replan_threshold =
        ReplanThreshold::new(replan_threshold).ok_or(Error::Corrupt("replan_threshold"))?;

    let crossing_values = read_zatoshi_list(conn, t.crossing_values, migration_id)?;
    let denominations = DenominationPlan::from_stored_parts(
        crossing_values,
        Zatoshis::from_u64(fee_buffer)?,
        change.map(Zatoshis::from_u64).transpose()?,
        Zatoshis::from_u64(prep_fees)?,
        Zatoshis::from_u64(total_input)?,
        Zatoshis::from_u64(total_migratable)?,
    )
    .map_err(|_| Error::Corrupt("denominations"))?;

    let preparation = read_preparation(conn, t, migration_id)?;
    let transactions = read_transactions(conn, t, migration_id)?;

    let status =
        MigrationStatus::try_from(status.as_str()).map_err(|_| Error::Corrupt("status"))?;
    Ok(MigrationState::from_parts(
        status,
        denominations,
        preparation,
        transactions,
        anchor_bucket_interval,
        replan_threshold,
    ))
}

/// Read an ordered list of zatoshi amounts (`ordinal`, `value`) from a child table.
fn read_zatoshi_list(
    conn: &Connection,
    table: &str,
    migration_id: i64,
) -> Result<Vec<Zatoshis>, Error> {
    let mut stmt = conn.prepare(&format!(
        "SELECT value FROM {table} WHERE migration_id = ? ORDER BY ordinal"
    ))?;
    let rows = stmt.query_map(params![migration_id], |row| row.get::<_, u64>(0))?;
    let mut out = Vec::new();
    for v in rows {
        out.push(Zatoshis::from_u64(v?)?);
    }
    Ok(out)
}

fn read_preparation(
    conn: &Connection,
    t: &Tables,
    migration_id: i64,
) -> Result<PreparationPlan, Error> {
    // The layers/transactions grid, reconstructed from the input and output rows: every transaction
    // has at least one such row (the write side rejects a state where one does not), so the distinct
    // `(layer, tx_index)` coordinates enumerate the full grid in order.
    let coords: Vec<(usize, usize)> = {
        let mut stmt = conn.prepare(&format!(
            "SELECT layer, tx_index FROM {} WHERE migration_id = :id
             UNION
             SELECT layer, tx_index FROM {} WHERE migration_id = :id
             ORDER BY layer, tx_index",
            t.prep_inputs, t.prep_outputs
        ))?;
        let rows = stmt.query_map(named_params! { ":id": migration_id }, |row| {
            Ok((
                row.get::<_, u64>(0)? as usize,
                row.get::<_, u64>(1)? as usize,
            ))
        })?;
        rows.collect::<Result<_, _>>()?
    };
    let mut layers: Vec<Vec<PrepTransaction>> = Vec::new();
    for (layer, tx_index) in coords {
        // Both indices must be contiguous from zero: a gap means a layer or transaction left no
        // rows, and silently renumbering would misdirect later layers' prior-output references.
        if layer == layers.len() && tx_index == 0 {
            layers.push(Vec::new());
        } else if !(layer + 1 == layers.len() && tx_index == layers[layer].len()) {
            return Err(Error::Corrupt(
                "preparation grid: non-contiguous coordinates",
            ));
        }
        let inputs = read_prep_inputs(conn, t, migration_id, layer, tx_index)?;
        let outputs = read_prep_outputs(conn, t, migration_id, layer, tx_index)?;
        layers[layer].push(PrepTransaction::from_parts(inputs, outputs));
    }

    let direct_funding = {
        let mut stmt = conn.prepare(&format!(
            "SELECT wallet_index, value FROM {} WHERE migration_id = ? ORDER BY ordinal",
            t.prep_direct_funding
        ))?;
        let rows = stmt.query_map(params![migration_id], |row| {
            Ok((row.get::<_, u64>(0)? as usize, row.get::<_, u64>(1)?))
        })?;
        let mut out = Vec::new();
        for r in rows {
            let (idx, value) = r?;
            out.push((idx, Zatoshis::from_u64(value)?));
        }
        out
    };

    Ok(PreparationPlan::from_parts(layers, direct_funding))
}

fn read_prep_inputs(
    conn: &Connection,
    t: &Tables,
    migration_id: i64,
    layer: usize,
    tx_index: usize,
) -> Result<Vec<PrepInput>, Error> {
    let mut stmt = conn.prepare(&format!(
        "SELECT source, wallet_index, prior_layer, prior_transaction, prior_output, value
           FROM {}
          WHERE migration_id = ? AND layer = ? AND tx_index = ?
          ORDER BY ordinal",
        t.prep_inputs
    ))?;
    let rows = stmt.query_map(
        params![migration_id, layer as u64, tx_index as u64],
        |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Option<u64>>(1)?,
                row.get::<_, Option<u64>>(2)?,
                row.get::<_, Option<u64>>(3)?,
                row.get::<_, Option<u64>>(4)?,
                row.get::<_, u64>(5)?,
            ))
        },
    )?;
    let mut out = Vec::new();
    for r in rows {
        let (source, wallet_index, prior_layer, prior_transaction, prior_output, value) = r?;
        let value = Zatoshis::from_u64(value)?;
        let input = match source.as_str() {
            "wallet" => PrepInput::Wallet {
                index: wallet_index.ok_or(Error::Corrupt("prep_input.wallet_index"))? as usize,
                value,
            },
            "prior" => PrepInput::Prior {
                layer: prior_layer.ok_or(Error::Corrupt("prep_input.prior_layer"))? as usize,
                transaction: prior_transaction
                    .ok_or(Error::Corrupt("prep_input.prior_transaction"))?
                    as usize,
                output: prior_output.ok_or(Error::Corrupt("prep_input.prior_output"))? as usize,
                value,
            },
            _ => return Err(Error::Corrupt("prep_input.source")),
        };
        out.push(input);
    }
    Ok(out)
}

fn read_prep_outputs(
    conn: &Connection,
    t: &Tables,
    migration_id: i64,
    layer: usize,
    tx_index: usize,
) -> Result<Vec<PrepOutput>, Error> {
    let mut stmt = conn.prepare(&format!(
        "SELECT role, value FROM {}
          WHERE migration_id = ? AND layer = ? AND tx_index = ?
          ORDER BY ordinal",
        t.prep_outputs
    ))?;
    let rows = stmt.query_map(
        params![migration_id, layer as u64, tx_index as u64],
        |row| Ok((row.get::<_, String>(0)?, row.get::<_, u64>(1)?)),
    )?;
    let mut out = Vec::new();
    for r in rows {
        let (role, value) = r?;
        let value = Zatoshis::from_u64(value)?;
        let output =
            PrepOutput::from_role(&role, value).map_err(|_| Error::Corrupt("prep_output.role"))?;
        out.push(output);
    }
    Ok(out)
}

fn read_transactions(
    conn: &Connection,
    t: &Tables,
    migration_id: i64,
) -> Result<Vec<MigrationTransaction>, Error> {
    let rows: Vec<TxRow> = {
        let mut stmt = conn.prepare(&format!(
            "SELECT transfer_id, kind, kind_layer, kind_index, kind_crossing, pczt,
                    scheduled_height, expiry_height, anchor_boundary, state, txid, mined_height,
                    lock_owner, unsatisfiable_at, unsatisfiable_kind, broadcast_failure_at
               FROM {}
              WHERE migration_id = ?
              ORDER BY transfer_id",
            t.transactions
        ))?;
        let mapped = stmt.query_map(params![migration_id], |row| {
            Ok(TxRow {
                transfer_id: row.get(0)?,
                kind: row.get(1)?,
                kind_layer: row.get(2)?,
                kind_index: row.get(3)?,
                kind_crossing: row.get(4)?,
                pczt: row.get(5)?,
                scheduled_height: row.get(6)?,
                expiry_height: row.get(7)?,
                anchor_boundary: row.get(8)?,
                state: row.get(9)?,
                txid: row.get(10)?,
                mined_height: row.get(11)?,
                lock_owner: row.get(12)?,
                unsatisfiable_at: row.get(13)?,
                unsatisfiable_kind: row.get(14)?,
                broadcast_failure_at: row.get(15)?,
            })
        })?;
        mapped.collect::<Result<_, _>>()?
    };

    let mut out = Vec::with_capacity(rows.len());
    for r in rows {
        let id = MigrationTransferId::new(r.transfer_id);
        let kind = MigrationTxKind::from_stored(
            &r.kind,
            r.kind_layer.map(|x| x as usize),
            r.kind_index.map(|x| x as usize),
            r.kind_crossing.map(|x| x as usize),
        )
        .map_err(|_| Error::Corrupt("kind"))?;
        // Every row carries its transaction's id, derived when the transaction was built, so this
        // is required rather than optional — and it is the SAME value the lifecycle state carries
        // once broadcast, which is why the state is reassembled from it below rather than from a
        // separately stored copy that could disagree.
        let txid = r.txid.map(TxId::from_bytes).ok_or(Error::Corrupt("txid"))?;
        let state = MigrationTxState::from_stored(
            &r.state,
            Some(<[u8; 32]>::from(txid)),
            r.mined_height.map(BlockHeight::from_u32),
        )
        .map_err(|_| Error::Corrupt("state"))?;
        let depends_on = read_deps(conn, t, migration_id, r.transfer_id)?;
        let spend_nullifiers = read_spend_nullifiers(conn, t, migration_id, r.transfer_id)?;

        // An unsatisfiability mark is ONE value spread over two columns: the height the
        // observation rests on and which observation it was. A name this build does not know is
        // corruption, exactly as an unrecognized `state` or `status` discriminant is — treating it
        // as no mark would return a dead transaction to the prove and broadcast queues.
        let unsatisfiable_at = r.unsatisfiable_at.map(BlockHeight::from_u32);
        let unsatisfiable_kind = r
            .unsatisfiable_kind
            .as_deref()
            .map(|name| {
                UnsatisfiableKind::try_from(name).map_err(|_| Error::Corrupt("unsatisfiable_kind"))
            })
            .transpose()?;
        // The engine holds the mark as a pair, so only a row carrying both halves or neither
        // reassembles: a stamp without a kind cannot be rendered, and a kind without a stamp has
        // no height for reorg truncation to judge it against, so either alone was not written by
        // this store.
        let unsatisfiable = match (unsatisfiable_at, unsatisfiable_kind) {
            (Some(at), Some(kind)) => Some((at, kind)),
            (None, None) => None,
            _ => {
                return Err(Error::Corrupt(
                    "unsatisfiable_at / unsatisfiable_kind disagree",
                ));
            }
        };

        out.push(MigrationTransaction::from_parts(
            id,
            kind,
            r.pczt,
            depends_on,
            BlockHeight::from_u32(r.scheduled_height),
            BlockHeight::from_u32(r.expiry_height),
            r.anchor_boundary.map(BlockHeight::from_u32),
            txid,
            state,
            r.lock_owner.map(MigrationLockOwner::from_bytes),
            unsatisfiable,
            spend_nullifiers,
            r.broadcast_failure_at.map(BlockHeight::from_u32),
        ));
    }
    Ok(out)
}

/// Returns the distinct [`LockOwner`]s recorded on `account`'s migration transactions (empty if
/// the account has no migration, or none of its transactions hold a lock). A direct `DISTINCT`
/// query over the transactions table, scoped by the account's resolved migration id, so this
/// avoids reconstructing the whole migration (with its preparation plan and every transaction)
/// just to inspect which locks it holds.
fn read_lock_owners(
    conn: &Connection,
    t: &Tables,
    account: AccountRef,
) -> Result<BTreeSet<LockOwner>, Error> {
    let Some(migration_id) = resolve_migration_id(conn, t, account)? else {
        return Ok(BTreeSet::new());
    };
    let mut stmt = conn.prepare(&format!(
        "SELECT DISTINCT lock_owner FROM {} WHERE migration_id = ? AND lock_owner IS NOT NULL",
        t.transactions
    ))?;
    let rows = stmt.query_map(params![migration_id], |row| row.get::<_, [u8; 32]>(0))?;
    let mut out = BTreeSet::new();
    for r in rows {
        out.insert(LockOwner::new(r?));
    }
    Ok(out)
}

/// One row of the transactions table, before it is decoded into a [`MigrationTransaction`]. The
/// field names mirror the column names exactly.
struct TxRow {
    /// The transaction's ordinal within its migration — the second half of the table's
    /// `(migration_id, transfer_id)` primary key, and the [`MigrationTransferId`] dependency edges
    /// name it by. Unrelated to `txid` below; the released creating migration still spells this
    /// `tx_id`, which is what made the two easy to read as one.
    transfer_id: u32,
    kind: String,
    kind_layer: Option<u64>,
    kind_index: Option<u64>,
    kind_crossing: Option<u64>,
    pczt: Vec<u8>,
    scheduled_height: u32,
    expiry_height: u32,
    anchor_boundary: Option<u32>,
    state: String,
    /// The hex-encoded consensus transaction ID the transaction was broadcast under; `NULL` until
    /// it is broadcast. Unrelated to `transfer_id` above.
    txid: Option<[u8; 32]>,
    mined_height: Option<u32>,
    /// The stored lock-owner token, read directly as a fixed-size blob: `rusqlite`'s `[u8; 32]`
    /// `FromSql` impl errors cleanly (`InvalidBlobSize`) if a non-NULL blob is not exactly 32
    /// bytes, so a corrupt row is rejected rather than silently truncated or panicking.
    lock_owner: Option<[u8; 32]>,
    /// The chain height backing a spent-input observation, when the transaction has been
    /// determined unsatisfiable; `NULL` while no such determination stands.
    unsatisfiable_at: Option<u32>,
    /// The wire name of the [`UnsatisfiableKind`] recorded beside `unsatisfiable_at`, still
    /// unparsed here; the decode step parses it and rejects a row where the two columns disagree
    /// about whether a mark stands.
    unsatisfiable_kind: Option<String>,
    /// The chain tip an application observed from a node that rejected a broadcast of this
    /// transaction, while that rejection stands unadjudicated; `NULL` otherwise. Independent of
    /// the mark columns above in both directions.
    broadcast_failure_at: Option<u32>,
}

fn read_deps(
    conn: &Connection,
    t: &Tables,
    migration_id: i64,
    transfer_id: u32,
) -> Result<Vec<MigrationTransferId>, Error> {
    let mut stmt = conn.prepare(&format!(
        "SELECT depends_on_transfer_id FROM {}
          WHERE migration_id = ? AND transfer_id = ?
          ORDER BY ordinal",
        t.transaction_deps
    ))?;
    let rows = stmt.query_map(params![migration_id, transfer_id], |row| {
        row.get::<_, u32>(0)
    })?;
    let mut out = Vec::new();
    for r in rows {
        out.push(MigrationTransferId::new(r?));
    }
    Ok(out)
}

/// The cached real-spend nullifiers of one migration transaction, in the order it holds them.
///
/// Read like the dependency edges beside them: one child-table query per transaction, ordered by
/// the `ordinal` that carries the list's order. A row whose `nullifier` is not exactly 32 bytes is
/// rejected by `rusqlite`'s fixed-size-array `FromSql` impl (`InvalidBlobSize`), which is the
/// read-side half of the `CHECK` the table carries — the write side cannot store one at all.
///
/// A transaction with NO rows here reads back with an empty cache, which is not by itself
/// corruption: a `mined` transaction is exempt from the backfill that populates it. The
/// non-vacuity rule belongs to whoever asks a satisfiability question about the transaction; see
/// [`check_step_satisfiability`].
fn read_spend_nullifiers(
    conn: &Connection,
    t: &Tables,
    migration_id: i64,
    transfer_id: u32,
) -> Result<Vec<[u8; 32]>, Error> {
    let mut stmt = conn.prepare(&format!(
        "SELECT nullifier FROM {}
          WHERE migration_id = ? AND transfer_id = ?
          ORDER BY ordinal",
        t.spend_nullifiers
    ))?;
    let rows = stmt.query_map(params![migration_id, transfer_id], |row| {
        row.get::<_, [u8; 32]>(0)
    })?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}

/// Report whether the wallet's chain view obstructs the pre-signed transaction `tx`, observed at
/// the wallet's fully-scanned height: each cached real-spend nullifier is looked up in the source
/// pool's received-note table (scoped to the store's account), a spend recorded in a transaction
/// MINED within the scanned region reads as [`SeenSpent`](InputObservation::SeenSpent), a known
/// note without one as [`Unspent`](InputObservation::Unspent), and an unrecognized nullifier as
/// [`Unknown`](InputObservation::Unknown); the observations, plus the transaction-level expiry
/// judgment, then compose through [`classify_input_observations`].
///
/// A broadcast-but-unmined transaction additionally has its INSTALLED anchor judged against the
/// current chain (see [`anchor_displaced`]), which is where `settle` and `source_root_at` are
/// used; that answer takes the precedence position below `Expired`, so it is asked only when the
/// per-input fold has answered nothing definite.
///
/// The per-input [`InputObservation::Invalidated`] observation — a known note whose UNMINED
/// creating transaction was itself proven against a dead anchor — is NOT produced, so a
/// dead-anchored creator still reads as `Unspent` or `Unknown`, which errs toward `Satisfiable` /
/// `NotYetSatisfiable`, never toward a false mark. Two data are missing for it, and neither is
/// recoverable from what the wallet stores:
///
/// - the creating transaction's ANCHOR HEIGHT. A raw transaction carries its anchor ROOT, not the
///   height that root was drawn at, and the wallet's `transactions` table has no anchor column. The
///   settlement judgment (invariant: a displacement is definitive only once the chain has built
///   `settle` blocks past the displaced height) has no reference height to be made against — and
///   the only case that would need one is exactly the case a root search cannot date, since a root
///   still found among the retained checkpoints is by definition still live.
/// - a FOREIGN unmined creator's raw bytes. `transactions.raw` is nullable and is populated only
///   for transactions the wallet itself created or has since enhanced, so for the general creator
///   the anchor cannot be read at all.
///
/// A creator INSIDE the migration needs neither: `advance_migration` reaches its victims through
/// the dependency closure of the producer's own mark.
/// The height at which the wallet's scan has observed `txid` mined, or `None`.
///
/// Bounded by the FULLY-SCANNED height, not the chain tip (which is what `wallet::get_tx_height`
/// bounds by): `transactions.mined_height` is also written by transaction-status retrieval, which
/// can learn that a transaction mined well before scanning reaches its block. Promoting on that
/// would stamp `Mined { height }` above the region a rollback truncates, and
/// `MigrationState::truncate_to_height` would then leave the promotion standing over chain state
/// the wallet had discarded. The bound is the same one every unsatisfiability mark rests on — see
/// `check_step_satisfiability`'s `as_of_height` discipline — so inclusion and obstruction are
/// judged against one consistent view of what this wallet has actually seen.
///
/// A wallet that has scanned nothing has no view to answer from, so it reports nothing mined
/// rather than erroring: the sweep this serves runs on every drive call, including before a wallet
/// has ever synced, and "not observed mined" is the honest answer there.
fn mined_height(conn: &Connection, txid: TxId) -> Result<Option<BlockHeight>, Error> {
    let view = conn.unchecked_transaction()?;
    let Some(as_of_height) = crate::wallet::fully_scanned_height(&view)? else {
        return Ok(None);
    };
    let mined = view
        .query_row(
            "SELECT mined_height FROM transactions WHERE txid = :txid",
            named_params! { ":txid": txid.as_ref() },
            |row| Ok(row.get::<_, Option<u32>>(0)?.map(BlockHeight::from)),
        )
        .optional()?
        .flatten();
    view.commit()?;
    Ok(mined.filter(|height| *height <= as_of_height))
}

fn check_step_satisfiability(
    conn: &Connection,
    t: &Tables,
    account_id: AccountRef,
    tx: &MigrationTransaction,
    settle: ReorgSettleDepth,
    source_root_at: Option<SourceRootAt>,
) -> Result<StepSatisfiability, Error> {
    // An empty nullifier cache on a non-mined transaction is corruption, never vacuous
    // satisfiability (see `classify_input_observations`): every validly committed transaction
    // caches its real-spend nullifiers, and only a mined row is exempt from the backfill that
    // supplies the cache for transactions committed before it existed. That exemption is the
    // `orchard_ironwood_migration_unsatisfiability` schema migration's, and it is why the empty
    // cache is admissible at all: a stored PCZT that has been PROVEN no longer says which of its
    // spends are real, so the cache cannot be reconstructed from one, and hard-failing there would
    // block every wallet whose migration had already completed for no benefit while the row stays
    // mined. Checked before anything touches the database: corruption needs no chain state, so a
    // wallet with nothing scanned still reports it (rather than masking it as
    // [`Error::ChainStateUnavailable`]).
    if tx.spend_nullifiers().is_empty() && !matches!(tx.state(), MigrationTxState::Mined { .. }) {
        return Err(Error::Corrupt("spend_nullifiers"));
    }

    // Every read — the fully-scanned height, the per-nullifier observations, and the anchor
    // comparison — happens inside one transaction, so the answer rests on a single database
    // snapshot: a concurrent scan cannot advance the scan queue between the `as_of_height` read
    // and the observations it is supposed to back, nor rewrite the commitment tree between the
    // `as_of_height` read and the roots compared against it. Every observation applies the same
    // evidence-height <= `as_of_height` discipline.
    let view = conn.unchecked_transaction()?;

    let as_of_height =
        crate::wallet::fully_scanned_height(&view)?.ok_or(Error::ChainStateUnavailable)?;

    // Per cached nullifier: is the note known, and if so, has the wallet seen it spent in a
    // transaction MINED at or below `as_of_height`? An unmined recorded spend does not obstruct:
    // the pre-signed transaction and the recorded spender are then merely competing for the note.
    //
    // The `mined_height <= as_of_height` bound is the invariant that keeps unsatisfiability marks
    // honest: a mark's evidence must lie inside the scanned region backing `as_of_height`, because
    // reorg truncation clears marks whose `unsatisfiable_at` exceeds the truncation height — so
    // evidence at height <= `as_of_height` guarantees that a rollback of the evidence forces a
    // truncation below the mark's stamp, and no false mark can survive. Evidence ABOVE
    // `as_of_height` (possible when transaction-status polling records a mined height ahead of
    // scanning) must not obstruct yet; it reads as `Unspent` until scanning catches up.
    let mut stmt = view.prepare(&format!(
        "SELECT EXISTS (
             SELECT 1 FROM {spends} s
             JOIN transactions ON transactions.id_tx = s.transaction_id
             WHERE s.{note_fk} = rn.id AND transactions.mined_height <= :as_of_height
         )
         FROM {notes} rn
         WHERE rn.nf = :nf AND rn.account_id = :account_id",
        spends = t.source_note_spends,
        note_fk = t.source_note_spends_note_fk,
        notes = t.source_notes,
    ))?;
    let observations = tx
        .spend_nullifiers()
        .iter()
        .map(|nf| {
            let seen_spent: Option<bool> = stmt
                .query_row(
                    named_params! {
                        ":nf": nf,
                        ":account_id": account_id.0,
                        ":as_of_height": u32::from(as_of_height),
                    },
                    |row| row.get(0),
                )
                .optional()?;
            Ok((
                *nf,
                match seen_spent {
                    None => InputObservation::Unknown,
                    Some(false) => InputObservation::Unspent,
                    Some(true) => InputObservation::SeenSpent,
                },
            ))
        })
        .collect::<Result<Vec<_>, Error>>()?;
    drop(stmt);

    // Expiry is judged at the next block the transaction could be mined in (`as_of_height + 1`),
    // mirroring the engine's `MigrationState::is_expired` exactly: an `expiry_height` of 0
    // disables expiry, and a mined transaction is never expired.
    let expiry = u32::from(tx.expiry_height());
    let expired = !matches!(tx.state(), MigrationTxState::Mined { .. })
        && expiry != 0
        && expiry <= u32::from(as_of_height);

    let classified = classify_input_observations(as_of_height, expired, &observations);

    // `AnchorInvalidated` sits BELOW `Expired` in the answer precedence, so it is asked only when
    // the per-input fold (and expiry) answered nothing definite. Asking it last also keeps the
    // tree work off every answer that was already decided.
    let answer = if matches!(
        classified,
        StepSatisfiability::Satisfiable { .. } | StepSatisfiability::NotYetSatisfiable { .. }
    ) && anchor_displaced(&view, t, tx, as_of_height, settle, source_root_at)?
    {
        StepSatisfiability::Unsatisfiable {
            cause: UnsatisfiableCause::AnchorInvalidated,
            as_of_height,
        }
    } else {
        classified
    };

    view.commit()?;
    Ok(answer)
}

/// Whether `tx` is broadcast, unmined, and PERMANENTLY unminable because the anchor installed in
/// its proven PCZT is no longer a root of the chain the wallet has scanned — the observation
/// behind [`UnsatisfiableCause::AnchorInvalidated`].
///
/// Every gate below is a condition for CONCLUDING; failing any of them answers "cannot conclude"
/// (`false`), never "invalidated", because a false mark strands live value behind an observation
/// only a reorg can clear.
///
/// 1. **Only a broadcast-unmined transaction.** A transaction that has not been proven has no
///    installed anchor to judge, and a mined one's disposition no longer turns on it.
/// 2. **Only a transaction that RECORDS the height it anchored to.** A transfer's
///    [`anchor_boundary`](MigrationTransaction::anchor_boundary) is that height; a PREPARATION
///    carries none — it is proved against a caller-chosen checkpoint at or after its dependencies
///    mined, and that height is persisted nowhere — so a preparation is not judged here. Without
///    it there is neither a root to compare against nor a reference height to settle the
///    comparison at.
/// 3. **Evidence at or below `as_of_height`.** A boundary above the fully-scanned height is
///    outside the region backing this answer; its checkpoint may yet be rewritten by scanning that
///    has not happened. This is the invariant that keeps a mark honest: the mark carries
///    `as_of_height`, and reorg truncation clears marks stamped above the truncation height, so
///    evidence inside the scanned region guarantees a rollback of that evidence forces a truncation
///    below the stamp.
/// 4. **Settled per the caller's [`ReorgSettleDepth`].** The displacement is definitive only once
///    the scanned chain has built `settle` blocks on top of the boundary whose content changed:
///    `as_of_height >= boundary + settle`. Since a displacement at the boundary means the chains
///    forked strictly BELOW it, this also buries the fork itself by more than `settle` — the rule
///    is stricter than "the fork is settled", never laxer. It rests only on `as_of_height` and a
///    height the transaction itself records, so it needs no reorg history the wallet does not keep.
/// 5. **An EXHAUSTIVE negative.** A mismatch at the boundary is not by itself death: consensus
///    accepts an anchor that is the root of ANY previous block, and a reorg that re-mines the same
///    outputs across different block boundaries leaves the same root live at a different height.
///    So the installed anchor is ruled out against every distinct tree state the wallet retains at
///    or below `as_of_height`, and only an exhaustive miss concludes. A state whose root the
///    retained shard data cannot produce is one that was not ruled out, so it ends the search
///    without concluding, as does a probe set larger than [`ANCHOR_PROBE_LIMIT`].
///
/// What the wallet RETAINS is narrower than what it has SCANNED, and that is the one place this
/// judgment can still be wrong. The shard tree prunes ordinary checkpoints past `PRUNING_DEPTH`,
/// keeping only the anchor-grid boundaries beyond it, so a root that aged out without being a
/// retained boundary is invisible to the search: an exhaustive miss over the retained states is
/// not an exhaustive miss over the chain's blocks. The hole opens only once the fork carries more
/// than `PRUNING_DEPTH` blocks — a reorg deeper than the wallet's own rewind window — and it
/// cannot be closed by waiting, since a transfer's expiry window is far wider than that. This is
/// the residual case in which the judgment can mark a transfer that is still, in fact, mineable.
///
/// Only the SOURCE pool's anchor is judged. A transfer also installs a DESTINATION-pool anchor at
/// the same height, and a reorg can invalidate that one alone; not judging it can only miss a
/// death (answering satisfiable for a transaction that will not mine), never invent one, and the
/// missed case self-heals at the transaction's own expiry.
fn anchor_displaced(
    view: &rusqlite::Transaction<'_>,
    t: &Tables,
    tx: &MigrationTransaction,
    as_of_height: BlockHeight,
    settle: ReorgSettleDepth,
    source_root_at: Option<SourceRootAt>,
) -> Result<bool, Error> {
    if !matches!(tx.state(), MigrationTxState::Broadcast { .. }) {
        return Ok(false);
    }
    let (Some(root_at), Some(boundary)) = (source_root_at, tx.anchor_boundary()) else {
        return Ok(false);
    };
    if boundary > as_of_height || u32::from(as_of_height) - u32::from(boundary) < settle.blocks() {
        return Ok(false);
    }

    // The anchor the PROVER installed, read back from the stored proven PCZT — the only record of
    // it, since neither the engine's transaction type nor this schema stores anchor bytes. It is
    // absent on a PCZT that was never proven, which a broadcast transaction's cannot be.
    let Some(installed) = installed_source_anchor(tx.pczt())? else {
        return Ok(false);
    };
    let Some(at_boundary) = root_at(view, boundary)? else {
        // The boundary's checkpoint is not retained, so there is nothing to compare: whether the
        // anchor still names a root of this chain is simply unknown here.
        return Ok(false);
    };
    if at_boundary == installed {
        return Ok(false);
    }

    let probes = source_tree_probe_heights(view, t, boundary, as_of_height)?;
    if probes.len() > ANCHOR_PROBE_LIMIT {
        return Ok(false);
    }
    for height in probes {
        match root_at(view, height)? {
            // A state whose root the retained shard data cannot produce is a state that was NOT
            // ruled out; concluding over it would not be an exhaustive negative.
            None => return Ok(false),
            Some(root) if root == installed => return Ok(false),
            Some(_) => {}
        }
    }
    Ok(true)
}

/// The SOURCE-pool anchor installed in a stored PCZT, or `None` if none has been installed (the
/// PCZT was never proven).
///
/// The `orchard` bundle of the PCZT data model is the SOURCE bundle of every pool migration this
/// store serves: a ZIP 318 crossing spends Orchard notes and creates destination-pool ones, which
/// occupy the separate `ironwood` bundle. The same assumption backs the `spend_nullifiers` cache
/// the schema migration backfills from these bytes. Reading it needs only the base PCZT data
/// model, no protocol feature.
fn installed_source_anchor(pczt: &[u8]) -> Result<Option<[u8; 32]>, Error> {
    let parsed = pczt::Pczt::parse(pczt).map_err(|_| Error::Corrupt("pczt"))?;
    Ok(*parsed.orchard().anchor())
}

/// The checkpoint heights at which the source pool's tree takes each DISTINCT state at or below
/// `as_of_height` — the complete set of heights whose roots an installed anchor must be ruled out
/// of, ordered by distance from `boundary` so a still-live anchor is found in the fewest probes.
///
/// Checkpoints sharing a `position` share a root (a block that added no note commitments leaves the
/// tree where it was), so one representative per position is enough, and the empty tree state
/// (`position IS NULL`) groups as one alongside them.
fn source_tree_probe_heights(
    view: &rusqlite::Transaction<'_>,
    t: &Tables,
    boundary: BlockHeight,
    as_of_height: BlockHeight,
) -> Result<Vec<BlockHeight>, Error> {
    let mut stmt = view.prepare(&format!(
        "SELECT MIN(checkpoint_id) FROM {} WHERE checkpoint_id <= :as_of_height GROUP BY position",
        t.source_tree_checkpoints
    ))?;
    let rows = stmt.query_map(
        named_params! { ":as_of_height": u32::from(as_of_height) },
        |row| row.get::<_, u32>(0),
    )?;
    let mut out = Vec::new();
    for height in rows {
        out.push(BlockHeight::from_u32(height?));
    }
    out.sort_by_key(|h| u32::from(*h).abs_diff(u32::from(boundary)));
    Ok(out)
}

// ---------------------------------------------------------------------------
// Write
// ---------------------------------------------------------------------------

/// Replace `account_id`'s migration in the tables named by `t` with `state` (deletes that account's
/// existing migration and its children first, if any). Runs inside the caller's transaction so the
/// replacement is atomic.
fn replace_migration(
    tx: &rusqlite::Transaction,
    t: &Tables,
    account_id: AccountRef,
    state: &MigrationState,
) -> Result<(), Error> {
    let prior = resolve_migration_id(tx, t, account_id)?;
    replace_migration_row(tx, t, account_id, prior, state)
}

/// Persist `state` as the migration row `prior` — updating the parent row in place and replacing
/// its child rows wholesale — or insert it fresh when `prior` is `None`. A record therefore keeps
/// its `id`, `uuid`, and `committed_height` for its whole life; every other column mirrors
/// `state`. The row-addressed half of [`replace_migration`], shared with the truncation walk —
/// which rewrites rows (including revisited `Complete` history) that pending-only resolution
/// cannot name.
fn replace_migration_row(
    tx: &rusqlite::Transaction,
    t: &Tables,
    account_id: AccountRef,
    prior: Option<i64>,
    state: &MigrationState,
) -> Result<(), Error> {
    // The layers/transactions grid is stored only through the input and output rows, so a layer
    // with no transactions, or a transaction with neither inputs nor outputs, would leave no trace
    // and read back with later coordinates silently renumbered — misdirecting prior-output
    // references. A plan the engine produced never contains these; reject rather than corrupt.
    for transactions in state.preparation().layers() {
        if transactions.is_empty() {
            return Err(Error::Unrepresentable("empty preparation layer"));
        }
        for prep_tx in transactions {
            if prep_tx.inputs().is_empty() && prep_tx.outputs().is_empty() {
                return Err(Error::Unrepresentable(
                    "preparation transaction with no inputs or outputs",
                ));
            }
        }
    }

    // The child tables are replaced wholesale (delete, then reinsert below): the state is a
    // nested aggregate and this keeps "the store agrees with `state`" true by construction, with
    // no per-row diff logic to drift. The PARENT row is updated in place, so `id` is stable for
    // the record's life (the children key off it), as are the identity columns the state does
    // not carry: `uuid`, and `committed_height` (a fact about the one commit event). A state
    // persisted as terminal keeps its row — `resolve_migration_id` is pending-only, so nothing
    // ever addresses it as "the account's migration" again — which is how a migration enters the
    // retained history. Children are deleted explicitly in case foreign-key cascades are not
    // enabled.
    // A state persisted as TERMINAL is leaving service: nothing will ever broadcast its pending
    // transactions, so the reservations they hold are released here, in the same write that
    // records the terminal status. This is what discharges the release obligation for EVERY
    // terminal transition that flows through the ordinary persist path — the consumer's
    // `mark_superseded` response to `Replan`, an engine-side `mark_cancelled`, a `Failed`
    // post-mortem — not only the store-level cancel (which exists for records this path cannot
    // read).
    if state.is_terminal() {
        let owners: Vec<MigrationLockOwner> = state
            .transactions()
            .iter()
            .filter(|t| {
                !matches!(
                    t.state(),
                    MigrationTxState::Broadcast { .. } | MigrationTxState::Mined { .. }
                )
            })
            .filter_map(|t| t.lock_owner())
            .collect();
        let released = release_lock_owners(tx, t, &owners)?;
        tracing::debug!(
            "released {released} note reservation(s) held by {} transaction(s) of the migration \
             now persisted as terminal",
            owners.len()
        );
    }

    let ns = state.denominations();
    let migration_id = match prior {
        Some(migration_id) => {
            for table in [
                t.transaction_deps,
                t.spend_nullifiers,
                t.transactions,
                t.prep_inputs,
                t.prep_outputs,
                t.prep_direct_funding,
                t.crossing_values,
            ] {
                tx.execute(
                    &format!("DELETE FROM {table} WHERE migration_id = ?"),
                    params![migration_id],
                )?;
            }
            tx.execute(
                &format!(
                    "UPDATE {} SET status = :status,
                                   note_split_fee_buffer = :fee_buffer,
                                   note_split_change = :change,
                                   note_split_prep_fees = :prep_fees,
                                   note_split_total_input = :total_input,
                                   note_split_total_migratable = :total_migratable,
                                   anchor_bucket_interval = :anchor_bucket_interval,
                                   replan_threshold = :replan_threshold
                     WHERE id = :id",
                    t.migrations
                ),
                named_params! {
                    ":id": migration_id,
                    ":status": state.status().as_ref(),
                    ":fee_buffer": ns.note_fee_buffer().into_u64(),
                    ":change": ns.change().map(Zatoshis::into_u64),
                    ":prep_fees": ns.prep_fees().into_u64(),
                    ":total_input": ns.total_input().into_u64(),
                    ":total_migratable": ns.total_migratable().into_u64(),
                    ":anchor_bucket_interval": state.anchor_bucket_interval().block_count().get(),
                    ":replan_threshold": state.replan_threshold().percent(),
                },
            )?;
            migration_id
        }
        None => {
            // A fresh record: mint its identity, and stamp the chain height the wallet
            // currently knows as its commit height — the "when" a history listing sorts by.
            // `None` when the wallet has no chain view yet (a fixture, a wallet before first
            // sync); the column is nullable and no value is invented.
            tx.execute(
                &format!(
                    "INSERT INTO {} (account_id, status, note_split_fee_buffer, note_split_change,
                                     note_split_prep_fees, note_split_total_input, note_split_total_migratable,
                                     anchor_bucket_interval, replan_threshold, uuid, committed_height)
                     VALUES (:account_id, :status, :fee_buffer, :change, :prep_fees, :total_input, :total_migratable,
                             :anchor_bucket_interval, :replan_threshold, :uuid, :committed_height)",
                    t.migrations
                ),
                named_params! {
                    ":account_id": account_id.0,
                    ":uuid": uuid::Uuid::new_v4(),
                    ":committed_height": crate::wallet::chain_tip_height(tx)?.map(u32::from),
                    ":status": state.status().as_ref(),
                    ":fee_buffer": ns.note_fee_buffer().into_u64(),
                    ":change": ns.change().map(Zatoshis::into_u64),
                    ":prep_fees": ns.prep_fees().into_u64(),
                    ":total_input": ns.total_input().into_u64(),
                    ":total_migratable": ns.total_migratable().into_u64(),
                    ":anchor_bucket_interval": state.anchor_bucket_interval().block_count().get(),
                    ":replan_threshold": state.replan_threshold().percent(),
                },
            )?;
            tx.last_insert_rowid()
        }
    };

    insert_zatoshi_list(tx, t.crossing_values, migration_id, ns.crossing_values())?;

    let prep = state.preparation();
    for (layer, transactions) in prep.layers().iter().enumerate() {
        for (tx_index, prep_tx) in transactions.iter().enumerate() {
            for (ordinal, input) in prep_tx.inputs().iter().enumerate() {
                let (source, wallet_index, prior_layer, prior_transaction, prior_output) =
                    match input {
                        PrepInput::Wallet { index, .. } => {
                            ("wallet", Some(*index as u64), None, None, None)
                        }
                        PrepInput::Prior {
                            layer,
                            transaction,
                            output,
                            ..
                        } => (
                            "prior",
                            None,
                            Some(*layer as u64),
                            Some(*transaction as u64),
                            Some(*output as u64),
                        ),
                    };
                tx.execute(
                    &format!(
                        "INSERT INTO {} (migration_id, layer, tx_index, ordinal, source,
                                         wallet_index, prior_layer, prior_transaction, prior_output, value)
                         VALUES (:migration_id, :layer, :tx_index, :ordinal, :source,
                                 :wallet_index, :prior_layer, :prior_transaction, :prior_output, :value)",
                        t.prep_inputs
                    ),
                    named_params! {
                        ":migration_id": migration_id,
                        ":layer": layer as u64,
                        ":tx_index": tx_index as u64,
                        ":ordinal": ordinal as u64,
                        ":source": source,
                        ":wallet_index": wallet_index,
                        ":prior_layer": prior_layer,
                        ":prior_transaction": prior_transaction,
                        ":prior_output": prior_output,
                        ":value": input.value().into_u64(),
                    },
                )?;
            }
            for (ordinal, output) in prep_tx.outputs().iter().enumerate() {
                tx.execute(
                    &format!(
                        "INSERT INTO {} (migration_id, layer, tx_index, ordinal, role, value)
                         VALUES (:migration_id, :layer, :tx_index, :ordinal, :role, :value)",
                        t.prep_outputs
                    ),
                    named_params! {
                        ":migration_id": migration_id,
                        ":layer": layer as u64,
                        ":tx_index": tx_index as u64,
                        ":ordinal": ordinal as u64,
                        ":role": output.as_ref(),
                        ":value": output.value().into_u64(),
                    },
                )?;
            }
        }
    }
    for (ordinal, (wallet_index, value)) in prep.direct_funding_notes().iter().enumerate() {
        tx.execute(
            &format!(
                "INSERT INTO {} (migration_id, ordinal, wallet_index, value)
                 VALUES (:migration_id, :ordinal, :wallet_index, :value)",
                t.prep_direct_funding
            ),
            named_params! {
                ":migration_id": migration_id,
                ":ordinal": ordinal as u64,
                ":wallet_index": *wallet_index as u64,
                ":value": (*value).into_u64(),
            },
        )?;
    }

    for mtx in state.transactions() {
        let kind = mtx.kind();
        let (kind_layer, kind_index) = kind
            .preparation_indices()
            .map_or((None, None), |(l, i)| (Some(l as u64), Some(i as u64)));
        let kind_crossing = kind.transfer_crossing().map(|c| c as u64);
        let tx_state = mtx.state();
        // The mark is one value, split back into its two columns here. Bound to locals so the
        // kind's wire name can be written as a borrowed `&str`, like every other discriminant
        // column, rather than allocating a `String` per row.
        let (unsatisfiable_at, unsatisfiable_kind) = mtx.unsatisfiable().unzip();
        tx.execute(
            &format!(
                "INSERT INTO {} (migration_id, transfer_id, kind, kind_layer, kind_index,
                                 kind_crossing, pczt, scheduled_height, expiry_height,
                                 anchor_boundary, state, txid, mined_height, lock_owner,
                                 unsatisfiable_at, unsatisfiable_kind, broadcast_failure_at)
                 VALUES (:migration_id, :transfer_id, :kind, :kind_layer, :kind_index,
                         :kind_crossing, :pczt, :scheduled_height, :expiry_height,
                         :anchor_boundary, :state, :txid, :mined_height, :lock_owner,
                         :unsatisfiable_at, :unsatisfiable_kind, :broadcast_failure_at)",
                t.transactions
            ),
            named_params! {
                ":migration_id": migration_id,
                ":transfer_id": u32::from(mtx.id()),
                ":kind": kind.as_ref(),
                ":kind_layer": kind_layer,
                ":kind_index": kind_index,
                ":kind_crossing": kind_crossing,
                ":pczt": mtx.pczt().as_slice(),
                ":scheduled_height": u32::from(mtx.scheduled_height()),
                ":expiry_height": u32::from(mtx.expiry_height()),
                ":anchor_boundary": mtx.anchor_boundary().map(u32::from),
                ":state": tx_state.as_ref(),
                ":txid": mtx.txid().as_ref(),
                ":mined_height": tx_state.mined_height().map(u32::from),
                ":lock_owner": mtx.lock_owner().map(|o| *o.as_bytes()),
                ":unsatisfiable_at": unsatisfiable_at.map(u32::from),
                ":unsatisfiable_kind": unsatisfiable_kind.as_ref().map(|k| k.as_ref()),
                ":broadcast_failure_at": mtx.broadcast_failure_at().map(u32::from),
            },
        )?;
        for (ordinal, dep) in mtx.depends_on().iter().enumerate() {
            tx.execute(
                &format!(
                    "INSERT INTO {} (migration_id, transfer_id, ordinal, depends_on_transfer_id)
                     VALUES (:migration_id, :transfer_id, :ordinal, :depends_on_transfer_id)",
                    t.transaction_deps
                ),
                named_params! {
                    ":migration_id": migration_id,
                    ":transfer_id": u32::from(mtx.id()),
                    ":ordinal": ordinal as u64,
                    ":depends_on_transfer_id": u32::from(*dep),
                },
            )?;
        }
        // The cache is a list, so its rows carry the position they were read out of the PCZT at,
        // exactly as the dependency edges above carry theirs.
        for (ordinal, nf) in mtx.spend_nullifiers().iter().enumerate() {
            tx.execute(
                &format!(
                    "INSERT INTO {} (migration_id, transfer_id, ordinal, nullifier)
                     VALUES (:migration_id, :transfer_id, :ordinal, :nullifier)",
                    t.spend_nullifiers
                ),
                named_params! {
                    ":migration_id": migration_id,
                    ":transfer_id": u32::from(mtx.id()),
                    ":ordinal": ordinal as u64,
                    ":nullifier": nf,
                },
            )?;
        }
    }
    Ok(())
}

/// Insert an ordered list of zatoshi amounts as `(ordinal, value)` rows into a child table.
fn insert_zatoshi_list(
    tx: &rusqlite::Transaction,
    table: &str,
    migration_id: i64,
    values: &[Zatoshis],
) -> Result<(), Error> {
    for (ordinal, value) in values.iter().enumerate() {
        tx.execute(
            &format!(
                "INSERT INTO {table} (migration_id, ordinal, value)
                 VALUES (:migration_id, :ordinal, :value)"
            ),
            named_params! {
                ":migration_id": migration_id,
                ":ordinal": ordinal as u64,
                ":value": (*value).into_u64(),
            },
        )?;
    }
    Ok(())
}
