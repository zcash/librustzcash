//! The generic, pool-agnostic SQLite pool-migration table DDL.
//!
//! This module is entirely crate-internal: it holds the DDL builders shared by every pool migration,
//! parameterized over the table names in [`Tables`]. The schema is fully NORMALIZED: every structured
//! value is stored in typed columns and child-table rows, so it can be queried directly. The only
//! `BLOB` column is the pre-signed transaction (`pczt`), which is genuinely unstructured,
//! already-versioned bytes. All amounts are zatoshi `INTEGER` columns; the broadcast `txid` is stored
//! as hex `TEXT`.
//!
//! The preparation plan's layers/transactions grid has no tables of its own: each input and output
//! row carries its transaction's `(layer, tx_index)` coordinate, and every transaction a real plan
//! produces has at least one input and one output (and no layer is empty), so the grid is implied
//! by those rows. Likewise the funding-note values have no table: they are derived from the note
//! split (each crossing value plus the fee buffer).
//!
//! The column set is the same for every pool; only the table and index names change. The store logic
//! that reads and writes these tables (the `PoolMigrationRead` / `PoolMigrationWrite` implementation
//! over the engine types) is added separately; this module defines only the schema.

use rusqlite::Connection;

/// The per-pool table and index names the DDL operates over. A concrete migration submodule supplies
/// a `'static` value of this for its own pool; the builders interpolate these into every statement,
/// so one set of DDL serves every pool.
pub(crate) struct Tables {
    /// The migration-state table (one singleton row; holds the note-split scalars).
    pub migrations: &'static str,
    /// The note-split crossing values (an ordered list).
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
    /// The index over `(state, scheduled_height)` on the transactions table.
    pub tx_due_index: &'static str,
}

fn create_migrations_sql(t: &Tables) -> String {
    format!(
        "CREATE TABLE IF NOT EXISTS {} (
            id INTEGER PRIMARY KEY,
            status TEXT NOT NULL,
            note_split_fee_buffer INTEGER NOT NULL,
            note_split_change INTEGER,
            note_split_prep_fees INTEGER NOT NULL,
            note_split_total_input INTEGER NOT NULL,
            note_split_total_migratable INTEGER NOT NULL
        )",
        t.migrations
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

fn create_transactions_sql(t: &Tables) -> String {
    format!(
        "CREATE TABLE IF NOT EXISTS {} (
            migration_id INTEGER NOT NULL REFERENCES {}(id) ON DELETE CASCADE,
            tx_id INTEGER NOT NULL,
            kind TEXT NOT NULL,
            kind_layer INTEGER,
            kind_index INTEGER,
            kind_crossing INTEGER,
            pczt BLOB NOT NULL,
            scheduled_height INTEGER NOT NULL,
            expiry_height INTEGER NOT NULL,
            anchor_boundary INTEGER,
            state TEXT NOT NULL,
            txid TEXT,
            mined_height INTEGER,
            PRIMARY KEY (migration_id, tx_id)
        )",
        t.transactions, t.migrations
    )
}

fn create_transaction_deps_sql(t: &Tables) -> String {
    format!(
        "CREATE TABLE IF NOT EXISTS {} (
            migration_id INTEGER NOT NULL,
            tx_id INTEGER NOT NULL,
            ordinal INTEGER NOT NULL,
            depends_on_tx_id INTEGER NOT NULL,
            PRIMARY KEY (migration_id, tx_id, ordinal),
            FOREIGN KEY (migration_id, tx_id)
                REFERENCES {}(migration_id, tx_id) ON DELETE CASCADE
        )",
        t.transaction_deps, t.transactions
    )
}

fn create_tx_due_index_sql(t: &Tables) -> String {
    format!(
        "CREATE INDEX IF NOT EXISTS {} ON {} (state, scheduled_height)",
        t.tx_due_index, t.transactions
    )
}

/// Create the pool-migration tables (and the due-transaction index) named by `t` on `conn`. This is
/// the body the pool's schema migration's `up()` calls; it is idempotent (`IF NOT EXISTS`). Tables
/// are created in dependency order so each foreign-key target exists first.
pub(crate) fn init(conn: &Connection, t: &Tables) -> rusqlite::Result<()> {
    conn.execute_batch(&format!(
        "{};\n{};\n{};\n{};\n{};\n{};\n{};\n{};",
        create_migrations_sql(t),
        create_crossing_values_sql(t),
        create_prep_inputs_sql(t),
        create_prep_outputs_sql(t),
        create_prep_direct_funding_sql(t),
        create_transactions_sql(t),
        create_transaction_deps_sql(t),
        create_tx_due_index_sql(t),
    ))
}
