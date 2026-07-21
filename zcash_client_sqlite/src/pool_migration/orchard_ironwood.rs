//! The SQLite pool-migration tables instantiated for the Orchard -> Ironwood migration (ZIP 318);
//! tables prefixed `orchard_ironwood_migration[s]_`.
//!
//! This exposes the pool's [`init_migration_tables`] DDL; the thin `schemerz` migration in
//! `crate::wallet::init::migrations::orchard_ironwood_migration_tables` runs it inside the wallet
//! schema. The store implementation (reading and writing the rows) is added separately.

use rusqlite::Connection;

use super::store::{self, Tables};

/// The Orchard -> Ironwood table and index names the DDL operates over.
static TABLES: Tables = Tables {
    migrations: "orchard_ironwood_migrations",
    crossing_values: "orchard_ironwood_migration_crossing_values",
    prep_inputs: "orchard_ironwood_migration_prep_inputs",
    prep_outputs: "orchard_ironwood_migration_prep_outputs",
    prep_direct_funding: "orchard_ironwood_migration_prep_direct_funding",
    transactions: "orchard_ironwood_migration_transactions",
    transaction_deps: "orchard_ironwood_migration_transaction_deps",
    tx_due_index: "idx_orchard_ironwood_migration_tx_due",
};

/// Create the Orchard -> Ironwood pool-migration tables (and the due-transaction index) on `conn`.
/// This is the body the `orchard_ironwood_migration_tables` schema migration's `up()` calls; it is
/// idempotent (`IF NOT EXISTS`).
pub fn init_migration_tables(conn: &Connection) -> rusqlite::Result<()> {
    store::init(conn, &TABLES)
}

#[cfg(test)]
mod tests {
    use super::init_migration_tables;
    use rusqlite::Connection;

    #[test]
    fn creates_the_tables_and_is_idempotent() {
        let conn = Connection::open_in_memory().expect("opens an in-memory database");
        init_migration_tables(&conn).expect("creates the tables");
        // `IF NOT EXISTS` means a second run is a no-op, not an error.
        init_migration_tables(&conn).expect("is idempotent");

        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master \
                 WHERE type IN ('table', 'index') AND name LIKE '%orchard_ironwood%' \
                 AND name NOT LIKE 'sqlite_%'",
                [],
                |row| row.get(0),
            )
            .expect("queries the schema");
        // The seven tables plus the due-transaction index (excluding the composite-key auto-indexes).
        assert_eq!(count, 8);
    }
}
