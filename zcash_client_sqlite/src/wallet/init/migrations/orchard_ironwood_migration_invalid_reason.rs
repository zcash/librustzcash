//! Adds the `invalid_reason` column to `orchard_ironwood_migration_transactions` where it is
//! missing.
//!
//! The column is the payload of the `invalid` migration-transaction lifecycle state (the
//! event-based failure state: a funding note spent outside the migration, or a node-rejected
//! broadcast), non-NULL exactly for a row whose `state` is `invalid`, mirroring how `txid` and
//! `mined_height` carry the `broadcast` and `mined` payloads.
//!
//! The table's DDL in [`orchard_ironwood_migration_tables`] gained the column at the same time, so
//! a fresh wallet creates it there and this migration is a no-op; a wallet that applied that
//! migration before the column existed gets it added here (its `CREATE TABLE IF NOT EXISTS` never
//! runs again). Both paths converge on the schema in
//! [`crate::wallet::db::TABLE_ORCHARD_IRONWOOD_MIGRATION_TRANSACTIONS`]. No backfill is needed: a
//! pre-existing row cannot be in the `invalid` state (no released store could write one), and for
//! every other state the column is NULL — exactly what `ADD COLUMN` leaves behind.

use std::collections::HashSet;

use rusqlite::named_params;
use schemerz_rusqlite::RusqliteMigration;
use uuid::Uuid;

use super::orchard_ironwood_migration_tables;
use crate::wallet::init::WalletMigrationError;

/// Adds the `invalid_reason` column to `orchard_ironwood_migration_transactions` where it is
/// missing.
pub const MIGRATION_ID: Uuid = Uuid::from_u128(0x091bc432_5f94_4708_9e89_863ee014738f);

const DEPENDENCIES: &[Uuid] = &[orchard_ironwood_migration_tables::MIGRATION_ID];

pub(super) struct Migration;

impl schemerz::Migration<Uuid> for Migration {
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }

    fn dependencies(&self) -> HashSet<Uuid> {
        DEPENDENCIES.iter().copied().collect()
    }

    fn description(&self) -> &'static str {
        "Adds the invalid_reason column to orchard_ironwood_migration_transactions where missing."
    }
}

impl RusqliteMigration for Migration {
    type Error = WalletMigrationError;

    fn up(&self, transaction: &rusqlite::Transaction) -> Result<(), Self::Error> {
        // A wallet whose table was created from the current DDL already has the column; adding it
        // again is an error rather than a no-op, so the presence check is load-bearing.
        let has_column = transaction.query_row(
            "SELECT EXISTS (
                SELECT 1 FROM pragma_table_info('orchard_ironwood_migration_transactions')
                WHERE name = :column_name
             )",
            named_params![":column_name": COLUMN_NAME],
            |row| row.get::<_, bool>(0),
        )?;

        if !has_column {
            // Nullable with no default: NULL is the correct value for every pre-existing row (none
            // can be in the `invalid` state), and SQLite appends the column after the existing
            // ones, matching its position in the current `CREATE TABLE` so the two paths agree on
            // the stored schema text.
            transaction.execute_batch(&format!(
                "ALTER TABLE orchard_ironwood_migration_transactions
                 ADD COLUMN {COLUMN_NAME} TEXT"
            ))?;
        }

        Ok(())
    }

    fn down(&self, _transaction: &rusqlite::Transaction) -> Result<(), Self::Error> {
        Err(WalletMigrationError::CannotRevert(MIGRATION_ID))
    }
}

const COLUMN_NAME: &str = "invalid_reason";

#[cfg(test)]
mod tests {
    use rusqlite::Connection;

    use super::*;
    use crate::wallet::init::migrations::tests::test_migrate;

    #[test]
    fn migrate() {
        test_migrate(&[MIGRATION_ID]);
    }

    /// The pre-fix schema: `orchard_ironwood_migration_transactions` without `invalid_reason`,
    /// which is what a wallet that applied `orchard_ironwood_migration_tables` before the column
    /// existed has on disk. (The parent `orchard_ironwood_migrations` table is stubbed to satisfy
    /// the foreign key.)
    fn create_pre_fix_table(conn: &Connection) {
        conn.execute_batch(
            "CREATE TABLE orchard_ironwood_migrations (
                id INTEGER PRIMARY KEY
            );
            CREATE TABLE orchard_ironwood_migration_transactions (
                migration_id INTEGER NOT NULL REFERENCES orchard_ironwood_migrations(id) ON DELETE CASCADE,
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
                lock_owner BLOB,
                PRIMARY KEY (migration_id, tx_id)
            );",
        )
        .unwrap();
    }

    fn has_invalid_reason_column(conn: &Connection) -> bool {
        conn.query_row(
            "SELECT EXISTS (
                SELECT 1 FROM pragma_table_info('orchard_ironwood_migration_transactions')
                WHERE name = 'invalid_reason'
             )",
            [],
            |row| row.get::<_, bool>(0),
        )
        .unwrap()
    }

    /// The upgrade path: the column is added, and an existing row keeps its state with a NULL
    /// reason (no pre-existing row can be `invalid`, so NULL is correct for all of them).
    #[test]
    fn adds_column_and_leaves_existing_rows_null() {
        let mut conn = Connection::open_in_memory().unwrap();
        create_pre_fix_table(&conn);
        conn.execute_batch(
            "INSERT INTO orchard_ironwood_migrations (id) VALUES (1);
             INSERT INTO orchard_ironwood_migration_transactions (
                migration_id, tx_id, kind, kind_crossing, pczt, scheduled_height, expiry_height,
                state
             )
             VALUES (1, 0, 'transfer', 0, x'00', 100, 200, 'signed');",
        )
        .unwrap();

        let tx = conn.transaction().unwrap();
        RusqliteMigration::up(&Migration, &tx).unwrap();
        tx.commit().unwrap();

        assert!(has_invalid_reason_column(&conn));

        let (state, invalid_reason) = conn
            .query_row(
                "SELECT state, invalid_reason FROM orchard_ironwood_migration_transactions",
                [],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?)),
            )
            .unwrap();
        assert_eq!(state, "signed");
        assert_eq!(invalid_reason, None);
    }

    /// The fresh path: the table already carries the column, so `up` must leave it alone rather
    /// than fail with "duplicate column name".
    #[test]
    fn is_a_no_op_when_the_column_is_present() {
        let mut conn = Connection::open_in_memory().unwrap();
        crate::pool_migration::orchard_ironwood::init_migration_tables(&conn).unwrap();
        assert!(has_invalid_reason_column(&conn));

        let tx = conn.transaction().unwrap();
        RusqliteMigration::up(&Migration, &tx).unwrap();
        tx.commit().unwrap();

        assert!(has_invalid_reason_column(&conn));
    }
}
