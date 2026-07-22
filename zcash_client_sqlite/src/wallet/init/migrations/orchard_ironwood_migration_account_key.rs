//! Keys the Orchard -> Ironwood pool-migration tables added by
//! [`orchard_ironwood_migration_tables`] by account.
//!
//! `orchard_ironwood_migrations` previously held at most one row: a wallet tracked at most one
//! in-progress migration regardless of how many accounts it held. This migration adds that table's
//! `account_uuid` column and the unique index enforcing at most one migration per account, so each
//! account's migration is tracked independently. The DDL lives in [`crate::pool_migration`], which
//! now builds the account-keyed shape directly, so a wallet created after this migration exists
//! reaches it without `up` doing any work. For a wallet that already ran
//! [`orchard_ironwood_migration_tables`] under the old shape, `up` reaches the new shape by dropping
//! and recreating the pool-migration tables.
//!
//! ## The old-shape data contract
//!
//! Dropping the old-shape tables DISCARDS any in-progress migration they held; it is deliberately
//! not carried onto the new shape. The old singleton row recorded no owning account (that was the
//! whole limitation this migration lifts), so there is no sound account to re-key it to: silently
//! assigning it to some account could mis-attribute a migration in a multi-account wallet. The
//! wallet instead re-plans the migration from its current on-chain state on the next run, exactly
//! as it would for a wallet that had never started one. This loses no released behavior, because
//! these tables have not yet been part of a public release, and there is at most one such
//! in-progress migration per wallet to re-plan.
//!
//! [`orchard_ironwood_migration_tables`]: super::orchard_ironwood_migration_tables

use std::collections::HashSet;

use schemerz_rusqlite::RusqliteMigration;
use uuid::Uuid;

use crate::wallet::init::WalletMigrationError;

use super::orchard_ironwood_migration_tables;

pub(super) const MIGRATION_ID: Uuid = Uuid::from_u128(0x95db78fa_5546_47a1_9b60_ad6c586d8fe7);

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
        "Keys the Orchard -> Ironwood pool-migration tables by account."
    }
}

impl RusqliteMigration for Migration {
    type Error = WalletMigrationError;

    fn up(&self, transaction: &rusqlite::Transaction) -> Result<(), Self::Error> {
        let has_account_uuid: bool = transaction
            .prepare(
                "SELECT 1 FROM pragma_table_info('orchard_ironwood_migrations')
                  WHERE name = 'account_uuid'",
            )?
            .exists([])?;

        if has_account_uuid {
            return Ok(());
        }

        // The account-keyed shape has already replaced the singleton DDL in
        // `crate::pool_migration`, so recreating the tables through the same
        // `init_migration_tables` this migration's predecessor called is sufficient: there is at
        // most one in-progress migration to replan, and these tables have not yet been part of a
        // public release.
        transaction.execute_batch(
            "DROP INDEX IF EXISTS idx_orchard_ironwood_migrations_account;
             DROP INDEX IF EXISTS idx_orchard_ironwood_migration_tx_due;
             DROP TABLE IF EXISTS orchard_ironwood_migration_transaction_deps;
             DROP TABLE IF EXISTS orchard_ironwood_migration_transactions;
             DROP TABLE IF EXISTS orchard_ironwood_migration_prep_direct_funding;
             DROP TABLE IF EXISTS orchard_ironwood_migration_prep_outputs;
             DROP TABLE IF EXISTS orchard_ironwood_migration_prep_inputs;
             DROP TABLE IF EXISTS orchard_ironwood_migration_crossing_values;
             DROP TABLE IF EXISTS orchard_ironwood_migrations;",
        )?;

        crate::pool_migration::orchard_ironwood::init_migration_tables(transaction)?;

        Ok(())
    }

    fn down(&self, _transaction: &rusqlite::Transaction) -> Result<(), Self::Error> {
        Err(WalletMigrationError::CannotRevert(MIGRATION_ID))
    }
}

#[cfg(test)]
mod tests {
    use rusqlite::Connection;
    use schemerz_rusqlite::RusqliteMigration;

    use super::Migration;
    use crate::wallet::init::migrations::tests::test_migrate;

    #[test]
    fn migrate() {
        test_migrate(&[super::MIGRATION_ID]);
    }

    /// The `orchard_ironwood_migrations` schema exactly as left by `orchard_ironwood_migration_tables`
    /// before this migration: a singleton row with no `account_uuid` column, referenced by one child
    /// table (`orchard_ironwood_migration_crossing_values`) with a seeded row. Foreign-key
    /// enforcement stays off, matching the real migrator, which runs migrations with foreign keys
    /// disabled.
    const LEGACY_SCHEMA: &str = "
        PRAGMA foreign_keys = OFF;
        CREATE TABLE orchard_ironwood_migrations (
            id INTEGER PRIMARY KEY,
            status TEXT NOT NULL,
            note_split_fee_buffer INTEGER NOT NULL,
            note_split_change INTEGER,
            note_split_prep_fees INTEGER NOT NULL,
            note_split_total_input INTEGER NOT NULL,
            note_split_total_migratable INTEGER NOT NULL
        );
        CREATE TABLE orchard_ironwood_migration_crossing_values (
            migration_id INTEGER NOT NULL REFERENCES orchard_ironwood_migrations(id) ON DELETE CASCADE,
            ordinal INTEGER NOT NULL,
            value INTEGER NOT NULL,
            PRIMARY KEY (migration_id, ordinal)
        );
        INSERT INTO orchard_ironwood_migrations (
            id, status, note_split_fee_buffer, note_split_change,
            note_split_prep_fees, note_split_total_input, note_split_total_migratable
        ) VALUES (0, 'planning', 1000, NULL, 0, 50000, 49000);
        INSERT INTO orchard_ironwood_migration_crossing_values (migration_id, ordinal, value)
        VALUES (0, 0, 12345);";

    /// A wallet that already ran the old singleton-shaped migration keeps no data across the shape
    /// change: the legacy parent row and its child row are both gone, but the recreated parent
    /// table now has an `account_uuid` column.
    #[test]
    fn up_recreates_legacy_singleton_shape_with_account_uuid() {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(LEGACY_SCHEMA).unwrap();

        let tx = conn.transaction().unwrap();
        Migration.up(&tx).unwrap();

        let has_account_uuid: bool = tx
            .prepare(
                "SELECT 1 FROM pragma_table_info('orchard_ironwood_migrations')
                  WHERE name = 'account_uuid'",
            )
            .unwrap()
            .exists([])
            .unwrap();
        assert!(
            has_account_uuid,
            "the recreated table must have an account_uuid column"
        );

        let migrations: i64 = tx
            .query_row(
                "SELECT COUNT(*) FROM orchard_ironwood_migrations",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            migrations, 0,
            "the legacy singleton row must not survive the shape change"
        );
        // The in-progress migration is discarded, NOT silently carried onto the new shape under a
        // fabricated account: no row keyed to any account survives (the wallet re-plans instead).
        // The old singleton recorded no owning account, so any survivor would be mis-attributed.
        let rekeyed: i64 = tx
            .query_row(
                "SELECT COUNT(*) FROM orchard_ironwood_migrations WHERE account_uuid IS NOT NULL",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            rekeyed, 0,
            "no legacy migration may be re-keyed onto the new account-scoped shape"
        );
        let crossing_values: i64 = tx
            .query_row(
                "SELECT COUNT(*) FROM orchard_ironwood_migration_crossing_values",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            crossing_values, 0,
            "a dropped parent's children must not survive either"
        );
    }

    /// A wallet already on the account-keyed shape is untouched: `up` must detect the existing
    /// `account_uuid` column and skip the drop-and-recreate entirely.
    #[test]
    fn up_is_a_noop_on_the_new_account_keyed_shape() {
        let mut conn = Connection::open_in_memory().unwrap();
        crate::pool_migration::orchard_ironwood::init_migration_tables(&conn).unwrap();
        conn.execute(
            "INSERT INTO orchard_ironwood_migrations (
                account_uuid, status, note_split_fee_buffer, note_split_change,
                note_split_prep_fees, note_split_total_input, note_split_total_migratable
            ) VALUES (X'00000000000000000000000000000001', 'planning', 1000, NULL, 0, 50000, 49000)",
            [],
        )
        .unwrap();

        let tx = conn.transaction().unwrap();
        Migration.up(&tx).unwrap();
        tx.commit().unwrap();

        let migrations: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM orchard_ironwood_migrations",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            migrations, 1,
            "up() must leave a database already in the new shape untouched"
        );
    }
}
