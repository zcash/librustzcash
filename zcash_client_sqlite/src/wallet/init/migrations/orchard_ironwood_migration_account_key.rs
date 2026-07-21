//! Re-keys the Orchard -> Ironwood pool-migration tables by account.
//!
//! The original `orchard_ironwood_migration_tables` migration stored at most one migration per
//! database (a singleton row). Wallets that host several accounts — each potentially with its own
//! seed or an imported viewing key, such as a software account next to a hardware-wallet account —
//! migrate them independently, concurrently or one after another, so the tables are re-keyed by the
//! owning account's UUID (`account_uuid` replacing the former singleton row id).
//!
//! The table DDL and its evolution live in the `zcash_pool_migration_sqlite` crate; this migration
//! is the thin registration that applies the account-keyed shape inside the wallet schema. A legacy
//! (singleton-keyed) table is dropped and recreated — no released crate ever wrote the legacy
//! shape, so there is no deployed data to carry over. A database whose tables were already created
//! at the account-keyed shape (any database initialized after this migration was introduced) sees a
//! no-op.

use std::collections::HashSet;

use schemerz_rusqlite::RusqliteMigration;
use uuid::Uuid;

use crate::wallet::init::WalletMigrationError;

use super::orchard_ironwood_migration_tables;

pub(super) const MIGRATION_ID: Uuid =
    zcash_pool_migration_sqlite::orchard_ironwood::ACCOUNT_KEY_MIGRATION_ID;

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
        "Re-keys the Orchard -> Ironwood pool-migration tables by account."
    }
}

impl RusqliteMigration for Migration {
    type Error = WalletMigrationError;

    fn up(&self, transaction: &rusqlite::Transaction) -> Result<(), Self::Error> {
        // A legacy table is one created by the original migration before the account-keyed shape
        // existed: it has rows in `PRAGMA table_info` but no `account_uuid` column. A database
        // initialized after the shape change gets the account-keyed DDL straight from the original
        // migration (`init_migration_tables` always emits the current shape), making this a no-op.
        let legacy = {
            let mut stmt = transaction.prepare("PRAGMA table_info(orchard_ironwood_migrations)")?;
            let mut rows = stmt.query([])?;
            let mut has_columns = false;
            let mut has_account_uuid = false;
            while let Some(row) = rows.next()? {
                has_columns = true;
                if row.get::<_, String>(1)? == "account_uuid" {
                    has_account_uuid = true;
                }
            }
            has_columns && !has_account_uuid
        };

        if legacy {
            // No released crate ever wrote the singleton shape, so the legacy tables are dropped
            // rather than migrated; the index drops with its table.
            transaction.execute_batch(
                "DROP TABLE orchard_ironwood_migration_transactions;
                 DROP TABLE orchard_ironwood_migrations;",
            )?;
        }

        // `Transaction` derefs to `Connection`; the DDL and its evolution live in the store crate.
        zcash_pool_migration_sqlite::orchard_ironwood::init_migration_tables(transaction)?;
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

    use crate::wallet::init::migrations::tests::test_migrate;

    /// The DDL the original migration emitted before the account-keyed shape existed, verbatim;
    /// used to reconstruct a legacy database, since `init_migration_tables` only ever emits the
    /// current shape.
    const LEGACY_DDL: &str = "
        CREATE TABLE orchard_ironwood_migrations (
            id INTEGER PRIMARY KEY,
            status TEXT NOT NULL,
            note_split BLOB NOT NULL,
            funding_notes BLOB NOT NULL,
            preparation BLOB NOT NULL
        );
        CREATE TABLE orchard_ironwood_migration_transactions (
            migration_id INTEGER NOT NULL REFERENCES orchard_ironwood_migrations(id) ON DELETE CASCADE,
            tx_id INTEGER NOT NULL,
            kind BLOB NOT NULL,
            pczt BLOB NOT NULL,
            depends_on BLOB NOT NULL,
            scheduled_height INTEGER NOT NULL,
            expiry_height INTEGER NOT NULL,
            anchor_boundary INTEGER,
            state TEXT NOT NULL,
            txid BLOB,
            mined_height INTEGER,
            PRIMARY KEY (migration_id, tx_id)
        );
        CREATE INDEX idx_orchard_ironwood_migration_tx_due
            ON orchard_ironwood_migration_transactions (state, scheduled_height);";

    /// Whether the migrations table currently has an `account_uuid` column.
    fn has_account_uuid(conn: &Connection) -> bool {
        let mut stmt = conn
            .prepare("PRAGMA table_info(orchard_ironwood_migrations)")
            .unwrap();
        let names = stmt
            .query_map([], |row| row.get::<_, String>(1))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        names.iter().any(|n| n == "account_uuid")
    }

    #[test]
    fn migrate() {
        test_migrate(&[super::MIGRATION_ID]);
    }

    /// A database created at the original singleton shape is re-keyed: the legacy tables are
    /// dropped and the account-keyed shape created in their place.
    #[test]
    fn legacy_singleton_tables_are_rekeyed() {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(LEGACY_DDL).unwrap();
        conn.execute_batch(
            "INSERT INTO orchard_ironwood_migrations (id, status, note_split, funding_notes, preparation)
             VALUES (0, 'planning', x'00', x'00', x'00');",
        )
        .unwrap();
        assert!(!has_account_uuid(&conn));

        let tx = conn.transaction().unwrap();
        super::Migration.up(&tx).unwrap();
        tx.commit().unwrap();

        assert!(has_account_uuid(&conn));
        let rows: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM orchard_ironwood_migrations",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(rows, 0);
    }

    /// A database whose tables were created at the current (account-keyed) shape is untouched:
    /// existing rows survive the no-op.
    #[test]
    fn account_keyed_tables_are_untouched() {
        let mut conn = Connection::open_in_memory().unwrap();
        zcash_pool_migration_sqlite::orchard_ironwood::init_migration_tables(&conn).unwrap();
        conn.execute_batch(
            "INSERT INTO orchard_ironwood_migrations
                (account_uuid, status, note_split, funding_notes, preparation)
             VALUES (x'11111111111111111111111111111111', 'planning', x'00', x'00', x'00');",
        )
        .unwrap();

        let tx = conn.transaction().unwrap();
        super::Migration.up(&tx).unwrap();
        tx.commit().unwrap();

        assert!(has_account_uuid(&conn));
        let rows: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM orchard_ironwood_migrations",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(rows, 1);
    }
}
