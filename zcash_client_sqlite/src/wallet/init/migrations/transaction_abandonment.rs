//! Persists local transaction abandonment and exposes it in transaction history.

use std::collections::HashSet;

use schemerz_rusqlite::RusqliteMigration;
use uuid::Uuid;

use crate::wallet::init::WalletMigrationError;

use super::{fix_v_transactions_multi_account_totals, tx_status_observation_intent};

/// Adds local abandonment state to stored transactions.
pub const MIGRATION_ID: Uuid = Uuid::from_u128(0xf413eba8_c10b_42fd_88d9_17be388a33b9);

pub(super) const DEPENDENCIES: &[Uuid] = &[
    fix_v_transactions_multi_account_totals::MIGRATION_ID,
    tx_status_observation_intent::MIGRATION_ID,
];

pub(super) struct Migration;

impl schemerz::Migration<Uuid> for Migration {
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }

    fn dependencies(&self) -> HashSet<Uuid> {
        DEPENDENCIES.iter().copied().collect()
    }

    fn description(&self) -> &'static str {
        "Persists local transaction abandonment and exposes it in transaction history."
    }
}

impl RusqliteMigration for Migration {
    type Error = WalletMigrationError;

    fn up(&self, transaction: &rusqlite::Transaction) -> Result<(), Self::Error> {
        let history = view_sql(transaction, "v_transactions")?;
        let merged = view_sql(transaction, "v_transactions_with_pending_migrations")?;
        // Extend the predecessor's frozen definitions rather than depending on the
        // runtime definitions, which may refer to columns introduced by later migrations.
        let history = replace_once(
            &history,
            "transactions.zip318_kind",
            "transactions.zip318_kind, transactions.abandoned",
        )?;
        let merged = replace_once(
            &merged,
            "FROM v_transactions",
            ", v_transactions.abandoned AS abandoned FROM v_transactions",
        )?;
        let merged = replace_once(
            &merged,
            "FROM v_migration_transactions vmt",
            ", 0 AS abandoned FROM v_migration_transactions vmt",
        )?;
        transaction.execute_batch(
            "ALTER TABLE transactions ADD COLUMN
                 abandoned INTEGER NOT NULL DEFAULT 0 CHECK (abandoned IN (0, 1));
             DROP VIEW v_transactions_with_pending_migrations;
             DROP VIEW v_transactions;
             CREATE INDEX idx_transparent_spend_map_prevout ON transparent_spend_map (
                 prevout_txid ASC,
                 prevout_output_index ASC
             );",
        )?;
        transaction.execute_batch(&history)?;
        transaction.execute_batch(&merged)?;
        Ok(())
    }

    fn down(&self, _transaction: &rusqlite::Transaction) -> Result<(), Self::Error> {
        Err(WalletMigrationError::CannotRevert(MIGRATION_ID))
    }
}

fn view_sql(conn: &rusqlite::Connection, view: &str) -> Result<String, WalletMigrationError> {
    Ok(conn.query_row(
        "SELECT sql FROM sqlite_schema WHERE type = 'view' AND name = ?",
        [view],
        |row| row.get(0),
    )?)
}

fn replace_once(sql: &str, from: &str, to: &str) -> Result<String, WalletMigrationError> {
    if sql.matches(from).count() != 1 {
        return Err(WalletMigrationError::CorruptedData(
            "Unexpected transaction history view definition".to_owned(),
        ));
    }
    Ok(sql.replacen(from, to, 1))
}

#[cfg(test)]
mod tests {
    use tempfile::NamedTempFile;
    use zcash_protocol::consensus::Network;

    use crate::{
        WalletDb,
        testing::db::{test_clock, test_rng},
        wallet::init::{WalletMigrator, migrations::tests::test_migrate},
    };

    use super::{fix_v_transactions_multi_account_totals, tx_status_observation_intent};

    #[test]
    fn migrate() {
        test_migrate(&[super::MIGRATION_ID]);
    }

    #[test]
    fn existing_transactions_survive_migration_failure_and_retry() {
        let file = NamedTempFile::new().unwrap();
        let mut db =
            WalletDb::for_path(file.path(), Network::TestNetwork, test_clock(), test_rng())
                .unwrap();
        WalletMigrator::new()
            .init_or_migrate_to(
                &mut db,
                &[
                    fix_v_transactions_multi_account_totals::MIGRATION_ID,
                    tx_status_observation_intent::MIGRATION_ID,
                ],
            )
            .unwrap();
        let txid = zcash_protocol::TxId::from_bytes([1; 32]);
        let raw = vec![2u8; 32];
        db.conn
            .execute(
                "INSERT INTO transactions (txid, raw, min_observed_height, expiry_height)
             VALUES (?, ?, 0, 0)",
                rusqlite::params![txid.as_ref(), &raw],
            )
            .unwrap();
        // The conflicting index makes the migration fail after adding its column
        // and dropping the old views.
        db.conn
            .execute_batch(
                "CREATE INDEX idx_transparent_spend_map_prevout
             ON transparent_spend_map (spending_transaction_id);",
            )
            .unwrap();
        assert!(
            WalletMigrator::new()
                .init_or_migrate_to(&mut db, &[super::MIGRATION_ID])
                .is_err()
        );
        let abandoned_columns: usize = db
            .conn
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_info('transactions') WHERE name = 'abandoned'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(abandoned_columns, 0);
        for view in ["v_transactions", "v_transactions_with_pending_migrations"] {
            let count: usize = db
                .conn
                .query_row(&format!("SELECT COUNT(*) FROM {view}"), [], |row| {
                    row.get(0)
                })
                .unwrap();
            assert_eq!(count, 0);
        }
        db.conn
            .execute_batch("DROP INDEX idx_transparent_spend_map_prevout")
            .unwrap();
        WalletMigrator::new()
            .init_or_migrate_to(&mut db, &[super::MIGRATION_ID])
            .unwrap();
        let (abandoned, stored): (bool, Vec<u8>) = db
            .conn
            .query_row(
                "SELECT abandoned, raw FROM transactions WHERE txid = ?",
                [txid.as_ref()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert!(!abandoned);
        assert_eq!(stored, raw);
        for view in ["v_transactions", "v_transactions_with_pending_migrations"] {
            let count: usize = db
                .conn
                .query_row(&format!("SELECT COUNT(abandoned) FROM {view}"), [], |row| {
                    row.get(0)
                })
                .unwrap();
            assert_eq!(count, 0);
        }
    }
}
