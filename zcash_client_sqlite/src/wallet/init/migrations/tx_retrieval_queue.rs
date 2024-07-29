//! A migration to add the `tx_retrieval_queue` table to the database.

use rusqlite::Transaction;
use schemer_rusqlite::RusqliteMigration;
use std::collections::HashSet;
use uuid::Uuid;

use crate::wallet::init::WalletMigrationError;

use super::utxos_to_txos;

pub(super) const MIGRATION_ID: Uuid = Uuid::from_u128(0xfec02b61_3988_4b4f_9699_98977fac9e7f);

pub(crate) struct Migration;

impl schemer::Migration for Migration {
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }

    fn dependencies(&self) -> HashSet<Uuid> {
        [utxos_to_txos::MIGRATION_ID].into_iter().collect()
    }

    fn description(&self) -> &'static str {
        "Adds a table for tracking transactions to be downloaded for transparent output and/or memo retrieval."
    }
}

impl RusqliteMigration for Migration {
    type Error = WalletMigrationError;

    fn up(&self, transaction: &Transaction) -> Result<(), WalletMigrationError> {
        transaction.execute_batch(
            "CREATE TABLE tx_retrieval_queue (
                txid BLOB NOT NULL UNIQUE,
                query_type INTEGER NOT NULL,
                dependent_transaction_id INTEGER,
                FOREIGN KEY (dependent_transaction_id) REFERENCES transactions(id_tx)
            );",
        )?;

        Ok(())
    }

    fn down(&self, transaction: &Transaction) -> Result<(), WalletMigrationError> {
        transaction.execute_batch("DROP TABLE tx_retrieval_queue;")?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::wallet::init::migrations::tests::test_migrate;

    #[test]
    fn migrate() {
        test_migrate(&[super::MIGRATION_ID]);
    }
}
