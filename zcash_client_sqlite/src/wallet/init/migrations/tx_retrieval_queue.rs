//! Adds tables for tracking transactions to be downloaded for transparent output and/or memo retrieval.

use rusqlite::{named_params, Transaction};
use schemer_rusqlite::RusqliteMigration;
use std::collections::HashSet;
use uuid::Uuid;
use zcash_client_backend::data_api::DecryptedTransaction;
use zcash_primitives::transaction::builder::DEFAULT_TX_EXPIRY_DELTA;
use zcash_protocol::consensus::{self, BlockHeight, BranchId};

use crate::wallet::{self, init::WalletMigrationError};

use super::utxos_to_txos;

pub(super) const MIGRATION_ID: Uuid = Uuid::from_u128(0xfec02b61_3988_4b4f_9699_98977fac9e7f);

pub(super) struct Migration<P> {
    pub(super) params: P,
}

impl<P> schemer::Migration for Migration<P> {
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }

    fn dependencies(&self) -> HashSet<Uuid> {
        [utxos_to_txos::MIGRATION_ID].into_iter().collect()
    }

    fn description(&self) -> &'static str {
        "Adds tables for tracking transactions to be downloaded for transparent output and/or memo retrieval."
    }
}

impl<P: consensus::Parameters> RusqliteMigration for Migration<P> {
    type Error = WalletMigrationError;

    fn up(&self, transaction: &Transaction) -> Result<(), WalletMigrationError> {
        transaction.execute_batch(
            "CREATE TABLE tx_retrieval_queue (
                txid BLOB NOT NULL UNIQUE,
                query_type INTEGER NOT NULL,
                dependent_transaction_id INTEGER,
                FOREIGN KEY (dependent_transaction_id) REFERENCES transactions(id_tx)
            );

            ALTER TABLE transactions ADD COLUMN target_height INTEGER;

            CREATE TABLE transparent_spend_search_queue (
                address TEXT NOT NULL,
                transaction_id INTEGER NOT NULL,
                output_index INTEGER NOT NULL,
                FOREIGN KEY (transaction_id) REFERENCES transactions(id_tx),
                CONSTRAINT value_received_height UNIQUE (transaction_id, output_index)
            );

            CREATE TABLE transparent_spend_map (
                spending_transaction_id INTEGER NOT NULL,
                prevout_txid BLOB NOT NULL,
                prevout_output_index INTEGER NOT NULL,
                FOREIGN KEY (spending_transaction_id) REFERENCES transactions(id_tx)
                -- NOTE: We can't create a unique constraint on just (prevout_txid, prevout_output_index) 
                -- because the same output may be attempted to be spent in multiple transactions, even 
                -- though only one will ever be mined.
                CONSTRAINT transparent_spend_map_unique UNIQUE (
                    spending_transaction_id, prevout_txid, prevout_output_index
                )
            );",
        )?;

        // Add estimated target height information for each transaction we know to
        // have been created by the wallet; transactions that were discovered via
        // chain scanning will have their `created` field set to `NULL`.
        transaction.execute(
            "UPDATE transactions
             SET target_height = expiry_height - :default_expiry_delta
             WHERE expiry_height > :default_expiry_delta
             AND created IS NOT NULL",
            named_params![":default_expiry_delta": DEFAULT_TX_EXPIRY_DELTA],
        )?;

        // Call `decrypt_and_store_transaction` for each transaction known to the wallet to
        // populate the enhancement queues with any transparent history information that we don't
        // already have.
        let mut stmt_transactions =
            transaction.prepare("SELECT raw, mined_height FROM transactions")?;
        let mut rows = stmt_transactions.query([])?;
        while let Some(row) = rows.next()? {
            let tx_data = row.get::<_, Option<Vec<u8>>>(0)?;
            let mined_height = row.get::<_, Option<u32>>(1)?.map(BlockHeight::from);

            if let Some(tx_data) = tx_data {
                let tx = zcash_primitives::transaction::Transaction::read(
                    &tx_data[..],
                    // We assume unmined transactions are created with the current consensus branch ID.
                    mined_height
                        .map_or(BranchId::Sapling, |h| BranchId::for_height(&self.params, h)),
                )
                .map_err(|_| {
                    WalletMigrationError::CorruptedData(
                        "Could not read serialized transaction data.".to_owned(),
                    )
                })?;

                wallet::store_decrypted_tx(
                    transaction,
                    &self.params,
                    DecryptedTransaction::new(
                        mined_height,
                        &tx,
                        vec![],
                        #[cfg(feature = "orchard")]
                        vec![],
                    ),
                )?;
            }
        }

        Ok(())
    }

    fn down(&self, transaction: &Transaction) -> Result<(), WalletMigrationError> {
        transaction.execute_batch(
            "DROP TABLE transparent_spend_map;
             DROP TABLE transparent_spend_search_queue;
             ALTER TABLE transactions DROP COLUMN target_height;
             DROP TABLE tx_retrieval_queue;",
        )?;

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
