//! Adds expiration to transaction enhancement requests.

use rusqlite::{Transaction, named_params};
use schemerz_rusqlite::RusqliteMigration;
use std::collections::HashSet;
use uuid::Uuid;
use zcash_primitives::transaction::builder::DEFAULT_TX_EXPIRY_DELTA;

use crate::wallet::{chain_tip_height, init::WalletMigrationError};

use super::tx_retrieval_queue;

pub(super) const MIGRATION_ID: Uuid = Uuid::from_u128(0x9ffe82d4_3bf5_459a_9a21_7affd9e88e95);

const DEPENDENCIES: &[Uuid] = &[tx_retrieval_queue::MIGRATION_ID];

pub(super) struct Migration;

impl schemerz::Migration<Uuid> for Migration {
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }

    fn dependencies(&self) -> HashSet<Uuid> {
        DEPENDENCIES.iter().copied().collect()
    }

    fn description(&self) -> &'static str {
        "Adds expiration to transaction enhancement requests"
    }
}

impl RusqliteMigration for Migration {
    type Error = WalletMigrationError;

    fn up(&self, conn: &Transaction) -> Result<(), WalletMigrationError> {
        let chain_tip = chain_tip_height(conn)?;

        conn.execute_batch(
            "ALTER TABLE tx_retrieval_queue ADD COLUMN request_expiry INTEGER;

             UPDATE tx_retrieval_queue
             SET request_expiry = t.expiry_height
             FROM transactions t
             WHERE t.txid = tx_retrieval_queue.txid;",
        )?;

        // Requests may have been added to the queue for transaction IDs that do not correspond to
        // any mined transaction; this has occurred in the past when the null txid was added to the
        // queue when trying to traverse the input graph from a coinbase transaction belonging to
        // the wallet; it also has the potential to occur in some reorg cases involving zero-conf
        // transactions.
        conn.execute(
            "UPDATE tx_retrieval_queue
             SET request_expiry = :manual_expiry
             WHERE request_expiry IS NULL",
            named_params! {
                ":manual_expiry": chain_tip.map(|h| u32::from(h) + DEFAULT_TX_EXPIRY_DELTA)
            },
        )?;
        Ok(())
    }

    fn down(&self, _: &Transaction) -> Result<(), WalletMigrationError> {
        Err(WalletMigrationError::CannotRevert(MIGRATION_ID))
    }
}

#[cfg(test)]
mod tests {
    use crate::wallet::init::migrations::tests::test_migrate;

    use super::MIGRATION_ID;

    #[test]
    fn migrate() {
        test_migrate(&[MIGRATION_ID]);
    }
}
