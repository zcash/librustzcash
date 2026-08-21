//! Adds a table mapping a spent transparent outpoint to the transaction that spent it,
//! identified by its transaction locator rather than by a `transactions` row.
//!
//! `transparent_spend_map` already records spends of outputs the wallet does not yet hold, but
//! keys them by `spending_transaction_id`, so the spending transaction must be one the wallet
//! stores. That holds for transactions received in full, and not for block scanning: nearly every
//! transparent input in a scanned block belongs to a transaction with no wallet involvement, and
//! creating a `transactions` row for each would be wrong.
//!
//! This table keys the same relation by `(block_height, tx_index)`, exactly as `nullifier_map`
//! does for shielded spends, so the spending transaction is named without a `transactions` row and
//! at a fraction of the storage cost of a txid. Its rows are removed by the same pruning: they
//! cascade from `tx_locator_map`, which `prune_nullifier_map` trims below the wallet's fully
//! scanned height.

use std::collections::HashSet;

use schemerz_rusqlite::RusqliteMigration;
use uuid::Uuid;

use super::{nullifier_map, tx_retrieval_queue};
use crate::wallet::init::WalletMigrationError;

/// Adds a table mapping a spent transparent outpoint to the transaction locator of the
/// transaction that spent it.
pub const MIGRATION_ID: Uuid = Uuid::from_u128(0xb72f8199_a8a2_4a07_9dbd_18ea49d8a17d);

// `nullifier_map` creates `tx_locator_map`, which this table's foreign key references.
// `tx_retrieval_queue` creates `transparent_spend_map`, the sibling this table complements;
// depending on it keeps the two ordered so that the pair is always introduced together.
pub(super) const DEPENDENCIES: &[Uuid] = &[
    nullifier_map::MIGRATION_ID,
    tx_retrieval_queue::MIGRATION_ID,
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
        "Adds a lookup table from transparent outpoints spent on-chain to the transaction locators of the transactions that spent them."
    }
}

impl RusqliteMigration for Migration {
    type Error = WalletMigrationError;

    fn up(&self, transaction: &rusqlite::Transaction) -> Result<(), Self::Error> {
        transaction.execute_batch(
            "CREATE TABLE transparent_spend_locator_map (
                prevout_txid BLOB NOT NULL,
                prevout_output_index INTEGER NOT NULL,
                block_height INTEGER NOT NULL,
                tx_index INTEGER NOT NULL,
                CONSTRAINT tx_locator
                    FOREIGN KEY (block_height, tx_index)
                    REFERENCES tx_locator_map(block_height, tx_index)
                    ON DELETE CASCADE
                    ON UPDATE RESTRICT,
                CONSTRAINT prevout_uniq UNIQUE (prevout_txid, prevout_output_index)
            );
            CREATE INDEX transparent_spend_locator_idx
                ON transparent_spend_locator_map (block_height, tx_index);",
        )?;

        Ok(())
    }

    fn down(&self, _transaction: &rusqlite::Transaction) -> Result<(), Self::Error> {
        Err(WalletMigrationError::CannotRevert(MIGRATION_ID))
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
