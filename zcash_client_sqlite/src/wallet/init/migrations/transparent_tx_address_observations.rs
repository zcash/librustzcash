//! Adds a durable index from each transparent address named by a wallet-involved transaction
//! to that transaction, in both involvement directions.
//!
//! The wallet recognizes transparent involvement by joining its stored transactions against its
//! address book. Checking a transaction against the book at the time the transaction is stored
//! maintains only the delta in which the transaction is new; the delta in which the *address* is
//! new — an account imported, a receiver imported, or the gap limit advanced after the
//! transaction was stored — has no counterpart, so a stored transaction paying an address that
//! joins the book later is never recognized.
//!
//! This index supplies the missing side. It is address-keyed and durable, which is what
//! distinguishes it from `transparent_spend_map` and `transparent_spend_locator_map`: those
//! resolve out-of-order discovery of a spend whose output arrives later, are keyed by outpoint,
//! and in the locator case are pruned below the fully scanned height.
//!
//! Every transaction for which the wallet already stores complete data is parsed here, so that
//! an existing wallet gains the index for its whole history rather than only for transactions
//! observed after the upgrade.

use std::collections::HashSet;

use schemerz_rusqlite::RusqliteMigration;
use uuid::Uuid;
use zcash_protocol::consensus;

use super::{standalone_address, transparent_spend_locator_map};
use crate::wallet::init::WalletMigrationError;

#[cfg(feature = "transparent-inputs")]
use crate::wallet::transparent::observations;

/// Adds the `transparent_tx_address_observations` index of transparent addresses named by
/// wallet-involved transactions.
pub const MIGRATION_ID: Uuid = Uuid::from_u128(0xc2ba7b74_738b_4669_a249_820350060cb9);

// `standalone_address` brings the `addresses` table to the shape against which observations are
// reconciled; `transparent_spend_locator_map` creates the sibling spend map whose division of
// labour with this index the table documentation describes.
pub(super) const DEPENDENCIES: &[Uuid] = &[
    standalone_address::MIGRATION_ID,
    transparent_spend_locator_map::MIGRATION_ID,
];

pub(super) struct Migration<P> {
    pub(super) _params: P,
}

impl<P> schemerz::Migration<Uuid> for Migration<P> {
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }

    fn dependencies(&self) -> HashSet<Uuid> {
        DEPENDENCIES.iter().copied().collect()
    }

    fn description(&self) -> &'static str {
        "Adds an index from transparent addresses to the wallet-involved transactions that name them."
    }
}

impl<P: consensus::Parameters> RusqliteMigration for Migration<P> {
    type Error = WalletMigrationError;

    fn up(&self, transaction: &rusqlite::Transaction) -> Result<(), Self::Error> {
        transaction.execute_batch(
            "CREATE TABLE transparent_tx_address_observations (
                transaction_id INTEGER NOT NULL
                    REFERENCES transactions(id_tx) ON DELETE CASCADE,
                involvement INTEGER NOT NULL,
                item_index INTEGER NOT NULL,
                address TEXT NOT NULL,
                value_zat INTEGER,
                prevout_txid BLOB,
                prevout_output_index INTEGER,
                PRIMARY KEY (transaction_id, involvement, item_index),
                CONSTRAINT involvement_data_consistency CHECK (
                    (involvement = 0 AND value_zat IS NOT NULL
                        AND prevout_txid IS NULL AND prevout_output_index IS NULL)
                    OR (involvement = 1 AND value_zat IS NULL
                        AND prevout_txid IS NOT NULL AND prevout_output_index IS NOT NULL)
                )
            ) WITHOUT ROWID;
            CREATE INDEX transparent_tx_address_observations_address
            ON transparent_tx_address_observations (
                address
            );",
        )?;

        #[cfg(feature = "transparent-inputs")]
        observations::backfill_observations(transaction, &self._params)?;

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
