//! The migration that adds initial support for transparent UTXOs to the wallet.
use std::collections::HashSet;

use schemerz_rusqlite::RusqliteMigration;
use uuid::Uuid;

use crate::wallet::init::{WalletMigrationError, migrations::initial_setup};

pub(super) const MIGRATION_ID: Uuid = Uuid::from_u128(0xa2e0ed2e_8852_475e_b0a4_f154b15b9dbe);

const DEPENDENCIES: &[Uuid] = &[initial_setup::MIGRATION_ID];

pub(super) struct Migration;

impl schemerz::Migration<Uuid> for Migration {
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }

    fn dependencies(&self) -> HashSet<Uuid> {
        DEPENDENCIES.iter().copied().collect()
    }

    fn description(&self) -> &'static str {
        "Add support for receiving transparent UTXOs."
    }
}

impl RusqliteMigration for Migration {
    type Error = WalletMigrationError;

    fn up(&self, transaction: &rusqlite::Transaction) -> Result<(), WalletMigrationError> {
        transaction.execute_batch(
            "CREATE TABLE IF NOT EXISTS utxos (
                id_utxo INTEGER PRIMARY KEY,
                address TEXT NOT NULL,
                prevout_txid BLOB NOT NULL,
                prevout_idx INTEGER NOT NULL,
                script BLOB NOT NULL,
                value_zat INTEGER NOT NULL,
                height INTEGER NOT NULL,
                spent_in_tx INTEGER,
                FOREIGN KEY (spent_in_tx) REFERENCES transactions(id_tx),
                CONSTRAINT tx_outpoint UNIQUE (prevout_txid, prevout_idx)
            );",
        )?;
        Ok(())
    }

    fn down(&self, transaction: &rusqlite::Transaction) -> Result<(), WalletMigrationError> {
        transaction.execute_batch("DROP TABLE utxos;")?;
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
