//! The migration that adds initial support for transparent UTXOs to the wallet.
use std::collections::HashSet;

use rusqlite;
use schemer;
use schemer_rusqlite::RusqliteMigration;
use uuid::Uuid;

use crate::wallet::init::{migrations::initial_setup, WalletMigrationError};

pub(super) const MIGRATION_ID: Uuid = Uuid::from_u128(0xa2e0ed2e_8852_475e_b0a4_f154b15b9dbe);

pub(super) struct Migration;

impl schemer::Migration for Migration {
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }

    fn dependencies(&self) -> HashSet<Uuid> {
        [initial_setup::MIGRATION_ID].into_iter().collect()
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
