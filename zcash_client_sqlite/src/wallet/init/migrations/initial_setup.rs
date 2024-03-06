//! The migration that performs the initial setup of the wallet database.
use std::collections::HashSet;

use rusqlite;
use schemer;
use schemer_rusqlite::RusqliteMigration;
use uuid::Uuid;

use crate::wallet::init::WalletMigrationError;

/// Identifier for the migration that performs the initial setup of the wallet database.
pub(super) const MIGRATION_ID: Uuid = Uuid::from_u128(0xbc4f5e57_d600_4b6c_990f_b3538f0bfce1);

pub(super) struct Migration;

impl schemer::Migration for Migration {
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }

    fn dependencies(&self) -> HashSet<Uuid> {
        HashSet::new()
    }

    fn description(&self) -> &'static str {
        "Initialize the wallet database."
    }
}

impl RusqliteMigration for Migration {
    type Error = WalletMigrationError;

    fn up(&self, transaction: &rusqlite::Transaction) -> Result<(), WalletMigrationError> {
        transaction.execute_batch(
            // We set the user_version field of the database to a constant value of 8 to allow
            // correct integration with the Android SDK with versions of the database that were
            // created prior to the introduction of migrations in this crate.  This constant should
            // remain fixed going forward, and should not be altered by migrations; migration
            // status is maintained exclusively by the schemer_migrations table.
            "PRAGMA user_version = 8;
            CREATE TABLE IF NOT EXISTS accounts (
                account INTEGER PRIMARY KEY,
                extfvk TEXT NOT NULL,
                address TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS blocks (
                height INTEGER PRIMARY KEY,
                hash BLOB NOT NULL,
                time INTEGER NOT NULL,
                sapling_tree BLOB NOT NULL
            );
            CREATE TABLE IF NOT EXISTS transactions (
                id_tx INTEGER PRIMARY KEY,
                txid BLOB NOT NULL UNIQUE,
                created TEXT,
                block INTEGER,
                tx_index INTEGER,
                expiry_height INTEGER,
                raw BLOB,
                FOREIGN KEY (block) REFERENCES blocks(height)
            );
            CREATE TABLE IF NOT EXISTS received_notes (
                id_note INTEGER PRIMARY KEY,
                tx INTEGER NOT NULL,
                output_index INTEGER NOT NULL,
                account INTEGER NOT NULL,
                diversifier BLOB NOT NULL,
                value INTEGER NOT NULL,
                rcm BLOB NOT NULL,
                nf BLOB NOT NULL UNIQUE,
                is_change INTEGER NOT NULL,
                memo BLOB,
                spent INTEGER,
                FOREIGN KEY (tx) REFERENCES transactions(id_tx),
                FOREIGN KEY (account) REFERENCES accounts(account),
                FOREIGN KEY (spent) REFERENCES transactions(id_tx),
                CONSTRAINT tx_output UNIQUE (tx, output_index)
            );
            CREATE TABLE IF NOT EXISTS sapling_witnesses (
                id_witness INTEGER PRIMARY KEY,
                note INTEGER NOT NULL,
                block INTEGER NOT NULL,
                witness BLOB NOT NULL,
                FOREIGN KEY (note) REFERENCES received_notes(id_note),
                FOREIGN KEY (block) REFERENCES blocks(height),
                CONSTRAINT witness_height UNIQUE (note, block)
            );
            CREATE TABLE IF NOT EXISTS sent_notes (
                id_note INTEGER PRIMARY KEY,
                tx INTEGER NOT NULL,
                output_index INTEGER NOT NULL,
                from_account INTEGER NOT NULL,
                address TEXT NOT NULL,
                value INTEGER NOT NULL,
                memo BLOB,
                FOREIGN KEY (tx) REFERENCES transactions(id_tx),
                FOREIGN KEY (from_account) REFERENCES accounts(account),
                CONSTRAINT tx_output UNIQUE (tx, output_index)
            );",
        )?;
        Ok(())
    }

    fn down(&self, _transaction: &rusqlite::Transaction) -> Result<(), WalletMigrationError> {
        // We should never down-migrate the first migration, as that can irreversibly
        // destroy data.
        Err(WalletMigrationError::CannotRevert(MIGRATION_ID))
    }
}
