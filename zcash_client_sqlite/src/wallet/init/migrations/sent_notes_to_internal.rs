//! A migration that adds an identifier for the account that received a sent note
//! on an internal address to the sent_notes table.
use std::collections::HashSet;

use rusqlite;
use schemer;
use schemer_rusqlite::RusqliteMigration;
use uuid::Uuid;

use super::ufvk_support;
use crate::wallet::init::WalletMigrationError;

/// This migration adds the `to_account` field to the `sent_notes` table.
pub(super) const MIGRATION_ID: Uuid = Uuid::from_u128(0x0ddbe561_8259_4212_9ab7_66fdc4a74e1d);

pub(super) struct Migration;

impl schemer::Migration for Migration {
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }

    fn dependencies(&self) -> HashSet<Uuid> {
        [ufvk_support::MIGRATION_ID].into_iter().collect()
    }

    fn description(&self) -> &'static str {
        "Adds an identifier for the account that received an internal note to the sent_notes table"
    }
}

impl RusqliteMigration for Migration {
    type Error = WalletMigrationError;

    fn up(&self, transaction: &rusqlite::Transaction) -> Result<(), WalletMigrationError> {
        // Adds the `to_account` column to the `sent_notes` table and establishes the
        // foreign key relationship with the `account` table.
        transaction.execute_batch(
            "CREATE TABLE sent_notes_new (
                id_note INTEGER PRIMARY KEY,
                tx INTEGER NOT NULL,
                output_pool INTEGER NOT NULL,
                output_index INTEGER NOT NULL,
                from_account INTEGER NOT NULL,
                to_address TEXT,
                to_account INTEGER,
                value INTEGER NOT NULL,
                memo BLOB,
                FOREIGN KEY (tx) REFERENCES transactions(id_tx),
                FOREIGN KEY (from_account) REFERENCES accounts(account),
                FOREIGN KEY (to_account) REFERENCES accounts(account),
                CONSTRAINT tx_output UNIQUE (tx, output_pool, output_index),
                CONSTRAINT note_recipient CHECK (
                    (to_address IS NOT NULL) != (to_account IS NOT NULL)
                )
            );
            INSERT INTO sent_notes_new (
                id_note, tx, output_pool, output_index,
                from_account, to_address,
                value, memo)
            SELECT
                id_note, tx, output_pool, output_index,
                from_account, address,
                value, memo
            FROM sent_notes;",
        )?;

        transaction.execute_batch(
            "DROP TABLE sent_notes;
            ALTER TABLE sent_notes_new RENAME TO sent_notes;",
        )?;

        Ok(())
    }

    fn down(&self, _transaction: &rusqlite::Transaction) -> Result<(), WalletMigrationError> {
        Err(WalletMigrationError::CannotRevert(MIGRATION_ID))
    }
}
