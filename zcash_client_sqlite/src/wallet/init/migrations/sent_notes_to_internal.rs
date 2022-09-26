//! A migration that adds an identifier for the account that received a sent note
//! on an internal address to the sent_notes table.
use std::collections::HashSet;

use rusqlite;
use schemer;
use schemer_rusqlite::RusqliteMigration;
use uuid::Uuid;

use super::{addresses_table, utxos_table};
use crate::wallet::init::WalletMigrationError;

/// This migration adds the `to_account` field to the `sent_notes` table.
///
/// 0ddbe561-8259-4212-9ab7-66fdc4a74e1d
pub(super) const MIGRATION_ID: Uuid = Uuid::from_fields(
    0x0ddbe561,
    0x8259,
    0x4212,
    b"\x9a\xb7\x66\xfd\xc4\xa7\x4e\x1d",
);

pub(super) struct Migration;

impl schemer::Migration for Migration {
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }

    fn dependencies(&self) -> HashSet<Uuid> {
        [utxos_table::MIGRATION_ID, addresses_table::MIGRATION_ID]
            .into_iter()
            .collect()
    }

    fn description(&self) -> &'static str {
        "Adds an identifier for the account that received an internal note to the sent_notes table"
    }
}

impl RusqliteMigration for Migration {
    type Error = WalletMigrationError;

    fn up(&self, transaction: &rusqlite::Transaction) -> Result<(), WalletMigrationError> {
        transaction.execute_batch("ALTER TABLE sent_notes ADD COLUMN to_account INTEGER;")?;

        // `to_account` should be null for all migrated rows, since internal addresses
        // have not been used for change or shielding prior to this migration.
        transaction.execute_batch(
            "CREATE TABLE sent_notes_new (
                id_note INTEGER PRIMARY KEY,
                tx INTEGER NOT NULL,
                output_pool INTEGER NOT NULL ,
                output_index INTEGER NOT NULL,
                from_account INTEGER NOT NULL,
                to_address TEXT,
                to_account INTEGER,
                value INTEGER NOT NULL,
                memo BLOB,
                FOREIGN KEY (tx) REFERENCES transactions(id_tx),
                FOREIGN KEY (from_account) REFERENCES accounts(account),
                FOREIGN KEY (to_account) REFERENCES accounts(account),
                CONSTRAINT tx_output UNIQUE (tx, output_pool, output_index)
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
        // TODO: something better than just panic?
        panic!("Cannot revert this migration.");
    }
}
