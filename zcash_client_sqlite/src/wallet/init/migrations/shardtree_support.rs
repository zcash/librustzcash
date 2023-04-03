//! This migration adds tables to the wallet database that are needed to persist note commitment
//! tree data using the `shardtree` crate, and migrates existing witness data into these data
//! structures.

use std::collections::HashSet;

use rusqlite;
use schemer;
use schemer_rusqlite::RusqliteMigration;
use uuid::Uuid;

use crate::wallet::init::{migrations::received_notes_nullable_nf, WalletMigrationError};

pub(super) const MIGRATION_ID: Uuid = Uuid::from_fields(
    0x7da6489d,
    0xe835,
    0x4657,
    b"\x8b\xe5\xf5\x12\xbc\xce\x6c\xbf",
);

pub(super) struct Migration;

impl schemer::Migration for Migration {
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }

    fn dependencies(&self) -> HashSet<Uuid> {
        [received_notes_nullable_nf::MIGRATION_ID]
            .into_iter()
            .collect()
    }

    fn description(&self) -> &'static str {
        "Add support for receiving storage of note commitment tree data using the `shardtree` crate."
    }
}

impl RusqliteMigration for Migration {
    type Error = WalletMigrationError;

    fn up(&self, transaction: &rusqlite::Transaction) -> Result<(), WalletMigrationError> {
        // Add commitment tree sizes to block metadata.
        transaction.execute_batch(
            "ALTER TABLE blocks ADD COLUMN sapling_commitment_tree_size INTEGER;
             ALTER TABLE blocks ADD COLUMN orchard_commitment_tree_size INTEGER;
             ALTER TABLE sapling_received_notes ADD COLUMN commitment_tree_position INTEGER;",
        )?;

        Ok(())
    }

    fn down(&self, _transaction: &rusqlite::Transaction) -> Result<(), WalletMigrationError> {
        Ok(())
    }
}
