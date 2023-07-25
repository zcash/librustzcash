//! This migration adds a table for storing mappings from nullifiers to the transaction
//! they are revealed in.

use std::collections::HashSet;

use schemer_rusqlite::RusqliteMigration;
use tracing::debug;
use uuid::Uuid;

use crate::wallet::init::WalletMigrationError;

use super::received_notes_nullable_nf;

pub(super) const MIGRATION_ID: Uuid = Uuid::from_u128(0xe2d71ac5_6a44_4c6b_a9a0_6d0a79d355f1);

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
        "Adds a lookup table for nullifiers we've observed on-chain that we haven't confirmed are not ours."
    }
}

impl RusqliteMigration for Migration {
    type Error = WalletMigrationError;

    fn up(&self, transaction: &rusqlite::Transaction) -> Result<(), Self::Error> {
        // We don't enforce any foreign key constraint to the blocks table, to allow
        // loading the nullifier map separately from block scanning.
        debug!("Creating tables for nullifier map");
        transaction.execute_batch(
            "CREATE TABLE tx_locator_map (
                block_height INTEGER NOT NULL,
                tx_index INTEGER NOT NULL,
                txid BLOB NOT NULL UNIQUE,
                PRIMARY KEY (block_height, tx_index)
            );
            CREATE TABLE nullifier_map (
                spend_pool INTEGER NOT NULL,
                nf BLOB NOT NULL,
                block_height INTEGER NOT NULL,
                tx_index INTEGER NOT NULL,
                CONSTRAINT tx_locator
                    FOREIGN KEY (block_height, tx_index)
                    REFERENCES tx_locator_map(block_height, tx_index)
                    ON DELETE CASCADE
                    ON UPDATE RESTRICT,
                CONSTRAINT nf_uniq UNIQUE (spend_pool, nf)
            );
            CREATE INDEX nf_map_locator_idx ON nullifier_map(block_height, tx_index);",
        )?;

        Ok(())
    }

    fn down(&self, transaction: &rusqlite::Transaction) -> Result<(), Self::Error> {
        transaction.execute_batch(
            "DROP TABLE nullifier_map;
            DROP TABLE tx_locator_map;",
        )?;
        Ok(())
    }
}
