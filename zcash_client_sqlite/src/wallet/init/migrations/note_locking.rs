//! This migration adds `lock_expiry_height` columns to received note tables to support
//! height-based note locking during proposal creation.
use std::collections::HashSet;

use schemerz_rusqlite::RusqliteMigration;
use uuid::Uuid;

use crate::wallet::init::{WalletMigrationError, migrations::ironwood_received_notes};

pub(super) const MIGRATION_ID: Uuid = Uuid::from_u128(0xa1d4a28c_7582_4457_b0f4_d3f297b62a71);

// This migration only appends a nullable column to each of the `sapling_received_notes`,
// `orchard_received_notes`, `ironwood_received_notes`, and `transparent_received_outputs`
// tables, so it need only run after the last migration that establishes the schema of those
// tables. `ironwood_received_notes` is that migration: it transitively depends on every
// migration that creates or rebuilds any of the four tables (the sapling/orchard/transparent
// rebuilds all precede it via `orchard_note_version` -> `witness_stabilized_notes` ->
// `account_delete_cascade`), and it creates the `ironwood_received_notes` table itself.
const DEPENDENCIES: &[Uuid] = &[ironwood_received_notes::MIGRATION_ID];

pub(super) struct Migration;

impl schemerz::Migration<Uuid> for Migration {
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }

    fn dependencies(&self) -> HashSet<Uuid> {
        DEPENDENCIES.iter().copied().collect()
    }

    fn description(&self) -> &'static str {
        "Adds lock_expiry_height columns to received note tables for height-based note locking."
    }
}

impl RusqliteMigration for Migration {
    type Error = WalletMigrationError;

    fn up(&self, conn: &rusqlite::Transaction) -> Result<(), Self::Error> {
        conn.execute_batch(
            "ALTER TABLE sapling_received_notes ADD COLUMN lock_expiry_height INTEGER;
             ALTER TABLE orchard_received_notes ADD COLUMN lock_expiry_height INTEGER;
             ALTER TABLE ironwood_received_notes ADD COLUMN lock_expiry_height INTEGER;
             ALTER TABLE transparent_received_outputs ADD COLUMN lock_expiry_height INTEGER;",
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
