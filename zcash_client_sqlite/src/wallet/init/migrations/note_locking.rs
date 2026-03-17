//! This migration adds `lock_expiry_height` columns to received note tables to support
//! height-based note locking during proposal creation.
use std::collections::HashSet;

use schemerz_rusqlite::RusqliteMigration;
use uuid::Uuid;

use crate::wallet::init::{WalletMigrationError, migrations::v_tx_outputs_key_scopes};

pub(super) const MIGRATION_ID: Uuid = Uuid::from_u128(0xa1d4a28c_7582_4457_b0f4_d3f297b62a71);

const DEPENDENCIES: &[Uuid] = &[v_tx_outputs_key_scopes::MIGRATION_ID];

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
