//! This migration adds `lock_expiry_height` columns to received note tables to support
//! height-based note locking during proposal creation.
use std::collections::HashSet;

use schemerz_rusqlite::RusqliteMigration;
use uuid::Uuid;

use crate::wallet::init::{
    WalletMigrationError,
    migrations::{
        add_transparent_receiver_address_index, add_transparent_value_index,
        ironwood_pool_code_views, ivk_item_cache, tree_retained_checkpoints,
        v_tx_outputs_key_scopes,
    },
};

pub(super) const MIGRATION_ID: Uuid = Uuid::from_u128(0xa1d4a28c_7582_4457_b0f4_d3f297b62a71);

const DEPENDENCIES: &[Uuid] = &[
    v_tx_outputs_key_scopes::MIGRATION_ID,
    ivk_item_cache::MIGRATION_ID,
    add_transparent_receiver_address_index::MIGRATION_ID,
    add_transparent_value_index::MIGRATION_ID,
    ironwood_pool_code_views::MIGRATION_ID,
    tree_retained_checkpoints::MIGRATION_ID,
];

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
