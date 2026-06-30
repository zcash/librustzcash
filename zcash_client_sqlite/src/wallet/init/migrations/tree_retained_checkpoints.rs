//! Migration that adds tables for tracking explicitly-retained shardtree checkpoints ("anchors").
//!
//! A retained checkpoint is exempt from automatic pruning of excess checkpoints, so that its root
//! and the witnesses anchored to it remain computable even after it has aged more than
//! `max_checkpoints` behind the tip of the note commitment tree.

use std::collections::HashSet;

use schemerz_rusqlite::RusqliteMigration;
use uuid::Uuid;

use super::witness_stabilized_notes;
use crate::wallet::init::WalletMigrationError;

pub(super) const MIGRATION_ID: Uuid = Uuid::from_u128(0x62032f4a_88b5_454d_a591_10f3d4c4d2b7);

const DEPENDENCIES: &[Uuid] = &[witness_stabilized_notes::MIGRATION_ID];

pub(super) struct Migration;

impl schemerz::Migration<Uuid> for Migration {
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }

    fn dependencies(&self) -> HashSet<Uuid> {
        DEPENDENCIES.iter().copied().collect()
    }

    fn description(&self) -> &'static str {
        "Adds tables for tracking explicitly-retained shardtree checkpoints."
    }
}

impl RusqliteMigration for Migration {
    type Error = WalletMigrationError;

    fn up(&self, transaction: &rusqlite::Transaction) -> Result<(), WalletMigrationError> {
        transaction.execute_batch(
            "CREATE TABLE sapling_tree_retained_checkpoints (
                checkpoint_id INTEGER PRIMARY KEY
            );
            CREATE TABLE orchard_tree_retained_checkpoints (
                checkpoint_id INTEGER PRIMARY KEY
            );",
        )?;
        Ok(())
    }

    fn down(&self, _transaction: &rusqlite::Transaction) -> Result<(), WalletMigrationError> {
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
