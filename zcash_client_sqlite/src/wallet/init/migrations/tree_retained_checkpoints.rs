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
            );
            CREATE TABLE ironwood_tree_retained_checkpoints (
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
    use secrecy::Secret;
    use tempfile::NamedTempFile;
    use zcash_protocol::consensus::{BlockHeight, Network};

    use crate::{
        testing::db::{test_clock, test_rng},
        wallet::{
            commitment_tree::add_retained_checkpoint, init::migrations::tests::test_migrate,
            init::WalletMigrator,
        },
        WalletDb,
    };

    #[test]
    fn migrate() {
        test_migrate(&[super::MIGRATION_ID]);
    }

    /// This migration must create a retained-checkpoints table for *every* shielded pool that
    /// has a shardtree, Ironwood included. The shardtree stores persist a retained checkpoint
    /// via [`add_retained_checkpoint`] with the pool's table prefix, so a missing
    /// `ironwood_tree_retained_checkpoints` makes an Ironwood scan fail with
    /// `PutBlocksCommitmentTree { pool: Ironwood, .. no such table }` as soon as a checkpoint is
    /// retained. Exercise that exact write for all three pools.
    #[test]
    fn retained_checkpoint_tables_exist_for_all_pools() {
        let data_file = NamedTempFile::new().unwrap();
        let mut db_data =
            WalletDb::for_path(data_file.path(), Network::TestNetwork, test_clock(), test_rng())
                .unwrap();
        WalletMigrator::new()
            .with_seed(Secret::new(vec![0xab; 32]))
            .ignore_seed_relevance()
            .init_or_migrate_to(&mut db_data, &[super::MIGRATION_ID])
            .unwrap();

        let mut conn = rusqlite::Connection::open(data_file.path()).unwrap();
        let tx = conn.transaction().unwrap();
        for prefix in ["sapling", "orchard", "ironwood"] {
            add_retained_checkpoint(&tx, prefix, BlockHeight::from_u32(1))
                .unwrap_or_else(|e| panic!("add_retained_checkpoint({prefix}) failed: {e:?}"));
        }
        tx.commit().unwrap();
    }
}
