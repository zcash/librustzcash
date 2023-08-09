//! This migration adds a view that returns the un-scanned ranges associated with each sapling note
//! commitment tree shard.

use std::collections::HashSet;

use schemer_rusqlite::RusqliteMigration;
use uuid::Uuid;
use zcash_client_backend::data_api::scanning::ScanPriority;
use zcash_primitives::consensus;

use crate::wallet::{init::WalletMigrationError, scanning::priority_code};

use super::shardtree_support;

pub(super) const MIGRATION_ID: Uuid = Uuid::from_u128(0xfa934bdc_97b6_4980_8a83_b2cb1ac465fd);

pub(super) struct Migration<P> {
    pub(super) params: P,
}

impl<P> schemer::Migration for Migration<P> {
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }

    fn dependencies(&self) -> HashSet<Uuid> {
        [shardtree_support::MIGRATION_ID].into_iter().collect()
    }

    fn description(&self) -> &'static str {
        "Adds a view that returns the un-scanned ranges associated with each sapling note commitment tree shard."
    }
}

impl<P: consensus::Parameters> RusqliteMigration for Migration<P> {
    type Error = WalletMigrationError;

    fn up(&self, transaction: &rusqlite::Transaction) -> Result<(), Self::Error> {
        transaction.execute_batch(
            &format!(
                "CREATE VIEW v_sapling_shard_unscanned_ranges AS
                SELECT
                    shard.shard_index,
                    shard.shard_index << 16 AS start_position,
                    (shard.shard_index + 1) << 16 AS end_position_exclusive,
                    IFNULL(prev_shard.subtree_end_height, {}) AS subtree_start_height,
                    shard.subtree_end_height AS subtree_end_height,
                    shard.contains_marked,
                    scan_queue.block_range_start,
                    scan_queue.block_range_end,
                    scan_queue.priority
                FROM sapling_tree_shards shard
                LEFT OUTER JOIN sapling_tree_shards prev_shard
                    ON shard.shard_index = prev_shard.shard_index + 1
                INNER JOIN scan_queue ON 
                    (scan_queue.block_range_start BETWEEN subtree_start_height AND shard.subtree_end_height) OR
                    ((scan_queue.block_range_end - 1) BETWEEN subtree_start_height AND shard.subtree_end_height) OR
                    (
                        scan_queue.block_range_start <= prev_shard.subtree_end_height
                        AND (scan_queue.block_range_end - 1) >= shard.subtree_end_height
                    )
                WHERE scan_queue.priority != {}",
                u32::from(self.params.activation_height(consensus::NetworkUpgrade::Sapling).unwrap()),
                priority_code(&ScanPriority::Scanned),
            )
        )?;

        Ok(())
    }

    fn down(&self, transaction: &rusqlite::Transaction) -> Result<(), Self::Error> {
        transaction.execute_batch("DROP VIEW v_sapling_shard_unscanned_ranges;")?;
        Ok(())
    }
}
