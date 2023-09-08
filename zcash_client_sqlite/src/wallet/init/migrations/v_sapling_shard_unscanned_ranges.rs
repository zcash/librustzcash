//! This migration adds a view that returns the un-scanned ranges associated with each sapling note
//! commitment tree shard.

use std::collections::HashSet;

use schemer_rusqlite::RusqliteMigration;
use uuid::Uuid;
use zcash_client_backend::data_api::{scanning::ScanPriority, SAPLING_SHARD_HEIGHT};
use zcash_primitives::consensus::{self, NetworkUpgrade};

use crate::wallet::{init::WalletMigrationError, scanning::priority_code};

use super::add_account_birthdays;

pub(super) const MIGRATION_ID: Uuid = Uuid::from_u128(0xfa934bdc_97b6_4980_8a83_b2cb1ac465fd);

pub(super) struct Migration<P> {
    pub(super) params: P,
}

impl<P> schemer::Migration for Migration<P> {
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }

    fn dependencies(&self) -> HashSet<Uuid> {
        [add_account_birthdays::MIGRATION_ID].into_iter().collect()
    }

    fn description(&self) -> &'static str {
        "Adds a view that returns the un-scanned ranges associated with each sapling note commitment tree shard."
    }
}

impl<P: consensus::Parameters> RusqliteMigration for Migration<P> {
    type Error = WalletMigrationError;

    fn up(&self, transaction: &rusqlite::Transaction) -> Result<(), Self::Error> {
        transaction.execute_batch(&format!(
            "CREATE VIEW v_sapling_shard_scan_ranges AS
                SELECT
                    shard.shard_index,
                    shard.shard_index << {} AS start_position,
                    (shard.shard_index + 1) << {} AS end_position_exclusive,
                    IFNULL(prev_shard.subtree_end_height, {}) AS subtree_start_height,
                    shard.subtree_end_height,
                    shard.contains_marked,
                    scan_queue.block_range_start,
                    scan_queue.block_range_end,
                    scan_queue.priority
                FROM sapling_tree_shards shard
                LEFT OUTER JOIN sapling_tree_shards prev_shard
                    ON shard.shard_index = prev_shard.shard_index + 1
                -- Join with scan ranges that overlap with the subtree's involved blocks.
                INNER JOIN scan_queue ON (
                    subtree_start_height < scan_queue.block_range_end AND
                    (
                        scan_queue.block_range_start <= shard.subtree_end_height OR
                        shard.subtree_end_height IS NULL
                    )
                )",
            SAPLING_SHARD_HEIGHT,
            SAPLING_SHARD_HEIGHT,
            u32::from(
                self.params
                    .activation_height(NetworkUpgrade::Sapling)
                    .unwrap()
            ),
        ))?;

        transaction.execute_batch(&format!(
            "CREATE VIEW v_sapling_shard_unscanned_ranges AS
                WITH wallet_birthday AS (SELECT MIN(birthday_height) AS height FROM accounts)
                SELECT
                    shard_index,
                    start_position,
                    end_position_exclusive,
                    subtree_start_height,
                    subtree_end_height,
                    contains_marked,
                    block_range_start,
                    block_range_end,
                    priority
                FROM v_sapling_shard_scan_ranges
                INNER JOIN wallet_birthday
                WHERE priority > {}
                AND block_range_end > wallet_birthday.height;",
            priority_code(&ScanPriority::Scanned),
        ))?;

        Ok(())
    }

    fn down(&self, transaction: &rusqlite::Transaction) -> Result<(), Self::Error> {
        transaction.execute_batch("DROP VIEW v_sapling_shard_unscanned_ranges;")?;
        Ok(())
    }
}
