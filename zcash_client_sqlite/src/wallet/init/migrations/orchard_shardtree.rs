//! This migration adds tables to the wallet database that are needed to persist Orchard note
//! commitment tree data using the `shardtree` crate.

use std::collections::HashSet;

use rusqlite::{named_params, OptionalExtension};
use schemer_rusqlite::RusqliteMigration;
use tracing::debug;
use uuid::Uuid;
use zcash_client_backend::data_api::scanning::ScanPriority;
use zcash_protocol::consensus::{self, BlockHeight, NetworkUpgrade};

use super::shardtree_support;
use crate::wallet::{init::WalletMigrationError, scan_queue_extrema, scanning::priority_code};

pub(super) const MIGRATION_ID: Uuid = Uuid::from_u128(0x3a6487f7_e068_42bb_9d12_6bb8dbe6da00);

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
        "Add support for storage of Orchard note commitment tree data using the `shardtree` crate."
    }
}

impl<P: consensus::Parameters> RusqliteMigration for Migration<P> {
    type Error = WalletMigrationError;

    fn up(&self, transaction: &rusqlite::Transaction) -> Result<(), WalletMigrationError> {
        // Add shard persistence
        debug!("Creating tables for Orchard shard persistence");
        transaction.execute_batch(
            "CREATE TABLE orchard_tree_shards (
                shard_index INTEGER PRIMARY KEY,
                subtree_end_height INTEGER,
                root_hash BLOB,
                shard_data BLOB,
                contains_marked INTEGER,
                CONSTRAINT root_unique UNIQUE (root_hash)
            );
            CREATE TABLE orchard_tree_cap (
                -- cap_id exists only to be able to take advantage of `ON CONFLICT`
                -- upsert functionality; the table will only ever contain one row
                cap_id INTEGER PRIMARY KEY,
                cap_data BLOB NOT NULL
            );",
        )?;

        // Add checkpoint persistence
        debug!("Creating tables for checkpoint persistence");
        transaction.execute_batch(
            "CREATE TABLE orchard_tree_checkpoints (
                checkpoint_id INTEGER PRIMARY KEY,
                position INTEGER
            );
            CREATE TABLE orchard_tree_checkpoint_marks_removed (
                checkpoint_id INTEGER NOT NULL,
                mark_removed_position INTEGER NOT NULL,
                FOREIGN KEY (checkpoint_id) REFERENCES orchard_tree_checkpoints(checkpoint_id)
                ON DELETE CASCADE,
                CONSTRAINT spend_position_unique UNIQUE (checkpoint_id, mark_removed_position)
            );",
        )?;

        transaction.execute_batch(&format!(
            "CREATE VIEW v_orchard_shard_scan_ranges AS
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
                FROM orchard_tree_shards shard
                LEFT OUTER JOIN orchard_tree_shards prev_shard
                    ON shard.shard_index = prev_shard.shard_index + 1
                -- Join with scan ranges that overlap with the subtree's involved blocks.
                INNER JOIN scan_queue ON (
                    subtree_start_height < scan_queue.block_range_end AND
                    (
                        scan_queue.block_range_start <= shard.subtree_end_height OR
                        shard.subtree_end_height IS NULL
                    )
                )",
            16, // ORCHARD_SHARD_HEIGHT is only available when `feature = "orchard"` is enabled.
            16, // ORCHARD_SHARD_HEIGHT is only available when `feature = "orchard"` is enabled.
            u32::from(self.params.activation_height(NetworkUpgrade::Nu5).unwrap()),
        ))?;

        transaction.execute_batch(&format!(
            "CREATE VIEW v_orchard_shard_unscanned_ranges AS
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
                FROM v_orchard_shard_scan_ranges
                INNER JOIN wallet_birthday
                WHERE priority > {}
                AND block_range_end > wallet_birthday.height;",
            priority_code(&ScanPriority::Scanned),
        ))?;

        transaction.execute_batch(
            "CREATE VIEW v_orchard_shards_scan_state AS
            SELECT
                shard_index,
                start_position,
                end_position_exclusive,
                subtree_start_height,
                subtree_end_height,
                contains_marked,
                MAX(priority) AS max_priority
            FROM v_orchard_shard_scan_ranges
            GROUP BY
                shard_index,
                start_position,
                end_position_exclusive,
                subtree_start_height,
                subtree_end_height,
                contains_marked;",
        )?;

        // Treat the current best-known chain tip height as the height to use for Orchard
        // initialization, bounded below by NU5 activation.
        if let Some(orchard_init_height) = scan_queue_extrema(transaction)?.and_then(|r| {
            self.params
                .activation_height(NetworkUpgrade::Nu5)
                .map(|orchard_activation| std::cmp::max(orchard_activation, *r.end()))
        }) {
            // If a scan range exists that contains the Orchard init height, split it in two at the
            // init height.
            if let Some((start, end, range_priority)) = transaction
                .query_row_and_then(
                    "SELECT block_range_start, block_range_end, priority
                     FROM scan_queue
                     WHERE block_range_start <= :orchard_init_height
                     AND block_range_end > :orchard_init_height",
                    named_params![":orchard_init_height": u32::from(orchard_init_height)],
                    |row| {
                        let start = BlockHeight::from(row.get::<_, u32>(0)?);
                        let end = BlockHeight::from(row.get::<_, u32>(1)?);
                        let range_priority: i64 = row.get(2)?;
                        Ok((start, end, range_priority))
                    },
                )
                .optional()?
            {
                transaction.execute(
                    "DELETE from scan_queue WHERE block_range_start = :start",
                    named_params![":start": u32::from(start)],
                )?;
                if start < orchard_init_height {
                    // Rewrite the start of the scan range to be exactly what it was prior to the
                    // change.
                    transaction.execute(
                        "INSERT INTO scan_queue (block_range_start, block_range_end, priority)
                     VALUES (:block_range_start, :block_range_end, :priority)",
                        named_params![
                            ":block_range_start": u32::from(start),
                            ":block_range_end": u32::from(orchard_init_height),
                            ":priority": range_priority,
                        ],
                    )?;
                }
                // Rewrite the remainder of the range to have at least priority `Historic`
                transaction.execute(
                    "INSERT INTO scan_queue (block_range_start, block_range_end, priority)
                     VALUES (:block_range_start, :block_range_end, :priority)",
                    named_params![
                        ":block_range_start": u32::from(orchard_init_height),
                        ":block_range_end": u32::from(end),
                        ":priority":
                            std::cmp::max(range_priority, priority_code(&ScanPriority::Historic)),
                    ],
                )?;
                // Rewrite any scanned ranges above the end of the first Orchard
                // range to have at least priority `Historic`
                transaction.execute(
                    "UPDATE scan_queue SET priority = :historic
                     WHERE :block_range_start >= :orchard_initial_range_end
                     AND priority < :historic",
                    named_params![
                        ":historic": priority_code(&ScanPriority::Historic),
                        ":orchard_initial_range_end": u32::from(end),
                    ],
                )?;
            }
        }

        Ok(())
    }

    fn down(&self, _transaction: &rusqlite::Transaction) -> Result<(), WalletMigrationError> {
        Err(WalletMigrationError::CannotRevert(MIGRATION_ID))
    }
}
