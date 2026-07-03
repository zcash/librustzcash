//! This migration adds tables to the wallet database that are needed to persist Ironwood note
//! commitment tree data using the `shardtree` crate.

use std::collections::HashSet;

use rusqlite::{OptionalExtension, named_params};
use schemerz_rusqlite::RusqliteMigration;
use tracing::debug;
use uuid::Uuid;
use zcash_client_backend::data_api::scanning::ScanPriority;
use zcash_protocol::consensus::{self, BlockHeight, NetworkUpgrade};

use super::{orchard_shardtree, wallet_summaries};
use crate::wallet::{chain_tip_height, init::WalletMigrationError, scanning::priority_code};

pub(super) const MIGRATION_ID: Uuid = Uuid::from_u128(0x1f5420e3_f8a0_4afd_a9e5_e20fc6fae271);

// Depends on `orchard_shardtree` (the Ironwood tree tables mirror the Orchard ones) and on
// `wallet_summaries` (which adds the `blocks` output/action-count columns), so the Ironwood
// block-metadata columns append after all existing `blocks` columns.
const DEPENDENCIES: &[Uuid] = &[
    orchard_shardtree::MIGRATION_ID,
    wallet_summaries::MIGRATION_ID,
];

pub(super) struct Migration<P> {
    pub(super) params: P,
}

impl<P> schemerz::Migration<Uuid> for Migration<P> {
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }

    fn dependencies(&self) -> HashSet<Uuid> {
        DEPENDENCIES.iter().copied().collect()
    }

    fn description(&self) -> &'static str {
        "Add support for storage of Ironwood note commitment tree data using the `shardtree` crate."
    }
}

impl<P: consensus::Parameters> RusqliteMigration for Migration<P> {
    type Error = WalletMigrationError;

    fn up(&self, transaction: &rusqlite::Transaction) -> Result<(), WalletMigrationError> {
        // Add Ironwood block metadata, mirroring the Sapling and Orchard columns.
        debug!("Adding Ironwood block metadata columns");
        transaction.execute_batch(
            "ALTER TABLE blocks ADD COLUMN ironwood_commitment_tree_size INTEGER;
             ALTER TABLE blocks ADD COLUMN ironwood_action_count INTEGER;",
        )?;

        // Add shard persistence
        debug!("Creating tables for Ironwood shard persistence");
        transaction.execute_batch(
            "CREATE TABLE ironwood_tree_shards (
                shard_index INTEGER PRIMARY KEY,
                subtree_end_height INTEGER,
                root_hash BLOB,
                shard_data BLOB,
                contains_marked INTEGER,
                CONSTRAINT root_unique UNIQUE (root_hash)
            );
            CREATE TABLE ironwood_tree_cap (
                -- cap_id exists only to be able to take advantage of `ON CONFLICT`
                -- upsert functionality; the table will only ever contain one row
                cap_id INTEGER PRIMARY KEY,
                cap_data BLOB NOT NULL
            );",
        )?;

        // Add checkpoint persistence
        debug!("Creating tables for Ironwood checkpoint persistence");
        transaction.execute_batch(
            "CREATE TABLE ironwood_tree_checkpoints (
                checkpoint_id INTEGER PRIMARY KEY,
                position INTEGER
            );
            CREATE TABLE ironwood_tree_checkpoint_marks_removed (
                checkpoint_id INTEGER NOT NULL,
                mark_removed_position INTEGER NOT NULL,
                FOREIGN KEY (checkpoint_id) REFERENCES ironwood_tree_checkpoints(checkpoint_id)
                ON DELETE CASCADE,
                CONSTRAINT spend_position_unique UNIQUE (checkpoint_id, mark_removed_position)
            );",
        )?;

        transaction.execute_batch(&format!(
            "CREATE VIEW v_ironwood_shard_scan_ranges AS
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
                FROM ironwood_tree_shards shard
                LEFT OUTER JOIN ironwood_tree_shards prev_shard
                    ON shard.shard_index = prev_shard.shard_index + 1
                -- Join with scan ranges that overlap with the subtree's involved blocks.
                INNER JOIN scan_queue ON (
                    subtree_start_height < scan_queue.block_range_end AND
                    (
                        scan_queue.block_range_start <= shard.subtree_end_height OR
                        shard.subtree_end_height IS NULL
                    )
                )",
            16, // Ironwood shares the Orchard shard height, ORCHARD_SHARD_HEIGHT.
            16, // Ironwood shares the Orchard shard height, ORCHARD_SHARD_HEIGHT.
            // NU6.3 might not be active in regtest mode.
            self.params
                .activation_height(NetworkUpgrade::Nu6_3)
                .map(|h| u32::from(h).to_string())
                .as_deref()
                .unwrap_or("NULL"),
        ))?;

        transaction.execute_batch(&format!(
            "CREATE VIEW v_ironwood_shard_unscanned_ranges AS
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
                FROM v_ironwood_shard_scan_ranges
                INNER JOIN wallet_birthday
                WHERE priority > {}
                AND block_range_end > wallet_birthday.height;",
            priority_code(&ScanPriority::Scanned),
        ))?;

        transaction.execute_batch(
            "CREATE VIEW v_ironwood_shards_scan_state AS
            SELECT
                shard_index,
                start_position,
                end_position_exclusive,
                subtree_start_height,
                subtree_end_height,
                contains_marked,
                MAX(priority) AS max_priority
            FROM v_ironwood_shard_scan_ranges
            GROUP BY
                shard_index,
                start_position,
                end_position_exclusive,
                subtree_start_height,
                subtree_end_height,
                contains_marked;",
        )?;

        // If this wallet has already scanned NU6.3-era blocks, requeue from NU6.3 activation so
        // those historical blocks are rescanned with Ironwood tree state enabled.
        if let Some(ironwood_init_height) = chain_tip_height(transaction)?.and_then(|h| {
            self.params
                .activation_height(NetworkUpgrade::Nu6_3)
                .filter(|ironwood_activation| h >= *ironwood_activation)
        }) {
            // If a scan range exists that contains the Ironwood init height, split it in two at the
            // init height.
            if let Some((start, end, range_priority)) = transaction
                .query_row_and_then(
                    "SELECT block_range_start, block_range_end, priority
                     FROM scan_queue
                     WHERE block_range_start <= :ironwood_init_height
                     AND block_range_end > :ironwood_init_height",
                    named_params![":ironwood_init_height": u32::from(ironwood_init_height)],
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
                if start < ironwood_init_height {
                    // Rewrite the start of the scan range to be exactly what it was prior to the
                    // change.
                    transaction.execute(
                        "INSERT INTO scan_queue (block_range_start, block_range_end, priority)
                         VALUES (:block_range_start, :block_range_end, :priority)",
                        named_params![
                            ":block_range_start": u32::from(start),
                            ":block_range_end": u32::from(ironwood_init_height),
                            ":priority": range_priority,
                        ],
                    )?;
                }
                // Rewrite the remainder of the range to have at least priority `Historic`
                transaction.execute(
                    "INSERT INTO scan_queue (block_range_start, block_range_end, priority)
                     VALUES (:block_range_start, :block_range_end, :priority)",
                    named_params![
                        ":block_range_start": u32::from(ironwood_init_height),
                        ":block_range_end": u32::from(end),
                        ":priority":
                            std::cmp::max(range_priority, priority_code(&ScanPriority::Historic)),
                    ],
                )?;
                // Rewrite any scanned ranges above the end of the first Ironwood
                // range to have at least priority `Historic`
                transaction.execute(
                    "UPDATE scan_queue SET priority = :historic
                     WHERE block_range_start >= :ironwood_initial_range_end
                     AND priority < :historic",
                    named_params![
                        ":historic": priority_code(&ScanPriority::Historic),
                        ":ironwood_initial_range_end": u32::from(end),
                    ],
                )?;
            } else {
                // No scan range straddles the init height; just bump the priority of everything at
                // or above it to at least `Historic`.
                transaction.execute(
                    "UPDATE scan_queue SET priority = :historic
                     WHERE block_range_start >= :ironwood_init_height
                     AND priority < :historic",
                    named_params![
                        ":historic": priority_code(&ScanPriority::Historic),
                        ":ironwood_init_height": u32::from(ironwood_init_height),
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

#[cfg(test)]
mod tests {
    use rusqlite::Connection;
    use schemerz_rusqlite::RusqliteMigration;
    use zcash_client_backend::data_api::scanning::ScanPriority;
    use zcash_protocol::{consensus::BlockHeight, local_consensus::LocalNetwork};

    use crate::wallet::init::migrations::tests::test_migrate;
    use crate::wallet::scanning::priority_code;

    #[test]
    fn migrate() {
        test_migrate(&[super::MIGRATION_ID]);
    }

    #[test]
    fn migrate_requeues_scanned_nu6_3_range_from_activation() {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE blocks (
                height INTEGER PRIMARY KEY,
                hash BLOB NOT NULL,
                time INTEGER NOT NULL,
                sapling_tree BLOB NOT NULL,
                sapling_commitment_tree_size INTEGER,
                orchard_commitment_tree_size INTEGER,
                sapling_output_count INTEGER,
                orchard_action_count INTEGER
            );
            CREATE TABLE accounts (birthday_height INTEGER);
            CREATE TABLE scan_queue (
                block_range_start INTEGER NOT NULL,
                block_range_end INTEGER NOT NULL,
                priority INTEGER NOT NULL,
                CONSTRAINT range_start_uniq UNIQUE (block_range_start),
                CONSTRAINT range_end_uniq UNIQUE (block_range_end),
                CONSTRAINT range_bounds_order CHECK (
                    block_range_start < block_range_end
                )
            );",
        )
        .unwrap();

        let activation = BlockHeight::from_u32(100_000);
        conn.execute(
            "INSERT INTO scan_queue (block_range_start, block_range_end, priority)
             VALUES (:start, :end, :priority)",
            rusqlite::named_params![
                ":start": u32::from(activation - 10),
                ":end": u32::from(activation + 11),
                ":priority": priority_code(&ScanPriority::Scanned),
            ],
        )
        .unwrap();

        let tx = conn.transaction().unwrap();
        super::Migration {
            params: LocalNetwork {
                overwinter: Some(BlockHeight::from_u32(1)),
                sapling: Some(activation),
                blossom: Some(activation),
                heartwood: Some(activation),
                canopy: Some(activation),
                nu5: Some(activation),
                nu6: None,
                nu6_1: None,
                nu6_2: None,
                nu6_3: Some(activation),
                #[cfg(zcash_unstable = "nu7")]
                nu7: None,
            },
        }
        .up(&tx)
        .unwrap();

        let ranges = tx
            .prepare(
                "SELECT block_range_start, block_range_end, priority
                 FROM scan_queue
                 ORDER BY block_range_start",
            )
            .unwrap()
            .query_map([], |row| {
                Ok((
                    row.get::<_, u32>(0)?,
                    row.get::<_, u32>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            })
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        assert_eq!(
            ranges,
            vec![
                (
                    u32::from(activation - 10),
                    u32::from(activation),
                    priority_code(&ScanPriority::Scanned),
                ),
                (
                    u32::from(activation),
                    u32::from(activation + 11),
                    priority_code(&ScanPriority::Historic),
                ),
            ]
        );
    }
}
