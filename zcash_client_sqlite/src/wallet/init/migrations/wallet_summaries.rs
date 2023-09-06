//! This migration adds views and database changes required to provide accurate wallet summaries.

use std::collections::HashSet;

use schemer_rusqlite::RusqliteMigration;
use uuid::Uuid;

use crate::wallet::init::WalletMigrationError;

use super::v_sapling_shard_unscanned_ranges;

pub(super) const MIGRATION_ID: Uuid = Uuid::from_u128(0xc5bf7f71_2297_41ff_89e1_75e07c4e8838);

pub(super) struct Migration;

impl schemer::Migration for Migration {
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }

    fn dependencies(&self) -> HashSet<Uuid> {
        [v_sapling_shard_unscanned_ranges::MIGRATION_ID]
            .into_iter()
            .collect()
    }

    fn description(&self) -> &'static str {
        "Adds views and data required to produce accurate wallet summaries."
    }
}

impl RusqliteMigration for Migration {
    type Error = WalletMigrationError;

    fn up(&self, transaction: &rusqlite::Transaction) -> Result<(), Self::Error> {
        // Add columns to the `blocks` table to track the number of scanned outputs in each block.
        // We use the note commitment tree size information that we have in contiguous regions to
        // populate this data, but we don't make any attempt to handle the boundary cases because
        // we're just using this information for the progress metric, which can be a bit sloppy.
        transaction.execute_batch(
            "ALTER TABLE blocks ADD COLUMN sapling_output_count INTEGER;
            ALTER TABLE blocks ADD COLUMN orchard_action_count INTEGER;",
        )?;

        transaction.execute_batch(
            // set the number of outputs everywhere that we have sequential blocks
            "CREATE TEMPORARY TABLE block_deltas AS
                SELECT
                    cur.height AS height,
                    (cur.sapling_commitment_tree_size - prev.sapling_commitment_tree_size) AS sapling_delta,
                    (cur.orchard_commitment_tree_size - prev.orchard_commitment_tree_size) AS orchard_delta
                FROM blocks cur
                INNER JOIN blocks prev
                ON cur.height = prev.height + 1;

            UPDATE blocks
            SET sapling_output_count = block_deltas.sapling_delta,
                orchard_action_count = block_deltas.orchard_delta
            FROM block_deltas
            WHERE block_deltas.height = blocks.height;"
        )?;

        transaction.execute_batch(
            "CREATE VIEW v_sapling_shards_scan_state AS
            SELECT
                shard_index,
                start_position,
                end_position_exclusive,
                subtree_start_height,
                subtree_end_height,
                contains_marked,
                MAX(priority) AS max_priority
            FROM v_sapling_shard_scan_ranges
            GROUP BY
                shard_index,
                start_position,
                end_position_exclusive,
                subtree_start_height,
                subtree_end_height,
                contains_marked;",
        )?;

        Ok(())
    }

    fn down(&self, _transaction: &rusqlite::Transaction) -> Result<(), Self::Error> {
        panic!("This migration cannot be reverted.");
    }
}
