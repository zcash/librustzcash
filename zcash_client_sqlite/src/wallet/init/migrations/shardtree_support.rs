//! This migration adds tables to the wallet database that are needed to persist note commitment
//! tree data using the `shardtree` crate, and migrates existing witness data into these data
//! structures.

use std::collections::{BTreeSet, HashSet};

use incrementalmerkletree::Retention;
use rusqlite::{self, named_params, params};
use schemer;
use schemer_rusqlite::RusqliteMigration;
use shardtree::{error::ShardTreeError, store::caching::CachingShardStore, ShardTree};
use tracing::{debug, trace};
use uuid::Uuid;

use zcash_client_backend::data_api::{
    scanning::{ScanPriority, ScanRange},
    SAPLING_SHARD_HEIGHT,
};
use zcash_primitives::{
    consensus::{self, BlockHeight, NetworkUpgrade},
    merkle_tree::{read_commitment_tree, read_incremental_witness},
    sapling,
};

use crate::{
    wallet::{
        block_height_extrema,
        commitment_tree::SqliteShardStore,
        init::{migrations::received_notes_nullable_nf, WalletMigrationError},
        scanning::insert_queue_entries,
    },
    PRUNING_DEPTH, SAPLING_TABLES_PREFIX,
};

pub(super) const MIGRATION_ID: Uuid = Uuid::from_fields(
    0x7da6489d,
    0xe835,
    0x4657,
    b"\x8b\xe5\xf5\x12\xbc\xce\x6c\xbf",
);

pub(super) struct Migration<P> {
    pub(super) params: P,
}

impl<P> schemer::Migration for Migration<P> {
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }

    fn dependencies(&self) -> HashSet<Uuid> {
        [received_notes_nullable_nf::MIGRATION_ID]
            .into_iter()
            .collect()
    }

    fn description(&self) -> &'static str {
        "Add support for receiving storage of note commitment tree data using the `shardtree` crate."
    }
}

impl<P: consensus::Parameters> RusqliteMigration for Migration<P> {
    type Error = WalletMigrationError;

    fn up(&self, transaction: &rusqlite::Transaction) -> Result<(), WalletMigrationError> {
        // Add commitment tree sizes to block metadata.
        debug!("Adding new columns");
        transaction.execute_batch(
            "ALTER TABLE blocks ADD COLUMN sapling_commitment_tree_size INTEGER;
             ALTER TABLE blocks ADD COLUMN orchard_commitment_tree_size INTEGER;
             ALTER TABLE sapling_received_notes ADD COLUMN commitment_tree_position INTEGER;",
        )?;

        // Add shard persistence
        debug!("Creating tables for shard persistence");
        transaction.execute_batch(
            "CREATE TABLE sapling_tree_shards (
                shard_index INTEGER PRIMARY KEY,
                subtree_end_height INTEGER,
                root_hash BLOB,
                shard_data BLOB,
                contains_marked INTEGER,
                CONSTRAINT root_unique UNIQUE (root_hash)
            );
            CREATE TABLE sapling_tree_cap (
                -- cap_id exists only to be able to take advantage of `ON CONFLICT`
                -- upsert functionality; the table will only ever contain one row
                cap_id INTEGER PRIMARY KEY,
                cap_data BLOB NOT NULL
            );",
        )?;

        // Add checkpoint persistence
        debug!("Creating tables for checkpoint persistence");
        transaction.execute_batch(
            "CREATE TABLE sapling_tree_checkpoints (
                checkpoint_id INTEGER PRIMARY KEY,
                position INTEGER
            );
            CREATE TABLE sapling_tree_checkpoint_marks_removed (
                checkpoint_id INTEGER NOT NULL,
                mark_removed_position INTEGER NOT NULL,
                FOREIGN KEY (checkpoint_id) REFERENCES sapling_tree_checkpoints(checkpoint_id)
                ON DELETE CASCADE,
                CONSTRAINT spend_position_unique UNIQUE (checkpoint_id, mark_removed_position)
            );",
        )?;

        let block_height_extrema = block_height_extrema(transaction)?;

        let shard_store =
            SqliteShardStore::<_, sapling::Node, SAPLING_SHARD_HEIGHT>::from_connection(
                transaction,
                SAPLING_TABLES_PREFIX,
            )?;
        let shard_store = CachingShardStore::load(shard_store).map_err(ShardTreeError::Storage)?;
        let mut shard_tree: ShardTree<
            _,
            { sapling::NOTE_COMMITMENT_TREE_DEPTH },
            SAPLING_SHARD_HEIGHT,
        > = ShardTree::new(shard_store, PRUNING_DEPTH.try_into().unwrap());
        // Insert all the tree information that we can get from block-end commitment trees
        {
            let mut stmt_blocks = transaction.prepare("SELECT height, sapling_tree FROM blocks")?;
            let mut stmt_update_block_sapling_tree_size = transaction
                .prepare("UPDATE blocks SET sapling_commitment_tree_size = ? WHERE height = ?")?;

            let mut block_rows = stmt_blocks.query([])?;
            while let Some(row) = block_rows.next()? {
                let block_height: u32 = row.get(0)?;
                let sapling_tree_data: Vec<u8> = row.get(1)?;

                let block_end_tree = read_commitment_tree::<
                    sapling::Node,
                    _,
                    { sapling::NOTE_COMMITMENT_TREE_DEPTH },
                >(&sapling_tree_data[..])
                .map_err(|e| {
                    rusqlite::Error::FromSqlConversionFailure(
                        sapling_tree_data.len(),
                        rusqlite::types::Type::Blob,
                        Box::new(e),
                    )
                })?;

                if block_height % 1000 == 0 {
                    debug!(height = block_height, "Migrating tree data to shardtree");
                }
                trace!(
                    height = block_height,
                    size = block_end_tree.size(),
                    "Storing Sapling commitment tree size"
                );
                stmt_update_block_sapling_tree_size
                    .execute(params![block_end_tree.size(), block_height])?;

                // We only need to load frontiers into the ShardTree that are close enough
                // to the wallet's known chain tip to fill `PRUNING_DEPTH` checkpoints, so
                // that ShardTree's witness generation will be able to correctly handle
                // anchor depths. Loading frontiers further back than this doesn't add any
                // useful nodes to the ShardTree (as we don't support rollbacks beyond
                // `PRUNING_DEPTH`, and we won't be finding notes in earlier blocks), and
                // hurts performance (as frontier importing has a significant Merkle tree
                // hashing cost).
                if let Some((nonempty_frontier, (_, latest_height))) = block_end_tree
                    .to_frontier()
                    .value()
                    .zip(block_height_extrema)
                {
                    let block_height = BlockHeight::from(block_height);
                    if block_height + PRUNING_DEPTH >= latest_height {
                        trace!(
                            height = u32::from(block_height),
                            frontier = ?nonempty_frontier,
                            "Inserting frontier nodes",
                        );
                        shard_tree
                            .insert_frontier_nodes(
                                nonempty_frontier.clone(),
                                Retention::Checkpoint {
                                    id: block_height,
                                    is_marked: false,
                                },
                            )
                            .map_err(|e| match e {
                                ShardTreeError::Query(e) => ShardTreeError::Query(e),
                                ShardTreeError::Insert(e) => ShardTreeError::Insert(e),
                                ShardTreeError::Storage(_) => unreachable!(),
                            })?
                    }
                }
            }
        }

        // Insert all the tree information that we can get from existing incremental witnesses
        debug!("Migrating witness data to shardtree");
        {
            let mut stmt_blocks =
                transaction.prepare("SELECT note, block, witness FROM sapling_witnesses")?;
            let mut stmt_set_note_position = transaction.prepare(
                "UPDATE sapling_received_notes
                SET commitment_tree_position = :position
                WHERE id_note = :note_id",
            )?;
            let mut updated_note_positions = BTreeSet::new();
            let mut rows = stmt_blocks.query([])?;
            while let Some(row) = rows.next()? {
                let note_id: i64 = row.get(0)?;
                let block_height: u32 = row.get(1)?;
                let row_data: Vec<u8> = row.get(2)?;
                let witness = read_incremental_witness::<
                    sapling::Node,
                    _,
                    { sapling::NOTE_COMMITMENT_TREE_DEPTH },
                >(&row_data[..])
                .map_err(|e| {
                    rusqlite::Error::FromSqlConversionFailure(
                        row_data.len(),
                        rusqlite::types::Type::Blob,
                        Box::new(e),
                    )
                })?;

                let witnessed_position = witness.witnessed_position();
                if !updated_note_positions.contains(&witnessed_position) {
                    stmt_set_note_position.execute(named_params![
                        ":note_id": note_id,
                        ":position": u64::from(witnessed_position)
                    ])?;
                    updated_note_positions.insert(witnessed_position);
                }

                shard_tree
                    .insert_witness_nodes(witness, BlockHeight::from(block_height))
                    .map_err(|e| match e {
                        ShardTreeError::Query(e) => ShardTreeError::Query(e),
                        ShardTreeError::Insert(e) => ShardTreeError::Insert(e),
                        ShardTreeError::Storage(_) => unreachable!(),
                    })?;
            }
        }

        shard_tree
            .into_store()
            .flush()
            .map_err(ShardTreeError::Storage)?;

        // Establish the scan queue & wallet history table.
        // block_range_end is exclusive.
        debug!("Creating table for scan queue");
        transaction.execute_batch(
            "CREATE TABLE scan_queue (
                block_range_start INTEGER NOT NULL,
                block_range_end INTEGER NOT NULL,
                priority INTEGER NOT NULL,
                CONSTRAINT range_start_uniq UNIQUE (block_range_start),
                CONSTRAINT range_end_uniq UNIQUE (block_range_end),
                CONSTRAINT range_bounds_order CHECK (
                    block_range_start < block_range_end
                )
            );",
        )?;

        if let Some((start, end)) = block_height_extrema {
            // `ScanRange` uses an exclusive upper bound.
            let chain_end = end + 1;
            let ignored_range =
                self.params
                    .activation_height(NetworkUpgrade::Sapling)
                    .map(|sapling_activation| {
                        let ignored_range_start = std::cmp::min(sapling_activation, start);
                        ScanRange::from_parts(ignored_range_start..start, ScanPriority::Ignored)
                    });
            let scanned_range = ScanRange::from_parts(start..chain_end, ScanPriority::Scanned);
            insert_queue_entries(
                transaction,
                ignored_range.iter().chain(Some(scanned_range).iter()),
            )?;
        }

        Ok(())
    }

    fn down(&self, _transaction: &rusqlite::Transaction) -> Result<(), WalletMigrationError> {
        // TODO: something better than just panic?
        panic!("Cannot revert this migration.");
    }
}
