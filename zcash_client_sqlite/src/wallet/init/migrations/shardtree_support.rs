//! This migration adds tables to the wallet database that are needed to persist note commitment
//! tree data using the `shardtree` crate, and migrates existing witness data into these data
//! structures.

use std::collections::{BTreeSet, HashSet};

use incrementalmerkletree::Retention;
use rusqlite::{self, named_params, params};
use schemer;
use schemer_rusqlite::RusqliteMigration;
use shardtree::ShardTree;
use uuid::Uuid;

use zcash_client_backend::data_api::SAPLING_SHARD_HEIGHT;
use zcash_primitives::{
    consensus::BlockHeight,
    merkle_tree::{read_commitment_tree, read_incremental_witness},
    sapling,
};

use crate::{
    wallet::{
        commitment_tree::SqliteShardStore,
        init::{migrations::received_notes_nullable_nf, WalletMigrationError},
    },
    SAPLING_TABLES_PREFIX,
};

pub(super) const MIGRATION_ID: Uuid = Uuid::from_fields(
    0x7da6489d,
    0xe835,
    0x4657,
    b"\x8b\xe5\xf5\x12\xbc\xce\x6c\xbf",
);

pub(super) struct Migration;

impl schemer::Migration for Migration {
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

impl RusqliteMigration for Migration {
    type Error = WalletMigrationError;

    fn up(&self, transaction: &rusqlite::Transaction) -> Result<(), WalletMigrationError> {
        // Add commitment tree sizes to block metadata.
        transaction.execute_batch(
            "ALTER TABLE blocks ADD COLUMN sapling_commitment_tree_size INTEGER;
             ALTER TABLE blocks ADD COLUMN orchard_commitment_tree_size INTEGER;
             ALTER TABLE sapling_received_notes ADD COLUMN commitment_tree_position INTEGER;",
        )?;

        // Add shard persistence
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
        transaction.execute_batch(
            "CREATE TABLE sapling_tree_checkpoints (
                checkpoint_id INTEGER PRIMARY KEY,
                position INTEGER
            );
            CREATE TABLE sapling_tree_checkpoint_marks_removed (
                checkpoint_id INTEGER NOT NULL,
                mark_removed_position INTEGER NOT NULL,
                FOREIGN KEY (checkpoint_id) REFERENCES sapling_tree_checkpoints(checkpoint_id)
                ON DELETE CASCADE
            );",
        )?;

        let shard_store =
            SqliteShardStore::<_, sapling::Node, SAPLING_SHARD_HEIGHT>::from_connection(
                transaction,
                SAPLING_TABLES_PREFIX,
            )?;
        let mut shard_tree: ShardTree<
            _,
            { sapling::NOTE_COMMITMENT_TREE_DEPTH },
            SAPLING_SHARD_HEIGHT,
        > = ShardTree::new(shard_store, 100);
        // Insert all the tree information that we can get from block-end commitment trees
        {
            let mut stmt_blocks = transaction.prepare("SELECT height, sapling_tree FROM blocks")?;
            let mut stmt_update_block_sapling_tree_size = transaction
                .prepare("UPDATE blocks SET sapling_commitment_tree_size = ? WHERE height = ?")?;

            let mut block_rows = stmt_blocks.query([])?;
            while let Some(row) = block_rows.next()? {
                let block_height: u32 = row.get(0)?;
                let sapling_tree_data: Vec<u8> = row.get(1)?;
                if sapling_tree_data == vec![0x00] {
                    continue;
                }

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

                stmt_update_block_sapling_tree_size
                    .execute(params![block_end_tree.size(), block_height])?;

                if let Some(nonempty_frontier) = block_end_tree.to_frontier().value() {
                    shard_tree.insert_frontier_nodes(
                        nonempty_frontier.clone(),
                        Retention::Checkpoint {
                            id: BlockHeight::from(block_height),
                            is_marked: false,
                        },
                    )?;
                }
            }
        }

        // Insert all the tree information that we can get from existing incremental witnesses
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

                shard_tree.insert_witness_nodes(witness, BlockHeight::from(block_height))?;
            }
        }

        Ok(())
    }

    fn down(&self, _transaction: &rusqlite::Transaction) -> Result<(), WalletMigrationError> {
        // TODO: something better than just panic?
        panic!("Cannot revert this migration.");
    }
}
