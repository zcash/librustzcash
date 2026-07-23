//! Test-support utilities exposed under the `test-dependencies` feature: an in-memory
//! [`db::TestDbFactory`] / [`db::TestDb`] wallet for the `zcash_client_backend` testing framework, a
//! [`BlockCache`] compact-block source, and the [`highest_rooted_orchard_checkpoint`] commitment-tree
//! helper. Consumed by this crate's own tests and, through the feature, by downstream crates' tests.

use prost::Message;
use rusqlite::params;
use tempfile::NamedTempFile;

use zcash_client_backend::{
    data_api::testing::{CacheInsertionResult, NoteCommitments, TestCache},
    proto::compact_formats::CompactBlock,
};
use zcash_protocol::TxId;
use zcash_protocol::consensus::BlockHeight;

use crate::{chain::init::init_cache_database, error::SqliteClientError};

use super::BlockDb;

#[cfg(all(test, feature = "unstable"))]
use {
    crate::{
        FsBlockDb, FsBlockDbError,
        chain::{BlockMeta, init::init_blockmeta_db},
    },
    std::fs::File,
    tempfile::TempDir,
};

pub mod db;
// The shielded-pool testers are used only by this crate's own in-crate tests, not by external
// consumers of the exposed harness, so they stay test-only and keep their heavier test-only
// dependencies (proptest, incrementalmerkletree-testing) out of the `test-dependencies` build.
#[cfg(test)]
pub(crate) mod pool;

/// An in-memory compact-block cache backed by a temporary [`BlockDb`], implementing the
/// `zcash_client_backend` testing framework's [`TestCache`].
pub struct BlockCache {
    _cache_file: NamedTempFile,
    db_cache: BlockDb,
}

impl BlockCache {
    /// Creates an empty cache over a fresh temporary block database.
    pub fn new() -> Self {
        let cache_file = NamedTempFile::new().unwrap();
        let db_cache = BlockDb::for_path(cache_file.path()).unwrap();
        init_cache_database(&db_cache).unwrap();

        BlockCache {
            _cache_file: cache_file,
            db_cache,
        }
    }
}

impl Default for BlockCache {
    fn default() -> Self {
        Self::new()
    }
}

/// The result of inserting a compact block into a [`BlockCache`]: the block's transaction ids and
/// the note commitments it added.
pub struct BlockCacheInsertionResult {
    txids: Vec<TxId>,
    #[allow(dead_code)]
    note_commitments: NoteCommitments,
}

impl BlockCacheInsertionResult {
    #[allow(dead_code)]
    pub(crate) fn note_commitments(&self) -> &NoteCommitments {
        &self.note_commitments
    }
}

impl CacheInsertionResult for BlockCacheInsertionResult {
    fn txids(&self) -> &[TxId] {
        &self.txids[..]
    }
}

impl TestCache for BlockCache {
    type BsError = SqliteClientError;
    type BlockSource = BlockDb;
    type InsertResult = BlockCacheInsertionResult;

    fn block_source(&self) -> &Self::BlockSource {
        &self.db_cache
    }

    fn insert(&mut self, cb: &CompactBlock) -> Self::InsertResult {
        let cb_bytes = cb.encode_to_vec();
        let note_commitments = NoteCommitments::from_compact_block(cb);
        self.db_cache
            .0
            .execute(
                "INSERT INTO compactblocks (height, data) VALUES (?, ?)",
                params![u32::from(cb.height()), cb_bytes,],
            )
            .unwrap();

        BlockCacheInsertionResult {
            txids: cb.vtx.iter().map(|tx| tx.txid()).collect(),
            note_commitments,
        }
    }

    fn truncate_to_height(&mut self, height: zcash_protocol::consensus::BlockHeight) {
        self.db_cache
            .0
            .execute(
                "DELETE FROM compactblocks WHERE height > ?",
                params![u32::from(height)],
            )
            .unwrap();
    }
}

/// The highest checkpoint at or below `from` whose Orchard commitment-tree root is available, or
/// `None` if there is none at or below `from`. Right after scanning, the tip checkpoint is not yet
/// rooted, so a spend anchors to the newest settled checkpoint below it (every note mined at or
/// before that height is still witnessable there).
#[cfg(feature = "orchard")]
pub fn highest_rooted_orchard_checkpoint<W>(db: &mut W, from: BlockHeight) -> Option<BlockHeight>
where
    W: zcash_client_backend::data_api::WalletCommitmentTrees,
{
    use shardtree::error::ShardTreeError;
    use shardtree::store::ShardStore;
    use zcash_client_backend::data_api::WalletCommitmentTrees;

    db.with_orchard_tree_mut::<_, _, ShardTreeError<<W as WalletCommitmentTrees>::Error>>(|tree| {
        // Take the highest checkpoint id at or below `from` directly from the checkpoint set,
        // rather than probing the tree at every height down from `from`.
        let store = tree.store();
        let count = store.checkpoint_count().map_err(ShardTreeError::Storage)?;
        let mut highest: Option<BlockHeight> = None;
        store
            .for_each_checkpoint(count, |id, _| {
                if *id <= from {
                    highest = Some(highest.map_or(*id, |h| h.max(*id)));
                }
                Ok(())
            })
            .map_err(ShardTreeError::Storage)?;
        Ok(highest)
    })
    .expect("queries the Orchard tree")
}

#[cfg(all(test, feature = "unstable"))]
pub(crate) struct FsBlockCache {
    fsblockdb_root: TempDir,
    db_meta: FsBlockDb,
}

#[cfg(all(test, feature = "unstable"))]
impl FsBlockCache {
    pub(crate) fn new() -> Self {
        let fsblockdb_root = tempfile::tempdir().unwrap();
        let mut db_meta = FsBlockDb::for_path(&fsblockdb_root).unwrap();
        init_blockmeta_db(&mut db_meta).unwrap();

        FsBlockCache {
            fsblockdb_root,
            db_meta,
        }
    }
}

/// The result of inserting a compact block into an [`FsBlockCache`]: the block's transaction ids and
/// its on-disk block metadata.
#[cfg(all(test, feature = "unstable"))]
#[derive(Debug)]
pub struct FsBlockCacheInsertionResult {
    txids: Vec<TxId>,
    pub(crate) block_meta: BlockMeta,
}

#[cfg(all(test, feature = "unstable"))]
impl CacheInsertionResult for FsBlockCacheInsertionResult {
    fn txids(&self) -> &[TxId] {
        &self.txids[..]
    }
}

#[cfg(all(test, feature = "unstable"))]
impl TestCache for FsBlockCache {
    type BsError = FsBlockDbError;
    type BlockSource = FsBlockDb;
    type InsertResult = FsBlockCacheInsertionResult;

    fn block_source(&self) -> &Self::BlockSource {
        &self.db_meta
    }

    fn insert(&mut self, cb: &CompactBlock) -> Self::InsertResult {
        use std::io::Write;

        let txids = cb.vtx.iter().map(|tx| tx.txid()).collect();
        let block_meta = BlockMeta {
            height: cb.height(),
            block_hash: cb.hash(),
            block_time: cb.time,
            sapling_outputs_count: cb.vtx.iter().map(|tx| tx.outputs.len() as u32).sum(),
            orchard_actions_count: cb.vtx.iter().map(|tx| tx.actions.len() as u32).sum(),
        };

        let blocks_dir = self.fsblockdb_root.as_ref().join("blocks");
        let block_path = block_meta.block_file_path(&blocks_dir);

        File::create(block_path)
            .unwrap()
            .write_all(&cb.encode_to_vec())
            .unwrap();

        FsBlockCacheInsertionResult { txids, block_meta }
    }

    fn truncate_to_height(&mut self, height: zcash_protocol::consensus::BlockHeight) {
        self.db_meta.truncate_to_height(height).unwrap()
    }
}
