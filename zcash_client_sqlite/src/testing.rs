use prost::Message;
use rusqlite::params;
use tempfile::NamedTempFile;

use zcash_client_backend::{
    data_api::testing::{CacheInsertionResult, NoteCommitments, TestCache},
    proto::compact_formats::CompactBlock,
};
use zcash_protocol::TxId;

use crate::{chain::init::init_cache_database, error::SqliteClientError};

use super::BlockDb;

#[cfg(feature = "unstable")]
use {
    crate::{
        FsBlockDb, FsBlockDbError,
        chain::{BlockMeta, init::init_blockmeta_db},
    },
    std::fs::File,
    tempfile::TempDir,
};

pub(crate) mod db;
pub(crate) mod pool;

pub(crate) struct BlockCache {
    _cache_file: NamedTempFile,
    db_cache: BlockDb,
}

impl BlockCache {
    pub(crate) fn new() -> Self {
        let cache_file = NamedTempFile::new().unwrap();
        let db_cache = BlockDb::for_path(cache_file.path()).unwrap();
        init_cache_database(&db_cache).unwrap();

        BlockCache {
            _cache_file: cache_file,
            db_cache,
        }
    }
}

pub struct BlockCacheInsertionResult {
    txids: Vec<TxId>,
    note_commitments: NoteCommitments,
}

impl BlockCacheInsertionResult {
    pub fn note_commitments(&self) -> &NoteCommitments {
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

#[cfg(feature = "unstable")]
pub(crate) struct FsBlockCache {
    fsblockdb_root: TempDir,
    db_meta: FsBlockDb,
}

#[cfg(feature = "unstable")]
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

#[cfg(feature = "unstable")]
#[derive(Debug)]
pub struct FsBlockCacheInsertionResult {
    txids: Vec<TxId>,
    pub(crate) block_meta: BlockMeta,
}

#[cfg(feature = "unstable")]
impl CacheInsertionResult for FsBlockCacheInsertionResult {
    fn txids(&self) -> &[TxId] {
        &self.txids[..]
    }
}

#[cfg(feature = "unstable")]
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
