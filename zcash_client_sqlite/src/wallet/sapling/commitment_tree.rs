use either::Either;
use incrementalmerkletree::Address;
use rusqlite::{self, named_params, OptionalExtension};
use shardtree::{Checkpoint, LocatedPrunableTree, PrunableTree, ShardStore};
use std::io::{self, Cursor};

use zcash_primitives::{consensus::BlockHeight, sapling};

use crate::serialization::read_shard;

pub struct WalletDbSaplingShardStore<'conn, 'a> {
    pub(crate) conn: &'a rusqlite::Transaction<'conn>,
}

impl<'conn, 'a> WalletDbSaplingShardStore<'conn, 'a> {
    pub(crate) fn from_connection(
        conn: &'a rusqlite::Transaction<'conn>,
    ) -> Result<Self, rusqlite::Error> {
        Ok(WalletDbSaplingShardStore { conn })
    }
}

impl<'conn, 'a: 'conn> ShardStore for WalletDbSaplingShardStore<'conn, 'a> {
    type H = sapling::Node;
    type CheckpointId = BlockHeight;
    type Error = Either<io::Error, rusqlite::Error>;

    fn get_shard(
        &self,
        shard_root: Address,
    ) -> Result<Option<LocatedPrunableTree<Self::H>>, Self::Error> {
        get_shard(self.conn, shard_root)
    }

    fn last_shard(&self) -> Result<Option<LocatedPrunableTree<Self::H>>, Self::Error> {
        // SELECT shard_data FROM sapling_tree ORDER BY shard_index DESC LIMIT 1
        todo!()
    }

    fn put_shard(&mut self, _subtree: LocatedPrunableTree<Self::H>) -> Result<(), Self::Error> {
        todo!()
    }

    fn get_shard_roots(&self) -> Result<Vec<Address>, Self::Error> {
        // SELECT
        todo!()
    }

    fn truncate(&mut self, _from: Address) -> Result<(), Self::Error> {
        todo!()
    }

    fn get_cap(&self) -> Result<PrunableTree<Self::H>, Self::Error> {
        todo!()
    }

    fn put_cap(&mut self, _cap: PrunableTree<Self::H>) -> Result<(), Self::Error> {
        todo!()
    }

    fn min_checkpoint_id(&self) -> Result<Option<Self::CheckpointId>, Self::Error> {
        todo!()
    }

    fn max_checkpoint_id(&self) -> Result<Option<Self::CheckpointId>, Self::Error> {
        todo!()
    }

    fn add_checkpoint(
        &mut self,
        _checkpoint_id: Self::CheckpointId,
        _checkpoint: Checkpoint,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn checkpoint_count(&self) -> Result<usize, Self::Error> {
        todo!()
    }

    fn get_checkpoint_at_depth(
        &self,
        _checkpoint_depth: usize,
    ) -> Result<Option<(Self::CheckpointId, Checkpoint)>, Self::Error> {
        todo!()
    }

    fn get_checkpoint(
        &self,
        _checkpoint_id: &Self::CheckpointId,
    ) -> Result<Option<Checkpoint>, Self::Error> {
        todo!()
    }

    fn with_checkpoints<F>(&mut self, _limit: usize, _callback: F) -> Result<(), Self::Error>
    where
        F: FnMut(&Self::CheckpointId, &Checkpoint) -> Result<(), Self::Error>,
    {
        todo!()
    }

    fn update_checkpoint_with<F>(
        &mut self,
        _checkpoint_id: &Self::CheckpointId,
        _update: F,
    ) -> Result<bool, Self::Error>
    where
        F: Fn(&mut Checkpoint) -> Result<(), Self::Error>,
    {
        todo!()
    }

    fn remove_checkpoint(
        &mut self,
        _checkpoint_id: &Self::CheckpointId,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn truncate_checkpoints(
        &mut self,
        _checkpoint_id: &Self::CheckpointId,
    ) -> Result<(), Self::Error> {
        todo!()
    }
}

pub(crate) fn get_shard(
    conn: &rusqlite::Connection,
    shard_root: Address,
) -> Result<Option<LocatedPrunableTree<sapling::Node>>, Either<io::Error, rusqlite::Error>> {
    conn.query_row(
        "SELECT shard_data 
         FROM sapling_tree_shards
         WHERE shard_index = :shard_index",
        named_params![":shard_index": shard_root.index()],
        |row| row.get::<_, Vec<u8>>(0),
    )
    .optional()
    .map_err(Either::Right)?
    .map(|shard_data| {
        let shard_tree = read_shard(&mut Cursor::new(shard_data)).map_err(Either::Left)?;
        Ok(LocatedPrunableTree::from_parts(shard_root, shard_tree))
    })
    .transpose()
}
