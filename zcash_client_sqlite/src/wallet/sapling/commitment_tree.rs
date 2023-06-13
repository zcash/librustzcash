use either::Either;

use incrementalmerkletree::{Address, Position};
use rusqlite::{self, named_params, Connection, OptionalExtension};
use shardtree::{Checkpoint, LocatedPrunableTree, PrunableTree, ShardStore, TreeState};

use std::{
    collections::BTreeSet,
    io::{self, Cursor},
    ops::Deref,
};

use zcash_primitives::{consensus::BlockHeight, merkle_tree::HashSer, sapling};

use crate::serialization::{read_shard, write_shard_v1};

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

    fn put_shard(&mut self, subtree: LocatedPrunableTree<Self::H>) -> Result<(), Self::Error> {
        put_shard(self.conn, subtree)
    }

    fn get_shard_roots(&self) -> Result<Vec<Address>, Self::Error> {
        // SELECT
        todo!()
    }

    fn truncate(&mut self, from: Address) -> Result<(), Self::Error> {
        truncate(self.conn, from)
    }

    fn get_cap(&self) -> Result<PrunableTree<Self::H>, Self::Error> {
        get_cap(self.conn)
    }

    fn put_cap(&mut self, cap: PrunableTree<Self::H>) -> Result<(), Self::Error> {
        put_cap(self.conn, cap)
    }

    fn min_checkpoint_id(&self) -> Result<Option<Self::CheckpointId>, Self::Error> {
        todo!()
    }

    fn max_checkpoint_id(&self) -> Result<Option<Self::CheckpointId>, Self::Error> {
        todo!()
    }

    fn add_checkpoint(
        &mut self,
        checkpoint_id: Self::CheckpointId,
        checkpoint: Checkpoint,
    ) -> Result<(), Self::Error> {
        add_checkpoint(self.conn, checkpoint_id, checkpoint)
    }

    fn checkpoint_count(&self) -> Result<usize, Self::Error> {
        checkpoint_count(self.conn)
    }

    fn get_checkpoint_at_depth(
        &self,
        _checkpoint_depth: usize,
    ) -> Result<Option<(Self::CheckpointId, Checkpoint)>, Self::Error> {
        todo!()
    }

    fn get_checkpoint(
        &self,
        checkpoint_id: &Self::CheckpointId,
    ) -> Result<Option<Checkpoint>, Self::Error> {
        get_checkpoint(self.conn, *checkpoint_id)
    }

    fn with_checkpoints<F>(&mut self, _limit: usize, _callback: F) -> Result<(), Self::Error>
    where
        F: FnMut(&Self::CheckpointId, &Checkpoint) -> Result<(), Self::Error>,
    {
        todo!()
    }

    fn update_checkpoint_with<F>(
        &mut self,
        checkpoint_id: &Self::CheckpointId,
        update: F,
    ) -> Result<bool, Self::Error>
    where
        F: Fn(&mut Checkpoint) -> Result<(), Self::Error>,
    {
        update_checkpoint_with(self.conn, *checkpoint_id, update)
    }

    fn remove_checkpoint(&mut self, checkpoint_id: &Self::CheckpointId) -> Result<(), Self::Error> {
        remove_checkpoint(self.conn, *checkpoint_id)
    }

    fn truncate_checkpoints(
        &mut self,
        checkpoint_id: &Self::CheckpointId,
    ) -> Result<(), Self::Error> {
        truncate_checkpoints(self.conn, *checkpoint_id)
    }
}

type Error = Either<io::Error, rusqlite::Error>;

pub(crate) fn get_shard(
    conn: &rusqlite::Connection,
    shard_root: Address,
) -> Result<Option<LocatedPrunableTree<sapling::Node>>, Error> {
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

pub(crate) fn put_shard(
    conn: &rusqlite::Connection,
    subtree: LocatedPrunableTree<sapling::Node>,
) -> Result<(), Error> {
    let subtree_root_hash = subtree
        .root()
        .annotation()
        .and_then(|ann| {
            ann.as_ref().map(|rc| {
                let mut root_hash = vec![];
                rc.write(&mut root_hash)?;
                Ok(root_hash)
            })
        })
        .transpose()
        .map_err(Either::Left)?;

    let mut subtree_data = vec![];
    write_shard_v1(&mut subtree_data, subtree.root()).map_err(Either::Left)?;

    conn.prepare_cached(
        "INSERT INTO sapling_tree_shards (shard_index, root_hash, shard_data)
             VALUES (:shard_index, :root_hash, :shard_data)
             ON CONFLICT (shard_index) DO UPDATE
             SET root_hash = :root_hash,
             shard_data = :shard_data",
    )
    .and_then(|mut stmt_put_shard| {
        stmt_put_shard.execute(named_params![
            ":shard_index": subtree.root_addr().index(),
            ":root_hash": subtree_root_hash,
            ":shard_data": subtree_data
        ])
    })
    .map_err(Either::Right)?;

    Ok(())
}

pub(crate) fn truncate(conn: &rusqlite::Transaction<'_>, from: Address) -> Result<(), Error> {
    conn.execute(
        "DELETE FROM sapling_tree_shards WHERE shard_index >= ?",
        [from.index()],
    )
    .map_err(Either::Right)
    .map(|_| ())
}

pub(crate) fn get_cap(conn: &rusqlite::Connection) -> Result<PrunableTree<sapling::Node>, Error> {
    conn.query_row("SELECT cap_data FROM sapling_tree_cap", [], |row| {
        row.get::<_, Vec<u8>>(0)
    })
    .optional()
    .map_err(Either::Right)?
    .map_or_else(
        || Ok(PrunableTree::empty()),
        |cap_data| read_shard(&mut Cursor::new(cap_data)).map_err(Either::Left),
    )
}

pub(crate) fn put_cap(
    conn: &rusqlite::Transaction<'_>,
    cap: PrunableTree<sapling::Node>,
) -> Result<(), Error> {
    let mut stmt = conn
        .prepare_cached(
            "INSERT INTO sapling_tree_cap (cap_id, cap_data)
                 VALUES (0, :cap_data)
                 ON CONFLICT (cap_id) DO UPDATE
                 SET cap_data = :cap_data",
        )
        .map_err(Either::Right)?;

    let mut cap_data = vec![];
    write_shard_v1(&mut cap_data, &cap).map_err(Either::Left)?;
    stmt.execute([cap_data]).map_err(Either::Right)?;

    Ok(())
}

pub(crate) fn add_checkpoint(
    conn: &rusqlite::Transaction<'_>,
    checkpoint_id: BlockHeight,
    checkpoint: Checkpoint,
) -> Result<(), Error> {
    conn.prepare_cached(
        "INSERT INTO sapling_tree_checkpoints (checkpoint_id, position)
                 VALUES (:checkpoint_id, :position)",
    )
    .and_then(|mut stmt_insert_checkpoint| {
        stmt_insert_checkpoint.execute(named_params![
            ":checkpoint_id": u32::from(checkpoint_id),
            ":position": checkpoint.position().map(u64::from)
        ])
    })
    .map_err(Either::Right)?;

    Ok(())
}

pub(crate) fn checkpoint_count(conn: &rusqlite::Connection) -> Result<usize, Error> {
    conn.query_row("SELECT COUNT(*) FROM sapling_tree_checkpoints", [], |row| {
        row.get::<_, usize>(0)
    })
    .map_err(Either::Right)
}

pub(crate) fn get_checkpoint<C: Deref<Target = Connection>>(
    conn: &C,
    checkpoint_id: BlockHeight,
) -> Result<Option<Checkpoint>, Either<io::Error, rusqlite::Error>> {
    let checkpoint_position = conn
        .query_row(
            "SELECT position
                FROM sapling_tree_checkpoints
                WHERE checkpoint_id = ?",
            [u32::from(checkpoint_id)],
            |row| {
                row.get::<_, Option<u64>>(0)
                    .map(|opt| opt.map(Position::from))
            },
        )
        .optional()
        .map_err(Either::Right)?;

    let mut marks_removed = BTreeSet::new();
    let mut stmt = conn
        .prepare_cached(
            "SELECT mark_removed_position
                FROM sapling_tree_checkpoint_marks_removed
                WHERE checkpoint_id = ?",
        )
        .map_err(Either::Right)?;
    let mut mark_removed_rows = stmt
        .query([u32::from(checkpoint_id)])
        .map_err(Either::Right)?;

    while let Some(row) = mark_removed_rows.next().map_err(Either::Right)? {
        marks_removed.insert(
            row.get::<_, u64>(0)
                .map(Position::from)
                .map_err(Either::Right)?,
        );
    }

    Ok(checkpoint_position.map(|pos_opt| {
        Checkpoint::from_parts(
            pos_opt.map_or(TreeState::Empty, TreeState::AtPosition),
            marks_removed,
        )
    }))
}

pub(crate) fn update_checkpoint_with<F>(
    conn: &rusqlite::Transaction<'_>,
    checkpoint_id: BlockHeight,
    update: F,
) -> Result<bool, Error>
where
    F: Fn(&mut Checkpoint) -> Result<(), Error>,
{
    if let Some(mut c) = get_checkpoint(conn, checkpoint_id)? {
        update(&mut c)?;
        remove_checkpoint(conn, checkpoint_id)?;
        add_checkpoint(conn, checkpoint_id, c)?;
        Ok(true)
    } else {
        Ok(false)
    }
}

pub(crate) fn remove_checkpoint(
    conn: &rusqlite::Transaction<'_>,
    checkpoint_id: BlockHeight,
) -> Result<(), Error> {
    conn.execute(
        "DELETE FROM sapling_tree_checkpoints WHERE checkpoint_id = ?",
        [u32::from(checkpoint_id)],
    )
    .map_err(Either::Right)?;

    Ok(())
}

pub(crate) fn truncate_checkpoints(
    conn: &rusqlite::Transaction<'_>,
    checkpoint_id: BlockHeight,
) -> Result<(), Error> {
    conn.execute(
        "DELETE FROM sapling_tree_checkpoints WHERE checkpoint_id >= ?",
        [u32::from(checkpoint_id)],
    )
    .map_err(Either::Right)?;

    conn.execute(
        "DELETE FROM sapling_tree_checkpoint_marks_removed WHERE checkpoint_id >= ?",
        [u32::from(checkpoint_id)],
    )
    .map_err(Either::Right)?;
    Ok(())
}
