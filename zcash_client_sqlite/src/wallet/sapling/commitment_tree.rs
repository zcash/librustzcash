use either::Either;
use rusqlite::{self, named_params, OptionalExtension};
use std::{
    collections::BTreeSet,
    io::{self, Cursor},
    marker::PhantomData,
};

use incrementalmerkletree::{Address, Level, Position};
use shardtree::{Checkpoint, LocatedPrunableTree, PrunableTree, ShardStore, TreeState};

use zcash_primitives::{consensus::BlockHeight, merkle_tree::HashSer};

use crate::serialization::{read_shard, write_shard_v1};

pub struct SqliteShardStore<C, H, const SHARD_HEIGHT: u8> {
    pub(crate) conn: C,
    _hash_type: PhantomData<H>,
}

impl<C, H, const SHARD_HEIGHT: u8> SqliteShardStore<C, H, SHARD_HEIGHT> {
    const SHARD_ROOT_LEVEL: Level = Level::new(SHARD_HEIGHT);

    pub(crate) fn from_connection(conn: C) -> Result<Self, rusqlite::Error> {
        Ok(SqliteShardStore {
            conn,
            _hash_type: PhantomData,
        })
    }
}

impl<'conn, 'a: 'conn, H: HashSer, const SHARD_HEIGHT: u8> ShardStore
    for SqliteShardStore<&'a rusqlite::Transaction<'conn>, H, SHARD_HEIGHT>
{
    type H = H;
    type CheckpointId = BlockHeight;
    type Error = Either<io::Error, rusqlite::Error>;

    fn get_shard(
        &self,
        shard_root: Address,
    ) -> Result<Option<LocatedPrunableTree<Self::H>>, Self::Error> {
        get_shard(self.conn, shard_root)
    }

    fn last_shard(&self) -> Result<Option<LocatedPrunableTree<Self::H>>, Self::Error> {
        last_shard(self.conn, Self::SHARD_ROOT_LEVEL)
    }

    fn put_shard(&mut self, subtree: LocatedPrunableTree<Self::H>) -> Result<(), Self::Error> {
        put_shard(self.conn, subtree)
    }

    fn get_shard_roots(&self) -> Result<Vec<Address>, Self::Error> {
        get_shard_roots(self.conn, Self::SHARD_ROOT_LEVEL)
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
        min_checkpoint_id(self.conn)
    }

    fn max_checkpoint_id(&self) -> Result<Option<Self::CheckpointId>, Self::Error> {
        max_checkpoint_id(self.conn)
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
        checkpoint_depth: usize,
    ) -> Result<Option<(Self::CheckpointId, Checkpoint)>, Self::Error> {
        get_checkpoint_at_depth(self.conn, checkpoint_depth)
    }

    fn get_checkpoint(
        &self,
        checkpoint_id: &Self::CheckpointId,
    ) -> Result<Option<Checkpoint>, Self::Error> {
        get_checkpoint(self.conn, *checkpoint_id)
    }

    fn with_checkpoints<F>(&mut self, limit: usize, callback: F) -> Result<(), Self::Error>
    where
        F: FnMut(&Self::CheckpointId, &Checkpoint) -> Result<(), Self::Error>,
    {
        with_checkpoints(self.conn, limit, callback)
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

impl<H: HashSer, const SHARD_HEIGHT: u8> ShardStore
    for SqliteShardStore<rusqlite::Connection, H, SHARD_HEIGHT>
{
    type H = H;
    type CheckpointId = BlockHeight;
    type Error = Either<io::Error, rusqlite::Error>;

    fn get_shard(
        &self,
        shard_root: Address,
    ) -> Result<Option<LocatedPrunableTree<Self::H>>, Self::Error> {
        get_shard(&self.conn, shard_root)
    }

    fn last_shard(&self) -> Result<Option<LocatedPrunableTree<Self::H>>, Self::Error> {
        last_shard(&self.conn, Self::SHARD_ROOT_LEVEL)
    }

    fn put_shard(&mut self, subtree: LocatedPrunableTree<Self::H>) -> Result<(), Self::Error> {
        let tx = self.conn.transaction().map_err(Either::Right)?;
        put_shard(&tx, subtree)?;
        tx.commit().map_err(Either::Right)?;
        Ok(())
    }

    fn get_shard_roots(&self) -> Result<Vec<Address>, Self::Error> {
        get_shard_roots(&self.conn, Self::SHARD_ROOT_LEVEL)
    }

    fn truncate(&mut self, from: Address) -> Result<(), Self::Error> {
        truncate(&self.conn, from)
    }

    fn get_cap(&self) -> Result<PrunableTree<Self::H>, Self::Error> {
        get_cap(&self.conn)
    }

    fn put_cap(&mut self, cap: PrunableTree<Self::H>) -> Result<(), Self::Error> {
        put_cap(&self.conn, cap)
    }

    fn min_checkpoint_id(&self) -> Result<Option<Self::CheckpointId>, Self::Error> {
        min_checkpoint_id(&self.conn)
    }

    fn max_checkpoint_id(&self) -> Result<Option<Self::CheckpointId>, Self::Error> {
        max_checkpoint_id(&self.conn)
    }

    fn add_checkpoint(
        &mut self,
        checkpoint_id: Self::CheckpointId,
        checkpoint: Checkpoint,
    ) -> Result<(), Self::Error> {
        let tx = self.conn.transaction().map_err(Either::Right)?;
        add_checkpoint(&tx, checkpoint_id, checkpoint)?;
        tx.commit().map_err(Either::Right)
    }

    fn checkpoint_count(&self) -> Result<usize, Self::Error> {
        checkpoint_count(&self.conn)
    }

    fn get_checkpoint_at_depth(
        &self,
        checkpoint_depth: usize,
    ) -> Result<Option<(Self::CheckpointId, Checkpoint)>, Self::Error> {
        get_checkpoint_at_depth(&self.conn, checkpoint_depth)
    }

    fn get_checkpoint(
        &self,
        checkpoint_id: &Self::CheckpointId,
    ) -> Result<Option<Checkpoint>, Self::Error> {
        get_checkpoint(&self.conn, *checkpoint_id)
    }

    fn with_checkpoints<F>(&mut self, limit: usize, callback: F) -> Result<(), Self::Error>
    where
        F: FnMut(&Self::CheckpointId, &Checkpoint) -> Result<(), Self::Error>,
    {
        let tx = self.conn.transaction().map_err(Either::Right)?;
        with_checkpoints(&tx, limit, callback)?;
        tx.commit().map_err(Either::Right)
    }

    fn update_checkpoint_with<F>(
        &mut self,
        checkpoint_id: &Self::CheckpointId,
        update: F,
    ) -> Result<bool, Self::Error>
    where
        F: Fn(&mut Checkpoint) -> Result<(), Self::Error>,
    {
        let tx = self.conn.transaction().map_err(Either::Right)?;
        let result = update_checkpoint_with(&tx, *checkpoint_id, update)?;
        tx.commit().map_err(Either::Right)?;
        Ok(result)
    }

    fn remove_checkpoint(&mut self, checkpoint_id: &Self::CheckpointId) -> Result<(), Self::Error> {
        let tx = self.conn.transaction().map_err(Either::Right)?;
        remove_checkpoint(&tx, *checkpoint_id)?;
        tx.commit().map_err(Either::Right)
    }

    fn truncate_checkpoints(
        &mut self,
        checkpoint_id: &Self::CheckpointId,
    ) -> Result<(), Self::Error> {
        let tx = self.conn.transaction().map_err(Either::Right)?;
        truncate_checkpoints(&tx, *checkpoint_id)?;
        tx.commit().map_err(Either::Right)
    }
}

type Error = Either<io::Error, rusqlite::Error>;

pub(crate) fn get_shard<H: HashSer>(
    conn: &rusqlite::Connection,
    shard_root: Address,
) -> Result<Option<LocatedPrunableTree<H>>, Error> {
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

pub(crate) fn last_shard<H: HashSer>(
    conn: &rusqlite::Connection,
    shard_root_level: Level,
) -> Result<Option<LocatedPrunableTree<H>>, Error> {
    conn.query_row(
        "SELECT shard_index, shard_data
                 FROM sapling_tree_shards
                 ORDER BY shard_index DESC
                 LIMIT 1",
        [],
        |row| {
            let shard_index: u64 = row.get(0)?;
            let shard_data: Vec<u8> = row.get(1)?;
            Ok((shard_index, shard_data))
        },
    )
    .optional()
    .map_err(Either::Right)?
    .map(|(shard_index, shard_data)| {
        let shard_root = Address::from_parts(shard_root_level, shard_index);
        let shard_tree = read_shard(&mut Cursor::new(shard_data)).map_err(Either::Left)?;
        Ok(LocatedPrunableTree::from_parts(shard_root, shard_tree))
    })
    .transpose()
}

pub(crate) fn put_shard<H: HashSer>(
    conn: &rusqlite::Transaction<'_>,
    subtree: LocatedPrunableTree<H>,
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

    let mut stmt_put_shard = conn
        .prepare_cached(
            "INSERT INTO sapling_tree_shards (shard_index, root_hash, shard_data)
             VALUES (:shard_index, :root_hash, :shard_data)
             ON CONFLICT (shard_index) DO UPDATE
             SET root_hash = :root_hash,
             shard_data = :shard_data",
        )
        .map_err(Either::Right)?;

    stmt_put_shard
        .execute(named_params![
            ":shard_index": subtree.root_addr().index(),
            ":root_hash": subtree_root_hash,
            ":shard_data": subtree_data
        ])
        .map_err(Either::Right)?;

    Ok(())
}

pub(crate) fn get_shard_roots(
    conn: &rusqlite::Connection,
    shard_root_level: Level,
) -> Result<Vec<Address>, Error> {
    let mut stmt = conn
        .prepare("SELECT shard_index FROM sapling_tree_shards ORDER BY shard_index")
        .map_err(Either::Right)?;
    let mut rows = stmt.query([]).map_err(Either::Right)?;

    let mut res = vec![];
    while let Some(row) = rows.next().map_err(Either::Right)? {
        res.push(Address::from_parts(
            shard_root_level,
            row.get(0).map_err(Either::Right)?,
        ));
    }
    Ok(res)
}

pub(crate) fn truncate(conn: &rusqlite::Connection, from: Address) -> Result<(), Error> {
    conn.execute(
        "DELETE FROM sapling_tree_shards WHERE shard_index >= ?",
        [from.index()],
    )
    .map_err(Either::Right)
    .map(|_| ())
}

pub(crate) fn get_cap<H: HashSer>(conn: &rusqlite::Connection) -> Result<PrunableTree<H>, Error> {
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

pub(crate) fn put_cap<H: HashSer>(
    conn: &rusqlite::Connection,
    cap: PrunableTree<H>,
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

pub(crate) fn min_checkpoint_id(conn: &rusqlite::Connection) -> Result<Option<BlockHeight>, Error> {
    conn.query_row(
        "SELECT MIN(checkpoint_id) FROM sapling_tree_checkpoints",
        [],
        |row| {
            row.get::<_, Option<u32>>(0)
                .map(|opt| opt.map(BlockHeight::from))
        },
    )
    .map_err(Either::Right)
}

pub(crate) fn max_checkpoint_id(conn: &rusqlite::Connection) -> Result<Option<BlockHeight>, Error> {
    conn.query_row(
        "SELECT MAX(checkpoint_id) FROM sapling_tree_checkpoints",
        [],
        |row| {
            row.get::<_, Option<u32>>(0)
                .map(|opt| opt.map(BlockHeight::from))
        },
    )
    .map_err(Either::Right)
}

pub(crate) fn add_checkpoint(
    conn: &rusqlite::Transaction<'_>,
    checkpoint_id: BlockHeight,
    checkpoint: Checkpoint,
) -> Result<(), Error> {
    let mut stmt_insert_checkpoint = conn
        .prepare_cached(
            "INSERT INTO sapling_tree_checkpoints (checkpoint_id, position)
             VALUES (:checkpoint_id, :position)",
        )
        .map_err(Either::Right)?;

    stmt_insert_checkpoint
        .execute(named_params![
            ":checkpoint_id": u32::from(checkpoint_id),
            ":position": checkpoint.position().map(u64::from)
        ])
        .map_err(Either::Right)?;

    let mut stmt_insert_mark_removed = conn.prepare_cached(
        "INSERT INTO sapling_tree_checkpoint_marks_removed (checkpoint_id, mark_removed_position)
         VALUES (:checkpoint_id, :position)",
    ).map_err(Either::Right)?;

    for pos in checkpoint.marks_removed() {
        stmt_insert_mark_removed
            .execute(named_params![
                ":checkpoint_id": u32::from(checkpoint_id),
                ":position": u64::from(*pos)
            ])
            .map_err(Either::Right)?;
    }

    Ok(())
}

pub(crate) fn checkpoint_count(conn: &rusqlite::Connection) -> Result<usize, Error> {
    conn.query_row("SELECT COUNT(*) FROM sapling_tree_checkpoints", [], |row| {
        row.get::<_, usize>(0)
    })
    .map_err(Either::Right)
}

pub(crate) fn get_checkpoint(
    conn: &rusqlite::Connection,
    checkpoint_id: BlockHeight,
) -> Result<Option<Checkpoint>, Error> {
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

    checkpoint_position
        .map(|pos_opt| {
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

            Ok(Checkpoint::from_parts(
                pos_opt.map_or(TreeState::Empty, TreeState::AtPosition),
                marks_removed,
            ))
        })
        .transpose()
}

pub(crate) fn get_checkpoint_at_depth(
    conn: &rusqlite::Connection,
    checkpoint_depth: usize,
) -> Result<Option<(BlockHeight, Checkpoint)>, Error> {
    if checkpoint_depth == 0 {
        return Ok(None);
    }

    let checkpoint_parts = conn
        .query_row(
            "SELECT checkpoint_id, position
            FROM sapling_tree_checkpoints
            ORDER BY checkpoint_id DESC
            LIMIT 1
            OFFSET :offset",
            named_params![":offset": checkpoint_depth - 1],
            |row| {
                let checkpoint_id: u32 = row.get(0)?;
                let position: Option<u64> = row.get(1)?;
                Ok((
                    BlockHeight::from(checkpoint_id),
                    position.map(Position::from),
                ))
            },
        )
        .optional()
        .map_err(Either::Right)?;

    checkpoint_parts
        .map(|(checkpoint_id, pos_opt)| {
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

            Ok((
                checkpoint_id,
                Checkpoint::from_parts(
                    pos_opt.map_or(TreeState::Empty, TreeState::AtPosition),
                    marks_removed,
                ),
            ))
        })
        .transpose()
}

pub(crate) fn with_checkpoints<F>(
    conn: &rusqlite::Transaction<'_>,
    limit: usize,
    mut callback: F,
) -> Result<(), Error>
where
    F: FnMut(&BlockHeight, &Checkpoint) -> Result<(), Error>,
{
    let mut stmt_get_checkpoints = conn
        .prepare_cached(
            "SELECT checkpoint_id, position
            FROM sapling_tree_checkpoints
            LIMIT :limit",
        )
        .map_err(Either::Right)?;

    let mut stmt_get_checkpoint_marks_removed = conn
        .prepare_cached(
            "SELECT mark_removed_position
            FROM sapling_tree_checkpoint_marks_removed
            WHERE checkpoint_id = :checkpoint_id",
        )
        .map_err(Either::Right)?;

    let mut rows = stmt_get_checkpoints
        .query(named_params![":limit": limit])
        .map_err(Either::Right)?;

    while let Some(row) = rows.next().map_err(Either::Right)? {
        let checkpoint_id = row.get::<_, u32>(0).map_err(Either::Right)?;
        let tree_state = row
            .get::<_, Option<u64>>(1)
            .map(|opt| opt.map_or_else(|| TreeState::Empty, |p| TreeState::AtPosition(p.into())))
            .map_err(Either::Right)?;

        let mut mark_removed_rows = stmt_get_checkpoint_marks_removed
            .query(named_params![":checkpoint_id": checkpoint_id])
            .map_err(Either::Right)?;
        let mut marks_removed = BTreeSet::new();
        while let Some(mr_row) = mark_removed_rows.next().map_err(Either::Right)? {
            let mark_removed_position = mr_row
                .get::<_, u64>(0)
                .map(Position::from)
                .map_err(Either::Right)?;
            marks_removed.insert(mark_removed_position);
        }

        callback(
            &BlockHeight::from(checkpoint_id),
            &Checkpoint::from_parts(tree_state, marks_removed),
        )?
    }

    Ok(())
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
    // sapling_tree_checkpoints is constructed with `ON DELETE CASCADE`
    let mut stmt_delete_checkpoint = conn
        .prepare_cached(
            "DELETE FROM sapling_tree_checkpoints
             WHERE checkpoint_id = :checkpoint_id",
        )
        .map_err(Either::Right)?;

    stmt_delete_checkpoint
        .execute(named_params![":checkpoint_id": u32::from(checkpoint_id),])
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

#[cfg(test)]
mod tests {
    use tempfile::NamedTempFile;

    use incrementalmerkletree::testing::{
        check_append, check_checkpoint_rewind, check_remove_mark, check_rewind_remove_mark,
        check_root_hashes, check_witness_consistency, check_witnesses,
    };
    use shardtree::ShardTree;

    use super::SqliteShardStore;
    use crate::{tests, wallet::init::init_wallet_db, WalletDb};

    fn new_tree(m: usize) -> ShardTree<SqliteShardStore<rusqlite::Connection, String, 3>, 4, 3> {
        let data_file = NamedTempFile::new().unwrap();
        let mut db_data = WalletDb::for_path(data_file.path(), tests::network()).unwrap();
        data_file.keep().unwrap();

        init_wallet_db(&mut db_data, None).unwrap();
        let store = SqliteShardStore::<_, String, 3>::from_connection(db_data.conn).unwrap();
        ShardTree::new(store, m)
    }

    #[test]
    fn append() {
        check_append(new_tree);
    }

    #[test]
    fn root_hashes() {
        check_root_hashes(new_tree);
    }

    #[test]
    fn witnesses() {
        check_witnesses(new_tree);
    }

    #[test]
    fn witness_consistency() {
        check_witness_consistency(new_tree);
    }

    #[test]
    fn checkpoint_rewind() {
        check_checkpoint_rewind(new_tree);
    }

    #[test]
    fn remove_mark() {
        check_remove_mark(new_tree);
    }

    #[test]
    fn rewind_remove_mark() {
        check_rewind_remove_mark(new_tree);
    }
}
