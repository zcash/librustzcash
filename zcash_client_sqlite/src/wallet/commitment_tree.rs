use either::Either;
use rusqlite::{self, named_params, OptionalExtension};
use std::{
    collections::BTreeSet,
    io::{self, Cursor},
    marker::PhantomData,
    sync::Arc,
};
use zcash_client_backend::data_api::chain::CommitmentTreeRoot;

use incrementalmerkletree::{Address, Hashable, Level, Position, Retention};
use shardtree::{
    Checkpoint, LocatedPrunableTree, LocatedTree, PrunableTree, RetentionFlags, ShardStore,
    ShardTreeError, TreeState,
};

use zcash_primitives::{consensus::BlockHeight, merkle_tree::HashSer};

use crate::serialization::{read_shard, write_shard};

pub struct SqliteShardStore<C, H, const SHARD_HEIGHT: u8> {
    pub(crate) conn: C,
    table_prefix: &'static str,
    _hash_type: PhantomData<H>,
}

impl<C, H, const SHARD_HEIGHT: u8> SqliteShardStore<C, H, SHARD_HEIGHT> {
    const SHARD_ROOT_LEVEL: Level = Level::new(SHARD_HEIGHT);

    pub(crate) fn from_connection(
        conn: C,
        table_prefix: &'static str,
    ) -> Result<Self, rusqlite::Error> {
        Ok(SqliteShardStore {
            conn,
            table_prefix,
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
        get_shard(self.conn, self.table_prefix, shard_root)
    }

    fn last_shard(&self) -> Result<Option<LocatedPrunableTree<Self::H>>, Self::Error> {
        last_shard(self.conn, self.table_prefix, Self::SHARD_ROOT_LEVEL)
    }

    fn put_shard(&mut self, subtree: LocatedPrunableTree<Self::H>) -> Result<(), Self::Error> {
        put_shard(self.conn, self.table_prefix, subtree)
    }

    fn get_shard_roots(&self) -> Result<Vec<Address>, Self::Error> {
        get_shard_roots(self.conn, self.table_prefix, Self::SHARD_ROOT_LEVEL)
    }

    fn truncate(&mut self, from: Address) -> Result<(), Self::Error> {
        truncate(self.conn, self.table_prefix, from)
    }

    fn get_cap(&self) -> Result<PrunableTree<Self::H>, Self::Error> {
        get_cap(self.conn, self.table_prefix)
    }

    fn put_cap(&mut self, cap: PrunableTree<Self::H>) -> Result<(), Self::Error> {
        put_cap(self.conn, self.table_prefix, cap)
    }

    fn min_checkpoint_id(&self) -> Result<Option<Self::CheckpointId>, Self::Error> {
        min_checkpoint_id(self.conn, self.table_prefix)
    }

    fn max_checkpoint_id(&self) -> Result<Option<Self::CheckpointId>, Self::Error> {
        max_checkpoint_id(self.conn, self.table_prefix)
    }

    fn add_checkpoint(
        &mut self,
        checkpoint_id: Self::CheckpointId,
        checkpoint: Checkpoint,
    ) -> Result<(), Self::Error> {
        add_checkpoint(self.conn, self.table_prefix, checkpoint_id, checkpoint)
    }

    fn checkpoint_count(&self) -> Result<usize, Self::Error> {
        checkpoint_count(self.conn, self.table_prefix)
    }

    fn get_checkpoint_at_depth(
        &self,
        checkpoint_depth: usize,
    ) -> Result<Option<(Self::CheckpointId, Checkpoint)>, Self::Error> {
        get_checkpoint_at_depth(self.conn, self.table_prefix, checkpoint_depth)
    }

    fn get_checkpoint(
        &self,
        checkpoint_id: &Self::CheckpointId,
    ) -> Result<Option<Checkpoint>, Self::Error> {
        get_checkpoint(self.conn, self.table_prefix, *checkpoint_id)
    }

    fn with_checkpoints<F>(&mut self, limit: usize, callback: F) -> Result<(), Self::Error>
    where
        F: FnMut(&Self::CheckpointId, &Checkpoint) -> Result<(), Self::Error>,
    {
        with_checkpoints(self.conn, self.table_prefix, limit, callback)
    }

    fn update_checkpoint_with<F>(
        &mut self,
        checkpoint_id: &Self::CheckpointId,
        update: F,
    ) -> Result<bool, Self::Error>
    where
        F: Fn(&mut Checkpoint) -> Result<(), Self::Error>,
    {
        update_checkpoint_with(self.conn, self.table_prefix, *checkpoint_id, update)
    }

    fn remove_checkpoint(&mut self, checkpoint_id: &Self::CheckpointId) -> Result<(), Self::Error> {
        remove_checkpoint(self.conn, self.table_prefix, *checkpoint_id)
    }

    fn truncate_checkpoints(
        &mut self,
        checkpoint_id: &Self::CheckpointId,
    ) -> Result<(), Self::Error> {
        truncate_checkpoints(self.conn, self.table_prefix, *checkpoint_id)
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
        get_shard(&self.conn, self.table_prefix, shard_root)
    }

    fn last_shard(&self) -> Result<Option<LocatedPrunableTree<Self::H>>, Self::Error> {
        last_shard(&self.conn, self.table_prefix, Self::SHARD_ROOT_LEVEL)
    }

    fn put_shard(&mut self, subtree: LocatedPrunableTree<Self::H>) -> Result<(), Self::Error> {
        let tx = self.conn.transaction().map_err(Either::Right)?;
        put_shard(&tx, self.table_prefix, subtree)?;
        tx.commit().map_err(Either::Right)?;
        Ok(())
    }

    fn get_shard_roots(&self) -> Result<Vec<Address>, Self::Error> {
        get_shard_roots(&self.conn, self.table_prefix, Self::SHARD_ROOT_LEVEL)
    }

    fn truncate(&mut self, from: Address) -> Result<(), Self::Error> {
        truncate(&self.conn, self.table_prefix, from)
    }

    fn get_cap(&self) -> Result<PrunableTree<Self::H>, Self::Error> {
        get_cap(&self.conn, self.table_prefix)
    }

    fn put_cap(&mut self, cap: PrunableTree<Self::H>) -> Result<(), Self::Error> {
        put_cap(&self.conn, self.table_prefix, cap)
    }

    fn min_checkpoint_id(&self) -> Result<Option<Self::CheckpointId>, Self::Error> {
        min_checkpoint_id(&self.conn, self.table_prefix)
    }

    fn max_checkpoint_id(&self) -> Result<Option<Self::CheckpointId>, Self::Error> {
        max_checkpoint_id(&self.conn, self.table_prefix)
    }

    fn add_checkpoint(
        &mut self,
        checkpoint_id: Self::CheckpointId,
        checkpoint: Checkpoint,
    ) -> Result<(), Self::Error> {
        let tx = self.conn.transaction().map_err(Either::Right)?;
        add_checkpoint(&tx, self.table_prefix, checkpoint_id, checkpoint)?;
        tx.commit().map_err(Either::Right)
    }

    fn checkpoint_count(&self) -> Result<usize, Self::Error> {
        checkpoint_count(&self.conn, self.table_prefix)
    }

    fn get_checkpoint_at_depth(
        &self,
        checkpoint_depth: usize,
    ) -> Result<Option<(Self::CheckpointId, Checkpoint)>, Self::Error> {
        get_checkpoint_at_depth(&self.conn, self.table_prefix, checkpoint_depth)
    }

    fn get_checkpoint(
        &self,
        checkpoint_id: &Self::CheckpointId,
    ) -> Result<Option<Checkpoint>, Self::Error> {
        get_checkpoint(&self.conn, self.table_prefix, *checkpoint_id)
    }

    fn with_checkpoints<F>(&mut self, limit: usize, callback: F) -> Result<(), Self::Error>
    where
        F: FnMut(&Self::CheckpointId, &Checkpoint) -> Result<(), Self::Error>,
    {
        let tx = self.conn.transaction().map_err(Either::Right)?;
        with_checkpoints(&tx, self.table_prefix, limit, callback)?;
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
        let result = update_checkpoint_with(&tx, self.table_prefix, *checkpoint_id, update)?;
        tx.commit().map_err(Either::Right)?;
        Ok(result)
    }

    fn remove_checkpoint(&mut self, checkpoint_id: &Self::CheckpointId) -> Result<(), Self::Error> {
        let tx = self.conn.transaction().map_err(Either::Right)?;
        remove_checkpoint(&tx, self.table_prefix, *checkpoint_id)?;
        tx.commit().map_err(Either::Right)
    }

    fn truncate_checkpoints(
        &mut self,
        checkpoint_id: &Self::CheckpointId,
    ) -> Result<(), Self::Error> {
        let tx = self.conn.transaction().map_err(Either::Right)?;
        truncate_checkpoints(&tx, self.table_prefix, *checkpoint_id)?;
        tx.commit().map_err(Either::Right)
    }
}

type Error = Either<io::Error, rusqlite::Error>;

pub(crate) fn get_shard<H: HashSer>(
    conn: &rusqlite::Connection,
    table_prefix: &'static str,
    shard_root_addr: Address,
) -> Result<Option<LocatedPrunableTree<H>>, Error> {
    conn.query_row(
        &format!(
            "SELECT shard_data, root_hash
             FROM {}_tree_shards
             WHERE shard_index = :shard_index",
            table_prefix
        ),
        named_params![":shard_index": shard_root_addr.index()],
        |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Option<Vec<u8>>>(1)?)),
    )
    .optional()
    .map_err(Either::Right)?
    .map(|(shard_data, root_hash)| {
        let shard_tree = read_shard(&mut Cursor::new(shard_data)).map_err(Either::Left)?;
        let located_tree = LocatedPrunableTree::from_parts(shard_root_addr, shard_tree);
        if let Some(root_hash_data) = root_hash {
            let root_hash = H::read(Cursor::new(root_hash_data)).map_err(Either::Left)?;
            Ok(located_tree.reannotate_root(Some(Arc::new(root_hash))))
        } else {
            Ok(located_tree)
        }
    })
    .transpose()
}

pub(crate) fn last_shard<H: HashSer>(
    conn: &rusqlite::Connection,
    table_prefix: &'static str,
    shard_root_level: Level,
) -> Result<Option<LocatedPrunableTree<H>>, Error> {
    conn.query_row(
        &format!(
            "SELECT shard_index, shard_data
             FROM {}_tree_shards
             ORDER BY shard_index DESC
             LIMIT 1",
            table_prefix
        ),
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
    table_prefix: &'static str,
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
    write_shard(&mut subtree_data, subtree.root()).map_err(Either::Left)?;

    let mut stmt_put_shard = conn
        .prepare_cached(&format!(
            "INSERT INTO {}_tree_shards (shard_index, root_hash, shard_data)
             VALUES (:shard_index, :root_hash, :shard_data)
             ON CONFLICT (shard_index) DO UPDATE
             SET root_hash = :root_hash,
             shard_data = :shard_data",
            table_prefix
        ))
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
    table_prefix: &'static str,
    shard_root_level: Level,
) -> Result<Vec<Address>, Error> {
    let mut stmt = conn
        .prepare(&format!(
            "SELECT shard_index FROM {}_tree_shards ORDER BY shard_index",
            table_prefix
        ))
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

pub(crate) fn truncate(
    conn: &rusqlite::Connection,
    table_prefix: &'static str,
    from: Address,
) -> Result<(), Error> {
    conn.execute(
        &format!(
            "DELETE FROM {}_tree_shards WHERE shard_index >= ?",
            table_prefix
        ),
        [from.index()],
    )
    .map_err(Either::Right)
    .map(|_| ())
}

pub(crate) fn get_cap<H: HashSer>(
    conn: &rusqlite::Connection,
    table_prefix: &'static str,
) -> Result<PrunableTree<H>, Error> {
    conn.query_row(
        &format!("SELECT cap_data FROM {}_tree_cap", table_prefix),
        [],
        |row| row.get::<_, Vec<u8>>(0),
    )
    .optional()
    .map_err(Either::Right)?
    .map_or_else(
        || Ok(PrunableTree::empty()),
        |cap_data| read_shard(&mut Cursor::new(cap_data)).map_err(Either::Left),
    )
}

pub(crate) fn put_cap<H: HashSer>(
    conn: &rusqlite::Connection,
    table_prefix: &'static str,
    cap: PrunableTree<H>,
) -> Result<(), Error> {
    let mut stmt = conn
        .prepare_cached(&format!(
            "INSERT INTO {}_tree_cap (cap_id, cap_data)
             VALUES (0, :cap_data)
             ON CONFLICT (cap_id) DO UPDATE
             SET cap_data = :cap_data",
            table_prefix
        ))
        .map_err(Either::Right)?;

    let mut cap_data = vec![];
    write_shard(&mut cap_data, &cap).map_err(Either::Left)?;
    stmt.execute([cap_data]).map_err(Either::Right)?;

    Ok(())
}

pub(crate) fn min_checkpoint_id(
    conn: &rusqlite::Connection,
    table_prefix: &'static str,
) -> Result<Option<BlockHeight>, Error> {
    conn.query_row(
        &format!(
            "SELECT MIN(checkpoint_id) FROM {}_tree_checkpoints",
            table_prefix
        ),
        [],
        |row| {
            row.get::<_, Option<u32>>(0)
                .map(|opt| opt.map(BlockHeight::from))
        },
    )
    .map_err(Either::Right)
}

pub(crate) fn max_checkpoint_id(
    conn: &rusqlite::Connection,
    table_prefix: &'static str,
) -> Result<Option<BlockHeight>, Error> {
    conn.query_row(
        &format!(
            "SELECT MAX(checkpoint_id) FROM {}_tree_checkpoints",
            table_prefix
        ),
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
    table_prefix: &'static str,
    checkpoint_id: BlockHeight,
    checkpoint: Checkpoint,
) -> Result<(), Error> {
    let mut stmt_insert_checkpoint = conn
        .prepare_cached(&format!(
            "INSERT INTO {}_tree_checkpoints (checkpoint_id, position)
             VALUES (:checkpoint_id, :position)",
            table_prefix
        ))
        .map_err(Either::Right)?;

    stmt_insert_checkpoint
        .execute(named_params![
            ":checkpoint_id": u32::from(checkpoint_id),
            ":position": checkpoint.position().map(u64::from)
        ])
        .map_err(Either::Right)?;

    let mut stmt_insert_mark_removed = conn
        .prepare_cached(&format!(
            "INSERT INTO {}_tree_checkpoint_marks_removed (checkpoint_id, mark_removed_position)
             VALUES (:checkpoint_id, :position)",
            table_prefix
        ))
        .map_err(Either::Right)?;

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

pub(crate) fn checkpoint_count(
    conn: &rusqlite::Connection,
    table_prefix: &'static str,
) -> Result<usize, Error> {
    conn.query_row(
        &format!("SELECT COUNT(*) FROM {}_tree_checkpoints", table_prefix),
        [],
        |row| row.get::<_, usize>(0),
    )
    .map_err(Either::Right)
}

pub(crate) fn get_checkpoint(
    conn: &rusqlite::Connection,
    table_prefix: &'static str,
    checkpoint_id: BlockHeight,
) -> Result<Option<Checkpoint>, Error> {
    let checkpoint_position = conn
        .query_row(
            &format!(
                "SELECT position
            FROM {}_tree_checkpoints
            WHERE checkpoint_id = ?",
                table_prefix
            ),
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
            let mut stmt = conn
                .prepare_cached(&format!(
                    "SELECT mark_removed_position
                    FROM {}_tree_checkpoint_marks_removed
                    WHERE checkpoint_id = ?",
                    table_prefix
                ))
                .map_err(Either::Right)?;
            let mark_removed_rows = stmt
                .query([u32::from(checkpoint_id)])
                .map_err(Either::Right)?;

            let marks_removed = mark_removed_rows
                .mapped(|row| row.get::<_, u64>(0).map(Position::from))
                .collect::<Result<BTreeSet<_>, _>>()
                .map_err(Either::Right)?;

            Ok(Checkpoint::from_parts(
                pos_opt.map_or(TreeState::Empty, TreeState::AtPosition),
                marks_removed,
            ))
        })
        .transpose()
}

pub(crate) fn get_checkpoint_at_depth(
    conn: &rusqlite::Connection,
    table_prefix: &'static str,
    checkpoint_depth: usize,
) -> Result<Option<(BlockHeight, Checkpoint)>, Error> {
    if checkpoint_depth == 0 {
        return Ok(None);
    }

    let checkpoint_parts = conn
        .query_row(
            &format!(
                "SELECT checkpoint_id, position
                FROM {}_tree_checkpoints
                ORDER BY checkpoint_id DESC
                LIMIT 1
                OFFSET :offset",
                table_prefix
            ),
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
            let mut stmt = conn
                .prepare_cached(&format!(
                    "SELECT mark_removed_position
                    FROM {}_tree_checkpoint_marks_removed
                    WHERE checkpoint_id = ?",
                    table_prefix
                ))
                .map_err(Either::Right)?;
            let mark_removed_rows = stmt
                .query([u32::from(checkpoint_id)])
                .map_err(Either::Right)?;

            let marks_removed = mark_removed_rows
                .mapped(|row| row.get::<_, u64>(0).map(Position::from))
                .collect::<Result<BTreeSet<_>, _>>()
                .map_err(Either::Right)?;

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
    table_prefix: &'static str,
    limit: usize,
    mut callback: F,
) -> Result<(), Error>
where
    F: FnMut(&BlockHeight, &Checkpoint) -> Result<(), Error>,
{
    let mut stmt_get_checkpoints = conn
        .prepare_cached(&format!(
            "SELECT checkpoint_id, position
            FROM {}_tree_checkpoints
            ORDER BY position
            LIMIT :limit",
            table_prefix
        ))
        .map_err(Either::Right)?;

    let mut stmt_get_checkpoint_marks_removed = conn
        .prepare_cached(&format!(
            "SELECT mark_removed_position
            FROM {}_tree_checkpoint_marks_removed
            WHERE checkpoint_id = :checkpoint_id",
            table_prefix
        ))
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

        let mark_removed_rows = stmt_get_checkpoint_marks_removed
            .query(named_params![":checkpoint_id": checkpoint_id])
            .map_err(Either::Right)?;

        let marks_removed = mark_removed_rows
            .mapped(|row| row.get::<_, u64>(0).map(Position::from))
            .collect::<Result<BTreeSet<_>, _>>()
            .map_err(Either::Right)?;

        callback(
            &BlockHeight::from(checkpoint_id),
            &Checkpoint::from_parts(tree_state, marks_removed),
        )?
    }

    Ok(())
}

pub(crate) fn update_checkpoint_with<F>(
    conn: &rusqlite::Transaction<'_>,
    table_prefix: &'static str,
    checkpoint_id: BlockHeight,
    update: F,
) -> Result<bool, Error>
where
    F: Fn(&mut Checkpoint) -> Result<(), Error>,
{
    if let Some(mut c) = get_checkpoint(conn, table_prefix, checkpoint_id)? {
        update(&mut c)?;
        remove_checkpoint(conn, table_prefix, checkpoint_id)?;
        add_checkpoint(conn, table_prefix, checkpoint_id, c)?;
        Ok(true)
    } else {
        Ok(false)
    }
}

pub(crate) fn remove_checkpoint(
    conn: &rusqlite::Transaction<'_>,
    table_prefix: &'static str,
    checkpoint_id: BlockHeight,
) -> Result<(), Error> {
    // cascading delete here obviates the need to manually delete from
    // `tree_checkpoint_marks_removed`
    let mut stmt_delete_checkpoint = conn
        .prepare_cached(&format!(
            "DELETE FROM {}_tree_checkpoints
             WHERE checkpoint_id = :checkpoint_id",
            table_prefix
        ))
        .map_err(Either::Right)?;

    stmt_delete_checkpoint
        .execute(named_params![":checkpoint_id": u32::from(checkpoint_id),])
        .map_err(Either::Right)?;

    Ok(())
}

pub(crate) fn truncate_checkpoints(
    conn: &rusqlite::Transaction<'_>,
    table_prefix: &'static str,
    checkpoint_id: BlockHeight,
) -> Result<(), Error> {
    // cascading delete here obviates the need to manually delete from
    // `tree_checkpoint_marks_removed`
    conn.execute(
        &format!(
            "DELETE FROM {}_tree_checkpoints WHERE checkpoint_id >= ?",
            table_prefix
        ),
        [u32::from(checkpoint_id)],
    )
    .map_err(Either::Right)?;

    Ok(())
}

pub(crate) fn put_shard_roots<
    H: Hashable + HashSer + Clone + Eq,
    const DEPTH: u8,
    const SHARD_HEIGHT: u8,
>(
    conn: &rusqlite::Transaction<'_>,
    table_prefix: &'static str,
    start_index: u64,
    roots: &[CommitmentTreeRoot<H>],
) -> Result<(), ShardTreeError<Error>> {
    if roots.is_empty() {
        // nothing to do
        return Ok(());
    }

    // We treat the cap as a tree with `DEPTH - SHARD_HEIGHT` levels, so that we can make a
    // batch insertion of root data using `Position::from(start_index)` as the starting position
    // and treating the roots as level-0 leaves.
    #[derive(Clone, Debug, PartialEq, Eq)]
    struct LevelShifter<H, const SHARD_HEIGHT: u8>(H);
    impl<H: Hashable, const SHARD_HEIGHT: u8> Hashable for LevelShifter<H, SHARD_HEIGHT> {
        fn empty_leaf() -> Self {
            Self(H::empty_root(SHARD_HEIGHT.into()))
        }

        fn combine(level: Level, a: &Self, b: &Self) -> Self {
            Self(H::combine(level + SHARD_HEIGHT, &a.0, &b.0))
        }

        fn empty_root(level: Level) -> Self
        where
            Self: Sized,
        {
            Self(H::empty_root(level + SHARD_HEIGHT))
        }
    }
    impl<H: HashSer, const SHARD_HEIGHT: u8> HashSer for LevelShifter<H, SHARD_HEIGHT> {
        fn read<R: io::Read>(reader: R) -> io::Result<Self>
        where
            Self: Sized,
        {
            H::read(reader).map(Self)
        }

        fn write<W: io::Write>(&self, writer: W) -> io::Result<()> {
            self.0.write(writer)
        }
    }

    let cap = LocatedTree::from_parts(
        Address::from_parts((DEPTH - SHARD_HEIGHT).into(), 0),
        get_cap::<LevelShifter<H, SHARD_HEIGHT>>(conn, table_prefix)
            .map_err(ShardTreeError::Storage)?,
    );

    let cap_result = cap
        .batch_insert(
            Position::from(start_index),
            roots.iter().map(|r| {
                (
                    LevelShifter(r.root_hash().clone()),
                    Retention::Checkpoint {
                        id: (),
                        is_marked: false,
                    },
                )
            }),
        )
        .map_err(ShardTreeError::Insert)?
        .expect("slice of inserted roots was verified to be nonempty");

    put_cap(conn, table_prefix, cap_result.subtree.take_root()).map_err(ShardTreeError::Storage)?;

    for (root, i) in roots.iter().zip(0u64..) {
        // We want to avoid deserializing the subtree just to annotate its root node, so we simply
        // cache the downloaded root alongside of any already-persisted subtree. We will update the
        // subtree data itself by reannotating the root node of the tree, handling conflicts, at
        // the time that we deserialize the tree.
        let mut stmt = conn
            .prepare_cached(&format!(
            "INSERT INTO {}_tree_shards (shard_index, subtree_end_height, root_hash, shard_data)
            VALUES (:shard_index, :subtree_end_height, :root_hash, :shard_data)
            ON CONFLICT (shard_index) DO UPDATE
            SET subtree_end_height = :subtree_end_height, root_hash = :root_hash",
            table_prefix
        ))
            .map_err(|e| ShardTreeError::Storage(Either::Right(e)))?;

        // The `shard_data` value will only be used in the case that no tree already exists.
        let mut shard_data: Vec<u8> = vec![];
        let tree = PrunableTree::leaf((root.root_hash().clone(), RetentionFlags::EPHEMERAL));
        write_shard(&mut shard_data, &tree)
            .map_err(|e| ShardTreeError::Storage(Either::Left(e)))?;

        let mut root_hash_data: Vec<u8> = vec![];
        root.root_hash()
            .write(&mut root_hash_data)
            .map_err(|e| ShardTreeError::Storage(Either::Left(e)))?;

        stmt.execute(named_params![
            ":shard_index": start_index + i,
            ":subtree_end_height": u32::from(root.subtree_end_height()),
            ":root_hash": root_hash_data,
            ":shard_data": shard_data,
        ])
        .map_err(|e| ShardTreeError::Storage(Either::Right(e)))?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use tempfile::NamedTempFile;

    use incrementalmerkletree::{
        testing::{
            check_append, check_checkpoint_rewind, check_remove_mark, check_rewind_remove_mark,
            check_root_hashes, check_witness_consistency, check_witnesses,
        },
        Position, Retention,
    };
    use shardtree::ShardTree;
    use zcash_client_backend::data_api::chain::CommitmentTreeRoot;
    use zcash_primitives::consensus::BlockHeight;

    use super::SqliteShardStore;
    use crate::{tests, wallet::init::init_wallet_db, WalletDb, SAPLING_TABLES_PREFIX};

    fn new_tree(m: usize) -> ShardTree<SqliteShardStore<rusqlite::Connection, String, 3>, 4, 3> {
        let data_file = NamedTempFile::new().unwrap();
        let mut db_data = WalletDb::for_path(data_file.path(), tests::network()).unwrap();
        data_file.keep().unwrap();

        init_wallet_db(&mut db_data, None).unwrap();
        let store =
            SqliteShardStore::<_, String, 3>::from_connection(db_data.conn, SAPLING_TABLES_PREFIX)
                .unwrap();
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

    #[test]
    fn put_shard_roots() {
        let data_file = NamedTempFile::new().unwrap();
        let mut db_data = WalletDb::for_path(data_file.path(), tests::network()).unwrap();
        data_file.keep().unwrap();

        init_wallet_db(&mut db_data, None).unwrap();
        let tx = db_data.conn.transaction().unwrap();
        let store =
            SqliteShardStore::<_, String, 3>::from_connection(&tx, SAPLING_TABLES_PREFIX).unwrap();

        // introduce some roots
        let roots = (0u32..4)
            .into_iter()
            .map(|idx| {
                CommitmentTreeRoot::from_parts(
                    BlockHeight::from((idx + 1) * 3),
                    if idx == 3 {
                        "abcdefgh".to_string()
                    } else {
                        idx.to_string()
                    },
                )
            })
            .collect::<Vec<_>>();
        super::put_shard_roots::<_, 6, 3>(store.conn, SAPLING_TABLES_PREFIX, 0, &roots).unwrap();

        // simulate discovery of a note
        let mut tree = ShardTree::<_, 6, 3>::new(store, 10);
        tree.batch_insert(
            Position::from(24),
            ('a'..='h').into_iter().map(|c| {
                (
                    c.to_string(),
                    match c {
                        'c' => Retention::Marked,
                        'h' => Retention::Checkpoint {
                            id: BlockHeight::from(3),
                            is_marked: false,
                        },
                        _ => Retention::Ephemeral,
                    },
                )
            }),
        )
        .unwrap();

        // construct a witness for the note
        let witness = tree.witness(Position::from(26), 0).unwrap();
        assert_eq!(
            witness.path_elems(),
            &[
                "d",
                "ab",
                "efgh",
                "2",
                "01",
                "________________________________"
            ]
        );
    }
}
