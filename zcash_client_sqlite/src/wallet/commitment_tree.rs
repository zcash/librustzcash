use rusqlite::{self, named_params, OptionalExtension};
use std::{
    collections::BTreeSet,
    error, fmt,
    io::{self, Cursor},
    marker::PhantomData,
    ops::Range,
    sync::Arc,
};
use zcash_client_backend::data_api::chain::CommitmentTreeRoot;

use incrementalmerkletree::{Address, Hashable, Level, Position, Retention};
use shardtree::{
    error::ShardTreeError,
    store::{Checkpoint, ShardStore, TreeState},
    LocatedPrunableTree, LocatedTree, PrunableTree, RetentionFlags,
};

use zcash_primitives::{consensus::BlockHeight, merkle_tree::HashSer};

use zcash_client_backend::serialization::shardtree::{read_shard, write_shard};

/// Errors that can appear in SQLite-back [`ShardStore`] implementation operations.
#[derive(Debug)]
pub enum Error {
    /// Errors in deserializing stored shard data
    Serialization(io::Error),
    /// Errors encountered querying stored shard data
    Query(rusqlite::Error),
    /// Raised when the caller attempts to add a checkpoint at a block height where a checkpoint
    /// already exists, but the tree state being checkpointed or the marks removed at that
    /// checkpoint conflict with the existing tree state.
    CheckpointConflict {
        checkpoint_id: BlockHeight,
        checkpoint: Checkpoint,
        extant_tree_state: TreeState,
        extant_marks_removed: Option<BTreeSet<Position>>,
    },
    /// Raised when attempting to add shard roots to the database that
    /// are discontinuous with the existing roots in the database.
    SubtreeDiscontinuity {
        attempted_insertion_range: Range<u64>,
        existing_range: Range<u64>,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self {
            Error::Serialization(err) => write!(f, "Commitment tree serializtion error: {}", err),
            Error::Query(err) => write!(f, "Commitment tree query or update error: {}", err),
            Error::CheckpointConflict {
                checkpoint_id,
                checkpoint,
                extant_tree_state,
                extant_marks_removed,
            } => {
                write!(
                    f,
                    "Conflict at checkpoint id {}, tried to insert {:?}, which is incompatible with existing state ({:?}, {:?})",
                    checkpoint_id, checkpoint, extant_tree_state, extant_marks_removed
                )
            }
            Error::SubtreeDiscontinuity {
                attempted_insertion_range,
                existing_range,
            } => {
                write!(
                    f,
                    "Attempted to write subtree roots with indicies {:?} which is discontinuous with existing subtree range {:?}",
                    attempted_insertion_range, existing_range,
                )
            }
        }
    }
}

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match &self {
            Error::Serialization(e) => Some(e),
            Error::Query(e) => Some(e),
            Error::CheckpointConflict { .. } => None,
            Error::SubtreeDiscontinuity { .. } => None,
        }
    }
}

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
    type Error = Error;

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
    type Error = Error;

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
        let tx = self.conn.transaction().map_err(Error::Query)?;
        put_shard(&tx, self.table_prefix, subtree)?;
        tx.commit().map_err(Error::Query)?;
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
        let tx = self.conn.transaction().map_err(Error::Query)?;
        add_checkpoint(&tx, self.table_prefix, checkpoint_id, checkpoint)?;
        tx.commit().map_err(Error::Query)
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
        let tx = self.conn.transaction().map_err(Error::Query)?;
        with_checkpoints(&tx, self.table_prefix, limit, callback)?;
        tx.commit().map_err(Error::Query)
    }

    fn update_checkpoint_with<F>(
        &mut self,
        checkpoint_id: &Self::CheckpointId,
        update: F,
    ) -> Result<bool, Self::Error>
    where
        F: Fn(&mut Checkpoint) -> Result<(), Self::Error>,
    {
        let tx = self.conn.transaction().map_err(Error::Query)?;
        let result = update_checkpoint_with(&tx, self.table_prefix, *checkpoint_id, update)?;
        tx.commit().map_err(Error::Query)?;
        Ok(result)
    }

    fn remove_checkpoint(&mut self, checkpoint_id: &Self::CheckpointId) -> Result<(), Self::Error> {
        let tx = self.conn.transaction().map_err(Error::Query)?;
        remove_checkpoint(&tx, self.table_prefix, *checkpoint_id)?;
        tx.commit().map_err(Error::Query)
    }

    fn truncate_checkpoints(
        &mut self,
        checkpoint_id: &Self::CheckpointId,
    ) -> Result<(), Self::Error> {
        let tx = self.conn.transaction().map_err(Error::Query)?;
        truncate_checkpoints(&tx, self.table_prefix, *checkpoint_id)?;
        tx.commit().map_err(Error::Query)
    }
}

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
    .map_err(Error::Query)?
    .map(|(shard_data, root_hash)| {
        let shard_tree = read_shard(&mut Cursor::new(shard_data)).map_err(Error::Serialization)?;
        let located_tree = LocatedPrunableTree::from_parts(shard_root_addr, shard_tree);
        if let Some(root_hash_data) = root_hash {
            let root_hash = H::read(Cursor::new(root_hash_data)).map_err(Error::Serialization)?;
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
    .map_err(Error::Query)?
    .map(|(shard_index, shard_data)| {
        let shard_root = Address::from_parts(shard_root_level, shard_index);
        let shard_tree = read_shard(&mut Cursor::new(shard_data)).map_err(Error::Serialization)?;
        Ok(LocatedPrunableTree::from_parts(shard_root, shard_tree))
    })
    .transpose()
}

/// Returns an error iff the proposed insertion range
/// for the tree shards would create a discontinuity
/// in the database.
fn check_shard_discontinuity(
    conn: &rusqlite::Connection,
    table_prefix: &'static str,
    proposed_insertion_range: Range<u64>,
) -> Result<(), Error> {
    if let Ok((Some(stored_min), Some(stored_max))) = conn
        .query_row(
            &format!(
                "SELECT MIN(shard_index), MAX(shard_index) FROM {}_tree_shards",
                table_prefix
            ),
            [],
            |row| {
                let min = row.get::<_, Option<u64>>(0)?;
                let max = row.get::<_, Option<u64>>(1)?;
                Ok((min, max))
            },
        )
        .map_err(Error::Query)
    {
        // If the ranges overlap, or are directly adjacent, then we aren't creating a
        // discontinuity. We can check this by comparing their start-inclusive,
        // end-exclusive bounds:
        // - If `cur_start == ins_end` then the proposed insertion range is immediately
        //   before the current shards. If `cur_start > ins_end` then there is a gap.
        // - If `ins_start == cur_end` then the proposed insertion range is immediately
        //   after the current shards. If `ins_start > cur_end` then there is a gap.
        let (cur_start, cur_end) = (stored_min, stored_max + 1);
        let (ins_start, ins_end) = (proposed_insertion_range.start, proposed_insertion_range.end);
        if cur_start > ins_end || ins_start > cur_end {
            return Err(Error::SubtreeDiscontinuity {
                attempted_insertion_range: proposed_insertion_range,
                existing_range: cur_start..cur_end,
            });
        }
    }

    Ok(())
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
        .map_err(Error::Serialization)?;

    let mut subtree_data = vec![];
    write_shard(&mut subtree_data, subtree.root()).map_err(Error::Serialization)?;

    let shard_index = subtree.root_addr().index();

    check_shard_discontinuity(conn, table_prefix, shard_index..shard_index + 1)?;

    let mut stmt_put_shard = conn
        .prepare_cached(&format!(
            "INSERT INTO {}_tree_shards (shard_index, root_hash, shard_data)
             VALUES (:shard_index, :root_hash, :shard_data)
             ON CONFLICT (shard_index) DO UPDATE
             SET root_hash = :root_hash,
             shard_data = :shard_data",
            table_prefix
        ))
        .map_err(Error::Query)?;

    stmt_put_shard
        .execute(named_params![
            ":shard_index": shard_index,
            ":root_hash": subtree_root_hash,
            ":shard_data": subtree_data
        ])
        .map_err(Error::Query)?;

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
        .map_err(Error::Query)?;
    let mut rows = stmt.query([]).map_err(Error::Query)?;

    let mut res = vec![];
    while let Some(row) = rows.next().map_err(Error::Query)? {
        res.push(Address::from_parts(
            shard_root_level,
            row.get(0).map_err(Error::Query)?,
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
    .map_err(Error::Query)
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
    .map_err(Error::Query)?
    .map_or_else(
        || Ok(PrunableTree::empty()),
        |cap_data| read_shard(&mut Cursor::new(cap_data)).map_err(Error::Serialization),
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
        .map_err(Error::Query)?;

    let mut cap_data = vec![];
    write_shard(&mut cap_data, &cap).map_err(Error::Serialization)?;
    stmt.execute([cap_data]).map_err(Error::Query)?;

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
    .map_err(Error::Query)
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
    .map_err(Error::Query)
}

pub(crate) fn add_checkpoint(
    conn: &rusqlite::Transaction<'_>,
    table_prefix: &'static str,
    checkpoint_id: BlockHeight,
    checkpoint: Checkpoint,
) -> Result<(), Error> {
    let extant_tree_state = conn
        .query_row(
            &format!(
                "SELECT position FROM {}_tree_checkpoints WHERE checkpoint_id = :checkpoint_id",
                table_prefix
            ),
            named_params![":checkpoint_id": u32::from(checkpoint_id),],
            |row| {
                row.get::<_, Option<u64>>(0).map(|opt| {
                    opt.map_or_else(
                        || TreeState::Empty,
                        |pos| TreeState::AtPosition(Position::from(pos)),
                    )
                })
            },
        )
        .optional()
        .map_err(Error::Query)?;

    match extant_tree_state {
        Some(current) => {
            if current != checkpoint.tree_state() {
                // If the checkpoint position for a given checkpoint identifier has changed, we treat
                // this as an error because the wallet should have detected a chain reorg and truncated
                // the tree.
                Err(Error::CheckpointConflict {
                    checkpoint_id,
                    checkpoint,
                    extant_tree_state: current,
                    extant_marks_removed: None,
                })
            } else {
                // if the existing spends are the same, we can skip the insert; if the
                // existing spends have changed, this is also a conflict.
                let marks_removed = get_marks_removed(conn, table_prefix, checkpoint_id)?;
                if &marks_removed == checkpoint.marks_removed() {
                    Ok(())
                } else {
                    Err(Error::CheckpointConflict {
                        checkpoint_id,
                        checkpoint,
                        extant_tree_state: current,
                        extant_marks_removed: Some(marks_removed),
                    })
                }
            }
        }
        None => {
            let mut stmt_insert_checkpoint = conn
                .prepare_cached(&format!(
                    "INSERT INTO {}_tree_checkpoints (checkpoint_id, position)
                     VALUES (:checkpoint_id, :position)",
                    table_prefix
                ))
                .map_err(Error::Query)?;

            stmt_insert_checkpoint
                .execute(named_params![
                    ":checkpoint_id": u32::from(checkpoint_id),
                    ":position": checkpoint.position().map(u64::from)
                ])
                .map_err(Error::Query)?;

            let mut stmt_insert_mark_removed = conn
                .prepare_cached(&format!(
                    "INSERT INTO {}_tree_checkpoint_marks_removed (checkpoint_id, mark_removed_position)
                     VALUES (:checkpoint_id, :position)",
                    table_prefix
                ))
                .map_err(Error::Query)?;

            for pos in checkpoint.marks_removed() {
                stmt_insert_mark_removed
                    .execute(named_params![
                        ":checkpoint_id": u32::from(checkpoint_id),
                        ":position": u64::from(*pos)
                    ])
                    .map_err(Error::Query)?;
            }

            Ok(())
        }
    }
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
    .map_err(Error::Query)
}

fn get_marks_removed(
    conn: &rusqlite::Connection,
    table_prefix: &'static str,
    checkpoint_id: BlockHeight,
) -> Result<BTreeSet<Position>, Error> {
    let mut stmt = conn
        .prepare_cached(&format!(
            "SELECT mark_removed_position
            FROM {}_tree_checkpoint_marks_removed
            WHERE checkpoint_id = ?",
            table_prefix
        ))
        .map_err(Error::Query)?;
    let mark_removed_rows = stmt
        .query([u32::from(checkpoint_id)])
        .map_err(Error::Query)?;

    mark_removed_rows
        .mapped(|row| row.get::<_, u64>(0).map(Position::from))
        .collect::<Result<BTreeSet<_>, _>>()
        .map_err(Error::Query)
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
        .map_err(Error::Query)?;

    checkpoint_position
        .map(|pos_opt| {
            Ok(Checkpoint::from_parts(
                pos_opt.map_or(TreeState::Empty, TreeState::AtPosition),
                get_marks_removed(conn, table_prefix, checkpoint_id)?,
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
        .map_err(Error::Query)?;

    checkpoint_parts
        .map(|(checkpoint_id, pos_opt)| {
            let mut stmt = conn
                .prepare_cached(&format!(
                    "SELECT mark_removed_position
                    FROM {}_tree_checkpoint_marks_removed
                    WHERE checkpoint_id = ?",
                    table_prefix
                ))
                .map_err(Error::Query)?;
            let mark_removed_rows = stmt
                .query([u32::from(checkpoint_id)])
                .map_err(Error::Query)?;

            let marks_removed = mark_removed_rows
                .mapped(|row| row.get::<_, u64>(0).map(Position::from))
                .collect::<Result<BTreeSet<_>, _>>()
                .map_err(Error::Query)?;

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
        .map_err(Error::Query)?;

    let mut stmt_get_checkpoint_marks_removed = conn
        .prepare_cached(&format!(
            "SELECT mark_removed_position
            FROM {}_tree_checkpoint_marks_removed
            WHERE checkpoint_id = :checkpoint_id",
            table_prefix
        ))
        .map_err(Error::Query)?;

    let mut rows = stmt_get_checkpoints
        .query(named_params![":limit": limit])
        .map_err(Error::Query)?;

    while let Some(row) = rows.next().map_err(Error::Query)? {
        let checkpoint_id = row.get::<_, u32>(0).map_err(Error::Query)?;
        let tree_state = row
            .get::<_, Option<u64>>(1)
            .map(|opt| opt.map_or_else(|| TreeState::Empty, |p| TreeState::AtPosition(p.into())))
            .map_err(Error::Query)?;

        let mark_removed_rows = stmt_get_checkpoint_marks_removed
            .query(named_params![":checkpoint_id": checkpoint_id])
            .map_err(Error::Query)?;

        let marks_removed = mark_removed_rows
            .mapped(|row| row.get::<_, u64>(0).map(Position::from))
            .collect::<Result<BTreeSet<_>, _>>()
            .map_err(Error::Query)?;

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
        .map_err(Error::Query)?;

    stmt_delete_checkpoint
        .execute(named_params![":checkpoint_id": u32::from(checkpoint_id),])
        .map_err(Error::Query)?;

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
    .map_err(Error::Query)?;

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

    check_shard_discontinuity(
        conn,
        table_prefix,
        start_index..start_index + (roots.len() as u64),
    )
    .map_err(ShardTreeError::Storage)?;

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
            .map_err(|e| ShardTreeError::Storage(Error::Query(e)))?;

        // The `shard_data` value will only be used in the case that no tree already exists.
        let mut shard_data: Vec<u8> = vec![];
        let tree = PrunableTree::leaf((root.root_hash().clone(), RetentionFlags::EPHEMERAL));
        write_shard(&mut shard_data, &tree)
            .map_err(|e| ShardTreeError::Storage(Error::Serialization(e)))?;

        let mut root_hash_data: Vec<u8> = vec![];
        root.root_hash()
            .write(&mut root_hash_data)
            .map_err(|e| ShardTreeError::Storage(Error::Serialization(e)))?;

        stmt.execute(named_params![
            ":shard_index": start_index + i,
            ":subtree_end_height": u32::from(root.subtree_end_height()),
            ":root_hash": root_hash_data,
            ":shard_data": shard_data,
        ])
        .map_err(|e| ShardTreeError::Storage(Error::Query(e)))?;
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
    use zcash_primitives::consensus::{BlockHeight, Network};

    use super::SqliteShardStore;
    use crate::{wallet::init::init_wallet_db, WalletDb, SAPLING_TABLES_PREFIX};

    fn new_tree(m: usize) -> ShardTree<SqliteShardStore<rusqlite::Connection, String, 3>, 4, 3> {
        let data_file = NamedTempFile::new().unwrap();
        let mut db_data = WalletDb::for_path(data_file.path(), Network::TestNetwork).unwrap();
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
        let mut db_data = WalletDb::for_path(data_file.path(), Network::TestNetwork).unwrap();
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
