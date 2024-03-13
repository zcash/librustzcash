//! Functions for enforcing chain validity and handling chain reorgs.

use prost::Message;
use rusqlite::params;

use zcash_primitives::consensus::BlockHeight;

use zcash_client_backend::{data_api::chain::error::Error, proto::compact_formats::CompactBlock};

use crate::{error::SqliteClientError, BlockDb};

#[cfg(feature = "unstable")]
use {
    crate::{BlockHash, FsBlockDb, FsBlockDbError},
    rusqlite::Connection,
    std::fs::File,
    std::io::Read,
    std::path::{Path, PathBuf},
};

pub mod init;
pub mod migrations;

/// Implements a traversal of `limit` blocks of the block cache database.
///
/// Starting at `from_height`, the `with_row` callback is invoked with each block retrieved from
/// the backing store. If the `limit` value provided is `None`, all blocks are traversed up to the
/// maximum height.
pub(crate) fn blockdb_with_blocks<F, DbErrT>(
    block_source: &BlockDb,
    from_height: Option<BlockHeight>,
    limit: Option<usize>,
    mut with_row: F,
) -> Result<(), Error<DbErrT, SqliteClientError>>
where
    F: FnMut(CompactBlock) -> Result<(), Error<DbErrT, SqliteClientError>>,
{
    fn to_chain_error<D, E: Into<SqliteClientError>>(err: E) -> Error<D, SqliteClientError> {
        Error::BlockSource(err.into())
    }

    // Fetch the CompactBlocks we need to scan
    let mut stmt_blocks = block_source
        .0
        .prepare(
            "SELECT height, data FROM compactblocks
            WHERE height >= ?
            ORDER BY height ASC LIMIT ?",
        )
        .map_err(to_chain_error)?;

    let mut rows = stmt_blocks
        .query(params![
            from_height.map_or(0u32, u32::from),
            limit
                .and_then(|l| u32::try_from(l).ok())
                .unwrap_or(u32::MAX)
        ])
        .map_err(to_chain_error)?;

    // Only look for the `from_height` in the scanned blocks if it is set.
    let mut from_height_found = from_height.is_none();
    while let Some(row) = rows.next().map_err(to_chain_error)? {
        let height = BlockHeight::from_u32(row.get(0).map_err(to_chain_error)?);
        if !from_height_found {
            // We will only perform this check on the first row.
            let from_height = from_height.expect("can only reach here if set");
            if from_height != height {
                return Err(to_chain_error(SqliteClientError::CacheMiss(from_height)));
            } else {
                from_height_found = true;
            }
        }

        let data: Vec<u8> = row.get(1).map_err(to_chain_error)?;
        let block = CompactBlock::decode(&data[..]).map_err(to_chain_error)?;
        if block.height() != height {
            return Err(to_chain_error(SqliteClientError::CorruptedData(format!(
                "Block height {} did not match row's height field value {}",
                block.height(),
                height
            ))));
        }

        with_row(block)?;
    }

    if !from_height_found {
        let from_height = from_height.expect("can only reach here if set");
        return Err(to_chain_error(SqliteClientError::CacheMiss(from_height)));
    }

    Ok(())
}

/// Data structure representing a row in the block metadata database.
#[cfg(feature = "unstable")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockMeta {
    pub height: BlockHeight,
    pub block_hash: BlockHash,
    pub block_time: u32,
    pub sapling_outputs_count: u32,
    pub orchard_actions_count: u32,
}

#[cfg(feature = "unstable")]
impl BlockMeta {
    pub fn block_file_path<P: AsRef<Path>>(&self, blocks_dir: &P) -> PathBuf {
        blocks_dir.as_ref().join(Path::new(&format!(
            "{}-{}-compactblock",
            self.height, self.block_hash
        )))
    }
}

/// Inserts a batch of rows into the block metadata database.
#[cfg(feature = "unstable")]
pub(crate) fn blockmetadb_insert(
    conn: &Connection,
    block_meta: &[BlockMeta],
) -> Result<(), rusqlite::Error> {
    use rusqlite::named_params;

    let mut stmt_insert = conn.prepare(
        "INSERT INTO compactblocks_meta (
            height,
            blockhash,
            time,
            sapling_outputs_count,
            orchard_actions_count
        )
        VALUES (
            :height,
            :blockhash,
            :time,
            :sapling_outputs_count,
            :orchard_actions_count
        )
        ON CONFLICT (height) DO UPDATE
        SET blockhash = :blockhash,
            time = :time,
            sapling_outputs_count = :sapling_outputs_count,
            orchard_actions_count = :orchard_actions_count",
    )?;

    conn.execute("BEGIN IMMEDIATE", [])?;
    let result = block_meta
        .iter()
        .map(|m| {
            stmt_insert.execute(named_params![
                ":height": u32::from(m.height),
                ":blockhash": &m.block_hash.0[..],
                ":time": m.block_time,
                ":sapling_outputs_count": m.sapling_outputs_count,
                ":orchard_actions_count": m.orchard_actions_count,
            ])
        })
        .collect::<Result<Vec<_>, _>>();
    match result {
        Ok(_) => {
            conn.execute("COMMIT", [])?;
            Ok(())
        }
        Err(error) => {
            match conn.execute("ROLLBACK", []) {
                Ok(_) => Err(error),
                Err(e) =>
                    // Panicking here is probably the right thing to do, because it
                    // means the database is corrupt.
                    panic!(
                        "Rollback failed with error {} while attempting to recover from error {}; database is likely corrupt.",
                        e,
                        error
                    )
            }
        }
    }
}

#[cfg(feature = "unstable")]
pub(crate) fn blockmetadb_truncate_to_height(
    conn: &Connection,
    block_height: BlockHeight,
) -> Result<(), rusqlite::Error> {
    conn.prepare("DELETE FROM compactblocks_meta WHERE height > ?")?
        .execute(params![u32::from(block_height)])?;
    Ok(())
}

#[cfg(feature = "unstable")]
pub(crate) fn blockmetadb_get_max_cached_height(
    conn: &Connection,
) -> Result<Option<BlockHeight>, rusqlite::Error> {
    conn.query_row("SELECT MAX(height) FROM compactblocks_meta", [], |row| {
        // `SELECT MAX(_)` will always return a row, but it will return `null` if the
        // table is empty, which has no integer type. We handle the optionality here.
        let h: Option<u32> = row.get(0)?;
        Ok(h.map(BlockHeight::from))
    })
}

/// Returns the metadata for the block with the given height, if it exists in the database.
#[cfg(feature = "unstable")]
pub(crate) fn blockmetadb_find_block(
    conn: &Connection,
    height: BlockHeight,
) -> Result<Option<BlockMeta>, rusqlite::Error> {
    use rusqlite::OptionalExtension;

    conn.query_row(
        "SELECT blockhash, time, sapling_outputs_count, orchard_actions_count
        FROM compactblocks_meta
        WHERE height = ?",
        [u32::from(height)],
        |row| {
            Ok(BlockMeta {
                height,
                block_hash: BlockHash::from_slice(&row.get::<_, Vec<_>>(0)?),
                block_time: row.get(1)?,
                sapling_outputs_count: row.get(2)?,
                orchard_actions_count: row.get(3)?,
            })
        },
    )
    .optional()
}

/// Implements a traversal of `limit` blocks of the filesystem-backed
/// block cache.
///
/// Starting at `from_height`, the `with_row` callback is invoked with each block retrieved from
/// the backing store. If the `limit` value provided is `None`, all blocks are traversed up to the
/// maximum height for which metadata is available.
#[cfg(feature = "unstable")]
pub(crate) fn fsblockdb_with_blocks<F, DbErrT>(
    cache: &FsBlockDb,
    from_height: Option<BlockHeight>,
    limit: Option<usize>,
    mut with_block: F,
) -> Result<(), Error<DbErrT, FsBlockDbError>>
where
    F: FnMut(CompactBlock) -> Result<(), Error<DbErrT, FsBlockDbError>>,
{
    fn to_chain_error<D, E: Into<FsBlockDbError>>(err: E) -> Error<D, FsBlockDbError> {
        Error::BlockSource(err.into())
    }

    // Fetch the CompactBlocks we need to scan
    let mut stmt_blocks = cache
        .conn
        .prepare(
            "SELECT height, blockhash, time, sapling_outputs_count, orchard_actions_count
             FROM compactblocks_meta
             WHERE height >= ?
             ORDER BY height ASC LIMIT ?",
        )
        .map_err(to_chain_error)?;

    let rows = stmt_blocks
        .query_map(
            params![
                from_height.map_or(0u32, u32::from),
                limit
                    .and_then(|l| u32::try_from(l).ok())
                    .unwrap_or(u32::MAX)
            ],
            |row| {
                Ok(BlockMeta {
                    height: BlockHeight::from_u32(row.get(0)?),
                    block_hash: BlockHash::from_slice(&row.get::<_, Vec<_>>(1)?),
                    block_time: row.get(2)?,
                    sapling_outputs_count: row.get(3)?,
                    orchard_actions_count: row.get(4)?,
                })
            },
        )
        .map_err(to_chain_error)?;

    // Only look for the `from_height` in the scanned blocks if it is set.
    let mut from_height_found = from_height.is_none();
    for row_result in rows {
        let cbr = row_result.map_err(to_chain_error)?;
        if !from_height_found {
            // We will only perform this check on the first row.
            let from_height = from_height.expect("can only reach here if set");
            if from_height != cbr.height {
                return Err(to_chain_error(FsBlockDbError::CacheMiss(from_height)));
            } else {
                from_height_found = true;
            }
        }

        let mut block_file =
            File::open(cbr.block_file_path(&cache.blocks_dir)).map_err(to_chain_error)?;
        let mut block_data = vec![];
        block_file
            .read_to_end(&mut block_data)
            .map_err(to_chain_error)?;

        let block = CompactBlock::decode(&block_data[..]).map_err(to_chain_error)?;

        if block.height() != cbr.height {
            return Err(to_chain_error(FsBlockDbError::CorruptedData(format!(
                "Block height {} did not match row's height field value {}",
                block.height(),
                cbr.height
            ))));
        }

        with_block(block)?;
    }

    if !from_height_found {
        let from_height = from_height.expect("can only reach here if set");
        return Err(to_chain_error(FsBlockDbError::CacheMiss(from_height)));
    }

    Ok(())
}

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use crate::{testing, wallet::sapling::tests::SaplingPoolTester};

    #[cfg(feature = "orchard")]
    use crate::wallet::orchard::tests::OrchardPoolTester;

    #[test]
    fn valid_chain_states_sapling() {
        testing::pool::valid_chain_states::<SaplingPoolTester>()
    }

    #[test]
    #[cfg(feature = "orchard")]
    fn valid_chain_states_orchard() {
        testing::pool::valid_chain_states::<OrchardPoolTester>()
    }

    // FIXME: This requires test framework fixes to pass.
    #[test]
    #[cfg(feature = "orchard")]
    fn invalid_chain_cache_disconnected_sapling() {
        testing::pool::invalid_chain_cache_disconnected::<SaplingPoolTester>()
    }

    #[test]
    #[cfg(feature = "orchard")]
    fn invalid_chain_cache_disconnected_orchard() {
        testing::pool::invalid_chain_cache_disconnected::<OrchardPoolTester>()
    }

    #[test]
    fn data_db_truncation_sapling() {
        testing::pool::data_db_truncation::<SaplingPoolTester>()
    }

    #[test]
    #[cfg(feature = "orchard")]
    fn data_db_truncation_orchard() {
        testing::pool::data_db_truncation::<OrchardPoolTester>()
    }

    #[test]
    fn scan_cached_blocks_allows_blocks_out_of_order_sapling() {
        testing::pool::scan_cached_blocks_allows_blocks_out_of_order::<SaplingPoolTester>()
    }

    #[test]
    #[cfg(feature = "orchard")]
    fn scan_cached_blocks_allows_blocks_out_of_order_orchard() {
        testing::pool::scan_cached_blocks_allows_blocks_out_of_order::<OrchardPoolTester>()
    }

    #[test]
    fn scan_cached_blocks_finds_received_notes_sapling() {
        testing::pool::scan_cached_blocks_finds_received_notes::<SaplingPoolTester>()
    }

    #[test]
    #[cfg(feature = "orchard")]
    fn scan_cached_blocks_finds_received_notes_orchard() {
        testing::pool::scan_cached_blocks_finds_received_notes::<OrchardPoolTester>()
    }

    #[test]
    fn scan_cached_blocks_finds_change_notes_sapling() {
        testing::pool::scan_cached_blocks_finds_change_notes::<SaplingPoolTester>()
    }

    #[test]
    #[cfg(feature = "orchard")]
    fn scan_cached_blocks_finds_change_notes_orchard() {
        testing::pool::scan_cached_blocks_finds_change_notes::<OrchardPoolTester>()
    }

    #[test]
    fn scan_cached_blocks_detects_spends_out_of_order_sapling() {
        testing::pool::scan_cached_blocks_detects_spends_out_of_order::<SaplingPoolTester>()
    }

    #[test]
    #[cfg(feature = "orchard")]
    fn scan_cached_blocks_detects_spends_out_of_order_orchard() {
        testing::pool::scan_cached_blocks_detects_spends_out_of_order::<OrchardPoolTester>()
    }
}
