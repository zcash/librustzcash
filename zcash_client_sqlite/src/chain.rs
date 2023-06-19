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
/// Starting at the next block above `last_scanned_height`, the `with_row` callback is invoked with
/// each block retrieved from the backing store. If the `limit` value provided is `None`, all
/// blocks are traversed up to the maximum height.
pub(crate) fn blockdb_with_blocks<F, DbErrT, NoteRef>(
    block_source: &BlockDb,
    last_scanned_height: Option<BlockHeight>,
    limit: Option<u32>,
    mut with_row: F,
) -> Result<(), Error<DbErrT, SqliteClientError, NoteRef>>
where
    F: FnMut(CompactBlock) -> Result<(), Error<DbErrT, SqliteClientError, NoteRef>>,
{
    fn to_chain_error<D, E: Into<SqliteClientError>, N>(err: E) -> Error<D, SqliteClientError, N> {
        Error::BlockSource(err.into())
    }

    // Fetch the CompactBlocks we need to scan
    let mut stmt_blocks = block_source
        .0
        .prepare(
            "SELECT height, data FROM compactblocks 
            WHERE height > ? 
            ORDER BY height ASC LIMIT ?",
        )
        .map_err(to_chain_error)?;

    let mut rows = stmt_blocks
        .query(params![
            last_scanned_height.map_or(0u32, u32::from),
            limit.unwrap_or(u32::max_value()),
        ])
        .map_err(to_chain_error)?;

    while let Some(row) = rows.next().map_err(to_chain_error)? {
        let height = BlockHeight::from_u32(row.get(0).map_err(to_chain_error)?);
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
    let mut stmt_insert = conn.prepare(
        "INSERT INTO compactblocks_meta (height, blockhash, time, sapling_outputs_count, orchard_actions_count)
        VALUES (?, ?, ?, ?, ?)"
    )?;

    conn.execute("BEGIN IMMEDIATE", [])?;
    let result = block_meta
        .iter()
        .map(|m| {
            stmt_insert.execute(params![
                u32::from(m.height),
                &m.block_hash.0[..],
                m.block_time,
                m.sapling_outputs_count,
                m.orchard_actions_count,
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
/// Starting at the next block height above `last_scanned_height`, the `with_row` callback is
/// invoked with each block retrieved from the backing store. If the `limit` value provided is
/// `None`, all blocks are traversed up to the maximum height for which metadata is available.
#[cfg(feature = "unstable")]
pub(crate) fn fsblockdb_with_blocks<F, DbErrT, NoteRef>(
    cache: &FsBlockDb,
    last_scanned_height: Option<BlockHeight>,
    limit: Option<u32>,
    mut with_block: F,
) -> Result<(), Error<DbErrT, FsBlockDbError, NoteRef>>
where
    F: FnMut(CompactBlock) -> Result<(), Error<DbErrT, FsBlockDbError, NoteRef>>,
{
    fn to_chain_error<D, E: Into<FsBlockDbError>, N>(err: E) -> Error<D, FsBlockDbError, N> {
        Error::BlockSource(err.into())
    }

    // Fetch the CompactBlocks we need to scan
    let mut stmt_blocks = cache
        .conn
        .prepare(
            "SELECT height, blockhash, time, sapling_outputs_count, orchard_actions_count
             FROM compactblocks_meta
             WHERE height > ?
             ORDER BY height ASC LIMIT ?",
        )
        .map_err(to_chain_error)?;

    let rows = stmt_blocks
        .query_map(
            params![
                last_scanned_height.map_or(0u32, u32::from),
                limit.unwrap_or(u32::max_value()),
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

    for row_result in rows {
        let cbr = row_result.map_err(to_chain_error)?;
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

    Ok(())
}

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use secrecy::Secret;
    use tempfile::NamedTempFile;

    use zcash_primitives::{
        block::BlockHash, transaction::components::Amount, zip32::ExtendedSpendingKey,
    };

    use zcash_client_backend::data_api::chain::{
        error::{Cause, Error},
        scan_cached_blocks, validate_chain,
    };
    use zcash_client_backend::data_api::WalletRead;

    use crate::{
        chain::init::init_cache_database,
        tests::{
            self, fake_compact_block, fake_compact_block_spending, init_test_accounts_table,
            insert_into_cache, sapling_activation_height, AddressType,
        },
        wallet::{get_balance, init::init_wallet_db, truncate_to_height},
        AccountId, BlockDb, WalletDb,
    };

    #[test]
    fn valid_chain_states() {
        let cache_file = NamedTempFile::new().unwrap();
        let db_cache = BlockDb::for_path(cache_file.path()).unwrap();
        init_cache_database(&db_cache).unwrap();

        let data_file = NamedTempFile::new().unwrap();
        let mut db_data = WalletDb::for_path(data_file.path(), tests::network()).unwrap();
        init_wallet_db(&mut db_data, Some(Secret::new(vec![]))).unwrap();

        // Add an account to the wallet
        let (dfvk, _taddr) = init_test_accounts_table(&db_data);

        // Empty chain should return None
        assert_matches!(db_data.get_max_height_hash(), Ok(None));

        // Create a fake CompactBlock sending value to the address
        let fake_block_hash = BlockHash([0; 32]);
        let fake_block_height = sapling_activation_height();

        let (cb, _) = fake_compact_block(
            fake_block_height,
            fake_block_hash,
            &dfvk,
            AddressType::DefaultExternal,
            Amount::from_u64(5).unwrap(),
        );

        insert_into_cache(&db_cache, &cb);

        // Cache-only chain should be valid
        let validate_chain_result = validate_chain(
            &db_cache,
            Some((fake_block_height, fake_block_hash)),
            Some(1),
        );

        assert_matches!(validate_chain_result, Ok(()));

        // Scan the cache
        let mut db_write = db_data.get_update_ops().unwrap();
        scan_cached_blocks(&tests::network(), &db_cache, &mut db_write, None).unwrap();

        // Data-only chain should be valid
        validate_chain(&db_cache, db_data.get_max_height_hash().unwrap(), None).unwrap();

        // Create a second fake CompactBlock sending more value to the address
        let (cb2, _) = fake_compact_block(
            sapling_activation_height() + 1,
            cb.hash(),
            &dfvk,
            AddressType::DefaultExternal,
            Amount::from_u64(7).unwrap(),
        );
        insert_into_cache(&db_cache, &cb2);

        // Data+cache chain should be valid
        validate_chain(&db_cache, db_data.get_max_height_hash().unwrap(), None).unwrap();

        // Scan the cache again
        scan_cached_blocks(&tests::network(), &db_cache, &mut db_write, None).unwrap();

        // Data-only chain should be valid
        validate_chain(&db_cache, db_data.get_max_height_hash().unwrap(), None).unwrap();
    }

    #[test]
    fn invalid_chain_cache_disconnected() {
        let cache_file = NamedTempFile::new().unwrap();
        let db_cache = BlockDb::for_path(cache_file.path()).unwrap();
        init_cache_database(&db_cache).unwrap();

        let data_file = NamedTempFile::new().unwrap();
        let mut db_data = WalletDb::for_path(data_file.path(), tests::network()).unwrap();
        init_wallet_db(&mut db_data, Some(Secret::new(vec![]))).unwrap();

        // Add an account to the wallet
        let (dfvk, _taddr) = init_test_accounts_table(&db_data);

        // Create some fake CompactBlocks
        let (cb, _) = fake_compact_block(
            sapling_activation_height(),
            BlockHash([0; 32]),
            &dfvk,
            AddressType::DefaultExternal,
            Amount::from_u64(5).unwrap(),
        );
        let (cb2, _) = fake_compact_block(
            sapling_activation_height() + 1,
            cb.hash(),
            &dfvk,
            AddressType::DefaultExternal,
            Amount::from_u64(7).unwrap(),
        );
        insert_into_cache(&db_cache, &cb);
        insert_into_cache(&db_cache, &cb2);

        // Scan the cache
        let mut db_write = db_data.get_update_ops().unwrap();
        scan_cached_blocks(&tests::network(), &db_cache, &mut db_write, None).unwrap();

        // Data-only chain should be valid
        validate_chain(&db_cache, db_data.get_max_height_hash().unwrap(), None).unwrap();

        // Create more fake CompactBlocks that don't connect to the scanned ones
        let (cb3, _) = fake_compact_block(
            sapling_activation_height() + 2,
            BlockHash([1; 32]),
            &dfvk,
            AddressType::DefaultExternal,
            Amount::from_u64(8).unwrap(),
        );
        let (cb4, _) = fake_compact_block(
            sapling_activation_height() + 3,
            cb3.hash(),
            &dfvk,
            AddressType::DefaultExternal,
            Amount::from_u64(3).unwrap(),
        );
        insert_into_cache(&db_cache, &cb3);
        insert_into_cache(&db_cache, &cb4);

        // Data+cache chain should be invalid at the data/cache boundary
        let val_result = validate_chain(&db_cache, db_data.get_max_height_hash().unwrap(), None);

        assert_matches!(val_result, Err(Error::Chain(e)) if e.at_height() == sapling_activation_height() + 2);
    }

    #[test]
    fn invalid_chain_cache_reorg() {
        let cache_file = NamedTempFile::new().unwrap();
        let db_cache = BlockDb::for_path(cache_file.path()).unwrap();
        init_cache_database(&db_cache).unwrap();

        let data_file = NamedTempFile::new().unwrap();
        let mut db_data = WalletDb::for_path(data_file.path(), tests::network()).unwrap();
        init_wallet_db(&mut db_data, Some(Secret::new(vec![]))).unwrap();

        // Add an account to the wallet
        let (dfvk, _taddr) = init_test_accounts_table(&db_data);

        // Create some fake CompactBlocks
        let (cb, _) = fake_compact_block(
            sapling_activation_height(),
            BlockHash([0; 32]),
            &dfvk,
            AddressType::DefaultExternal,
            Amount::from_u64(5).unwrap(),
        );
        let (cb2, _) = fake_compact_block(
            sapling_activation_height() + 1,
            cb.hash(),
            &dfvk,
            AddressType::DefaultExternal,
            Amount::from_u64(7).unwrap(),
        );
        insert_into_cache(&db_cache, &cb);
        insert_into_cache(&db_cache, &cb2);

        // Scan the cache
        let mut db_write = db_data.get_update_ops().unwrap();
        scan_cached_blocks(&tests::network(), &db_cache, &mut db_write, None).unwrap();

        // Data-only chain should be valid
        validate_chain(&db_cache, db_data.get_max_height_hash().unwrap(), None).unwrap();

        // Create more fake CompactBlocks that contain a reorg
        let (cb3, _) = fake_compact_block(
            sapling_activation_height() + 2,
            cb2.hash(),
            &dfvk,
            AddressType::DefaultExternal,
            Amount::from_u64(8).unwrap(),
        );
        let (cb4, _) = fake_compact_block(
            sapling_activation_height() + 3,
            BlockHash([1; 32]),
            &dfvk,
            AddressType::DefaultExternal,
            Amount::from_u64(3).unwrap(),
        );
        insert_into_cache(&db_cache, &cb3);
        insert_into_cache(&db_cache, &cb4);

        // Data+cache chain should be invalid inside the cache
        let val_result = validate_chain(&db_cache, db_data.get_max_height_hash().unwrap(), None);

        assert_matches!(val_result, Err(Error::Chain(e)) if e.at_height() == sapling_activation_height() + 3);
    }

    #[test]
    fn data_db_truncation() {
        let cache_file = NamedTempFile::new().unwrap();
        let db_cache = BlockDb::for_path(cache_file.path()).unwrap();
        init_cache_database(&db_cache).unwrap();

        let data_file = NamedTempFile::new().unwrap();
        let mut db_data = WalletDb::for_path(data_file.path(), tests::network()).unwrap();
        init_wallet_db(&mut db_data, Some(Secret::new(vec![]))).unwrap();

        // Add an account to the wallet
        let (dfvk, _taddr) = init_test_accounts_table(&db_data);

        // Account balance should be zero
        assert_eq!(
            get_balance(&db_data, AccountId::from(0)).unwrap(),
            Amount::zero()
        );

        // Create fake CompactBlocks sending value to the address
        let value = Amount::from_u64(5).unwrap();
        let value2 = Amount::from_u64(7).unwrap();
        let (cb, _) = fake_compact_block(
            sapling_activation_height(),
            BlockHash([0; 32]),
            &dfvk,
            AddressType::DefaultExternal,
            value,
        );

        let (cb2, _) = fake_compact_block(
            sapling_activation_height() + 1,
            cb.hash(),
            &dfvk,
            AddressType::DefaultExternal,
            value2,
        );
        insert_into_cache(&db_cache, &cb);
        insert_into_cache(&db_cache, &cb2);

        // Scan the cache
        let mut db_write = db_data.get_update_ops().unwrap();
        scan_cached_blocks(&tests::network(), &db_cache, &mut db_write, None).unwrap();

        // Account balance should reflect both received notes
        assert_eq!(
            get_balance(&db_data, AccountId::from(0)).unwrap(),
            (value + value2).unwrap()
        );

        // "Rewind" to height of last scanned block
        truncate_to_height(&db_data, sapling_activation_height() + 1).unwrap();

        // Account balance should be unaltered
        assert_eq!(
            get_balance(&db_data, AccountId::from(0)).unwrap(),
            (value + value2).unwrap()
        );

        // Rewind so that one block is dropped
        truncate_to_height(&db_data, sapling_activation_height()).unwrap();

        // Account balance should only contain the first received note
        assert_eq!(get_balance(&db_data, AccountId::from(0)).unwrap(), value);

        // Scan the cache again
        scan_cached_blocks(&tests::network(), &db_cache, &mut db_write, None).unwrap();

        // Account balance should again reflect both received notes
        assert_eq!(
            get_balance(&db_data, AccountId::from(0)).unwrap(),
            (value + value2).unwrap()
        );
    }

    #[test]
    fn scan_cached_blocks_requires_sequential_blocks() {
        let cache_file = NamedTempFile::new().unwrap();
        let db_cache = BlockDb::for_path(cache_file.path()).unwrap();
        init_cache_database(&db_cache).unwrap();

        let data_file = NamedTempFile::new().unwrap();
        let mut db_data = WalletDb::for_path(data_file.path(), tests::network()).unwrap();
        init_wallet_db(&mut db_data, Some(Secret::new(vec![]))).unwrap();

        // Add an account to the wallet
        let (dfvk, _taddr) = init_test_accounts_table(&db_data);

        // Create a block with height SAPLING_ACTIVATION_HEIGHT
        let value = Amount::from_u64(50000).unwrap();
        let (cb1, _) = fake_compact_block(
            sapling_activation_height(),
            BlockHash([0; 32]),
            &dfvk,
            AddressType::DefaultExternal,
            value,
        );
        insert_into_cache(&db_cache, &cb1);
        let mut db_write = db_data.get_update_ops().unwrap();
        scan_cached_blocks(&tests::network(), &db_cache, &mut db_write, None).unwrap();
        assert_eq!(get_balance(&db_data, AccountId::from(0)).unwrap(), value);

        // We cannot scan a block of height SAPLING_ACTIVATION_HEIGHT + 2 next
        let (cb2, _) = fake_compact_block(
            sapling_activation_height() + 1,
            cb1.hash(),
            &dfvk,
            AddressType::DefaultExternal,
            value,
        );
        let (cb3, _) = fake_compact_block(
            sapling_activation_height() + 2,
            cb2.hash(),
            &dfvk,
            AddressType::DefaultExternal,
            value,
        );
        insert_into_cache(&db_cache, &cb3);
        match scan_cached_blocks(&tests::network(), &db_cache, &mut db_write, None) {
            Err(Error::Chain(e)) => {
                assert_matches!(
                    e.cause(),
                    Cause::BlockHeightDiscontinuity(h) if *h
                        == sapling_activation_height() + 2
                );
            }
            Ok(_) | Err(_) => panic!("Should have failed"),
        }

        // If we add a block of height SAPLING_ACTIVATION_HEIGHT + 1, we can now scan both
        insert_into_cache(&db_cache, &cb2);
        scan_cached_blocks(&tests::network(), &db_cache, &mut db_write, None).unwrap();
        assert_eq!(
            get_balance(&db_data, AccountId::from(0)).unwrap(),
            Amount::from_u64(150_000).unwrap()
        );
    }

    #[test]
    fn scan_cached_blocks_finds_received_notes() {
        let cache_file = NamedTempFile::new().unwrap();
        let db_cache = BlockDb::for_path(cache_file.path()).unwrap();
        init_cache_database(&db_cache).unwrap();

        let data_file = NamedTempFile::new().unwrap();
        let mut db_data = WalletDb::for_path(data_file.path(), tests::network()).unwrap();
        init_wallet_db(&mut db_data, Some(Secret::new(vec![]))).unwrap();

        // Add an account to the wallet
        let (dfvk, _taddr) = init_test_accounts_table(&db_data);

        // Account balance should be zero
        assert_eq!(
            get_balance(&db_data, AccountId::from(0)).unwrap(),
            Amount::zero()
        );

        // Create a fake CompactBlock sending value to the address
        let value = Amount::from_u64(5).unwrap();
        let (cb, _) = fake_compact_block(
            sapling_activation_height(),
            BlockHash([0; 32]),
            &dfvk,
            AddressType::DefaultExternal,
            value,
        );
        insert_into_cache(&db_cache, &cb);

        // Scan the cache
        let mut db_write = db_data.get_update_ops().unwrap();
        scan_cached_blocks(&tests::network(), &db_cache, &mut db_write, None).unwrap();

        // Account balance should reflect the received note
        assert_eq!(get_balance(&db_data, AccountId::from(0)).unwrap(), value);

        // Create a second fake CompactBlock sending more value to the address
        let value2 = Amount::from_u64(7).unwrap();
        let (cb2, _) = fake_compact_block(
            sapling_activation_height() + 1,
            cb.hash(),
            &dfvk,
            AddressType::DefaultExternal,
            value2,
        );
        insert_into_cache(&db_cache, &cb2);

        // Scan the cache again
        scan_cached_blocks(&tests::network(), &db_cache, &mut db_write, None).unwrap();

        // Account balance should reflect both received notes
        assert_eq!(
            get_balance(&db_data, AccountId::from(0)).unwrap(),
            (value + value2).unwrap()
        );
    }

    #[test]
    fn scan_cached_blocks_finds_change_notes() {
        let cache_file = NamedTempFile::new().unwrap();
        let db_cache = BlockDb::for_path(cache_file.path()).unwrap();
        init_cache_database(&db_cache).unwrap();

        let data_file = NamedTempFile::new().unwrap();
        let mut db_data = WalletDb::for_path(data_file.path(), tests::network()).unwrap();
        init_wallet_db(&mut db_data, Some(Secret::new(vec![]))).unwrap();

        // Add an account to the wallet
        let (dfvk, _taddr) = init_test_accounts_table(&db_data);

        // Account balance should be zero
        assert_eq!(
            get_balance(&db_data, AccountId::from(0)).unwrap(),
            Amount::zero()
        );

        // Create a fake CompactBlock sending value to the address
        let value = Amount::from_u64(5).unwrap();
        let (cb, nf) = fake_compact_block(
            sapling_activation_height(),
            BlockHash([0; 32]),
            &dfvk,
            AddressType::DefaultExternal,
            value,
        );
        insert_into_cache(&db_cache, &cb);

        // Scan the cache
        let mut db_write = db_data.get_update_ops().unwrap();
        scan_cached_blocks(&tests::network(), &db_cache, &mut db_write, None).unwrap();

        // Account balance should reflect the received note
        assert_eq!(get_balance(&db_data, AccountId::from(0)).unwrap(), value);

        // Create a second fake CompactBlock spending value from the address
        let extsk2 = ExtendedSpendingKey::master(&[0]);
        let to2 = extsk2.default_address().1;
        let value2 = Amount::from_u64(2).unwrap();
        insert_into_cache(
            &db_cache,
            &fake_compact_block_spending(
                sapling_activation_height() + 1,
                cb.hash(),
                (nf, value),
                &dfvk,
                to2,
                value2,
            ),
        );

        // Scan the cache again
        scan_cached_blocks(&tests::network(), &db_cache, &mut db_write, None).unwrap();

        // Account balance should equal the change
        assert_eq!(
            get_balance(&db_data, AccountId::from(0)).unwrap(),
            (value - value2).unwrap()
        );
    }
}
