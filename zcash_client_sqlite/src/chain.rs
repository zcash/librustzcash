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
    use std::num::NonZeroU32;

    use secrecy::Secret;
    use tempfile::NamedTempFile;

    use zcash_primitives::{
        block::BlockHash,
        transaction::{components::Amount, fees::zip317::FeeRule},
        zip32::ExtendedSpendingKey,
    };

    use zcash_client_backend::{
        address::RecipientAddress,
        data_api::{
            chain::{error::Error, scan_cached_blocks},
            wallet::{input_selection::GreedyInputSelector, spend},
            WalletRead, WalletWrite,
        },
        fees::{zip317::SingleOutputChangeStrategy, DustOutputPolicy},
        scanning::ScanError,
        wallet::OvkPolicy,
        zip321::{Payment, TransactionRequest},
    };

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
        let (dfvk, _taddr) = init_test_accounts_table(&mut db_data);

        // Empty chain should return None
        assert_matches!(db_data.get_max_height_hash(), Ok(None));

        // Create a fake CompactBlock sending value to the address
        let (cb, _) = fake_compact_block(
            sapling_activation_height(),
            BlockHash([0; 32]),
            &dfvk,
            AddressType::DefaultExternal,
            Amount::from_u64(5).unwrap(),
            0,
        );

        insert_into_cache(&db_cache, &cb);

        // Scan the cache
        scan_cached_blocks(
            &tests::network(),
            &db_cache,
            &mut db_data,
            sapling_activation_height(),
            1,
        )
        .unwrap();

        // Create a second fake CompactBlock sending more value to the address
        let (cb2, _) = fake_compact_block(
            sapling_activation_height() + 1,
            cb.hash(),
            &dfvk,
            AddressType::DefaultExternal,
            Amount::from_u64(7).unwrap(),
            1,
        );

        insert_into_cache(&db_cache, &cb2);

        // Scanning should detect no inconsistencies
        assert_matches!(
            scan_cached_blocks(
                &tests::network(),
                &db_cache,
                &mut db_data,
                sapling_activation_height() + 1,
                1,
            ),
            Ok(())
        );
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
        let (dfvk, _taddr) = init_test_accounts_table(&mut db_data);

        // Create some fake CompactBlocks
        let (cb, _) = fake_compact_block(
            sapling_activation_height(),
            BlockHash([0; 32]),
            &dfvk,
            AddressType::DefaultExternal,
            Amount::from_u64(5).unwrap(),
            0,
        );
        let (cb2, _) = fake_compact_block(
            sapling_activation_height() + 1,
            cb.hash(),
            &dfvk,
            AddressType::DefaultExternal,
            Amount::from_u64(7).unwrap(),
            1,
        );
        insert_into_cache(&db_cache, &cb);
        insert_into_cache(&db_cache, &cb2);

        // Scanning the cache should find no inconsistencies
        assert_matches!(
            scan_cached_blocks(
                &tests::network(),
                &db_cache,
                &mut db_data,
                sapling_activation_height(),
                2,
            ),
            Ok(())
        );

        // Create more fake CompactBlocks that don't connect to the scanned ones
        let (cb3, _) = fake_compact_block(
            sapling_activation_height() + 2,
            BlockHash([1; 32]),
            &dfvk,
            AddressType::DefaultExternal,
            Amount::from_u64(8).unwrap(),
            2,
        );
        let (cb4, _) = fake_compact_block(
            sapling_activation_height() + 3,
            cb3.hash(),
            &dfvk,
            AddressType::DefaultExternal,
            Amount::from_u64(3).unwrap(),
            3,
        );
        insert_into_cache(&db_cache, &cb3);
        insert_into_cache(&db_cache, &cb4);

        // Data+cache chain should be invalid at the data/cache boundary
        assert_matches!(
            scan_cached_blocks(
                &tests::network(),
                &db_cache,
                &mut db_data,
                sapling_activation_height() + 2,
                2
            ),
            Err(Error::Scan(ScanError::PrevHashMismatch { at_height }))
                if at_height == sapling_activation_height() + 2
        );
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
        let (dfvk, _taddr) = init_test_accounts_table(&mut db_data);

        // Account balance should be zero
        assert_eq!(
            get_balance(&db_data.conn, AccountId::from(0)).unwrap(),
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
            0,
        );

        let (cb2, _) = fake_compact_block(
            sapling_activation_height() + 1,
            cb.hash(),
            &dfvk,
            AddressType::DefaultExternal,
            value2,
            1,
        );
        insert_into_cache(&db_cache, &cb);
        insert_into_cache(&db_cache, &cb2);

        // Scan the cache
        scan_cached_blocks(
            &tests::network(),
            &db_cache,
            &mut db_data,
            sapling_activation_height(),
            2,
        )
        .unwrap();

        // Account balance should reflect both received notes
        assert_eq!(
            get_balance(&db_data.conn, AccountId::from(0)).unwrap(),
            (value + value2).unwrap()
        );

        // "Rewind" to height of last scanned block
        db_data
            .transactionally(|wdb| {
                truncate_to_height(wdb.conn.0, &wdb.params, sapling_activation_height() + 1)
            })
            .unwrap();

        // Account balance should be unaltered
        assert_eq!(
            get_balance(&db_data.conn, AccountId::from(0)).unwrap(),
            (value + value2).unwrap()
        );

        // Rewind so that one block is dropped
        db_data
            .transactionally(|wdb| {
                truncate_to_height(wdb.conn.0, &wdb.params, sapling_activation_height())
            })
            .unwrap();

        // Account balance should only contain the first received note
        assert_eq!(
            get_balance(&db_data.conn, AccountId::from(0)).unwrap(),
            value
        );

        // Scan the cache again
        scan_cached_blocks(
            &tests::network(),
            &db_cache,
            &mut db_data,
            sapling_activation_height(),
            2,
        )
        .unwrap();

        // Account balance should again reflect both received notes
        assert_eq!(
            get_balance(&db_data.conn, AccountId::from(0)).unwrap(),
            (value + value2).unwrap()
        );
    }

    #[test]
    fn scan_cached_blocks_allows_blocks_out_of_order() {
        let cache_file = NamedTempFile::new().unwrap();
        let db_cache = BlockDb::for_path(cache_file.path()).unwrap();
        init_cache_database(&db_cache).unwrap();

        let data_file = NamedTempFile::new().unwrap();
        let mut db_data = WalletDb::for_path(data_file.path(), tests::network()).unwrap();
        init_wallet_db(&mut db_data, Some(Secret::new(vec![]))).unwrap();

        // Add an account to the wallet
        let seed = Secret::new([0u8; 32].to_vec());
        let (_, usk) = db_data.create_account(&seed).unwrap();
        let dfvk = usk.sapling().to_diversifiable_full_viewing_key();

        // Create a block with height SAPLING_ACTIVATION_HEIGHT
        let value = Amount::from_u64(50000).unwrap();
        let (cb1, _) = fake_compact_block(
            sapling_activation_height(),
            BlockHash([0; 32]),
            &dfvk,
            AddressType::DefaultExternal,
            value,
            0,
        );
        insert_into_cache(&db_cache, &cb1);
        scan_cached_blocks(
            &tests::network(),
            &db_cache,
            &mut db_data,
            sapling_activation_height(),
            1,
        )
        .unwrap();
        assert_eq!(
            get_balance(&db_data.conn, AccountId::from(0)).unwrap(),
            value
        );

        // Create blocks to reach SAPLING_ACTIVATION_HEIGHT + 2
        let (cb2, _) = fake_compact_block(
            sapling_activation_height() + 1,
            cb1.hash(),
            &dfvk,
            AddressType::DefaultExternal,
            value,
            1,
        );
        let (cb3, _) = fake_compact_block(
            sapling_activation_height() + 2,
            cb2.hash(),
            &dfvk,
            AddressType::DefaultExternal,
            value,
            2,
        );

        // Scan the later block first
        insert_into_cache(&db_cache, &cb3);
        assert_matches!(
            scan_cached_blocks(
                &tests::network(),
                &db_cache,
                &mut db_data,
                sapling_activation_height() + 2,
                1
            ),
            Ok(_)
        );

        // If we add a block of height SAPLING_ACTIVATION_HEIGHT + 1, we can now scan that
        insert_into_cache(&db_cache, &cb2);
        scan_cached_blocks(
            &tests::network(),
            &db_cache,
            &mut db_data,
            sapling_activation_height() + 1,
            1,
        )
        .unwrap();
        assert_eq!(
            get_balance(&db_data.conn, AccountId::from(0)).unwrap(),
            Amount::from_u64(150_000).unwrap()
        );

        // We can spend the received notes
        let req = TransactionRequest::new(vec![Payment {
            recipient_address: RecipientAddress::Shielded(dfvk.default_address().1),
            amount: Amount::from_u64(110_000).unwrap(),
            memo: None,
            label: None,
            message: None,
            other_params: vec![],
        }])
        .unwrap();
        let input_selector = GreedyInputSelector::new(
            SingleOutputChangeStrategy::new(FeeRule::standard()),
            DustOutputPolicy::default(),
        );
        assert_matches!(
            spend(
                &mut db_data,
                &tests::network(),
                crate::wallet::sapling::tests::test_prover(),
                &input_selector,
                &usk,
                req,
                OvkPolicy::Sender,
                NonZeroU32::new(1).unwrap(),
            ),
            Ok(_)
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
        let (dfvk, _taddr) = init_test_accounts_table(&mut db_data);

        // Account balance should be zero
        assert_eq!(
            get_balance(&db_data.conn, AccountId::from(0)).unwrap(),
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
            0,
        );
        insert_into_cache(&db_cache, &cb);

        // Scan the cache
        scan_cached_blocks(
            &tests::network(),
            &db_cache,
            &mut db_data,
            sapling_activation_height(),
            1,
        )
        .unwrap();

        // Account balance should reflect the received note
        assert_eq!(
            get_balance(&db_data.conn, AccountId::from(0)).unwrap(),
            value
        );

        // Create a second fake CompactBlock sending more value to the address
        let value2 = Amount::from_u64(7).unwrap();
        let (cb2, _) = fake_compact_block(
            sapling_activation_height() + 1,
            cb.hash(),
            &dfvk,
            AddressType::DefaultExternal,
            value2,
            1,
        );
        insert_into_cache(&db_cache, &cb2);

        // Scan the cache again
        scan_cached_blocks(
            &tests::network(),
            &db_cache,
            &mut db_data,
            sapling_activation_height() + 1,
            1,
        )
        .unwrap();

        // Account balance should reflect both received notes
        assert_eq!(
            get_balance(&db_data.conn, AccountId::from(0)).unwrap(),
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
        let (dfvk, _taddr) = init_test_accounts_table(&mut db_data);

        // Account balance should be zero
        assert_eq!(
            get_balance(&db_data.conn, AccountId::from(0)).unwrap(),
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
            0,
        );
        insert_into_cache(&db_cache, &cb);

        // Scan the cache
        scan_cached_blocks(
            &tests::network(),
            &db_cache,
            &mut db_data,
            sapling_activation_height(),
            1,
        )
        .unwrap();

        // Account balance should reflect the received note
        assert_eq!(
            get_balance(&db_data.conn, AccountId::from(0)).unwrap(),
            value
        );

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
                1,
            ),
        );

        // Scan the cache again
        scan_cached_blocks(
            &tests::network(),
            &db_cache,
            &mut db_data,
            sapling_activation_height() + 1,
            1,
        )
        .unwrap();

        // Account balance should equal the change
        assert_eq!(
            get_balance(&db_data.conn, AccountId::from(0)).unwrap(),
            (value - value2).unwrap()
        );
    }
}
