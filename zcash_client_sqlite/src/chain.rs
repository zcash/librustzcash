//! Functions for enforcing chain validity and handling chain reorgs.
//!
//! # Examples
//!
//! ```
//! use tempfile::NamedTempFile;
//! use zcash_primitives::{
//!     consensus::{BlockHeight, Network, Parameters}
//! };
//!
//! use zcash_client_backend::{
//!     data_api::{
//!         WalletRead,
//!         chain::{
//!             validate_chain,
//!             scan_cached_blocks,
//!         },
//!         error::Error,
//!     }
//! };
//!
//! use zcash_client_sqlite::{
//!     BlockDB,
//!     WalletDB,
//!     wallet::{rewind_to_height},
//! };
//!
//! let network = Network::TestNetwork;
//! let cache_file = NamedTempFile::new().unwrap();
//! let db_cache = BlockDB::for_path(cache_file).unwrap();
//! let data_file = NamedTempFile::new().unwrap();
//! let db_data = WalletDB::for_path(data_file).unwrap();
//!
//! // 1) Download new CompactBlocks into db_cache.
//!
//! // 2) Run the chain validator on the received blocks.
//! //
//! // Given that we assume the server always gives us correct-at-the-time blocks, any
//! // errors are in the blocks we have previously cached or scanned.
//! if let Err(e) = validate_chain(&network, &db_cache, (&db_data).get_max_height_hash().unwrap()) {
//!     match e.0 {
//!         Error::InvalidChain(upper_bound, _) => {
//!             // a) Pick a height to rewind to.
//!             //
//!             // This might be informed by some external chain reorg information, or
//!             // heuristics such as the platform, available bandwidth, size of recent
//!             // CompactBlocks, etc.
//!             let rewind_height = upper_bound - 10;
//!
//!             // b) Rewind scanned block information.
//!             rewind_to_height(&db_data, &network, rewind_height);
//!
//!             // c) Delete cached blocks from rewind_height onwards.
//!             //
//!             // This does imply that assumed-valid blocks will be re-downloaded, but it
//!             // is also possible that in the intervening time, a chain reorg has
//!             // occurred that orphaned some of those blocks.
//!
//!             // d) If there is some separate thread or service downloading
//!             // CompactBlocks, tell it to go back and download from rewind_height
//!             // onwards.
//!         }
//!         _ => {
//!             // Handle other errors.
//!         }
//!     }
//! }
//!
//! // 3) Scan (any remaining) cached blocks.
//! //
//! // At this point, the cache and scanned data are locally consistent (though not
//! // necessarily consistent with the latest chain tip - this would be discovered the
//! // next time this codepath is executed after new blocks are received).
//! scan_cached_blocks(&network, &db_cache, &db_data, None);
//! ```
use protobuf::parse_from_bytes;

use rusqlite::types::ToSql;

use zcash_primitives::consensus::BlockHeight;

use zcash_client_backend::{data_api::error::Error, proto::compact_formats::CompactBlock};

use crate::{error::SqliteClientError, BlockDB};

pub mod init;

struct CompactBlockRow {
    height: BlockHeight,
    data: Vec<u8>,
}

pub fn with_blocks<F>(
    cache: &BlockDB,
    from_height: BlockHeight,
    limit: Option<u32>,
    mut with_row: F,
) -> Result<(), SqliteClientError>
where
    F: FnMut(CompactBlock) -> Result<(), SqliteClientError>,
{
    // Fetch the CompactBlocks we need to scan
    let mut stmt_blocks = cache.0.prepare(
        "SELECT height, data FROM compactblocks WHERE height > ? ORDER BY height ASC LIMIT ?",
    )?;
    let rows = stmt_blocks.query_map(
        &[
            u32::from(from_height).to_sql()?,
            limit.unwrap_or(u32::max_value()).to_sql()?,
        ],
        |row| {
            Ok(CompactBlockRow {
                height: BlockHeight::from_u32(row.get(0)?),
                data: row.get(1)?,
            })
        },
    )?;

    for row_result in rows {
        let cbr = row_result?;
        let block: CompactBlock = parse_from_bytes(&cbr.data)?;

        if block.height() != cbr.height {
            return Err(Error::CorruptedData(format!(
                "Block height {} did not match row's height field value {}",
                block.height(),
                cbr.height
            ))
            .into());
        }

        with_row(block)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use rusqlite::Connection;
    use tempfile::NamedTempFile;

    use zcash_primitives::{
        block::BlockHash,
        transaction::components::Amount,
        zip32::{ExtendedFullViewingKey, ExtendedSpendingKey},
    };

    use zcash_client_backend::data_api::WalletRead;
    use zcash_client_backend::data_api::{
        chain::{scan_cached_blocks, validate_chain},
        error::{ChainInvalid, Error},
    };

    use crate::{
        chain::init::init_cache_database,
        tests::{
            self, fake_compact_block, fake_compact_block_spending, insert_into_cache,
            sapling_activation_height,
        },
        wallet::{
            get_balance,
            init::{init_accounts_table, init_data_database},
            rewind_to_height,
        },
        AccountId, BlockDB, WalletDB, NoteId,
    };

    #[test]
    fn valid_chain_states() {
        let cache_file = NamedTempFile::new().unwrap();
        let db_cache = BlockDB(Connection::open(cache_file.path()).unwrap());
        init_cache_database(&db_cache).unwrap();

        let data_file = NamedTempFile::new().unwrap();
        let db_data = WalletDB(Connection::open(data_file.path()).unwrap());
        init_data_database(&db_data).unwrap();

        // Add an account to the wallet
        let extsk = ExtendedSpendingKey::master(&[]);
        let extfvk = ExtendedFullViewingKey::from(&extsk);
        init_accounts_table(&db_data, &tests::network(), &[extfvk.clone()]).unwrap();

        // Empty chain should be valid
        validate_chain(
            &tests::network(),
            &db_cache,
            (&db_data).get_max_height_hash().unwrap(),
        )
        .unwrap();

        // Create a fake CompactBlock sending value to the address
        let (cb, _) = fake_compact_block(
            sapling_activation_height(),
            BlockHash([0; 32]),
            extfvk.clone(),
            Amount::from_u64(5).unwrap(),
        );
        insert_into_cache(&db_cache, &cb);

        // Cache-only chain should be valid
        validate_chain(
            &tests::network(),
            &db_cache,
            (&db_data).get_max_height_hash().unwrap(),
        )
        .unwrap();

        // Scan the cache
        scan_cached_blocks(&tests::network(), &db_cache, &db_data, None).unwrap();

        // Data-only chain should be valid
        validate_chain(
            &tests::network(),
            &db_cache,
            (&db_data).get_max_height_hash().unwrap(),
        )
        .unwrap();

        // Create a second fake CompactBlock sending more value to the address
        let (cb2, _) = fake_compact_block(
            sapling_activation_height() + 1,
            cb.hash(),
            extfvk,
            Amount::from_u64(7).unwrap(),
        );
        insert_into_cache(&db_cache, &cb2);

        // Data+cache chain should be valid
        validate_chain(
            &tests::network(),
            &db_cache,
            (&db_data).get_max_height_hash().unwrap(),
        )
        .unwrap();

        // Scan the cache again
        scan_cached_blocks(&tests::network(), &db_cache, &db_data, None).unwrap();

        // Data-only chain should be valid
        validate_chain(
            &tests::network(),
            &db_cache,
            (&db_data).get_max_height_hash().unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn invalid_chain_cache_disconnected() {
        let cache_file = NamedTempFile::new().unwrap();
        let db_cache = BlockDB(Connection::open(cache_file.path()).unwrap());
        init_cache_database(&db_cache).unwrap();

        let data_file = NamedTempFile::new().unwrap();
        let db_data = WalletDB(Connection::open(data_file.path()).unwrap());
        init_data_database(&db_data).unwrap();

        // Add an account to the wallet
        let extsk = ExtendedSpendingKey::master(&[]);
        let extfvk = ExtendedFullViewingKey::from(&extsk);
        init_accounts_table(&db_data, &tests::network(), &[extfvk.clone()]).unwrap();

        // Create some fake CompactBlocks
        let (cb, _) = fake_compact_block(
            sapling_activation_height(),
            BlockHash([0; 32]),
            extfvk.clone(),
            Amount::from_u64(5).unwrap(),
        );
        let (cb2, _) = fake_compact_block(
            sapling_activation_height() + 1,
            cb.hash(),
            extfvk.clone(),
            Amount::from_u64(7).unwrap(),
        );
        insert_into_cache(&db_cache, &cb);
        insert_into_cache(&db_cache, &cb2);

        // Scan the cache
        scan_cached_blocks(&tests::network(), &db_cache, &db_data, None).unwrap();

        // Data-only chain should be valid
        validate_chain(
            &tests::network(),
            &db_cache,
            (&db_data).get_max_height_hash().unwrap(),
        )
        .unwrap();

        // Create more fake CompactBlocks that don't connect to the scanned ones
        let (cb3, _) = fake_compact_block(
            sapling_activation_height() + 2,
            BlockHash([1; 32]),
            extfvk.clone(),
            Amount::from_u64(8).unwrap(),
        );
        let (cb4, _) = fake_compact_block(
            sapling_activation_height() + 3,
            cb3.hash(),
            extfvk.clone(),
            Amount::from_u64(3).unwrap(),
        );
        insert_into_cache(&db_cache, &cb3);
        insert_into_cache(&db_cache, &cb4);

        // Data+cache chain should be invalid at the data/cache boundary
        match validate_chain(
            &tests::network(),
            &db_cache,
            (&db_data).get_max_height_hash().unwrap(),
        )
        .map_err(|e| e.0)
        {
            Err(Error::InvalidChain(upper_bound, _)) => {
                assert_eq!(upper_bound, sapling_activation_height() + 2)
            }
            _ => panic!(),
        }
    }

    #[test]
    fn invalid_chain_cache_reorg() {
        let cache_file = NamedTempFile::new().unwrap();
        let db_cache = BlockDB(Connection::open(cache_file.path()).unwrap());
        init_cache_database(&db_cache).unwrap();

        let data_file = NamedTempFile::new().unwrap();
        let db_data = WalletDB(Connection::open(data_file.path()).unwrap());
        init_data_database(&db_data).unwrap();

        // Add an account to the wallet
        let extsk = ExtendedSpendingKey::master(&[]);
        let extfvk = ExtendedFullViewingKey::from(&extsk);
        init_accounts_table(&db_data, &tests::network(), &[extfvk.clone()]).unwrap();

        // Create some fake CompactBlocks
        let (cb, _) = fake_compact_block(
            sapling_activation_height(),
            BlockHash([0; 32]),
            extfvk.clone(),
            Amount::from_u64(5).unwrap(),
        );
        let (cb2, _) = fake_compact_block(
            sapling_activation_height() + 1,
            cb.hash(),
            extfvk.clone(),
            Amount::from_u64(7).unwrap(),
        );
        insert_into_cache(&db_cache, &cb);
        insert_into_cache(&db_cache, &cb2);

        // Scan the cache
        scan_cached_blocks(&tests::network(), &db_cache, &db_data, None).unwrap();

        // Data-only chain should be valid
        validate_chain(
            &tests::network(),
            &db_cache,
            (&db_data).get_max_height_hash().unwrap(),
        )
        .unwrap();

        // Create more fake CompactBlocks that contain a reorg
        let (cb3, _) = fake_compact_block(
            sapling_activation_height() + 2,
            cb2.hash(),
            extfvk.clone(),
            Amount::from_u64(8).unwrap(),
        );
        let (cb4, _) = fake_compact_block(
            sapling_activation_height() + 3,
            BlockHash([1; 32]),
            extfvk.clone(),
            Amount::from_u64(3).unwrap(),
        );
        insert_into_cache(&db_cache, &cb3);
        insert_into_cache(&db_cache, &cb4);

        // Data+cache chain should be invalid inside the cache
        match validate_chain(
            &tests::network(),
            &db_cache,
            (&db_data).get_max_height_hash().unwrap(),
        )
        .map_err(|e| e.0)
        {
            Err(Error::InvalidChain(upper_bound, _)) => {
                assert_eq!(upper_bound, sapling_activation_height() + 3)
            }
            _ => panic!(),
        }
    }

    #[test]
    fn data_db_rewinding() {
        let cache_file = NamedTempFile::new().unwrap();
        let db_cache = BlockDB(Connection::open(cache_file.path()).unwrap());
        init_cache_database(&db_cache).unwrap();

        let data_file = NamedTempFile::new().unwrap();
        let db_data = WalletDB(Connection::open(data_file.path()).unwrap());
        init_data_database(&db_data).unwrap();

        // Add an account to the wallet
        let extsk = ExtendedSpendingKey::master(&[]);
        let extfvk = ExtendedFullViewingKey::from(&extsk);
        init_accounts_table(&db_data, &tests::network(), &[extfvk.clone()]).unwrap();

        // Account balance should be zero
        assert_eq!(get_balance(&db_data, AccountId(0)).unwrap(), Amount::zero());

        // Create fake CompactBlocks sending value to the address
        let value = Amount::from_u64(5).unwrap();
        let value2 = Amount::from_u64(7).unwrap();
        let (cb, _) = fake_compact_block(
            sapling_activation_height(),
            BlockHash([0; 32]),
            extfvk.clone(),
            value,
        );

        let (cb2, _) =
            fake_compact_block(sapling_activation_height() + 1, cb.hash(), extfvk, value2);
        insert_into_cache(&db_cache, &cb);
        insert_into_cache(&db_cache, &cb2);

        // Scan the cache
        scan_cached_blocks(&tests::network(), &db_cache, &db_data, None).unwrap();

        // Account balance should reflect both received notes
        assert_eq!(get_balance(&db_data, AccountId(0)).unwrap(), value + value2);

        // "Rewind" to height of last scanned block
        rewind_to_height(&db_data, &tests::network(), sapling_activation_height() + 1).unwrap();

        // Account balance should be unaltered
        assert_eq!(get_balance(&db_data, AccountId(0)).unwrap(), value + value2);

        // Rewind so that one block is dropped
        rewind_to_height(&db_data, &tests::network(), sapling_activation_height()).unwrap();

        // Account balance should only contain the first received note
        assert_eq!(get_balance(&db_data, AccountId(0)).unwrap(), value);

        // Scan the cache again
        scan_cached_blocks(&tests::network(), &db_cache, &db_data, None).unwrap();

        // Account balance should again reflect both received notes
        assert_eq!(get_balance(&db_data, AccountId(0)).unwrap(), value + value2);
    }

    #[test]
    fn scan_cached_blocks_requires_sequential_blocks() {
        let cache_file = NamedTempFile::new().unwrap();
        let db_cache = BlockDB(Connection::open(cache_file.path()).unwrap());
        init_cache_database(&db_cache).unwrap();

        let data_file = NamedTempFile::new().unwrap();
        let db_data = WalletDB(Connection::open(data_file.path()).unwrap());
        init_data_database(&db_data).unwrap();

        // Add an account to the wallet
        let extsk = ExtendedSpendingKey::master(&[]);
        let extfvk = ExtendedFullViewingKey::from(&extsk);
        init_accounts_table(&db_data, &tests::network(), &[extfvk.clone()]).unwrap();

        // Create a block with height SAPLING_ACTIVATION_HEIGHT
        let value = Amount::from_u64(50000).unwrap();
        let (cb1, _) = fake_compact_block(
            sapling_activation_height(),
            BlockHash([0; 32]),
            extfvk.clone(),
            value,
        );
        insert_into_cache(&db_cache, &cb1);
        scan_cached_blocks(&tests::network(), &db_cache, &db_data, None).unwrap();
        assert_eq!(get_balance(&db_data, AccountId(0)).unwrap(), value);

        // We cannot scan a block of height SAPLING_ACTIVATION_HEIGHT + 2 next
        let (cb2, _) = fake_compact_block(
            sapling_activation_height() + 1,
            cb1.hash(),
            extfvk.clone(),
            value,
        );
        let (cb3, _) = fake_compact_block(
            sapling_activation_height() + 2,
            cb2.hash(),
            extfvk.clone(),
            value,
        );
        insert_into_cache(&db_cache, &cb3);
        match scan_cached_blocks(&tests::network(), &db_cache, &db_data, None) {
            Ok(_) => panic!("Should have failed"),
            Err(e) => {
                assert_eq!(
                    e.to_string(),
                    ChainInvalid::block_height_discontinuity::<rusqlite::Error, NoteId>(
                        sapling_activation_height() + 1,
                        sapling_activation_height() + 2
                    )
                    .to_string()
                );
            }
        }

        // If we add a block of height SAPLING_ACTIVATION_HEIGHT + 1, we can now scan both
        insert_into_cache(&db_cache, &cb2);
        scan_cached_blocks(&tests::network(), &db_cache, &db_data, None).unwrap();
        assert_eq!(
            get_balance(&db_data, AccountId(0)).unwrap(),
            Amount::from_u64(150_000).unwrap()
        );
    }

    #[test]
    fn scan_cached_blocks_finds_received_notes() {
        let cache_file = NamedTempFile::new().unwrap();
        let db_cache = BlockDB(Connection::open(cache_file.path()).unwrap());
        init_cache_database(&db_cache).unwrap();

        let data_file = NamedTempFile::new().unwrap();
        let db_data = WalletDB(Connection::open(data_file.path()).unwrap());
        init_data_database(&db_data).unwrap();

        // Add an account to the wallet
        let extsk = ExtendedSpendingKey::master(&[]);
        let extfvk = ExtendedFullViewingKey::from(&extsk);
        init_accounts_table(&db_data, &tests::network(), &[extfvk.clone()]).unwrap();

        // Account balance should be zero
        assert_eq!(get_balance(&db_data, AccountId(0)).unwrap(), Amount::zero());

        // Create a fake CompactBlock sending value to the address
        let value = Amount::from_u64(5).unwrap();
        let (cb, _) = fake_compact_block(
            sapling_activation_height(),
            BlockHash([0; 32]),
            extfvk.clone(),
            value,
        );
        insert_into_cache(&db_cache, &cb);

        // Scan the cache
        scan_cached_blocks(&tests::network(), &db_cache, &db_data, None).unwrap();

        // Account balance should reflect the received note
        assert_eq!(get_balance(&db_data, AccountId(0)).unwrap(), value);

        // Create a second fake CompactBlock sending more value to the address
        let value2 = Amount::from_u64(7).unwrap();
        let (cb2, _) =
            fake_compact_block(sapling_activation_height() + 1, cb.hash(), extfvk, value2);
        insert_into_cache(&db_cache, &cb2);

        // Scan the cache again
        scan_cached_blocks(&tests::network(), &db_cache, &db_data, None).unwrap();

        // Account balance should reflect both received notes
        assert_eq!(get_balance(&db_data, AccountId(0)).unwrap(), value + value2);
    }

    #[test]
    fn scan_cached_blocks_finds_change_notes() {
        let cache_file = NamedTempFile::new().unwrap();
        let db_cache = BlockDB(Connection::open(cache_file.path()).unwrap());
        init_cache_database(&db_cache).unwrap();

        let data_file = NamedTempFile::new().unwrap();
        let db_data = WalletDB(Connection::open(data_file.path()).unwrap());
        init_data_database(&db_data).unwrap();

        // Add an account to the wallet
        let extsk = ExtendedSpendingKey::master(&[]);
        let extfvk = ExtendedFullViewingKey::from(&extsk);
        init_accounts_table(&db_data, &tests::network(), &[extfvk.clone()]).unwrap();

        // Account balance should be zero
        assert_eq!(get_balance(&db_data, AccountId(0)).unwrap(), Amount::zero());

        // Create a fake CompactBlock sending value to the address
        let value = Amount::from_u64(5).unwrap();
        let (cb, nf) = fake_compact_block(
            sapling_activation_height(),
            BlockHash([0; 32]),
            extfvk.clone(),
            value,
        );
        insert_into_cache(&db_cache, &cb);

        // Scan the cache
        scan_cached_blocks(&tests::network(), &db_cache, &db_data, None).unwrap();

        // Account balance should reflect the received note
        assert_eq!(get_balance(&db_data, AccountId(0)).unwrap(), value);

        // Create a second fake CompactBlock spending value from the address
        let extsk2 = ExtendedSpendingKey::master(&[0]);
        let to2 = extsk2.default_address().unwrap().1;
        let value2 = Amount::from_u64(2).unwrap();
        insert_into_cache(
            &db_cache,
            &fake_compact_block_spending(
                sapling_activation_height() + 1,
                cb.hash(),
                (nf, value),
                extfvk,
                to2,
                value2,
            ),
        );

        // Scan the cache again
        scan_cached_blocks(&tests::network(), &db_cache, &db_data, None).unwrap();

        // Account balance should equal the change
        assert_eq!(get_balance(&db_data, AccountId(0)).unwrap(), value - value2);
    }
}
