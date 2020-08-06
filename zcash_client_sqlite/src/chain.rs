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
//!         chain::validate_combined_chain,
//!         error::Error,
//!     }
//! };
//!
//! use zcash_client_sqlite::{
//!     DataConnection,
//!     CacheConnection,
//!     chain::{rewind_to_height},
//!     scan::scan_cached_blocks,
//! };
//!
//! let network = Network::TestNetwork;
//! let cache_file = NamedTempFile::new().unwrap();
//! let db_cache = CacheConnection::for_path(cache_file).unwrap();
//! let data_file = NamedTempFile::new().unwrap();
//! let db_data = DataConnection::for_path(data_file).unwrap();
//!
//! // 1) Download new CompactBlocks into db_cache.
//!
//! // 2) Run the chain validator on the received blocks.
//! //
//! // Given that we assume the server always gives us correct-at-the-time blocks, any
//! // errors are in the blocks we have previously cached or scanned.
//! if let Err(e) = validate_combined_chain(&network, &db_cache, &db_data) {
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
use rusqlite::{OptionalExtension, NO_PARAMS};

use zcash_primitives::{
    block::BlockHash,
    consensus::{self, BlockHeight, NetworkUpgrade},
};

use zcash_client_backend::{
    data_api::error::{ChainInvalid, Error},
    proto::compact_formats::CompactBlock,
};

use crate::{error::SqliteClientError, CacheConnection, DataConnection};

struct CompactBlockRow {
    height: BlockHeight,
    data: Vec<u8>,
}

pub fn validate_chain<F>(
    conn: &CacheConnection,
    from_height: BlockHeight,
    validate: F,
) -> Result<Option<BlockHash>, SqliteClientError>
where
    F: Fn(&CompactBlock, &CompactBlock) -> Result<(), SqliteClientError>,
{
    let mut stmt_blocks = conn
        .0
        .prepare("SELECT height, data FROM compactblocks WHERE height >= ? ORDER BY height DESC")?;

    let block_rows = stmt_blocks.query_map(&[u32::from(from_height)], |row| {
        let height: BlockHeight = row.get(0).map(u32::into)?;
        let data = row.get::<_, Vec<_>>(1)?;
        Ok(CompactBlockRow { height, data })
    })?;

    let mut blocks = block_rows.map(|cbr_result| {
        let cbr = cbr_result.map_err(Error::Database)?;
        let block: CompactBlock = parse_from_bytes(&cbr.data).map_err(Error::from)?;

        if block.height() == cbr.height {
            Ok(block)
        } else {
            Err(ChainInvalid::block_height_mismatch(
                cbr.height,
                block.height(),
            ))
        }
    });

    let mut current_block: CompactBlock = match blocks.next() {
        Some(Ok(block)) => block,
        Some(Err(error)) => {
            return Err(SqliteClientError(error));
        }
        None => {
            // No cached blocks, and we've already validated the blocks we've scanned,
            // so there's nothing to validate.
            // TODO: Maybe we still want to check if there are cached blocks that are
            // at heights we previously scanned? Check scanning flow again.
            return Ok(None);
        }
    };

    for block_result in blocks {
        let block = block_result?;
        validate(&current_block, &block)?;
        current_block = block;
    }

    Ok(Some(current_block.hash()))
}

pub fn block_height_extrema(
    conn: &DataConnection,
) -> Result<Option<(BlockHeight, BlockHeight)>, rusqlite::Error> {
    conn.0
        .query_row(
            "SELECT MIN(height), MAX(height) FROM blocks",
            NO_PARAMS,
            |row| {
                let min_height: u32 = row.get(0)?;
                let max_height: u32 = row.get(1)?;
                Ok(Some((min_height.into(), max_height.into())))
            },
        )
        //.optional() doesn't work here because a failed aggregate function
        //produces a runtime error, not an empty set of rows.
        .or(Ok(None))
}

pub fn get_block_hash(
    conn: &DataConnection,
    block_height: BlockHeight,
) -> Result<Option<BlockHash>, rusqlite::Error> {
    conn.0
        .query_row(
            "SELECT hash FROM blocks WHERE height = ?",
            &[u32::from(block_height)],
            |row| {
                let row_data = row.get::<_, Vec<_>>(0)?;
                Ok(BlockHash::from_slice(&row_data))
            },
        )
        .optional()
}

/// Rewinds the database to the given height.
///
/// If the requested height is greater than or equal to the height of the last scanned
/// block, this function does nothing.
pub fn rewind_to_height<P: consensus::Parameters>(
    conn: &DataConnection,
    parameters: &P,
    block_height: BlockHeight,
) -> Result<(), SqliteClientError> {
    let sapling_activation_height = parameters
        .activation_height(NetworkUpgrade::Sapling)
        .ok_or(SqliteClientError(Error::SaplingNotActive))?;

    // Recall where we synced up to previously.
    // If we have never synced, use Sapling activation height.
    let last_scanned_height =
        conn.0
            .query_row("SELECT MAX(height) FROM blocks", NO_PARAMS, |row| {
                row.get(0)
                    .map(u32::into)
                    .or(Ok(sapling_activation_height - 1))
            })?;

    if block_height >= last_scanned_height {
        // Nothing to do.
        return Ok(());
    }

    // Start an SQL transaction for rewinding.
    conn.0.execute("BEGIN IMMEDIATE", NO_PARAMS)?;

    // Decrement witnesses.
    conn.0.execute(
        "DELETE FROM sapling_witnesses WHERE block > ?",
        &[u32::from(block_height)],
    )?;

    // Un-mine transactions.
    conn.0.execute(
        "UPDATE transactions SET block = NULL, tx_index = NULL WHERE block > ?",
        &[u32::from(block_height)],
    )?;

    // Now that they aren't depended on, delete scanned blocks.
    conn.0.execute(
        "DELETE FROM blocks WHERE height > ?",
        &[u32::from(block_height)],
    )?;

    // Commit the SQL transaction, rewinding atomically.
    conn.0.execute("COMMIT", NO_PARAMS)?;

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

    use zcash_client_backend::data_api::{chain::validate_combined_chain, error::Error};

    use crate::{
        init::{init_accounts_table, init_cache_database, init_data_database},
        query::get_balance,
        scan::scan_cached_blocks,
        tests::{self, fake_compact_block, insert_into_cache, sapling_activation_height},
        AccountId, CacheConnection, DataConnection,
    };

    use super::rewind_to_height;

    #[test]
    fn valid_chain_states() {
        let cache_file = NamedTempFile::new().unwrap();
        let db_cache = CacheConnection(Connection::open(cache_file.path()).unwrap());
        init_cache_database(&db_cache).unwrap();

        let data_file = NamedTempFile::new().unwrap();
        let db_data = DataConnection(Connection::open(data_file.path()).unwrap());
        init_data_database(&db_data).unwrap();

        // Add an account to the wallet
        let extsk = ExtendedSpendingKey::master(&[]);
        let extfvk = ExtendedFullViewingKey::from(&extsk);
        init_accounts_table(&db_data, &tests::network(), &[extfvk.clone()]).unwrap();

        // Empty chain should be valid
        validate_combined_chain(&tests::network(), &db_cache, &db_data).unwrap();

        // Create a fake CompactBlock sending value to the address
        let (cb, _) = fake_compact_block(
            sapling_activation_height(),
            BlockHash([0; 32]),
            extfvk.clone(),
            Amount::from_u64(5).unwrap(),
        );
        insert_into_cache(&db_cache, &cb);

        // Cache-only chain should be valid
        validate_combined_chain(&tests::network(), &db_cache, &db_data).unwrap();

        // Scan the cache
        scan_cached_blocks(&tests::network(), &db_cache, &db_data, None).unwrap();

        // Data-only chain should be valid
        validate_combined_chain(&tests::network(), &db_cache, &db_data).unwrap();

        // Create a second fake CompactBlock sending more value to the address
        let (cb2, _) = fake_compact_block(
            sapling_activation_height() + 1,
            cb.hash(),
            extfvk,
            Amount::from_u64(7).unwrap(),
        );
        insert_into_cache(&db_cache, &cb2);

        // Data+cache chain should be valid
        validate_combined_chain(&tests::network(), &db_cache, &db_data).unwrap();

        // Scan the cache again
        scan_cached_blocks(&tests::network(), &db_cache, &db_data, None).unwrap();

        // Data-only chain should be valid
        validate_combined_chain(&tests::network(), &db_cache, &db_data).unwrap();
    }

    #[test]
    fn invalid_chain_cache_disconnected() {
        let cache_file = NamedTempFile::new().unwrap();
        let db_cache = CacheConnection(Connection::open(cache_file.path()).unwrap());
        init_cache_database(&db_cache).unwrap();

        let data_file = NamedTempFile::new().unwrap();
        let db_data = DataConnection(Connection::open(data_file.path()).unwrap());
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
        validate_combined_chain(&tests::network(), &db_cache, &db_data).unwrap();

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
        match validate_combined_chain(&tests::network(), &db_cache, &db_data).map_err(|e| e.0) {
            Err(Error::InvalidChain(upper_bound, _)) => {
                assert_eq!(upper_bound, sapling_activation_height() + 1)
            }
            _ => panic!(),
        }
    }

    #[test]
    fn invalid_chain_cache_reorg() {
        let cache_file = NamedTempFile::new().unwrap();
        let db_cache = CacheConnection(Connection::open(cache_file.path()).unwrap());
        init_cache_database(&db_cache).unwrap();

        let data_file = NamedTempFile::new().unwrap();
        let db_data = DataConnection(Connection::open(data_file.path()).unwrap());
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
        validate_combined_chain(&tests::network(), &db_cache, &db_data).unwrap();

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
        match validate_combined_chain(&tests::network(), &db_cache, &db_data).map_err(|e| e.0) {
            Err(Error::InvalidChain(upper_bound, _)) => {
                assert_eq!(upper_bound, sapling_activation_height() + 2)
            }
            _ => panic!(),
        }
    }

    #[test]
    fn data_db_rewinding() {
        let cache_file = NamedTempFile::new().unwrap();
        let db_cache = CacheConnection(Connection::open(cache_file.path()).unwrap());
        init_cache_database(&db_cache).unwrap();

        let data_file = NamedTempFile::new().unwrap();
        let db_data = DataConnection(Connection::open(data_file.path()).unwrap());
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
}
