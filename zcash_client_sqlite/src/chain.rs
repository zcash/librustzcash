//! Functions for enforcing chain validity and handling chain reorgs.
//!
//! # Examples
//!
//! ```
//! use std::ops::{Sub};
//! use zcash_primitives::{
//!     consensus::BlockHeight,
//! };
//! use zcash_client_sqlite::{
//!     chain::{rewind_to_height, validate_combined_chain},
//!     error::ErrorKind,
//!     scan::scan_cached_blocks,
//! };
//!
//! let db_cache = "/path/to/cache.db";
//! let db_data = "/path/to/data.db";
//!
//! // 1) Download new CompactBlocks into db_cache.
//!
//! // 2) Run the chain validator on the received blocks.
//! //
//! // Given that we assume the server always gives us correct-at-the-time blocks, any
//! // errors are in the blocks we have previously cached or scanned.
//! if let Err(e) = validate_combined_chain(&db_cache, &db_data) {
//!     match e.kind() {
//!         ErrorKind::InvalidChain(upper_bound, _) => {
//!             // a) Pick a height to rewind to.
//!             //
//!             // This might be informed by some external chain reorg information, or
//!             // heuristics such as the platform, available bandwidth, size of recent
//!             // CompactBlocks, etc.
//!             let rewind_height = upper_bound.sub(10);
//!
//!             // b) Rewind scanned block information.
//!             rewind_to_height(&db_data, rewind_height);
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
//! scan_cached_blocks(&db_cache, &db_data, None);
//! ```

use protobuf::parse_from_bytes;
use rusqlite::{Connection, NO_PARAMS};
use std::path::Path;

use zcash_primitives::consensus::BlockHeight;

use zcash_client_backend::proto::compact_formats::CompactBlock;

use crate::{
    error::{Error, ErrorKind},
    SAPLING_ACTIVATION_HEIGHT,
};

#[derive(Debug)]
pub enum ChainInvalidCause {
    PrevHashMismatch,
    /// (expected_height, actual_height)
    HeightMismatch(BlockHeight, BlockHeight),
}

struct CompactBlockRow {
    height: BlockHeight,
    data: Vec<u8>,
}

/// Checks that the scanned blocks in the data database, when combined with the recent
/// `CompactBlock`s in the cache database, form a valid chain.
///
/// This function is built on the core assumption that the information provided in the
/// cache database is more likely to be accurate than the previously-scanned information.
/// This follows from the design (and trust) assumption that the `lightwalletd` server
/// provides accurate block information as of the time it was requested.
///
/// Returns:
/// - `Ok(())` if the combined chain is valid.
/// - `Err(ErrorKind::InvalidChain(upper_bound, cause))` if the combined chain is invalid.
///   `upper_bound` is the height of the highest invalid block (on the assumption that the
///   highest block in the cache database is correct).
/// - `Err(e)` if there was an error during validation unrelated to chain validity.
///
/// This function does not mutate either of the databases.
pub fn validate_combined_chain<P: AsRef<Path>, Q: AsRef<Path>>(
    db_cache: P,
    db_data: Q,
) -> Result<(), Error> {
    let cache = Connection::open(db_cache)?;
    let data = Connection::open(db_data)?;

    // Recall where we synced up to previously.
    // If we have never synced, use Sapling activation height to select all cached CompactBlocks.
    let (have_scanned, last_scanned_height) =
        data.query_row("SELECT MAX(height) FROM blocks", NO_PARAMS, |row| {
            row.get(0)
                .map(|h: u32| (true, h.into()))
                .or(Ok((false, SAPLING_ACTIVATION_HEIGHT - 1)))
        })?;

    // Fetch the CompactBlocks we need to validate
    let mut stmt_blocks = cache
        .prepare("SELECT height, data FROM compactblocks WHERE height > ? ORDER BY height DESC")?;
    let mut rows = stmt_blocks.query_map(&[u32::from(last_scanned_height)], |row| {
        Ok(CompactBlockRow {
            height: row.get(0).map(u32::into)?,
            data: row.get(1)?,
        })
    })?;

    // Take the highest cached block as accurate.
    let (mut last_height, mut last_prev_hash) = {
        let assumed_correct = match rows.next() {
            Some(row) => row?,
            None => {
                // No cached blocks, and we've already validated the blocks we've scanned,
                // so there's nothing to validate.
                // TODO: Maybe we still want to check if there are cached blocks that are
                // at heights we previously scanned? Check scanning flow again.
                return Ok(());
            }
        };
        let block: CompactBlock = parse_from_bytes(&assumed_correct.data)?;
        (block.height(), block.prev_hash())
    };

    for row in rows {
        let row = row?;

        // Scanned blocks MUST be height-sequential.
        if row.height != (last_height - 1) {
            return Err(Error(ErrorKind::InvalidChain(
                last_height - 1,
                ChainInvalidCause::HeightMismatch(last_height - 1, row.height),
            )));
        }
        last_height = row.height;

        let block: CompactBlock = parse_from_bytes(&row.data)?;

        // Cached blocks MUST be hash-chained.
        if block.hash() != last_prev_hash {
            return Err(Error(ErrorKind::InvalidChain(
                last_height,
                ChainInvalidCause::PrevHashMismatch,
            )));
        }
        last_prev_hash = block.prev_hash();
    }

    if have_scanned {
        // Cached blocks MUST hash-chain to the last scanned block.
        let last_scanned_hash = data.query_row(
            "SELECT hash FROM blocks WHERE height = ?",
            &[u32::from(last_scanned_height)],
            |row| row.get::<_, Vec<_>>(0),
        )?;
        if &last_scanned_hash[..] != &last_prev_hash.0[..] {
            return Err(Error(ErrorKind::InvalidChain(
                last_scanned_height,
                ChainInvalidCause::PrevHashMismatch,
            )));
        }
    }

    // All good!
    Ok(())
}

/// Rewinds the data database to the given height.
///
/// If the requested height is greater than or equal to the height of the last scanned
/// block, this function does nothing.
pub fn rewind_to_height<P: AsRef<Path>>(db_data: P, height: BlockHeight) -> Result<(), Error> {
    let data = Connection::open(db_data)?;

    // Recall where we synced up to previously.
    // If we have never synced, use Sapling activation height.
    let last_scanned_height =
        data.query_row("SELECT MAX(height) FROM blocks", NO_PARAMS, |row| {
            row.get(0)
                .map(u32::into)
                .or(Ok(SAPLING_ACTIVATION_HEIGHT - 1))
        })?;

    if height >= last_scanned_height {
        // Nothing to do.
        return Ok(());
    }

    // Start an SQL transaction for rewinding.
    data.execute("BEGIN IMMEDIATE", NO_PARAMS)?;

    // Decrement witnesses.
    data.execute(
        "DELETE FROM sapling_witnesses WHERE block > ?",
        &[u32::from(height)],
    )?;

    // Un-mine transactions.
    data.execute(
        "UPDATE transactions SET block = NULL, tx_index = NULL WHERE block > ?",
        &[u32::from(height)],
    )?;

    // Now that they aren't depended on, delete scanned blocks.
    data.execute("DELETE FROM blocks WHERE height > ?", &[u32::from(height)])?;

    // Commit the SQL transaction, rewinding atomically.
    data.execute("COMMIT", NO_PARAMS)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use tempfile::NamedTempFile;
    use zcash_primitives::{
        block::BlockHash,
        transaction::components::Amount,
        zip32::{ExtendedFullViewingKey, ExtendedSpendingKey},
    };

    use super::{rewind_to_height, validate_combined_chain};
    use crate::{
        error::ErrorKind,
        init::{init_accounts_table, init_cache_database, init_data_database},
        query::get_balance,
        scan::scan_cached_blocks,
        tests::{fake_compact_block, insert_into_cache},
        SAPLING_ACTIVATION_HEIGHT,
    };

    #[test]
    fn valid_chain_states() {
        let cache_file = NamedTempFile::new().unwrap();
        let db_cache = cache_file.path();
        init_cache_database(&db_cache).unwrap();

        let data_file = NamedTempFile::new().unwrap();
        let db_data = data_file.path();
        init_data_database(&db_data).unwrap();

        // Add an account to the wallet
        let extsk = ExtendedSpendingKey::master(&[]);
        let extfvk = ExtendedFullViewingKey::from(&extsk);
        init_accounts_table(&db_data, &[extfvk.clone()]).unwrap();

        // Empty chain should be valid
        validate_combined_chain(db_cache, db_data).unwrap();

        // Create a fake CompactBlock sending value to the address
        let (cb, _) = fake_compact_block(
            SAPLING_ACTIVATION_HEIGHT,
            BlockHash([0; 32]),
            extfvk.clone(),
            Amount::from_u64(5).unwrap(),
        );
        insert_into_cache(db_cache, &cb);

        // Cache-only chain should be valid
        validate_combined_chain(db_cache, db_data).unwrap();

        // Scan the cache
        scan_cached_blocks(db_cache, db_data, None).unwrap();

        // Data-only chain should be valid
        validate_combined_chain(db_cache, db_data).unwrap();

        // Create a second fake CompactBlock sending more value to the address
        let (cb2, _) = fake_compact_block(
            SAPLING_ACTIVATION_HEIGHT + 1,
            cb.hash(),
            extfvk,
            Amount::from_u64(7).unwrap(),
        );
        insert_into_cache(db_cache, &cb2);

        // Data+cache chain should be valid
        validate_combined_chain(db_cache, db_data).unwrap();

        // Scan the cache again
        scan_cached_blocks(db_cache, db_data, None).unwrap();

        // Data-only chain should be valid
        validate_combined_chain(db_cache, db_data).unwrap();
    }

    #[test]
    fn invalid_chain_cache_disconnected() {
        let cache_file = NamedTempFile::new().unwrap();
        let db_cache = cache_file.path();
        init_cache_database(&db_cache).unwrap();

        let data_file = NamedTempFile::new().unwrap();
        let db_data = data_file.path();
        init_data_database(&db_data).unwrap();

        // Add an account to the wallet
        let extsk = ExtendedSpendingKey::master(&[]);
        let extfvk = ExtendedFullViewingKey::from(&extsk);
        init_accounts_table(&db_data, &[extfvk.clone()]).unwrap();

        // Create some fake CompactBlocks
        let (cb, _) = fake_compact_block(
            SAPLING_ACTIVATION_HEIGHT,
            BlockHash([0; 32]),
            extfvk.clone(),
            Amount::from_u64(5).unwrap(),
        );
        let (cb2, _) = fake_compact_block(
            SAPLING_ACTIVATION_HEIGHT + 1,
            cb.hash(),
            extfvk.clone(),
            Amount::from_u64(7).unwrap(),
        );
        insert_into_cache(db_cache, &cb);
        insert_into_cache(db_cache, &cb2);

        // Scan the cache
        scan_cached_blocks(db_cache, db_data, None).unwrap();

        // Data-only chain should be valid
        validate_combined_chain(db_cache, db_data).unwrap();

        // Create more fake CompactBlocks that don't connect to the scanned ones
        let (cb3, _) = fake_compact_block(
            SAPLING_ACTIVATION_HEIGHT + 2,
            BlockHash([1; 32]),
            extfvk.clone(),
            Amount::from_u64(8).unwrap(),
        );
        let (cb4, _) = fake_compact_block(
            SAPLING_ACTIVATION_HEIGHT + 3,
            cb3.hash(),
            extfvk.clone(),
            Amount::from_u64(3).unwrap(),
        );
        insert_into_cache(db_cache, &cb3);
        insert_into_cache(db_cache, &cb4);

        // Data+cache chain should be invalid at the data/cache boundary
        match validate_combined_chain(db_cache, db_data) {
            Err(e) => match e.kind() {
                ErrorKind::InvalidChain(upper_bound, _) => {
                    assert_eq!(*upper_bound, SAPLING_ACTIVATION_HEIGHT + 1)
                }
                _ => panic!(),
            },
            _ => panic!(),
        }
    }

    #[test]
    fn invalid_chain_cache_reorg() {
        let cache_file = NamedTempFile::new().unwrap();
        let db_cache = cache_file.path();
        init_cache_database(&db_cache).unwrap();

        let data_file = NamedTempFile::new().unwrap();
        let db_data = data_file.path();
        init_data_database(&db_data).unwrap();

        // Add an account to the wallet
        let extsk = ExtendedSpendingKey::master(&[]);
        let extfvk = ExtendedFullViewingKey::from(&extsk);
        init_accounts_table(&db_data, &[extfvk.clone()]).unwrap();

        // Create some fake CompactBlocks
        let (cb, _) = fake_compact_block(
            SAPLING_ACTIVATION_HEIGHT,
            BlockHash([0; 32]),
            extfvk.clone(),
            Amount::from_u64(5).unwrap(),
        );
        let (cb2, _) = fake_compact_block(
            SAPLING_ACTIVATION_HEIGHT + 1,
            cb.hash(),
            extfvk.clone(),
            Amount::from_u64(7).unwrap(),
        );
        insert_into_cache(db_cache, &cb);
        insert_into_cache(db_cache, &cb2);

        // Scan the cache
        scan_cached_blocks(db_cache, db_data, None).unwrap();

        // Data-only chain should be valid
        validate_combined_chain(db_cache, db_data).unwrap();

        // Create more fake CompactBlocks that contain a reorg
        let (cb3, _) = fake_compact_block(
            SAPLING_ACTIVATION_HEIGHT + 2,
            cb2.hash(),
            extfvk.clone(),
            Amount::from_u64(8).unwrap(),
        );
        let (cb4, _) = fake_compact_block(
            SAPLING_ACTIVATION_HEIGHT + 3,
            BlockHash([1; 32]),
            extfvk.clone(),
            Amount::from_u64(3).unwrap(),
        );
        insert_into_cache(db_cache, &cb3);
        insert_into_cache(db_cache, &cb4);

        // Data+cache chain should be invalid inside the cache
        match validate_combined_chain(db_cache, db_data) {
            Err(e) => match e.kind() {
                ErrorKind::InvalidChain(upper_bound, _) => {
                    assert_eq!(*upper_bound, SAPLING_ACTIVATION_HEIGHT + 2)
                }
                _ => panic!(),
            },
            _ => panic!(),
        }
    }

    #[test]
    fn data_db_rewinding() {
        let cache_file = NamedTempFile::new().unwrap();
        let db_cache = cache_file.path();
        init_cache_database(&db_cache).unwrap();

        let data_file = NamedTempFile::new().unwrap();
        let db_data = data_file.path();
        init_data_database(&db_data).unwrap();

        // Add an account to the wallet
        let extsk = ExtendedSpendingKey::master(&[]);
        let extfvk = ExtendedFullViewingKey::from(&extsk);
        init_accounts_table(&db_data, &[extfvk.clone()]).unwrap();

        // Account balance should be zero
        assert_eq!(get_balance(db_data, 0).unwrap(), Amount::zero());

        // Create fake CompactBlocks sending value to the address
        let value = Amount::from_u64(5).unwrap();
        let value2 = Amount::from_u64(7).unwrap();
        let (cb, _) = fake_compact_block(
            SAPLING_ACTIVATION_HEIGHT,
            BlockHash([0; 32]),
            extfvk.clone(),
            value,
        );
        let (cb2, _) = fake_compact_block(SAPLING_ACTIVATION_HEIGHT + 1, cb.hash(), extfvk, value2);
        insert_into_cache(db_cache, &cb);
        insert_into_cache(db_cache, &cb2);

        // Scan the cache
        scan_cached_blocks(db_cache, db_data, None).unwrap();

        // Account balance should reflect both received notes
        assert_eq!(get_balance(db_data, 0).unwrap(), value + value2);

        // "Rewind" to height of last scanned block
        rewind_to_height(db_data, SAPLING_ACTIVATION_HEIGHT + 1).unwrap();

        // Account balance should be unaltered
        assert_eq!(get_balance(db_data, 0).unwrap(), value + value2);

        // Rewind so that one block is dropped
        rewind_to_height(db_data, SAPLING_ACTIVATION_HEIGHT).unwrap();

        // Account balance should only contain the first received note
        assert_eq!(get_balance(db_data, 0).unwrap(), value);

        // Scan the cache again
        scan_cached_blocks(db_cache, db_data, None).unwrap();

        // Account balance should again reflect both received notes
        assert_eq!(get_balance(db_data, 0).unwrap(), value + value2);
    }
}
