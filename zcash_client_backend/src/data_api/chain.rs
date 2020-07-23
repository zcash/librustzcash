use zcash_primitives::consensus::{self, NetworkUpgrade};

use crate::data_api::{
    error::{ChainInvalid, Error},
    CacheOps, DBOps,
};

pub const ANCHOR_OFFSET: u32 = 10;

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
pub fn validate_combined_chain<
    E,
    P: consensus::Parameters,
    C: CacheOps<Error = Error<E>>,
    D: DBOps<Error = Error<E>>,
>(
    parameters: &P,
    cache: &C,
    data: &D,
) -> Result<(), Error<E>> {
    let sapling_activation_height = parameters
        .activation_height(NetworkUpgrade::Sapling)
        .ok_or(Error::SaplingNotActive)?;

    // Recall where we synced up to previously.
    // If we have never synced, use Sapling activation height to select all cached CompactBlocks.
    let data_scan_max_height = data
        .block_height_extrema()?
        .map(|(_, max)| max)
        .unwrap_or(sapling_activation_height - 1);

    // The cache will contain blocks above the maximum height of data in the database;
    // validate from that maximum height up to the chain tip, returning the
    // hash of the block at data_scan_max_height
    let cached_hash_opt = cache.validate_chain(data_scan_max_height, |top_block, next_block| {
        if next_block.height() != top_block.height() - 1 {
            Err(ChainInvalid::block_height_mismatch(
                top_block.height() - 1,
                next_block.height(),
            ))
        } else if next_block.hash() != top_block.prev_hash() {
            Err(ChainInvalid::prev_hash_mismatch(next_block.height()))
        } else {
            Ok(())
        }
    })?;

    match (cached_hash_opt, data.get_block_hash(data_scan_max_height)?) {
        (Some(cached_hash), Some(data_scan_max_hash)) =>
        // Cached blocks must hash-chain to the last scanned block.
        {
            if cached_hash == data_scan_max_hash {
                Ok(())
            } else {
                Err(ChainInvalid::prev_hash_mismatch::<E>(data_scan_max_height))
            }
        }
        (Some(_), None) => Err(Error::CorruptedData(
            "No block hash available at last scanned height.",
        )),
        (None, _) =>
        // No cached blocks are present, this is fine.
        {
            Ok(())
        }
    }
}
