use std::cmp;

use zcash_primitives::consensus::{self, BlockHeight, NetworkUpgrade};

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
    E0,
    E: From<Error<E0>>,
    P: consensus::Parameters,
    C: CacheOps<Error = E>,
    D: DBOps<Error = E>,
>(
    parameters: &P,
    cache: &C,
    data: &D,
) -> Result<(), E> {
    let sapling_activation_height = parameters
        .activation_height(NetworkUpgrade::Sapling)
        .ok_or(Error::SaplingNotActive)?;

    // Recall where we synced up to previously.
    // If we have never synced, use Sapling activation height to select all cached CompactBlocks.
    let data_max_height = data.block_height_extrema()?.map(|(_, max)| max);

    // The cache will contain blocks above the maximum height of data in the database;
    // validate from that maximum height up to the chain tip, returning the
    // hash of the block at data_max_height
    let from_height = data_max_height.unwrap_or(sapling_activation_height - 1);
    let cached_hash_opt = cache.validate_chain(from_height, |top_block, next_block| {
        if next_block.height() != top_block.height() - 1 {
            Err(
                ChainInvalid::block_height_mismatch(top_block.height() - 1, next_block.height())
                    .into(),
            )
        } else if next_block.hash() != top_block.prev_hash() {
            Err(ChainInvalid::prev_hash_mismatch(next_block.height()).into())
        } else {
            Ok(())
        }
    })?;

    match (cached_hash_opt, data_max_height) {
        (Some(cached_hash), Some(h)) => match data.get_block_hash(h)? {
            Some(data_scan_max_hash) => {
                if cached_hash == data_scan_max_hash {
                    Ok(())
                } else {
                    Err(ChainInvalid::prev_hash_mismatch(h).into())
                }
            }
            None => Err(Error::CorruptedData(
                "No block hash available for block at maximum chain height.",
            )
            .into()),
        },
        _ => {
            // No cached blocks are present, or the max data height is absent, this is fine.
            Ok(())
        }
    }
}

/// Determines the target height for a transaction, and the height from which to
/// select anchors, based on the current synchronised block chain.
pub fn get_target_and_anchor_heights<E0, E: From<Error<E0>>, D: DBOps<Error = E>>(
    data: &D,
) -> Result<(BlockHeight, BlockHeight), E> {
    data.block_height_extrema().and_then(|heights| {
        match heights {
            Some((min_height, max_height)) => {
                let target_height = max_height + 1;

                // Select an anchor ANCHOR_OFFSET back from the target block,
                // unless that would be before the earliest block we have.
                let anchor_height = BlockHeight::from(cmp::max(
                    u32::from(target_height).saturating_sub(ANCHOR_OFFSET),
                    u32::from(min_height),
                ));

                Ok((target_height, anchor_height))
            }
            None => Err(Error::ScanRequired.into()),
        }
    })
}
