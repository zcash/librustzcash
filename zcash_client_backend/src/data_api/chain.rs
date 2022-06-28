#![allow(clippy::needless_doctest_main)]
//! Tools for blockchain validation & scanning
//!
//! # Examples
//!
//! ```
//! # #[cfg(feature = "test-dependencies")]
//! # {
//! use zcash_primitives::{
//!     consensus::{BlockHeight, Network, Parameters}
//! };
//!
//! use zcash_client_backend::{
//!     data_api::{
//!         BlockSource, WalletRead, WalletWrite,
//!         chain::{
//!             validate_chain,
//!             scan_cached_blocks,
//!         },
//!         error::Error,
//!         testing,
//!     },
//! };
//!
//! # fn main() {
//! #   test();
//! # }
//! #
//! # fn test() -> Result<(), Error<u32>> {
//! let network = Network::TestNetwork;
//! let db_cache = testing::MockBlockSource {};
//! let mut db_data = testing::MockWalletDb {};
//!
//! // 1) Download new CompactBlocks into db_cache.
//!
//! // 2) Run the chain validator on the received blocks.
//! //
//! // Given that we assume the server always gives us correct-at-the-time blocks, any
//! // errors are in the blocks we have previously cached or scanned.
//! if let Err(e) = validate_chain(&network, &db_cache, db_data.get_max_height_hash()?) {
//!     match e {
//!         Error::InvalidChain(lower_bound, _) => {
//!             // a) Pick a height to rewind to.
//!             //
//!             // This might be informed by some external chain reorg information, or
//!             // heuristics such as the platform, available bandwidth, size of recent
//!             // CompactBlocks, etc.
//!             let rewind_height = lower_bound - 10;
//!
//!             // b) Rewind scanned block information.
//!             db_data.rewind_to_height(rewind_height);
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
//!         },
//!         e => {
//!             // handle or return other errors
//!
//!         }
//!     }
//! }
//!
//! // 3) Scan (any remaining) cached blocks.
//! //
//! // At this point, the cache and scanned data are locally consistent (though not
//! // necessarily consistent with the latest chain tip - this would be discovered the
//! // next time this codepath is executed after new blocks are received).
//! scan_cached_blocks(&network, &db_cache, &mut db_data, None)
//! # }
//! # }
//! ```

use std::fmt::Debug;

use zcash_primitives::{
    block::BlockHash,
    consensus::{self, BlockHeight, NetworkUpgrade},
    merkle_tree::CommitmentTree,
    sapling::Nullifier,
};

use crate::{
    data_api::{
        error::{ChainInvalid, Error},
        BlockSource, PrunedBlock, WalletWrite,
    },
    proto::compact_formats::CompactBlock,
    wallet::WalletTx,
    welding_rig::scan_block,
};

/// Checks that the scanned blocks in the data database, when combined with the recent
/// `CompactBlock`s in the cache database, form a valid chain.
///
/// This function is built on the core assumption that the information provided in the
/// cache database is more likely to be accurate than the previously-scanned information.
/// This follows from the design (and trust) assumption that the `lightwalletd` server
/// provides accurate block information as of the time it was requested.
///
/// Arguments:
/// - `parameters` Network parameters
/// - `cache` Source of compact blocks
/// - `from_tip` Height & hash of last validated block; if no validation has previously
///    been performed, this will begin scanning from `sapling_activation_height - 1`
///
/// Returns:
/// - `Ok(())` if the combined chain is valid.
/// - `Err(ErrorKind::InvalidChain(upper_bound, cause))` if the combined chain is invalid.
///   `upper_bound` is the height of the highest invalid block (on the assumption that the
///   highest block in the cache database is correct).
/// - `Err(e)` if there was an error during validation unrelated to chain validity.
///
/// This function does not mutate either of the databases.
pub fn validate_chain<N, E, P, C>(
    parameters: &P,
    cache: &C,
    validate_from: Option<(BlockHeight, BlockHash)>,
) -> Result<(), E>
where
    E: From<Error<N>>,
    P: consensus::Parameters,
    C: BlockSource<Error = E>,
{
    let sapling_activation_height = parameters
        .activation_height(NetworkUpgrade::Sapling)
        .ok_or(Error::SaplingNotActive)?;

    // The cache will contain blocks above the `validate_from` height.  Validate from that maximum
    // height up to the chain tip, returning the hash of the block found in the cache at the
    // `validate_from` height, which can then be used to verify chain integrity by comparing
    // against the `validate_from` hash.
    let from_height = validate_from
        .map(|(height, _)| height)
        .unwrap_or(sapling_activation_height - 1);

    let mut prev_height = from_height;
    let mut prev_hash: Option<BlockHash> = validate_from.map(|(_, hash)| hash);

    cache.with_blocks(from_height, None, move |block| {
        let current_height = block.height();
        let result = if current_height != prev_height + 1 {
            Err(ChainInvalid::block_height_discontinuity(
                prev_height + 1,
                current_height,
            ))
        } else {
            match prev_hash {
                None => Ok(()),
                Some(h) if h == block.prev_hash() => Ok(()),
                Some(_) => Err(ChainInvalid::prev_hash_mismatch(current_height)),
            }
        };

        prev_height = current_height;
        prev_hash = Some(block.hash());
        result.map_err(E::from)
    })
}

#[allow(clippy::needless_doctest_main)]
/// Scans at most `limit` new blocks added to the cache for any transactions received by
/// the tracked accounts.
///
/// This function will return without error after scanning at most `limit` new blocks, to
/// enable the caller to update their UI with scanning progress. Repeatedly calling this
/// function will process sequential ranges of blocks, and is equivalent to calling
/// `scan_cached_blocks` and passing `None` for the optional `limit` value.
///
/// This function pays attention only to cached blocks with heights greater than the
/// highest scanned block in `data`. Cached blocks with lower heights are not verified
/// against previously-scanned blocks. In particular, this function **assumes** that the
/// caller is handling rollbacks.
///
/// For brand-new light client databases, this function starts scanning from the Sapling
/// activation height. This height can be fast-forwarded to a more recent block by
/// initializing the client database with a starting block (for example, calling
/// `init_blocks_table` before this function if using `zcash_client_sqlite`).
///
/// Scanned blocks are required to be height-sequential. If a block is missing from the
/// cache, an error will be returned with kind [`ChainInvalid::BlockHeightDiscontinuity`].
pub fn scan_cached_blocks<E, N, P, C, D>(
    params: &P,
    cache: &C,
    data: &mut D,
    limit: Option<u32>,
) -> Result<(), E>
where
    P: consensus::Parameters,
    C: BlockSource<Error = E>,
    D: WalletWrite<Error = E, NoteRef = N>,
    N: Copy + Debug,
    E: From<Error<N>>,
{
    let sapling_activation_height = params
        .activation_height(NetworkUpgrade::Sapling)
        .ok_or(Error::SaplingNotActive)?;

    // Recall where we synced up to previously.
    // If we have never synced, use sapling activation height to select all cached CompactBlocks.
    let mut last_height = data.block_height_extrema().map(|opt| {
        opt.map(|(_, max)| max)
            .unwrap_or(sapling_activation_height - 1)
    })?;

    // Fetch the UnifiedFullViewingKeys we are tracking
    let ufvks = data.get_unified_full_viewing_keys()?;
    // TODO: Change `scan_block` to also scan Orchard.
    // https://github.com/zcash/librustzcash/issues/403
    let dfvks: Vec<_> = ufvks
        .iter()
        .filter_map(|(account, ufvk)| ufvk.sapling().map(move |k| (account, k)))
        .collect();

    // Get the most recent CommitmentTree
    let mut tree = data
        .get_commitment_tree(last_height)
        .map(|t| t.unwrap_or_else(CommitmentTree::empty))?;

    // Get most recent incremental witnesses for the notes we are tracking
    let mut witnesses = data.get_witnesses(last_height)?;

    // Get the nullifiers for the notes we are tracking
    let mut nullifiers = data.get_nullifiers()?;

    cache.with_blocks(last_height, limit, |block: CompactBlock| {
        let current_height = block.height();

        // Scanned blocks MUST be height-sequential.
        if current_height != (last_height + 1) {
            return Err(
                ChainInvalid::block_height_discontinuity(last_height + 1, current_height).into(),
            );
        }

        let block_hash = BlockHash::from_slice(&block.hash);
        let block_time = block.time;

        let txs: Vec<WalletTx<Nullifier>> = {
            let mut witness_refs: Vec<_> = witnesses.iter_mut().map(|w| &mut w.1).collect();

            scan_block(
                params,
                block,
                &dfvks,
                &nullifiers,
                &mut tree,
                &mut witness_refs[..],
            )
        };

        // Enforce that all roots match. This is slow, so only include in debug builds.
        #[cfg(debug_assertions)]
        {
            let cur_root = tree.root();
            for row in &witnesses {
                if row.1.root() != cur_root {
                    return Err(Error::InvalidWitnessAnchor(row.0, current_height).into());
                }
            }
            for tx in &txs {
                for output in tx.shielded_outputs.iter() {
                    if output.witness.root() != cur_root {
                        return Err(Error::InvalidNewWitnessAnchor(
                            output.index,
                            tx.txid,
                            current_height,
                            output.witness.root(),
                        )
                        .into());
                    }
                }
            }
        }

        let new_witnesses = data.advance_by_block(
            &(PrunedBlock {
                block_height: current_height,
                block_hash,
                block_time,
                commitment_tree: &tree,
                transactions: &txs,
            }),
            &witnesses,
        )?;

        let spent_nf: Vec<Nullifier> = txs
            .iter()
            .flat_map(|tx| tx.shielded_spends.iter().map(|spend| spend.nf))
            .collect();
        nullifiers.retain(|(_, nf)| !spent_nf.contains(nf));
        nullifiers.extend(
            txs.iter()
                .flat_map(|tx| tx.shielded_outputs.iter().map(|out| (out.account, out.nf))),
        );

        witnesses.extend(new_witnesses);

        last_height = current_height;

        Ok(())
    })?;

    Ok(())
}
