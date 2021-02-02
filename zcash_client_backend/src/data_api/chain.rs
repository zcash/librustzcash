//! Tools for blockchain validation & scanning
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
//!         BlockSource, WalletRead, WalletWrite,
//!         chain::{
//!             validate_chain,
//!             scan_cached_blocks,
//!         },
//!         error::Error,
//!     },
//! };
//!
//! use zcash_client_sqlite::{
//!     BlockDB,
//!     WalletDB,
//!     error::SqliteClientError,
//!     wallet::{rewind_to_height},
//!     wallet::init::{init_wallet_db},
//! };
//!
//! # // doctests have a problem with sqlite IO, so we ignore errors
//! # // generated in this example code as it's not really testing anything
//! # fn main() {
//! #   test();
//! # }
//! #
//! # fn test() -> Result<(), SqliteClientError> {
//! let network = Network::TestNetwork;
//! let cache_file = NamedTempFile::new()?;
//! let db_cache = BlockDB::for_path(cache_file)?;
//! let db_file = NamedTempFile::new()?;
//! let db_read = WalletDB::for_path(db_file, network)?;
//! init_wallet_db(&db_read)?;
//!
//! let mut db_data = db_read.get_update_ops()?;
//!
//! // 1) Download new CompactBlocks into db_cache.
//!
//! // 2) Run the chain validator on the received blocks.
//! //
//! // Given that we assume the server always gives us correct-at-the-time blocks, any
//! // errors are in the blocks we have previously cached or scanned.
//! if let Err(e) = validate_chain(&network, &db_cache, db_data.get_max_height_hash()?) {
//!     match e {
//!         SqliteClientError::BackendError(Error::InvalidChain(lower_bound, _)) => {
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
//!         }
//!         e => {
//!             // Handle or return other errors.
//!             return Err(e);
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
//! ```

use std::fmt::Debug;

use zcash_primitives::{
    block::BlockHash,
    consensus::{self, BlockHeight, NetworkUpgrade},
    merkle_tree::CommitmentTree,
};

use crate::{
    data_api::{
        error::{ChainInvalid, Error},
        BlockSource, WalletWrite,
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
/// activation height. This height can be fast-forwarded to a more recent block by calling
/// [`init_blocks_table`] before this function.
///
/// Scanned blocks are required to be height-sequential. If a block is missing from the
/// cache, an error will be returned with kind [`ChainInvalid::HeightMismatch`].
///
/// # Examples
///
/// ```
/// use tempfile::NamedTempFile;
/// use zcash_primitives::consensus::{
///     Network,
///     Parameters,
/// };
/// use zcash_client_backend::{
///     data_api::chain::scan_cached_blocks,
/// };
/// use zcash_client_sqlite::{
///     BlockDB,
///     WalletDB,
///     error::SqliteClientError,
///     wallet::init::init_wallet_db,
/// };
///
/// # // doctests have a problem with sqlite IO, so we ignore errors
/// # // generated in this example code as it's not really testing anything
/// # fn main() {
/// #   test();
/// # }
/// #
/// # fn test() -> Result<(), SqliteClientError> {
/// let cache_file = NamedTempFile::new().unwrap();
/// let cache = BlockDB::for_path(cache_file).unwrap();
///
/// let data_file = NamedTempFile::new().unwrap();
/// let db_read = WalletDB::for_path(data_file, Network::TestNetwork)?;
/// init_wallet_db(&db_read)?;
///
/// let mut data = db_read.get_update_ops()?;
/// scan_cached_blocks(&Network::TestNetwork, &cache, &mut data, None)?;
/// # Ok(())
/// # }
/// ```
///
/// [`init_blocks_table`]: crate::init::init_blocks_table
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

    // Fetch the ExtendedFullViewingKeys we are tracking
    let extfvks = data.get_extended_full_viewing_keys()?;
    let ivks: Vec<_> = extfvks
        .iter()
        .map(|(a, extfvk)| (*a, extfvk.fvk.vk.ivk()))
        .collect();

    // Get the most recent CommitmentTree
    let mut tree = data
        .get_commitment_tree(last_height)
        .map(|t| t.unwrap_or(CommitmentTree::new()))?;

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
        last_height = current_height;

        let block_hash = BlockHash::from_slice(&block.hash);
        let block_time = block.time;

        let txs: Vec<WalletTx> = {
            let mut witness_refs: Vec<_> = witnesses.iter_mut().map(|w| &mut w.1).collect();
            scan_block(
                params,
                block,
                &ivks,
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
                    return Err(Error::InvalidWitnessAnchor(row.0, last_height).into());
                }
            }
            for tx in &txs {
                for output in tx.shielded_outputs.iter() {
                    if output.witness.root() != cur_root {
                        return Err(Error::InvalidNewWitnessAnchor(
                            output.index,
                            tx.txid,
                            last_height,
                            output.witness.root(),
                        )
                        .into());
                    }
                }
            }
        }

        // database updates for each block are transactional
        data.transactionally(|up| {
            // Insert the block into the database.
            up.insert_block(current_height, block_hash, block_time, &tree)?;

            for tx in txs {
                let tx_row = up.put_tx_meta(&tx, current_height)?;

                // Mark notes as spent and remove them from the scanning cache
                for spend in &tx.shielded_spends {
                    up.mark_spent(tx_row, &spend.nf)?;
                }

                // remove spent nullifiers from the nullifier set
                nullifiers
                    .retain(|(_, nf)| !tx.shielded_spends.iter().any(|spend| &spend.nf == nf));

                for output in tx.shielded_outputs {
                    if let Some(extfvk) = &extfvks.get(&output.account) {
                        let nf = output
                            .note
                            .nf(&extfvk.fvk.vk, output.witness.position() as u64);

                        let received_note_id = up.put_received_note(&output, &Some(nf), tx_row)?;

                        // Save witness for note.
                        witnesses.push((received_note_id, output.witness));

                        // Cache nullifier for note (to detect subsequent spends in this scan).
                        nullifiers.push((output.account, nf));
                    }
                }
            }

            // Insert current witnesses into the database.
            for (received_note_id, witness) in witnesses.iter() {
                up.insert_witness(*received_note_id, witness, last_height)?;
            }

            // Prune the stored witnesses (we only expect rollbacks of at most 100 blocks).
            up.prune_witnesses(last_height - 100)?;

            // Update now-expired transactions that didn't get mined.
            up.update_expired_notes(last_height)?;

            Ok(())
        })
    })?;

    Ok(())
}
