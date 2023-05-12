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
//!         WalletRead, WalletWrite,
//!         chain::{
//!             BlockSource,
//!             error::Error,
//!             scan_cached_blocks,
//!             validate_chain,
//!             testing as chain_testing,
//!         },
//!         testing,
//!     },
//! };
//!
//! # use std::convert::Infallible;
//!
//! # fn main() {
//! #   test();
//! # }
//! #
//! # fn test() -> Result<(), Error<(), Infallible, u32>> {
//! let network = Network::TestNetwork;
//! let block_source = chain_testing::MockBlockSource;
//! let mut db_data = testing::MockWalletDb {
//!     network: Network::TestNetwork
//! };
//!
//! // 1) Download new CompactBlocks into block_source.
//!
//! // 2) Run the chain validator on the received blocks.
//! //
//! // Given that we assume the server always gives us correct-at-the-time blocks, any
//! // errors are in the blocks we have previously cached or scanned.
//! let max_height_hash = db_data.get_max_height_hash().map_err(Error::Wallet)?;
//! if let Err(e) = validate_chain(&block_source, max_height_hash, None) {
//!     match e {
//!         Error::Chain(e) => {
//!             // a) Pick a height to rewind to.
//!             //
//!             // This might be informed by some external chain reorg information, or
//!             // heuristics such as the platform, available bandwidth, size of recent
//!             // CompactBlocks, etc.
//!             let rewind_height = e.at_height() - 10;
//!
//!             // b) Rewind scanned block information.
//!             db_data.truncate_to_height(rewind_height);
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
//! scan_cached_blocks(&network, &block_source, &mut db_data, None)
//! # }
//! # }
//! ```

use std::convert::Infallible;

use zcash_primitives::{
    block::BlockHash,
    consensus::{self, BlockHeight},
    sapling::{self, note_encryption::PreparedIncomingViewingKey, Nullifier},
    zip32::Scope,
};

use crate::{
    data_api::{PrunedBlock, WalletWrite},
    proto::compact_formats::CompactBlock,
    scan::BatchRunner,
    wallet::WalletTx,
    welding_rig::{add_block_to_runner, scan_block_with_runner},
};

pub mod error;
use error::{ChainError, Error};

/// This trait provides sequential access to raw blockchain data via a callback-oriented
/// API.
pub trait BlockSource {
    type Error;

    /// Scan the specified `limit` number of blocks from the blockchain, starting at
    /// `from_height`, applying the provided callback to each block. If `from_height`
    /// is `None` then scanning will begin at the first available block.
    ///
    /// * `WalletErrT`: the types of errors produced by the wallet operations performed
    ///   as part of processing each row.
    /// * `NoteRefT`: the type of note identifiers in the wallet data store, for use in
    ///   reporting errors related to specific notes.
    fn with_blocks<F, WalletErrT, NoteRefT>(
        &self,
        from_height: Option<BlockHeight>,
        limit: Option<u32>,
        with_row: F,
    ) -> Result<(), error::Error<WalletErrT, Self::Error, NoteRefT>>
    where
        F: FnMut(CompactBlock) -> Result<(), error::Error<WalletErrT, Self::Error, NoteRefT>>;
}

/// Checks that the scanned blocks in the data database, when combined with the recent
/// `CompactBlock`s in the block_source database, form a valid chain.
///
/// This function is built on the core assumption that the information provided in the
/// block source is more likely to be accurate than the previously-scanned information.
/// This follows from the design (and trust) assumption that the `lightwalletd` server
/// provides accurate block information as of the time it was requested.
///
/// Arguments:
/// - `block_source` Source of compact blocks
/// - `validate_from` Height & hash of last validated block;
/// - `limit` specified number of blocks that will be valididated. Callers providing
/// a `limit` argument are responsible of making subsequent calls to `validate_chain()`
/// to complete validating the remaining blocks stored on the `block_source`. If `none`
/// is provided, there will be no limit set to the validation and upper bound of the
/// validation range will be the latest height present in the `block_source`.
///
/// Returns:
/// - `Ok(())` if the combined chain is valid up to the given height
/// and block hash.
/// - `Err(Error::Chain(cause))` if the combined chain is invalid.
/// - `Err(e)` if there was an error during validation unrelated to chain validity.
pub fn validate_chain<BlockSourceT>(
    block_source: &BlockSourceT,
    mut validate_from: Option<(BlockHeight, BlockHash)>,
    limit: Option<u32>,
) -> Result<(), Error<Infallible, BlockSourceT::Error, Infallible>>
where
    BlockSourceT: BlockSource,
{
    // The block source will contain blocks above the `validate_from` height.  Validate from that
    // maximum height up to the chain tip, returning the hash of the block found in the block
    // source at the `validate_from` height, which can then be used to verify chain integrity by
    // comparing against the `validate_from` hash.

    block_source.with_blocks::<_, Infallible, Infallible>(
        validate_from.map(|(h, _)| h),
        limit,
        move |block| {
            if let Some((valid_height, valid_hash)) = validate_from {
                if block.height() != valid_height + 1 {
                    return Err(ChainError::block_height_discontinuity(
                        valid_height + 1,
                        block.height(),
                    )
                    .into());
                } else if block.prev_hash() != valid_hash {
                    return Err(ChainError::prev_hash_mismatch(block.height()).into());
                }
            }

            validate_from = Some((block.height(), block.hash()));
            Ok(())
        },
    )
}

/// Scans at most `limit` new blocks added to the block source for any transactions received by the
/// tracked accounts.
///
/// This function will return without error after scanning at most `limit` new blocks, to enable
/// the caller to update their UI with scanning progress. Repeatedly calling this function will
/// process sequential ranges of blocks, and is equivalent to calling `scan_cached_blocks` and
/// passing `None` for the optional `limit` value.
///
/// This function pays attention only to cached blocks with heights greater than the highest
/// scanned block in `data`. Cached blocks with lower heights are not verified against
/// previously-scanned blocks. In particular, this function **assumes** that the caller is handling
/// rollbacks.
///
/// For brand-new light client databases, this function starts scanning from the Sapling activation
/// height. This height can be fast-forwarded to a more recent block by initializing the client
/// database with a starting block (for example, calling `init_blocks_table` before this function
/// if using `zcash_client_sqlite`).
///
/// Scanned blocks are required to be height-sequential. If a block is missing from the block
/// source, an error will be returned with cause [`error::Cause::BlockHeightDiscontinuity`].
#[tracing::instrument(skip(params, block_source, data_db))]
#[allow(clippy::type_complexity)]
pub fn scan_cached_blocks<ParamsT, DbT, BlockSourceT>(
    params: &ParamsT,
    block_source: &BlockSourceT,
    data_db: &mut DbT,
    limit: Option<u32>,
) -> Result<(), Error<DbT::Error, BlockSourceT::Error, DbT::NoteRef>>
where
    ParamsT: consensus::Parameters + Send + 'static,
    BlockSourceT: BlockSource,
    DbT: WalletWrite,
{
    // Recall where we synced up to previously.
    let mut last_height = data_db
        .block_height_extrema()
        .map_err(Error::Wallet)?
        .map(|(_, max)| max);

    // Fetch the UnifiedFullViewingKeys we are tracking
    let ufvks = data_db
        .get_unified_full_viewing_keys()
        .map_err(Error::Wallet)?;
    // TODO: Change `scan_block` to also scan Orchard.
    // https://github.com/zcash/librustzcash/issues/403
    let dfvks: Vec<_> = ufvks
        .iter()
        .filter_map(|(account, ufvk)| ufvk.sapling().map(move |k| (account, k)))
        .collect();

    // Get the most recent CommitmentTree
    let mut tree = last_height.map_or_else(
        || Ok(sapling::CommitmentTree::empty()),
        |h| {
            data_db
                .get_commitment_tree(h)
                .map(|t| t.unwrap_or_else(sapling::CommitmentTree::empty))
                .map_err(Error::Wallet)
        },
    )?;

    // Get most recent incremental witnesses for the notes we are tracking
    let mut witnesses = last_height.map_or_else(
        || Ok(vec![]),
        |h| data_db.get_witnesses(h).map_err(Error::Wallet),
    )?;

    // Get the nullifiers for the notes we are tracking
    let mut nullifiers = data_db.get_nullifiers().map_err(Error::Wallet)?;

    let mut batch_runner = BatchRunner::<_, _, _, ()>::new(
        100,
        dfvks
            .iter()
            .flat_map(|(account, dfvk)| {
                [
                    ((**account, Scope::External), dfvk.to_ivk(Scope::External)),
                    ((**account, Scope::Internal), dfvk.to_ivk(Scope::Internal)),
                ]
            })
            .map(|(tag, ivk)| (tag, PreparedIncomingViewingKey::new(&ivk))),
    );

    block_source.with_blocks::<_, DbT::Error, DbT::NoteRef>(
        last_height,
        limit,
        |block: CompactBlock| {
            add_block_to_runner(params, block, &mut batch_runner);
            Ok(())
        },
    )?;

    batch_runner.flush();

    block_source.with_blocks::<_, DbT::Error, DbT::NoteRef>(
        last_height,
        limit,
        |block: CompactBlock| {
            let current_height = block.height();

            // Scanned blocks MUST be height-sequential.
            if let Some(h) = last_height {
                if current_height != (h + 1) {
                    return Err(
                        ChainError::block_height_discontinuity(h + 1, current_height).into(),
                    );
                }
            }

            let block_hash = BlockHash::from_slice(&block.hash);
            let block_time = block.time;

            let txs: Vec<WalletTx<Nullifier>> = {
                let mut witness_refs: Vec<_> = witnesses.iter_mut().map(|w| &mut w.1).collect();

                scan_block_with_runner(
                    params,
                    block,
                    &dfvks,
                    &nullifiers,
                    &mut tree,
                    &mut witness_refs[..],
                    Some(&mut batch_runner),
                )
            };

            // Enforce that all roots match. This is slow, so only include in debug builds.
            #[cfg(debug_assertions)]
            {
                let cur_root = tree.root();
                for row in &witnesses {
                    if row.1.root() != cur_root {
                        return Err(
                            ChainError::invalid_witness_anchor(current_height, row.0).into()
                        );
                    }
                }
                for tx in &txs {
                    for output in tx.sapling_outputs.iter() {
                        if output.witness().root() != cur_root {
                            return Err(ChainError::invalid_new_witness_anchor(
                                current_height,
                                tx.txid,
                                output.index(),
                                output.witness().root(),
                            )
                            .into());
                        }
                    }
                }
            }

            let new_witnesses = data_db
                .advance_by_block(
                    &(PrunedBlock {
                        block_height: current_height,
                        block_hash,
                        block_time,
                        commitment_tree: &tree,
                        transactions: &txs,
                    }),
                    &witnesses,
                )
                .map_err(Error::Wallet)?;

            let spent_nf: Vec<&Nullifier> = txs
                .iter()
                .flat_map(|tx| tx.sapling_spends.iter().map(|spend| spend.nf()))
                .collect();
            nullifiers.retain(|(_, nf)| !spent_nf.contains(&nf));
            nullifiers.extend(txs.iter().flat_map(|tx| {
                tx.sapling_outputs
                    .iter()
                    .map(|out| (out.account(), *out.nf()))
            }));

            witnesses.extend(new_witnesses);

            last_height = Some(current_height);

            Ok(())
        },
    )?;

    Ok(())
}

#[cfg(feature = "test-dependencies")]
pub mod testing {
    use std::convert::Infallible;
    use zcash_primitives::consensus::BlockHeight;

    use crate::proto::compact_formats::CompactBlock;

    use super::{error::Error, BlockSource};

    pub struct MockBlockSource;

    impl BlockSource for MockBlockSource {
        type Error = Infallible;

        fn with_blocks<F, DbErrT, NoteRef>(
            &self,
            _from_height: Option<BlockHeight>,
            _limit: Option<u32>,
            _with_row: F,
        ) -> Result<(), Error<DbErrT, Infallible, NoteRef>>
        where
            F: FnMut(CompactBlock) -> Result<(), Error<DbErrT, Infallible, NoteRef>>,
        {
            Ok(())
        }
    }
}
