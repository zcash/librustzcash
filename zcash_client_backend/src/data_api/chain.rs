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
//! let mut db_data = testing::MockWalletDb::new(Network::TestNetwork);
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
//! scan_cached_blocks(&network, &block_source, &mut db_data, None, None)
//! # }
//! # }
//! ```

use std::convert::Infallible;

use zcash_primitives::{
    block::BlockHash,
    consensus::{self, BlockHeight},
    sapling::{self, note_encryption::PreparedIncomingViewingKey},
    zip32::Scope,
};

use crate::{
    data_api::{NullifierQuery, WalletWrite},
    proto::compact_formats::CompactBlock,
    scan::BatchRunner,
    welding_rig::{add_block_to_runner, scan_block_with_runner},
};

pub mod error;
use error::{ChainError, Error};

pub struct CommitmentTreeMeta {
    sapling_tree_size: u64,
    //TODO: orchard_tree_size: u64
}

impl CommitmentTreeMeta {
    pub fn from_parts(sapling_tree_size: u64) -> Self {
        Self { sapling_tree_size }
    }

    pub fn sapling_tree_size(&self) -> u64 {
        self.sapling_tree_size
    }
}

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
        validate_from.map(|(h, _)| h + 1),
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
    from_height: Option<BlockHeight>,
    limit: Option<u32>,
) -> Result<(), Error<DbT::Error, BlockSourceT::Error, DbT::NoteRef>>
where
    ParamsT: consensus::Parameters + Send + 'static,
    BlockSourceT: BlockSource,
    DbT: WalletWrite,
{
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

    // Get the nullifiers for the unspent notes we are tracking
    let mut sapling_nullifiers = data_db
        .get_sapling_nullifiers(NullifierQuery::Unspent)
        .map_err(Error::Wallet)?;

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

    // Start at either the provided height, or where we synced up to previously.
    let (from_height, commitment_tree_meta) = from_height.map_or_else(
        || {
            data_db.fully_scanned_height().map_or_else(
                |e| Err(Error::Wallet(e)),
                |last_scanned| {
                    Ok(last_scanned.map_or_else(|| (None, None), |(h, m)| (Some(h + 1), Some(m))))
                },
            )
        },
        |h| Ok((Some(h), None)),
    )?;

    block_source.with_blocks::<_, DbT::Error, DbT::NoteRef>(
        from_height,
        limit,
        |block: CompactBlock| {
            add_block_to_runner(params, block, &mut batch_runner);
            Ok(())
        },
    )?;

    batch_runner.flush();

    block_source.with_blocks::<_, DbT::Error, DbT::NoteRef>(
        from_height,
        limit,
        |block: CompactBlock| {
            let pruned_block = scan_block_with_runner(
                params,
                block,
                &dfvks,
                &sapling_nullifiers,
                commitment_tree_meta.as_ref(),
                Some(&mut batch_runner),
            )
            .map_err(Error::Sync)?;

            let spent_nf: Vec<&sapling::Nullifier> = pruned_block
                .transactions
                .iter()
                .flat_map(|tx| tx.sapling_spends.iter().map(|spend| spend.nf()))
                .collect();

            sapling_nullifiers.retain(|(_, nf)| !spent_nf.contains(&nf));
            sapling_nullifiers.extend(pruned_block.transactions.iter().flat_map(|tx| {
                tx.sapling_outputs
                    .iter()
                    .map(|out| (out.account(), *out.nf()))
            }));

            data_db.put_block(pruned_block).map_err(Error::Wallet)?;

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
