#![allow(clippy::needless_doctest_main)]
//! Tools for blockchain validation & scanning
//!
//! # Examples
//!
//! ```
//! # #[cfg(feature = "test-dependencies")]
//! # {
//! use zcash_primitives::{
//!     consensus::{BlockHeight, Network, Parameters},
//! };
//!
//! use zcash_client_backend::{
//!     data_api::{
//!         WalletRead, WalletWrite, WalletCommitmentTrees,
//!         chain::{
//!             BlockSource,
//!             CommitmentTreeRoot,
//!             error::Error,
//!             scan_cached_blocks,
//!             testing as chain_testing,
//!         },
//!         scanning::ScanPriority,
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
//! # fn test() -> Result<(), Error<(), Infallible>> {
//! let network = Network::TestNetwork;
//! let block_source = chain_testing::MockBlockSource;
//! let mut wallet_db = testing::MockWalletDb::new(Network::TestNetwork);
//!
//! // 1) Download note commitment tree data from lightwalletd
//! let roots: Vec<CommitmentTreeRoot<sapling::Node>> = unimplemented!();
//!
//! // 2) Pass the commitment tree data to the database.
//! wallet_db.put_sapling_subtree_roots(0, &roots).unwrap();
//!
//! // 3) Download chain tip metadata from lightwalletd
//! let tip_height: BlockHeight = unimplemented!();
//!
//! // 4) Notify the wallet of the updated chain tip.
//! wallet_db.update_chain_tip(tip_height).map_err(Error::Wallet)?;
//!
//! // 5) Get the suggested scan ranges from the wallet database
//! let mut scan_ranges = wallet_db.suggest_scan_ranges().map_err(Error::Wallet)?;
//!
//! // 6) Run the following loop until the wallet's view of the chain tip as of the previous wallet
//! //    session is valid.
//! loop {
//!     // If there is a range of blocks that needs to be verified, it will always be returned as
//!     // the first element of the vector of suggested ranges.
//!     match scan_ranges.first() {
//!         Some(scan_range) if scan_range.priority() == ScanPriority::Verify => {
//!             // Download the chain state for the block prior to the start of the range you want
//!             // to scan.
//!             let chain_state = unimplemented!("get_chain_state(scan_range.block_range().start - 1)?;");
//!             // Download the blocks in `scan_range` into the block source, overwriting any
//!             // existing blocks in this range.
//!             unimplemented!("cache_blocks(scan_range)?;");
//!
//!             // Scan the downloaded blocks
//!             let scan_result = scan_cached_blocks(
//!                 &network,
//!                 &block_source,
//!                 &mut wallet_db,
//!                 scan_range.block_range().start,
//!                 chain_state,
//!                 scan_range.len()
//!             );
//!
//!             // Check for scanning errors that indicate that the wallet's chain tip is out of
//!             // sync with blockchain history.
//!             match scan_result {
//!                 Ok(_) => {
//!                     // At this point, the cache and scanned data are locally consistent (though
//!                     // not necessarily consistent with the latest chain tip - this would be
//!                     // discovered the next time this codepath is executed after new blocks are
//!                     // received) so we can break out of the loop.
//!                     break;
//!                 }
//!                 Err(Error::Scan(err)) if err.is_continuity_error() => {
//!                     // Pick a height to rewind to, which must be at least one block before
//!                     // the height at which the error occurred, but may be an earlier height
//!                     // determined based on heuristics such as the platform, available bandwidth,
//!                     // size of recent CompactBlocks, etc.
//!                     let rewind_height = err.at_height().saturating_sub(10);
//!
//!                     // Rewind to the chosen height.
//!                     wallet_db.truncate_to_height(rewind_height).map_err(Error::Wallet)?;
//!
//!                     // Delete cached blocks from rewind_height onwards.
//!                     //
//!                     // This does imply that assumed-valid blocks will be re-downloaded, but it
//!                     // is also possible that in the intervening time, a chain reorg has
//!                     // occurred that orphaned some of those blocks.
//!                     unimplemented!();
//!                 }
//!                 Err(other) => {
//!                     // Handle or return other errors
//!                 }
//!             }
//!
//!             // In case we updated the suggested scan ranges, now re-request.
//!             scan_ranges = wallet_db.suggest_scan_ranges().map_err(Error::Wallet)?;
//!         }
//!         _ => {
//!             // Nothing to verify; break out of the loop
//!             break;
//!         }
//!     }
//! }
//!
//! // 7) Loop over the remaining suggested scan ranges, retrieving the requested data and calling
//! //    `scan_cached_blocks` on each range. Periodically, or if a continuity error is
//! //    encountered, this process should be repeated starting at step (3).
//! let scan_ranges = wallet_db.suggest_scan_ranges().map_err(Error::Wallet)?;
//! for scan_range in scan_ranges {
//!     // Download the chain state for the block prior to the start of the range you want
//!     // to scan.
//!     let chain_state = unimplemented!("get_chain_state(scan_range.block_range().start - 1)?;");
//!     // Download the blocks in `scan_range` into the block source. While in this example this
//!     // step is performed in-line, it's fine for the download of scan ranges to be asynchronous
//!     // and for the scanner to process the downloaded ranges as they become available in a
//!     // separate thread. The scan ranges should also be broken down into smaller chunks as
//!     // appropriate, and for ranges with priority `Historic` it can be useful to download and
//!     // scan the range in reverse order (to discover more recent unspent notes sooner), or from
//!     // the start and end of the range inwards.
//!     unimplemented!("cache_blocks(scan_range)?;");
//!
//!     // Scan the downloaded blocks.
//!     let scan_result = scan_cached_blocks(
//!         &network,
//!         &block_source,
//!         &mut wallet_db,
//!         scan_range.block_range().start,
//!         chain_state,
//!         scan_range.len()
//!     )?;
//!
//!     // Handle scan errors, etc.
//! }
//! # Ok(())
//! # }
//! # }
//! ```

use std::ops::Range;

use incrementalmerkletree::frontier::Frontier;
use subtle::ConditionallySelectable;
use zcash_primitives::consensus::{self, BlockHeight};

use crate::{
    data_api::{NullifierQuery, WalletWrite},
    proto::compact_formats::CompactBlock,
    scanning::{scan_block_with_runners, BatchRunners, Nullifiers, ScanningKeys},
};

pub mod error;
use error::Error;

use super::WalletRead;

/// A struct containing metadata about a subtree root of the note commitment tree.
///
/// This stores the block height at which the leaf that completed the subtree was
/// added, and the root hash of the complete subtree.
pub struct CommitmentTreeRoot<H> {
    subtree_end_height: BlockHeight,
    root_hash: H,
}

impl<H> CommitmentTreeRoot<H> {
    /// Construct a new `CommitmentTreeRoot` from its constituent parts.
    pub fn from_parts(subtree_end_height: BlockHeight, root_hash: H) -> Self {
        Self {
            subtree_end_height,
            root_hash,
        }
    }

    /// Returns the block height at which the leaf that completed the subtree was added.
    pub fn subtree_end_height(&self) -> BlockHeight {
        self.subtree_end_height
    }

    /// Returns the root of the complete subtree.
    pub fn root_hash(&self) -> &H {
        &self.root_hash
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
    fn with_blocks<F, WalletErrT>(
        &self,
        from_height: Option<BlockHeight>,
        limit: Option<usize>,
        with_block: F,
    ) -> Result<(), error::Error<WalletErrT, Self::Error>>
    where
        F: FnMut(CompactBlock) -> Result<(), error::Error<WalletErrT, Self::Error>>;
}

/// Metadata about modifications to the wallet state made in the course of scanning a set of
/// blocks.
#[derive(Clone, Debug)]
pub struct ScanSummary {
    pub(crate) scanned_range: Range<BlockHeight>,
    pub(crate) spent_sapling_note_count: usize,
    pub(crate) received_sapling_note_count: usize,
    #[cfg(feature = "orchard")]
    pub(crate) spent_orchard_note_count: usize,
    #[cfg(feature = "orchard")]
    pub(crate) received_orchard_note_count: usize,
}

impl ScanSummary {
    /// Constructs a new [`ScanSummary`] for the provided block range.
    pub(crate) fn for_range(scanned_range: Range<BlockHeight>) -> Self {
        Self {
            scanned_range,
            spent_sapling_note_count: 0,
            received_sapling_note_count: 0,
            #[cfg(feature = "orchard")]
            spent_orchard_note_count: 0,
            #[cfg(feature = "orchard")]
            received_orchard_note_count: 0,
        }
    }

    /// Returns the range of blocks successfully scanned.
    pub fn scanned_range(&self) -> Range<BlockHeight> {
        self.scanned_range.clone()
    }

    /// Returns the number of our previously-detected Sapling notes that were spent in transactions
    /// in blocks in the scanned range. If we have not yet detected a particular note as ours, for
    /// example because we are scanning the chain in reverse height order, we will not detect it
    /// being spent at this time.
    pub fn spent_sapling_note_count(&self) -> usize {
        self.spent_sapling_note_count
    }

    /// Returns the number of Sapling notes belonging to the wallet that were received in blocks in
    /// the scanned range. Note that depending upon the scanning order, it is possible that some of
    /// the received notes counted here may already have been spent in later blocks closer to the
    /// chain tip.
    pub fn received_sapling_note_count(&self) -> usize {
        self.received_sapling_note_count
    }

    /// Returns the number of our previously-detected Orchard notes that were spent in transactions
    /// in blocks in the scanned range. If we have not yet detected a particular note as ours, for
    /// example because we are scanning the chain in reverse height order, we will not detect it
    /// being spent at this time.
    #[cfg(feature = "orchard")]
    pub fn spent_orchard_note_count(&self) -> usize {
        self.spent_orchard_note_count
    }

    /// Returns the number of Orchard notes belonging to the wallet that were received in blocks in
    /// the scanned range. Note that depending upon the scanning order, it is possible that some of
    /// the received notes counted here may already have been spent in later blocks closer to the
    /// chain tip.
    #[cfg(feature = "orchard")]
    pub fn received_orchard_note_count(&self) -> usize {
        self.received_orchard_note_count
    }
}

/// The final note commitment tree state for each shielded pool, as of a particular block height.
#[derive(Debug, Clone)]
pub struct ChainState {
    block_height: BlockHeight,
    final_sapling_tree: Frontier<sapling::Node, { sapling::NOTE_COMMITMENT_TREE_DEPTH }>,
    #[cfg(feature = "orchard")]
    final_orchard_tree:
        Frontier<orchard::tree::MerkleHashOrchard, { orchard::NOTE_COMMITMENT_TREE_DEPTH as u8 }>,
}

impl ChainState {
    /// Construct a new empty chain state.
    pub fn empty(block_height: BlockHeight) -> Self {
        Self {
            block_height,
            final_sapling_tree: Frontier::empty(),
            #[cfg(feature = "orchard")]
            final_orchard_tree: Frontier::empty(),
        }
    }

    /// Construct a new [`ChainState`] from its constituent parts.
    pub fn new(
        block_height: BlockHeight,
        final_sapling_tree: Frontier<sapling::Node, { sapling::NOTE_COMMITMENT_TREE_DEPTH }>,
        #[cfg(feature = "orchard")] final_orchard_tree: Frontier<
            orchard::tree::MerkleHashOrchard,
            { orchard::NOTE_COMMITMENT_TREE_DEPTH as u8 },
        >,
    ) -> Self {
        Self {
            block_height,
            final_sapling_tree,
            #[cfg(feature = "orchard")]
            final_orchard_tree,
        }
    }

    /// Returns the block height to which this chain state applies.
    pub fn block_height(&self) -> BlockHeight {
        self.block_height
    }

    /// Returns the frontier of the Sapling note commitment tree as of the end of the block at
    /// [`Self::block_height`].
    pub fn final_sapling_tree(
        &self,
    ) -> &Frontier<sapling::Node, { sapling::NOTE_COMMITMENT_TREE_DEPTH }> {
        &self.final_sapling_tree
    }

    /// Returns the frontier of the Orchard note commitment tree as of the end of the block at
    /// [`Self::block_height`].
    #[cfg(feature = "orchard")]
    pub fn final_orchard_tree(
        &self,
    ) -> &Frontier<orchard::tree::MerkleHashOrchard, { orchard::NOTE_COMMITMENT_TREE_DEPTH as u8 }>
    {
        &self.final_orchard_tree
    }
}

/// Scans at most `limit` blocks from the provided block source for in order to find transactions
/// received by the accounts tracked in the provided wallet database.
///
/// This function will return after scanning at most `limit` new blocks, to enable the caller to
/// update their UI with scanning progress. Repeatedly calling this function with `from_height ==
/// None` will process sequential ranges of blocks.
///
/// ## Panics
///
/// This method will panic if `from_height != from_state.block_height() + 1`.
#[tracing::instrument(skip(params, block_source, data_db))]
#[allow(clippy::type_complexity)]
pub fn scan_cached_blocks<ParamsT, DbT, BlockSourceT>(
    params: &ParamsT,
    block_source: &BlockSourceT,
    data_db: &mut DbT,
    from_height: BlockHeight,
    from_state: &ChainState,
    limit: usize,
) -> Result<ScanSummary, Error<DbT::Error, BlockSourceT::Error>>
where
    ParamsT: consensus::Parameters + Send + 'static,
    BlockSourceT: BlockSource,
    DbT: WalletWrite,
    <DbT as WalletRead>::AccountId: ConditionallySelectable + Default + Send + 'static,
{
    assert_eq!(from_height, from_state.block_height + 1);

    // Fetch the UnifiedFullViewingKeys we are tracking
    let account_ufvks = data_db
        .get_unified_full_viewing_keys()
        .map_err(Error::Wallet)?;
    let scanning_keys = ScanningKeys::from_account_ufvks(account_ufvks);
    let mut runners = BatchRunners::<_, (), ()>::for_keys(100, &scanning_keys);

    block_source.with_blocks::<_, DbT::Error>(Some(from_height), Some(limit), |block| {
        runners.add_block(params, block).map_err(|e| e.into())
    })?;
    runners.flush();

    let mut prior_block_metadata = if from_height > BlockHeight::from(0) {
        data_db
            .block_metadata(from_height - 1)
            .map_err(Error::Wallet)?
    } else {
        None
    };

    // Get the nullifiers for the unspent notes we are tracking
    let mut nullifiers = Nullifiers::new(
        data_db
            .get_sapling_nullifiers(NullifierQuery::Unspent)
            .map_err(Error::Wallet)?,
        #[cfg(feature = "orchard")]
        data_db
            .get_orchard_nullifiers(NullifierQuery::Unspent)
            .map_err(Error::Wallet)?,
    );

    let mut scanned_blocks = vec![];
    let mut scan_summary = ScanSummary::for_range(from_height..from_height);
    block_source.with_blocks::<_, DbT::Error>(
        Some(from_height),
        Some(limit),
        |block: CompactBlock| {
            scan_summary.scanned_range.end = block.height() + 1;
            let scanned_block = scan_block_with_runners::<_, _, _, (), ()>(
                params,
                block,
                &scanning_keys,
                &nullifiers,
                prior_block_metadata.as_ref(),
                Some(&mut runners),
            )
            .map_err(Error::Scan)?;

            for wtx in &scanned_block.transactions {
                scan_summary.spent_sapling_note_count += wtx.sapling_spends().len();
                scan_summary.received_sapling_note_count += wtx.sapling_outputs().len();
                #[cfg(feature = "orchard")]
                {
                    scan_summary.spent_orchard_note_count += wtx.orchard_spends().len();
                    scan_summary.received_orchard_note_count += wtx.orchard_outputs().len();
                }
            }

            let sapling_spent_nf: Vec<&sapling::Nullifier> = scanned_block
                .transactions
                .iter()
                .flat_map(|tx| tx.sapling_spends().iter().map(|spend| spend.nf()))
                .collect();
            nullifiers.retain_sapling(|(_, nf)| !sapling_spent_nf.contains(&nf));
            nullifiers.extend_sapling(scanned_block.transactions.iter().flat_map(|tx| {
                tx.sapling_outputs()
                    .iter()
                    .flat_map(|out| out.nf().into_iter().map(|nf| (*out.account_id(), *nf)))
            }));

            #[cfg(feature = "orchard")]
            {
                let orchard_spent_nf: Vec<&orchard::note::Nullifier> = scanned_block
                    .transactions
                    .iter()
                    .flat_map(|tx| tx.orchard_spends().iter().map(|spend| spend.nf()))
                    .collect();

                nullifiers.retain_orchard(|(_, nf)| !orchard_spent_nf.contains(&nf));
                nullifiers.extend_orchard(scanned_block.transactions.iter().flat_map(|tx| {
                    tx.orchard_outputs()
                        .iter()
                        .flat_map(|out| out.nf().into_iter().map(|nf| (*out.account_id(), *nf)))
                }));
            }

            prior_block_metadata = Some(scanned_block.to_block_metadata());
            scanned_blocks.push(scanned_block);

            Ok(())
        },
    )?;

    data_db
        .put_blocks(from_state, scanned_blocks)
        .map_err(Error::Wallet)?;
    Ok(scan_summary)
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

        fn with_blocks<F, DbErrT>(
            &self,
            _from_height: Option<BlockHeight>,
            _limit: Option<usize>,
            _with_row: F,
        ) -> Result<(), Error<DbErrT, Infallible>>
        where
            F: FnMut(CompactBlock) -> Result<(), Error<DbErrT, Infallible>>,
        {
            Ok(())
        }
    }
}
