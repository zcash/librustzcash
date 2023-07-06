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
//! # fn test() -> Result<(), Error<(), Infallible>> {
//! let network = Network::TestNetwork;
//! let block_source = chain_testing::MockBlockSource;
//! let mut db_data = testing::MockWalletDb::new(Network::TestNetwork);
//!
//! // 1) Download new CompactBlocks into block_source.
//! //
//! // 2) FIXME: Obtain necessary block metadata for continuity checking?
//! //
//! // 3) Scan cached blocks.
//! //
//! // FIXME: update documentation on how to detect when a rewind is required.
//! //
//! // At this point, the cache and scanned data are locally consistent (though not
//! // necessarily consistent with the latest chain tip - this would be discovered the
//! // next time this codepath is executed after new blocks are received).
//! scan_cached_blocks(&network, &block_source, &mut db_data, BlockHeight::from(0), 10)
//! # }
//! # }
//! ```

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
    scanning::{add_block_to_runner, check_continuity, scan_block_with_runner},
};

use super::BlockMetadata;

pub mod error;
use error::Error;

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
        limit: Option<u32>,
        with_row: F,
    ) -> Result<(), error::Error<WalletErrT, Self::Error>>
    where
        F: FnMut(CompactBlock) -> Result<(), error::Error<WalletErrT, Self::Error>>;
}

/// Scans at most `limit` new blocks added to the block source for any transactions received by the
/// tracked accounts.
///
/// If the `from_height` argument is not `None`, then this method block source will begin
/// requesting blocks from the provided block source at the specified height; if `from_height` is
/// `None then this will begin scanning at first block after the position to which the wallet has
/// previously fully scanned the chain, thereby beginning or continuing a linear scan over all
/// blocks.
///
/// This function will return without error after scanning at most `limit` new blocks, to enable
/// the caller to update their UI with scanning progress. Repeatedly calling this function with
/// `from_height == None` will process sequential ranges of blocks.
///
/// For brand-new light client databases, if `from_height == None` this function starts scanning
/// from the Sapling activation height. This height can be fast-forwarded to a more recent block by
/// initializing the client database with a starting block (for example, calling
/// `init_blocks_table` before this function if using `zcash_client_sqlite`).
#[tracing::instrument(skip(params, block_source, data_db))]
#[allow(clippy::type_complexity)]
pub fn scan_cached_blocks<ParamsT, DbT, BlockSourceT>(
    params: &ParamsT,
    block_source: &BlockSourceT,
    data_db: &mut DbT,
    from_height: BlockHeight,
    limit: u32,
) -> Result<(), Error<DbT::Error, BlockSourceT::Error>>
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

    let mut prior_block_metadata = if from_height > BlockHeight::from(0) {
        data_db
            .block_metadata(from_height - 1)
            .map_err(Error::Wallet)?
    } else {
        None
    };

    let mut continuity_check_metadata = prior_block_metadata;
    block_source.with_blocks::<_, DbT::Error>(
        Some(from_height),
        Some(limit),
        |block: CompactBlock| {
            // check block continuity
            if let Some(scan_error) = check_continuity(&block, continuity_check_metadata.as_ref()) {
                return Err(Error::Scan(scan_error));
            }

            if from_height == BlockHeight::from(0) {
                // We can always derive a valid `continuity_check_metadata` for the
                // genesis block, even if the block source doesn't have
                // `sapling_commitment_tree_size`. So briefly set it to a dummy value that
                // ensures the `map` below produces the correct genesis block value.
                assert!(continuity_check_metadata.is_none());
                continuity_check_metadata = Some(BlockMetadata::from_parts(
                    BlockHeight::from(0),
                    BlockHash([0; 32]),
                    0,
                ));
            }
            continuity_check_metadata = continuity_check_metadata.as_ref().map(|m| {
                BlockMetadata::from_parts(
                    block.height(),
                    block.hash(),
                    block
                        .chain_metadata
                        .as_ref()
                        .map(|m| m.sapling_commitment_tree_size)
                        .unwrap_or_else(|| {
                            m.sapling_tree_size()
                                + u32::try_from(
                                    block.vtx.iter().map(|tx| tx.outputs.len()).sum::<usize>(),
                                )
                                .unwrap()
                        }),
                )
            });

            add_block_to_runner(params, block, &mut batch_runner);

            Ok(())
        },
    )?;

    batch_runner.flush();

    let mut scanned_blocks = vec![];
    block_source.with_blocks::<_, DbT::Error>(
        Some(from_height),
        Some(limit),
        |block: CompactBlock| {
            let scanned_block = scan_block_with_runner(
                params,
                block,
                &dfvks,
                &sapling_nullifiers,
                prior_block_metadata.as_ref(),
                Some(&mut batch_runner),
            )
            .map_err(Error::Scan)?;

            let spent_nf: Vec<&sapling::Nullifier> = scanned_block
                .transactions
                .iter()
                .flat_map(|tx| tx.sapling_spends.iter().map(|spend| spend.nf()))
                .collect();

            sapling_nullifiers.retain(|(_, nf)| !spent_nf.contains(&nf));
            sapling_nullifiers.extend(scanned_block.transactions.iter().flat_map(|tx| {
                tx.sapling_outputs
                    .iter()
                    .map(|out| (out.account(), *out.nf()))
            }));

            prior_block_metadata = Some(*scanned_block.metadata());
            scanned_blocks.push(scanned_block);
            Ok(())
        },
    )?;

    data_db.put_blocks(scanned_blocks).map_err(Error::Wallet)?;
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

        fn with_blocks<F, DbErrT>(
            &self,
            _from_height: Option<BlockHeight>,
            _limit: Option<u32>,
            _with_row: F,
        ) -> Result<(), Error<DbErrT, Infallible>>
        where
            F: FnMut(CompactBlock) -> Result<(), Error<DbErrT, Infallible>>,
        {
            Ok(())
        }
    }
}
