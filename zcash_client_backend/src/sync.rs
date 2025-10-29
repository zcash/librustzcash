//! Implementation of the synchronization flow described in the crate root.
//!
//! This is currently a simple implementation that does not yet implement a few features:
//!
//! - Block batches are not downloaded in parallel with scanning.
//! - Transactions are not enhanced once detected (that is, after an output is detected in
//!   a transaction, the full transaction is not downloaded and scanned).
//! - There is no mechanism for notifying the caller of progress updates.
//! - There is no mechanism for interrupting the synchronization flow, other than ending
//!   the process.

use std::fmt;

use futures_util::TryStreamExt;
use shardtree::error::ShardTreeError;
use subtle::ConditionallySelectable;
use tonic::{
    body::Body as TonicBody,
    client::GrpcService,
    codegen::{Body, Bytes, StdError},
};
use tracing::{debug, info};

use zcash_primitives::merkle_tree::HashSer;
use zcash_protocol::consensus::{BlockHeight, Parameters};

use crate::{
    data_api::{
        WalletCommitmentTrees, WalletRead, WalletWrite,
        chain::{
            BlockCache, ChainState, CommitmentTreeRoot, error::Error as ChainError,
            scan_cached_blocks,
        },
        scanning::{ScanPriority, ScanRange},
    },
    proto::service::{self, BlockId, compact_tx_streamer_client::CompactTxStreamerClient},
    scanning::ScanError,
};

#[cfg(feature = "orchard")]
use orchard::tree::MerkleHashOrchard;

#[cfg(feature = "transparent-inputs")]
use {
    crate::wallet::WalletTransparentOutput,
    ::transparent::{
        address::Script,
        bundle::{OutPoint, TxOut},
    },
    zcash_keys::encoding::AddressCodec as _,
    zcash_protocol::value::Zatoshis,
    zcash_script::script,
};

/// Scans the chain until the wallet is up-to-date.
pub async fn run<P, ChT, CaT, DbT>(
    client: &mut CompactTxStreamerClient<ChT>,
    params: &P,
    db_cache: &CaT,
    db_data: &mut DbT,
    batch_size: u32,
) -> Result<(), Error<CaT::Error, <DbT as WalletRead>::Error, <DbT as WalletCommitmentTrees>::Error>>
where
    P: Parameters + Send + 'static,
    ChT: GrpcService<TonicBody>,
    ChT::Error: Into<StdError>,
    ChT::ResponseBody: Body<Data = Bytes> + Send + 'static,
    <ChT::ResponseBody as Body>::Error: Into<StdError> + Send,
    CaT: BlockCache,
    CaT::Error: std::error::Error + Send + Sync + 'static,
    DbT: WalletWrite + WalletCommitmentTrees,
    DbT::AccountId: ConditionallySelectable + Default + Send + 'static,
    <DbT as WalletRead>::Error: std::error::Error + Send + Sync + 'static,
    <DbT as WalletCommitmentTrees>::Error: std::error::Error + Send + Sync + 'static,
{
    // 1) Download note commitment tree data from lightwalletd
    // 2) Pass the commitment tree data to the database.
    update_subtree_roots(client, db_data).await?;

    while running(client, params, db_cache, db_data, batch_size).await? {}

    Ok(())
}

pub async fn running<P, ChT, CaT, DbT, TrErr>(
    client: &mut CompactTxStreamerClient<ChT>,
    params: &P,
    db_cache: &CaT,
    db_data: &mut DbT,
    batch_size: u32,
) -> Result<bool, Error<CaT::Error, <DbT as WalletRead>::Error, TrErr>>
where
    P: Parameters + Send + 'static,
    ChT: GrpcService<TonicBody>,
    ChT::Error: Into<StdError>,
    ChT::ResponseBody: Body<Data = Bytes> + Send + 'static,
    <ChT::ResponseBody as Body>::Error: Into<StdError> + Send,
    CaT: BlockCache,
    CaT::Error: std::error::Error + Send + Sync + 'static,
    DbT: WalletWrite,
    DbT::AccountId: ConditionallySelectable + Default + Send + 'static,
    DbT::Error: std::error::Error + Send + Sync + 'static,
{
    // 3) Download chain tip metadata from lightwalletd
    // 4) Notify the wallet of the updated chain tip.
    update_chain_tip(client, db_data).await?;

    // Refresh UTXOs for the accounts in the wallet. We do this before we perform
    // any shielded scanning, to ensure that we discover any UTXOs between the old
    // fully-scanned height and the current chain tip.
    #[cfg(feature = "transparent-inputs")]
    for account_id in db_data.get_account_ids().map_err(Error::Wallet)? {
        let start_height = db_data
            .utxo_query_height(account_id)
            .map_err(Error::Wallet)?;
        info!(
            "Refreshing UTXOs for {:?} from height {}",
            account_id, start_height,
        );
        refresh_utxos(params, client, db_data, account_id, start_height).await?;
    }

    // 5) Get the suggested scan ranges from the wallet database
    let mut scan_ranges = db_data.suggest_scan_ranges().map_err(Error::Wallet)?;

    // Store the handles to cached block deletions (which we spawn into separate
    // tasks to allow us to continue downloading and scanning other ranges).
    let mut block_deletions = vec![];

    // 6) Run the following loop until the wallet's view of the chain tip as of
    //    the previous wallet session is valid.
    loop {
        // If there is a range of blocks that needs to be verified, it will always
        // be returned as the first element of the vector of suggested ranges.
        match scan_ranges.first() {
            Some(scan_range) if scan_range.priority() == ScanPriority::Verify => {
                // Download the blocks in `scan_range` into the block source,
                // overwriting any existing blocks in this range.
                download_blocks(client, db_cache, scan_range).await?;

                let chain_state =
                    download_chain_state(client, scan_range.block_range().start - 1).await?;

                // Scan the downloaded blocks and check for scanning errors that
                // indicate the wallet's chain tip is out of sync with blockchain
                // history.
                let scan_ranges_updated =
                    scan_blocks(params, db_cache, db_data, &chain_state, scan_range).await?;

                // Delete the now-scanned blocks, because keeping the entire chain
                // in CompactBlock files on disk is horrendous for the filesystem.
                block_deletions.push(db_cache.delete(scan_range.clone()));

                if scan_ranges_updated {
                    // The suggested scan ranges have been updated, so we re-request.
                    scan_ranges = db_data.suggest_scan_ranges().map_err(Error::Wallet)?;
                } else {
                    // At this point, the cache and scanned data are locally
                    // consistent (though not necessarily consistent with the
                    // latest chain tip - this would be discovered the next time
                    // this codepath is executed after new blocks are received) so
                    // we can break out of the loop.
                    break;
                }
            }
            _ => {
                // Nothing to verify; break out of the loop
                break;
            }
        }
    }

    // 7) Loop over the remaining suggested scan ranges, retrieving the requested data
    //    and calling `scan_cached_blocks` on each range.
    let scan_ranges = db_data.suggest_scan_ranges().map_err(Error::Wallet)?;
    debug!("Suggested ranges: {:?}", scan_ranges);
    for scan_range in scan_ranges.into_iter().flat_map(|r| {
        // Limit the number of blocks we download and scan at any one time.
        (0..).scan(r, |acc, _| {
            if acc.is_empty() {
                None
            } else if let Some((cur, next)) = acc.split_at(acc.block_range().start + batch_size) {
                *acc = next;
                Some(cur)
            } else {
                let cur = acc.clone();
                let end = acc.block_range().end;
                *acc = ScanRange::from_parts(end..end, acc.priority());
                Some(cur)
            }
        })
    }) {
        // Download the blocks in `scan_range` into the block source.
        download_blocks(client, db_cache, &scan_range).await?;

        let chain_state = download_chain_state(client, scan_range.block_range().start - 1).await?;

        // Scan the downloaded blocks.
        let scan_ranges_updated =
            scan_blocks(params, db_cache, db_data, &chain_state, &scan_range).await?;

        // Delete the now-scanned blocks.
        block_deletions.push(db_cache.delete(scan_range));

        if scan_ranges_updated {
            // The suggested scan ranges have been updated (either due to a continuity
            // error or because a higher priority range has been added).
            info!("Waiting for cached blocks to be deleted...");
            for deletion in block_deletions {
                deletion.await.map_err(Error::Cache)?;
            }
            return Ok(true);
        }
    }

    info!("Waiting for cached blocks to be deleted...");
    for deletion in block_deletions {
        deletion.await.map_err(Error::Cache)?;
    }
    Ok(false)
}

pub async fn update_subtree_roots<ChT, DbT, CaErr, DbErr>(
    client: &mut CompactTxStreamerClient<ChT>,
    db_data: &mut DbT,
) -> Result<(), Error<CaErr, DbErr, <DbT as WalletCommitmentTrees>::Error>>
where
    ChT: GrpcService<TonicBody>,
    ChT::Error: Into<StdError>,
    ChT::ResponseBody: Body<Data = Bytes> + Send + 'static,
    <ChT::ResponseBody as Body>::Error: Into<StdError> + Send,
    DbT: WalletCommitmentTrees,
    <DbT as WalletCommitmentTrees>::Error: std::error::Error + Send + Sync + 'static,
{
    let mut request = service::GetSubtreeRootsArg::default();
    request.set_shielded_protocol(service::ShieldedProtocol::Sapling);

    let sapling_roots: Vec<CommitmentTreeRoot<sapling::Node>> = client
        .get_subtree_roots(request)
        .await?
        .into_inner()
        .and_then(|root| async move {
            let root_hash = sapling::Node::read(&root.root_hash[..])?;
            Ok(CommitmentTreeRoot::from_parts(
                BlockHeight::from_u32(root.completing_block_height as u32),
                root_hash,
            ))
        })
        .try_collect()
        .await?;

    info!("Sapling tree has {} subtrees", sapling_roots.len());
    db_data
        .put_sapling_subtree_roots(0, &sapling_roots)
        .map_err(Error::WalletTrees)?;

    #[cfg(feature = "orchard")]
    {
        let mut request = service::GetSubtreeRootsArg::default();
        request.set_shielded_protocol(service::ShieldedProtocol::Orchard);

        let orchard_roots: Vec<CommitmentTreeRoot<MerkleHashOrchard>> = client
            .get_subtree_roots(request)
            .await?
            .into_inner()
            .and_then(|root| async move {
                let root_hash = MerkleHashOrchard::read(&root.root_hash[..])?;
                Ok(CommitmentTreeRoot::from_parts(
                    BlockHeight::from_u32(root.completing_block_height as u32),
                    root_hash,
                ))
            })
            .try_collect()
            .await?;

        info!("Orchard tree has {} subtrees", orchard_roots.len());
        db_data
            .put_orchard_subtree_roots(0, &orchard_roots)
            .map_err(Error::WalletTrees)?;
    }

    Ok(())
}

pub async fn update_chain_tip<ChT, DbT, CaErr, TrErr>(
    client: &mut CompactTxStreamerClient<ChT>,
    db_data: &mut DbT,
) -> Result<(), Error<CaErr, <DbT as WalletRead>::Error, TrErr>>
where
    ChT: GrpcService<TonicBody>,
    ChT::Error: Into<StdError>,
    ChT::ResponseBody: Body<Data = Bytes> + Send + 'static,
    <ChT::ResponseBody as Body>::Error: Into<StdError> + Send,
    DbT: WalletWrite,
    DbT::Error: std::error::Error + Send + Sync + 'static,
{
    let tip_height: BlockHeight = client
        .get_latest_block(service::ChainSpec::default())
        .await?
        .get_ref()
        .height
        .try_into()
        .map_err(|_| Error::MisbehavingServer)?;

    info!("Latest block height is {}", tip_height);
    db_data
        .update_chain_tip(tip_height)
        .map_err(Error::Wallet)?;

    Ok(())
}

pub async fn download_blocks<ChT, CaT, DbErr, TrErr>(
    client: &mut CompactTxStreamerClient<ChT>,
    db_cache: &CaT,
    scan_range: &ScanRange,
) -> Result<(), Error<CaT::Error, DbErr, TrErr>>
where
    ChT: GrpcService<TonicBody>,
    ChT::Error: Into<StdError>,
    ChT::ResponseBody: Body<Data = Bytes> + Send + 'static,
    <ChT::ResponseBody as Body>::Error: Into<StdError> + Send,
    CaT: BlockCache,
    CaT::Error: std::error::Error + Send + Sync + 'static,
{
    info!("Fetching {}", scan_range);
    let mut start = service::BlockId::default();
    start.height = scan_range.block_range().start.into();
    let mut end = service::BlockId::default();
    end.height = (scan_range.block_range().end - 1).into();
    let range = service::BlockRange {
        start: Some(start),
        end: Some(end),
    };
    let compact_blocks = client
        .get_block_range(range)
        .await?
        .into_inner()
        .try_collect::<Vec<_>>()
        .await?;

    db_cache
        .insert(compact_blocks)
        .await
        .map_err(Error::Cache)?;

    Ok(())
}

pub async fn download_chain_state<ChT, CaErr, DbErr, TrErr>(
    client: &mut CompactTxStreamerClient<ChT>,
    block_height: BlockHeight,
) -> Result<ChainState, Error<CaErr, DbErr, TrErr>>
where
    ChT: GrpcService<TonicBody>,
    ChT::Error: Into<StdError>,
    ChT::ResponseBody: Body<Data = Bytes> + Send + 'static,
    <ChT::ResponseBody as Body>::Error: Into<StdError> + Send,
{
    let tree_state = client
        .get_tree_state(BlockId {
            height: block_height.into(),
            hash: vec![],
        })
        .await?;

    tree_state
        .into_inner()
        .to_chain_state()
        .map_err(|_| Error::MisbehavingServer)
}

/// Scans the given block range and checks for scanning errors that indicate the wallet's
/// chain tip is out of sync with blockchain history.
///
/// Returns `true` if scanning these blocks materially changed the suggested scan ranges.
pub async fn scan_blocks<P, CaT, DbT, TrErr>(
    params: &P,
    db_cache: &CaT,
    db_data: &mut DbT,
    initial_chain_state: &ChainState,
    scan_range: &ScanRange,
) -> Result<bool, Error<CaT::Error, <DbT as WalletRead>::Error, TrErr>>
where
    P: Parameters + Send + 'static,
    CaT: BlockCache,
    CaT::Error: std::error::Error + Send + Sync + 'static,
    DbT: WalletWrite,
    DbT::AccountId: ConditionallySelectable + Default + Send + 'static,
    DbT::Error: std::error::Error + Send + Sync + 'static,
{
    info!("Scanning {}", scan_range);
    let scan_result = scan_cached_blocks(
        params,
        db_cache,
        db_data,
        scan_range.block_range().start,
        initial_chain_state,
        scan_range.len(),
    );

    match scan_result {
        Err(ChainError::Scan(err)) if err.is_continuity_error() => {
            // Pick a height to rewind to, which must be at least one block before the
            // height at which the error occurred, but may be an earlier height determined
            // based on heuristics such as the platform, available bandwidth, size of
            // recent CompactBlocks, etc.
            let rewind_height = err.at_height().saturating_sub(10);
            info!(
                "Chain reorg detected at {}, rewinding to {}",
                err.at_height(),
                rewind_height,
            );

            // Rewind to the chosen height.
            db_data
                .truncate_to_height(rewind_height)
                .map_err(Error::Wallet)?;

            // Delete cached blocks from rewind_height onwards.
            //
            // This does imply that assumed-valid blocks will be re-downloaded, but it is
            // also possible that in the intervening time, a chain reorg has occurred that
            // orphaned some of those blocks.
            db_cache
                .truncate(rewind_height)
                .await
                .map_err(Error::Cache)?;

            // The database was truncated, invalidating prior suggested ranges.
            Ok(true)
        }
        Ok(_) => {
            // If scanning these blocks caused a suggested range to be added that has a
            // higher priority than the current range, invalidate the current ranges.
            let latest_ranges = db_data.suggest_scan_ranges().map_err(Error::Wallet)?;

            Ok(if let Some(range) = latest_ranges.first() {
                range.priority() > scan_range.priority()
            } else {
                false
            })
        }
        Err(e) => Err(e.into()),
    }
}

/// Refreshes the given account's view of UTXOs that exist starting at the given height.
///
/// ## Note about UTXO tracking
///
/// (Extracted from [a comment in the Android SDK].)
///
/// We no longer clear UTXOs here, as `WalletDb::put_received_transparent_utxo` now uses
/// an upsert instead of an insert. This means that now-spent UTXOs would previously have
/// been deleted, but now are left in the database (like shielded notes).
///
/// Due to the fact that the `lightwalletd` query only returns _current_ UTXOs, we don't
/// learn about recently-spent UTXOs here, so the transparent balance does not get updated
/// here.
///
/// Instead, when a received shielded note is "enhanced" by downloading the full
/// transaction, we mark any UTXOs spent in that transaction as spent in the database.
/// This relies on two current properties:
/// - UTXOs are only ever spent in shielding transactions.
/// - At least one shielded note from each shielding transaction is always enhanced.
///
/// However, for greater reliability, we may want to alter the Data Access API to support
/// "inferring spentness" from what is _not_ returned as a UTXO, or alternatively fetch
/// TXOs from `lightwalletd` instead of just UTXOs.
///
/// [a comment in the Android SDK]: https://github.com/Electric-Coin-Company/zcash-android-wallet-sdk/blob/855204fc8ae4057fdac939f98df4aa38c8e662f1/sdk-lib/src/main/java/cash/z/ecc/android/sdk/block/processor/CompactBlockProcessor.kt#L979-L991
#[cfg(feature = "transparent-inputs")]
pub async fn refresh_utxos<P, ChT, DbT, CaErr, TrErr>(
    params: &P,
    client: &mut CompactTxStreamerClient<ChT>,
    db_data: &mut DbT,
    account_id: DbT::AccountId,
    start_height: BlockHeight,
) -> Result<(), Error<CaErr, <DbT as WalletRead>::Error, TrErr>>
where
    P: Parameters + Send + 'static,
    ChT: GrpcService<TonicBody>,
    ChT::Error: Into<StdError>,
    ChT::ResponseBody: Body<Data = Bytes> + Send + 'static,
    <ChT::ResponseBody as Body>::Error: Into<StdError> + Send,
    DbT: WalletWrite,
    DbT::Error: std::error::Error + Send + Sync + 'static,
{
    let request = service::GetAddressUtxosArg {
        addresses: db_data
            .get_transparent_receivers(account_id, true, true)
            .map_err(Error::Wallet)?
            .into_keys()
            .map(|addr| addr.encode(params))
            .collect(),
        start_height: start_height.into(),
        max_entries: 0,
    };

    if request.addresses.is_empty() {
        info!("{:?} has no transparent receivers", account_id);
    } else {
        client
            .get_address_utxos_stream(request)
            .await?
            .into_inner()
            .map_err(Error::Server)
            .and_then(|reply| async move {
                WalletTransparentOutput::from_parts(
                    OutPoint::new(
                        reply.txid[..]
                            .try_into()
                            .map_err(|_| Error::MisbehavingServer)?,
                        reply
                            .index
                            .try_into()
                            .map_err(|_| Error::MisbehavingServer)?,
                    ),
                    TxOut::new(
                        Zatoshis::from_nonnegative_i64(reply.value_zat)
                            .map_err(|_| Error::MisbehavingServer)?,
                        Script(script::Code(reply.script)),
                    ),
                    Some(
                        BlockHeight::try_from(reply.height)
                            .map_err(|_| Error::MisbehavingServer)?,
                    ),
                )
                .ok_or(Error::MisbehavingServer)
            })
            .try_for_each(|output| {
                let res = db_data.put_received_transparent_utxo(&output).map(|_| ());
                async move { res.map_err(Error::Wallet) }
            })
            .await?;
    }

    Ok(())
}

/// Errors that can occur while syncing.
#[derive(Debug)]
pub enum Error<CaErr, DbErr, TrErr> {
    /// An error while interacting with a [`BlockCache`].
    Cache(CaErr),
    /// The lightwalletd server returned invalid information, and is misbehaving.
    MisbehavingServer,
    /// An error while scanning blocks.
    Scan(ScanError),
    /// An error while communicating with the lightwalletd server.
    Server(tonic::Status),
    /// An error while interacting with a wallet database via [`WalletRead`] or
    /// [`WalletWrite`].
    Wallet(DbErr),
    /// An error while interacting with a wallet database via [`WalletCommitmentTrees`].
    WalletTrees(ShardTreeError<TrErr>),
}

impl<CaErr, DbErr, TrErr> fmt::Display for Error<CaErr, DbErr, TrErr>
where
    CaErr: fmt::Display,
    DbErr: fmt::Display,
    TrErr: fmt::Display,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Cache(e) => write!(f, "Error while interacting with block cache: {e}"),
            Error::MisbehavingServer => write!(f, "lightwalletd server is misbehaving"),
            Error::Scan(e) => write!(f, "Error while scanning blocks: {e}"),
            Error::Server(e) => {
                write!(f, "Error while communicating with lightwalletd server: {e}")
            }
            Error::Wallet(e) => write!(f, "Error while interacting with wallet database: {e}"),
            Error::WalletTrees(e) => write!(
                f,
                "Error while interacting with wallet commitment trees: {e}"
            ),
        }
    }
}

impl<CaErr, DbErr, TrErr> std::error::Error for Error<CaErr, DbErr, TrErr>
where
    CaErr: std::error::Error,
    DbErr: std::error::Error,
    TrErr: std::error::Error,
{
}

impl<CaErr, DbErr, TrErr> From<ChainError<DbErr, CaErr>> for Error<CaErr, DbErr, TrErr> {
    fn from(e: ChainError<DbErr, CaErr>) -> Self {
        match e {
            ChainError::Wallet(e) => Error::Wallet(e),
            ChainError::BlockSource(e) => Error::Cache(e),
            ChainError::Scan(e) => Error::Scan(e),
        }
    }
}

impl<CaErr, DbErr, TrErr> From<tonic::Status> for Error<CaErr, DbErr, TrErr> {
    fn from(status: tonic::Status) -> Self {
        Error::Server(status)
    }
}
