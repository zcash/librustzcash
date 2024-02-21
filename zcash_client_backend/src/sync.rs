use anyhow::anyhow;
use futures_util::TryStreamExt;
use subtle::ConditionallySelectable;
use tonic::{
    body::BoxBody,
    client::GrpcService,
    codegen::{Body, Bytes, StdError},
};
use tracing::{debug, info};
use zcash_primitives::{
    consensus::{BlockHeight, Parameters},
    merkle_tree::HashSer,
};

use crate::{
    data_api::{
        chain::{error::Error as ChainError, scan_cached_blocks, BlockCache, CommitmentTreeRoot},
        scanning::{ScanPriority, ScanRange},
        WalletCommitmentTrees, WalletRead, WalletWrite,
    },
    proto::service::{self, compact_tx_streamer_client::CompactTxStreamerClient},
};

/// Scans the chain until the wallet is up-to-date.
pub async fn run<P, ChT, BcT, DbT>(
    client: &mut CompactTxStreamerClient<ChT>,
    params: &P,
    block_cache: &mut BcT,
    wallet_data: &mut DbT,
    batch_size: u32,
) -> Result<(), anyhow::Error>
where
    P: Parameters + Send + 'static,
    ChT: GrpcService<BoxBody>,
    ChT::Error: Into<StdError>,
    ChT::ResponseBody: Body<Data = Bytes> + Send + 'static,
    <ChT::ResponseBody as Body>::Error: Into<StdError> + Send,
    BcT: BlockCache,
    BcT::Error: std::error::Error + Send + Sync + 'static,
    DbT: WalletWrite + WalletCommitmentTrees,
    <DbT as WalletRead>::AccountId: ConditionallySelectable + Default + Send + 'static,
    <DbT as WalletRead>::Error: std::error::Error + Send + Sync + 'static,
    <DbT as WalletCommitmentTrees>::Error: std::error::Error + Send + Sync + 'static,
{
    // 1) Download note commitment tree data from lightwalletd
    // 2) Pass the commitment tree data to the database.
    update_subtree_roots(client, wallet_data).await?;

    while running(client, params, block_cache, wallet_data, batch_size).await? {}

    Ok(())
}

async fn running<P, ChT, BcT, DbT>(
    client: &mut CompactTxStreamerClient<ChT>,
    params: &P,
    block_cache: &mut BcT,
    wallet_data: &mut DbT,
    batch_size: u32,
) -> Result<bool, anyhow::Error>
where
    P: Parameters + Send + 'static,
    ChT: GrpcService<BoxBody>,
    ChT::Error: Into<StdError>,
    ChT::ResponseBody: Body<Data = Bytes> + Send + 'static,
    <ChT::ResponseBody as Body>::Error: Into<StdError> + Send,
    BcT: BlockCache,
    BcT::Error: std::error::Error + Send + Sync + 'static,
    DbT: WalletWrite,
    <DbT as WalletRead>::AccountId: ConditionallySelectable + Default + Send + 'static,
    DbT::Error: std::error::Error + Send + Sync + 'static,
{
    // 3) Download chain tip metadata from lightwalletd
    // 4) Notify the wallet of the updated chain tip.
    update_chain_tip(client, wallet_data).await?;

    // 5) Get the suggested scan ranges from the wallet database
    let mut scan_ranges = wallet_data.suggest_scan_ranges()?;

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
                download_blocks(client, block_cache, scan_range).await?;

                // Scan the downloaded blocks and check for scanning errors that
                // indicate the wallet's chain tip is out of sync with blockchain
                // history.
                let scan_ranges_updated =
                    scan_blocks(params, block_cache, wallet_data, scan_range)?;

                // Delete the now-scanned blocks, because keeping the entire chain
                // in CompactBlock files on disk is horrendous for the filesystem.
                block_deletions.push(block_cache.delete(scan_range));

                if scan_ranges_updated {
                    // The suggested scan ranges have been updated, so we re-request.
                    scan_ranges = wallet_data.suggest_scan_ranges()?;
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
    let scan_ranges = wallet_data.suggest_scan_ranges()?;
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
        download_blocks(client, block_cache, &scan_range).await?;

        // Scan the downloaded blocks.
        let scan_ranges_updated = scan_blocks(params, block_cache, wallet_data, &scan_range)?;

        // Delete the now-scanned blocks.
        block_deletions.push(block_cache.delete(&scan_range));

        if scan_ranges_updated {
            // The suggested scan ranges have been updated (either due to a continuity
            // error or because a higher priority range has been added).
            info!("Waiting for cached blocks to be deleted...");
            for deletion in block_deletions {
                deletion.await??;
            }
            return Ok(true);
        }
    }

    info!("Waiting for cached blocks to be deleted...");
    for deletion in block_deletions {
        deletion.await??;
    }
    Ok(false)
}

async fn update_subtree_roots<ChT, DbT>(
    client: &mut CompactTxStreamerClient<ChT>,
    wallet_data: &mut DbT,
) -> Result<(), anyhow::Error>
where
    ChT: GrpcService<BoxBody>,
    ChT::Error: Into<StdError>,
    ChT::ResponseBody: Body<Data = Bytes> + Send + 'static,
    <ChT::ResponseBody as Body>::Error: Into<StdError> + Send,
    DbT: WalletCommitmentTrees,
    DbT::Error: std::error::Error + Send + Sync + 'static,
{
    let mut request = service::GetSubtreeRootsArg::default();
    request.set_shielded_protocol(service::ShieldedProtocol::Sapling);
    // Hack to work around a bug in the initial lightwalletd implementation.
    request.max_entries = 65536;

    let roots: Vec<CommitmentTreeRoot<sapling::Node>> = client
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

    info!("Sapling tree has {} subtrees", roots.len());
    wallet_data.put_sapling_subtree_roots(0, &roots)?;

    Ok(())
}

async fn update_chain_tip<ChT, DbT>(
    client: &mut CompactTxStreamerClient<ChT>,
    wallet_data: &mut DbT,
) -> Result<(), anyhow::Error>
where
    ChT: GrpcService<BoxBody>,
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
        // TODO
        .map_err(|_| anyhow::anyhow!("invalid amount"))?;

    info!("Latest block height is {}", tip_height);
    wallet_data.update_chain_tip(tip_height)?;

    Ok(())
}

async fn download_blocks<ChT, BcT>(
    client: &mut CompactTxStreamerClient<ChT>,
    block_cache: &BcT,
    scan_range: &ScanRange,
) -> Result<(), anyhow::Error>
where
    ChT: GrpcService<BoxBody>,
    ChT::Error: Into<StdError>,
    ChT::ResponseBody: Body<Data = Bytes> + Send + 'static,
    <ChT::ResponseBody as Body>::Error: Into<StdError> + Send,
    BcT: BlockCache,
    BcT::Error: std::error::Error + Send + Sync + 'static,
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

    let mut compact_blocks = vec![];
    let mut block_stream = client
        .get_block_range(range)
        .await
        .map_err(anyhow::Error::from)?
        .into_inner();
    while let Some(block) = block_stream.message().await.map_err(anyhow::Error::from)? {
        compact_blocks.push(block);
    }

    block_cache
        .insert(compact_blocks)
        .map_err(anyhow::Error::from)?;

    Ok(())
}

/// Scans the given block range and checks for scanning errors that indicate the wallet's
/// chain tip is out of sync with blockchain history.
///
/// Returns `true` if scanning these blocks materially changed the suggested scan ranges.
fn scan_blocks<P, BcT, DbT>(
    params: &P,
    block_cache: &BcT,
    wallet_data: &mut DbT,
    scan_range: &ScanRange,
) -> Result<bool, anyhow::Error>
where
    P: Parameters + Send + 'static,
    BcT: BlockCache,
    BcT::Error: std::error::Error + Send + Sync + 'static,
    DbT: WalletWrite,
    <DbT as WalletRead>::AccountId: ConditionallySelectable + Default + Send + 'static,
    DbT::Error: std::error::Error + Send + Sync + 'static,
{
    info!("Scanning {}", scan_range);
    let scan_result = scan_cached_blocks(params, block_cache, wallet_data, scan_range);

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
            wallet_data.truncate_to_height(rewind_height)?;

            // Delete cached blocks from rewind_height onwards.
            //
            // This does imply that assumed-valid blocks will be re-downloaded, but it is
            // also possible that in the intervening time, a chain reorg has occurred that
            // orphaned some of those blocks.
            block_cache
                .truncate(rewind_height)
                .map_err(|e| anyhow!("{:?}", e))?;

            // The database was truncated, invalidating prior suggested ranges.
            Ok(true)
        }
        Ok(_) => {
            // If scanning these blocks caused a suggested range to be added that has a
            // higher priority than the current range, invalidate the current ranges.
            let latest_ranges = wallet_data.suggest_scan_ranges()?;

            Ok(if let Some(range) = latest_ranges.first() {
                range.priority() > scan_range.priority()
            } else {
                false
            })
        }
        Err(e) => Err(anyhow!("{:?}", e)),
    }
}
