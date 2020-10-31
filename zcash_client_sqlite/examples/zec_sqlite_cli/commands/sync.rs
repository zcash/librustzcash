use futures_util::TryStreamExt;
use gumdrop::Options;
use prost::Message;
use tokio::{fs::File, io::AsyncWriteExt};
use zcash_client_backend::{
    data_api::{chain::scan_cached_blocks, WalletRead},
    proto::service,
};
use zcash_client_sqlite::{chain::BlockMeta, FsBlockDb, WalletDb};
use zcash_primitives::consensus::{BlockHeight, Parameters};

use crate::{
    data::{get_block_path, get_db_paths},
    error,
    remote::connect_to_lightwalletd,
};

use super::init::CHECKPOINT_HEIGHT;

const BATCH_SIZE: u32 = 10_000;

// Options accepted for the `sync` command
#[derive(Debug, Options)]
pub(crate) struct Command {}

impl Command {
    pub(crate) async fn run(
        self,
        params: impl Parameters + Copy + Send + 'static,
        wallet_dir: Option<String>,
    ) -> Result<(), anyhow::Error> {
        let (fsblockdb_root, db_data) = get_db_paths(wallet_dir.as_ref());
        let fsblockdb_root = fsblockdb_root.as_path();
        let db_cache = FsBlockDb::for_path(fsblockdb_root).map_err(error::Error::from)?;

        let mut client = connect_to_lightwalletd().await?;

        // Download all the CompactBlocks we need.
        let latest_height = {
            // Recall where we synced up to previously.
            // If we have never synced, use wallet birthday to fetch all relevant CompactBlocks.
            let mut start_height: BlockHeight = db_cache
                .get_max_cached_height()
                .map(|res| res.map(|h| h + 1))
                .map_err(error::Error::from)?
                .unwrap_or(BlockHeight::from(CHECKPOINT_HEIGHT as u32));

            loop {
                // Get the latest height.
                let latest_height: BlockHeight = client
                    .get_latest_block(service::ChainSpec::default())
                    .await?
                    .get_ref()
                    .height
                    .try_into()
                    // TODO
                    .map_err(|_| error::Error::InvalidAmount)?;

                if latest_height + 1 == start_height {
                    break latest_height;
                } else if latest_height < start_height {
                    // If the latest height is before the start height, we need to do some
                    // cleanup. TODO: Do the cleanup.
                    return Err(anyhow::format_err!(
                        "Rollback detected, which we don't handle yet"
                    ));
                }

                // Calculate the next batch size.
                let end_height = if u32::from(latest_height - start_height) < BATCH_SIZE {
                    latest_height
                } else {
                    start_height + BATCH_SIZE - 1
                };

                // Request the next batch of blocks.
                println!("Fetching blocks {}..{}", start_height, end_height);
                let mut start = service::BlockId::default();
                start.height = start_height.into();
                let mut end = service::BlockId::default();
                end.height = end_height.into();
                let range = service::BlockRange {
                    start: Some(start),
                    end: Some(end),
                };
                let block_meta = client
                    .get_block_range(range)
                    .await
                    .map_err(anyhow::Error::from)?
                    .into_inner()
                    .and_then(|block| async move {
                        let (sapling_outputs_count, orchard_actions_count) = block
                            .vtx
                            .iter()
                            .map(|tx| (tx.outputs.len() as u32, tx.actions.len() as u32))
                            .fold((0, 0), |(acc_sapling, acc_orchard), (sapling, orchard)| {
                                (acc_sapling + sapling, acc_orchard + orchard)
                            });

                        let meta = BlockMeta {
                            height: block.height(),
                            block_hash: block.hash(),
                            block_time: block.time,
                            sapling_outputs_count,
                            orchard_actions_count,
                        };

                        let encoded = block.encode_to_vec();
                        let mut block_file =
                            File::create(get_block_path(&fsblockdb_root, &meta)).await?;
                        block_file.write_all(&encoded).await?;

                        Ok(meta)
                    })
                    .try_collect::<Vec<_>>()
                    .await?;

                db_cache
                    .write_block_metadata(&block_meta)
                    .map_err(error::Error::from)?;

                if end_height == latest_height {
                    break latest_height;
                } else {
                    start_height = end_height + 1
                }
            }
        };

        let db_data = WalletDb::for_path(db_data, params)?;
        let mut db_data = db_data.get_update_ops()?;

        // Scan the cached CompactBlocks.
        loop {
            let last_height = db_data
                .block_height_extrema()
                .map(|opt| opt.map(|(_, max)| max))?;
            match last_height {
                Some(h) if h >= latest_height => break,
                Some(h) if h + BATCH_SIZE > latest_height => {
                    println!("Scanning blocks {}..{}", h, latest_height)
                }
                Some(h) => println!("Scanning blocks {}..{}", h, h + BATCH_SIZE),
                None => (),
            }
            scan_cached_blocks(&params, &db_cache, &mut db_data, Some(BATCH_SIZE))?;
        }

        Ok(())
    }
}
