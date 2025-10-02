use async_trait::async_trait;
use std::collections::BTreeMap;
use std::convert::Infallible;
use wasm_sync::RwLock;
use zcash_client_backend::data_api::chain::{BlockCache, BlockSource};
use zcash_client_backend::data_api::scanning::ScanRange;
use zcash_client_backend::proto::compact_formats::CompactBlock;
use zcash_protocol::consensus::BlockHeight;

/// A block cache that just holds blocks in a map in memory
#[derive(Default)]
pub struct MemBlockCache(pub(crate) RwLock<BTreeMap<BlockHeight, CompactBlock>>);

impl MemBlockCache {
    /// Constructs a new empty [`MemBlockCache`].
    pub fn new() -> Self {
        Default::default()
    }

    /// Returns the [`CompactBlock`] at the given height, if it exists in the cache.
    pub fn find_block(&self, block_height: BlockHeight) -> Option<CompactBlock> {
        self.0.read().unwrap().get(&block_height).cloned()
    }
}

impl BlockSource for MemBlockCache {
    type Error = Infallible;

    fn with_blocks<F, WalletErrT>(
        &self,
        from_height: Option<zcash_protocol::consensus::BlockHeight>,
        limit: Option<usize>,
        mut with_block: F,
    ) -> Result<(), zcash_client_backend::data_api::chain::error::Error<WalletErrT, Self::Error>>
    where
        F: FnMut(
            CompactBlock,
        ) -> Result<
            (),
            zcash_client_backend::data_api::chain::error::Error<WalletErrT, Self::Error>,
        >,
    {
        let inner = self.0.read().unwrap();
        let block_iter = inner
            .iter()
            .filter(|(_, cb)| {
                if let Some(from_height) = from_height {
                    cb.height() >= from_height
                } else {
                    true
                }
            })
            .take(limit.unwrap_or(usize::MAX));

        for (_, cb) in block_iter {
            with_block(cb.clone())?;
        }
        Ok(())
    }
}

#[async_trait]
impl BlockCache for MemBlockCache {
    fn get_tip_height(
        &self,
        range: Option<&ScanRange>,
    ) -> Result<Option<BlockHeight>, Self::Error> {
        let inner = self.0.read().unwrap();
        if let Some(range) = range {
            let range = range.block_range();
            for h in (u32::from(range.start)..u32::from(range.end)).rev() {
                if let Some(cb) = inner.get(&h.into()) {
                    return Ok(Some(cb.height()));
                }
            }
        } else {
            return Ok(inner.last_key_value().map(|(h, _)| *h));
        }

        Ok(None)
    }

    async fn read(&self, range: &ScanRange) -> Result<Vec<CompactBlock>, Self::Error> {
        let inner = self.0.read().unwrap();
        let mut ret = Vec::with_capacity(range.len());
        let range = range.block_range();
        for height in u32::from(range.start)..u32::from(range.end) {
            if let Some(cb) = inner.get(&height.into()) {
                ret.push(cb.clone());
            }
        }

        Ok(ret)
    }

    async fn insert(&self, compact_blocks: Vec<CompactBlock>) -> Result<(), Self::Error> {
        let mut inner = self.0.write().unwrap();
        compact_blocks.into_iter().for_each(|compact_block| {
            inner.insert(compact_block.height(), compact_block);
        });
        Ok(())
    }

    async fn delete(&self, range: ScanRange) -> Result<(), Self::Error> {
        let mut inner = self.0.write().unwrap();
        let range = range.block_range();
        for height in u32::from(range.start)..u32::from(range.end) {
            inner.remove(&height.into());
        }
        Ok(())
    }
}
