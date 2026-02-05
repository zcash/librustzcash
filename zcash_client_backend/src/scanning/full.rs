use std::collections::{HashMap, HashSet};
use std::convert::TryFrom;
use std::hash::Hash;

use incrementalmerkletree::Retention;
use sapling::note_encryption::{CompactOutputDescription, SaplingDomain};
use subtle::ConditionallySelectable;

use tracing::{debug, trace};
use zcash_primitives::{
    block::BlockHash,
    transaction::{Transaction, components::sapling::zip212_enforcement},
};
use zcash_protocol::memo::MemoBytes;
use zcash_protocol::{
    ShieldedProtocol, TxId,
    consensus::{self, BlockHeight, NetworkUpgrade},
};

use super::{Nullifiers, ScanError, ScanningKeys, find_received, find_spent};
use crate::data_api::DecryptedTransaction;
use crate::scan::DecryptedOutput;
use crate::{
    data_api::{BlockMetadata, ScannedBlock, ScannedBundles},
    proto::compact_formats::CompactBlock,
    scan::{Batch, BatchRunner, FullDecryptor, Tasks},
    wallet::{WalletSpend, WalletTx},
};

#[cfg(feature = "orchard")]
use orchard::{note_encryption::OrchardDomain, primitives::redpallas, tree::MerkleHashOrchard};

#[cfg(not(feature = "orchard"))]
use std::marker::PhantomData;

type TaggedSaplingBatch<IvkTag> = Batch<
    IvkTag,
    SaplingDomain,
    sapling::bundle::OutputDescription<sapling::bundle::GrothProofBytes>,
    FullDecryptor,
>;
type TaggedSaplingBatchRunner<IvkTag, Tasks> = BatchRunner<
    IvkTag,
    SaplingDomain,
    sapling::bundle::OutputDescription<sapling::bundle::GrothProofBytes>,
    FullDecryptor,
    Tasks,
>;

#[cfg(feature = "orchard")]
type TaggedOrchardBatch<IvkTag> = Batch<
    IvkTag,
    OrchardDomain,
    orchard::Action<redpallas::Signature<redpallas::SpendAuth>>,
    FullDecryptor,
>;
#[cfg(feature = "orchard")]
type TaggedOrchardBatchRunner<IvkTag, Tasks> = BatchRunner<
    IvkTag,
    OrchardDomain,
    orchard::Action<redpallas::Signature<redpallas::SpendAuth>>,
    FullDecryptor,
    Tasks,
>;

pub(crate) trait SaplingTasks<IvkTag>: Tasks<TaggedSaplingBatch<IvkTag>> {}
impl<IvkTag, T: Tasks<TaggedSaplingBatch<IvkTag>>> SaplingTasks<IvkTag> for T {}

#[cfg(not(feature = "orchard"))]
pub(crate) trait OrchardTasks<IvkTag> {}
#[cfg(not(feature = "orchard"))]
impl<IvkTag, T> OrchardTasks<IvkTag> for T {}

#[cfg(feature = "orchard")]
pub(crate) trait OrchardTasks<IvkTag>: Tasks<TaggedOrchardBatch<IvkTag>> {}
#[cfg(feature = "orchard")]
impl<IvkTag, T: Tasks<TaggedOrchardBatch<IvkTag>>> OrchardTasks<IvkTag> for T {}

pub(crate) struct BatchRunners<IvkTag, TS: SaplingTasks<IvkTag>, TO: OrchardTasks<IvkTag>> {
    sapling: TaggedSaplingBatchRunner<IvkTag, TS>,
    #[cfg(feature = "orchard")]
    orchard: TaggedOrchardBatchRunner<IvkTag, TO>,
    #[cfg(not(feature = "orchard"))]
    orchard: PhantomData<TO>,
}

impl<IvkTag, TS, TO> BatchRunners<IvkTag, TS, TO>
where
    IvkTag: Clone + Send + 'static,
    TS: SaplingTasks<IvkTag>,
    TO: OrchardTasks<IvkTag>,
{
    pub(crate) fn for_keys<AccountId>(
        batch_size_threshold: usize,
        scanning_keys: &ScanningKeys<AccountId, IvkTag>,
    ) -> Self {
        BatchRunners {
            sapling: BatchRunner::new(
                batch_size_threshold,
                scanning_keys
                    .sapling()
                    .iter()
                    .map(|(id, key)| (id.clone(), key.prepare())),
            ),
            #[cfg(feature = "orchard")]
            orchard: BatchRunner::new(
                batch_size_threshold,
                scanning_keys
                    .orchard()
                    .iter()
                    .map(|(id, key)| (id.clone(), key.prepare())),
            ),
            #[cfg(not(feature = "orchard"))]
            orchard: PhantomData,
        }
    }

    /// Adds the given transaction's shielded outputs to the various batch runners.
    ///
    /// `block_tag` is the hash of the block that triggered this txid being added to the
    /// batch, or `None` to indicate that no block triggered it (i.e. it was a mempool
    /// change).
    ///
    /// `height` is the height of the block that triggered this txid being added to the
    /// batch, or the mempool height (chain tip height + 1) if `block_tag` is `None`.
    ///
    /// After adding the outputs, any accumulated batch of sufficient size is run on the
    /// global threadpool. Subsequent calls to `Self::add_transaction` will accumulate
    /// those output kinds into new batches.
    // #[tracing::instrument(skip_all, fields(height = block.height))]
    pub(crate) fn add_transaction<P>(
        &mut self,
        params: &P,
        block_tag: Option<BlockHash>,
        height: BlockHeight,
        tx: Transaction,
    ) -> Result<(), ScanError>
    where
        P: consensus::Parameters + Send + 'static,
        IvkTag: Copy + Send + 'static,
    {
        let block_tag = block_tag.unwrap_or(BlockHash([0; 32]));
        let zip212_enforcement = zip212_enforcement(params, height);
        let txid = tx.txid();

        if let Some(bundle) = tx.sapling_bundle() {
            self.sapling.add_outputs(
                block_tag,
                txid,
                |_| SaplingDomain::new(zip212_enforcement),
                bundle.shielded_outputs(),
            );
        }

        #[cfg(feature = "orchard")]
        if let Some(bundle) = tx.orchard_bundle() {
            self.orchard.add_outputs(
                block_tag,
                txid,
                OrchardDomain::for_action,
                &bundle.actions().iter().cloned().collect::<Vec<_>>(),
            );
        }

        Ok(())
    }

    /// Runs the currently accumulated batches on the global threadpool.
    ///
    /// Subsequent calls to `Self::add_transaction` will be accumulated into new batches.
    pub(crate) fn flush(&mut self) {
        self.sapling.flush();
        #[cfg(feature = "orchard")]
        self.orchard.flush();
    }

    /// Collects the pending decryption results for the given transaction.
    ///
    /// `block_tag` is the hash of the block that triggered this txid being added to the
    /// batch, or the all-zeros hash to indicate that no block triggered it (i.e. it was a
    /// mempool change).
    pub(crate) fn collect_results(
        &mut self,
        block_tag: Option<BlockHash>,
        txid: [u8; 32],
    ) -> (SaplingBatchResult<IvkTag>, OrchardBatchResult<IvkTag>) {
        let block_tag = block_tag.unwrap_or(BlockHash([0; 32]));
        let txid = TxId::from_bytes(txid);

        let sapling = self.sapling.collect_results(block_tag, txid);
        let orchard = self.orchard.collect_results(block_tag, txid);

        // // Update the size of the batch scanner.
        // metrics::decrement_gauge!(METRIC_SIZE_TXS, 1.0);

        (sapling, orchard)
    }
}

type SaplingBatchResult<IvkTag> =
    HashMap<(TxId, usize), DecryptedOutput<IvkTag, SaplingDomain, [u8; 512]>>;
type OrchardBatchResult<IvkTag> =
    HashMap<(TxId, usize), DecryptedOutput<IvkTag, OrchardDomain, [u8; 512]>>;
