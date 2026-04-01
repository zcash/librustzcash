use std::collections::{HashMap, HashSet};
use std::convert::TryFrom;
use std::fmt;
use std::hash::Hash;

use incrementalmerkletree::Retention;
use sapling::note_encryption::SaplingDomain;
use subtle::ConditionallySelectable;
use tracing::{debug, trace, warn};

use zcash_note_encryption::batch;
use zcash_primitives::{
    block::{Block, BlockHeader},
    transaction::{Transaction, components::sapling::zip212_enforcement},
};
use zcash_protocol::{
    ShieldedProtocol,
    consensus::{self, BlockHeight, NetworkUpgrade, TxIndex},
};

use super::{Nullifiers, PositionTracker, ScanError, ScanningKeys, find_received, find_spent};
use crate::{
    data_api::{
        BlockMetadata, ScannedBlock, ScannedBundles, ll::wallet::detect_wallet_transparent_outputs,
    },
    scan::{Batch, BatchReceiver, BatchRunner, DecryptedOutput, FullDecryptor, Tasks},
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
        sapling_batch_size_threshold: usize,
        #[cfg(feature = "orchard")] orchard_batch_size_threshold: usize,
        scanning_keys: &ScanningKeys<AccountId, IvkTag>,
    ) -> Self {
        BatchRunners {
            sapling: BatchRunner::new(
                sapling_batch_size_threshold,
                scanning_keys
                    .sapling()
                    .iter()
                    .map(|(id, key)| (id.clone(), key.prepare())),
            ),
            #[cfg(feature = "orchard")]
            orchard: BatchRunner::new(
                orchard_batch_size_threshold,
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
    #[tracing::instrument(skip_all, fields(height = u32::from(height)))]
    pub(crate) fn process_transaction<P>(
        &mut self,
        params: &P,
        height: BlockHeight,
        tx: Transaction,
    ) -> PendingBatch<IvkTag>
    where
        P: consensus::Parameters + Send + 'static,
        IvkTag: Copy + Send + 'static,
    {
        let zip212_enforcement = zip212_enforcement(params, height);

        let sapling_batch = tx.sapling_bundle().map(|bundle| {
            self.sapling.process_outputs(
                |_| SaplingDomain::new(zip212_enforcement),
                bundle.shielded_outputs(),
            )
        });

        #[cfg(feature = "orchard")]
        let orchard_batch = tx.orchard_bundle().map(|bundle| {
            self.orchard.process_outputs(
                OrchardDomain::for_action,
                &bundle.actions().iter().cloned().collect::<Vec<_>>(),
            )
        });

        PendingBatch {
            tx,
            sapling_batch,
            #[cfg(feature = "orchard")]
            orchard_batch,
        }
    }

    /// Runs the currently accumulated batches on the global threadpool.
    ///
    /// Subsequent calls to [`Self::process_transaction`] will be accumulated into new batches.
    pub(crate) fn flush(&mut self) {
        self.sapling.flush();
        #[cfg(feature = "orchard")]
        self.orchard.flush();
    }
}

/// A pending batch decryption result for a single transaction.
pub(crate) struct PendingBatch<IvkTag> {
    tx: Transaction,
    sapling_batch: Option<BatchReceiver<IvkTag, SaplingDomain, [u8; 512]>>,
    #[cfg(feature = "orchard")]
    orchard_batch: Option<BatchReceiver<IvkTag, OrchardDomain, [u8; 512]>>,
}

impl<IvkTag> PendingBatch<IvkTag> {
    /// Blocks until the results of the batch are ready.
    pub(crate) fn wait(self) -> BatchResult<IvkTag> {
        BatchResult {
            tx: self.tx,
            sapling: self
                .sapling_batch
                .map(|b| b.into_results())
                .unwrap_or_default(),
            #[cfg(feature = "orchard")]
            orchard: self
                .orchard_batch
                .map(|b| b.into_results())
                .unwrap_or_default(),
        }
    }
}

/// The result of batch-decrypting a single transaction.
pub struct BatchResult<IvkTag> {
    tx: Transaction,
    sapling: HashMap<usize, DecryptedOutput<IvkTag, SaplingDomain, [u8; 512]>>,
    #[cfg(feature = "orchard")]
    orchard: HashMap<usize, DecryptedOutput<IvkTag, OrchardDomain, [u8; 512]>>,
}

/// Decrypts a block with a set of [`ScanningKeys`].
///
/// This is an inline synchronous version of [`decryptor::Engine`], that internally spins
/// up batch runners for processing the block, and discards them afterwards.
///
/// This is the first half of block scanning. Pass the result to [`scan_block`] for the
/// second half.
///
/// [`decryptor::Engine`]: crate::sync::decryptor::Engine
pub fn decrypt_block<P, AccountId, IvkTag>(
    params: &P,
    block: Block,
    scanning_keys: &ScanningKeys<AccountId, IvkTag>,
) -> (BlockHeader, Vec<BatchResult<IvkTag>>)
where
    P: consensus::Parameters + Send + 'static,
    IvkTag: Copy + Send + 'static,
{
    let mut runners = BatchRunners::<_, (), ()>::for_keys(
        200,
        #[cfg(feature = "orchard")]
        200,
        scanning_keys,
    );

    let mined_height = block.claimed_height();
    let (header, vtx) = block.into_parts();
    let batches = vtx
        .into_iter()
        .map(|tx| runners.process_transaction(params, mined_height, tx))
        .collect::<Vec<_>>();

    let vtx = batches
        .into_iter()
        .map(|batch| batch.wait())
        .collect::<Vec<_>>();

    (header, vtx)
}

/// Scans a block with a set of [`ScanningKeys`].
///
/// Returns a vector of [`WalletTx`]s decryptable by any of the given keys. If an output is
/// decrypted by a full viewing key, the nullifiers of that output will also be computed.
///
/// This is the second half of block scanning. Use [`decrypt_block`] or
/// [`decryptor::Engine`] for the first half.
///
/// An error will be returned if any of the [`BatchResult`]s in `vtx` references an
/// `IvkTag` not present in `scanning_keys`. To avoid this error, ensure you use the same
/// set of [`ScanningKeys`] with both this function and [`decrypt_block`] (or
/// [`decryptor::new`] if you are running the decryption engine yourself).
///
/// [`CompactBlock`]: crate::proto::compact_formats::CompactBlock
/// [`WalletTx`]: crate::wallet::WalletTx
/// [`decryptor::new`]: crate::sync::decryptor::new
#[tracing::instrument(skip_all, fields(height = u32::from(height)))]
pub fn scan_block<P, AccountId, IvkTag>(
    params: &P,
    height: BlockHeight,
    header: &BlockHeader,
    vtx: &[BatchResult<IvkTag>],
    scanning_keys: &ScanningKeys<AccountId, IvkTag>,
    nullifiers: &Nullifiers<AccountId>,
    prior_block_metadata: Option<&BlockMetadata>,
) -> Result<ScannedBlock<AccountId>, ScanError>
where
    P: consensus::Parameters + Send + 'static,
    AccountId: Default + fmt::Debug + Eq + Hash + ConditionallySelectable + Send + Sync + 'static,
    IvkTag: Copy + std::hash::Hash + Eq + Send + 'static,
{
    fn check_hash_continuity(
        height: BlockHeight,
        header: &BlockHeader,
        prior_block_metadata: Option<&BlockMetadata>,
    ) -> Option<ScanError> {
        if let Some(prev) = prior_block_metadata {
            if height != prev.block_height() + 1 {
                debug!(
                    "Block height discontinuity at {:?}, previous was {:?} ",
                    height,
                    prev.block_height()
                );
                return Some(ScanError::BlockHeightDiscontinuity {
                    prev_height: prev.block_height(),
                    new_height: height,
                });
            }

            if header.prev_block != prev.block_hash() {
                debug!("Block hash discontinuity at {:?}", height);
                return Some(ScanError::PrevHashMismatch { at_height: height });
            }
        }

        None
    }

    if let Some(scan_error) = check_hash_continuity(height, header, prior_block_metadata) {
        return Err(scan_error);
    }

    trace!("Block continuity okay at {:?}", height);

    let cur_hash = header.hash();
    let zip212_enforcement = zip212_enforcement(params, height);

    let mut pos_tracker = PositionTracker::for_block(params, height, vtx, prior_block_metadata)?;

    let mut wtxs: Vec<WalletTx<AccountId>> = vec![];

    let mut sapling_nullifier_map = Vec::with_capacity(vtx.len());
    let mut sapling_note_commitments: Vec<(sapling::Node, Retention<BlockHeight>)> = vec![];

    #[cfg(feature = "orchard")]
    let mut orchard_nullifier_map = Vec::with_capacity(vtx.len());
    #[cfg(feature = "orchard")]
    let mut orchard_note_commitments: Vec<(MerkleHashOrchard, Retention<BlockHeight>)> = vec![];

    for (tx_index, tx) in vtx.iter().enumerate() {
        let txid = tx.tx.txid();
        let tx_index =
            TxIndex::try_from(tx_index).expect("Cannot fit more than 2^16 transactions in a block");

        // TODO: Detect.
        let transparent_spends: Vec<()> = vec![];

        let (sapling_spends, sapling_unlinked_nullifiers) = tx
            .tx
            .sapling_bundle()
            .map(|bundle| {
                find_spent(
                    bundle.shielded_spends(),
                    &nullifiers.sapling,
                    |spend| *spend.nullifier(),
                    WalletSpend::from_parts,
                )
            })
            .unwrap_or_default();

        sapling_nullifier_map.push((tx_index, txid, sapling_unlinked_nullifiers));

        #[cfg(feature = "orchard")]
        let orchard_spends = {
            let (orchard_spends, orchard_unlinked_nullifiers) = tx
                .tx
                .orchard_bundle()
                .map(|bundle| {
                    find_spent(
                        bundle.actions().iter(),
                        &nullifiers.orchard,
                        |action| *action.nullifier(),
                        WalletSpend::from_parts,
                    )
                })
                .unwrap_or_default();
            orchard_nullifier_map.push((tx_index, txid, orchard_unlinked_nullifiers));
            orchard_spends
        };

        // Collect the set of accounts that were spent from in this transaction
        let spent_from_accounts = sapling_spends.iter().map(|spend| spend.account_id());
        #[cfg(feature = "orchard")]
        let spent_from_accounts =
            spent_from_accounts.chain(orchard_spends.iter().map(|spend| spend.account_id()));
        let spent_from_accounts = spent_from_accounts.copied().collect::<HashSet<_>>();

        // TODO(#1305): Correctly track accounts that fund each transaction output.
        let funding_account = spent_from_accounts.iter().next().copied();
        if spent_from_accounts.len() > 1 {
            warn!(
                "More than one wallet account detected as funding transaction {:?}, selecting {:?}",
                tx.tx.txid(),
                funding_account.unwrap()
            )
        }

        let transparent_outputs = detect_wallet_transparent_outputs(
            params,
            &tx.tx,
            Some(height),
            funding_account,
            #[cfg(feature = "transparent-inputs")]
            |address| wallet_db.find_account_for_transparent_address(address),
        )?;
        let has_transparent = !(transparent_spends.is_empty() && transparent_outputs.is_empty());

        let (sapling_outputs, mut sapling_nc) = tx
            .tx
            .sapling_bundle()
            .map(|bundle| {
                find_received(
                    height,
                    pos_tracker.tx_contains_last_sapling_outputs_in_block(&tx.tx),
                    txid,
                    |output_idx| pos_tracker.sapling_note_position(output_idx),
                    &scanning_keys.sapling,
                    &spent_from_accounts,
                    &bundle
                        .shielded_outputs()
                        .iter()
                        .map(|output| (SaplingDomain::new(zip212_enforcement), output.clone()))
                        .collect::<Vec<_>>(),
                    Some(|_| tx.sapling.clone()),
                    batch::try_note_decryption,
                    |output| sapling::Node::from_cmu(output.cmu()),
                )
            })
            .unwrap_or_default();
        sapling_note_commitments.append(&mut sapling_nc);
        let has_sapling = !(sapling_spends.is_empty() && sapling_outputs.is_empty());

        #[cfg(feature = "orchard")]
        let (orchard_outputs, mut orchard_nc) = tx
            .tx
            .orchard_bundle()
            .map(|bundle| {
                find_received(
                    height,
                    pos_tracker.tx_contains_last_orchard_actions_in_block(&tx.tx),
                    txid,
                    |output_idx| pos_tracker.orchard_note_position(output_idx),
                    &scanning_keys.orchard,
                    &spent_from_accounts,
                    &bundle
                        .actions()
                        .iter()
                        .map(|action| (OrchardDomain::for_action(action), action.clone()))
                        .collect::<Vec<_>>(),
                    Some(|_| tx.orchard.clone()),
                    batch::try_note_decryption,
                    |action| MerkleHashOrchard::from_cmx(action.cmx()),
                )
            })
            .unwrap_or_default();
        #[cfg(feature = "orchard")]
        orchard_note_commitments.append(&mut orchard_nc);

        #[cfg(feature = "orchard")]
        let has_orchard = !(orchard_spends.is_empty() && orchard_outputs.is_empty());
        #[cfg(not(feature = "orchard"))]
        let has_orchard = false;

        if has_transparent || has_sapling || has_orchard {
            wtxs.push(WalletTx::new(
                txid,
                tx_index,
                transparent_outputs,
                sapling_spends,
                sapling_outputs,
                #[cfg(feature = "orchard")]
                orchard_spends,
                #[cfg(feature = "orchard")]
                orchard_outputs,
            ));
        }

        pos_tracker.increment_over_tx(&tx.tx);
    }

    pos_tracker.check_end_of_block_consistency()?;

    Ok(ScannedBlock::from_parts(
        height,
        cur_hash,
        header.time,
        wtxs,
        ScannedBundles::new(
            pos_tracker.sapling_final_tree_size,
            sapling_note_commitments,
            sapling_nullifier_map,
        ),
        #[cfg(feature = "orchard")]
        ScannedBundles::new(
            pos_tracker.orchard_final_tree_size,
            orchard_note_commitments,
            orchard_nullifier_map,
        ),
    ))
}

impl PositionTracker {
    fn for_block<P, IvkTag>(
        params: &P,
        at_height: BlockHeight,
        vtx: &[BatchResult<IvkTag>],
        prior_block_metadata: Option<&BlockMetadata>,
    ) -> Result<Self, ScanError>
    where
        P: consensus::Parameters,
    {
        /// Returns the size of the given shielded protocol's note commitment tree before and
        /// after the application of the given block.
        #[allow(clippy::too_many_arguments)]
        fn tree_sizes_around<P, IvkTag>(
            params: &P,
            at_height: BlockHeight,
            vtx: &[BatchResult<IvkTag>],
            prior_block_metadata: Option<&BlockMetadata>,
            protocol: ShieldedProtocol,
            activation_nu: NetworkUpgrade,
            prior_tree_size: impl Fn(&BlockMetadata) -> Option<u32>,
            tx_output_count: impl Fn(&Transaction) -> usize,
        ) -> Result<(u32, u32), ScanError>
        where
            P: consensus::Parameters,
        {
            let start_tree_size = prior_block_metadata.and_then(prior_tree_size).map_or_else(
                || {
                    // If we're below the protocol's activation height, or it is
                    // not set, the tree size is zero.
                    params.activation_height(activation_nu).map_or_else(
                        || Ok(0),
                        |activation_height| {
                            if at_height < activation_height {
                                Ok(0)
                            } else {
                                Err(ScanError::TreeSizeUnknown {
                                    protocol,
                                    at_height,
                                })
                            }
                        },
                    )
                },
                Ok,
            )?;

            // We pre-compute the end tree size here so we can determine when we reach the
            // last transaction in the block that adds notes to the tree. This enables us
            // to correctly set the tree checkpoint in `find_received`.
            let end_tree_size = start_tree_size
                + vtx
                    .iter()
                    .map(|tx| &tx.tx)
                    .map(tx_output_count)
                    .map(|tx_outputs| u32::try_from(tx_outputs).unwrap())
                    .sum::<u32>();

            Ok((start_tree_size, end_tree_size))
        }

        let (sapling_prior_tree_size, sapling_final_tree_size) = tree_sizes_around(
            params,
            at_height,
            vtx,
            prior_block_metadata,
            ShieldedProtocol::Sapling,
            NetworkUpgrade::Sapling,
            |m| m.sapling_tree_size(),
            |tx| {
                tx.sapling_bundle()
                    .map_or(0, |b| b.shielded_outputs().len())
            },
        )?;

        #[cfg(feature = "orchard")]
        let (orchard_prior_tree_size, orchard_final_tree_size) = tree_sizes_around(
            params,
            at_height,
            vtx,
            prior_block_metadata,
            ShieldedProtocol::Orchard,
            NetworkUpgrade::Nu5,
            |m| m.orchard_tree_size(),
            |tx| tx.orchard_bundle().map_or(0, |b| b.actions().len()),
        )?;

        Ok(Self {
            sapling_tree_position: sapling_prior_tree_size,
            sapling_final_tree_size,
            #[cfg(feature = "orchard")]
            orchard_tree_position: orchard_prior_tree_size,
            #[cfg(feature = "orchard")]
            orchard_final_tree_size,
        })
    }

    fn tx_contains_last_sapling_outputs_in_block(&self, tx: &Transaction) -> bool {
        self.sapling_tree_position
            + tx.sapling_bundle().map_or(0, |b| {
                u32::try_from(b.shielded_outputs().len())
                    .expect("Sapling output count cannot exceed a u32")
            })
            == self.sapling_final_tree_size
    }

    #[cfg(feature = "orchard")]
    fn tx_contains_last_orchard_actions_in_block(&self, tx: &Transaction) -> bool {
        self.orchard_tree_position
            + tx.orchard_bundle().map_or(0, |b| {
                u32::try_from(b.actions().len()).expect("Orchard action count cannot exceed a u32")
            })
            == self.orchard_final_tree_size
    }

    fn increment_over_tx(&mut self, tx: &Transaction) {
        self.sapling_tree_position += tx.sapling_bundle().map_or(0, |b| {
            u32::try_from(b.shielded_outputs().len())
                .expect("Sapling output count cannot exceed a u32")
        });
        #[cfg(feature = "orchard")]
        {
            self.orchard_tree_position += tx.orchard_bundle().map_or(0, |b| {
                u32::try_from(b.actions().len()).expect("Orchard action count cannot exceed a u32")
            });
        }
    }

    fn check_end_of_block_consistency(&self) -> Result<(), ScanError> {
        // It is a programming error to construct `PositionTracker` from a `CompactBlock`
        // and then not call `PositionTracker::increment_over_tx` on every transaction
        // within the block.
        assert_eq!(self.sapling_tree_position, self.sapling_final_tree_size);
        #[cfg(feature = "orchard")]
        assert_eq!(self.orchard_tree_position, self.orchard_final_tree_size);

        Ok(())
    }
}
