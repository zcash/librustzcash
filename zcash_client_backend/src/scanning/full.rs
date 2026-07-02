use std::collections::{HashMap, HashSet};
use std::convert::TryFrom;
use std::fmt;
use std::hash::Hash;

use incrementalmerkletree::Retention;
use sapling::note_encryption::SaplingDomain;
use subtle::ConditionallySelectable;
use tracing::{debug, trace, warn};

use zcash_note_encryption::{Domain, batch};
use zcash_primitives::{
    block::{Block, BlockHeader},
    transaction::{Transaction, components::sapling::zip212_enforcement},
};
use zcash_protocol::{
    ShieldedPool,
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

#[cfg(feature = "transparent-inputs")]
use transparent::{address::TransparentAddress, keys::TransparentKeyScope};

/// The default number of outputs at which a batch runner immediately flushes a batch.
pub(crate) const DEFAULT_BATCH_SIZE_THRESHOLD: usize = 200;

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
    /// Constructs a fresh set of batch runners that will trial-decrypt outputs using the
    /// given scanning keys.
    ///
    /// Each per-pool runner immediately flushes a batch once it has accumulated the
    /// corresponding `*_batch_size_threshold` number of outputs.
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

    /// Adds the given transaction's shielded outputs to the various batch runners,
    /// returning a [`PendingBatch`] from which the decryption results can be awaited.
    ///
    /// `height` is the height of the block containing the transaction, or the mempool
    /// height (chain tip height + 1) for a mempool transaction.
    ///
    /// After adding the outputs, any accumulated batch of sufficient size is run on the
    /// global threadpool. Subsequent calls to `Self::process_transaction` will accumulate
    /// outputs into new batches.
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
                bundle.shielded_outputs().iter().cloned(),
            )
        });

        #[cfg(feature = "orchard")]
        let orchard_batch = tx.orchard_bundle().map(|bundle| {
            self.orchard
                .process_outputs(OrchardDomain::for_action, bundle.actions().iter().cloned())
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
    sapling_batch: Option<BatchReceiver<IvkTag, SaplingDomain, <SaplingDomain as Domain>::Memo>>,
    #[cfg(feature = "orchard")]
    orchard_batch: Option<BatchReceiver<IvkTag, OrchardDomain, <OrchardDomain as Domain>::Memo>>,
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

    /// Waits, without blocking the current thread, until the results of the batch are
    /// ready.
    ///
    /// This is the asynchronous counterpart of [`Self::wait`].
    #[cfg(feature = "sync-decryptor")]
    pub(crate) async fn wait_async(self) -> BatchResult<IvkTag> {
        let sapling = match self.sapling_batch {
            Some(b) => b.into_results_async().await,
            None => HashMap::new(),
        };
        #[cfg(feature = "orchard")]
        let orchard = match self.orchard_batch {
            Some(b) => b.into_results_async().await,
            None => HashMap::new(),
        };
        BatchResult {
            tx: self.tx,
            sapling,
            #[cfg(feature = "orchard")]
            orchard,
        }
    }
}

/// The result of batch-decrypting a single transaction.
///
/// This is an opaque value, produced by [`decrypt_block`] (or the `sync::decryptor`
/// engine) and consumed by [`scan_block`]; it is not intended to be inspected directly.
pub struct BatchResult<IvkTag> {
    tx: Transaction,
    sapling:
        HashMap<usize, DecryptedOutput<IvkTag, SaplingDomain, <SaplingDomain as Domain>::Memo>>,
    #[cfg(feature = "orchard")]
    orchard:
        HashMap<usize, DecryptedOutput<IvkTag, OrchardDomain, <OrchardDomain as Domain>::Memo>>,
}

/// Decrypts a block with a set of [`ScanningKeys`].
///
/// This is an inline, synchronous alternative to the batch decryption engine in the
/// `sync::decryptor` module (available behind the `sync-decryptor` feature flag): it
/// internally spins up batch runners to process the block, and discards them afterwards.
///
/// This is the first half of block scanning. Pass the result to [`scan_block`] for the
/// second half.
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
        DEFAULT_BATCH_SIZE_THRESHOLD,
        #[cfg(feature = "orchard")]
        DEFAULT_BATCH_SIZE_THRESHOLD,
        scanning_keys,
    );

    let mined_height = block.claimed_height();
    let (header, vtx) = block.into_parts();
    let batches = vtx
        .into_iter()
        .map(|tx| runners.process_transaction(params, mined_height, tx))
        .collect::<Vec<_>>();

    // Flush any partially-accumulated batch so that every batch is actually run;
    // otherwise `PendingBatch::wait` would block forever waiting on a batch that
    // never started.
    runners.flush();

    let vtx = batches
        .into_iter()
        .map(|batch| batch.wait())
        .collect::<Vec<_>>();

    (header, vtx)
}

/// Errors that can occur while scanning a full block via [`scan_block`].
#[derive(Debug)]
#[non_exhaustive]
pub enum ScanBlockError<E> {
    /// A structural or continuity error in the block being scanned.
    Scan(ScanError),
    /// An error occurred while looking up the wallet account associated with a
    /// transparent address.
    AddressLookup(E),
}

impl<E> From<ScanError> for ScanBlockError<E> {
    fn from(e: ScanError) -> Self {
        ScanBlockError::Scan(e)
    }
}

impl<E: fmt::Display> fmt::Display for ScanBlockError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ScanBlockError::Scan(e) => write!(f, "Error scanning block: {e}"),
            ScanBlockError::AddressLookup(e) => write!(
                f,
                "Error looking up the wallet account for a transparent address: {e}"
            ),
        }
    }
}

impl<E: std::error::Error + 'static> std::error::Error for ScanBlockError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ScanBlockError::Scan(e) => Some(e),
            ScanBlockError::AddressLookup(e) => Some(e),
        }
    }
}

/// Scans a block with a set of [`ScanningKeys`].
///
/// Returns a [`ScannedBlock`] containing one [`WalletTx`] for each transaction in the
/// block that is decryptable by any of the given keys. If an output is decrypted by a
/// full viewing key, the nullifiers of that output will also be computed.
///
/// This is the second half of block scanning. Use [`decrypt_block`], or the
/// `sync::decryptor` engine (available behind the `sync-decryptor` feature flag), for
/// the first half.
///
/// # Panics
///
/// Panics if any of the [`BatchResult`]s in `vtx` references an `IvkTag` not present in
/// `scanning_keys`. To uphold this precondition, use the same set of [`ScanningKeys`]
/// with both this function and [`decrypt_block`] (or `sync::decryptor::new` if you are
/// running the decryption engine yourself).
///
/// [`WalletTx`]: crate::wallet::WalletTx
#[tracing::instrument(skip_all, fields(height = u32::from(height)))]
#[allow(clippy::too_many_arguments)]
pub fn scan_block<P, AccountId, IvkTag, E>(
    params: &P,
    height: BlockHeight,
    header: &BlockHeader,
    vtx: Vec<BatchResult<IvkTag>>,
    scanning_keys: &ScanningKeys<AccountId, IvkTag>,
    nullifiers: &Nullifiers<AccountId>,
    prior_block_metadata: Option<&BlockMetadata>,
    #[cfg(feature = "transparent-inputs")] find_account_for_address: impl Fn(
        &TransparentAddress,
    ) -> Result<
        Option<(AccountId, Option<TransparentKeyScope>)>,
        E,
    >,
) -> Result<ScannedBlock<AccountId>, ScanBlockError<E>>
where
    P: consensus::Parameters + Send + 'static,
    AccountId: Default + fmt::Debug + Ord + Hash + ConditionallySelectable + Send + Sync + 'static,
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
        return Err(scan_error.into());
    }

    trace!("Block continuity okay at {:?}", height);

    let cur_hash = header.hash();
    let zip212_enforcement = zip212_enforcement(params, height);

    let mut pos_tracker = PositionTracker::for_block(params, height, &vtx, prior_block_metadata)?;

    let mut wtxs: Vec<WalletTx<AccountId>> = vec![];

    let mut sapling_nullifier_map = Vec::with_capacity(vtx.len());
    let mut sapling_note_commitments: Vec<(sapling::Node, Retention<BlockHeight>)> = vec![];

    #[cfg(feature = "orchard")]
    let mut orchard_nullifier_map = Vec::with_capacity(vtx.len());
    #[cfg(feature = "orchard")]
    let mut orchard_note_commitments: Vec<(MerkleHashOrchard, Retention<BlockHeight>)> = vec![];

    for (tx_index, batch) in vtx.into_iter().enumerate() {
        let BatchResult {
            tx,
            sapling: sapling_decrypted,
            #[cfg(feature = "orchard")]
                orchard: orchard_decrypted,
        } = batch;
        let txid = tx.txid();
        let tx_index =
            TxIndex::try_from(tx_index).expect("Cannot fit more than 2^16 transactions in a block");

        let (sapling_spends, sapling_unlinked_nullifiers) = tx
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

        // TODO(#1305): Correctly track accounts that fund each transaction output. For now
        // we pick a single funding account; when more than one wallet account contributed
        // inputs we select the lowest account id, so that the choice is deterministic.
        let funding_account = spent_from_accounts.iter().min().copied();
        if spent_from_accounts.len() > 1 {
            warn!(
                "More than one wallet account detected as funding transaction {:?}, selecting {:?}",
                txid,
                funding_account
                    .expect("funding_account is Some when spent_from_accounts is nonempty")
            )
        }

        // TODO: Transparent spend detection for full blocks is not yet implemented; only
        // received transparent outputs are scanned here.
        // https://github.com/zcash/librustzcash/issues/2395
        let transparent_outputs = detect_wallet_transparent_outputs(
            params,
            &tx,
            Some(height),
            funding_account,
            #[cfg(feature = "transparent-inputs")]
            &find_account_for_address,
        )
        .map_err(ScanBlockError::AddressLookup)?;
        let has_transparent = !transparent_outputs.is_empty();

        let (sapling_outputs, mut sapling_nc) = tx
            .sapling_bundle()
            .map(|bundle| {
                find_received(
                    height,
                    pos_tracker.tx_contains_last_sapling_outputs_in_block(&tx),
                    txid,
                    |output_idx| pos_tracker.sapling_note_position(output_idx),
                    &scanning_keys.sapling,
                    &spent_from_accounts,
                    &bundle
                        .shielded_outputs()
                        .iter()
                        .map(|output| (SaplingDomain::new(zip212_enforcement), output.clone()))
                        .collect::<Vec<_>>(),
                    Some(move |_| sapling_decrypted),
                    batch::try_note_decryption,
                    |output| sapling::Node::from_cmu(output.cmu()),
                )
            })
            .unwrap_or_default();
        sapling_note_commitments.append(&mut sapling_nc);
        let has_sapling = !(sapling_spends.is_empty() && sapling_outputs.is_empty());

        #[cfg(feature = "orchard")]
        let (orchard_outputs, mut orchard_nc) = tx
            .orchard_bundle()
            .map(|bundle| {
                find_received(
                    height,
                    pos_tracker.tx_contains_last_orchard_actions_in_block(&tx),
                    txid,
                    |output_idx| pos_tracker.orchard_note_position(output_idx),
                    &scanning_keys.orchard,
                    &spent_from_accounts,
                    &bundle
                        .actions()
                        .iter()
                        .map(|action| (OrchardDomain::for_action(action), action.clone()))
                        .collect::<Vec<_>>(),
                    Some(move |_| orchard_decrypted),
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

        pos_tracker.increment_over_tx(&tx);
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

/// Returns the size of the given shielded protocol's note commitment tree both before and
/// after the application of a block at `at_height`.
///
/// - `activation_height` is the height at which `protocol` activated, if set.
/// - `prior_tree_size` is the tree size as of the end of the previous block, if known.
/// - `output_counts` yields the number of `protocol` outputs in each transaction of the
///   block, in order.
///
/// Returns [`ScanError::TreeSizeUnknown`] if the starting size cannot be determined (the
/// block is at or above the protocol's activation height but no prior size is known), or
/// [`ScanError::TreeSizeOverflow`] if applying the block's outputs would take the tree
/// size beyond the `u32` range.
fn tree_sizes_around(
    at_height: BlockHeight,
    activation_height: Option<BlockHeight>,
    prior_tree_size: Option<u32>,
    mut output_counts: impl Iterator<Item = usize>,
    protocol: ShieldedPool,
) -> Result<(u32, u32), ScanError> {
    let start_tree_size = match prior_tree_size {
        Some(size) => size,
        // If we're below the protocol's activation height, or it is not set, the tree
        // size is zero; otherwise the starting size is unknown.
        None => match activation_height {
            Some(activation_height) if at_height >= activation_height => {
                return Err(ScanError::TreeSizeUnknown {
                    protocol,
                    at_height,
                });
            }
            _ => 0,
        },
    };

    // We pre-compute the end tree size here so we can determine when we reach the last
    // transaction in the block that adds notes to the tree. This enables us to correctly
    // set the tree checkpoint in `find_received`. Note commitment tree sizes are
    // `u32`-bounded by the protocol, so overflow here indicates corrupt or adversarial
    // input rather than a valid chain state.
    let overflow = || ScanError::TreeSizeOverflow {
        protocol,
        at_height,
    };
    let end_tree_size = output_counts.try_fold(start_tree_size, |acc, tx_outputs| {
        let tx_outputs = u32::try_from(tx_outputs).map_err(|_| overflow())?;
        acc.checked_add(tx_outputs).ok_or_else(overflow)
    })?;

    Ok((start_tree_size, end_tree_size))
}

/// Returns the number of Sapling outputs in `tx`.
///
/// Note commitment tree sizes are `u32`-bounded by the protocol, so a valid transaction
/// can never contain more than `u32::MAX` outputs.
fn sapling_output_count(tx: &Transaction) -> u32 {
    tx.sapling_bundle().map_or(0, |b| {
        u32::try_from(b.shielded_outputs().len()).expect("Sapling output count cannot exceed a u32")
    })
}

/// Returns the number of Orchard actions in `tx`.
///
/// Note commitment tree sizes are `u32`-bounded by the protocol, so a valid transaction
/// can never contain more than `u32::MAX` actions.
#[cfg(feature = "orchard")]
fn orchard_action_count(tx: &Transaction) -> u32 {
    tx.orchard_bundle().map_or(0, |b| {
        u32::try_from(b.actions().len()).expect("Orchard action count cannot exceed a u32")
    })
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
        let (sapling_prior_tree_size, sapling_final_tree_size) = tree_sizes_around(
            at_height,
            params.activation_height(NetworkUpgrade::Sapling),
            prior_block_metadata.and_then(|m| m.sapling_tree_size()),
            vtx.iter().map(|b| {
                b.tx.sapling_bundle()
                    .map_or(0, |bd| bd.shielded_outputs().len())
            }),
            ShieldedPool::Sapling,
        )?;

        #[cfg(feature = "orchard")]
        let (orchard_prior_tree_size, orchard_final_tree_size) = tree_sizes_around(
            at_height,
            params.activation_height(NetworkUpgrade::Nu5),
            prior_block_metadata.and_then(|m| m.orchard_tree_size()),
            vtx.iter()
                .map(|b| b.tx.orchard_bundle().map_or(0, |bd| bd.actions().len())),
            ShieldedPool::Orchard,
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

    /// Returns `true` if a transaction contributing `sapling_output_count` outputs would
    /// bring the Sapling tree position up to the block's final Sapling tree size; that is,
    /// such a transaction contains the last Sapling output in the block.
    fn contains_last_sapling_outputs(&self, sapling_output_count: u32) -> bool {
        self.sapling_tree_position + sapling_output_count == self.sapling_final_tree_size
    }

    fn tx_contains_last_sapling_outputs_in_block(&self, tx: &Transaction) -> bool {
        self.contains_last_sapling_outputs(sapling_output_count(tx))
    }

    /// Returns `true` if a transaction contributing `orchard_action_count` actions would
    /// bring the Orchard tree position up to the block's final Orchard tree size; that is,
    /// such a transaction contains the last Orchard output in the block.
    #[cfg(feature = "orchard")]
    fn contains_last_orchard_actions(&self, orchard_action_count: u32) -> bool {
        self.orchard_tree_position + orchard_action_count == self.orchard_final_tree_size
    }

    #[cfg(feature = "orchard")]
    fn tx_contains_last_orchard_actions_in_block(&self, tx: &Transaction) -> bool {
        self.contains_last_orchard_actions(orchard_action_count(tx))
    }

    /// Advances the tracked tree positions past a transaction with the given output
    /// counts.
    fn increment(
        &mut self,
        sapling_output_count: u32,
        #[cfg(feature = "orchard")] orchard_action_count: u32,
    ) {
        self.sapling_tree_position += sapling_output_count;
        #[cfg(feature = "orchard")]
        {
            self.orchard_tree_position += orchard_action_count;
        }
    }

    fn increment_over_tx(&mut self, tx: &Transaction) {
        self.increment(
            sapling_output_count(tx),
            #[cfg(feature = "orchard")]
            orchard_action_count(tx),
        );
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

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use zcash_protocol::{consensus::BlockHeight, testing::arb_protocol};

    use super::{PositionTracker, tree_sizes_around};
    use crate::scanning::ScanError;

    // The behaviour of `tree_sizes_around` is independent of the shielded protocol (the
    // protocol is only echoed back in errors), so these properties are checked for a
    // `ShieldedPool` drawn uniformly at random via `arb_protocol`.
    proptest! {
        /// A known prior tree size is the starting point, and each transaction's outputs
        /// are summed onto it to reach the final size. An empty block (no transactions, or
        /// transactions with no outputs) leaves the size unchanged.
        #[test]
        fn uses_known_prior_size(
            protocol in arb_protocol(),
            at_height in 0u32..1_000_000,
            prior in 0u32..100_000,
            counts in prop::collection::vec(0usize..1_000, 0..16),
        ) {
            let expected_end = prior + counts.iter().map(|c| *c as u32).sum::<u32>();
            let result = tree_sizes_around(
                BlockHeight::from(at_height),
                Some(BlockHeight::from(1u32)),
                Some(prior),
                counts.into_iter(),
                protocol,
            );
            prop_assert_eq!(result.unwrap(), (prior, expected_end));
        }

        /// With no prior size and a block below the activation height, the tree starts
        /// empty.
        #[test]
        fn zero_below_activation_without_prior(
            protocol in arb_protocol(),
            at_height in 0u32..1_000_000,
            activation_offset in 1u32..1_000,
            counts in prop::collection::vec(0usize..1_000, 0..16),
        ) {
            // `at_height` is strictly below the activation height.
            let activation = at_height + activation_offset;
            let expected_end: u32 = counts.iter().map(|c| *c as u32).sum();
            let result = tree_sizes_around(
                BlockHeight::from(at_height),
                Some(BlockHeight::from(activation)),
                None,
                counts.into_iter(),
                protocol,
            );
            prop_assert_eq!(result.unwrap(), (0, expected_end));
        }

        /// With no prior size and no activation height (e.g. a protocol not activated on
        /// this network), the tree starts empty regardless of the block height.
        #[test]
        fn zero_when_activation_unset(
            protocol in arb_protocol(),
            at_height in 0u32..1_000_000,
            counts in prop::collection::vec(0usize..1_000, 0..16),
        ) {
            let expected_end: u32 = counts.iter().map(|c| *c as u32).sum();
            let result = tree_sizes_around(
                BlockHeight::from(at_height),
                None,
                None,
                counts.into_iter(),
                protocol,
            );
            prop_assert_eq!(result.unwrap(), (0, expected_end));
        }

        /// A known prior size is used even when the block is below the activation height.
        #[test]
        fn prior_size_takes_precedence_below_activation(
            protocol in arb_protocol(),
            at_height in 0u32..1_000_000,
            activation_offset in 1u32..1_000,
            prior in 0u32..100_000,
            counts in prop::collection::vec(0usize..1_000, 0..16),
        ) {
            let activation = at_height + activation_offset;
            let expected_end = prior + counts.iter().map(|c| *c as u32).sum::<u32>();
            let result = tree_sizes_around(
                BlockHeight::from(at_height),
                Some(BlockHeight::from(activation)),
                Some(prior),
                counts.into_iter(),
                protocol,
            );
            prop_assert_eq!(result.unwrap(), (prior, expected_end));
        }

        /// At or above the activation height with no prior size, the starting size cannot
        /// be determined, and the error reports the queried protocol and height.
        #[test]
        fn unknown_at_or_above_activation_without_prior(
            protocol in arb_protocol(),
            activation in 0u32..1_000_000,
            delta in 0u32..1_000,
        ) {
            // `at_height` is at or above the activation height.
            let at_height = activation + delta;
            let result = tree_sizes_around(
                BlockHeight::from(at_height),
                Some(BlockHeight::from(activation)),
                None,
                std::iter::empty(),
                protocol,
            );
            let matched = matches!(
                result,
                Err(ScanError::TreeSizeUnknown { protocol: p, at_height: h })
                    if p == protocol && h == BlockHeight::from(at_height)
            );
            prop_assert!(matched);
        }

        /// Applying the block's outputs would push the tree size beyond the `u32` range,
        /// and the error reports the queried protocol.
        #[test]
        fn overflow_is_reported(
            protocol in arb_protocol(),
            headroom in 0u32..100,
            extra in 1u32..100,
        ) {
            // A single transaction whose output count exceeds the remaining headroom takes
            // the tree size past `u32::MAX`.
            let prior = u32::MAX - headroom;
            let count = headroom as usize + extra as usize;
            let result = tree_sizes_around(
                BlockHeight::from(100u32),
                Some(BlockHeight::from(1u32)),
                Some(prior),
                std::iter::once(count),
                protocol,
            );
            let matched = matches!(
                result,
                Err(ScanError::TreeSizeOverflow { protocol: p, .. }) if p == protocol
            );
            prop_assert!(matched);
        }

        /// Reaching exactly `u32::MAX` is a valid (non-overflowing) final size.
        #[test]
        fn exact_u32_max_boundary_is_not_overflow(
            protocol in arb_protocol(),
            count in 0u32..1_000,
        ) {
            let prior = u32::MAX - count;
            let result = tree_sizes_around(
                BlockHeight::from(100u32),
                Some(BlockHeight::from(1u32)),
                Some(prior),
                std::iter::once(count as usize),
                protocol,
            );
            prop_assert_eq!(result.unwrap(), (prior, u32::MAX));
        }
    }

    #[test]
    fn contains_last_sapling_outputs_detects_boundary() {
        let tracker = PositionTracker {
            sapling_tree_position: 10,
            sapling_final_tree_size: 15,
            #[cfg(feature = "orchard")]
            orchard_tree_position: 0,
            #[cfg(feature = "orchard")]
            orchard_final_tree_size: 0,
        };

        // A transaction adding exactly the remaining outputs contains the block's last
        // Sapling output; any other count does not land on the boundary.
        assert!(tracker.contains_last_sapling_outputs(5));
        assert!(!tracker.contains_last_sapling_outputs(0));
        assert!(!tracker.contains_last_sapling_outputs(4));
        assert!(!tracker.contains_last_sapling_outputs(6));
    }

    #[test]
    fn increment_advances_sapling_position_to_final_size() {
        let mut tracker = PositionTracker {
            sapling_tree_position: 0,
            sapling_final_tree_size: 6,
            #[cfg(feature = "orchard")]
            orchard_tree_position: 0,
            #[cfg(feature = "orchard")]
            orchard_final_tree_size: 0,
        };

        // Walk a block of three transactions with 2, 0 and 4 Sapling outputs; only the
        // last one lands on the boundary.
        assert!(!tracker.contains_last_sapling_outputs(2));
        tracker.increment(
            2,
            #[cfg(feature = "orchard")]
            0,
        );
        assert!(!tracker.contains_last_sapling_outputs(0));
        tracker.increment(
            0,
            #[cfg(feature = "orchard")]
            0,
        );
        assert!(tracker.contains_last_sapling_outputs(4));
        tracker.increment(
            4,
            #[cfg(feature = "orchard")]
            0,
        );

        assert_eq!(tracker.sapling_tree_position, 6);
        tracker.check_end_of_block_consistency().unwrap();
    }

    #[cfg(feature = "orchard")]
    #[test]
    fn increment_advances_orchard_position_to_final_size() {
        let mut tracker = PositionTracker {
            sapling_tree_position: 0,
            sapling_final_tree_size: 0,
            orchard_tree_position: 4,
            orchard_final_tree_size: 9,
        };

        assert!(tracker.contains_last_orchard_actions(5));
        assert!(!tracker.contains_last_orchard_actions(4));
        tracker.increment(0, 5);

        assert_eq!(tracker.orchard_tree_position, 9);
        tracker.check_end_of_block_consistency().unwrap();
    }

    #[test]
    #[should_panic]
    fn check_end_of_block_consistency_panics_when_incomplete() {
        // Failing to increment over every transaction in the block is a programming error,
        // surfaced as a panic.
        let tracker = PositionTracker {
            sapling_tree_position: 3,
            sapling_final_tree_size: 6,
            #[cfg(feature = "orchard")]
            orchard_tree_position: 0,
            #[cfg(feature = "orchard")]
            orchard_final_tree_size: 0,
        };
        let _ = tracker.check_end_of_block_consistency();
    }
}
