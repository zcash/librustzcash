use std::collections::HashSet;
use std::convert::TryFrom;
use std::hash::Hash;

use incrementalmerkletree::Retention;
use sapling::note_encryption::{CompactOutputDescription, SaplingDomain};
use subtle::ConditionallySelectable;

use tracing::{debug, trace};
use zcash_note_encryption::batch;
use zcash_primitives::transaction::components::sapling::zip212_enforcement;
use zcash_protocol::{
    ShieldedProtocol,
    consensus::{self, BlockHeight, NetworkUpgrade, TxIndex},
};

use super::{Nullifiers, PositionTracker, ScanError, ScanningKeys, find_received, find_spent};
use crate::{
    data_api::{BlockMetadata, ScannedBlock, ScannedBundles},
    proto::{
        CompactFormatError,
        compact_formats::{ChainMetadata, CompactBlock, CompactTx},
    },
    scan::{Batch, BatchRunner, CompactDecryptor, Tasks},
    wallet::{WalletSpend, WalletTx},
};

#[cfg(feature = "orchard")]
use orchard::{
    note_encryption::{CompactAction, OrchardDomain},
    tree::MerkleHashOrchard,
};

#[cfg(not(feature = "orchard"))]
use std::marker::PhantomData;

type TaggedSaplingBatch<IvkTag> = Batch<
    IvkTag,
    SaplingDomain,
    sapling::note_encryption::CompactOutputDescription,
    CompactDecryptor,
>;
type TaggedSaplingBatchRunner<IvkTag, Tasks> = BatchRunner<
    IvkTag,
    SaplingDomain,
    sapling::note_encryption::CompactOutputDescription,
    CompactDecryptor,
    Tasks,
>;

#[cfg(feature = "orchard")]
type TaggedOrchardBatch<IvkTag> =
    Batch<IvkTag, OrchardDomain, orchard::note_encryption::CompactAction, CompactDecryptor>;
#[cfg(feature = "orchard")]
type TaggedOrchardBatchRunner<IvkTag, Tasks> = BatchRunner<
    IvkTag,
    OrchardDomain,
    orchard::note_encryption::CompactAction,
    CompactDecryptor,
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

    pub(crate) fn flush(&mut self) {
        self.sapling.flush();
        #[cfg(feature = "orchard")]
        self.orchard.flush();
    }

    #[tracing::instrument(skip_all, fields(height = block.height))]
    pub(crate) fn add_block<P>(&mut self, params: &P, block: CompactBlock) -> Result<(), ScanError>
    where
        P: consensus::Parameters + Send + 'static,
        IvkTag: Copy + Send + 'static,
    {
        let block_height =
            block
                .height()
                .map_err(|error| ScanError::BlockEncodingInvalid {
                    at_height: None,
                    error,
                })?;
        let block_hash = block.hash().map_err(|error| ScanError::BlockEncodingInvalid {
            at_height: Some(block_height),
            error,
        })?;
        let zip212_enforcement = zip212_enforcement(params, block_height);

        for (block_index, tx) in block.vtx.into_iter().enumerate() {
            let txid = tx.txid().map_err(|error| ScanError::TxEncodingInvalid {
                at_height: block_height,
                block_index,
                error,
            })?;

            self.sapling.add_outputs(
                block_hash,
                txid,
                |_| SaplingDomain::new(zip212_enforcement),
                &tx.outputs
                    .iter()
                    .enumerate()
                    .map(|(i, output)| {
                        CompactOutputDescription::try_from(output).map_err(|_| {
                            ScanError::EncodingInvalid {
                                at_height: block_height,
                                txid,
                                pool_type: ShieldedProtocol::Sapling,
                                index: i,
                            }
                        })
                    })
                    .collect::<Result<Vec<_>, _>>()?,
            );

            #[cfg(feature = "orchard")]
            self.orchard.add_outputs(
                block_hash,
                txid,
                OrchardDomain::for_compact_action,
                &tx.actions
                    .iter()
                    .enumerate()
                    .map(|(i, action)| {
                        CompactAction::try_from(action).map_err(|_| ScanError::EncodingInvalid {
                            at_height: block_height,
                            txid,
                            pool_type: ShieldedProtocol::Orchard,
                            index: i,
                        })
                    })
                    .collect::<Result<Vec<_>, _>>()?,
            );
        }

        Ok(())
    }
}

#[tracing::instrument(skip_all, fields(height = block.height))]
pub(crate) fn scan_block_with_runners<P, AccountId, IvkTag, TS, TO>(
    params: &P,
    block: CompactBlock,
    scanning_keys: &ScanningKeys<AccountId, IvkTag>,
    nullifiers: &Nullifiers<AccountId>,
    prior_block_metadata: Option<&BlockMetadata>,
    mut batch_runners: Option<&mut BatchRunners<IvkTag, TS, TO>>,
) -> Result<ScannedBlock<AccountId>, ScanError>
where
    P: consensus::Parameters + Send + 'static,
    AccountId: Default + Eq + Hash + ConditionallySelectable + Send + Sync + 'static,
    IvkTag: Copy + std::hash::Hash + Eq + Send + 'static,
    TS: SaplingTasks<IvkTag> + Sync,
    TO: OrchardTasks<IvkTag> + Sync,
{
    // Decode block-level fields up front so that any malformed field surfaces as a
    // `BlockEncodingInvalid` error rather than panicking deeper in the scanner.
    let cur_height = block
        .height()
        .map_err(|error| ScanError::BlockEncodingInvalid {
            at_height: None,
            error,
        })?;
    let cur_hash = block.hash().map_err(|error| ScanError::BlockEncodingInvalid {
        at_height: Some(cur_height),
        error,
    })?;

    fn check_hash_continuity(
        block: &CompactBlock,
        cur_height: BlockHeight,
        prior_block_metadata: Option<&BlockMetadata>,
    ) -> Result<Option<ScanError>, ScanError> {
        if let Some(prev) = prior_block_metadata {
            if cur_height != prev.block_height() + 1 {
                debug!(
                    "Block height discontinuity at {:?}, previous was {:?} ",
                    cur_height,
                    prev.block_height()
                );
                return Ok(Some(ScanError::BlockHeightDiscontinuity {
                    prev_height: prev.block_height(),
                    new_height: cur_height,
                }));
            }

            let prev_hash =
                block
                    .prev_hash()
                    .map_err(|error| ScanError::BlockEncodingInvalid {
                        at_height: Some(cur_height),
                        error,
                    })?;
            if prev_hash != prev.block_hash() {
                debug!("Block hash discontinuity at {:?}", cur_height);
                return Ok(Some(ScanError::PrevHashMismatch {
                    at_height: cur_height,
                }));
            }
        }

        Ok(None)
    }

    if let Some(scan_error) = check_hash_continuity(&block, cur_height, prior_block_metadata)? {
        return Err(scan_error);
    }

    trace!("Block continuity okay at {:?}", cur_height);

    let zip212_enforcement = zip212_enforcement(params, cur_height);

    let mut pos_tracker =
        PositionTracker::for_compact_block(params, &block, cur_height, prior_block_metadata)?;

    let mut wtxs: Vec<WalletTx<AccountId>> = vec![];

    let mut sapling_nullifier_map = Vec::with_capacity(block.vtx.len());
    let mut sapling_note_commitments: Vec<(sapling::Node, Retention<BlockHeight>)> = vec![];

    #[cfg(feature = "orchard")]
    let mut orchard_nullifier_map = Vec::with_capacity(block.vtx.len());
    #[cfg(feature = "orchard")]
    let mut orchard_note_commitments: Vec<(MerkleHashOrchard, Retention<BlockHeight>)> = vec![];

    for (block_index, tx) in block.vtx.into_iter().enumerate() {
        let txid = tx.txid().map_err(|error| ScanError::TxEncodingInvalid {
            at_height: cur_height,
            block_index,
            error,
        })?;
        let tx_index =
            TxIndex::try_from(tx.index).map_err(|_| ScanError::TxEncodingInvalid {
                at_height: cur_height,
                block_index,
                error: CompactFormatError::OutOfRange,
            })?;

        let sapling_spend_nfs: Vec<sapling::Nullifier> = tx
            .spends
            .iter()
            .map(|spend| {
                spend.nf().map_err(|error| ScanError::TxEncodingInvalid {
                    at_height: cur_height,
                    block_index,
                    error,
                })
            })
            .collect::<Result<_, _>>()?;
        let (sapling_spends, sapling_unlinked_nullifiers) = find_spent(
            &sapling_spend_nfs,
            &nullifiers.sapling,
            |&nf| nf,
            WalletSpend::from_parts,
        );

        sapling_nullifier_map.push((tx_index, txid, sapling_unlinked_nullifiers));

        #[cfg(feature = "orchard")]
        let orchard_spends = {
            let orchard_spend_nfs: Vec<orchard::note::Nullifier> = tx
                .actions
                .iter()
                .map(|action| {
                    action
                        .nf()
                        .map_err(|error| ScanError::TxEncodingInvalid {
                            at_height: cur_height,
                            block_index,
                            error,
                        })
                })
                .collect::<Result<_, _>>()?;
            let (orchard_spends, orchard_unlinked_nullifiers) = find_spent(
                &orchard_spend_nfs,
                &nullifiers.orchard,
                |&nf| nf,
                WalletSpend::from_parts,
            );
            orchard_nullifier_map.push((tx_index, txid, orchard_unlinked_nullifiers));
            orchard_spends
        };

        // Collect the set of accounts that were spent from in this transaction
        let spent_from_accounts = sapling_spends.iter().map(|spend| spend.account_id());
        #[cfg(feature = "orchard")]
        let spent_from_accounts =
            spent_from_accounts.chain(orchard_spends.iter().map(|spend| spend.account_id()));
        let spent_from_accounts = spent_from_accounts.copied().collect::<HashSet<_>>();

        let (sapling_outputs, mut sapling_nc) = find_received(
            cur_height,
            pos_tracker.compact_tx_contains_last_sapling_outputs_in_block(&tx),
            txid,
            |output_idx| pos_tracker.sapling_note_position(output_idx),
            &scanning_keys.sapling,
            &spent_from_accounts,
            &tx.outputs
                .iter()
                .enumerate()
                .map(|(i, output)| {
                    Ok((
                        SaplingDomain::new(zip212_enforcement),
                        CompactOutputDescription::try_from(output).map_err(|_| {
                            ScanError::EncodingInvalid {
                                at_height: cur_height,
                                txid,
                                pool_type: ShieldedProtocol::Sapling,
                                index: i,
                            }
                        })?,
                    ))
                })
                .collect::<Result<Vec<_>, _>>()?,
            batch_runners
                .as_mut()
                .map(|runners| |txid| runners.sapling.collect_results(cur_hash, txid)),
            |ivks, outputs| {
                batch::try_compact_note_decryption(ivks, outputs)
                    .into_iter()
                    .map(|opt| opt.map(|((note, recipient), i)| ((note, recipient, ()), i)))
                    .collect()
            },
            |output| sapling::Node::from_cmu(&output.cmu),
        );
        sapling_note_commitments.append(&mut sapling_nc);
        let has_sapling = !(sapling_spends.is_empty() && sapling_outputs.is_empty());

        #[cfg(feature = "orchard")]
        let (orchard_outputs, mut orchard_nc) = find_received(
            cur_height,
            pos_tracker.compact_tx_contains_last_orchard_actions_in_block(&tx),
            txid,
            |output_idx| pos_tracker.orchard_note_position(output_idx),
            &scanning_keys.orchard,
            &spent_from_accounts,
            &tx.actions
                .iter()
                .enumerate()
                .map(|(i, action)| {
                    let action = CompactAction::try_from(action).map_err(|_| {
                        ScanError::EncodingInvalid {
                            at_height: cur_height,
                            txid,
                            pool_type: ShieldedProtocol::Orchard,
                            index: i,
                        }
                    })?;
                    Ok((OrchardDomain::for_compact_action(&action), action))
                })
                .collect::<Result<Vec<_>, _>>()?,
            batch_runners
                .as_mut()
                .map(|runners| |txid| runners.orchard.collect_results(cur_hash, txid)),
            |ivks, outputs| {
                batch::try_compact_note_decryption(ivks, outputs)
                    .into_iter()
                    .map(|opt| opt.map(|((note, recipient), i)| ((note, recipient, ()), i)))
                    .collect()
            },
            |output| MerkleHashOrchard::from_cmx(&output.cmx()),
        );
        #[cfg(feature = "orchard")]
        orchard_note_commitments.append(&mut orchard_nc);

        #[cfg(feature = "orchard")]
        let has_orchard = !(orchard_spends.is_empty() && orchard_outputs.is_empty());
        #[cfg(not(feature = "orchard"))]
        let has_orchard = false;

        if has_sapling || has_orchard {
            wtxs.push(WalletTx::new(
                txid,
                tx_index,
                sapling_spends,
                sapling_outputs,
                #[cfg(feature = "orchard")]
                orchard_spends,
                #[cfg(feature = "orchard")]
                orchard_outputs,
            ));
        }

        pos_tracker.increment_over_compact_tx(&tx);
    }

    pos_tracker.check_end_of_compact_block_consistency(cur_height, block.chain_metadata)?;

    Ok(ScannedBlock::from_parts(
        cur_height,
        cur_hash,
        block.time,
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
    fn for_compact_block<P>(
        params: &P,
        block: &CompactBlock,
        at_height: BlockHeight,
        prior_block_metadata: Option<&BlockMetadata>,
    ) -> Result<Self, ScanError>
    where
        P: consensus::Parameters,
    {
        /// Returns the size of the given shielded protocol's note commitment tree before and
        /// after the application of the given block.
        #[allow(clippy::too_many_arguments)]
        fn tree_sizes_around<P>(
            params: &P,
            block: &CompactBlock,
            at_height: BlockHeight,
            prior_block_metadata: Option<&BlockMetadata>,
            protocol: ShieldedProtocol,
            activation_nu: NetworkUpgrade,
            prior_tree_size: impl Fn(&BlockMetadata) -> Option<u32>,
            tx_output_count: impl Fn(&CompactTx) -> usize,
            final_tree_size: impl Fn(&ChainMetadata) -> u32,
        ) -> Result<(u32, u32), ScanError>
        where
            P: consensus::Parameters,
        {

            let start_tree_size = prior_block_metadata.and_then(prior_tree_size).map_or_else(
                || {
                    block.chain_metadata.as_ref().map_or_else(
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
                        |m| {
                            let output_count: u32 = block
                                .vtx
                                .iter()
                                .map(&tx_output_count)
                                .sum::<usize>()
                                .try_into()
                                .expect("Shielded output count cannot exceed a u32");

                            // The default for `final_tree_size(m)` is zero, so we need to
                            // check that the subtraction will not underflow; if it would
                            // do so, we were given invalid chain metadata for a block
                            // with outputs in this shielded protocol.
                            final_tree_size(m).checked_sub(output_count).ok_or(
                                ScanError::TreeSizeInvalid {
                                    protocol,
                                    at_height,
                                },
                            )
                        },
                    )
                },
                Ok,
            )?;

            // We pre-compute the end tree size here so we can determine when we reach the
            // last transaction in the block that adds notes to the tree. This enables us
            // to correctly set the tree checkpoint in `find_received`.
            let end_tree_size = start_tree_size
                + block
                    .vtx
                    .iter()
                    .map(tx_output_count)
                    .map(|tx_outputs| u32::try_from(tx_outputs).unwrap())
                    .sum::<u32>();

            Ok((start_tree_size, end_tree_size))
        }

        let (sapling_prior_tree_size, sapling_final_tree_size) = tree_sizes_around(
            params,
            block,
            at_height,
            prior_block_metadata,
            ShieldedProtocol::Sapling,
            NetworkUpgrade::Sapling,
            |m| m.sapling_tree_size(),
            |tx| tx.outputs.len(),
            |m| m.sapling_commitment_tree_size,
        )?;

        #[cfg(feature = "orchard")]
        let (orchard_prior_tree_size, orchard_final_tree_size) = tree_sizes_around(
            params,
            block,
            at_height,
            prior_block_metadata,
            ShieldedProtocol::Orchard,
            NetworkUpgrade::Nu5,
            |m| m.orchard_tree_size(),
            |tx| tx.actions.len(),
            |m| m.orchard_commitment_tree_size,
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

    fn compact_tx_contains_last_sapling_outputs_in_block(&self, tx: &CompactTx) -> bool {
        self.sapling_tree_position
            + u32::try_from(tx.outputs.len()).expect("Sapling output count cannot exceed a u32")
            == self.sapling_final_tree_size
    }

    #[cfg(feature = "orchard")]
    fn compact_tx_contains_last_orchard_actions_in_block(&self, tx: &CompactTx) -> bool {
        self.orchard_tree_position
            + u32::try_from(tx.actions.len()).expect("Orchard action count cannot exceed a u32")
            == self.orchard_final_tree_size
    }

    fn increment_over_compact_tx(&mut self, tx: &CompactTx) {
        self.sapling_tree_position +=
            u32::try_from(tx.outputs.len()).expect("Sapling output count cannot exceed a u32");
        #[cfg(feature = "orchard")]
        {
            self.orchard_tree_position +=
                u32::try_from(tx.actions.len()).expect("Orchard action count cannot exceed a u32");
        }
    }

    fn check_end_of_compact_block_consistency(
        &self,
        at_height: BlockHeight,
        chain_metadata: Option<ChainMetadata>,
    ) -> Result<(), ScanError> {
        // It is a programming error to construct `PositionTracker` from a `CompactBlock`
        // and then not call `PositionTracker::increment_over_tx` on every transaction
        // within the block.
        assert_eq!(self.sapling_tree_position, self.sapling_final_tree_size);
        #[cfg(feature = "orchard")]
        assert_eq!(self.orchard_tree_position, self.orchard_final_tree_size);

        if let Some(chain_meta) = chain_metadata {
            if chain_meta.sapling_commitment_tree_size != self.sapling_tree_position {
                return Err(ScanError::TreeSizeMismatch {
                    protocol: ShieldedProtocol::Sapling,
                    at_height,
                    given: chain_meta.sapling_commitment_tree_size,
                    computed: self.sapling_tree_position,
                });
            }

            #[cfg(feature = "orchard")]
            if chain_meta.orchard_commitment_tree_size != self.orchard_tree_position {
                return Err(ScanError::TreeSizeMismatch {
                    protocol: ShieldedProtocol::Orchard,
                    at_height,
                    given: chain_meta.orchard_commitment_tree_size,
                    computed: self.orchard_tree_position,
                });
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {

    use std::convert::Infallible;

    use incrementalmerkletree::{Marking, Position, Retention};
    use sapling::Nullifier;
    use zcash_keys::keys::UnifiedSpendingKey;
    use zcash_primitives::block::BlockHash;
    use zcash_protocol::{
        consensus::{BlockHeight, Network},
        value::Zatoshis,
    };
    use zip32::AccountId;

    use super::{BatchRunners, scan_block_with_runners};
    use crate::{
        data_api::BlockMetadata,
        scanning::{Nullifiers, ScanningKeys, scan_block, testing::fake_compact_block},
    };

    #[test]
    fn scan_block_with_my_tx() {
        fn go(scan_multithreaded: bool) {
            let network = Network::TestNetwork;
            let account = AccountId::ZERO;
            let usk =
                UnifiedSpendingKey::from_seed(&network, &[0u8; 32], account).expect("Valid USK");
            let ufvk = usk.to_unified_full_viewing_key();
            let sapling_dfvk = ufvk.sapling().expect("Sapling key is present").clone();
            let scanning_keys = ScanningKeys::from_account_ufvks([(account, ufvk)]);

            let cb = fake_compact_block(
                1u32.into(),
                BlockHash([0; 32]),
                Nullifier([0; 32]),
                &sapling_dfvk,
                Zatoshis::const_from_u64(5),
                false,
                None,
            );
            assert_eq!(cb.vtx.len(), 2);

            let mut batch_runners = if scan_multithreaded {
                let mut runners = BatchRunners::<_, (), ()>::for_keys(10, &scanning_keys);
                runners
                    .add_block(&Network::TestNetwork, cb.clone())
                    .unwrap();
                runners.flush();

                Some(runners)
            } else {
                None
            };

            let scanned_block = scan_block_with_runners(
                &network,
                cb,
                &scanning_keys,
                &Nullifiers::empty(),
                Some(&BlockMetadata::from_parts(
                    BlockHeight::from(0),
                    BlockHash([0u8; 32]),
                    Some(0),
                    #[cfg(feature = "orchard")]
                    Some(0),
                )),
                batch_runners.as_mut(),
            )
            .unwrap();
            let txs = scanned_block.transactions();
            assert_eq!(txs.len(), 1);

            let tx = &txs[0];
            assert_eq!(tx.block_index(), 1.into());
            assert_eq!(tx.sapling_spends().len(), 0);
            assert_eq!(tx.sapling_outputs().len(), 1);
            assert_eq!(tx.sapling_outputs()[0].index(), 0);
            assert_eq!(tx.sapling_outputs()[0].account_id(), &account);
            assert_eq!(tx.sapling_outputs()[0].note().value().inner(), 5);
            assert_eq!(
                tx.sapling_outputs()[0].note_commitment_tree_position(),
                Position::from(1)
            );

            assert_eq!(scanned_block.sapling().final_tree_size(), 2);
            assert_eq!(
                scanned_block
                    .sapling()
                    .commitments()
                    .iter()
                    .map(|(_, retention)| *retention)
                    .collect::<Vec<_>>(),
                vec![
                    Retention::Ephemeral,
                    Retention::Checkpoint {
                        id: scanned_block.height(),
                        marking: Marking::Marked
                    }
                ]
            );
        }

        go(false);
        go(true);
    }

    #[test]
    fn scan_block_with_txs_after_my_tx() {
        fn go(scan_multithreaded: bool) {
            let network = Network::TestNetwork;
            let account = AccountId::ZERO;
            let usk =
                UnifiedSpendingKey::from_seed(&network, &[0u8; 32], account).expect("Valid USK");
            let ufvk = usk.to_unified_full_viewing_key();
            let sapling_dfvk = ufvk.sapling().expect("Sapling key is present").clone();
            let scanning_keys = ScanningKeys::from_account_ufvks([(account, ufvk)]);

            let cb = fake_compact_block(
                1u32.into(),
                BlockHash([0; 32]),
                Nullifier([0; 32]),
                &sapling_dfvk,
                Zatoshis::const_from_u64(5),
                true,
                Some((0, 0)),
            );
            assert_eq!(cb.vtx.len(), 3);

            let mut batch_runners = if scan_multithreaded {
                let mut runners = BatchRunners::<_, (), ()>::for_keys(10, &scanning_keys);
                runners
                    .add_block(&Network::TestNetwork, cb.clone())
                    .unwrap();
                runners.flush();

                Some(runners)
            } else {
                None
            };

            let scanned_block = scan_block_with_runners(
                &network,
                cb,
                &scanning_keys,
                &Nullifiers::empty(),
                None,
                batch_runners.as_mut(),
            )
            .unwrap();
            let txs = scanned_block.transactions();
            assert_eq!(txs.len(), 1);

            let tx = &txs[0];
            assert_eq!(tx.block_index(), 1.into());
            assert_eq!(tx.sapling_spends().len(), 0);
            assert_eq!(tx.sapling_outputs().len(), 1);
            assert_eq!(tx.sapling_outputs()[0].index(), 0);
            assert_eq!(tx.sapling_outputs()[0].account_id(), &AccountId::ZERO);
            assert_eq!(tx.sapling_outputs()[0].note().value().inner(), 5);

            assert_eq!(
                scanned_block
                    .sapling()
                    .commitments()
                    .iter()
                    .map(|(_, retention)| *retention)
                    .collect::<Vec<_>>(),
                vec![
                    Retention::Ephemeral,
                    Retention::Marked,
                    Retention::Checkpoint {
                        id: scanned_block.height(),
                        marking: Marking::None
                    }
                ]
            );
        }

        go(false);
        go(true);
    }

    #[test]
    fn scan_block_with_my_spend() {
        let network = Network::TestNetwork;
        let account = AccountId::try_from(12).unwrap();
        let usk = UnifiedSpendingKey::from_seed(&network, &[0u8; 32], account).expect("Valid USK");
        let ufvk = usk.to_unified_full_viewing_key();
        let scanning_keys = ScanningKeys::<AccountId, Infallible>::empty();

        let nf = Nullifier([7; 32]);
        let nullifiers = Nullifiers::new(
            vec![(account, nf)],
            #[cfg(feature = "orchard")]
            vec![],
        );

        let cb = fake_compact_block(
            1u32.into(),
            BlockHash([0; 32]),
            nf,
            ufvk.sapling().unwrap(),
            Zatoshis::const_from_u64(5),
            false,
            Some((0, 0)),
        );
        assert_eq!(cb.vtx.len(), 2);

        let scanned_block = scan_block(&network, cb, &scanning_keys, &nullifiers, None).unwrap();
        let txs = scanned_block.transactions();
        assert_eq!(txs.len(), 1);

        let tx = &txs[0];
        assert_eq!(tx.block_index(), 1.into());
        assert_eq!(tx.sapling_spends().len(), 1);
        assert_eq!(tx.sapling_outputs().len(), 0);
        assert_eq!(tx.sapling_spends()[0].index(), 0);
        assert_eq!(tx.sapling_spends()[0].nf(), &nf);
        assert_eq!(tx.sapling_spends()[0].account_id(), &account);

        assert_eq!(
            scanned_block
                .sapling()
                .commitments()
                .iter()
                .map(|(_, retention)| *retention)
                .collect::<Vec<_>>(),
            vec![
                Retention::Ephemeral,
                Retention::Checkpoint {
                    id: scanned_block.height(),
                    marking: Marking::None
                }
            ]
        );
    }

    // Regression tests for GHSA-cx5g-7x2r-g5vc. Each test constructs a `CompactBlock` whose
    // protobuf representation satisfies `compact_formats.proto` but encodes a field that
    // previously triggered an unrecoverable panic inside `scan_block`. The expected behavior is
    // that `scan_block` now returns the appropriate `ScanError::{Block,Tx,}EncodingInvalid` (or
    // `EncodingInvalid` for output-level defects) variant.

    use crate::{
        proto::compact_formats::{
            ChainMetadata as ProtoChainMetadata, CompactBlock as ProtoCompactBlock,
            CompactSaplingOutput as ProtoCompactSaplingOutput,
            CompactSaplingSpend as ProtoCompactSaplingSpend, CompactTx as ProtoCompactTx,
        },
        scanning::ScanError,
    };

    #[cfg(feature = "orchard")]
    use crate::proto::compact_formats::CompactOrchardAction as ProtoCompactOrchardAction;

    fn poc_well_formed_block() -> ProtoCompactBlock {
        ProtoCompactBlock {
            proto_version: 1,
            height: 1,
            hash: vec![1u8; 32],
            prev_hash: vec![0u8; 32],
            chain_metadata: Some(ProtoChainMetadata {
                sapling_commitment_tree_size: 0,
                orchard_commitment_tree_size: 0,
            }),
            ..Default::default()
        }
    }

    #[test]
    fn poc_no_panic_on_tx_index_overflowing_u16() {
        // Finding 01(a): tx.index is uint64 in protobuf but TxIndex is u16. A hostile
        // lightwalletd that sends index >= 65536 used to panic the wallet at compact.rs:244.
        let mut block = poc_well_formed_block();
        block.vtx.push(ProtoCompactTx {
            index: 65_536,
            txid: vec![2u8; 32],
            ..Default::default()
        });

        let scanning_keys = ScanningKeys::<AccountId, Infallible>::empty();
        let result = scan_block(
            &Network::TestNetwork,
            block,
            &scanning_keys,
            &Nullifiers::empty(),
            None,
        );
        assert!(
            matches!(
                result,
                Err(ScanError::TxEncodingInvalid {
                    block_index: 0,
                    ..
                })
            ),
            "expected TxEncodingInvalid at block_index 0",
        );
    }

    #[test]
    fn poc_no_panic_on_sapling_nf_wrong_length() {
        // Finding 01(b): CompactSaplingSpend.nf is `bytes` in protobuf with no length
        // constraint, but compact.rs:250 unwrapped the conversion to a 32-byte sapling::Nullifier
        // and panicked on any other length.
        let mut block = poc_well_formed_block();
        let mut tx = ProtoCompactTx {
            index: 0,
            txid: vec![2u8; 32],
            ..Default::default()
        };
        tx.spends.push(ProtoCompactSaplingSpend {
            nf: vec![0u8; 31],
        });
        block.vtx.push(tx);

        let scanning_keys = ScanningKeys::<AccountId, Infallible>::empty();
        let result = scan_block(
            &Network::TestNetwork,
            block,
            &scanning_keys,
            &Nullifiers::empty(),
            None,
        );
        assert!(
            matches!(
                result,
                Err(ScanError::TxEncodingInvalid {
                    block_index: 0,
                    ..
                })
            ),
            "expected TxEncodingInvalid at block_index 0",
        );
    }

    #[test]
    fn poc_no_panic_on_compact_block_hash_wrong_length() {
        // Finding 01(g): CompactBlock.hash is bytes in protobuf with no length constraint.
        // CompactBlock::hash() at proto.rs:65-70 called BlockHash::from_slice which panicked
        // on a non-32-byte input.
        let mut block = poc_well_formed_block();
        block.hash = vec![0u8; 16];

        let scanning_keys = ScanningKeys::<AccountId, Infallible>::empty();
        let result = scan_block(
            &Network::TestNetwork,
            block,
            &scanning_keys,
            &Nullifiers::empty(),
            None,
        );
        assert!(
            matches!(result, Err(ScanError::BlockEncodingInvalid { .. })),
            "expected BlockEncodingInvalid",
        );
    }

    #[test]
    fn poc_no_panic_on_compact_block_prev_hash_wrong_length() {
        // Finding 01(h): CompactBlock.prev_hash is bytes in protobuf with no length constraint.
        // CompactBlock::prev_hash() at proto.rs:79-84 called BlockHash::from_slice which panicked
        // on a non-32-byte input. Reachable from check_hash_continuity when prior_block_metadata
        // is Some.
        let mut block = poc_well_formed_block();
        block.height = 2;
        block.prev_hash = vec![0u8; 16];

        let scanning_keys = ScanningKeys::<AccountId, Infallible>::empty();
        let prior = BlockMetadata::from_parts(
            BlockHeight::from(1),
            BlockHash([0u8; 32]),
            Some(0),
            #[cfg(feature = "orchard")]
            Some(0),
        );
        let result = scan_block(
            &Network::TestNetwork,
            block,
            &scanning_keys,
            &Nullifiers::empty(),
            Some(&prior),
        );
        assert!(
            matches!(result, Err(ScanError::BlockEncodingInvalid { .. })),
            "expected BlockEncodingInvalid",
        );
    }

    #[test]
    fn poc_no_panic_on_compact_block_height_overflowing_u32() {
        // Finding 01(d): CompactBlock.height is uint64 in protobuf. proto.rs:94 unwrapped the
        // conversion to BlockHeight (a u32). A hostile lightwalletd could crash any wallet that
        // called scan_block by setting height >= 2^32.
        let mut block = poc_well_formed_block();
        block.height = u64::from(u32::MAX) + 1;

        let scanning_keys = ScanningKeys::<AccountId, Infallible>::empty();
        let result = scan_block(
            &Network::TestNetwork,
            block,
            &scanning_keys,
            &Nullifiers::empty(),
            None,
        );
        assert!(
            matches!(
                result,
                Err(ScanError::BlockEncodingInvalid {
                    at_height: None,
                    ..
                })
            ),
            "expected BlockEncodingInvalid with at_height=None",
        );
    }

    #[test]
    fn poc_no_panic_on_compact_tx_txid_wrong_length() {
        // Finding 01(e): CompactTx.txid is bytes in protobuf with no length constraint.
        // CompactTx::txid() at proto.rs:111-115 called copy_from_slice into a [0u8; 32] buffer,
        // which panicked on any non-32 length input.
        let mut block = poc_well_formed_block();
        block.vtx.push(ProtoCompactTx {
            index: 0,
            txid: vec![0u8; 16],
            ..Default::default()
        });

        let scanning_keys = ScanningKeys::<AccountId, Infallible>::empty();
        let result = scan_block(
            &Network::TestNetwork,
            block,
            &scanning_keys,
            &Nullifiers::empty(),
            None,
        );
        assert!(
            matches!(
                result,
                Err(ScanError::TxEncodingInvalid {
                    block_index: 0,
                    ..
                })
            ),
            "expected TxEncodingInvalid at block_index 0",
        );
    }

    #[test]
    fn poc_no_panic_on_compact_sapling_output_cmu_wrong_length() {
        // Finding 01(f): CompactSaplingOutput::cmu() at proto.rs:142-147 called copy_from_slice
        // into [0u8; 32] from `self.cmu`. Even though the function returns Result, the panic
        // happened inside copy_from_slice on a length mismatch — the Result could never carry
        // the InvalidLength signal because we panicked first. Reachable through find_received's
        // CompactOutputDescription::try_from which calls value.cmu()?.
        let mut block = poc_well_formed_block();
        if let Some(meta) = block.chain_metadata.as_mut() {
            meta.sapling_commitment_tree_size = 1;
        }
        let mut tx = ProtoCompactTx {
            index: 0,
            txid: vec![2u8; 32],
            ..Default::default()
        };
        tx.outputs.push(ProtoCompactSaplingOutput {
            cmu: vec![0u8; 16],
            ephemeral_key: vec![0u8; 32],
            ciphertext: vec![0u8; 52],
        });
        block.vtx.push(tx);

        let scanning_keys = ScanningKeys::<AccountId, Infallible>::empty();
        let prior = BlockMetadata::from_parts(
            BlockHeight::from(0),
            BlockHash([0u8; 32]),
            Some(0),
            #[cfg(feature = "orchard")]
            Some(0),
        );
        let result = scan_block(
            &Network::TestNetwork,
            block,
            &scanning_keys,
            &Nullifiers::empty(),
            Some(&prior),
        );
        assert!(
            matches!(result, Err(ScanError::EncodingInvalid { .. })),
            "expected EncodingInvalid",
        );
    }

    #[cfg(feature = "orchard")]
    #[test]
    fn poc_no_panic_on_orchard_nf_wrong_length() {
        // Finding 01(c): CompactOrchardAction.nullifier is `bytes` in protobuf with no length
        // constraint. compact.rs:265 unwrapped the conversion to a 32-byte array. A 31-byte
        // (or any non-32-byte) value panicked the wallet.
        let mut block = poc_well_formed_block();
        let mut tx = ProtoCompactTx {
            index: 0,
            txid: vec![2u8; 32],
            ..Default::default()
        };
        tx.actions.push(ProtoCompactOrchardAction {
            nullifier: vec![0u8; 31],
            cmx: vec![0u8; 32],
            ephemeral_key: vec![0u8; 32],
            ciphertext: vec![0u8; 52],
        });
        block.vtx.push(tx);

        let scanning_keys = ScanningKeys::<AccountId, Infallible>::empty();
        let prior = BlockMetadata::from_parts(
            BlockHeight::from(0),
            BlockHash([0u8; 32]),
            Some(0),
            Some(0),
        );
        let result = scan_block(
            &Network::TestNetwork,
            block,
            &scanning_keys,
            &Nullifiers::empty(),
            Some(&prior),
        );
        assert!(
            matches!(
                result,
                Err(ScanError::TxEncodingInvalid {
                    block_index: 0,
                    ..
                })
            ),
            "expected TxEncodingInvalid at block_index 0",
        );
    }
}
