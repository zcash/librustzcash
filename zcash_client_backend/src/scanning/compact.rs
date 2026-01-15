use std::collections::HashSet;
use std::convert::TryFrom;
use std::hash::Hash;

use incrementalmerkletree::Retention;
use sapling::note_encryption::{CompactOutputDescription, SaplingDomain};
use subtle::ConditionallySelectable;

use tracing::{debug, trace};
use zcash_primitives::transaction::components::sapling::zip212_enforcement;
use zcash_protocol::{
    ShieldedProtocol,
    consensus::{self, BlockHeight, NetworkUpgrade, TxIndex},
};

use super::{Nullifiers, ScanError, ScanningKeys, find_received, find_spent};
use crate::{
    data_api::{BlockMetadata, ScannedBlock, ScannedBundles},
    proto::compact_formats::CompactBlock,
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
        let block_hash = block.hash();
        let block_height = block.height();
        let zip212_enforcement = zip212_enforcement(params, block_height);

        for tx in block.vtx.into_iter() {
            let txid = tx.txid();

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
    AccountId: Default + Eq + Hash + ConditionallySelectable + Send + 'static,
    IvkTag: Copy + std::hash::Hash + Eq + Send + 'static,
    TS: SaplingTasks<IvkTag> + Sync,
    TO: OrchardTasks<IvkTag> + Sync,
{
    fn check_hash_continuity(
        block: &CompactBlock,
        prior_block_metadata: Option<&BlockMetadata>,
    ) -> Option<ScanError> {
        if let Some(prev) = prior_block_metadata {
            if block.height() != prev.block_height() + 1 {
                debug!(
                    "Block height discontinuity at {:?}, previous was {:?} ",
                    block.height(),
                    prev.block_height()
                );
                return Some(ScanError::BlockHeightDiscontinuity {
                    prev_height: prev.block_height(),
                    new_height: block.height(),
                });
            }

            if block.prev_hash() != prev.block_hash() {
                debug!("Block hash discontinuity at {:?}", block.height());
                return Some(ScanError::PrevHashMismatch {
                    at_height: block.height(),
                });
            }
        }

        None
    }

    if let Some(scan_error) = check_hash_continuity(&block, prior_block_metadata) {
        return Err(scan_error);
    }

    trace!("Block continuity okay at {:?}", block.height());

    let cur_height = block.height();
    let cur_hash = block.hash();
    let zip212_enforcement = zip212_enforcement(params, cur_height);

    let mut sapling_commitment_tree_size = prior_block_metadata
        .and_then(|m| m.sapling_tree_size())
        .map_or_else(
            || {
                block.chain_metadata.as_ref().map_or_else(
                    || {
                        // If we're below Sapling activation, or Sapling activation is not set, the tree size is zero
                        params
                            .activation_height(NetworkUpgrade::Sapling)
                            .map_or_else(
                                || Ok(0),
                                |sapling_activation| {
                                    if cur_height < sapling_activation {
                                        Ok(0)
                                    } else {
                                        Err(ScanError::TreeSizeUnknown {
                                            protocol: ShieldedProtocol::Sapling,
                                            at_height: cur_height,
                                        })
                                    }
                                },
                            )
                    },
                    |m| {
                        let sapling_output_count: u32 = block
                            .vtx
                            .iter()
                            .map(|tx| tx.outputs.len())
                            .sum::<usize>()
                            .try_into()
                            .expect("Sapling output count cannot exceed a u32");

                        // The default for m.sapling_commitment_tree_size is zero, so we need to check
                        // that the subtraction will not underflow; if it would do so, we were given
                        // invalid chain metadata for a block with Sapling outputs.
                        m.sapling_commitment_tree_size
                            .checked_sub(sapling_output_count)
                            .ok_or(ScanError::TreeSizeInvalid {
                                protocol: ShieldedProtocol::Sapling,
                                at_height: cur_height,
                            })
                    },
                )
            },
            Ok,
        )?;
    let sapling_final_tree_size = sapling_commitment_tree_size
        + block
            .vtx
            .iter()
            .map(|tx| u32::try_from(tx.outputs.len()).unwrap())
            .sum::<u32>();

    #[cfg(feature = "orchard")]
    let mut orchard_commitment_tree_size = prior_block_metadata
        .and_then(|m| m.orchard_tree_size())
        .map_or_else(
            || {
                block.chain_metadata.as_ref().map_or_else(
                    || {
                        // If we're below Orchard activation, or Orchard activation is not set, the tree size is zero
                        params.activation_height(NetworkUpgrade::Nu5).map_or_else(
                            || Ok(0),
                            |orchard_activation| {
                                if cur_height < orchard_activation {
                                    Ok(0)
                                } else {
                                    Err(ScanError::TreeSizeUnknown {
                                        protocol: ShieldedProtocol::Orchard,
                                        at_height: cur_height,
                                    })
                                }
                            },
                        )
                    },
                    |m| {
                        let orchard_action_count: u32 = block
                            .vtx
                            .iter()
                            .map(|tx| tx.actions.len())
                            .sum::<usize>()
                            .try_into()
                            .expect("Orchard action count cannot exceed a u32");

                        // The default for m.orchard_commitment_tree_size is zero, so we need to check
                        // that the subtraction will not underflow; if it would do so, we were given
                        // invalid chain metadata for a block with Orchard actions.
                        m.orchard_commitment_tree_size
                            .checked_sub(orchard_action_count)
                            .ok_or(ScanError::TreeSizeInvalid {
                                protocol: ShieldedProtocol::Orchard,
                                at_height: cur_height,
                            })
                    },
                )
            },
            Ok,
        )?;
    #[cfg(feature = "orchard")]
    let orchard_final_tree_size = orchard_commitment_tree_size
        + block
            .vtx
            .iter()
            .map(|tx| u32::try_from(tx.actions.len()).unwrap())
            .sum::<u32>();

    let mut wtxs: Vec<WalletTx<AccountId>> = vec![];
    let mut sapling_nullifier_map = Vec::with_capacity(block.vtx.len());
    let mut sapling_note_commitments: Vec<(sapling::Node, Retention<BlockHeight>)> = vec![];

    #[cfg(feature = "orchard")]
    let mut orchard_nullifier_map = Vec::with_capacity(block.vtx.len());
    #[cfg(feature = "orchard")]
    let mut orchard_note_commitments: Vec<(MerkleHashOrchard, Retention<BlockHeight>)> = vec![];

    for tx in block.vtx.into_iter() {
        let txid = tx.txid();
        let tx_index =
            TxIndex::try_from(tx.index).expect("Cannot fit more than 2^16 transactions in a block");

        let (sapling_spends, sapling_unlinked_nullifiers) = find_spent(
            &tx.spends,
            &nullifiers.sapling,
            |spend| {
                spend.nf().expect(
                    "Could not deserialize nullifier for spend from protobuf representation.",
                )
            },
            WalletSpend::from_parts,
        );

        sapling_nullifier_map.push((tx_index, txid, sapling_unlinked_nullifiers));

        #[cfg(feature = "orchard")]
        let orchard_spends = {
            let (orchard_spends, orchard_unlinked_nullifiers) = find_spent(
                &tx.actions,
                &nullifiers.orchard,
                |spend| {
                    spend.nf().expect(
                        "Could not deserialize nullifier for spend from protobuf representation.",
                    )
                },
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
            sapling_final_tree_size
                == sapling_commitment_tree_size + u32::try_from(tx.outputs.len()).unwrap(),
            txid,
            sapling_commitment_tree_size,
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
            |output| sapling::Node::from_cmu(&output.cmu),
        );
        sapling_note_commitments.append(&mut sapling_nc);
        let has_sapling = !(sapling_spends.is_empty() && sapling_outputs.is_empty());

        #[cfg(feature = "orchard")]
        let (orchard_outputs, mut orchard_nc) = find_received(
            cur_height,
            orchard_final_tree_size
                == orchard_commitment_tree_size + u32::try_from(tx.actions.len()).unwrap(),
            txid,
            orchard_commitment_tree_size,
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

        sapling_commitment_tree_size +=
            u32::try_from(tx.outputs.len()).expect("Sapling output count cannot exceed a u32");
        #[cfg(feature = "orchard")]
        {
            orchard_commitment_tree_size +=
                u32::try_from(tx.actions.len()).expect("Orchard action count cannot exceed a u32");
        }
    }

    if let Some(chain_meta) = block.chain_metadata {
        if chain_meta.sapling_commitment_tree_size != sapling_commitment_tree_size {
            return Err(ScanError::TreeSizeMismatch {
                protocol: ShieldedProtocol::Sapling,
                at_height: cur_height,
                given: chain_meta.sapling_commitment_tree_size,
                computed: sapling_commitment_tree_size,
            });
        }

        #[cfg(feature = "orchard")]
        if chain_meta.orchard_commitment_tree_size != orchard_commitment_tree_size {
            return Err(ScanError::TreeSizeMismatch {
                protocol: ShieldedProtocol::Orchard,
                at_height: cur_height,
                given: chain_meta.orchard_commitment_tree_size,
                computed: orchard_commitment_tree_size,
            });
        }
    }

    Ok(ScannedBlock::from_parts(
        cur_height,
        cur_hash,
        block.time,
        wtxs,
        ScannedBundles::new(
            sapling_commitment_tree_size,
            sapling_note_commitments,
            sapling_nullifier_map,
        ),
        #[cfg(feature = "orchard")]
        ScannedBundles::new(
            orchard_commitment_tree_size,
            orchard_note_commitments,
            orchard_nullifier_map,
        ),
    ))
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
}
