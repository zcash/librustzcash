use std::{hash::Hash, ops::Range};

use rayon::{
    iter::{IndexedParallelIterator as _, ParallelIterator},
    slice::ParallelSliceMut as _,
};
use tracing::{debug, info, trace, warn};

use incrementalmerkletree::{Marking, Position, Retention};
use shardtree::error::ShardTreeError;
use zcash_keys::{address::Receiver, encoding::AddressCodec as _};
use zcash_primitives::transaction::Transaction;
use zcash_protocol::{
    PoolType, ShieldedProtocol,
    consensus::{self, BlockHeight},
    value::{BalanceError, Zatoshis},
};

use crate::{
    TransferType,
    data_api::{
        DecryptedTransaction, SAPLING_SHARD_HEIGHT, ScannedBlock, TransactionStatus,
        WalletCommitmentTrees, chain::ChainState,
    },
    wallet::{Note, Recipient},
};

use super::{LowLevelWalletRead, LowLevelWalletWrite, TxMeta};

#[cfg(feature = "transparent-inputs")]
use {
    crate::{data_api::ll::ReceivedSaplingOutput as _, wallet::WalletTransparentOutput},
    std::collections::HashSet,
    transparent::{bundle::OutPoint, keys::TransparentKeyScope},
    zcash_keys::keys::{ReceiverRequirement, UnifiedAddressRequest},
};

#[cfg(feature = "orchard")]
use {
    crate::data_api::{ORCHARD_SHARD_HEIGHT, ll::ReceivedOrchardOutput as _},
    incrementalmerkletree::frontier::Frontier,
    shardtree::store::{Checkpoint, ShardStore as _},
    std::collections::BTreeMap,
};

/// The maximum number of blocks the wallet is allowed to rewind. This is
/// consistent with the bound in zcashd, and allows block data deeper than
/// this delta from the chain tip to be pruned.
pub(crate) const PRUNING_DEPTH: u32 = 100;

#[derive(Debug)]
struct TransparentSentOutput<AccountId> {
    from_account_uuid: AccountId,
    output_index: usize,
    recipient: Recipient<AccountId>,
    value: Zatoshis,
}

#[derive(Debug)]
pub struct WalletTransparentOutputs<AccountId> {
    #[cfg(feature = "transparent-inputs")]
    received: Vec<(WalletTransparentOutput, Option<TransparentKeyScope>)>,
    sent: Vec<TransparentSentOutput<AccountId>>,
}

impl<AccountId> WalletTransparentOutputs<AccountId> {
    fn empty() -> Self {
        Self {
            #[cfg(feature = "transparent-inputs")]
            received: vec![],
            sent: vec![],
        }
    }

    fn is_empty(&self) -> bool {
        #[cfg(feature = "transparent-inputs")]
        let has_received = !self.received.is_empty();
        #[cfg(not(feature = "transparent-inputs"))]
        let has_received = false;

        let has_sent = !self.sent.is_empty();

        !(has_received || has_sent)
    }
}

pub(crate) fn determine_fee<DbT, T: TxMeta>(
    _wallet_db: &DbT,
    tx: &T,
) -> Result<Option<Zatoshis>, DbT::Error>
where
    DbT: LowLevelWalletRead,
    DbT::Error: From<BalanceError>,
{
    tx.fee_paid(|_outpoint| {
        #[cfg(not(feature = "transparent-inputs"))]
        {
            // Transparent inputs aren't supported, so this closure should never be
            // called during transaction construction. But in case it is, handle it
            // correctly.
            Ok(None)
        }

        // This closure can do DB lookups to fetch the value of each transparent input.
        #[cfg(feature = "transparent-inputs")]
        if let Some(out) = _wallet_db.get_wallet_transparent_output(_outpoint, None)? {
            Ok(Some(out.txout().value()))
        } else {
            // If we can’t find it, fee computation can't complete accurately
            Ok(None)
        }
    })
}

pub enum PutBlocksError<SE, TE> {
    NonSequentialBlocks {
        prev_height: BlockHeight,
        block_height: BlockHeight,
    },
    Storage(SE),
    ShardTree(ShardTreeError<TE>),
}

impl<SE, TE> From<ShardTreeError<TE>> for PutBlocksError<SE, TE> {
    fn from(value: ShardTreeError<TE>) -> Self {
        PutBlocksError::ShardTree(value)
    }
}

pub fn put_blocks<DbT, SE, TE>(
    wallet_db: &mut DbT,
    from_state: &ChainState,
    blocks: Vec<ScannedBlock<DbT::AccountId>>,
) -> Result<(), PutBlocksError<SE, TE>>
where
    DbT: LowLevelWalletWrite<Error = SE> + WalletCommitmentTrees<Error = TE>,
    DbT::TxRef: Eq + Hash,
{
    struct BlockPositions {
        height: BlockHeight,
        sapling_start_position: Position,
        #[cfg(feature = "orchard")]
        orchard_start_position: Position,
    }

    if blocks.is_empty() {
        return Ok(());
    }

    let initial_block = blocks.first().expect("blocks is known to be nonempty");
    assert!(from_state.block_height() + 1 == initial_block.height());

    let start_positions = BlockPositions {
        height: initial_block.height(),
        sapling_start_position: Position::from(
            u64::from(initial_block.sapling().final_tree_size())
                - u64::try_from(initial_block.sapling().commitments().len()).unwrap(),
        ),
        #[cfg(feature = "orchard")]
        orchard_start_position: Position::from(
            u64::from(initial_block.orchard().final_tree_size())
                - u64::try_from(initial_block.orchard().commitments().len()).unwrap(),
        ),
    };

    let mut sapling_commitments = vec![];
    #[cfg(feature = "orchard")]
    let mut orchard_commitments = vec![];
    let mut last_scanned_height = None;
    let mut note_positions = vec![];

    #[cfg(feature = "transparent-inputs")]
    let mut tx_refs = HashSet::new();

    for block in blocks.into_iter() {
        if last_scanned_height
            .iter()
            .any(|prev| block.height() != *prev + 1)
        {
            return Err(PutBlocksError::NonSequentialBlocks {
                prev_height: last_scanned_height.expect("last scanned height is known"),
                block_height: block.height(),
            });
        }

        // Insert the block into the database.
        wallet_db
            .put_block_meta(
                block.height(),
                block.block_hash(),
                block.block_time(),
                block.sapling().final_tree_size(),
                block.sapling().commitments().len().try_into().unwrap(),
                #[cfg(feature = "orchard")]
                block.orchard().final_tree_size(),
                #[cfg(feature = "orchard")]
                block.orchard().commitments().len().try_into().unwrap(),
            )
            .map_err(PutBlocksError::Storage)?;

        for tx in block.transactions() {
            let tx_ref = wallet_db
                .put_tx_meta(tx, block.height())
                .map_err(PutBlocksError::Storage)?;

            #[cfg(feature = "transparent-inputs")]
            tx_refs.insert(tx_ref);

            wallet_db
                .queue_tx_retrieval(std::iter::once(tx.txid()), None)
                .map_err(PutBlocksError::Storage)?;

            // Mark notes as spent and remove them from the scanning cache
            for spend in tx.sapling_spends() {
                wallet_db
                    .mark_sapling_note_spent(spend.nf(), tx_ref)
                    .map_err(PutBlocksError::Storage)?;
            }
            #[cfg(feature = "orchard")]
            for spend in tx.orchard_spends() {
                wallet_db
                    .mark_orchard_note_spent(spend.nf(), tx_ref)
                    .map_err(PutBlocksError::Storage)?;
            }

            for output in tx.sapling_outputs() {
                // Check whether this note was spent in a later block range that
                // we previously scanned.
                let spent_in = output
                    .nf()
                    .map(|nf| wallet_db.detect_sapling_spend(nf))
                    .transpose()
                    .map_err(PutBlocksError::Storage)?
                    .flatten();

                wallet_db
                    .put_received_sapling_note(output, tx_ref, Some(block.height()), spent_in)
                    .map_err(PutBlocksError::Storage)?;
            }
            #[cfg(feature = "orchard")]
            for output in tx.orchard_outputs() {
                // Check whether this note was spent in a later block range that
                // we previously scanned.
                let spent_in = output
                    .nf()
                    .map(|nf| wallet_db.detect_orchard_spend(nf))
                    .transpose()
                    .map_err(PutBlocksError::Storage)?
                    .flatten();

                wallet_db
                    .put_received_orchard_note(output, tx_ref, Some(block.height()), spent_in)
                    .map_err(PutBlocksError::Storage)?;
            }
        }

        // Insert the new nullifiers from this block into the nullifier map.
        wallet_db
            .track_block_sapling_nullifiers(block.height(), block.sapling().nullifier_map())
            .map_err(PutBlocksError::Storage)?;

        #[cfg(feature = "orchard")]
        wallet_db
            .track_block_orchard_nullifiers(block.height(), block.orchard().nullifier_map())
            .map_err(PutBlocksError::Storage)?;

        note_positions.extend(block.transactions().iter().flat_map(|wtx| {
            let iter = wtx.sapling_outputs().iter().map(|out| {
                (
                    ShieldedProtocol::Sapling,
                    out.note_commitment_tree_position(),
                )
            });
            #[cfg(feature = "orchard")]
            let iter = iter.chain(wtx.orchard_outputs().iter().map(|out| {
                (
                    ShieldedProtocol::Orchard,
                    out.note_commitment_tree_position(),
                )
            }));

            iter
        }));

        last_scanned_height = Some(block.height());
        let block_commitments = block.into_commitments();
        trace!(
            "Sapling commitments for {:?}: {:?}",
            last_scanned_height,
            block_commitments
                .sapling
                .iter()
                .map(|(_, r)| *r)
                .collect::<Vec<_>>()
        );
        #[cfg(feature = "orchard")]
        trace!(
            "Orchard commitments for {:?}: {:?}",
            last_scanned_height,
            block_commitments
                .orchard
                .iter()
                .map(|(_, r)| *r)
                .collect::<Vec<_>>()
        );

        sapling_commitments.extend(block_commitments.sapling.into_iter().map(Some));
        #[cfg(feature = "orchard")]
        orchard_commitments.extend(block_commitments.orchard.into_iter().map(Some));
    }

    #[cfg(feature = "transparent-inputs")]
    for (account_id, key_scope) in wallet_db
        .find_involved_accounts(tx_refs)
        .map_err(PutBlocksError::Storage)?
    {
        if let Some(t_key_scope) = key_scope {
            use ReceiverRequirement::*;
            wallet_db
                .generate_transparent_gap_addresses(
                    account_id,
                    t_key_scope,
                    UnifiedAddressRequest::unsafe_custom(Allow, Allow, Require),
                )
                .map_err(PutBlocksError::Storage)?;
        }
    }

    // Prune the nullifier map of entries we no longer need.
    wallet_db
        .prune_tracked_nullifiers(PRUNING_DEPTH)
        .map_err(PutBlocksError::Storage)?;

    // We will have a start position and a last scanned height in all cases where
    // `blocks` is non-empty.
    if let Some(last_scanned_height) = last_scanned_height {
        // Create subtrees from the note commitments in parallel.
        const CHUNK_SIZE: usize = 1024;
        let sapling_subtrees = sapling_commitments
            .par_chunks_mut(CHUNK_SIZE)
            .enumerate()
            .filter_map(|(i, chunk)| {
                let start = start_positions.sapling_start_position + (i * CHUNK_SIZE) as u64;
                let end = start + chunk.len() as u64;

                shardtree::LocatedTree::from_iter(
                    start..end,
                    SAPLING_SHARD_HEIGHT.into(),
                    chunk.iter_mut().map(|n| n.take().expect("always Some")),
                )
            })
            .map(|res| (res.subtree, res.checkpoints))
            .collect::<Vec<_>>();

        #[cfg(feature = "orchard")]
        let orchard_subtrees = orchard_commitments
            .par_chunks_mut(CHUNK_SIZE)
            .enumerate()
            .filter_map(|(i, chunk)| {
                let start = start_positions.orchard_start_position + (i * CHUNK_SIZE) as u64;
                let end = start + chunk.len() as u64;

                shardtree::LocatedTree::from_iter(
                    start..end,
                    ORCHARD_SHARD_HEIGHT.into(),
                    chunk.iter_mut().map(|n| n.take().expect("always Some")),
                )
            })
            .map(|res| (res.subtree, res.checkpoints))
            .collect::<Vec<_>>();

        // Collect the complete set of Sapling checkpoints
        #[cfg(feature = "orchard")]
        let sapling_checkpoint_positions: BTreeMap<BlockHeight, Position> = sapling_subtrees
            .iter()
            .flat_map(|(_, checkpoints)| checkpoints.iter())
            .map(|(k, v)| (*k, *v))
            .collect();

        #[cfg(feature = "orchard")]
        let orchard_checkpoint_positions: BTreeMap<BlockHeight, Position> = orchard_subtrees
            .iter()
            .flat_map(|(_, checkpoints)| checkpoints.iter())
            .map(|(k, v)| (*k, *v))
            .collect();

        #[cfg(feature = "orchard")]
        fn ensure_checkpoints<'a, H, I: Iterator<Item = &'a BlockHeight>, const DEPTH: u8>(
            // An iterator of checkpoints heights for which we wish to ensure that
            // checkpoints exists.
            ensure_heights: I,
            // The map of checkpoint positions from which we will draw note commitment tree
            // position information for the newly created checkpoints.
            existing_checkpoint_positions: &BTreeMap<BlockHeight, Position>,
            // The frontier whose position will be used for an inserted checkpoint when
            // there is no preceding checkpoint in existing_checkpoint_positions.
            state_final_tree: &Frontier<H, DEPTH>,
        ) -> Vec<(BlockHeight, Checkpoint)> {
            ensure_heights
                .flat_map(|ensure_height| {
                    existing_checkpoint_positions
                        .range::<BlockHeight, _>(..=*ensure_height)
                        .last()
                        .map_or_else(
                            || {
                                Some((
                                    *ensure_height,
                                    state_final_tree
                                        .value()
                                        .map_or_else(Checkpoint::tree_empty, |t| {
                                            Checkpoint::at_position(t.position())
                                        }),
                                ))
                            },
                            |(existing_checkpoint_height, position)| {
                                if *existing_checkpoint_height < *ensure_height {
                                    Some((*ensure_height, Checkpoint::at_position(*position)))
                                } else {
                                    // The checkpoint already exists, so we don't need to
                                    // do anything.
                                    None
                                }
                            },
                        )
                        .into_iter()
                })
                .collect::<Vec<_>>()
        }

        #[cfg(feature = "orchard")]
        let (missing_sapling_checkpoints, missing_orchard_checkpoints) = (
            ensure_checkpoints(
                orchard_checkpoint_positions.keys(),
                &sapling_checkpoint_positions,
                from_state.final_sapling_tree(),
            ),
            ensure_checkpoints(
                sapling_checkpoint_positions.keys(),
                &orchard_checkpoint_positions,
                from_state.final_orchard_tree(),
            ),
        );

        // Update the Sapling note commitment tree with all newly read note commitments
        {
            let mut sapling_subtrees_iter = sapling_subtrees.into_iter();
            wallet_db.with_sapling_tree_mut::<_, _, PutBlocksError<SE, TE>>(|sapling_tree| {
                debug!(
                    "Sapling initial tree size at {:?}: {:?}",
                    from_state.block_height(),
                    from_state.final_sapling_tree().tree_size()
                );
                // We insert the frontier with `Checkpoint` retention because we need to be
                // able to truncate the tree back to this point.
                sapling_tree.insert_frontier(
                    from_state.final_sapling_tree().clone(),
                    Retention::Checkpoint {
                        id: from_state.block_height(),
                        marking: Marking::Reference,
                    },
                )?;

                for (tree, checkpoints) in &mut sapling_subtrees_iter {
                    sapling_tree.insert_tree(tree, checkpoints)?;
                }

                // Ensure we have a Sapling checkpoint for each checkpointed Orchard block height.
                // We skip all checkpoints below the minimum retained checkpoint in the
                // Sapling tree, because branches below this height may be pruned.
                #[cfg(feature = "orchard")]
                {
                    let min_checkpoint_height = sapling_tree
                        .store()
                        .min_checkpoint_id()
                        .map_err(ShardTreeError::Storage)?
                        .expect("At least one checkpoint was inserted (by insert_frontier)");

                    for (height, checkpoint) in &missing_sapling_checkpoints {
                        if *height > min_checkpoint_height {
                            sapling_tree
                                .store_mut()
                                .add_checkpoint(*height, checkpoint.clone())
                                .map_err(ShardTreeError::Storage)?;
                        }
                    }
                }

                Ok(())
            })?;
        }

        // Update the Orchard note commitment tree with all newly read note commitments
        #[cfg(feature = "orchard")]
        {
            let mut orchard_subtrees = orchard_subtrees.into_iter();
            wallet_db.with_orchard_tree_mut::<_, _, PutBlocksError<SE, TE>>(|orchard_tree| {
                debug!(
                    "Orchard initial tree size at {:?}: {:?}",
                    from_state.block_height(),
                    from_state.final_orchard_tree().tree_size()
                );
                // We insert the frontier with `Checkpoint` retention because we need to be
                // able to truncate the tree back to this point.
                orchard_tree.insert_frontier(
                    from_state.final_orchard_tree().clone(),
                    Retention::Checkpoint {
                        id: from_state.block_height(),
                        marking: Marking::Reference,
                    },
                )?;

                for (tree, checkpoints) in &mut orchard_subtrees {
                    orchard_tree.insert_tree(tree, checkpoints)?;
                }

                // Ensure we have an Orchard checkpoint for each checkpointed Sapling block height.
                // We skip all checkpoints below the minimum retained checkpoint in the
                // Orchard tree, because branches below this height may be pruned.
                {
                    let min_checkpoint_height = orchard_tree
                        .store()
                        .min_checkpoint_id()
                        .map_err(ShardTreeError::Storage)?
                        .expect("At least one checkpoint was inserted (by insert_frontier)");

                    for (height, checkpoint) in &missing_orchard_checkpoints {
                        if *height > min_checkpoint_height {
                            debug!(
                                "Adding missing Orchard checkpoint for height: {:?}: {:?}",
                                height,
                                checkpoint.position()
                            );
                            orchard_tree
                                .store_mut()
                                .add_checkpoint(*height, checkpoint.clone())
                                .map_err(ShardTreeError::Storage)?;
                        }
                    }
                }
                Ok(())
            })?;
        }

        wallet_db
            .notify_scan_complete(
                Range {
                    start: start_positions.height,
                    end: last_scanned_height + 1,
                },
                &note_positions,
            )
            .map_err(PutBlocksError::Storage)?;
    }

    Ok(())
}

/// Persists a decrypted transaction to the wallet database.
///
/// This function stores a transaction that has been decrypted by the wallet, including:
/// - The transaction data and any computed fee (if all inputs are known)
/// - Received shielded notes (Sapling and Orchard)
/// - Sent outputs with recipient information
/// - Transparent outputs received by or sent from the wallet
/// - Nullifier tracking for spent notes
///
/// The function also queues requests for retrieval of any unknown transparent inputs,
/// which may be needed to compute the transaction fee or track wallet history.
///
/// # Parameters
/// - `wallet_db`: The wallet database to update.
/// - `params`: The network parameters.
/// - `chain_tip_height`: The current chain tip height, used as the observation height for
///   unmined transactions.
/// - `d_tx`: The decrypted transaction to store.
///
/// # Returns
/// Returns `Ok(())` if the transaction was successfully stored, or an error if a database
/// operation failed.
pub fn store_decrypted_tx<DbT, P>(
    wallet_db: &mut DbT,
    params: &P,
    chain_tip_height: BlockHeight,
    d_tx: DecryptedTransaction<Transaction, <DbT as LowLevelWalletRead>::AccountId>,
) -> Result<(), <DbT as LowLevelWalletRead>::Error>
where
    DbT: LowLevelWalletWrite,
    DbT::AccountId: core::fmt::Debug,
    DbT::Error: From<BalanceError>,
    P: consensus::Parameters,
{
    let funding_accounts = wallet_db.get_funding_accounts(d_tx.tx())?;

    // TODO(#1305): Correctly track accounts that fund each transaction output.
    let funding_account = funding_accounts.iter().next().copied();
    if funding_accounts.len() > 1 {
        warn!(
            "More than one wallet account detected as funding transaction {:?}, selecting {:?}",
            d_tx.tx().txid(),
            funding_account.unwrap()
        )
    }

    let wallet_transparent_outputs = detect_wallet_transparent_outputs::<DbT, P>(
        #[cfg(feature = "transparent-inputs")]
        wallet_db,
        params,
        &d_tx,
        funding_account,
    )?;

    // If there is no wallet involvement, we don't need to store the transaction, so just return
    // here.
    if funding_account.is_none()
        && wallet_transparent_outputs.is_empty()
        && !d_tx.has_decrypted_outputs()
    {
        wallet_db.delete_retrieval_queue_entries(d_tx.tx().txid())?;
        return Ok(());
    }

    info!("Storing decrypted transaction with id {}", d_tx.tx().txid());
    let observed_height = d_tx.mined_height().unwrap_or(chain_tip_height + 1);

    // If the transaction is fully shielded, or all transparent inputs are available, set the
    // fee value.
    let fee = determine_fee(wallet_db, d_tx.tx())?;

    let tx_ref = wallet_db.put_tx_data(d_tx.tx(), fee, None, None, observed_height)?;
    if let Some(height) = d_tx.mined_height() {
        wallet_db.set_transaction_status(d_tx.tx().txid(), TransactionStatus::Mined(height))?;
    }

    // A flag used to determine whether it is necessary to query for transactions that
    // provided transparent inputs to this transaction, in order to be able to correctly
    // recover transparent transaction history.
    #[cfg(feature = "transparent-inputs")]
    let mut tx_has_wallet_outputs = false;

    // The set of account/scope pairs for which to update the gap limit.
    #[cfg(feature = "transparent-inputs")]
    let mut gap_update_set = HashSet::new();

    for output in d_tx.sapling_outputs() {
        #[cfg(feature = "transparent-inputs")]
        {
            tx_has_wallet_outputs = true;
        }
        match output.transfer_type() {
            TransferType::Outgoing => {
                let recipient = {
                    let receiver = Receiver::Sapling(output.note().recipient());
                    let recipient_address = wallet_db
                        .select_receiving_address(*output.account(), &receiver)?
                        .unwrap_or_else(|| receiver.to_zcash_address(params.network_type()));

                    Recipient::External {
                        recipient_address,
                        output_pool: PoolType::SAPLING,
                    }
                };

                wallet_db.put_sent_output(
                    *output.account(),
                    tx_ref,
                    output.index(),
                    &recipient,
                    output.note_value(),
                    Some(output.memo()),
                )?;
            }
            TransferType::WalletInternal => {
                wallet_db.put_received_sapling_note(output, tx_ref, d_tx.mined_height(), None)?;

                let recipient = Recipient::InternalAccount {
                    receiving_account: *output.account(),
                    external_address: None,
                    note: Box::new(Note::Sapling(output.note().clone())),
                };

                wallet_db.put_sent_output(
                    *output.account(),
                    tx_ref,
                    output.index(),
                    &recipient,
                    output.note_value(),
                    Some(output.memo()),
                )?;
            }
            TransferType::Incoming => {
                wallet_db.put_received_sapling_note(output, tx_ref, d_tx.mined_height(), None)?;

                #[cfg(feature = "transparent-inputs")]
                gap_update_set.insert((output.account_id(), TransparentKeyScope::EXTERNAL));

                if let Some(account_id) = funding_account {
                    let recipient = Recipient::InternalAccount {
                        receiving_account: *output.account(),
                        external_address: {
                            let receiver = Receiver::Sapling(output.note().recipient());
                            Some(
                                wallet_db
                                    .select_receiving_address(*output.account(), &receiver)?
                                    .unwrap_or_else(|| {
                                        receiver.to_zcash_address(params.network_type())
                                    }),
                            )
                        },
                        note: Box::new(Note::Sapling(output.note().clone())),
                    };

                    wallet_db.put_sent_output(
                        account_id,
                        tx_ref,
                        output.index(),
                        &recipient,
                        output.note_value(),
                        Some(output.memo()),
                    )?;
                }
            }
        }
    }

    // Mark Sapling notes as spent when we observe their nullifiers.
    for spend in d_tx
        .tx()
        .sapling_bundle()
        .iter()
        .flat_map(|b| b.shielded_spends().iter())
    {
        wallet_db.mark_sapling_note_spent(spend.nullifier(), tx_ref)?;
    }

    #[cfg(feature = "orchard")]
    for output in d_tx.orchard_outputs() {
        #[cfg(feature = "transparent-inputs")]
        {
            tx_has_wallet_outputs = true;
        }
        match output.transfer_type() {
            TransferType::Outgoing => {
                let recipient = {
                    let receiver = Receiver::Orchard(output.note().recipient());
                    let recipient_address = wallet_db
                        .select_receiving_address(*output.account(), &receiver)?
                        .unwrap_or_else(|| receiver.to_zcash_address(params.network_type()));

                    Recipient::External {
                        recipient_address,
                        output_pool: PoolType::ORCHARD,
                    }
                };

                wallet_db.put_sent_output(
                    *output.account(),
                    tx_ref,
                    output.index(),
                    &recipient,
                    output.note_value(),
                    Some(output.memo()),
                )?;
            }
            TransferType::WalletInternal => {
                wallet_db.put_received_orchard_note(output, tx_ref, d_tx.mined_height(), None)?;

                let recipient = Recipient::InternalAccount {
                    receiving_account: *output.account(),
                    external_address: None,
                    note: Box::new(Note::Orchard(*output.note())),
                };

                wallet_db.put_sent_output(
                    *output.account(),
                    tx_ref,
                    output.index(),
                    &recipient,
                    output.note_value(),
                    Some(output.memo()),
                )?;
            }
            TransferType::Incoming => {
                wallet_db.put_received_orchard_note(output, tx_ref, d_tx.mined_height(), None)?;

                #[cfg(feature = "transparent-inputs")]
                gap_update_set.insert((output.account_id(), TransparentKeyScope::EXTERNAL));

                if let Some(account_id) = funding_account {
                    // Even if the recipient address is external, record the send as internal.
                    let recipient = Recipient::InternalAccount {
                        receiving_account: *output.account(),
                        external_address: {
                            let receiver = Receiver::Orchard(output.note().recipient());
                            Some(
                                wallet_db
                                    .select_receiving_address(*output.account(), &receiver)?
                                    .unwrap_or_else(|| {
                                        receiver.to_zcash_address(params.network_type())
                                    }),
                            )
                        },
                        note: Box::new(Note::Orchard(*output.note())),
                    };

                    wallet_db.put_sent_output(
                        account_id,
                        tx_ref,
                        output.index(),
                        &recipient,
                        output.note_value(),
                        Some(output.memo()),
                    )?;
                }
            }
        }
    }

    // Mark Orchard notes as spent when we observe their nullifiers.
    #[cfg(feature = "orchard")]
    for action in d_tx
        .tx()
        .orchard_bundle()
        .iter()
        .flat_map(|b| b.actions().iter())
    {
        wallet_db.mark_orchard_note_spent(action.nullifier(), tx_ref)?;
    }

    // If any of the utxos spent in the transaction are ours, mark them as spent.
    #[cfg(feature = "transparent-inputs")]
    for txin in d_tx
        .tx()
        .transparent_bundle()
        .iter()
        .flat_map(|b| b.vin.iter())
    {
        wallet_db.mark_transparent_utxo_spent(txin.prevout(), tx_ref)?;
    }

    #[cfg(feature = "transparent-inputs")]
    for (received_t_output, key_scope) in &wallet_transparent_outputs.received {
        let (account_id, _) =
            wallet_db.put_transparent_output(received_t_output, observed_height, false)?;

        if let Some(t_key_scope) = key_scope {
            gap_update_set.insert((account_id, *t_key_scope));
        }

        // Since the wallet created the transparent output, we need to ensure
        // that any transparent inputs belonging to the wallet will be
        // discovered.
        tx_has_wallet_outputs = true;

        // When we receive transparent funds (particularly as ephemeral outputs
        // in transaction pairs sending to a ZIP 320 address) it becomes
        // possible that the spend of these outputs is not then later detected
        // if the transaction that spends them is purely transparent. This is
        // especially a problem in wallet recovery.
        wallet_db.queue_transparent_spend_detection(
            *received_t_output.recipient_address(),
            tx_ref,
            received_t_output.outpoint().n(),
        )?;
    }

    for sent_t_output in &wallet_transparent_outputs.sent {
        wallet_db.put_sent_output(
            sent_t_output.from_account_uuid,
            tx_ref,
            sent_t_output.output_index,
            &sent_t_output.recipient,
            sent_t_output.value,
            None,
        )?;

        // Even though we know the funding account, we don't know that we have
        // information for all of the transparent inputs to the transaction.
        #[cfg(feature = "transparent-inputs")]
        {
            tx_has_wallet_outputs = true;
        }
    }

    // Regenerate the gap limit addresses.
    #[cfg(feature = "transparent-inputs")]
    for (account_id, key_scope) in gap_update_set {
        use ReceiverRequirement::*;
        wallet_db.generate_transparent_gap_addresses(
            account_id,
            key_scope,
            UnifiedAddressRequest::unsafe_custom(Allow, Allow, Require),
        )?;
    }

    // For each transaction that spends a transparent output of this transaction and does not
    // already have a known fee value, set the fee if possible.
    for (spending_tx_ref, spending_tx) in
        wallet_db.get_txs_spending_transparent_outputs_of(tx_ref)?
    {
        if let Some(fee) = determine_fee(wallet_db, &spending_tx)? {
            wallet_db.update_tx_fee(spending_tx_ref, fee)?;
        }
    }

    // If the transaction has outputs that belong to the wallet as well as transparent
    // inputs, we may need to download the transactions corresponding to the transparent
    // prevout references to determine whether the transaction was created (at least in
    // part) by this wallet.
    #[cfg(feature = "transparent-inputs")]
    if tx_has_wallet_outputs {
        wallet_db.queue_transparent_input_retrieval(tx_ref, &d_tx)?
    }

    wallet_db.delete_retrieval_queue_entries(d_tx.tx().txid())?;

    // If the decrypted transaction is unmined and has no shielded components, add it to
    // the queue for status retrieval.
    #[cfg(feature = "transparent-inputs")]
    {
        let detectable_via_scanning = d_tx.tx().sapling_bundle().is_some();
        #[cfg(feature = "orchard")]
        let detectable_via_scanning =
            detectable_via_scanning | d_tx.tx().orchard_bundle().is_some();

        if d_tx.mined_height().is_none() && !detectable_via_scanning {
            wallet_db.queue_tx_retrieval(std::iter::once(d_tx.tx().txid()), None)?
        }
    }

    Ok(())
}

fn detect_wallet_transparent_outputs<DbT, P>(
    #[cfg(feature = "transparent-inputs")] wallet_db: &DbT,
    params: &P,
    d_tx: &DecryptedTransaction<Transaction, DbT::AccountId>,
    funding_account: Option<DbT::AccountId>,
) -> Result<WalletTransparentOutputs<DbT::AccountId>, DbT::Error>
where
    DbT: LowLevelWalletRead,
    DbT::AccountId: core::fmt::Debug,
    P: consensus::Parameters,
{
    // This `if` is just an optimization for cases where we would do nothing in the loop.
    if funding_account.is_some() || cfg!(feature = "transparent-inputs") {
        let mut result = WalletTransparentOutputs::empty();
        for (output_index, txout) in d_tx
            .tx()
            .transparent_bundle()
            .iter()
            .flat_map(|b| b.vout.iter())
            .enumerate()
        {
            if let Some(address) = txout.recipient_address() {
                debug!(
                    "{:?} output {} has recipient {}",
                    d_tx.tx().txid(),
                    output_index,
                    address.encode(params)
                );

                // If the output belongs to the wallet, add it to `transparent_received_outputs`.
                #[cfg(feature = "transparent-inputs")]
                if let Some((account_uuid, key_scope)) =
                    wallet_db.find_account_for_transparent_address(&address)?
                {
                    debug!(
                        "{:?} output {} belongs to account {:?}",
                        d_tx.tx().txid(),
                        output_index,
                        account_uuid
                    );
                    result.received.push((
                        WalletTransparentOutput::from_parts(
                            OutPoint::new(
                                d_tx.tx().txid().into(),
                                u32::try_from(output_index).unwrap(),
                            ),
                            txout.clone(),
                            d_tx.mined_height(),
                        )
                        .expect("txout.recipient_address extraction previously checked"),
                        key_scope,
                    ));
                } else {
                    debug!(
                        "Address {} is not recognized as belonging to any of our accounts.",
                        address.encode(params)
                    );
                }

                // If a transaction we observe contains spends from our wallet, we will
                // store its transparent outputs in the same way they would be stored by
                // create_spend_to_address.
                if let Some(account_uuid) = funding_account {
                    let receiver = Receiver::Transparent(address);

                    #[cfg(feature = "transparent-inputs")]
                    let recipient_address = wallet_db
                        .select_receiving_address(account_uuid, &receiver)?
                        .unwrap_or_else(|| receiver.to_zcash_address(params.network_type()));

                    #[cfg(not(feature = "transparent-inputs"))]
                    let recipient_address = receiver.to_zcash_address(params.network_type());

                    let recipient = Recipient::External {
                        recipient_address,
                        output_pool: PoolType::TRANSPARENT,
                    };

                    result.sent.push(TransparentSentOutput {
                        from_account_uuid: account_uuid,
                        output_index,
                        recipient,
                        value: txout.value(),
                    });
                }
            } else {
                warn!(
                    "Unable to determine recipient address for tx {} output {}",
                    d_tx.tx().txid(),
                    output_index
                );
            }
        }

        Ok(result)
    } else {
        Ok(WalletTransparentOutputs::empty())
    }
}
