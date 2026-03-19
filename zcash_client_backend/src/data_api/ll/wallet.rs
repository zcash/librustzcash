use std::collections::BTreeMap;
use std::hash::Hash;
use std::ops::Range;

use rayon::{
    iter::{IndexedParallelIterator as _, ParallelIterator},
    slice::ParallelSliceMut as _,
};
use tracing::{debug, info, trace, warn};

use incrementalmerkletree::{Hashable, Marking, Position, Retention, frontier::Frontier};
use shardtree::{LocatedPrunableTree, ShardTree, error::ShardTreeError, store::ShardStore};
use transparent::address::TransparentAddress;
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
        WalletCommitmentTrees, chain::ChainState, ll::ReceivedShieldedOutput,
    },
    wallet::Recipient,
};

use super::{LowLevelWalletRead, LowLevelWalletWrite, TxMeta};

#[cfg(feature = "transparent-inputs")]
use {
    crate::{data_api::Account, wallet::WalletTransparentOutput},
    std::collections::HashSet,
    transparent::{bundle::OutPoint, keys::TransparentKeyScope},
    zcash_keys::keys::{
        ReceiverRequirement, UnifiedAddressRequest,
        transparent::gap_limits::{
            AddressStore, GapAddressesError, GapLimits, generate_gap_addresses,
        },
    },
};

#[cfg(feature = "orchard")]
use {crate::data_api::ORCHARD_SHARD_HEIGHT, shardtree::store::Checkpoint};

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
struct WalletTransparentOutputs<AccountId> {
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

/// Generates transparent gap addresses for a given account and key scope.
///
/// This is a convenience function that resolves the account's viewing keys from the wallet
/// database and delegates to [`generate_gap_addresses`].
#[cfg(feature = "transparent-inputs")]
pub fn generate_transparent_gap_addresses<DbT, SE>(
    wallet_db: &mut DbT,
    gap_limits: GapLimits,
    account_id: <DbT as LowLevelWalletRead>::AccountId,
    key_scope: TransparentKeyScope,
    request: UnifiedAddressRequest,
) -> Result<(), GapAddressesError<SE>>
where
    DbT: LowLevelWalletWrite<Error = SE>
        + AddressStore<Error = SE, AccountRef = <DbT as LowLevelWalletRead>::AccountRef>,
    DbT::TxRef: Eq + Hash,
{
    let account_ref = wallet_db
        .get_account_ref(account_id)
        .map_err(GapAddressesError::Storage)?;

    let account = wallet_db
        .get_account_internal(account_ref)
        .map_err(GapAddressesError::Storage)?
        .ok_or(GapAddressesError::AccountUnknown)?;

    generate_gap_addresses(
        wallet_db,
        &gap_limits,
        account_ref,
        &account.uivk(),
        account.ufvk(),
        key_scope,
        request,
        false,
    )?;

    Ok(())
}

pub enum PutBlocksError<SE, TE> {
    /// Returned if a provided block sequence has gaps.
    NonSequentialBlocks {
        prev_height: BlockHeight,
        block_height: BlockHeight,
    },
    /// Wraps an error produced by the underlying data storage system.
    Storage(SE),
    /// Wraps an error produced by [`shardtree`] insertion.
    ShardTree(ShardTreeError<TE>),
    #[cfg(feature = "transparent-inputs")]
    GapAddresses(GapAddressesError<SE>),
}

impl<SE, TE> From<ShardTreeError<TE>> for PutBlocksError<SE, TE> {
    fn from(value: ShardTreeError<TE>) -> Self {
        PutBlocksError::ShardTree(value)
    }
}

#[cfg(feature = "transparent-inputs")]
impl<SE, TE> From<GapAddressesError<SE>> for PutBlocksError<SE, TE> {
    fn from(value: GapAddressesError<SE>) -> Self {
        PutBlocksError::GapAddresses(value)
    }
}

/// A trait alias capturing the database capabilities required by [`put_blocks`].
///
/// When the `transparent-inputs` feature is enabled, this additionally requires
/// [`AddressStore`] so that transparent gap addresses can be maintained as new
/// blocks are scanned.
#[cfg(not(feature = "transparent-inputs"))]
pub trait PutBlocksDbT<SE, TE, AR>:
    LowLevelWalletWrite<Error = SE> + WalletCommitmentTrees<Error = TE>
{
}

#[cfg(not(feature = "transparent-inputs"))]
impl<T: LowLevelWalletWrite<Error = SE> + WalletCommitmentTrees<Error = TE>, SE, TE, AR>
    PutBlocksDbT<SE, TE, AR> for T
{
}

/// A trait alias capturing the database capabilities required by [`put_blocks`].
///
/// When the `transparent-inputs` feature is enabled, this additionally requires
/// [`AddressStore`] so that transparent gap addresses can be maintained as new
/// blocks are scanned.
#[cfg(feature = "transparent-inputs")]
pub trait PutBlocksDbT<SE, TE, AR>:
    LowLevelWalletWrite<Error = SE>
    + WalletCommitmentTrees<Error = TE>
    + AddressStore<Error = SE, AccountRef = AR>
{
}

#[cfg(feature = "transparent-inputs")]
impl<
    T: LowLevelWalletWrite<Error = SE>
        + WalletCommitmentTrees<Error = TE>
        + AddressStore<Error = SE, AccountRef = AR>,
    SE,
    TE,
    AR,
> PutBlocksDbT<SE, TE, AR> for T
{
}

/// Adds information about a sequence of scanned blocks to the provided data store.
///
/// # Parameters
/// - `wallet_db`: A handle to the underlying data store.
/// - `from_state`: The note commitment tree state as of the end of the last block prior to the
///   first block in the provided block vector; [`PutBlocksError::NonSequentialBlocks`] will be
///   returned if this invariant is violated.
/// - `blocks`: The scanned block data to be added to the data store. This vector must contain
///   data for blocks in sequentially increasing height order;
///   [`PutBlocksError::NonSequentialBlocks`] will be returned if this invariant is violated.
pub fn put_blocks<DbT, SE, TE>(
    wallet_db: &mut DbT,
    #[cfg(feature = "transparent-inputs")] gap_limits: GapLimits,
    from_state: &ChainState,
    blocks: Vec<ScannedBlock<<DbT as LowLevelWalletRead>::AccountId>>,
) -> Result<(), PutBlocksError<SE, TE>>
where
    DbT: PutBlocksDbT<SE, TE, <DbT as LowLevelWalletRead>::AccountRef>,
    DbT::TxRef: Eq + Hash,
{
    if blocks.is_empty() {
        return Ok(());
    }

    let initial_block = blocks.first().expect("blocks is known to be nonempty");
    let mut initial_block_sequential = from_state.block_height() + 1 == initial_block.height();
    {
        initial_block_sequential &= from_state.final_sapling_tree().tree_size()
            + u64::try_from(initial_block.sapling().commitments().len()).unwrap()
            == u64::from(initial_block.sapling().final_tree_size());
    }
    #[cfg(feature = "orchard")]
    {
        initial_block_sequential &= from_state.final_orchard_tree().tree_size()
            + u64::try_from(initial_block.orchard().commitments().len()).unwrap()
            == u64::from(initial_block.orchard().final_tree_size());
    }
    if !initial_block_sequential {
        return Err(PutBlocksError::NonSequentialBlocks {
            prev_height: from_state.block_height(),
            block_height: initial_block.height(),
        });
    }

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
            mark_notes_spent(
                wallet_db,
                tx_ref,
                #[cfg(feature = "transparent-inputs")]
                None.iter(),
                tx.sapling_spends().iter().map(|spend| spend.nf()),
                #[cfg(feature = "orchard")]
                tx.orchard_spends().iter().map(|spend| spend.nf()),
            )
            .map_err(PutBlocksError::Storage)?;

            // TODO: Pass in the actual network parameters even though we don't need them.
            let params: Option<&consensus::Network> = None;

            put_shielded_outputs(
                wallet_db,
                params,
                tx_ref,
                None,
                tx.sapling_outputs(),
                // Check whether this note was spent in a later block range that
                // we previously scanned.
                |wallet_db, output| {
                    Ok(output
                        .nf()
                        .map(|nf| wallet_db.detect_sapling_spend(nf))
                        .transpose()?
                        .flatten())
                },
                |wallet_db, output, tx_ref, spent_in| {
                    wallet_db.put_received_sapling_note(
                        output,
                        tx_ref,
                        Some(block.height()),
                        spent_in,
                    )
                },
                |_account_id| (),
            )
            .map_err(PutBlocksError::Storage)?;

            #[cfg(feature = "orchard")]
            put_shielded_outputs(
                wallet_db,
                params,
                tx_ref,
                None,
                tx.orchard_outputs(),
                // Check whether this note was spent in a later block range that
                // we previously scanned.
                |wallet_db, output| {
                    Ok(output
                        .nf()
                        .map(|nf| wallet_db.detect_orchard_spend(nf))
                        .transpose()?
                        .flatten())
                },
                |wallet_db, output, tx_ref, spent_in| {
                    wallet_db.put_received_orchard_note(
                        output,
                        tx_ref,
                        Some(block.height()),
                        spent_in,
                    )
                },
                |_account_id| (),
            )
            .map_err(PutBlocksError::Storage)?;
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
            generate_transparent_gap_addresses(
                wallet_db,
                gap_limits,
                account_id,
                t_key_scope,
                UnifiedAddressRequest::unsafe_custom(Allow, Allow, Require),
            )
            .map_err(PutBlocksError::GapAddresses)?;
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
        let sapling_subtrees = build_subtrees::<_, SAPLING_SHARD_HEIGHT>(
            Position::from(from_state.final_sapling_tree().tree_size()),
            &mut sapling_commitments,
            CHUNK_SIZE,
        );

        #[cfg(feature = "orchard")]
        let orchard_subtrees = build_subtrees::<_, ORCHARD_SHARD_HEIGHT>(
            Position::from(from_state.final_orchard_tree().tree_size()),
            &mut orchard_commitments,
            CHUNK_SIZE,
        );

        // Ensure that we have the same set of checkpoints across all trees.
        #[cfg(feature = "orchard")]
        let (missing_sapling_checkpoints, missing_orchard_checkpoints) = {
            let sapling_checkpoint_positions = checkpoint_positions(&sapling_subtrees);
            let orchard_checkpoint_positions = checkpoint_positions(&orchard_subtrees);
            (
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
            )
        };

        // Update the Sapling note commitment tree with all newly read note commitments
        {
            let mut sapling_subtrees = sapling_subtrees.into_iter();
            #[cfg(feature = "orchard")]
            let mut missing_checkpoints = missing_sapling_checkpoints.into_iter();
            wallet_db.with_sapling_tree_mut(|sapling_tree| {
                update_tree(
                    "Sapling",
                    from_state.final_sapling_tree(),
                    from_state.block_height(),
                    sapling_tree,
                    &mut sapling_subtrees,
                    #[cfg(feature = "orchard")]
                    &mut missing_checkpoints,
                )
                .map_err(PutBlocksError::ShardTree)
            })?;
        }

        // Update the Orchard note commitment tree with all newly read note commitments
        #[cfg(feature = "orchard")]
        {
            let mut orchard_subtrees = orchard_subtrees.into_iter();
            let mut missing_checkpoints = missing_orchard_checkpoints.into_iter();
            wallet_db.with_orchard_tree_mut(|orchard_tree| {
                update_tree(
                    "Orchard",
                    from_state.final_orchard_tree(),
                    from_state.block_height(),
                    orchard_tree,
                    &mut orchard_subtrees,
                    &mut missing_checkpoints,
                )
                .map_err(PutBlocksError::ShardTree)
            })?;
        }

        wallet_db
            .notify_scan_complete(
                Range {
                    start: from_state.block_height() + 1,
                    end: last_scanned_height + 1,
                },
                &note_positions,
            )
            .map_err(PutBlocksError::Storage)?;
    }

    Ok(())
}

#[cfg(not(feature = "transparent-inputs"))]
type GapError<DbT> = <DbT as LowLevelWalletRead>::Error;

/// A trait alias capturing the database capabilities required by [`store_decrypted_tx`].
///
/// When the `transparent-inputs` feature is enabled, this additionally requires
/// [`AddressStore`] so that transparent gap addresses can be regenerated after
/// storing a decrypted transaction.
#[cfg(not(feature = "transparent-inputs"))]
pub trait StoreDecryptedTxDbT: LowLevelWalletWrite {}

#[cfg(not(feature = "transparent-inputs"))]
impl<T: LowLevelWalletWrite> StoreDecryptedTxDbT for T {}

#[cfg(feature = "transparent-inputs")]
type GapError<DbT> = GapAddressesError<<DbT as LowLevelWalletRead>::Error>;

/// A trait alias capturing the database capabilities required by [`store_decrypted_tx`].
///
/// When the `transparent-inputs` feature is enabled, this additionally requires
/// [`AddressStore`] so that transparent gap addresses can be regenerated after
/// storing a decrypted transaction.
#[cfg(feature = "transparent-inputs")]
pub trait StoreDecryptedTxDbT:
    LowLevelWalletWrite
    + AddressStore<
        Error = <Self as LowLevelWalletRead>::Error,
        AccountRef = <Self as LowLevelWalletRead>::AccountRef,
    >
where
    <Self as LowLevelWalletRead>::Error: From<GapError<Self>>,
{
}

#[cfg(feature = "transparent-inputs")]
impl<
    T: LowLevelWalletWrite
        + AddressStore<
            Error = <T as LowLevelWalletRead>::Error,
            AccountRef = <T as LowLevelWalletRead>::AccountRef,
        >,
> StoreDecryptedTxDbT for T
where
    <T as LowLevelWalletRead>::Error: From<GapError<T>>,
{
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
    #[cfg(feature = "transparent-inputs")] gap_limits: GapLimits,
    chain_tip_height: BlockHeight,
    d_tx: DecryptedTransaction<Transaction, <DbT as LowLevelWalletRead>::AccountId>,
) -> Result<(), <DbT as LowLevelWalletRead>::Error>
where
    DbT: StoreDecryptedTxDbT,
    <DbT as LowLevelWalletRead>::AccountId: core::fmt::Debug,
    <DbT as LowLevelWalletRead>::Error: From<BalanceError> + From<GapError<DbT>>,
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

    mark_notes_spent(
        wallet_db,
        tx_ref,
        #[cfg(feature = "transparent-inputs")]
        d_tx.tx()
            .transparent_bundle()
            .iter()
            .flat_map(|b| b.vin.iter())
            .map(|txin| txin.prevout()),
        d_tx.tx()
            .sapling_bundle()
            .iter()
            .flat_map(|b| b.shielded_spends().iter())
            .map(|spend| spend.nullifier()),
        #[cfg(feature = "orchard")]
        d_tx.tx()
            .orchard_bundle()
            .iter()
            .flat_map(|b| b.actions().iter())
            .map(|action| action.nullifier()),
    )?;

    // A flag used to determine whether it is necessary to query for transactions that
    // provided transparent inputs to this transaction, in order to be able to correctly
    // recover transparent transaction history.
    #[cfg(feature = "transparent-inputs")]
    let mut tx_has_wallet_outputs = false;
    #[cfg(feature = "transparent-inputs")]
    {
        tx_has_wallet_outputs |= !d_tx.sapling_outputs().is_empty();

        #[cfg(feature = "orchard")]
        {
            tx_has_wallet_outputs |= !d_tx.orchard_outputs().is_empty();
        }

        // Since the wallet created the transparent output, we need to ensure
        // that any transparent inputs belonging to the wallet will be
        // discovered.
        tx_has_wallet_outputs |= !wallet_transparent_outputs.received.is_empty();

        // Even though we know the funding account, we don't know that we have
        // information for all of the transparent inputs to the transaction.
        tx_has_wallet_outputs |= !wallet_transparent_outputs.sent.is_empty();
    }

    // The set of account/scope pairs for which to update the gap limit.
    #[cfg(feature = "transparent-inputs")]
    let mut gap_update_set = HashSet::new();

    put_shielded_outputs(
        wallet_db,
        Some(params),
        tx_ref,
        funding_account,
        d_tx.sapling_outputs(),
        |_, _| Ok(None),
        |wallet_db, output, tx_ref, spent_in| {
            wallet_db.put_received_sapling_note(output, tx_ref, d_tx.mined_height(), spent_in)
        },
        |_account_id| {
            #[cfg(feature = "transparent-inputs")]
            gap_update_set.insert((_account_id, TransparentKeyScope::EXTERNAL));
        },
    )?;

    #[cfg(feature = "orchard")]
    put_shielded_outputs(
        wallet_db,
        Some(params),
        tx_ref,
        funding_account,
        d_tx.orchard_outputs(),
        |_, _| Ok(None),
        |wallet_db, output, tx_ref, spent_in| {
            wallet_db.put_received_orchard_note(output, tx_ref, d_tx.mined_height(), spent_in)
        },
        |_account_id| {
            #[cfg(feature = "transparent-inputs")]
            gap_update_set.insert((_account_id, TransparentKeyScope::EXTERNAL));
        },
    )?;

    put_transparent_outputs(
        wallet_db,
        tx_ref,
        &wallet_transparent_outputs,
        #[cfg(feature = "transparent-inputs")]
        |wallet_db, output| wallet_db.put_transparent_output(output, observed_height, false),
        #[cfg(feature = "transparent-inputs")]
        |account_id, t_key_scope| {
            gap_update_set.insert((account_id, t_key_scope));
        },
    )?;

    // Regenerate the gap limit addresses.
    #[cfg(feature = "transparent-inputs")]
    for (account_id, key_scope) in gap_update_set {
        use ReceiverRequirement::*;
        generate_transparent_gap_addresses(
            wallet_db,
            gap_limits,
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
            let script_kind = txout.script_kind();
            if let Some(address) = script_kind
                .as_ref()
                .and_then(TransparentAddress::from_script_kind)
            {
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
                    let recipient_address =
                        external_address(wallet_db, params, account_uuid, receiver)?;

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
            } else if let Some(script_kind) = script_kind {
                warn!(
                    "Ignoring unsupported script kind '{}' for tx {} output {}",
                    script_kind.as_str(),
                    d_tx.tx().txid(),
                    output_index
                );
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

fn mark_notes_spent<'a, DbT>(
    wallet_db: &mut DbT,
    tx_ref: <DbT as LowLevelWalletRead>::TxRef,
    #[cfg(feature = "transparent-inputs")] transparent_prevouts: impl Iterator<
        Item = &'a transparent::bundle::OutPoint,
    >,
    sapling_nfs: impl Iterator<Item = &'a sapling::Nullifier>,
    #[cfg(feature = "orchard")] orchard_nfs: impl Iterator<Item = &'a orchard::note::Nullifier>,
) -> Result<(), <DbT as LowLevelWalletRead>::Error>
where
    DbT: LowLevelWalletWrite,
{
    // If any of the utxos spent in the transaction are ours, mark them as spent.
    #[cfg(feature = "transparent-inputs")]
    for outpoint in transparent_prevouts {
        wallet_db.mark_transparent_utxo_spent(outpoint, tx_ref)?;
    }

    // Mark Sapling notes as spent when we observe their nullifiers.
    for nf in sapling_nfs {
        wallet_db.mark_sapling_note_spent(nf, tx_ref)?;
    }

    // Mark Orchard notes as spent when we observe their nullifiers.
    #[cfg(feature = "orchard")]
    for nf in orchard_nfs {
        wallet_db.mark_orchard_note_spent(nf, tx_ref)?;
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn put_shielded_outputs<DbT, P, Output>(
    wallet_db: &mut DbT,
    params: Option<&P>,
    tx_ref: <DbT as LowLevelWalletRead>::TxRef,
    funding_account: Option<DbT::AccountId>,
    outputs: &[Output],
    detect_note_spent_in: impl Fn(
        &mut DbT,
        &Output,
    ) -> Result<
        Option<<DbT as LowLevelWalletRead>::TxRef>,
        <DbT as LowLevelWalletRead>::Error,
    >,
    put_received_note: impl Fn(
        &mut DbT,
        &Output,
        <DbT as LowLevelWalletRead>::TxRef,
        Option<<DbT as LowLevelWalletRead>::TxRef>,
    ) -> Result<(), <DbT as LowLevelWalletRead>::Error>,
    mut on_external_account: impl FnMut(<DbT as LowLevelWalletRead>::AccountId),
) -> Result<(), <DbT as LowLevelWalletRead>::Error>
where
    DbT: LowLevelWalletWrite,
    P: consensus::Parameters,
    Output: ReceivedShieldedOutput<AccountId = <DbT as LowLevelWalletRead>::AccountId>,
    Output::Note: Clone,
{
    for output in outputs {
        let sent_output = match output.transfer_type() {
            TransferType::Outgoing => {
                let note = output.note().clone().into();

                let recipient = Recipient::External {
                    recipient_address: external_address(
                        wallet_db,
                        params.expect("present when outgoing is possible (store_decrypted_tx)"),
                        output.account_id(),
                        note.receiver(),
                    )?,
                    output_pool: Output::POOL_TYPE,
                };

                Some((output.account_id(), recipient, note.value()))
            }
            TransferType::WalletInternal => {
                let spent_in = detect_note_spent_in(wallet_db, output)?;
                put_received_note(wallet_db, output, tx_ref, spent_in)?;

                let note = output.note().clone().into();
                let value = note.value();

                let recipient = Recipient::InternalAccount {
                    receiving_account: output.account_id(),
                    external_address: None,
                    note: Box::new(note),
                };

                Some((output.account_id(), recipient, value))
            }
            TransferType::Incoming => {
                let spent_in = detect_note_spent_in(wallet_db, output)?;
                put_received_note(wallet_db, output, tx_ref, spent_in)?;
                on_external_account(output.account_id());

                if let Some(account_id) = funding_account {
                    let note = output.note().clone().into();
                    let value = note.value();

                    // Even if the recipient address is external, record the send as internal.
                    let recipient = Recipient::InternalAccount {
                        receiving_account: output.account_id(),
                        external_address: Some(external_address(
                            wallet_db,
                            params.expect(
                                "present when funding_account is known (store_decrypted_tx)",
                            ),
                            output.account_id(),
                            note.receiver(),
                        )?),
                        note: Box::new(note),
                    };

                    Some((account_id, recipient, value))
                } else {
                    None
                }
            }
        };

        if let Some((from_account_uuid, recipient, value)) = sent_output {
            wallet_db.put_sent_output(
                from_account_uuid,
                tx_ref,
                output.index(),
                &recipient,
                value,
                output.memo(),
            )?;
        }
    }

    Ok(())
}

fn put_transparent_outputs<DbT>(
    wallet_db: &mut DbT,
    tx_ref: <DbT as LowLevelWalletRead>::TxRef,
    outputs: &WalletTransparentOutputs<<DbT as LowLevelWalletRead>::AccountId>,
    #[cfg(feature = "transparent-inputs")] put_received_output: impl Fn(
        &mut DbT,
        &WalletTransparentOutput,
    ) -> Result<
        (
            <DbT as LowLevelWalletRead>::AccountId,
            std::option::Option<TransparentKeyScope>,
        ),
        <DbT as LowLevelWalletRead>::Error,
    >,
    #[cfg(feature = "transparent-inputs")] mut on_received: impl FnMut(
        <DbT as LowLevelWalletRead>::AccountId,
        TransparentKeyScope,
    ),
) -> Result<(), <DbT as LowLevelWalletRead>::Error>
where
    DbT: LowLevelWalletWrite,
{
    #[cfg(feature = "transparent-inputs")]
    for (received_t_output, key_scope) in &outputs.received {
        let (account_id, _) = put_received_output(wallet_db, received_t_output)?;

        if let Some(t_key_scope) = key_scope {
            on_received(account_id, *t_key_scope);
        }

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

    for sent_t_output in &outputs.sent {
        wallet_db.put_sent_output(
            sent_t_output.from_account_uuid,
            tx_ref,
            sent_t_output.output_index,
            &sent_t_output.recipient,
            sent_t_output.value,
            None,
        )?;
    }

    Ok(())
}

/// Returns the most likely account address that corresponds to the given [`Receiver`].
fn external_address<DbT, P>(
    wallet_db: &DbT,
    params: &P,
    account_id: DbT::AccountId,
    receiver: Receiver,
) -> Result<zcash_address::ZcashAddress, <DbT as LowLevelWalletRead>::Error>
where
    DbT: LowLevelWalletRead,
    P: consensus::Parameters,
{
    let recipient_address = wallet_db
        .select_receiving_address(account_id, &receiver)?
        .unwrap_or_else(|| receiver.to_zcash_address(params.network_type()));

    Ok(recipient_address)
}

/// Creates subtrees from note commitments in parallel.
///
/// `commitments` is an `&mut [Option<_>]` to emulate move semantics inside a `rayon`
/// parallel iterator.
fn build_subtrees<H, const SHARD_HEIGHT: u8>(
    start_position: Position,
    commitments: &mut [Option<(H, Retention<BlockHeight>)>],
    chunk_size: usize,
) -> Vec<(LocatedPrunableTree<H>, BTreeMap<BlockHeight, Position>)>
where
    H: Clone + PartialEq + Hashable + Send + Sync,
{
    commitments
        .par_chunks_mut(chunk_size)
        .enumerate()
        .filter_map(|(i, chunk)| {
            let start = start_position + (i * chunk_size) as u64;
            let end = start + chunk.len() as u64;

            shardtree::LocatedTree::from_iter(
                start..end,
                SHARD_HEIGHT.into(),
                chunk.iter_mut().map(|n| n.take().expect("always Some")),
            )
        })
        .map(|res| (res.subtree, res.checkpoints))
        .collect()
}

/// Produces an overall set of checkpoints from a list of subtrees.
#[cfg(feature = "orchard")]
fn checkpoint_positions<H>(
    subtrees: &[(LocatedPrunableTree<H>, BTreeMap<BlockHeight, Position>)],
) -> BTreeMap<BlockHeight, Position> {
    subtrees
        .iter()
        .flat_map(|(_, checkpoints)| checkpoints.iter())
        .map(|(k, v)| (*k, *v))
        .collect()
}

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

/// Updates the given note commitment tree with all newly read note commitments starting
/// at the block `frontier_height + 1`.
fn update_tree<S, const DEPTH: u8, const SHARD_HEIGHT: u8>(
    protocol: &'static str,
    frontier: &Frontier<S::H, DEPTH>,
    frontier_height: BlockHeight,
    tree: &mut ShardTree<S, DEPTH, SHARD_HEIGHT>,
    subtrees: impl Iterator<Item = (LocatedPrunableTree<S::H>, BTreeMap<BlockHeight, Position>)>,
    #[cfg(feature = "orchard")] missing_checkpoints: impl Iterator<Item = (BlockHeight, Checkpoint)>,
) -> Result<(), ShardTreeError<S::Error>>
where
    S: ShardStore<CheckpointId = BlockHeight>,
    S::H: Clone + PartialEq + Hashable,
{
    debug!(
        "{protocol} initial tree size at {frontier_height:?}: {:?}",
        frontier.tree_size()
    );
    // We insert the frontier with `Checkpoint` retention because we need to be
    // able to truncate the tree back to this point.
    tree.insert_frontier(
        frontier.clone(),
        Retention::Checkpoint {
            id: frontier_height,
            marking: Marking::Reference,
        },
    )?;

    for (subtree, checkpoints) in subtrees {
        tree.insert_tree(subtree, checkpoints)?;
    }

    // Ensure we have a tree checkpoint for each checkpointed block height.
    // We skip all checkpoints below the minimum retained checkpoint in the
    // tree, because branches below this height may be pruned.
    #[cfg(feature = "orchard")]
    {
        let min_checkpoint_height = tree
            .store()
            .min_checkpoint_id()
            .map_err(ShardTreeError::Storage)?
            .expect("At least one checkpoint was inserted (by insert_frontier)");

        for (height, checkpoint) in missing_checkpoints {
            if height > min_checkpoint_height {
                debug!(
                    "Adding missing {protocol} checkpoint for height: {:?}: {:?}",
                    height,
                    checkpoint.position()
                );
                tree.store_mut()
                    .add_checkpoint(height, checkpoint.clone())
                    .map_err(ShardTreeError::Storage)?;
            }
        }
    }

    Ok(())
}
