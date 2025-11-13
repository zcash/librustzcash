use tracing::{debug, info, warn};

use zcash_keys::{address::Receiver, encoding::AddressCodec as _};
use zcash_protocol::{
    PoolType,
    consensus::{self, BlockHeight},
    value::{BalanceError, Zatoshis},
};

use crate::{
    TransferType,
    data_api::{DecryptedTransaction, TransactionStatus},
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
use crate::data_api::ll::ReceivedOrchardOutput as _;

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
    d_tx: DecryptedTransaction<<DbT as LowLevelWalletRead>::AccountId>,
) -> Result<(), <DbT as LowLevelWalletRead>::Error>
where
    DbT: LowLevelWalletWrite,
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

        if let Some(key_scope) = key_scope {
            gap_update_set.insert((account_id, *key_scope));
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
    for (spending_tx_ref, spending_tx) in wallet_db.get_spending_transactions(tx_ref)? {
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
    d_tx: &DecryptedTransaction<DbT::AccountId>,
    funding_account: Option<DbT::AccountId>,
) -> Result<WalletTransparentOutputs<DbT::AccountId>, DbT::Error>
where
    DbT: LowLevelWalletRead,
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
