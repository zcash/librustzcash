use std::fmt::Debug;
use zcash_primitives::{
    consensus::{self, NetworkUpgrade},
    memo::MemoBytes,
    sapling::prover::TxProver,
    transaction::{
        builder::Builder,
        components::{amount::DEFAULT_FEE, Amount},
        Transaction,
    },
    zip32::{AccountId, ExtendedFullViewingKey, ExtendedSpendingKey},
};

#[cfg(feature = "transparent-inputs")]
use zcash_primitives::{
    keys::OutgoingViewingKey, legacy::keys as transparent, legacy::keys::IncomingViewingKey,
};

use crate::{
    address::RecipientAddress,
    data_api::{
        error::Error, DecryptedTransaction, SentTransaction, SentTransactionOutput, WalletWrite,
    },
    decrypt_transaction,
    wallet::OvkPolicy,
    zip321::{Payment, TransactionRequest},
};

#[cfg(feature = "transparent-inputs")]
use crate::data_api::WalletWriteTransparent;

/// Scans a [`Transaction`] for any information that can be decrypted by the accounts in
/// the wallet, and saves it to the wallet.
pub fn decrypt_and_store_transaction<N, E, P, D>(
    params: &P,
    data: &mut D,
    tx: &Transaction,
) -> Result<(), E>
where
    E: From<Error<N>>,
    P: consensus::Parameters,
    D: WalletWrite<Error = E>,
{
    // Fetch the UnifiedFullViewingKeys we are tracking
    let ufvks = data.get_unified_full_viewing_keys()?;

    // Height is block height for mined transactions, and the "mempool height" (chain height + 1)
    // for mempool transactions.
    let height = data
        .get_tx_height(tx.txid())?
        .or(data
            .block_height_extrema()?
            .map(|(_, max_height)| max_height + 1))
        .or_else(|| params.activation_height(NetworkUpgrade::Sapling))
        .ok_or(Error::SaplingNotActive)?;

    let sapling_outputs = decrypt_transaction(params, height, tx, &ufvks);

    if !(sapling_outputs.is_empty() && tx.transparent_bundle().iter().all(|b| b.vout.is_empty())) {
        data.store_decrypted_tx(&DecryptedTransaction {
            tx,
            sapling_outputs: &sapling_outputs,
        })?;
    }

    Ok(())
}

#[allow(clippy::needless_doctest_main)]
/// Creates a transaction paying the specified address from the given account.
///
/// Returns the row index of the newly-created transaction in the `transactions` table
/// within the data database. The caller can read the raw transaction bytes from the `raw`
/// column in order to broadcast the transaction to the network.
///
/// Do not call this multiple times in parallel, or you will generate transactions that
/// double-spend the same notes.
///
/// # Transaction privacy
///
/// `ovk_policy` specifies the desired policy for which outgoing viewing key should be
/// able to decrypt the outputs of this transaction. This is primarily relevant to
/// wallet recovery from backup; in particular, [`OvkPolicy::Discard`] will prevent the
/// recipient's address, and the contents of `memo`, from ever being recovered from the
/// block chain. (The total value sent can always be inferred by the sender from the spent
/// notes and received change.)
///
/// Regardless of the specified policy, `create_spend_to_address` saves `to`, `value`, and
/// `memo` in `db_data`. This can be deleted independently of `ovk_policy`.
///
/// For details on what transaction information is visible to the holder of a full or
/// outgoing viewing key, refer to [ZIP 310].
///
/// [ZIP 310]: https://zips.z.cash/zip-0310
///
/// Parameters:
/// * `wallet_db`: A read/write reference to the wallet database
/// * `params`: Consensus parameters
/// * `prover`: The TxProver to use in constructing the shielded transaction.
/// * `account`: The ZIP32 account identifier associated with the extended spending
///   key that controls the funds to be used in creating this transaction.  This
///   procedure will return an error if this does not correctly correspond to `extsk`.
/// * `extsk`: The extended spending key that controls the funds that will be spent
///   in the resulting transaction.
/// * `amount`: The amount to send.
/// * `to`: The address to which `amount` will be paid.
/// * `memo`: A memo to be included in the output to the recipient.
/// * `ovk_policy`: The policy to use for constructing outgoing viewing keys that
///   can allow the sender to view the resulting notes on the blockchain.
/// * `min_confirmations`: The minimum number of confirmations that a previously
///   received note must have in the blockchain in order to be considered for being
///   spent. A value of 10 confirmations is recommended.
/// # Examples
///
/// ```
/// # #[cfg(feature = "test-dependencies")]
/// # {
/// use tempfile::NamedTempFile;
/// use zcash_primitives::{
///     consensus::{self, Network},
///     constants::testnet::COIN_TYPE,
///     transaction::{TxId, components::Amount},
///     zip32::AccountId,
/// };
/// use zcash_proofs::prover::LocalTxProver;
/// use zcash_client_backend::{
///     keys::sapling,
///     data_api::{wallet::create_spend_to_address, error::Error, testing},
///     wallet::OvkPolicy,
/// };
///
/// # fn main() {
/// #   test();
/// # }
/// #
/// # fn test() -> Result<TxId, Error<u32>> {
///
/// let tx_prover = match LocalTxProver::with_default_location() {
///     Some(tx_prover) => tx_prover,
///     None => {
///         panic!("Cannot locate the Zcash parameters. Please run zcash-fetch-params or fetch-params.sh to download the parameters, and then re-run the tests.");
///     }
/// };
///
/// let account = AccountId::from(0);
/// let extsk = sapling::spending_key(&[0; 32][..], COIN_TYPE, account);
/// let to = extsk.default_address().1.into();
///
/// let mut db_read = testing::MockWalletDb {};
///
/// create_spend_to_address(
///     &mut db_read,
///     &Network::TestNetwork,
///     tx_prover,
///     account,
///     &extsk,
///     &to,
///     Amount::from_u64(1).unwrap(),
///     None,
///     OvkPolicy::Sender,
///     10
/// )
///
/// # }
/// # }
/// ```
#[allow(clippy::too_many_arguments)]
pub fn create_spend_to_address<E, N, P, D, R>(
    wallet_db: &mut D,
    params: &P,
    prover: impl TxProver,
    account: AccountId,
    extsk: &ExtendedSpendingKey,
    to: &RecipientAddress,
    amount: Amount,
    memo: Option<MemoBytes>,
    ovk_policy: OvkPolicy,
    min_confirmations: u32,
) -> Result<R, E>
where
    E: From<Error<N>>,
    P: consensus::Parameters + Clone,
    R: Copy + Debug,
    D: WalletWrite<Error = E, TxRef = R>,
{
    let req = TransactionRequest::new(vec![Payment {
        recipient_address: to.clone(),
        amount,
        memo,
        label: None,
        message: None,
        other_params: vec![],
    }])
    .expect(
        "It should not be possible for this to violate ZIP 321 request construction invariants.",
    );

    spend(
        wallet_db,
        params,
        prover,
        extsk,
        account,
        &req,
        ovk_policy,
        min_confirmations,
    )
}

/// Constructs a transaction that sends funds as specified by the `request` argument
/// and stores it to the wallet's "sent transactions" data store, and returns a
/// unique identifier for the transaction; this identifier is used only for internal
/// reference purposes and is not the same as the transaction's txid, although after v4
/// transactions have been made invalid in a future network upgrade, the txid could
/// potentially be used for this type (as it is non-malleable for v5+ transactions).
///
/// This procedure uses the wallet's underlying note selection algorithm to choose
/// inputs of sufficient value to satisfy the request, if possible.
///
/// Do not call this multiple times in parallel, or you will generate transactions that
/// double-spend the same notes.
///
/// # Transaction privacy
///
/// `ovk_policy` specifies the desired policy for which outgoing viewing key should be
/// able to decrypt the outputs of this transaction. This is primarily relevant to
/// wallet recovery from backup; in particular, [`OvkPolicy::Discard`] will prevent the
/// recipient's address, and the contents of `memo`, from ever being recovered from the
/// block chain. (The total value sent can always be inferred by the sender from the spent
/// notes and received change.)
///
/// Regardless of the specified policy, `create_spend_to_address` saves `to`, `value`, and
/// `memo` in `db_data`. This can be deleted independently of `ovk_policy`.
///
/// For details on what transaction information is visible to the holder of a full or
/// outgoing viewing key, refer to [ZIP 310].
///
/// [ZIP 310]: https://zips.z.cash/zip-0310
///
/// Parameters:
/// * `wallet_db`: A read/write reference to the wallet database
/// * `params`: Consensus parameters
/// * `prover`: The TxProver to use in constructing the shielded transaction.
/// * `extsk`: The extended spending key that controls the funds that will be spent
///   in the resulting transaction.
/// * `account`: The ZIP32 account identifier associated with the extended spending
///   key that controls the funds to be used in creating this transaction.  This
///   procedure will return an error if this does not correctly correspond to `extsk`.
/// * `request`: The ZIP-321 payment request specifying the recipients and amounts
///   for the transaction.
/// * `ovk_policy`: The policy to use for constructing outgoing viewing keys that
///   can allow the sender to view the resulting notes on the blockchain.
/// * `min_confirmations`: The minimum number of confirmations that a previously
///   received note must have in the blockchain in order to be considered for being
///   spent. A value of 10 confirmations is recommended.
#[allow(clippy::too_many_arguments)]
pub fn spend<E, N, P, D, R>(
    wallet_db: &mut D,
    params: &P,
    prover: impl TxProver,
    extsk: &ExtendedSpendingKey,
    account: AccountId,
    request: &TransactionRequest,
    ovk_policy: OvkPolicy,
    min_confirmations: u32,
) -> Result<R, E>
where
    E: From<Error<N>>,
    P: consensus::Parameters + Clone,
    R: Copy + Debug,
    D: WalletWrite<Error = E, TxRef = R>,
{
    // Check that the ExtendedSpendingKey we have been given corresponds to the
    // ExtendedFullViewingKey for the account we are spending from.
    let extfvk = ExtendedFullViewingKey::from(extsk);
    if !wallet_db.is_valid_account_extfvk(account, &extfvk)? {
        return Err(E::from(Error::InvalidExtSk(account)));
    }

    // Apply the outgoing viewing key policy.
    let ovk = match ovk_policy {
        OvkPolicy::Sender => Some(extfvk.fvk.ovk),
        OvkPolicy::Custom(ovk) => Some(ovk),
        OvkPolicy::Discard => None,
    };

    // Target the next block, assuming we are up-to-date.
    let (height, anchor_height) = wallet_db
        .get_target_and_anchor_heights(min_confirmations)
        .and_then(|x| x.ok_or_else(|| Error::ScanRequired.into()))?;

    let value = request
        .payments()
        .iter()
        .map(|p| p.amount)
        .sum::<Option<Amount>>()
        .ok_or_else(|| E::from(Error::InvalidAmount))?;
    let target_value = (value + DEFAULT_FEE).ok_or_else(|| E::from(Error::InvalidAmount))?;
    let spendable_notes =
        wallet_db.select_spendable_sapling_notes(account, target_value, anchor_height)?;

    // Confirm we were able to select sufficient value
    let selected_value = spendable_notes
        .iter()
        .map(|n| n.note_value)
        .sum::<Option<_>>()
        .ok_or_else(|| E::from(Error::InvalidAmount))?;
    if selected_value < target_value {
        return Err(E::from(Error::InsufficientBalance(
            selected_value,
            target_value,
        )));
    }

    // Create the transaction
    let mut builder = Builder::new(params.clone(), height);
    for selected in spendable_notes {
        let from = extfvk
            .fvk
            .vk
            .to_payment_address(selected.diversifier)
            .unwrap(); //DiversifyHash would have to unexpectedly return the zero point for this to be None

        let note = from
            .create_note(selected.note_value.into(), selected.rseed)
            .unwrap();

        let merkle_path = selected.witness.path().expect("the tree is not empty");

        builder
            .add_sapling_spend(extsk.clone(), selected.diversifier, note, merkle_path)
            .map_err(Error::Builder)?;
    }

    for payment in request.payments() {
        match &payment.recipient_address {
            RecipientAddress::Unified(ua) => builder
                .add_sapling_output(
                    ovk,
                    ua.sapling()
                        .expect("TODO: Add Orchard support to builder")
                        .clone(),
                    payment.amount,
                    payment.memo.clone().unwrap_or_else(MemoBytes::empty),
                )
                .map_err(Error::Builder),
            RecipientAddress::Shielded(to) => builder
                .add_sapling_output(
                    ovk,
                    to.clone(),
                    payment.amount,
                    payment.memo.clone().unwrap_or_else(MemoBytes::empty),
                )
                .map_err(Error::Builder),
            RecipientAddress::Transparent(to) => {
                if payment.memo.is_some() {
                    Err(Error::MemoForbidden)
                } else {
                    builder
                        .add_transparent_output(to, payment.amount)
                        .map_err(Error::Builder)
                }
            }
        }?
    }

    let (tx, tx_metadata) = builder.build(&prover).map_err(Error::Builder)?;

    let sent_outputs = request.payments().iter().enumerate().map(|(i, payment)| {
        let idx = match &payment.recipient_address {
            // Sapling outputs are shuffled, so we need to look up where the output ended up.
            // TODO: When we add Orchard support, we will need to trial-decrypt to find them.
            RecipientAddress::Shielded(_) | RecipientAddress::Unified(_) =>
                tx_metadata.output_index(i).expect("An output should exist in the transaction for each shielded payment."),
            RecipientAddress::Transparent(addr) => {
                let script = addr.script();
                tx.transparent_bundle()
                    .and_then(|b| {
                        b.vout
                            .iter()
                            .enumerate()
                            .find(|(_, tx_out)| tx_out.script_pubkey == script)
                    })
                    .map(|(index, _)| index)
                    .expect("An output should exist in the transaction for each transparent payment.")
            }
        };

        SentTransactionOutput {
            output_index: idx,
            recipient_address: &payment.recipient_address,
            value: payment.amount,
            memo: payment.memo.clone()
        }
    }).collect();

    wallet_db.store_sent_tx(&SentTransaction {
        tx: &tx,
        created: time::OffsetDateTime::now_utc(),
        outputs: sent_outputs,
        account,
        #[cfg(feature = "transparent-inputs")]
        utxos_spent: vec![],
    })
}

/// Constructs a transaction that consumes available transparent UTXOs belonging to
/// the specified secret key, and sends them to the default address for the provided Sapling
/// extended full viewing key.
///
/// This procedure will not attempt to shield transparent funds if the total amount being shielded
/// is less than the default fee to send the transaction. Fees will be paid only from the transparent
/// UTXOs being consumed.
///
/// Parameters:
/// * `wallet_db`: A read/write reference to the wallet database
/// * `params`: Consensus parameters
/// * `prover`: The TxProver to use in constructing the shielded transaction.
/// * `sk`: The secp256k1 secret key that will be used to detect and spend transparent
///   UTXOs.
/// * `extfvk`: The extended full viewing key that will be used to produce the
///   Sapling address to which funds will be sent.
/// * `account`: The ZIP32 account identifier associated with the the extended
///   full viewing key. This procedure will return an error if this does not correctly
///   correspond to `extfvk`.
/// * `memo`: A memo to be included in the output to the (internal) recipient.
///   This can be used to take notes about auto-shielding operations internal
///   to the wallet that the wallet can use to improve how it represents those
///   shielding transactions to the user.
/// * `min_confirmations`: The minimum number of confirmations that a previously
///   received UTXO must have in the blockchain in order to be considered for being
///   spent.
#[cfg(feature = "transparent-inputs")]
#[allow(clippy::too_many_arguments)]
pub fn shield_transparent_funds<E, N, P, D, R, U>(
    wallet_db: &mut D,
    params: &P,
    prover: impl TxProver,
    sk: &transparent::AccountPrivKey,
    extfvk: &ExtendedFullViewingKey,
    account: AccountId,
    memo: &MemoBytes,
    min_confirmations: u32,
) -> Result<D::TxRef, E>
where
    E: From<Error<N>>,
    P: consensus::Parameters,
    R: Copy + Debug,
    D: WalletWrite<Error = E, TxRef = R> + WalletWriteTransparent<UtxoRef = U>,
{
    // Check that the ExtendedSpendingKey we have been given corresponds to the
    // ExtendedFullViewingKey for the account we are spending from.
    if !wallet_db.is_valid_account_extfvk(account, extfvk)? {
        return Err(E::from(Error::InvalidExtSk(account)));
    }

    let (latest_scanned_height, latest_anchor) = wallet_db
        .get_target_and_anchor_heights(min_confirmations)
        .and_then(|x| x.ok_or_else(|| Error::ScanRequired.into()))?;

    let account_pubkey = sk.to_account_pubkey();
    let ovk = OutgoingViewingKey(account_pubkey.internal_ovk().as_bytes());

    // derive own shielded address from the provided extended full viewing key
    // TODO: this should become the internal change address derived from
    // the wallet's UFVK
    let z_address = extfvk.default_address().1;

    // derive the t-address for the extpubkey at the minimum valid child index
    let (taddr, child_index) = account_pubkey
        .derive_external_ivk()
        .unwrap()
        .default_address();

    // get UTXOs from DB
    let utxos = wallet_db.get_unspent_transparent_outputs(&taddr, latest_anchor)?;
    let total_amount = utxos
        .iter()
        .map(|utxo| utxo.txout.value)
        .sum::<Option<Amount>>()
        .ok_or_else(|| E::from(Error::InvalidAmount))?;

    let fee = DEFAULT_FEE;
    if fee >= total_amount {
        return Err(E::from(Error::InsufficientBalance(total_amount, fee)));
    }

    let amount_to_shield = (total_amount - fee).ok_or_else(|| E::from(Error::InvalidAmount))?;

    let mut builder = Builder::new(params.clone(), latest_scanned_height);

    let secret_key = sk.derive_external_secret_key(child_index).unwrap();
    for utxo in &utxos {
        builder
            .add_transparent_input(secret_key, utxo.outpoint.clone(), utxo.txout.clone())
            .map_err(Error::Builder)?;
    }

    // there are no sapling notes so we set the change manually
    builder.send_change_to(ovk, z_address.clone());

    // add the sapling output to shield the funds
    builder
        .add_sapling_output(Some(ovk), z_address.clone(), amount_to_shield, memo.clone())
        .map_err(Error::Builder)?;

    let (tx, tx_metadata) = builder.build(&prover).map_err(Error::Builder)?;
    let output_index = tx_metadata.output_index(0).expect(
        "No sapling note was created in autoshielding transaction. This is a programming error.",
    );

    wallet_db.store_sent_tx(&SentTransaction {
        tx: &tx,
        created: time::OffsetDateTime::now_utc(),
        account,
        outputs: vec![SentTransactionOutput {
            output_index,
            recipient_address: &RecipientAddress::Shielded(z_address),
            value: amount_to_shield,
            memo: Some(memo.clone()),
        }],
        utxos_spent: utxos.iter().map(|utxo| utxo.outpoint.clone()).collect(),
    })
}
