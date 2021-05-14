use std::fmt::Debug;
use zcash_primitives::{
    consensus::{self, BranchId, NetworkUpgrade},
    memo::MemoBytes,
    sapling::prover::TxProver,
    transaction::{
        builder::Builder,
        components::{amount::DEFAULT_FEE, Amount},
        Transaction,
    },
    zip32::{ExtendedFullViewingKey, ExtendedSpendingKey},
};

use crate::{
    address::RecipientAddress,
    data_api::{
        error::Error, DecryptedTransaction, SentTransaction, SentTransactionOutput, WalletWrite,
    },
    decrypt_transaction,
    wallet::{AccountId, OvkPolicy},
    zip321::{Payment, TransactionRequest},
};

#[cfg(feature = "transparent-inputs")]
use zcash_primitives::{legacy::Script, transaction::components::TxOut};

#[cfg(feature = "transparent-inputs")]
use crate::keys::derive_transparent_address_from_secret_key;

pub const ANCHOR_OFFSET: u32 = 10;

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
    debug!("decrypt_and_store: {:?}", tx);

    // Fetch the ExtendedFullViewingKeys we are tracking
    let extfvks = data.get_extended_full_viewing_keys()?;

    // Height is block height for mined transactions, and the "mempool height" (chain height + 1)
    // for mempool transactions.
    let height = data
        .get_tx_height(tx.txid())?
        .or(data
            .block_height_extrema()?
            .map(|(_, max_height)| max_height + 1))
        .or_else(|| params.activation_height(NetworkUpgrade::Sapling))
        .ok_or(Error::SaplingNotActive)?;

    let sapling_outputs = decrypt_transaction(params, height, tx, &extfvks);

    if !(sapling_outputs.is_empty() && tx.vout.is_empty()) {
        let nullifiers = data.get_all_nullifiers()?;
        data.store_decrypted_tx(
            &DecryptedTransaction {
                tx,
                sapling_outputs: &sapling_outputs,
            },
            &nullifiers,
        )?;
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
/// # Examples
///
/// ```
/// use tempfile::NamedTempFile;
/// use zcash_primitives::{
///     consensus::{self, Network},
///     constants::testnet::COIN_TYPE,
///     transaction::components::Amount
/// };
/// use zcash_proofs::prover::LocalTxProver;
/// use zcash_client_backend::{
///     keys::spending_key,
///     data_api::wallet::create_spend_to_address,
///     wallet::{AccountId, OvkPolicy},
/// };
/// use zcash_client_sqlite::{
///     WalletDb,
///     error::SqliteClientError,
///     wallet::init::init_wallet_db,
/// };
///
/// # // doctests have a problem with sqlite IO, so we ignore errors
/// # // generated in this example code as it's not really testing anything
/// # fn main() {
/// #   test();
/// # }
/// #
/// # fn test() -> Result<(), SqliteClientError> {
/// let tx_prover = match LocalTxProver::with_default_location() {
///     Some(tx_prover) => tx_prover,
///     None => {
///         panic!("Cannot locate the Zcash parameters. Please run zcash-fetch-params or fetch-params.sh to download the parameters, and then re-run the tests.");
///     }
/// };
///
/// let account = AccountId(0);
/// let extsk = spending_key(&[0; 32][..], COIN_TYPE, account);
/// let to = extsk.default_address().unwrap().1.into();
///
/// let data_file = NamedTempFile::new().unwrap();
/// let db_read = WalletDb::for_path(data_file, Network::TestNetwork).unwrap();
/// init_wallet_db(&db_read)?;
/// let mut db = db_read.get_update_ops()?;
///
/// create_spend_to_address(
///     &mut db,
///     &Network::TestNetwork,
///     tx_prover,
///     account,
///     &extsk,
///     &to,
///     Amount::from_u64(1).unwrap(),
///     None,
///     OvkPolicy::Sender,
/// )?;
///
/// # Ok(())
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
) -> Result<R, E>
where
    E: From<Error<N>>,
    P: consensus::Parameters + Clone,
    R: Copy + Debug,
    D: WalletWrite<Error = E, TxRef = R>,
{
    let req = TransactionRequest {
        payments: vec![Payment {
            recipient_address: to.clone(),
            amount,
            memo,
            label: None,
            message: None,
            other_params: vec![],
        }],
    };

    spend(wallet_db, params, prover, account, extsk, &req, ovk_policy)
}

pub fn spend<E, N, P, D, R>(
    wallet_db: &mut D,
    params: &P,
    prover: impl TxProver,
    account: AccountId,
    extsk: &ExtendedSpendingKey,
    request: &TransactionRequest,
    ovk_policy: OvkPolicy,
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
        .get_target_and_anchor_heights()
        .and_then(|x| x.ok_or_else(|| Error::ScanRequired.into()))?;

    let target_value = request.payments.iter().map(|p| p.amount).sum::<Amount>() + DEFAULT_FEE;
    let spendable_notes =
        wallet_db.select_unspent_sapling_notes(account, target_value, anchor_height)?;

    // Confirm we were able to select sufficient value
    let selected_value = spendable_notes.iter().map(|n| n.note_value).sum();
    if selected_value < target_value {
        return Err(E::from(Error::InsufficientBalance(
            selected_value,
            target_value,
        )));
    }

    // Create the transaction
    let consensus_branch_id = BranchId::for_height(params, height);
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

    for payment in &request.payments {
        match &payment.recipient_address {
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
                        .add_transparent_output(&to, payment.amount)
                        .map_err(Error::Builder)
                }
            }
        }?
    }

    let (tx, tx_metadata) = builder
        .build(consensus_branch_id, &prover)
        .map_err(Error::Builder)?;

    let sent_outputs = request.payments.iter().enumerate().map(|(i, payment)| {
        let idx = match &payment.recipient_address {
            // Sapling outputs are shuffled, so we need to look up where the output ended up.
            RecipientAddress::Shielded(_) =>
                tx_metadata.output_index(i).expect("An output should exist in the transaction for each shielded payment."),
            RecipientAddress::Transparent(addr) => {
                let script = addr.script();
                tx.vout
                    .iter()
                    .enumerate()
                    .find(|(_, tx_out)| tx_out.script_pubkey == script)
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
        utxos_spent: vec![],
    })
}

#[cfg(feature = "transparent-inputs")]
#[allow(clippy::too_many_arguments)]
pub fn shield_funds<E, N, P, D, R>(
    wallet_db: &mut D,
    params: &P,
    prover: impl TxProver,
    account: AccountId,
    sk: &secp256k1::SecretKey,
    extsk: &ExtendedSpendingKey,
    memo: &MemoBytes,
    confirmations: u32,
) -> Result<D::TxRef, E>
where
    E: From<Error<N>>,
    P: consensus::Parameters,
    R: Copy + Debug,
    D: WalletWrite<Error = E, TxRef = R>,
{
    let (latest_scanned_height, latest_anchor) = wallet_db
        .get_target_and_anchor_heights()
        .and_then(|x| x.ok_or_else(|| Error::ScanRequired.into()))?;

    // derive the corresponding t-address
    let taddr = derive_transparent_address_from_secret_key(sk);

    // derive own shielded address from the provided extended spending key
    let z_address = extsk.default_address().unwrap().1;

    let exfvk = ExtendedFullViewingKey::from(extsk);

    let ovk = exfvk.fvk.ovk;

    // get UTXOs from DB
    let utxos = wallet_db.get_unspent_transparent_utxos(&taddr, latest_anchor - confirmations)?;
    let total_amount = utxos.iter().map(|utxo| utxo.value).sum::<Amount>();

    let fee = DEFAULT_FEE;
    if fee >= total_amount {
        return Err(E::from(Error::InsufficientBalance(total_amount, fee)));
    }

    let amount_to_shield = total_amount - fee;

    let mut builder = Builder::new(params.clone(), latest_scanned_height);

    #[cfg(feature = "transparent-inputs")]
    for utxo in &utxos {
        let coin = TxOut {
            value: utxo.value,
            script_pubkey: Script {
                0: utxo.script.clone(),
            },
        };

        builder
            .add_transparent_input(*sk, utxo.outpoint.clone(), coin)
            .map_err(Error::Builder)?;
    }

    // there are no sapling notes so we set the change manually
    builder.send_change_to(ovk, z_address.clone());

    // add the sapling output to shield the funds
    builder
        .add_sapling_output(Some(ovk), z_address.clone(), amount_to_shield, memo.clone())
        .map_err(Error::Builder)?;

    let consensus_branch_id = BranchId::for_height(params, latest_anchor);

    let (tx, tx_metadata) = builder
        .build(consensus_branch_id, &prover)
        .map_err(Error::Builder)?;
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
