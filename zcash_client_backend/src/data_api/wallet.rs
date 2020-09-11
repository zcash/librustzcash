//! Functions for scanning the chain and extracting relevant information.
use std::fmt::Debug;

use zcash_primitives::{
    consensus::{self, BranchId, NetworkUpgrade},
    note_encryption::Memo,
    prover::TxProver,
    transaction::{
        builder::Builder,
        components::{amount::DEFAULT_FEE, Amount},
        Transaction,
    },
    zip32::{ExtendedFullViewingKey, ExtendedSpendingKey},
};

use crate::{
    address::RecipientAddress,
    data_api::{error::Error, DBOps, DBUpdate},
    decrypt_transaction,
    wallet::{AccountId, OvkPolicy},
};

pub const ANCHOR_OFFSET: u32 = 10;

/// Scans a [`Transaction`] for any information that can be decrypted by the accounts in
/// the wallet, and saves it to the wallet.
pub fn decrypt_and_store_transaction<'db, E0, N, E, P, D>(
    params: &P,
    data: &'db D,
    tx: &Transaction,
) -> Result<(), E>
where
    E: From<Error<E0, N>>,
    P: consensus::Parameters,
    &'db D: DBOps<Error = E>,
{
    // Fetch the ExtendedFullViewingKeys we are tracking
    let extfvks = data.get_extended_full_viewing_keys(params)?;

    // Height is block height for mined transactions, and the "mempool height" (chain height + 1)
    // for mempool transactions.
    let height = data
        .get_tx_height(tx.txid())?
        .or(data
            .block_height_extrema()?
            .map(|(_, max_height)| max_height + 1))
        .or(params.activation_height(NetworkUpgrade::Sapling))
        .ok_or(Error::SaplingNotActive.into())?;

    let outputs = decrypt_transaction(params, height, tx, &extfvks);
    if outputs.is_empty() {
        Ok(())
    } else {
        let mut db_update = data.get_update_ops()?;

        // Update the database atomically, to ensure the result is internally consistent.
        db_update.transactionally(|up| {
            let tx_ref = up.put_tx_data(tx, None)?;

            for output in outputs {
                if output.outgoing {
                    up.put_sent_note(params, &output, tx_ref)?;
                } else {
                    up.put_received_note(&output, None, tx_ref)?;
                }
            }

            Ok(())
        })
    }
}

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
///     api::AccountId,
///     keys::spending_key,
///     data_api::wallet::create_spend_to_address,
///     wallet::OvkPolicy,
/// };
/// use zcash_client_sqlite::{
///     DataConnection,
/// };
///
/// let tx_prover = match LocalTxProver::with_default_location() {
///     Some(tx_prover) => tx_prover,
///     None => {
///         panic!("Cannot locate the Zcash parameters. Please run zcash-fetch-params or fetch-params.sh to download the parameters, and then re-run the tests.");
///     }
/// };
///
/// let account = AccountId(0);
/// let extsk = spending_key(&[0; 32][..], COIN_TYPE, account.0);
/// let to = extsk.default_address().unwrap().1.into();
///
/// let data_file = NamedTempFile::new().unwrap();
/// let db = DataConnection::for_path(data_file).unwrap();
/// match create_spend_to_address(
///     &db,
///     &Network::TestNetwork,
///     tx_prover,
///     account,
///     &extsk,
///     &to,
///     Amount::from_u64(1).unwrap(),
///     None,
///     OvkPolicy::Sender,
/// ) {
///     Ok(tx_row) => (),
///     Err(e) => (),
/// }
/// ```
pub fn create_spend_to_address<'db, E0, N, E, P, D, R>(
    data: &'db D,
    params: &P,
    prover: impl TxProver,
    account: AccountId,
    extsk: &ExtendedSpendingKey,
    to: &RecipientAddress,
    value: Amount,
    memo: Option<Memo>,
    ovk_policy: OvkPolicy,
) -> Result<R, Error<E, N>>
where
    E0: Into<Error<E, N>>,
    P: consensus::Parameters + Clone,
    R: Copy + Debug,
    &'db D: DBOps<Error = E0, TxRef = R>,
{
    // Check that the ExtendedSpendingKey we have been given corresponds to the
    // ExtendedFullViewingKey for the account we are spending from.
    let extfvk = ExtendedFullViewingKey::from(extsk);
    if !data
        .is_valid_account_extfvk(params, account, &extfvk)
        .map_err(|e| e.into())?
    {
        return Err(Error::InvalidExtSK(account));
    }

    // Apply the outgoing viewing key policy.
    let ovk = match ovk_policy {
        OvkPolicy::Sender => Some(extfvk.fvk.ovk),
        OvkPolicy::Custom(ovk) => Some(ovk),
        OvkPolicy::Discard => None,
    };

    // Target the next block, assuming we are up-to-date.
    let (height, anchor_height) = data
        .get_target_and_anchor_heights()
        .map_err(|e| e.into())
        .and_then(|x| x.ok_or(Error::ScanRequired))?;

    let target_value = value + DEFAULT_FEE;
    let spendable_notes = data
        .select_spendable_notes(account, target_value, anchor_height)
        .map_err(|e| e.into())?;

    // Confirm we were able to select sufficient value
    let selected_value = spendable_notes.iter().map(|n| n.note_value).sum();
    if selected_value < target_value {
        return Err(Error::InsufficientBalance(selected_value, target_value));
    }

    // Create the transaction
    let mut builder = Builder::new(params.clone(), height);
    for selected in spendable_notes {
        let from = extfvk
            .fvk
            .vk
            .to_payment_address(selected.diversifier)
            .unwrap(); //JUBJUB would have to unexpectedly be the zero point for this to be None

        let note = from
            .create_note(u64::from(selected.note_value), selected.rseed)
            .unwrap();

        let merkle_path = selected.witness.path().expect("the tree is not empty");

        builder
            .add_sapling_spend(extsk.clone(), selected.diversifier, note, merkle_path)
            .map_err(Error::Builder)?;
    }

    match to {
        RecipientAddress::Shielded(to) => {
            builder.add_sapling_output(ovk, to.clone(), value, memo.clone())
        }

        RecipientAddress::Transparent(to) => builder.add_transparent_output(&to, value),
    }?;

    let consensus_branch_id = BranchId::for_height(params, height);
    let (tx, tx_metadata) = builder
        .build(consensus_branch_id, &prover)
        .map_err(Error::Builder)?;

    // We only called add_sapling_output() once.
    let output_index = match tx_metadata.output_index(0) {
        Some(idx) => idx as i64,
        None => panic!("Output 0 should exist in the transaction"),
    };

    // Update the database atomically, to ensure the result is internally consistent.
    let mut db_update = data.get_update_ops().map_err(|e| e.into())?;
    db_update
        .transactionally(|up| {
            let created = time::OffsetDateTime::now_utc();
            let tx_ref = up.put_tx_data(&tx, Some(created))?;

            // Mark notes as spent.
            //
            // This locks the notes so they aren't selected again by a subsequent call to
            // create_spend_to_address() before this transaction has been mined (at which point the notes
            // get re-marked as spent).
            //
            // Assumes that create_spend_to_address() will never be called in parallel, which is a
            // reasonable assumption for a light client such as a mobile phone.
            for spend in &tx.shielded_spends {
                up.mark_spent(tx_ref, &spend.nullifier)?;
            }

            up.insert_sent_note(
                params,
                tx_ref,
                output_index as usize,
                account,
                to,
                value,
                memo,
            )?;

            // Return the row number of the transaction, so the caller can fetch it for sending.
            Ok(tx_ref)
        })
        .map_err(|e| e.into())
}
