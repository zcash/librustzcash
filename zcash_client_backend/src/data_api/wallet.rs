use std::fmt::Debug;

use zcash_primitives::{
    consensus::{self, NetworkUpgrade},
    memo::MemoBytes,
    merkle_tree::MerklePath,
    sapling::{self, prover::TxProver as SaplingProver},
    transaction::{
        builder::Builder,
        components::amount::{Amount, BalanceError, DEFAULT_FEE},
        fees::{FeeRule, FixedFeeRule},
        Transaction,
    },
    zip32::{sapling::DiversifiableFullViewingKey, sapling::ExtendedSpendingKey, Scope},
};

use crate::{
    address::RecipientAddress,
    data_api::{
        error::Error, DecryptedTransaction, PoolType, Recipient, SentTransaction,
        SentTransactionOutput, WalletWrite,
    },
    decrypt_transaction,
    fees::{ChangeValue, SingleOutputFixedFeeChangeStrategy},
    keys::UnifiedSpendingKey,
    wallet::{OvkPolicy, SpendableNote},
    zip321::{self, Payment},
};

pub mod input_selection;
use input_selection::{GreedyInputSelector, GreedyInputSelectorError, InputSelector};

#[cfg(feature = "transparent-inputs")]
use zcash_primitives::{
    legacy::TransparentAddress, sapling::keys::OutgoingViewingKey,
    transaction::components::amount::NonNegativeAmount,
};

/// Scans a [`Transaction`] for any information that can be decrypted by the accounts in
/// the wallet, and saves it to the wallet.
pub fn decrypt_and_store_transaction<ParamsT, DbT>(
    params: &ParamsT,
    data: &mut DbT,
    tx: &Transaction,
) -> Result<(), DbT::Error>
where
    ParamsT: consensus::Parameters,
    DbT: WalletWrite,
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
        .expect("Sapling activation height must be known.");

    data.store_decrypted_tx(&DecryptedTransaction {
        tx,
        sapling_outputs: &decrypt_transaction(params, height, tx, &ufvks),
    })?;

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
/// * `prover`: The [`sapling::TxProver`] to use in constructing the shielded transaction.
/// * `usk`: The unified spending key that controls the funds that will be spent
///   in the resulting transaction. This procedure will return an error if the
///   USK does not correspond to an account known to the wallet.
/// * `to`: The address to which `amount` will be paid.
/// * `amount`: The amount to send.
/// * `memo`: A memo to be included in the output to the recipient.
/// * `ovk_policy`: The policy to use for constructing outgoing viewing keys that
///   can allow the sender to view the resulting notes on the blockchain.
/// * `min_confirmations`: The minimum number of confirmations that a previously
///   received note must have in the blockchain in order to be considered for being
///   spent. A value of 10 confirmations is recommended.
///
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
///     keys::UnifiedSpendingKey,
///     data_api::{wallet::create_spend_to_address, error::Error, testing},
///     wallet::OvkPolicy,
/// };
///
/// # use std::convert::Infallible;
/// # use zcash_primitives::transaction::components::amount::BalanceError;
/// # use zcash_client_backend::{
/// #     data_api::wallet::input_selection::GreedyInputSelectorError,
/// # };
/// #
/// # fn main() {
/// #   test();
/// # }
/// #
/// # #[allow(deprecated)]
/// # fn test() -> Result<TxId, Error<(), GreedyInputSelectorError<BalanceError, u32>, Infallible, u32>> {
///
/// let tx_prover = match LocalTxProver::with_default_location() {
///     Some(tx_prover) => tx_prover,
///     None => {
///         panic!("Cannot locate the Zcash parameters. Please run zcash-fetch-params or fetch-params.sh to download the parameters, and then re-run the tests.");
///     }
/// };
///
/// let account = AccountId::from(0);
/// let usk = UnifiedSpendingKey::from_seed(&Network::TestNetwork, &[0; 32][..], account).unwrap();
/// let to = usk.to_unified_full_viewing_key().default_address().0.into();
///
/// let mut db_read = testing::MockWalletDb {
///     network: Network::TestNetwork
/// };
///
/// create_spend_to_address(
///     &mut db_read,
///     &Network::TestNetwork,
///     tx_prover,
///     &usk,
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
/// [`sapling::TxProver`]: zcash_primitives::sapling::prover::TxProver
#[allow(clippy::too_many_arguments)]
#[allow(clippy::type_complexity)]
#[deprecated(note = "Use `spend` instead.")]
pub fn create_spend_to_address<DbT, ParamsT>(
    wallet_db: &mut DbT,
    params: &ParamsT,
    prover: impl SaplingProver,
    usk: &UnifiedSpendingKey,
    to: &RecipientAddress,
    amount: Amount,
    memo: Option<MemoBytes>,
    ovk_policy: OvkPolicy,
    min_confirmations: u32,
) -> Result<
    DbT::TxRef,
    Error<
        DbT::Error,
        GreedyInputSelectorError<BalanceError>,
        core::convert::Infallible,
        DbT::NoteRef,
    >,
>
where
    ParamsT: consensus::Parameters + Clone,
    DbT: WalletWrite,
    DbT::NoteRef: Copy + Eq + Ord,
{
    let req = zip321::TransactionRequest::new(vec![Payment {
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

    let change_strategy = SingleOutputFixedFeeChangeStrategy::new(FixedFeeRule::new(DEFAULT_FEE));
    spend(
        wallet_db,
        params,
        prover,
        &GreedyInputSelector::<DbT, _>::new(change_strategy),
        usk,
        req,
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
/// * `prover`: The [`sapling::TxProver`] to use in constructing the shielded transaction.
/// * `input_selector`: The [`InputSelector`] that will be used to select available
///   inputs from the wallet database, choose change amounts and compute required
///   transaction fees.
/// * `usk`: The unified spending key that controls the funds that will be spent
///   in the resulting transaction. This procedure will return an error if the
///   USK does not correspond to an account known to the wallet.
/// * `request`: The ZIP-321 payment request specifying the recipients and amounts
///   for the transaction.
/// * `ovk_policy`: The policy to use for constructing outgoing viewing keys that
///   can allow the sender to view the resulting notes on the blockchain.
/// * `min_confirmations`: The minimum number of confirmations that a previously
///   received note must have in the blockchain in order to be considered for being
///   spent. A value of 10 confirmations is recommended.
///
/// [`sapling::TxProver`]: zcash_primitives::sapling::prover::TxProver
#[allow(clippy::too_many_arguments)]
#[allow(clippy::type_complexity)]
pub fn spend<DbT, ParamsT, InputsT>(
    wallet_db: &mut DbT,
    params: &ParamsT,
    prover: impl SaplingProver,
    input_selector: &InputsT,
    usk: &UnifiedSpendingKey,
    request: zip321::TransactionRequest,
    ovk_policy: OvkPolicy,
    min_confirmations: u32,
) -> Result<
    DbT::TxRef,
    Error<DbT::Error, InputsT::Error, <InputsT::FeeRule as FeeRule>::Error, DbT::NoteRef>,
>
where
    DbT: WalletWrite,
    DbT::TxRef: Copy + Debug,
    DbT::NoteRef: Copy + Eq + Ord,
    ParamsT: consensus::Parameters + Clone,
    InputsT: InputSelector<DataSource = DbT>,
{
    let account = wallet_db
        .get_account_for_ufvk(&usk.to_unified_full_viewing_key())
        .map_err(Error::DataSource)?
        .ok_or(Error::KeyNotRecognized)?;

    let dfvk = usk.sapling().to_diversifiable_full_viewing_key();

    // Apply the outgoing viewing key policy.
    let ovk = match ovk_policy {
        OvkPolicy::Sender => Some(dfvk.fvk().ovk),
        OvkPolicy::Custom(ovk) => Some(ovk),
        OvkPolicy::Discard => None,
    };

    // Target the next block, assuming we are up-to-date.
    let (target_height, anchor_height) = wallet_db
        .get_target_and_anchor_heights(min_confirmations)
        .map_err(Error::DataSource)
        .and_then(|x| x.ok_or(Error::ScanRequired))?;

    let proposal = input_selector.propose_transaction(
        params,
        wallet_db,
        account,
        anchor_height,
        target_height,
        request,
    )?;

    // Create the transaction. The type of the proposal ensures that there
    // are no possible transparent inputs, so we ignore those
    let mut builder = Builder::new(params.clone(), target_height);
    for selected in proposal.sapling_inputs() {
        let (note, key, merkle_path) = select_key_for_note(selected, usk.sapling(), &dfvk)
            .ok_or(Error::NoteMismatch(selected.note_id))?;

        builder.add_sapling_spend(key, selected.diversifier, note, merkle_path)?;
    }

    for payment in proposal.transaction_request().payments() {
        match &payment.recipient_address {
            RecipientAddress::Unified(ua) => {
                builder.add_sapling_output(
                    ovk,
                    ua.sapling()
                        .expect("TODO: Add Orchard support to builder")
                        .clone(),
                    payment.amount,
                    payment.memo.clone().unwrap_or_else(MemoBytes::empty),
                )?;
            }
            RecipientAddress::Shielded(to) => {
                builder.add_sapling_output(
                    ovk,
                    to.clone(),
                    payment.amount,
                    payment.memo.clone().unwrap_or_else(MemoBytes::empty),
                )?;
            }
            RecipientAddress::Transparent(to) => {
                if payment.memo.is_some() {
                    return Err(Error::MemoForbidden);
                } else {
                    builder.add_transparent_output(to, payment.amount)?;
                }
            }
        }
    }

    for change_value in proposal.balance().proposed_change() {
        match change_value {
            ChangeValue::Sapling(amount) => {
                builder.add_sapling_output(
                    Some(dfvk.to_ovk(Scope::Internal)),
                    dfvk.change_address().1,
                    *amount,
                    MemoBytes::empty(),
                )?;
            }
        }
    }

    let (tx, tx_metadata) = builder.build(&prover, proposal.fee_rule())?;

    let sent_outputs = proposal.transaction_request().payments().iter().enumerate().map(|(i, payment)| {
        let (output_index, recipient) = match &payment.recipient_address {
            // Sapling outputs are shuffled, so we need to look up where the output ended up.
            RecipientAddress::Shielded(addr) => {
                let idx = tx_metadata.output_index(i).expect("An output should exist in the transaction for each shielded payment.");
                (idx, Recipient::Sapling(addr.clone()))
            }
            RecipientAddress::Unified(addr) => {
                // TODO: When we add Orchard support, we will need to trial-decrypt to find them,
                // and return the appropriate pool type.
                let idx = tx_metadata.output_index(i).expect("An output should exist in the transaction for each shielded payment.");
                (idx, Recipient::Unified(addr.clone(), PoolType::Sapling))
            }
            RecipientAddress::Transparent(addr) => {
                let script = addr.script();
                let idx = tx.transparent_bundle()
                    .and_then(|b| {
                        b.vout
                            .iter()
                            .enumerate()
                            .find(|(_, tx_out)| tx_out.script_pubkey == script)
                    })
                    .map(|(index, _)| index)
                    .expect("An output should exist in the transaction for each transparent payment.");

                (idx, Recipient::Transparent(*addr))
            }
        };

        SentTransactionOutput {
            output_index,
            recipient,
            value: payment.amount,
            memo: payment.memo.clone()
        }
    }).collect();

    wallet_db
        .store_sent_tx(&SentTransaction {
            tx: &tx,
            created: time::OffsetDateTime::now_utc(),
            account,
            outputs: sent_outputs,
            fee_amount: proposal.balance().fee_required(),
            #[cfg(feature = "transparent-inputs")]
            utxos_spent: vec![],
        })
        .map_err(Error::DataSource)
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
/// * `prover`: The [`sapling::TxProver`] to use in constructing the shielded transaction.
/// * `input_selector`: The [`InputSelector`] to for note selection and change and fee
///   determination
/// * `usk`: The unified spending key that will be used to detect and spend transparent UTXOs,
///   and that will provide the shielded address to which funds will be sent. Funds will be
///   shielded to the internal (change) address associated with the most preferred shielded
///   receiver corresponding to this account, or if no shielded receiver can be used for this
///   account, this function will return an error. This procedure will return an error if the
///   USK does not correspond to an account known to the wallet.
/// * `from_addrs`: The list of transparent addresses that will be used to filter transaparent
///   UTXOs received by the wallet. Only UTXOs received at one of the provided addresses will
///   be selected to be shielded.
/// * `memo`: A memo to be included in the output to the (internal) recipient.
///   This can be used to take notes about auto-shielding operations internal
///   to the wallet that the wallet can use to improve how it represents those
///   shielding transactions to the user.
/// * `min_confirmations`: The minimum number of confirmations that a previously
///   received UTXO must have in the blockchain in order to be considered for being
///   spent.
///
/// [`sapling::TxProver`]: zcash_primitives::sapling::prover::TxProver
#[cfg(feature = "transparent-inputs")]
#[allow(clippy::too_many_arguments)]
#[allow(clippy::type_complexity)]
pub fn shield_transparent_funds<DbT, ParamsT, InputsT>(
    wallet_db: &mut DbT,
    params: &ParamsT,
    prover: impl SaplingProver,
    input_selector: &InputsT,
    usk: &UnifiedSpendingKey,
    from_addrs: &[TransparentAddress],
    memo: &MemoBytes,
    min_confirmations: u32,
) -> Result<
    DbT::TxRef,
    Error<DbT::Error, InputsT::Error, <InputsT::FeeRule as FeeRule>::Error, DbT::NoteRef>,
>
where
    ParamsT: consensus::Parameters,
    DbT: WalletWrite,
    DbT::NoteRef: Copy + Eq + Ord,
    InputsT: InputSelector<DataSource = DbT>,
{
    let account = wallet_db
        .get_account_for_ufvk(&usk.to_unified_full_viewing_key())
        .map_err(Error::DataSource)?
        .ok_or(Error::KeyNotRecognized)?;

    let shielding_address = usk
        .sapling()
        .to_diversifiable_full_viewing_key()
        .change_address()
        .1;
    let (target_height, latest_anchor) = wallet_db
        .get_target_and_anchor_heights(min_confirmations)
        .map_err(Error::DataSource)
        .and_then(|x| x.ok_or(Error::ScanRequired))?;

    let dfvk = usk.sapling().to_diversifiable_full_viewing_key();
    let account_pubkey = usk.transparent().to_account_pubkey();
    let ovk = OutgoingViewingKey(account_pubkey.internal_ovk().as_bytes());

    // get UTXOs from DB for each address
    let proposal = input_selector.propose_shielding(
        params,
        wallet_db,
        NonNegativeAmount::from_u64(100000).unwrap(),
        from_addrs,
        latest_anchor,
        target_height,
    )?;

    let known_addrs = wallet_db
        .get_transparent_receivers(account)
        .map_err(Error::DataSource)?;
    let mut builder = Builder::new(params.clone(), target_height);

    let mut utxos = vec![];
    for selected in proposal.sapling_inputs() {
        let (note, key, merkle_path) = select_key_for_note(selected, usk.sapling(), &dfvk)
            .ok_or(Error::NoteMismatch(selected.note_id))?;

        builder.add_sapling_spend(key, selected.diversifier, note, merkle_path)?;
    }

    for utxo in proposal.transparent_inputs() {
        utxos.push(utxo);
        let diversifier_index = known_addrs
            .get(utxo.recipient_address())
            .ok_or_else(|| Error::AddressNotRecognized(*utxo.recipient_address()))?
            .diversifier_index();

        let child_index = u32::try_from(*diversifier_index)
            .map_err(|_| Error::ChildIndexOutOfRange(*diversifier_index))?;

        let secret_key = usk
            .transparent()
            .derive_external_secret_key(child_index)
            .unwrap();

        builder.add_transparent_input(secret_key, utxo.outpoint().clone(), utxo.txout().clone())?;
    }

    for change_value in proposal.balance().proposed_change() {
        match change_value {
            ChangeValue::Sapling(amount) => {
                builder.add_sapling_output(
                    Some(ovk),
                    shielding_address.clone(),
                    *amount,
                    memo.clone(),
                )?;
            }
        }
    }

    // The transaction build process will check that the inputs and outputs balance
    let (tx, tx_metadata) = builder.build(&prover, proposal.fee_rule())?;

    wallet_db
        .store_sent_tx(&SentTransaction {
            tx: &tx,
            created: time::OffsetDateTime::now_utc(),
            account,
            // TODO: After Orchard is implemented, this will need to change to correctly
            // determine the Sapling output indices; `enumerate` will no longer suffice
            outputs: proposal
                .balance()
                .proposed_change()
                .iter()
                .enumerate()
                .map(|(idx, change_value)| match change_value {
                    ChangeValue::Sapling(value) => {
                        let output_index = tx_metadata.output_index(idx).expect(
                            "Missing Sapling output of autoshielding transaction. This is a programming error.",
                        );
                        SentTransactionOutput {
                            output_index,
                            recipient: Recipient::InternalAccount(account, PoolType::Sapling),
                            value: *value,
                            memo: Some(memo.clone()),
                        }
                    }
                })
                .collect(),
            fee_amount: proposal.balance().fee_required(),
            utxos_spent: utxos.iter().map(|utxo| utxo.outpoint().clone()).collect(),
        })
        .map_err(Error::DataSource)
}

fn select_key_for_note<N>(
    selected: &SpendableNote<N>,
    extsk: &ExtendedSpendingKey,
    dfvk: &DiversifiableFullViewingKey,
) -> Option<(
    sapling::Note,
    ExtendedSpendingKey,
    MerklePath<sapling::Node>,
)> {
    let merkle_path = selected.witness.path().expect("the tree is not empty");

    // Attempt to reconstruct the note being spent using both the internal and external dfvks
    // corresponding to the unified spending key, checking against the witness we are using
    // to spend the note that we've used the correct key.
    let external_note = dfvk
        .diversified_address(selected.diversifier)
        .and_then(|addr| addr.create_note(selected.note_value.into(), selected.rseed));
    let internal_note = dfvk
        .diversified_change_address(selected.diversifier)
        .and_then(|addr| addr.create_note(selected.note_value.into(), selected.rseed));

    let expected_root = selected.witness.root();
    external_note
        .filter(|n| expected_root == merkle_path.root(n.commitment()))
        .map(|n| (n, extsk.clone(), merkle_path.clone()))
        .or_else(|| {
            internal_note
                .filter(|n| expected_root == merkle_path.root(n.commitment()))
                .map(|n| (n, extsk.derive_internal(), merkle_path))
        })
}
