use std::num::NonZeroU32;

use nonempty::NonEmpty;
use rand_core::OsRng;
use sapling::{
    note_encryption::{try_sapling_note_decryption, PreparedIncomingViewingKey},
    prover::{OutputProver, SpendProver},
};
use zcash_primitives::{
    consensus::{self, BlockHeight, NetworkUpgrade},
    memo::MemoBytes,
    transaction::{
        builder::{BuildConfig, BuildResult, Builder},
        components::amount::{Amount, NonNegativeAmount},
        fees::{zip317::FeeError as Zip317FeeError, FeeRule, StandardFeeRule},
        Transaction, TxId,
    },
    zip32::{AccountId, Scope},
};

use crate::{
    address::Address,
    data_api::{
        error::Error, DecryptedTransaction, SentTransaction, SentTransactionOutput,
        WalletCommitmentTrees, WalletRead, WalletWrite,
    },
    decrypt_transaction,
    fees::{self, DustOutputPolicy},
    keys::UnifiedSpendingKey,
    proposal::ProposalError,
    proposal::{self, Proposal},
    wallet::{Note, OvkPolicy, Recipient},
    zip321::{self, Payment},
    PoolType, ShieldedProtocol,
};

pub mod input_selection;
use input_selection::{
    GreedyInputSelector, GreedyInputSelectorError, InputSelector, InputSelectorError,
};

use super::InputSource;

#[cfg(feature = "transparent-inputs")]
use {
    input_selection::ShieldingSelector,
    sapling::keys::OutgoingViewingKey,
    std::convert::Infallible,
    zcash_keys::encoding::AddressCodec,
    zcash_primitives::legacy::TransparentAddress,
    zcash_primitives::transaction::components::{OutPoint, TxOut},
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
        .or(data.chain_height()?.map(|max_height| max_height + 1))
        .or_else(|| params.activation_height(NetworkUpgrade::Sapling))
        .expect("Sapling activation height must be known.");

    data.store_decrypted_tx(DecryptedTransaction {
        tx,
        sapling_outputs: &decrypt_transaction(params, height, tx, &ufvks),
    })?;

    Ok(())
}

#[allow(clippy::needless_doctest_main)]
/// Creates a transaction or series of transactions paying the specified address from
/// the given account, and the [`TxId`] corresponding to each newly-created transaction.
///
/// These transactions can be retrieved from the underlying data store using the
/// [`WalletRead::get_transaction`] method.
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
/// * `spend_prover`: The [`sapling::SpendProver`] to use in constructing the shielded
///   transaction.
/// * `output_prover`: The [`sapling::OutputProver`] to use in constructing the shielded
///   transaction.
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
///   spent. A value of 10 confirmations is recommended and 0-conf transactions are
///   not supported.
/// * `change_memo`: A memo to be included in the change output
///
/// # Examples
///
/// ```
/// # #[cfg(all(feature = "test-dependencies", feature = "local-prover"))]
/// # {
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
///     10,
///     None
/// )
///
/// # }
/// # }
/// ```
///
/// [`sapling::SpendProver`]: sapling::prover::SpendProver
/// [`sapling::OutputProver`]: sapling::prover::OutputProver
#[allow(clippy::too_many_arguments)]
#[allow(clippy::type_complexity)]
#[deprecated(
    note = "Use `spend` instead. `create_spend_to_address` uses a fixed fee of 10000 zatoshis, which is not compliant with ZIP 317."
)]
pub fn create_spend_to_address<DbT, ParamsT>(
    wallet_db: &mut DbT,
    params: &ParamsT,
    spend_prover: &impl SpendProver,
    output_prover: &impl OutputProver,
    usk: &UnifiedSpendingKey,
    to: &Address,
    amount: NonNegativeAmount,
    memo: Option<MemoBytes>,
    ovk_policy: OvkPolicy,
    min_confirmations: NonZeroU32,
    change_memo: Option<MemoBytes>,
) -> Result<
    NonEmpty<TxId>,
    Error<
        <DbT as WalletRead>::Error,
        <DbT as WalletCommitmentTrees>::Error,
        GreedyInputSelectorError<Zip317FeeError, DbT::NoteRef>,
        Zip317FeeError,
    >,
>
where
    ParamsT: consensus::Parameters + Clone,
    DbT: WalletWrite + WalletCommitmentTrees + InputSource<Error = <DbT as WalletRead>::Error>,
    <DbT as InputSource>::NoteRef: Copy + Eq + Ord,
{
    let account = wallet_db
        .get_account_for_ufvk(&usk.to_unified_full_viewing_key())
        .map_err(Error::DataSource)?
        .ok_or(Error::KeyNotRecognized)?;

    #[allow(deprecated)]
    let proposal = propose_standard_transfer_to_address(
        wallet_db,
        params,
        StandardFeeRule::PreZip313,
        account,
        min_confirmations,
        to,
        amount,
        memo,
        change_memo,
    )?;

    create_proposed_transactions(
        wallet_db,
        params,
        spend_prover,
        output_prover,
        usk,
        ovk_policy,
        &proposal,
    )
}

/// Constructs a transaction or series of transactions that send funds as specified
/// by the `request` argument, stores them to the wallet's "sent transactions" data
/// store, and returns the [`TxId`] for each transaction constructed.
///
/// The newly-created transactions can be retrieved from the underlying data store using the
/// [`WalletRead::get_transaction`] method.
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
/// * `spend_prover`: The [`sapling::SpendProver`] to use in constructing the shielded
///   transaction.
/// * `output_prover`: The [`sapling::OutputProver`] to use in constructing the shielded
///   transaction.
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
///   spent. A value of 10 confirmations is recommended and 0-conf transactions are
///   not supported.
///
/// [`sapling::SpendProver`]: sapling::prover::SpendProver
/// [`sapling::OutputProver`]: sapling::prover::OutputProver
#[allow(clippy::too_many_arguments)]
#[allow(clippy::type_complexity)]
pub fn spend<DbT, ParamsT, InputsT>(
    wallet_db: &mut DbT,
    params: &ParamsT,
    spend_prover: &impl SpendProver,
    output_prover: &impl OutputProver,
    input_selector: &InputsT,
    usk: &UnifiedSpendingKey,
    request: zip321::TransactionRequest,
    ovk_policy: OvkPolicy,
    min_confirmations: NonZeroU32,
) -> Result<
    NonEmpty<TxId>,
    Error<
        <DbT as WalletRead>::Error,
        <DbT as WalletCommitmentTrees>::Error,
        InputsT::Error,
        <InputsT::FeeRule as FeeRule>::Error,
    >,
>
where
    DbT: WalletWrite + WalletCommitmentTrees + InputSource<Error = <DbT as WalletRead>::Error>,
    <DbT as InputSource>::NoteRef: Copy + Eq + Ord,
    ParamsT: consensus::Parameters + Clone,
    InputsT: InputSelector<InputSource = DbT>,
{
    let account = wallet_db
        .get_account_for_ufvk(&usk.to_unified_full_viewing_key())
        .map_err(Error::DataSource)?
        .ok_or(Error::KeyNotRecognized)?;

    let proposal = propose_transfer(
        wallet_db,
        params,
        account,
        input_selector,
        request,
        min_confirmations,
    )?;

    create_proposed_transactions(
        wallet_db,
        params,
        spend_prover,
        output_prover,
        usk,
        ovk_policy,
        &proposal,
    )
}

/// Select transaction inputs, compute fees, and construct a proposal for a transaction or series
/// of transactions that can then be authorized and made ready for submission to the network with
/// [`create_proposed_transaction`].
#[allow(clippy::too_many_arguments)]
#[allow(clippy::type_complexity)]
pub fn propose_transfer<DbT, ParamsT, InputsT, CommitmentTreeErrT>(
    wallet_db: &mut DbT,
    params: &ParamsT,
    spend_from_account: AccountId,
    input_selector: &InputsT,
    request: zip321::TransactionRequest,
    min_confirmations: NonZeroU32,
) -> Result<
    Proposal<InputsT::FeeRule, <DbT as InputSource>::NoteRef>,
    Error<
        <DbT as WalletRead>::Error,
        CommitmentTreeErrT,
        InputsT::Error,
        <InputsT::FeeRule as FeeRule>::Error,
    >,
>
where
    DbT: WalletRead + InputSource<Error = <DbT as WalletRead>::Error>,
    <DbT as InputSource>::NoteRef: Copy + Eq + Ord,
    ParamsT: consensus::Parameters + Clone,
    InputsT: InputSelector<InputSource = DbT>,
{
    let (target_height, anchor_height) = wallet_db
        .get_target_and_anchor_heights(min_confirmations)
        .map_err(|e| Error::from(InputSelectorError::DataSource(e)))?
        .ok_or_else(|| Error::from(InputSelectorError::SyncRequired))?;

    input_selector
        .propose_transaction(
            params,
            wallet_db,
            target_height,
            anchor_height,
            spend_from_account,
            request,
        )
        .map_err(Error::from)
}

/// Proposes making a payment to the specified address from the given account.
///
/// Returns the proposal, which may then be executed using [`create_proposed_transaction`].
/// Depending upon the recipient address, more than one transaction may be constructed
/// in the execution of the returned proposal.
///
/// This method uses the basic [`GreedyInputSelector`] for input selection.
///
/// Parameters:
/// * `wallet_db`: A read/write reference to the wallet database.
/// * `params`: Consensus parameters.
/// * `fee_rule`: The fee rule to use in creating the transaction.
/// * `spend_from_account`: The unified account that controls the funds that will be spent
///   in the resulting transaction. This procedure will return an error if the
///   account ID does not correspond to an account known to the wallet.
/// * `min_confirmations`: The minimum number of confirmations that a previously
///   received note must have in the blockchain in order to be considered for being
///   spent. A value of 10 confirmations is recommended and 0-conf transactions are
///   not supported.
/// * `to`: The address to which `amount` will be paid.
/// * `amount`: The amount to send.
/// * `memo`: A memo to be included in the output to the recipient.
/// * `change_memo`: A memo to be included in any change output that is created.
#[allow(clippy::too_many_arguments)]
#[allow(clippy::type_complexity)]
pub fn propose_standard_transfer_to_address<DbT, ParamsT, CommitmentTreeErrT>(
    wallet_db: &mut DbT,
    params: &ParamsT,
    fee_rule: StandardFeeRule,
    spend_from_account: AccountId,
    min_confirmations: NonZeroU32,
    to: &Address,
    amount: NonNegativeAmount,
    memo: Option<MemoBytes>,
    change_memo: Option<MemoBytes>,
) -> Result<
    Proposal<StandardFeeRule, DbT::NoteRef>,
    Error<
        <DbT as WalletRead>::Error,
        CommitmentTreeErrT,
        GreedyInputSelectorError<Zip317FeeError, DbT::NoteRef>,
        Zip317FeeError,
    >,
>
where
    ParamsT: consensus::Parameters + Clone,
    DbT: WalletRead + InputSource<Error = <DbT as WalletRead>::Error>,
    DbT::NoteRef: Copy + Eq + Ord,
{
    let request = zip321::TransactionRequest::new(vec![Payment {
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

    let change_strategy = fees::standard::SingleOutputChangeStrategy::new(fee_rule, change_memo);
    let input_selector =
        GreedyInputSelector::<DbT, _>::new(change_strategy, DustOutputPolicy::default());

    propose_transfer(
        wallet_db,
        params,
        spend_from_account,
        &input_selector,
        request,
        min_confirmations,
    )
}

/// Constructs a proposal to shield all of the funds belonging to the provided set of
/// addresses.
#[cfg(feature = "transparent-inputs")]
#[allow(clippy::too_many_arguments)]
#[allow(clippy::type_complexity)]
pub fn propose_shielding<DbT, ParamsT, InputsT, CommitmentTreeErrT>(
    wallet_db: &mut DbT,
    params: &ParamsT,
    input_selector: &InputsT,
    shielding_threshold: NonNegativeAmount,
    from_addrs: &[TransparentAddress],
    min_confirmations: u32,
) -> Result<
    Proposal<InputsT::FeeRule, Infallible>,
    Error<
        <DbT as WalletRead>::Error,
        CommitmentTreeErrT,
        InputsT::Error,
        <InputsT::FeeRule as FeeRule>::Error,
    >,
>
where
    ParamsT: consensus::Parameters,
    DbT: WalletRead + InputSource<Error = <DbT as WalletRead>::Error>,
    InputsT: ShieldingSelector<InputSource = DbT>,
{
    let chain_tip_height = wallet_db
        .chain_height()
        .map_err(|e| Error::from(InputSelectorError::DataSource(e)))?
        .ok_or_else(|| Error::from(InputSelectorError::SyncRequired))?;

    input_selector
        .propose_shielding(
            params,
            wallet_db,
            shielding_threshold,
            from_addrs,
            chain_tip_height + 1,
            min_confirmations,
        )
        .map_err(Error::from)
}

/// Construct, prove, and sign a transaction or series of transactions using the inputs supplied by
/// the given proposal, and persist it to the wallet database.
///
/// Returns the database identifier for each newly constructed transaction, or an error if
/// an error occurs in transaction construction, proving, or signing.
///
/// When evaluating multi-step proposals, only transparent outputs of any given step may be spent
/// in later steps; attempting to spend a shielded note (including change) output by an earlier
/// step is not supported, because the ultimate positions of those notes in the global note
/// commitment tree cannot be known until the transaction that produces those notes is mined,
/// and therefore the required spend proofs for such notes cannot be constructed.
#[allow(clippy::too_many_arguments)]
#[allow(clippy::type_complexity)]
pub fn create_proposed_transactions<DbT, ParamsT, InputsErrT, FeeRuleT, N>(
    wallet_db: &mut DbT,
    params: &ParamsT,
    spend_prover: &impl SpendProver,
    output_prover: &impl OutputProver,
    usk: &UnifiedSpendingKey,
    ovk_policy: OvkPolicy,
    proposal: &Proposal<FeeRuleT, N>,
) -> Result<
    NonEmpty<TxId>,
    Error<
        <DbT as WalletRead>::Error,
        <DbT as WalletCommitmentTrees>::Error,
        InputsErrT,
        FeeRuleT::Error,
    >,
>
where
    DbT: WalletWrite + WalletCommitmentTrees,
    ParamsT: consensus::Parameters + Clone,
    FeeRuleT: FeeRule,
{
    let mut step_results = Vec::with_capacity(proposal.steps().len());
    for step in proposal.steps() {
        let step_result = create_proposed_transaction(
            wallet_db,
            params,
            spend_prover,
            output_prover,
            usk,
            ovk_policy.clone(),
            proposal.fee_rule(),
            proposal.min_target_height(),
            &step_results,
            step,
        )?;
        step_results.push((step, step_result));
    }

    Ok(NonEmpty::from_vec(
        step_results
            .iter()
            .map(|(_, r)| r.transaction().txid())
            .collect(),
    )
    .expect("proposal.steps is NonEmpty"))
}

#[allow(clippy::too_many_arguments)]
#[allow(clippy::type_complexity)]
fn create_proposed_transaction<DbT, ParamsT, InputsErrT, FeeRuleT, N>(
    wallet_db: &mut DbT,
    params: &ParamsT,
    spend_prover: &impl SpendProver,
    output_prover: &impl OutputProver,
    usk: &UnifiedSpendingKey,
    ovk_policy: OvkPolicy,
    fee_rule: &FeeRuleT,
    min_target_height: BlockHeight,
    prior_step_results: &[(&proposal::Step<N>, BuildResult)],
    proposal_step: &proposal::Step<N>,
) -> Result<
    BuildResult,
    Error<
        <DbT as WalletRead>::Error,
        <DbT as WalletCommitmentTrees>::Error,
        InputsErrT,
        FeeRuleT::Error,
    >,
>
where
    DbT: WalletWrite + WalletCommitmentTrees,
    ParamsT: consensus::Parameters + Clone,
    FeeRuleT: FeeRule,
{
    // TODO: Spending shielded outputs of prior multi-step transaction steps is not yet
    // supported. Maybe support this at some point? Doing so would require a higher-level
    // approach in the wallet that waits for transactions with shielded outputs to be
    // mined and only then attempts to perform the next step.
    for s_ref in proposal_step.prior_step_inputs() {
        prior_step_results.get(s_ref.step_index()).map_or_else(
            || {
                // Return an error in case the step index doesn't match up with a step
                Err(Error::Proposal(ProposalError::ReferenceError(*s_ref)))
            },
            |step| match s_ref.output_index() {
                proposal::StepOutputIndex::Payment(i) => {
                    let prior_pool = step
                        .0
                        .payment_pools()
                        .get(&i)
                        .ok_or(Error::Proposal(ProposalError::ReferenceError(*s_ref)))?;

                    if matches!(prior_pool, PoolType::Shielded(_)) {
                        Err(Error::ProposalNotSupported)
                    } else {
                        Ok(())
                    }
                }
                proposal::StepOutputIndex::Change(_) => {
                    // Only shielded change is supported by zcash_client_backend, so multi-step
                    // transactions cannot yet spend prior transactions' change outputs.
                    Err(Error::ProposalNotSupported)
                }
            },
        )?;
    }

    let account = wallet_db
        .get_account_for_ufvk(&usk.to_unified_full_viewing_key())
        .map_err(Error::DataSource)?
        .ok_or(Error::KeyNotRecognized)?;

    let dfvk = usk.sapling().to_diversifiable_full_viewing_key();

    // Apply the outgoing viewing key policy.
    let external_ovk = match ovk_policy {
        OvkPolicy::Sender => Some(dfvk.to_ovk(Scope::External)),
        OvkPolicy::Custom(ovk) => Some(ovk),
        OvkPolicy::Discard => None,
    };

    let internal_ovk = || {
        #[cfg(feature = "transparent-inputs")]
        return if proposal_step.is_shielding() {
            Some(OutgoingViewingKey(
                usk.transparent()
                    .to_account_pubkey()
                    .internal_ovk()
                    .as_bytes(),
            ))
        } else {
            Some(dfvk.to_ovk(Scope::Internal))
        };

        #[cfg(not(feature = "transparent-inputs"))]
        Some(dfvk.to_ovk(Scope::Internal))
    };

    let (sapling_anchor, sapling_inputs) = proposal_step.shielded_inputs().map_or_else(
        || Ok((sapling::Anchor::empty_tree(), vec![])),
        |inputs| {
            wallet_db.with_sapling_tree_mut::<_, _, Error<_, _, _, _>>(|sapling_tree| {
                let anchor = sapling_tree
                    .root_at_checkpoint_id(&inputs.anchor_height())?
                    .into();

                let sapling_inputs = inputs
                    .notes()
                    .iter()
                    .map(|selected| {
                        match selected.note() {
                            Note::Sapling(note) => {
                                let key = match selected.spending_key_scope() {
                                    Scope::External => usk.sapling().clone(),
                                    Scope::Internal => usk.sapling().derive_internal(),
                                };

                                let merkle_path = sapling_tree.witness_at_checkpoint_id_caching(
                                    selected.note_commitment_tree_position(),
                                    &inputs.anchor_height(),
                                )?;

                                Ok((key, note, merkle_path))
                            }
                            #[cfg(feature = "orchard")]
                            Note::Orchard(_) => {
                                // FIXME: Implement this once `Proposal` has been refactored to
                                // include Orchard notes.
                                panic!("Orchard spends are not yet supported");
                            }
                        }
                    })
                    .collect::<Result<Vec<_>, Error<_, _, _, _>>>()?;

                Ok((anchor, sapling_inputs))
            })
        },
    )?;

    // Create the transaction. The type of the proposal ensures that there
    // are no possible transparent inputs, so we ignore those
    let mut builder = Builder::new(
        params.clone(),
        min_target_height,
        BuildConfig::Standard {
            sapling_anchor: Some(sapling_anchor),
            orchard_anchor: None,
        },
    );

    for (key, note, merkle_path) in sapling_inputs.into_iter() {
        builder.add_sapling_spend(&key, note.clone(), merkle_path)?;
    }

    #[cfg(feature = "transparent-inputs")]
    let utxos_spent = {
        let known_addrs = wallet_db
            .get_transparent_receivers(account)
            .map_err(Error::DataSource)?;

        let mut utxos_spent: Vec<OutPoint> = vec![];
        let mut add_transparent_input = |addr: &TransparentAddress,
                                         outpoint: OutPoint,
                                         utxo: TxOut|
         -> Result<
            (),
            Error<
                <DbT as WalletRead>::Error,
                <DbT as WalletCommitmentTrees>::Error,
                InputsErrT,
                FeeRuleT::Error,
            >,
        > {
            let address_metadata = known_addrs
                .get(addr)
                .ok_or(Error::AddressNotRecognized(*addr))?
                .clone()
                .ok_or_else(|| Error::NoSpendingKey(addr.encode(params)))?;

            let secret_key = usk
                .transparent()
                .derive_secret_key(address_metadata.scope(), address_metadata.address_index())
                .unwrap();

            utxos_spent.push(outpoint.clone());
            builder.add_transparent_input(secret_key, outpoint, utxo)?;

            Ok(())
        };

        for utxo in proposal_step.transparent_inputs() {
            add_transparent_input(
                utxo.recipient_address(),
                utxo.outpoint().clone(),
                utxo.txout().clone(),
            )?;
        }
        for input_ref in proposal_step.prior_step_inputs() {
            match input_ref.output_index() {
                proposal::StepOutputIndex::Payment(i) => {
                    // We know based upon the earlier check that this must be a transparent input,
                    // We also know that transparent outputs for that previous step were added to
                    // the transaction in payment index order, so we can use dead reckoning to
                    // figure out which output it ended up being.
                    let (prior_step, result) = &prior_step_results[input_ref.step_index()];
                    let recipient_address = match &prior_step
                        .transaction_request()
                        .payments()
                        .get(&i)
                        .expect("Payment step references are checked at construction")
                        .recipient_address
                    {
                        Address::Transparent(t) => Some(t),
                        Address::Unified(uaddr) => uaddr.transparent(),
                        _ => None,
                    }
                    .ok_or(Error::ProposalNotSupported)?;
                    let outpoint = OutPoint::new(
                        result.transaction().txid().into(),
                        u32::try_from(
                            prior_step
                                .payment_pools()
                                .iter()
                                .filter(|(_, pool)| pool == &&PoolType::Transparent)
                                .take_while(|(j, _)| j <= &&i)
                                .count()
                                - 1,
                        )
                        .expect("Transparent output index fits into a u32"),
                    );
                    let utxo = &result
                        .transaction()
                        .transparent_bundle()
                        .ok_or(Error::Proposal(ProposalError::ReferenceError(*input_ref)))?
                        .vout[outpoint.n() as usize];

                    add_transparent_input(recipient_address, outpoint, utxo.clone())?;
                }
                proposal::StepOutputIndex::Change(_) => unreachable!(),
            }
        }
        utxos_spent
    };

    let mut sapling_output_meta = vec![];
    let mut transparent_output_meta = vec![];
    for payment in proposal_step.transaction_request().payments().values() {
        match &payment.recipient_address {
            Address::Unified(ua) => {
                let memo = payment
                    .memo
                    .as_ref()
                    .map_or_else(MemoBytes::empty, |m| m.clone());

                if let Some(sapling_receiver) = ua.sapling() {
                    builder.add_sapling_output(
                        external_ovk,
                        *sapling_receiver,
                        payment.amount,
                        memo.clone(),
                    )?;
                    sapling_output_meta.push((
                        Recipient::Unified(
                            ua.clone(),
                            PoolType::Shielded(ShieldedProtocol::Sapling),
                        ),
                        payment.amount,
                        Some(memo),
                    ));
                } else if let Some(taddr) = ua.transparent() {
                    if payment.memo.is_some() {
                        return Err(Error::MemoForbidden);
                    } else {
                        builder.add_transparent_output(taddr, payment.amount)?;
                    }
                } else {
                    return Err(Error::NoSupportedReceivers(
                        ua.unknown().iter().map(|(tc, _)| *tc).collect(),
                    ));
                }
            }
            Address::Sapling(addr) => {
                let memo = payment
                    .memo
                    .as_ref()
                    .map_or_else(MemoBytes::empty, |m| m.clone());
                builder.add_sapling_output(external_ovk, *addr, payment.amount, memo.clone())?;
                sapling_output_meta.push((Recipient::Sapling(*addr), payment.amount, Some(memo)));
            }
            Address::Transparent(to) => {
                if payment.memo.is_some() {
                    return Err(Error::MemoForbidden);
                } else {
                    builder.add_transparent_output(to, payment.amount)?;
                }
                transparent_output_meta.push((to, payment.amount));
            }
        }
    }

    for change_value in proposal_step.balance().proposed_change() {
        let memo = change_value
            .memo()
            .map_or_else(MemoBytes::empty, |m| m.clone());
        match change_value.output_pool() {
            ShieldedProtocol::Sapling => {
                builder.add_sapling_output(
                    internal_ovk(),
                    dfvk.change_address().1,
                    change_value.value(),
                    memo.clone(),
                )?;
                sapling_output_meta.push((
                    Recipient::InternalAccount(
                        account,
                        PoolType::Shielded(ShieldedProtocol::Sapling),
                    ),
                    change_value.value(),
                    Some(memo),
                ))
            }
            #[cfg(zcash_unstable = "orchard")]
            ShieldedProtocol::Orchard => {
                #[cfg(not(feature = "orchard"))]
                return Err(Error::UnsupportedPoolType(PoolType::Shielded(
                    ShieldedProtocol::Orchard,
                )));

                #[cfg(feature = "orchard")]
                unimplemented!("FIXME: implement Orchard change output creation.")
            }
        }
    }

    // Build the transaction with the specified fee rule
    let build_result = builder.build(OsRng, spend_prover, output_prover, fee_rule)?;

    let internal_ivk = PreparedIncomingViewingKey::new(&dfvk.to_ivk(Scope::Internal));
    let sapling_outputs =
        sapling_output_meta
            .into_iter()
            .enumerate()
            .map(|(i, (recipient, value, memo))| {
                let output_index = build_result
                    .sapling_meta()
                    .output_index(i)
                    .expect("An output should exist in the transaction for each Sapling payment.");

                let received_as = if let Recipient::InternalAccount(
                    account,
                    PoolType::Shielded(ShieldedProtocol::Sapling),
                ) = recipient
                {
                    build_result
                        .transaction()
                        .sapling_bundle()
                        .and_then(|bundle| {
                            try_sapling_note_decryption(
                                &internal_ivk,
                                &bundle.shielded_outputs()[output_index],
                                consensus::sapling_zip212_enforcement(params, min_target_height),
                            )
                            .map(|(note, _, _)| (account, note))
                        })
                } else {
                    None
                };

                SentTransactionOutput::from_parts(output_index, recipient, value, memo, received_as)
            });

    let transparent_outputs = transparent_output_meta.into_iter().map(|(addr, value)| {
        let script = addr.script();
        let output_index = build_result
            .transaction()
            .transparent_bundle()
            .and_then(|b| {
                b.vout
                    .iter()
                    .enumerate()
                    .find(|(_, tx_out)| tx_out.script_pubkey == script)
            })
            .map(|(index, _)| index)
            .expect("An output should exist in the transaction for each transparent payment.");

        SentTransactionOutput::from_parts(
            output_index,
            Recipient::Transparent(*addr),
            value,
            None,
            None,
        )
    });

    wallet_db
        .store_sent_tx(&SentTransaction {
            tx: build_result.transaction(),
            created: time::OffsetDateTime::now_utc(),
            account,
            outputs: sapling_outputs.chain(transparent_outputs).collect(),
            fee_amount: Amount::from(proposal_step.balance().fee_required()),
            #[cfg(feature = "transparent-inputs")]
            utxos_spent,
        })
        .map_err(Error::DataSource)?;

    Ok(build_result)
}

/// Constructs a transaction that consumes available transparent UTXOs belonging to the specified
/// secret key, and sends them to the most-preferred receiver of the default internal address for
/// the provided Unified Spending Key.
///
/// This procedure will not attempt to shield transparent funds if the total amount being shielded
/// is less than the default fee to send the transaction. Fees will be paid only from the
/// transparent UTXOs being consumed.
///
/// Parameters:
/// * `wallet_db`: A read/write reference to the wallet database
/// * `params`: Consensus parameters
/// * `spend_prover`: The [`sapling::SpendProver`] to use in constructing the shielded
///   transaction.
/// * `output_prover`: The [`sapling::OutputProver`] to use in constructing the shielded
///   transaction.
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
/// * `min_confirmations`: The minimum number of confirmations that a previously
///   received note must have in the blockchain in order to be considered for being
///   spent. A value of 10 confirmations is recommended and 0-conf transactions are
///   not supported.
///
/// [`sapling::SpendProver`]: sapling::prover::SpendProver
/// [`sapling::OutputProver`]: sapling::prover::OutputProver
#[cfg(feature = "transparent-inputs")]
#[allow(clippy::too_many_arguments)]
#[allow(clippy::type_complexity)]
pub fn shield_transparent_funds<DbT, ParamsT, InputsT>(
    wallet_db: &mut DbT,
    params: &ParamsT,
    spend_prover: &impl SpendProver,
    output_prover: &impl OutputProver,
    input_selector: &InputsT,
    shielding_threshold: NonNegativeAmount,
    usk: &UnifiedSpendingKey,
    from_addrs: &[TransparentAddress],
    min_confirmations: u32,
) -> Result<
    NonEmpty<TxId>,
    Error<
        <DbT as WalletRead>::Error,
        <DbT as WalletCommitmentTrees>::Error,
        InputsT::Error,
        <InputsT::FeeRule as FeeRule>::Error,
    >,
>
where
    ParamsT: consensus::Parameters,
    DbT: WalletWrite + WalletCommitmentTrees + InputSource<Error = <DbT as WalletRead>::Error>,
    InputsT: ShieldingSelector<InputSource = DbT>,
{
    let proposal = propose_shielding(
        wallet_db,
        params,
        input_selector,
        shielding_threshold,
        from_addrs,
        min_confirmations,
    )?;

    create_proposed_transactions(
        wallet_db,
        params,
        spend_prover,
        output_prover,
        usk,
        OvkPolicy::Sender,
        &proposal,
    )
}
