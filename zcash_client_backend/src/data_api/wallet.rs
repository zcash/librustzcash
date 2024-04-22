//! # Functions for creating Zcash transactions that spend funds belonging to the wallet
//!
//! This module contains several different ways of creating Zcash transactions. This module is
//! designed around the idea that a Zcash wallet holds its funds in notes in either the Orchard
//! or Sapling shielded pool. In order to better preserve users' privacy, it does not provide any
//! functionality that allows users to directly spend transparent funds except by sending them to a
//! shielded internal address belonging to their wallet.
//!
//! The important high-level operations provided by this module are [`propose_transfer`],
//! and [`create_proposed_transactions`].
//!
//! [`propose_transfer`] takes a [`TransactionRequest`] object, selects inputs notes and
//! computes the fees required to satisfy that request, and returns a [`Proposal`] object that
//! describes the transaction to be made.
//!
//! [`create_proposed_transactions`] constructs one or more Zcash [`Transaction`]s based upon a
//! provided [`Proposal`], stores them to the wallet database, and returns the [`TxId`] for each
//! constructed transaction to the caller. The caller can then use the
//! [`WalletRead::get_transaction`] method to retrieve the newly constructed transactions. It is
//! the responsibility of the caller to retrieve and serialize the transactions and submit them for
//! inclusion into the Zcash blockchain.
//!
#![cfg_attr(
    feature = "transparent-inputs",
    doc = "
Another important high-level operation provided by this module is [`propose_shielding`], which
takes a set of transparent source addresses, and constructs a [`Proposal`] to send those funds
to a wallet-internal shielded address, as described in [ZIP 316](https://zips.z.cash/zip-0316).

[`propose_shielding`]: crate::data_api::wallet::propose_shielding
"
)]
//! [`TransactionRequest`]: crate::zip321::TransactionRequest
//! [`propose_transfer`]: crate::data_api::wallet::propose_transfer

use nonempty::NonEmpty;
use rand_core::OsRng;
use sapling::{
    note_encryption::{try_sapling_note_decryption, PreparedIncomingViewingKey},
    prover::{OutputProver, SpendProver},
};
use std::num::NonZeroU32;

use super::InputSource;
use crate::{
    address::Address,
    data_api::{
        error::Error, Account, SentTransaction, SentTransactionOutput, WalletCommitmentTrees,
        WalletRead, WalletWrite,
    },
    decrypt_transaction,
    fees::{self, DustOutputPolicy},
    keys::UnifiedSpendingKey,
    proposal::{self, Proposal, ProposalError},
    wallet::{Note, OvkPolicy, Recipient},
    zip321::{self, Payment},
    PoolType, ShieldedProtocol,
};
use zcash_primitives::transaction::{
    builder::{BuildConfig, BuildResult, Builder},
    components::{amount::NonNegativeAmount, sapling::zip212_enforcement},
    fees::{zip317::FeeError as Zip317FeeError, FeeRule, StandardFeeRule},
    Transaction, TxId,
};
use zcash_protocol::{
    consensus::{self, BlockHeight, NetworkUpgrade},
    memo::MemoBytes,
};
use zip32::Scope;

#[cfg(feature = "transparent-inputs")]
use {
    input_selection::ShieldingSelector,
    std::convert::Infallible,
    zcash_keys::encoding::AddressCodec,
    zcash_primitives::legacy::TransparentAddress,
    zcash_primitives::transaction::components::{OutPoint, TxOut},
};

pub mod input_selection;
use input_selection::{
    GreedyInputSelector, GreedyInputSelectorError, InputSelector, InputSelectorError,
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

    data.store_decrypted_tx(decrypt_transaction(params, height, tx, &ufvks))?;

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
///     keys::{UnifiedSpendingKey, UnifiedAddressRequest},
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
/// let req = UnifiedAddressRequest::new(false, true, true);
/// let usk = UnifiedSpendingKey::from_seed(&Network::TestNetwork, &[0; 32][..], account).unwrap();
/// let to = usk.to_unified_full_viewing_key().default_address(req).0.into();
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
    note = "Use `propose_transfer` and `create_proposed_transactions` instead. `create_spend_to_address` uses a fixed fee of 10000 zatoshis, which is not compliant with ZIP 317."
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
    fallback_change_pool: ShieldedProtocol,
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
    DbT: InputSource,
    DbT: WalletWrite<
        Error = <DbT as InputSource>::Error,
        AccountId = <DbT as InputSource>::AccountId,
    >,
    DbT: WalletCommitmentTrees,
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
        account.id(),
        min_confirmations,
        to,
        amount,
        memo,
        change_memo,
        fallback_change_pool,
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
#[deprecated(note = "Use `propose_transfer` and `create_proposed_transactions` instead.")]
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
    DbT: InputSource,
    DbT: WalletWrite<
        Error = <DbT as InputSource>::Error,
        AccountId = <DbT as InputSource>::AccountId,
    >,
    DbT: WalletCommitmentTrees,
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
        account.id(),
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
/// [`create_proposed_transactions`].
#[allow(clippy::too_many_arguments)]
#[allow(clippy::type_complexity)]
pub fn propose_transfer<DbT, ParamsT, InputsT, CommitmentTreeErrT>(
    wallet_db: &mut DbT,
    params: &ParamsT,
    spend_from_account: <DbT as InputSource>::AccountId,
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
/// Returns the proposal, which may then be executed using [`create_proposed_transactions`].
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
/// * `fallback_change_pool`: The shielded pool to which change should be sent if
///   automatic change pool determination fails.
#[allow(clippy::too_many_arguments)]
#[allow(clippy::type_complexity)]
pub fn propose_standard_transfer_to_address<DbT, ParamsT, CommitmentTreeErrT>(
    wallet_db: &mut DbT,
    params: &ParamsT,
    fee_rule: StandardFeeRule,
    spend_from_account: <DbT as InputSource>::AccountId,
    min_confirmations: NonZeroU32,
    to: &Address,
    amount: NonNegativeAmount,
    memo: Option<MemoBytes>,
    change_memo: Option<MemoBytes>,
    fallback_change_pool: ShieldedProtocol,
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
    DbT: InputSource,
    DbT: WalletRead<
        Error = <DbT as InputSource>::Error,
        AccountId = <DbT as InputSource>::AccountId,
    >,
    DbT::NoteRef: Copy + Eq + Ord,
{
    let request = zip321::TransactionRequest::new(vec![Payment::new(
        to.to_zcash_address(params),
        amount,
        memo,
        None,
        None,
        vec![],
    )
    .ok_or(Error::MemoForbidden)?])
    .expect(
        "It should not be possible for this to violate ZIP 321 request construction invariants.",
    );

    let change_strategy = fees::standard::SingleOutputChangeStrategy::new(
        fee_rule,
        change_memo,
        fallback_change_pool,
    );
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
        .ok_or(Error::KeyNotRecognized)?
        .id();

    let (sapling_anchor, sapling_inputs) =
        if proposal_step.involves(PoolType::Shielded(ShieldedProtocol::Sapling)) {
            proposal_step.shielded_inputs().map_or_else(
                || Ok((Some(sapling::Anchor::empty_tree()), vec![])),
                |inputs| {
                    wallet_db.with_sapling_tree_mut::<_, _, Error<_, _, _, _>>(|sapling_tree| {
                        let anchor = sapling_tree
                            .root_at_checkpoint_id(&inputs.anchor_height())?
                            .into();

                        let sapling_inputs = inputs
                            .notes()
                            .iter()
                            .filter_map(|selected| match selected.note() {
                                Note::Sapling(note) => {
                                    let key = match selected.spending_key_scope() {
                                        Scope::External => usk.sapling().clone(),
                                        Scope::Internal => usk.sapling().derive_internal(),
                                    };

                                    sapling_tree
                                        .witness_at_checkpoint_id_caching(
                                            selected.note_commitment_tree_position(),
                                            &inputs.anchor_height(),
                                        )
                                        .map(|merkle_path| Some((key, note, merkle_path)))
                                        .map_err(Error::from)
                                        .transpose()
                                }
                                #[cfg(feature = "orchard")]
                                Note::Orchard(_) => None,
                            })
                            .collect::<Result<Vec<_>, Error<_, _, _, _>>>()?;

                        Ok((Some(anchor), sapling_inputs))
                    })
                },
            )?
        } else {
            (None, vec![])
        };

    #[cfg(feature = "orchard")]
    let (orchard_anchor, orchard_inputs) =
        if proposal_step.involves(PoolType::Shielded(ShieldedProtocol::Orchard)) {
            proposal_step.shielded_inputs().map_or_else(
                || Ok((Some(orchard::Anchor::empty_tree()), vec![])),
                |inputs| {
                    wallet_db.with_orchard_tree_mut::<_, _, Error<_, _, _, _>>(|orchard_tree| {
                        let anchor = orchard_tree
                            .root_at_checkpoint_id(&inputs.anchor_height())?
                            .into();

                        let orchard_inputs = inputs
                            .notes()
                            .iter()
                            .filter_map(|selected| match selected.note() {
                                #[cfg(feature = "orchard")]
                                Note::Orchard(note) => orchard_tree
                                    .witness_at_checkpoint_id_caching(
                                        selected.note_commitment_tree_position(),
                                        &inputs.anchor_height(),
                                    )
                                    .map(|merkle_path| Some((note, merkle_path)))
                                    .map_err(Error::from)
                                    .transpose(),
                                Note::Sapling(_) => None,
                            })
                            .collect::<Result<Vec<_>, Error<_, _, _, _>>>()?;

                        Ok((Some(anchor), orchard_inputs))
                    })
                },
            )?
        } else {
            (None, vec![])
        };
    #[cfg(not(feature = "orchard"))]
    let orchard_anchor = None;

    // Create the transaction. The type of the proposal ensures that there
    // are no possible transparent inputs, so we ignore those
    let mut builder = Builder::new(
        params.clone(),
        min_target_height,
        BuildConfig::Standard {
            sapling_anchor,
            orchard_anchor,
        },
    );

    for (sapling_key, sapling_note, merkle_path) in sapling_inputs.into_iter() {
        builder.add_sapling_spend(&sapling_key, sapling_note.clone(), merkle_path)?;
    }

    #[cfg(feature = "orchard")]
    for (orchard_note, merkle_path) in orchard_inputs.into_iter() {
        builder.add_orchard_spend(usk.orchard(), *orchard_note, merkle_path.into())?;
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
                    let recipient_address = &prior_step
                        .transaction_request()
                        .payments()
                        .get(&i)
                        .expect("Payment step references are checked at construction")
                        .recipient_address()
                        .clone()
                        .convert_if_network(params.network_type())?;

                    let recipient_taddr = match recipient_address {
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

                    add_transparent_input(recipient_taddr, outpoint, utxo.clone())?;
                }
                proposal::StepOutputIndex::Change(_) => unreachable!(),
            }
        }
        utxos_spent
    };

    #[cfg(feature = "orchard")]
    let orchard_fvk: orchard::keys::FullViewingKey = usk.orchard().into();

    #[cfg(feature = "orchard")]
    let orchard_external_ovk = match &ovk_policy {
        OvkPolicy::Sender => Some(orchard_fvk.to_ovk(orchard::keys::Scope::External)),
        OvkPolicy::Custom { orchard, .. } => Some(orchard.clone()),
        OvkPolicy::Discard => None,
    };

    #[cfg(feature = "orchard")]
    let orchard_internal_ovk = || {
        #[cfg(feature = "transparent-inputs")]
        if proposal_step.is_shielding() {
            return Some(orchard::keys::OutgoingViewingKey::from(
                usk.transparent()
                    .to_account_pubkey()
                    .internal_ovk()
                    .as_bytes(),
            ));
        }

        Some(orchard_fvk.to_ovk(Scope::Internal))
    };

    let sapling_dfvk = usk.sapling().to_diversifiable_full_viewing_key();

    // Apply the outgoing viewing key policy.
    let sapling_external_ovk = match &ovk_policy {
        OvkPolicy::Sender => Some(sapling_dfvk.to_ovk(Scope::External)),
        OvkPolicy::Custom { sapling, .. } => Some(*sapling),
        OvkPolicy::Discard => None,
    };

    let sapling_internal_ovk = || {
        #[cfg(feature = "transparent-inputs")]
        if proposal_step.is_shielding() {
            return Some(sapling::keys::OutgoingViewingKey(
                usk.transparent()
                    .to_account_pubkey()
                    .internal_ovk()
                    .as_bytes(),
            ));
        }

        Some(sapling_dfvk.to_ovk(Scope::Internal))
    };

    #[cfg(feature = "orchard")]
    let mut orchard_output_meta = vec![];
    let mut sapling_output_meta = vec![];
    let mut transparent_output_meta = vec![];
    for (payment, output_pool) in proposal_step
        .payment_pools()
        .iter()
        .map(|(idx, output_pool)| {
            let payment = proposal_step
                .transaction_request()
                .payments()
                .get(idx)
                .expect(
                    "The mapping between payment index and payment is checked in step construction",
                );
            (payment, output_pool)
        })
    {
        let recipient_address: Address = payment
            .recipient_address()
            .clone()
            .convert_if_network(params.network_type())?;

        match recipient_address {
            Address::Unified(ua) => {
                let memo = payment.memo().map_or_else(MemoBytes::empty, |m| m.clone());

                match output_pool {
                    #[cfg(not(feature = "orchard"))]
                    PoolType::Shielded(ShieldedProtocol::Orchard) => {
                        return Err(Error::ProposalNotSupported);
                    }
                    #[cfg(feature = "orchard")]
                    PoolType::Shielded(ShieldedProtocol::Orchard) => {
                        builder.add_orchard_output(
                            orchard_external_ovk.clone(),
                            *ua.orchard().expect("The mapping between payment pool and receiver is checked in step construction"),
                            payment.amount().into(),
                            memo.clone(),
                        )?;
                        orchard_output_meta.push((
                            Recipient::External(
                                payment.recipient_address().clone(),
                                PoolType::Shielded(ShieldedProtocol::Orchard),
                            ),
                            payment.amount(),
                            Some(memo),
                        ));
                    }

                    PoolType::Shielded(ShieldedProtocol::Sapling) => {
                        builder.add_sapling_output(
                            sapling_external_ovk,
                            *ua.sapling().expect("The mapping between payment pool and receiver is checked in step construction"),
                            payment.amount(),
                            memo.clone(),
                        )?;
                        sapling_output_meta.push((
                            Recipient::External(
                                payment.recipient_address().clone(),
                                PoolType::Shielded(ShieldedProtocol::Sapling),
                            ),
                            payment.amount(),
                            Some(memo),
                        ));
                    }

                    PoolType::Transparent => {
                        if payment.memo().is_some() {
                            return Err(Error::MemoForbidden);
                        } else {
                            builder.add_transparent_output(
                                ua.transparent().expect("The mapping between payment pool and receiver is checked in step construction."),
                                payment.amount()
                            )?;
                        }
                    }
                }
            }
            Address::Sapling(addr) => {
                let memo = payment.memo().map_or_else(MemoBytes::empty, |m| m.clone());
                builder.add_sapling_output(
                    sapling_external_ovk,
                    addr,
                    payment.amount(),
                    memo.clone(),
                )?;
                sapling_output_meta.push((
                    Recipient::External(payment.recipient_address().clone(), PoolType::SAPLING),
                    payment.amount(),
                    Some(memo),
                ));
            }
            Address::Transparent(to) => {
                if payment.memo().is_some() {
                    return Err(Error::MemoForbidden);
                } else {
                    builder.add_transparent_output(&to, payment.amount())?;
                }
                transparent_output_meta.push((
                    Recipient::External(payment.recipient_address().clone(), PoolType::TRANSPARENT),
                    to,
                    payment.amount(),
                ));
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
                    sapling_internal_ovk(),
                    sapling_dfvk.change_address().1,
                    change_value.value(),
                    memo.clone(),
                )?;
                sapling_output_meta.push((
                    Recipient::InternalAccount {
                        receiving_account: account,
                        external_address: None,
                        note: PoolType::Shielded(ShieldedProtocol::Sapling),
                    },
                    change_value.value(),
                    Some(memo),
                ))
            }
            ShieldedProtocol::Orchard => {
                #[cfg(not(feature = "orchard"))]
                return Err(Error::UnsupportedChangeType(PoolType::Shielded(
                    ShieldedProtocol::Orchard,
                )));

                #[cfg(feature = "orchard")]
                {
                    builder.add_orchard_output(
                        orchard_internal_ovk(),
                        orchard_fvk.address_at(0u32, orchard::keys::Scope::Internal),
                        change_value.value().into(),
                        memo.clone(),
                    )?;
                    orchard_output_meta.push((
                        Recipient::InternalAccount {
                            receiving_account: account,
                            external_address: None,
                            note: PoolType::Shielded(ShieldedProtocol::Orchard),
                        },
                        change_value.value(),
                        Some(memo),
                    ))
                }
            }
        }
    }

    // Build the transaction with the specified fee rule
    let build_result = builder.build(OsRng, spend_prover, output_prover, fee_rule)?;

    #[cfg(feature = "orchard")]
    let orchard_internal_ivk = orchard_fvk.to_ivk(orchard::keys::Scope::Internal);
    #[cfg(feature = "orchard")]
    let orchard_outputs =
        orchard_output_meta
            .into_iter()
            .enumerate()
            .map(|(i, (recipient, value, memo))| {
                let output_index = build_result
                    .orchard_meta()
                    .output_action_index(i)
                    .expect("An action should exist in the transaction for each Orchard output.");

                let recipient = recipient
                    .map_internal_account_note(|pool| {
                        assert!(pool == PoolType::Shielded(ShieldedProtocol::Orchard));
                        build_result
                            .transaction()
                            .orchard_bundle()
                            .and_then(|bundle| {
                                bundle
                                    .decrypt_output_with_key(output_index, &orchard_internal_ivk)
                                    .map(|(note, _, _)| Note::Orchard(note))
                            })
                    })
                    .internal_account_note_transpose_option()
                    .expect("Wallet-internal outputs must be decryptable with the wallet's IVK");

                SentTransactionOutput::from_parts(output_index, recipient, value, memo)
            });

    let sapling_internal_ivk =
        PreparedIncomingViewingKey::new(&sapling_dfvk.to_ivk(Scope::Internal));
    let sapling_outputs =
        sapling_output_meta
            .into_iter()
            .enumerate()
            .map(|(i, (recipient, value, memo))| {
                let output_index = build_result
                    .sapling_meta()
                    .output_index(i)
                    .expect("An output should exist in the transaction for each Sapling payment.");

                let recipient = recipient
                    .map_internal_account_note(|pool| {
                        assert!(pool == PoolType::Shielded(ShieldedProtocol::Sapling));
                        build_result
                            .transaction()
                            .sapling_bundle()
                            .and_then(|bundle| {
                                try_sapling_note_decryption(
                                    &sapling_internal_ivk,
                                    &bundle.shielded_outputs()[output_index],
                                    zip212_enforcement(params, min_target_height),
                                )
                                .map(|(note, _, _)| Note::Sapling(note))
                            })
                    })
                    .internal_account_note_transpose_option()
                    .expect("Wallet-internal outputs must be decryptable with the wallet's IVK");

                SentTransactionOutput::from_parts(output_index, recipient, value, memo)
            });

    let transparent_outputs =
        transparent_output_meta
            .into_iter()
            .map(|(recipient, addr, value)| {
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
                    .expect(
                        "An output should exist in the transaction for each transparent payment.",
                    );

                SentTransactionOutput::from_parts(output_index, recipient, value, None)
            });

    let mut outputs = vec![];
    #[cfg(feature = "orchard")]
    outputs.extend(orchard_outputs);
    outputs.extend(sapling_outputs);
    outputs.extend(transparent_outputs);

    wallet_db
        .store_sent_tx(&SentTransaction {
            tx: build_result.transaction(),
            created: time::OffsetDateTime::now_utc(),
            account,
            outputs,
            fee_amount: proposal_step.balance().fee_required(),
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
