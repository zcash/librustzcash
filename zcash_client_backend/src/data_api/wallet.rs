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
use shardtree::error::{QueryError, ShardTreeError};
use std::num::NonZeroU32;

use super::InputSource;
use crate::{
    address::Address,
    data_api::{
        error::Error, Account, SentTransaction, SentTransactionOutput, WalletCommitmentTrees,
        WalletRead, WalletWrite,
    },
    decrypt_transaction,
    fees::{standard::SingleOutputChangeStrategy, ChangeStrategy, DustOutputPolicy},
    keys::UnifiedSpendingKey,
    proposal::{Proposal, ProposalError, Step, StepOutputIndex},
    wallet::{Note, OvkPolicy, Recipient},
    zip321::{self, Payment},
    PoolType, ShieldedProtocol,
};
use zcash_primitives::{
    legacy::TransparentAddress,
    transaction::{
        builder::{BuildConfig, BuildResult, Builder},
        components::{amount::NonNegativeAmount, sapling::zip212_enforcement, OutPoint},
        fees::{FeeRule, StandardFeeRule},
        Transaction, TxId,
    },
};
use zcash_protocol::{
    consensus::{self, BlockHeight, NetworkUpgrade},
    memo::MemoBytes,
};
use zip32::Scope;

#[cfg(feature = "transparent-inputs")]
use {
    crate::{fees::ChangeValue, proposal::StepOutput, wallet::TransparentAddressMetadata},
    core::convert::Infallible,
    input_selection::ShieldingSelector,
    std::collections::HashMap,
    zcash_keys::encoding::AddressCodec,
    zcash_primitives::transaction::components::TxOut,
};

pub mod input_selection;
use input_selection::{GreedyInputSelector, InputSelector, InputSelectorError};

/// Scans a [`Transaction`] for any information that can be decrypted by the accounts in
/// the wallet, and saves it to the wallet.
pub fn decrypt_and_store_transaction<ParamsT, DbT>(
    params: &ParamsT,
    data: &mut DbT,
    tx: &Transaction,
    mined_height: Option<BlockHeight>,
) -> Result<(), DbT::Error>
where
    ParamsT: consensus::Parameters,
    DbT: WalletWrite,
{
    // Fetch the UnifiedFullViewingKeys we are tracking
    let ufvks = data.get_unified_full_viewing_keys()?;

    // Height is block height for mined transactions, and the "mempool height" (chain height + 1)
    // for mempool transactions.
    let height = mined_height.map(Ok).unwrap_or_else(|| {
        Ok(data
            .get_tx_height(tx.txid())?
            .or(data.chain_height()?.map(|max_height| max_height + 1))
            .or_else(|| params.activation_height(NetworkUpgrade::Sapling))
            .expect("Sapling activation height must be known."))
    })?;

    data.store_decrypted_tx(decrypt_transaction(params, height, tx, &ufvks))?;

    Ok(())
}

pub type ProposeTransferErrT<DbT, CommitmentTreeErrT, InputsT, ChangeT> = Error<
    <DbT as WalletRead>::Error,
    CommitmentTreeErrT,
    <InputsT as InputSelector>::Error,
    <<ChangeT as ChangeStrategy>::FeeRule as FeeRule>::Error,
    <ChangeT as ChangeStrategy>::Error,
    <<InputsT as InputSelector>::InputSource as InputSource>::NoteRef,
>;

#[cfg(feature = "transparent-inputs")]
pub type ProposeShieldingErrT<DbT, CommitmentTreeErrT, InputsT, ChangeT> = Error<
    <DbT as WalletRead>::Error,
    CommitmentTreeErrT,
    <InputsT as ShieldingSelector>::Error,
    <<ChangeT as ChangeStrategy>::FeeRule as FeeRule>::Error,
    <ChangeT as ChangeStrategy>::Error,
    Infallible,
>;

pub type CreateErrT<DbT, InputsErrT, FeeRuleT, ChangeErrT, N> = Error<
    <DbT as WalletRead>::Error,
    <DbT as WalletCommitmentTrees>::Error,
    InputsErrT,
    <FeeRuleT as FeeRule>::Error,
    ChangeErrT,
    N,
>;

pub type TransferErrT<DbT, InputsT, ChangeT> = Error<
    <DbT as WalletRead>::Error,
    <DbT as WalletCommitmentTrees>::Error,
    <InputsT as InputSelector>::Error,
    <<ChangeT as ChangeStrategy>::FeeRule as FeeRule>::Error,
    <ChangeT as ChangeStrategy>::Error,
    <<InputsT as InputSelector>::InputSource as InputSource>::NoteRef,
>;

#[cfg(feature = "transparent-inputs")]
pub type ShieldErrT<DbT, InputsT, ChangeT> = Error<
    <DbT as WalletRead>::Error,
    <DbT as WalletCommitmentTrees>::Error,
    <InputsT as ShieldingSelector>::Error,
    <<ChangeT as ChangeStrategy>::FeeRule as FeeRule>::Error,
    <ChangeT as ChangeStrategy>::Error,
    Infallible,
>;

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
    TransferErrT<DbT, GreedyInputSelector<DbT>, SingleOutputChangeStrategy<DbT>>,
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
pub fn spend<DbT, ParamsT, InputsT, ChangeT>(
    wallet_db: &mut DbT,
    params: &ParamsT,
    spend_prover: &impl SpendProver,
    output_prover: &impl OutputProver,
    input_selector: &InputsT,
    change_strategy: &ChangeT,
    usk: &UnifiedSpendingKey,
    request: zip321::TransactionRequest,
    ovk_policy: OvkPolicy,
    min_confirmations: NonZeroU32,
) -> Result<NonEmpty<TxId>, TransferErrT<DbT, InputsT, ChangeT>>
where
    DbT: InputSource,
    DbT: WalletWrite<
        Error = <DbT as InputSource>::Error,
        AccountId = <DbT as InputSource>::AccountId,
    >,
    DbT: WalletCommitmentTrees,
    ParamsT: consensus::Parameters + Clone,
    InputsT: InputSelector<InputSource = DbT>,
    ChangeT: ChangeStrategy<MetaSource = DbT>,
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
        change_strategy,
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
pub fn propose_transfer<DbT, ParamsT, InputsT, ChangeT, CommitmentTreeErrT>(
    wallet_db: &mut DbT,
    params: &ParamsT,
    spend_from_account: <DbT as InputSource>::AccountId,
    input_selector: &InputsT,
    change_strategy: &ChangeT,
    request: zip321::TransactionRequest,
    min_confirmations: NonZeroU32,
) -> Result<
    Proposal<ChangeT::FeeRule, <DbT as InputSource>::NoteRef>,
    ProposeTransferErrT<DbT, CommitmentTreeErrT, InputsT, ChangeT>,
>
where
    DbT: WalletRead + InputSource<Error = <DbT as WalletRead>::Error>,
    <DbT as InputSource>::NoteRef: Copy + Eq + Ord,
    ParamsT: consensus::Parameters + Clone,
    InputsT: InputSelector<InputSource = DbT>,
    ChangeT: ChangeStrategy<MetaSource = DbT>,
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
            change_strategy,
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
    ProposeTransferErrT<
        DbT,
        CommitmentTreeErrT,
        GreedyInputSelector<DbT>,
        SingleOutputChangeStrategy<DbT>,
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

    let input_selector = GreedyInputSelector::<DbT>::new();
    let change_strategy = SingleOutputChangeStrategy::<DbT>::new(
        fee_rule,
        change_memo,
        fallback_change_pool,
        DustOutputPolicy::default(),
    );

    propose_transfer(
        wallet_db,
        params,
        spend_from_account,
        &input_selector,
        &change_strategy,
        request,
        min_confirmations,
    )
}

/// Constructs a proposal to shield all of the funds belonging to the provided set of
/// addresses.
#[cfg(feature = "transparent-inputs")]
#[allow(clippy::too_many_arguments)]
#[allow(clippy::type_complexity)]
pub fn propose_shielding<DbT, ParamsT, InputsT, ChangeT, CommitmentTreeErrT>(
    wallet_db: &mut DbT,
    params: &ParamsT,
    input_selector: &InputsT,
    change_strategy: &ChangeT,
    shielding_threshold: NonNegativeAmount,
    from_addrs: &[TransparentAddress],
    to_account: <DbT as InputSource>::AccountId,
    min_confirmations: u32,
) -> Result<
    Proposal<ChangeT::FeeRule, Infallible>,
    ProposeShieldingErrT<DbT, CommitmentTreeErrT, InputsT, ChangeT>,
>
where
    ParamsT: consensus::Parameters,
    DbT: WalletRead + InputSource<Error = <DbT as WalletRead>::Error>,
    InputsT: ShieldingSelector<InputSource = DbT>,
    ChangeT: ChangeStrategy<MetaSource = DbT>,
{
    let chain_tip_height = wallet_db
        .chain_height()
        .map_err(|e| Error::from(InputSelectorError::DataSource(e)))?
        .ok_or_else(|| Error::from(InputSelectorError::SyncRequired))?;

    input_selector
        .propose_shielding(
            params,
            wallet_db,
            change_strategy,
            shielding_threshold,
            from_addrs,
            to_account,
            chain_tip_height + 1,
            min_confirmations,
        )
        .map_err(Error::from)
}

struct StepResult<AccountId> {
    build_result: BuildResult,
    outputs: Vec<SentTransactionOutput<AccountId>>,
    fee_amount: NonNegativeAmount,
    #[cfg(feature = "transparent-inputs")]
    utxos_spent: Vec<OutPoint>,
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
pub fn create_proposed_transactions<DbT, ParamsT, InputsErrT, FeeRuleT, ChangeErrT, N>(
    wallet_db: &mut DbT,
    params: &ParamsT,
    spend_prover: &impl SpendProver,
    output_prover: &impl OutputProver,
    usk: &UnifiedSpendingKey,
    ovk_policy: OvkPolicy,
    proposal: &Proposal<FeeRuleT, N>,
) -> Result<NonEmpty<TxId>, CreateErrT<DbT, InputsErrT, FeeRuleT, ChangeErrT, N>>
where
    DbT: WalletWrite + WalletCommitmentTrees,
    ParamsT: consensus::Parameters + Clone,
    FeeRuleT: FeeRule,
{
    // The set of transparent `StepOutput`s available and unused from prior steps.
    // When a transparent `StepOutput` is created, it is added to the map. When it
    // is consumed, it is removed from the map.
    #[cfg(feature = "transparent-inputs")]
    let mut unused_transparent_outputs = HashMap::new();

    let account_id = wallet_db
        .get_account_for_ufvk(&usk.to_unified_full_viewing_key())
        .map_err(Error::DataSource)?
        .ok_or(Error::KeyNotRecognized)?
        .id();

    let mut step_results = Vec::with_capacity(proposal.steps().len());
    for step in proposal.steps() {
        let step_result: StepResult<_> = create_proposed_transaction(
            wallet_db,
            params,
            spend_prover,
            output_prover,
            usk,
            account_id,
            ovk_policy.clone(),
            proposal.fee_rule(),
            proposal.min_target_height(),
            &step_results,
            step,
            #[cfg(feature = "transparent-inputs")]
            &mut unused_transparent_outputs,
        )?;
        step_results.push((step, step_result));
    }

    // Ephemeral outputs must be referenced exactly once.
    #[cfg(feature = "transparent-inputs")]
    for so in unused_transparent_outputs.into_keys() {
        if let StepOutputIndex::Change(i) = so.output_index() {
            // references have already been checked
            if step_results[so.step_index()].0.balance().proposed_change()[i].is_ephemeral() {
                return Err(ProposalError::EphemeralOutputLeftUnspent(so).into());
            }
        }
    }

    let created = time::OffsetDateTime::now_utc();

    // Store the transactions only after creating all of them. This avoids undesired
    // retransmissions in case a transaction is stored and the creation of a subsequent
    // transaction fails.
    let mut transactions = Vec::with_capacity(proposal.steps().len());
    let mut txids = Vec::with_capacity(proposal.steps().len());
    #[allow(unused_variables)]
    for (_, step_result) in step_results.iter() {
        let tx = step_result.build_result.transaction();
        transactions.push(SentTransaction::new(
            tx,
            created,
            proposal.min_target_height(),
            account_id,
            &step_result.outputs,
            step_result.fee_amount,
            #[cfg(feature = "transparent-inputs")]
            &step_result.utxos_spent,
        ));
        txids.push(tx.txid());
    }

    wallet_db
        .store_transactions_to_be_sent(&transactions)
        .map_err(Error::DataSource)?;

    Ok(NonEmpty::from_vec(txids).expect("proposal.steps is NonEmpty"))
}

// `unused_transparent_outputs` maps `StepOutput`s for transparent outputs
// that have not been consumed so far, to the corresponding pair of
// `TransparentAddress` and `Outpoint`.
#[allow(clippy::too_many_arguments)]
#[allow(clippy::type_complexity)]
fn create_proposed_transaction<DbT, ParamsT, InputsErrT, FeeRuleT, ChangeErrT, N>(
    wallet_db: &mut DbT,
    params: &ParamsT,
    spend_prover: &impl SpendProver,
    output_prover: &impl OutputProver,
    usk: &UnifiedSpendingKey,
    account_id: <DbT as WalletRead>::AccountId,
    ovk_policy: OvkPolicy,
    fee_rule: &FeeRuleT,
    min_target_height: BlockHeight,
    prior_step_results: &[(&Step<N>, StepResult<<DbT as WalletRead>::AccountId>)],
    proposal_step: &Step<N>,
    #[cfg(feature = "transparent-inputs")] unused_transparent_outputs: &mut HashMap<
        StepOutput,
        (TransparentAddress, OutPoint),
    >,
) -> Result<
    StepResult<<DbT as WalletRead>::AccountId>,
    CreateErrT<DbT, InputsErrT, FeeRuleT, ChangeErrT, N>,
>
where
    DbT: WalletWrite + WalletCommitmentTrees,
    ParamsT: consensus::Parameters + Clone,
    FeeRuleT: FeeRule,
{
    #[cfg(feature = "transparent-inputs")]
    let step_index = prior_step_results.len();

    // We only support spending transparent payments or transparent ephemeral outputs from a
    // prior step (when "transparent-inputs" is enabled).
    //
    // TODO: Maybe support spending prior shielded outputs at some point? Doing so would require
    // a higher-level approach in the wallet that waits for transactions with shielded outputs to
    // be mined and only then attempts to perform the next step.
    #[allow(clippy::never_loop)]
    for input_ref in proposal_step.prior_step_inputs() {
        let (prior_step, _) = prior_step_results
            .get(input_ref.step_index())
            .ok_or(ProposalError::ReferenceError(*input_ref))?;

        #[allow(unused_variables)]
        let output_pool = match input_ref.output_index() {
            StepOutputIndex::Payment(i) => prior_step.payment_pools().get(&i).cloned(),
            StepOutputIndex::Change(i) => match prior_step.balance().proposed_change().get(i) {
                Some(change) if !change.is_ephemeral() => {
                    return Err(ProposalError::SpendsChange(*input_ref).into());
                }
                other => other.map(|change| change.output_pool()),
            },
        }
        .ok_or(ProposalError::ReferenceError(*input_ref))?;

        // Return an error on trying to spend a prior output that is not supported.
        #[cfg(feature = "transparent-inputs")]
        if output_pool != PoolType::TRANSPARENT {
            return Err(Error::ProposalNotSupported);
        }
        #[cfg(not(feature = "transparent-inputs"))]
        return Err(Error::ProposalNotSupported);
    }

    let (sapling_anchor, sapling_inputs) = if proposal_step
        .involves(PoolType::Shielded(ShieldedProtocol::Sapling))
    {
        proposal_step.shielded_inputs().map_or_else(
            || Ok((Some(sapling::Anchor::empty_tree()), vec![])),
            |inputs| {
                wallet_db.with_sapling_tree_mut::<_, _, Error<_, _, _, _, _, _>>(|sapling_tree| {
                    let anchor = sapling_tree
                        .root_at_checkpoint_id(&inputs.anchor_height())?
                        .ok_or(ProposalError::AnchorNotFound(inputs.anchor_height()))?
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
                                    .and_then(|witness| {
                                        witness.ok_or(ShardTreeError::Query(
                                            QueryError::CheckpointPruned,
                                        ))
                                    })
                                    .map(|merkle_path| Some((key, note, merkle_path)))
                                    .map_err(Error::from)
                                    .transpose()
                            }
                            #[cfg(feature = "orchard")]
                            Note::Orchard(_) => None,
                        })
                        .collect::<Result<Vec<_>, Error<_, _, _, _, _, _>>>()?;

                    Ok((Some(anchor), sapling_inputs))
                })
            },
        )?
    } else {
        (None, vec![])
    };

    #[cfg(feature = "orchard")]
    let (orchard_anchor, orchard_inputs) = if proposal_step
        .involves(PoolType::Shielded(ShieldedProtocol::Orchard))
    {
        proposal_step.shielded_inputs().map_or_else(
            || Ok((Some(orchard::Anchor::empty_tree()), vec![])),
            |inputs| {
                wallet_db.with_orchard_tree_mut::<_, _, Error<_, _, _, _, _, _>>(|orchard_tree| {
                    let anchor = orchard_tree
                        .root_at_checkpoint_id(&inputs.anchor_height())?
                        .ok_or(ProposalError::AnchorNotFound(inputs.anchor_height()))?
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
                                .and_then(|witness| {
                                    witness
                                        .ok_or(ShardTreeError::Query(QueryError::CheckpointPruned))
                                })
                                .map(|merkle_path| Some((note, merkle_path)))
                                .map_err(Error::from)
                                .transpose(),
                            Note::Sapling(_) => None,
                        })
                        .collect::<Result<Vec<_>, Error<_, _, _, _, _, _>>>()?;

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
    // are no possible transparent inputs, so we ignore those here.
    let mut builder = Builder::new(
        params.clone(),
        min_target_height,
        BuildConfig::Standard {
            sapling_anchor,
            orchard_anchor,
        },
    );

    #[cfg(all(feature = "transparent-inputs", not(feature = "orchard")))]
    let has_shielded_inputs = !sapling_inputs.is_empty();
    #[cfg(all(feature = "transparent-inputs", feature = "orchard"))]
    let has_shielded_inputs = !(sapling_inputs.is_empty() && orchard_inputs.is_empty());

    for (sapling_key, sapling_note, merkle_path) in sapling_inputs.into_iter() {
        builder.add_sapling_spend(&sapling_key, sapling_note.clone(), merkle_path)?;
    }

    #[cfg(feature = "orchard")]
    for (orchard_note, merkle_path) in orchard_inputs.into_iter() {
        builder.add_orchard_spend(usk.orchard(), *orchard_note, merkle_path.into())?;
    }

    #[cfg(feature = "transparent-inputs")]
    let mut cache = HashMap::<TransparentAddress, TransparentAddressMetadata>::new();

    #[cfg(feature = "transparent-inputs")]
    let mut metadata_from_address = |addr: TransparentAddress| -> Result<
        TransparentAddressMetadata,
        CreateErrT<DbT, InputsErrT, FeeRuleT, ChangeErrT, N>,
    > {
        match cache.get(&addr) {
            Some(result) => Ok(result.clone()),
            None => {
                // `wallet_db.get_transparent_address_metadata` includes reserved ephemeral
                // addresses in its lookup. We don't need to include these in order to be
                // able to construct ZIP 320 transactions, because in that case the ephemeral
                // output is represented via a "change" reference to a previous step. However,
                // we do need them in order to create a transaction from a proposal that
                // explicitly spends an output from an ephemeral address (only for outputs
                // already detected by this wallet instance).

                let result = wallet_db
                    .get_transparent_address_metadata(account_id, &addr)
                    .map_err(InputSelectorError::DataSource)?
                    .ok_or(Error::AddressNotRecognized(addr))?;
                cache.insert(addr, result.clone());
                Ok(result)
            }
        }
    };

    #[cfg(feature = "transparent-inputs")]
    let utxos_spent = {
        let mut utxos_spent: Vec<OutPoint> = vec![];
        let add_transparent_input =
            |builder: &mut Builder<_, _>,
             utxos_spent: &mut Vec<_>,
             address_metadata: &TransparentAddressMetadata,
             outpoint: OutPoint,
             txout: TxOut|
             -> Result<(), CreateErrT<DbT, InputsErrT, FeeRuleT, ChangeErrT, N>> {
                let secret_key = usk
                    .transparent()
                    .derive_secret_key(address_metadata.scope(), address_metadata.address_index())
                    .expect("spending key derivation should not fail");

                utxos_spent.push(outpoint.clone());
                builder.add_transparent_input(secret_key, outpoint, txout)?;

                Ok(())
            };

        for utxo in proposal_step.transparent_inputs() {
            add_transparent_input(
                &mut builder,
                &mut utxos_spent,
                &metadata_from_address(*utxo.recipient_address())?,
                utxo.outpoint().clone(),
                utxo.txout().clone(),
            )?;
        }
        for input_ref in proposal_step.prior_step_inputs() {
            // A referenced transparent step output must exist and be referenced *at most* once.
            // (Exactly once in the case of ephemeral outputs.)
            let (address, outpoint) = unused_transparent_outputs
                .remove(input_ref)
                .ok_or(Error::Proposal(ProposalError::ReferenceError(*input_ref)))?;

            let address_metadata = metadata_from_address(address)?;

            let txout = &prior_step_results[input_ref.step_index()]
                .1
                .build_result
                .transaction()
                .transparent_bundle()
                .ok_or(ProposalError::ReferenceError(*input_ref))?
                .vout[outpoint.n() as usize];

            add_transparent_input(
                &mut builder,
                &mut utxos_spent,
                &address_metadata,
                outpoint,
                txout.clone(),
            )?;
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
    let mut orchard_output_meta: Vec<(
        Recipient<_, PoolType, _>,
        NonNegativeAmount,
        Option<MemoBytes>,
    )> = vec![];
    let mut sapling_output_meta: Vec<(
        Recipient<_, PoolType, _>,
        NonNegativeAmount,
        Option<MemoBytes>,
    )> = vec![];
    let mut transparent_output_meta: Vec<(
        Recipient<_, _, ()>,
        TransparentAddress,
        NonNegativeAmount,
        StepOutputIndex,
    )> = vec![];

    for (&payment_index, output_pool) in proposal_step.payment_pools() {
        let payment = proposal_step
            .transaction_request()
            .payments()
            .get(&payment_index)
            .expect(
                "The mapping between payment index and payment is checked in step construction",
            );
        let recipient_address = payment.recipient_address();

        let add_sapling_output = |builder: &mut Builder<_, _>,
                                  sapling_output_meta: &mut Vec<_>,
                                  to: sapling::PaymentAddress|
         -> Result<
            (),
            CreateErrT<DbT, InputsErrT, FeeRuleT, ChangeErrT, N>,
        > {
            let memo = payment.memo().map_or_else(MemoBytes::empty, |m| m.clone());
            builder.add_sapling_output(sapling_external_ovk, to, payment.amount(), memo.clone())?;
            sapling_output_meta.push((
                Recipient::External(recipient_address.clone(), PoolType::SAPLING),
                payment.amount(),
                Some(memo),
            ));
            Ok(())
        };

        #[cfg(feature = "orchard")]
        let add_orchard_output =
            |builder: &mut Builder<_, _>,
             orchard_output_meta: &mut Vec<_>,
             to: orchard::Address|
             -> Result<(), CreateErrT<DbT, InputsErrT, FeeRuleT, ChangeErrT, N>> {
                let memo = payment.memo().map_or_else(MemoBytes::empty, |m| m.clone());
                builder.add_orchard_output(
                    orchard_external_ovk.clone(),
                    to,
                    payment.amount().into(),
                    memo.clone(),
                )?;
                orchard_output_meta.push((
                    Recipient::External(recipient_address.clone(), PoolType::ORCHARD),
                    payment.amount(),
                    Some(memo),
                ));
                Ok(())
            };

        let add_transparent_output =
            |builder: &mut Builder<_, _>,
             transparent_output_meta: &mut Vec<_>,
             to: TransparentAddress|
             -> Result<(), CreateErrT<DbT, InputsErrT, FeeRuleT, ChangeErrT, N>> {
                // Always reject sending to one of our known ephemeral addresses.
                #[cfg(feature = "transparent-inputs")]
                if wallet_db
                    .find_account_for_ephemeral_address(&to)
                    .map_err(Error::DataSource)?
                    .is_some()
                {
                    return Err(Error::PaysEphemeralTransparentAddress(to.encode(params)));
                }
                if payment.memo().is_some() {
                    return Err(Error::MemoForbidden);
                }
                builder.add_transparent_output(&to, payment.amount())?;
                transparent_output_meta.push((
                    Recipient::External(recipient_address.clone(), PoolType::TRANSPARENT),
                    to,
                    payment.amount(),
                    StepOutputIndex::Payment(payment_index),
                ));
                Ok(())
            };

        match recipient_address
            .clone()
            .convert_if_network(params.network_type())?
        {
            Address::Unified(ua) => match output_pool {
                #[cfg(not(feature = "orchard"))]
                PoolType::Shielded(ShieldedProtocol::Orchard) => {
                    return Err(Error::ProposalNotSupported);
                }
                #[cfg(feature = "orchard")]
                PoolType::Shielded(ShieldedProtocol::Orchard) => {
                    let to = *ua.orchard().expect("The mapping between payment pool and receiver is checked in step construction");
                    add_orchard_output(&mut builder, &mut orchard_output_meta, to)?;
                }
                PoolType::Shielded(ShieldedProtocol::Sapling) => {
                    let to = *ua.sapling().expect("The mapping between payment pool and receiver is checked in step construction");
                    add_sapling_output(&mut builder, &mut sapling_output_meta, to)?;
                }
                PoolType::Transparent => {
                    let to = *ua.transparent().expect("The mapping between payment pool and receiver is checked in step construction");
                    add_transparent_output(&mut builder, &mut transparent_output_meta, to)?;
                }
            },
            Address::Sapling(to) => {
                add_sapling_output(&mut builder, &mut sapling_output_meta, to)?;
            }
            Address::Transparent(to) => {
                add_transparent_output(&mut builder, &mut transparent_output_meta, to)?;
            }
            #[cfg(not(feature = "transparent-inputs"))]
            Address::Tex(_) => {
                return Err(Error::ProposalNotSupported);
            }
            #[cfg(feature = "transparent-inputs")]
            Address::Tex(data) => {
                if has_shielded_inputs {
                    return Err(ProposalError::PaysTexFromShielded.into());
                }
                let to = TransparentAddress::PublicKeyHash(data);
                add_transparent_output(&mut builder, &mut transparent_output_meta, to)?;
            }
        }
    }

    for change_value in proposal_step.balance().proposed_change() {
        let memo = change_value
            .memo()
            .map_or_else(MemoBytes::empty, |m| m.clone());
        let output_pool = change_value.output_pool();
        match output_pool {
            PoolType::Shielded(ShieldedProtocol::Sapling) => {
                builder.add_sapling_output(
                    sapling_internal_ovk(),
                    sapling_dfvk.change_address().1,
                    change_value.value(),
                    memo.clone(),
                )?;
                sapling_output_meta.push((
                    Recipient::InternalAccount {
                        receiving_account: account_id,
                        external_address: None,
                        note: output_pool,
                    },
                    change_value.value(),
                    Some(memo),
                ))
            }
            PoolType::Shielded(ShieldedProtocol::Orchard) => {
                #[cfg(not(feature = "orchard"))]
                return Err(Error::UnsupportedChangeType(output_pool));

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
                            receiving_account: account_id,
                            external_address: None,
                            note: output_pool,
                        },
                        change_value.value(),
                        Some(memo),
                    ))
                }
            }
            PoolType::Transparent => {
                #[cfg(not(feature = "transparent-inputs"))]
                return Err(Error::UnsupportedChangeType(output_pool));
            }
        }
    }

    // This reserves the ephemeral addresses even if transaction construction fails.
    // It is not worth the complexity of being able to unreserve them, because there
    // are few failure modes after this point that would allow us to do so.
    #[cfg(feature = "transparent-inputs")]
    {
        let ephemeral_outputs: Vec<(usize, &ChangeValue)> = proposal_step
            .balance()
            .proposed_change()
            .iter()
            .enumerate()
            .filter(|(_, change_value)| {
                change_value.is_ephemeral() && change_value.output_pool() == PoolType::Transparent
            })
            .collect();

        let addresses_and_metadata = wallet_db
            .reserve_next_n_ephemeral_addresses(account_id, ephemeral_outputs.len())
            .map_err(Error::DataSource)?;
        assert_eq!(addresses_and_metadata.len(), ephemeral_outputs.len());

        // We don't need the TransparentAddressMetadata here; we can look it up from the data source later.
        for ((change_index, change_value), (ephemeral_address, _)) in
            ephemeral_outputs.iter().zip(addresses_and_metadata)
        {
            // This output is ephemeral; we will report an error in `create_proposed_transactions`
            // if a later step does not consume it.
            builder.add_transparent_output(&ephemeral_address, change_value.value())?;
            transparent_output_meta.push((
                Recipient::EphemeralTransparent {
                    receiving_account: account_id,
                    ephemeral_address,
                    outpoint_metadata: (),
                },
                ephemeral_address,
                change_value.value(),
                StepOutputIndex::Change(*change_index),
            ))
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
                        assert!(pool == PoolType::ORCHARD);
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
                        assert!(pool == PoolType::SAPLING);
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

    let txid: [u8; 32] = build_result.transaction().txid().into();
    assert_eq!(
        transparent_output_meta.len(),
        build_result
            .transaction()
            .transparent_bundle()
            .map_or(0, |b| b.vout.len()),
    );

    #[allow(unused_variables)]
    let transparent_outputs = transparent_output_meta.into_iter().enumerate().map(
        |(n, (recipient, address, value, step_output_index))| {
            // This assumes that transparent outputs are pushed onto `transparent_output_meta`
            // with the same indices they have in the transaction's transparent outputs.
            // We do not reorder transparent outputs; there is no reason to do so because it
            // would not usefully improve privacy.
            let outpoint = OutPoint::new(txid, n as u32);

            let recipient = recipient.map_ephemeral_transparent_outpoint(|()| outpoint.clone());
            #[cfg(feature = "transparent-inputs")]
            unused_transparent_outputs.insert(
                StepOutput::new(step_index, step_output_index),
                (address, outpoint),
            );
            SentTransactionOutput::from_parts(n, recipient, value, None)
        },
    );

    let mut outputs: Vec<SentTransactionOutput<_>> = vec![];
    #[cfg(feature = "orchard")]
    outputs.extend(orchard_outputs);
    outputs.extend(sapling_outputs);
    outputs.extend(transparent_outputs);

    Ok(StepResult {
        build_result,
        outputs,
        fee_amount: proposal_step.balance().fee_required(),
        #[cfg(feature = "transparent-inputs")]
        utxos_spent,
    })
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
pub fn shield_transparent_funds<DbT, ParamsT, InputsT, ChangeT>(
    wallet_db: &mut DbT,
    params: &ParamsT,
    spend_prover: &impl SpendProver,
    output_prover: &impl OutputProver,
    input_selector: &InputsT,
    change_strategy: &ChangeT,
    shielding_threshold: NonNegativeAmount,
    usk: &UnifiedSpendingKey,
    from_addrs: &[TransparentAddress],
    to_account: <DbT as InputSource>::AccountId,
    min_confirmations: u32,
) -> Result<NonEmpty<TxId>, ShieldErrT<DbT, InputsT, ChangeT>>
where
    ParamsT: consensus::Parameters,
    DbT: WalletWrite + WalletCommitmentTrees + InputSource<Error = <DbT as WalletRead>::Error>,
    InputsT: ShieldingSelector<InputSource = DbT>,
    ChangeT: ChangeStrategy<MetaSource = DbT>,
{
    let proposal = propose_shielding(
        wallet_db,
        params,
        input_selector,
        change_strategy,
        shielding_threshold,
        from_addrs,
        to_account,
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
