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
use std::num::NonZeroU32;

use shardtree::error::{QueryError, ShardTreeError};

use super::InputSource;
use crate::{
    data_api::{
        error::Error, Account, SentTransaction, SentTransactionOutput, WalletCommitmentTrees,
        WalletRead, WalletWrite,
    },
    decrypt_transaction,
    fees::{
        standard::SingleOutputChangeStrategy, ChangeStrategy, DustOutputPolicy, StandardFeeRule,
    },
    proposal::{Proposal, ProposalError, Step, StepOutputIndex},
    wallet::{Note, OvkPolicy, Recipient},
};
use ::sapling::{
    note_encryption::{try_sapling_note_decryption, PreparedIncomingViewingKey},
    prover::{OutputProver, SpendProver},
};
use ::transparent::{
    address::TransparentAddress, builder::TransparentSigningSet, bundle::OutPoint,
};
use zcash_address::ZcashAddress;
use zcash_keys::{
    address::Address,
    keys::{UnifiedFullViewingKey, UnifiedSpendingKey},
};
use zcash_primitives::transaction::{
    builder::{BuildConfig, BuildResult, Builder},
    components::sapling::zip212_enforcement,
    fees::FeeRule,
    Transaction, TxId,
};
use zcash_protocol::{
    consensus::{self, BlockHeight},
    memo::MemoBytes,
    value::Zatoshis,
    PoolType, ShieldedProtocol,
};
use zip32::Scope;
use zip321::Payment;

#[cfg(feature = "transparent-inputs")]
use {
    crate::{fees::ChangeValue, proposal::StepOutput, wallet::TransparentAddressMetadata},
    ::transparent::bundle::TxOut,
    core::convert::Infallible,
    input_selection::ShieldingSelector,
    std::collections::HashMap,
    zcash_keys::encoding::AddressCodec,
};

#[cfg(feature = "pczt")]
use {
    crate::data_api::error::PcztError,
    ::transparent::pczt::Bip32Derivation,
    bip32::ChildNumber,
    orchard::note_encryption::OrchardDomain,
    pczt::roles::{
        creator::Creator, io_finalizer::IoFinalizer, spend_finalizer::SpendFinalizer,
        tx_extractor::TransactionExtractor, updater::Updater,
    },
    sapling::note_encryption::SaplingDomain,
    serde::{Deserialize, Serialize},
    zcash_note_encryption::try_output_recovery_with_pkd_esk,
    zcash_protocol::{
        consensus::NetworkConstants,
        value::{BalanceError, ZatBalance},
    },
};

pub mod input_selection;
use input_selection::{GreedyInputSelector, InputSelector, InputSelectorError};

#[cfg(feature = "pczt")]
const PROPRIETARY_PROPOSAL_INFO: &str = "zcash_client_backend:proposal_info";
#[cfg(feature = "pczt")]
const PROPRIETARY_OUTPUT_INFO: &str = "zcash_client_backend:output_info";

/// Information about the proposal from which a PCZT was created.
///
/// Stored under the proprietary field `PROPRIETARY_PROPOSAL_INFO`.
#[cfg(feature = "pczt")]
#[derive(Serialize, Deserialize)]
struct ProposalInfo<AccountId> {
    from_account: AccountId,
    target_height: u32,
}

/// Reduced version of [`Recipient`] stored inside a PCZT.
///
/// Stored under the proprietary field `PROPRIETARY_OUTPUT_INFO`.
#[cfg(feature = "pczt")]
#[derive(Serialize, Deserialize)]
enum PcztRecipient<AccountId> {
    External,
    #[cfg(feature = "transparent-inputs")]
    EphemeralTransparent {
        receiving_account: AccountId,
    },
    InternalAccount {
        receiving_account: AccountId,
    },
}

#[cfg(feature = "pczt")]
impl<AccountId: Copy> PcztRecipient<AccountId> {
    fn from_recipient(recipient: BuildRecipient<AccountId>) -> (Self, Option<ZcashAddress>) {
        match recipient {
            BuildRecipient::External {
                recipient_address, ..
            } => (PcztRecipient::External, Some(recipient_address)),
            #[cfg(feature = "transparent-inputs")]
            BuildRecipient::EphemeralTransparent {
                receiving_account, ..
            } => (
                PcztRecipient::EphemeralTransparent { receiving_account },
                None,
            ),
            BuildRecipient::InternalAccount {
                receiving_account,
                external_address,
            } => (
                PcztRecipient::InternalAccount { receiving_account },
                external_address,
            ),
        }
    }
}

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

    data.store_decrypted_tx(decrypt_transaction(
        params,
        mined_height.map_or_else(|| data.get_tx_height(tx.txid()), |h| Ok(Some(h)))?,
        data.chain_height()?,
        tx,
        &ufvks,
    ))?;

    Ok(())
}

/// Errors that may be generated in construction of proposals for shielded->shielded or
/// shielded->transparent transfers.
pub type ProposeTransferErrT<DbT, CommitmentTreeErrT, InputsT, ChangeT> = Error<
    <DbT as WalletRead>::Error,
    CommitmentTreeErrT,
    <InputsT as InputSelector>::Error,
    <<ChangeT as ChangeStrategy>::FeeRule as FeeRule>::Error,
    <ChangeT as ChangeStrategy>::Error,
    <<InputsT as InputSelector>::InputSource as InputSource>::NoteRef,
>;

/// Errors that may be generated in construction of proposals for transparent->shielded
/// wallet-internal transfers.
#[cfg(feature = "transparent-inputs")]
pub type ProposeShieldingErrT<DbT, CommitmentTreeErrT, InputsT, ChangeT> = Error<
    <DbT as WalletRead>::Error,
    CommitmentTreeErrT,
    <InputsT as ShieldingSelector>::Error,
    <<ChangeT as ChangeStrategy>::FeeRule as FeeRule>::Error,
    <ChangeT as ChangeStrategy>::Error,
    Infallible,
>;

/// Errors that may be generated in combined creation and execution of transaction proposals.
pub type CreateErrT<DbT, InputsErrT, FeeRuleT, ChangeErrT, N> = Error<
    <DbT as WalletRead>::Error,
    <DbT as WalletCommitmentTrees>::Error,
    InputsErrT,
    <FeeRuleT as FeeRule>::Error,
    ChangeErrT,
    N,
>;

/// Errors that may be generated in the execution of proposals that may send shielded inputs.
pub type TransferErrT<DbT, InputsT, ChangeT> = Error<
    <DbT as WalletRead>::Error,
    <DbT as WalletCommitmentTrees>::Error,
    <InputsT as InputSelector>::Error,
    <<ChangeT as ChangeStrategy>::FeeRule as FeeRule>::Error,
    <ChangeT as ChangeStrategy>::Error,
    <<InputsT as InputSelector>::InputSource as InputSource>::NoteRef,
>;

/// Errors that may be generated in the execution of shielding proposals.
#[cfg(feature = "transparent-inputs")]
pub type ShieldErrT<DbT, InputsT, ChangeT> = Error<
    <DbT as WalletRead>::Error,
    <DbT as WalletCommitmentTrees>::Error,
    <InputsT as ShieldingSelector>::Error,
    <<ChangeT as ChangeStrategy>::FeeRule as FeeRule>::Error,
    <ChangeT as ChangeStrategy>::Error,
    Infallible,
>;

/// Errors that may be generated when extracting a transaction from a PCZT.
#[cfg(feature = "pczt")]
pub type ExtractErrT<DbT, N> = Error<
    <DbT as WalletRead>::Error,
    <DbT as WalletCommitmentTrees>::Error,
    Infallible,
    Infallible,
    Infallible,
    N,
>;

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
    amount: Zatoshis,
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

/// Select transaction inputs, compute fees, and construct a proposal for a transaction or series
/// of transactions that would spend all available funds from the given `spend_pool`s that can then
/// be authorized and made ready for submission to the network with [`create_proposed_transactions`].
#[allow(clippy::too_many_arguments)]
#[allow(clippy::type_complexity)]
pub fn propose_send_max_transfer<DbT, ParamsT, InputsT, ChangeT, CommitmentTreeErrT>(
    wallet_db: &mut DbT,
    params: &ParamsT,
    spend_from_account: <DbT as InputSource>::AccountId,
    spend_pool: &[ShieldedProtocol],
    input_selector: &InputsT,
    change_strategy: &ChangeT,
    recipient: &Address,
    memo: Option<MemoBytes>,
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
        .propose_send_max(
            params,
            wallet_db,
            change_strategy,
            spend_from_account,
            spend_pool,
            anchor_height,
            target_height,
            recipient.to_zcash_address(params),
            memo,
        )
        .map_err(Error::from)
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
    shielding_threshold: Zatoshis,
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
    fee_amount: Zatoshis,
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
    let mut transactions = Vec::with_capacity(step_results.len());
    let mut txids = Vec::with_capacity(step_results.len());
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

#[derive(Debug, Clone)]
enum BuildRecipient<AccountId> {
    External {
        recipient_address: ZcashAddress,
        output_pool: PoolType,
    },
    #[cfg(feature = "transparent-inputs")]
    EphemeralTransparent {
        receiving_account: AccountId,
        ephemeral_address: TransparentAddress,
    },
    InternalAccount {
        receiving_account: AccountId,
        external_address: Option<ZcashAddress>,
    },
}

impl<AccountId> BuildRecipient<AccountId> {
    fn into_recipient_with_note(self, note: impl FnOnce() -> Note) -> Recipient<AccountId> {
        match self {
            BuildRecipient::External {
                recipient_address,
                output_pool,
            } => Recipient::External {
                recipient_address,
                output_pool,
            },
            #[cfg(feature = "transparent-inputs")]
            BuildRecipient::EphemeralTransparent { .. } => unreachable!(),
            BuildRecipient::InternalAccount {
                receiving_account,
                external_address,
            } => Recipient::InternalAccount {
                receiving_account,
                external_address,
                note: Box::new(note()),
            },
        }
    }

    fn into_recipient_with_outpoint(
        self,
        #[cfg(feature = "transparent-inputs")] outpoint: OutPoint,
    ) -> Recipient<AccountId> {
        match self {
            BuildRecipient::External {
                recipient_address,
                output_pool,
            } => Recipient::External {
                recipient_address,
                output_pool,
            },
            #[cfg(feature = "transparent-inputs")]
            BuildRecipient::EphemeralTransparent {
                receiving_account,
                ephemeral_address,
            } => Recipient::EphemeralTransparent {
                receiving_account,
                ephemeral_address,
                outpoint,
            },
            BuildRecipient::InternalAccount { .. } => unreachable!(),
        }
    }
}

#[allow(clippy::type_complexity)]
struct BuildState<'a, P, AccountId> {
    #[cfg(feature = "transparent-inputs")]
    step_index: usize,
    builder: Builder<'a, P, ()>,
    #[cfg(feature = "transparent-inputs")]
    transparent_input_addresses: HashMap<TransparentAddress, TransparentAddressMetadata>,
    #[cfg(feature = "orchard")]
    orchard_output_meta: Vec<(BuildRecipient<AccountId>, Zatoshis, Option<MemoBytes>)>,
    sapling_output_meta: Vec<(BuildRecipient<AccountId>, Zatoshis, Option<MemoBytes>)>,
    transparent_output_meta: Vec<(
        BuildRecipient<AccountId>,
        TransparentAddress,
        Zatoshis,
        StepOutputIndex,
    )>,
    #[cfg(feature = "transparent-inputs")]
    utxos_spent: Vec<OutPoint>,
}

// `unused_transparent_outputs` maps `StepOutput`s for transparent outputs
// that have not been consumed so far, to the corresponding pair of
// `TransparentAddress` and `Outpoint`.
#[allow(clippy::too_many_arguments)]
#[allow(clippy::type_complexity)]
fn build_proposed_transaction<DbT, ParamsT, InputsErrT, FeeRuleT, ChangeErrT, N>(
    wallet_db: &mut DbT,
    params: &ParamsT,
    ufvk: &UnifiedFullViewingKey,
    account_id: <DbT as WalletRead>::AccountId,
    ovk_policy: OvkPolicy,
    min_target_height: BlockHeight,
    prior_step_results: &[(&Step<N>, StepResult<<DbT as WalletRead>::AccountId>)],
    proposal_step: &Step<N>,
    #[cfg(feature = "transparent-inputs")] unused_transparent_outputs: &mut HashMap<
        StepOutput,
        (TransparentAddress, OutPoint),
    >,
) -> Result<
    BuildState<'static, ParamsT, DbT::AccountId>,
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
                            Note::Sapling(note) => sapling_tree
                                .witness_at_checkpoint_id_caching(
                                    selected.note_commitment_tree_position(),
                                    &inputs.anchor_height(),
                                )
                                .and_then(|witness| {
                                    witness
                                        .ok_or(ShardTreeError::Query(QueryError::CheckpointPruned))
                                })
                                .map(|merkle_path| {
                                    Some((selected.spending_key_scope(), note, merkle_path))
                                })
                                .map_err(Error::from)
                                .transpose(),
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

    for (_sapling_key_scope, sapling_note, merkle_path) in sapling_inputs.into_iter() {
        let key = match _sapling_key_scope {
            Scope::External => ufvk.sapling().map(|k| k.fvk().clone()),
            Scope::Internal => ufvk.sapling().map(|k| k.to_internal_fvk()),
        };

        builder.add_sapling_spend(
            key.ok_or(Error::KeyNotAvailable(PoolType::SAPLING))?,
            sapling_note.clone(),
            merkle_path,
        )?;
    }

    #[cfg(feature = "orchard")]
    for (orchard_note, merkle_path) in orchard_inputs.into_iter() {
        builder.add_orchard_spend(
            ufvk.orchard()
                .cloned()
                .ok_or(Error::KeyNotAvailable(PoolType::ORCHARD))?,
            *orchard_note,
            merkle_path.into(),
        )?;
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
        let add_transparent_input = |builder: &mut Builder<_, _>,
                                     utxos_spent: &mut Vec<_>,
                                     address_metadata: &TransparentAddressMetadata,
                                     outpoint: OutPoint,
                                     txout: TxOut|
         -> Result<
            (),
            CreateErrT<DbT, InputsErrT, FeeRuleT, ChangeErrT, N>,
        > {
            let pubkey = ufvk
                .transparent()
                .ok_or(Error::KeyNotAvailable(PoolType::Transparent))?
                .derive_address_pubkey(address_metadata.scope(), address_metadata.address_index())
                .expect("spending key derivation should not fail");

            utxos_spent.push(outpoint.clone());
            builder.add_transparent_input(pubkey, outpoint, txout)?;

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
    let orchard_external_ovk = match &ovk_policy {
        OvkPolicy::Sender => ufvk
            .orchard()
            .map(|fvk| fvk.to_ovk(orchard::keys::Scope::External)),
        OvkPolicy::Custom { orchard, .. } => Some(orchard.clone()),
        OvkPolicy::Discard => None,
    };

    #[cfg(feature = "orchard")]
    let orchard_internal_ovk = || {
        #[cfg(feature = "transparent-inputs")]
        if proposal_step.is_shielding() {
            return ufvk
                .transparent()
                .map(|k| orchard::keys::OutgoingViewingKey::from(k.internal_ovk().as_bytes()));
        }

        ufvk.orchard().map(|k| k.to_ovk(Scope::Internal))
    };

    // Apply the outgoing viewing key policy.
    let sapling_external_ovk = match &ovk_policy {
        OvkPolicy::Sender => ufvk.sapling().map(|k| k.to_ovk(Scope::External)),
        OvkPolicy::Custom { sapling, .. } => Some(*sapling),
        OvkPolicy::Discard => None,
    };

    let sapling_internal_ovk = || {
        #[cfg(feature = "transparent-inputs")]
        if proposal_step.is_shielding() {
            return ufvk
                .transparent()
                .map(|k| sapling::keys::OutgoingViewingKey(k.internal_ovk().as_bytes()));
        }

        ufvk.sapling().map(|k| k.to_ovk(Scope::Internal))
    };

    #[cfg(feature = "orchard")]
    let mut orchard_output_meta: Vec<(BuildRecipient<_>, Zatoshis, Option<MemoBytes>)> = vec![];
    let mut sapling_output_meta: Vec<(BuildRecipient<_>, Zatoshis, Option<MemoBytes>)> = vec![];
    let mut transparent_output_meta: Vec<(
        BuildRecipient<_>,
        TransparentAddress,
        Zatoshis,
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
                BuildRecipient::External {
                    recipient_address: recipient_address.clone(),
                    output_pool: PoolType::SAPLING,
                },
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
                    BuildRecipient::External {
                        recipient_address: recipient_address.clone(),
                        output_pool: PoolType::ORCHARD,
                    },
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
                    BuildRecipient::External {
                        recipient_address: recipient_address.clone(),
                        output_pool: PoolType::TRANSPARENT,
                    },
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
                    ufvk.sapling()
                        .ok_or(Error::KeyNotAvailable(PoolType::SAPLING))?
                        .change_address()
                        .1,
                    change_value.value(),
                    memo.clone(),
                )?;
                sapling_output_meta.push((
                    BuildRecipient::InternalAccount {
                        receiving_account: account_id,
                        external_address: None,
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
                        ufvk.orchard()
                            .ok_or(Error::KeyNotAvailable(PoolType::ORCHARD))?
                            .address_at(0u32, orchard::keys::Scope::Internal),
                        change_value.value().into(),
                        memo.clone(),
                    )?;
                    orchard_output_meta.push((
                        BuildRecipient::InternalAccount {
                            receiving_account: account_id,
                            external_address: None,
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
                BuildRecipient::EphemeralTransparent {
                    receiving_account: account_id,
                    ephemeral_address,
                },
                ephemeral_address,
                change_value.value(),
                StepOutputIndex::Change(*change_index),
            ))
        }
    }

    Ok(BuildState {
        #[cfg(feature = "transparent-inputs")]
        step_index,
        builder,
        #[cfg(feature = "transparent-inputs")]
        transparent_input_addresses: cache,
        #[cfg(feature = "orchard")]
        orchard_output_meta,
        sapling_output_meta,
        transparent_output_meta,
        #[cfg(feature = "transparent-inputs")]
        utxos_spent,
    })
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
    let build_state = build_proposed_transaction::<_, _, _, FeeRuleT, _, _>(
        wallet_db,
        params,
        &usk.to_unified_full_viewing_key(),
        account_id,
        ovk_policy,
        min_target_height,
        prior_step_results,
        proposal_step,
        #[cfg(feature = "transparent-inputs")]
        unused_transparent_outputs,
    )?;

    // Build the transaction with the specified fee rule
    #[cfg_attr(not(feature = "transparent-inputs"), allow(unused_mut))]
    let mut transparent_signing_set = TransparentSigningSet::new();
    #[cfg(feature = "transparent-inputs")]
    for (_, address_metadata) in build_state.transparent_input_addresses {
        transparent_signing_set.add_key(
            usk.transparent()
                .derive_secret_key(address_metadata.scope(), address_metadata.address_index())
                .expect("spending key derivation should not fail"),
        );
    }
    let sapling_extsks = &[usk.sapling().clone(), usk.sapling().derive_internal()];
    #[cfg(feature = "orchard")]
    let orchard_saks = &[usk.orchard().into()];
    #[cfg(not(feature = "orchard"))]
    let orchard_saks = &[];
    let build_result = build_state.builder.build(
        &transparent_signing_set,
        sapling_extsks,
        orchard_saks,
        OsRng,
        spend_prover,
        output_prover,
        fee_rule,
    )?;

    #[cfg(feature = "orchard")]
    let orchard_fvk: orchard::keys::FullViewingKey = usk.orchard().into();
    #[cfg(feature = "orchard")]
    let orchard_internal_ivk = orchard_fvk.to_ivk(orchard::keys::Scope::Internal);
    #[cfg(feature = "orchard")]
    let orchard_outputs = build_state.orchard_output_meta.into_iter().enumerate().map(
        |(i, (recipient, value, memo))| {
            let output_index = build_result
                .orchard_meta()
                .output_action_index(i)
                .expect("An action should exist in the transaction for each Orchard output.");

            let recipient = recipient.into_recipient_with_note(|| {
                build_result
                    .transaction()
                    .orchard_bundle()
                    .and_then(|bundle| {
                        bundle
                            .decrypt_output_with_key(output_index, &orchard_internal_ivk)
                            .map(|(note, _, _)| Note::Orchard(note))
                    })
                    .expect("Wallet-internal outputs must be decryptable with the wallet's IVK")
            });

            SentTransactionOutput::from_parts(output_index, recipient, value, memo)
        },
    );

    let sapling_dfvk = usk.sapling().to_diversifiable_full_viewing_key();
    let sapling_internal_ivk =
        PreparedIncomingViewingKey::new(&sapling_dfvk.to_ivk(Scope::Internal));
    let sapling_outputs = build_state.sapling_output_meta.into_iter().enumerate().map(
        |(i, (recipient, value, memo))| {
            let output_index = build_result
                .sapling_meta()
                .output_index(i)
                .expect("An output should exist in the transaction for each Sapling payment.");

            let recipient = recipient.into_recipient_with_note(|| {
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
                    .expect("Wallet-internal outputs must be decryptable with the wallet's IVK")
            });

            SentTransactionOutput::from_parts(output_index, recipient, value, memo)
        },
    );

    let txid: [u8; 32] = build_result.transaction().txid().into();
    assert_eq!(
        build_state.transparent_output_meta.len(),
        build_result
            .transaction()
            .transparent_bundle()
            .map_or(0, |b| b.vout.len()),
    );

    #[allow(unused_variables)]
    let transparent_outputs = build_state
        .transparent_output_meta
        .into_iter()
        .enumerate()
        .map(|(n, (recipient, address, value, step_output_index))| {
            // This assumes that transparent outputs are pushed onto `transparent_output_meta`
            // with the same indices they have in the transaction's transparent outputs.
            // We do not reorder transparent outputs; there is no reason to do so because it
            // would not usefully improve privacy.
            let outpoint = OutPoint::new(txid, n as u32);

            let recipient = recipient.into_recipient_with_outpoint(
                #[cfg(feature = "transparent-inputs")]
                outpoint.clone(),
            );

            #[cfg(feature = "transparent-inputs")]
            unused_transparent_outputs.insert(
                StepOutput::new(build_state.step_index, step_output_index),
                (address, outpoint),
            );
            SentTransactionOutput::from_parts(n, recipient, value, None)
        });

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
        utxos_spent: build_state.utxos_spent,
    })
}

/// Constructs a transaction using the inputs supplied by the given proposal.
///
/// Only single-step proposals are currently supported.
///
/// Returns a partially-created Zcash transaction (PCZT) that is ready to be authorized.
/// You can use the following roles for this:
/// - [`pczt::roles::prover::Prover`]
/// - [`pczt::roles::signer::Signer`] (if you have local access to the spend authorizing
///   keys)
/// - [`pczt::roles::combiner::Combiner`] (if you create proofs and apply signatures in
///   parallel)
///
/// Once the PCZT fully authorized, call [`extract_and_store_transaction_from_pczt`] to
/// finish transaction creation.
#[allow(clippy::too_many_arguments)]
#[allow(clippy::type_complexity)]
#[cfg(feature = "pczt")]
pub fn create_pczt_from_proposal<DbT, ParamsT, InputsErrT, FeeRuleT, ChangeErrT, N>(
    wallet_db: &mut DbT,
    params: &ParamsT,
    account_id: <DbT as WalletRead>::AccountId,
    ovk_policy: OvkPolicy,
    proposal: &Proposal<FeeRuleT, N>,
) -> Result<pczt::Pczt, CreateErrT<DbT, InputsErrT, FeeRuleT, ChangeErrT, N>>
where
    DbT: WalletWrite + WalletCommitmentTrees,
    ParamsT: consensus::Parameters + Clone,
    FeeRuleT: FeeRule,
    DbT::AccountId: serde::Serialize,
{
    use std::collections::HashSet;

    let account = wallet_db
        .get_account(account_id)
        .map_err(Error::DataSource)?
        .ok_or(Error::AccountIdNotRecognized)?;
    let ufvk = account.ufvk().ok_or(Error::AccountCannotSpend)?;
    let account_derivation = account.source().key_derivation();

    // For now we only support turning single-step proposals into PCZTs.
    if proposal.steps().len() > 1 {
        return Err(Error::ProposalNotSupported);
    }
    let fee_rule = proposal.fee_rule();
    let min_target_height = proposal.min_target_height();
    let prior_step_results = &[];
    let proposal_step = proposal.steps().first();
    let unused_transparent_outputs = &mut HashMap::new();

    let build_state = build_proposed_transaction::<_, _, _, FeeRuleT, _, _>(
        wallet_db,
        params,
        ufvk,
        account_id,
        ovk_policy,
        min_target_height,
        prior_step_results,
        proposal_step,
        #[cfg(feature = "transparent-inputs")]
        unused_transparent_outputs,
    )?;

    // Build the transaction with the specified fee rule
    let build_result = build_state.builder.build_for_pczt(OsRng, fee_rule)?;

    let created = Creator::build_from_parts(build_result.pczt_parts).ok_or(PcztError::Build)?;

    let io_finalized = IoFinalizer::new(created).finalize_io()?;

    #[cfg(feature = "orchard")]
    let orchard_outputs = build_state
        .orchard_output_meta
        .into_iter()
        .enumerate()
        .map(|(i, (recipient, _, _))| {
            let output_index = build_result
                .orchard_meta
                .output_action_index(i)
                .expect("An action should exist in the transaction for each Orchard output.");

            (output_index, PcztRecipient::from_recipient(recipient))
        })
        .collect::<HashMap<_, _>>();

    #[cfg(feature = "orchard")]
    let orchard_spends = (0..)
        .map(|i| build_result.orchard_meta.spend_action_index(i))
        .take_while(|item| item.is_some())
        .flatten()
        .collect::<HashSet<_>>();

    let sapling_outputs = build_state
        .sapling_output_meta
        .into_iter()
        .enumerate()
        .map(|(i, (recipient, _, _))| {
            let output_index = build_result
                .sapling_meta
                .output_index(i)
                .expect("An output should exist in the transaction for each Sapling output.");

            (output_index, PcztRecipient::from_recipient(recipient))
        })
        .collect::<HashMap<_, _>>();

    let pczt = Updater::new(io_finalized)
        .update_global_with(|mut updater| {
            updater.set_proprietary(
                PROPRIETARY_PROPOSAL_INFO.into(),
                postcard::to_allocvec(&ProposalInfo::<DbT::AccountId> {
                    from_account: account_id,
                    target_height: proposal.min_target_height().into(),
                })
                .expect("postcard encoding of PCZT proposal metadata should not fail"),
            )
        })
        .update_orchard_with(|mut updater| {
            for index in 0..updater.bundle().actions().len() {
                updater.update_action_with(index, |mut action_updater| {
                    // If the account has a known derivation, add the Orchard key path to the PCZT.
                    if let Some(derivation) = account_derivation {
                        // orchard_spends will only contain action indices for the real spends, and
                        // not the dummy inputs
                        if orchard_spends.contains(&index) {
                            // All spent notes are from the same account.
                            action_updater.set_spend_zip32_derivation(
                                orchard::pczt::Zip32Derivation::parse(
                                    derivation.seed_fingerprint().to_bytes(),
                                    vec![
                                        zip32::ChildIndex::hardened(32).index(),
                                        zip32::ChildIndex::hardened(
                                            params.network_type().coin_type(),
                                        )
                                        .index(),
                                        zip32::ChildIndex::hardened(u32::from(
                                            derivation.account_index(),
                                        ))
                                        .index(),
                                    ],
                                )
                                .expect("valid"),
                            );
                        }
                    }

                    if let Some((pczt_recipient, external_address)) = orchard_outputs.get(&index) {
                        if let Some(user_address) = external_address {
                            action_updater.set_output_user_address(user_address.encode());
                        }
                        action_updater.set_output_proprietary(
                            PROPRIETARY_OUTPUT_INFO.into(),
                            postcard::to_allocvec(pczt_recipient).expect(
                                "postcard encoding of PCZT recipient metadata should not fail",
                            ),
                        );
                    }

                    Ok(())
                })?;
            }
            Ok(())
        })?
        .update_sapling_with(|mut updater| {
            // If the account has a known derivation, add the Sapling key path to the PCZT.
            if let Some(derivation) = account_derivation {
                let non_dummy_spends = updater
                    .bundle()
                    .spends()
                    .iter()
                    .enumerate()
                    .filter_map(|(index, spend)| {
                        // Dummy spends will already have a proof generation key.
                        spend.proof_generation_key().is_none().then_some(index)
                    })
                    .collect::<Vec<_>>();

                for index in non_dummy_spends {
                    updater.update_spend_with(index, |mut spend_updater| {
                        // All non-dummy spent notes are from the same account.
                        spend_updater.set_zip32_derivation(
                            sapling::pczt::Zip32Derivation::parse(
                                derivation.seed_fingerprint().to_bytes(),
                                vec![
                                    zip32::ChildIndex::hardened(32).index(),
                                    zip32::ChildIndex::hardened(params.network_type().coin_type())
                                        .index(),
                                    zip32::ChildIndex::hardened(u32::from(
                                        derivation.account_index(),
                                    ))
                                    .index(),
                                ],
                            )
                            .expect("valid"),
                        );
                        Ok(())
                    })?;
                }
            }

            for index in 0..updater.bundle().outputs().len() {
                if let Some((pczt_recipient, external_address)) = sapling_outputs.get(&index) {
                    updater.update_output_with(index, |mut output_updater| {
                        if let Some(user_address) = external_address {
                            output_updater.set_user_address(user_address.encode());
                        }
                        output_updater.set_proprietary(
                            PROPRIETARY_OUTPUT_INFO.into(),
                            postcard::to_allocvec(pczt_recipient).expect(
                                "postcard encoding of PCZT recipient metadata should not fail",
                            ),
                        );
                        Ok(())
                    })?;
                }
            }

            Ok(())
        })?
        .update_transparent_with(|mut updater| {
            // If the account has a known derivation, add the transparent key paths to the PCZT.
            if let Some(derivation) = account_derivation {
                // Match address metadata to the inputs that spend from those addresses.
                let inputs_to_update = updater
                    .bundle()
                    .inputs()
                    .iter()
                    .enumerate()
                    .filter_map(|(index, input)| {
                        build_state
                            .transparent_input_addresses
                            .get(
                                &input
                                    .script_pubkey()
                                    .address()
                                    .expect("we created this with a supported transparent address"),
                            )
                            .map(|address_metadata| {
                                (
                                    index,
                                    address_metadata.scope(),
                                    address_metadata.address_index(),
                                )
                            })
                    })
                    .collect::<Vec<_>>();

                for (index, scope, address_index) in inputs_to_update {
                    updater.update_input_with(index, |mut input_updater| {
                        let pubkey = ufvk
                            .transparent()
                            .expect("we derived this successfully in build_proposed_transaction")
                            .derive_address_pubkey(scope, address_index)
                            .expect("spending key derivation should not fail");

                        input_updater.set_bip32_derivation(
                            pubkey.serialize(),
                            Bip32Derivation::parse(
                                derivation.seed_fingerprint().to_bytes(),
                                vec![
                                    // Transparent uses BIP 44 derivation.
                                    44 | ChildNumber::HARDENED_FLAG,
                                    params.network_type().coin_type() | ChildNumber::HARDENED_FLAG,
                                    u32::from(derivation.account_index())
                                        | ChildNumber::HARDENED_FLAG,
                                    ChildNumber::from(scope).into(),
                                    ChildNumber::from(address_index).into(),
                                ],
                            )
                            .expect("valid"),
                        );
                        Ok(())
                    })?;
                }
            }

            assert_eq!(
                build_state.transparent_output_meta.len(),
                updater.bundle().outputs().len(),
            );
            for (index, (recipient, _, _, _)) in
                build_state.transparent_output_meta.into_iter().enumerate()
            {
                updater.update_output_with(index, |mut output_updater| {
                    let (pczt_recipient, external_address) =
                        PcztRecipient::from_recipient(recipient);
                    if let Some(user_address) = external_address {
                        output_updater.set_user_address(user_address.encode());
                    }
                    output_updater.set_proprietary(
                        PROPRIETARY_OUTPUT_INFO.into(),
                        postcard::to_allocvec(&pczt_recipient)
                            .expect("postcard encoding of pczt recipient metadata should not fail"),
                    );
                    Ok(())
                })?;
            }

            Ok(())
        })?
        .finish();

    Ok(pczt)
}

/// Finalizes the given PCZT, and persists the transaction to the wallet database.
///
/// The PCZT should have been created via [`create_pczt_from_proposal`], which adds
/// metadata necessary for the wallet backend.
///
/// Returns the transaction ID for the resulting transaction.
///
/// - `sapling_vk` is optional to allow the caller to check whether a PCZT has Sapling
///   with [`pczt::roles::prover::Prover::requires_sapling_proofs`], and avoid downloading
///   the Sapling parameters if they are not needed. If `sapling_vk` is `None`, and the
///   PCZT has a Sapling bundle, this function will return an error.
/// - `orchard_vk` is optional to allow the caller to control where the Orchard verifying
///   key is generated or cached. If `orchard_vk` is `None`, and the PCZT has an Orchard
///   bundle, an Orchard verifying key will be generated on the fly.
#[cfg(feature = "pczt")]
pub fn extract_and_store_transaction_from_pczt<DbT, N>(
    wallet_db: &mut DbT,
    pczt: pczt::Pczt,
    sapling_vk: Option<(
        &sapling::circuit::SpendVerifyingKey,
        &sapling::circuit::OutputVerifyingKey,
    )>,
    #[cfg(feature = "orchard")] orchard_vk: Option<&orchard::circuit::VerifyingKey>,
) -> Result<TxId, ExtractErrT<DbT, N>>
where
    DbT: WalletWrite + WalletCommitmentTrees,
    DbT::AccountId: serde::de::DeserializeOwned,
{
    use std::collections::BTreeMap;
    use zcash_note_encryption::{Domain, ShieldedOutput, ENC_CIPHERTEXT_SIZE};

    let finalized = SpendFinalizer::new(pczt).finalize_spends()?;

    let proposal_info = finalized
        .global()
        .proprietary()
        .get(PROPRIETARY_PROPOSAL_INFO)
        .ok_or_else(|| PcztError::Invalid("PCZT missing proprietary proposal info field".into()))
        .and_then(|v| {
            postcard::from_bytes::<ProposalInfo<DbT::AccountId>>(v).map_err(|e| {
                PcztError::Invalid(format!(
                    "Postcard decoding of proprietary proposal info failed: {e}"
                ))
            })
        })?;

    let orchard_output_info = finalized
        .orchard()
        .actions()
        .iter()
        .map(|act| {
            let note = || {
                let recipient =
                    act.output().recipient().as_ref().and_then(|b| {
                        ::orchard::Address::from_raw_address_bytes(b).into_option()
                    })?;
                let value = act
                    .output()
                    .value()
                    .map(orchard::value::NoteValue::from_raw)?;
                let rho = orchard::note::Rho::from_bytes(act.spend().nullifier()).into_option()?;
                let rseed = act.output().rseed().as_ref().and_then(|rseed| {
                    orchard::note::RandomSeed::from_bytes(*rseed, &rho).into_option()
                })?;

                orchard::Note::from_parts(recipient, value, rho, rseed).into_option()
            };

            let external_address = act
                .output()
                .user_address()
                .as_deref()
                .map(ZcashAddress::try_from_encoded)
                .transpose()
                .map_err(|e| PcztError::Invalid(format!("Invalid user_address: {e}")))?;

            let pczt_recipient = act
                .output()
                .proprietary()
                .get(PROPRIETARY_OUTPUT_INFO)
                .map(|v| postcard::from_bytes::<PcztRecipient<DbT::AccountId>>(v))
                .transpose()
                .map_err(|e: postcard::Error| {
                    PcztError::Invalid(format!(
                        "Postcard decoding of proprietary output info failed: {e}"
                    ))
                })?
                .map(|pczt_recipient| (pczt_recipient, external_address));

            // If the pczt recipient is not present, this is a dummy note; if the note is not
            // present, then the PCZT has been pruned to make this output unrecoverable and so we
            // also ignore it.
            Ok(pczt_recipient.zip(note()))
        })
        .collect::<Result<Vec<_>, PcztError>>()?;

    let sapling_output_info = finalized
        .sapling()
        .outputs()
        .iter()
        .map(|out| {
            let note = || {
                let recipient = out
                    .recipient()
                    .as_ref()
                    .and_then(::sapling::PaymentAddress::from_bytes)?;
                let value = out.value().map(::sapling::value::NoteValue::from_raw)?;
                let rseed = out
                    .rseed()
                    .as_ref()
                    .cloned()
                    .map(::sapling::note::Rseed::AfterZip212)?;

                Some(::sapling::Note::from_parts(recipient, value, rseed))
            };

            let external_address = out
                .user_address()
                .as_deref()
                .map(ZcashAddress::try_from_encoded)
                .transpose()
                .map_err(|e| PcztError::Invalid(format!("Invalid user_address: {e}")))?;

            let pczt_recipient = out
                .proprietary()
                .get(PROPRIETARY_OUTPUT_INFO)
                .map(|v| postcard::from_bytes::<PcztRecipient<DbT::AccountId>>(v))
                .transpose()
                .map_err(|e: postcard::Error| {
                    PcztError::Invalid(format!(
                        "Postcard decoding of proprietary output info failed: {e}"
                    ))
                })?
                .map(|pczt_recipient| (pczt_recipient, external_address));

            // If the pczt recipient is not present, this is a dummy note; if the note is not
            // present, then the PCZT has been pruned to make this output unrecoverable and so we
            // also ignore it.
            Ok(pczt_recipient.zip(note()))
        })
        .collect::<Result<Vec<_>, PcztError>>()?;

    let transparent_output_info = finalized
        .transparent()
        .outputs()
        .iter()
        .map(|out| {
            let external_address = out
                .user_address()
                .as_deref()
                .map(ZcashAddress::try_from_encoded)
                .transpose()
                .map_err(|e| PcztError::Invalid(format!("Invalid user_address: {e}")))?;

            let pczt_recipient = out
                .proprietary()
                .get(PROPRIETARY_OUTPUT_INFO)
                .map(|v| postcard::from_bytes::<PcztRecipient<DbT::AccountId>>(v))
                .transpose()
                .map_err(|e: postcard::Error| {
                    PcztError::Invalid(format!(
                        "Postcard decoding of proprietary output info failed: {e}"
                    ))
                })?
                .map(|pczt_recipient| (pczt_recipient, external_address));

            Ok(pczt_recipient)
        })
        .collect::<Result<Vec<_>, PcztError>>()?;

    let utxos_map = finalized
        .transparent()
        .inputs()
        .iter()
        .map(|input| {
            ZatBalance::from_u64(*input.value()).map(|value| {
                (
                    OutPoint::new(*input.prevout_txid(), *input.prevout_index()),
                    value,
                )
            })
        })
        .collect::<Result<BTreeMap<_, _>, _>>()?;

    let mut tx_extractor = TransactionExtractor::new(finalized);
    if let Some((spend_vk, output_vk)) = sapling_vk {
        tx_extractor = tx_extractor.with_sapling(spend_vk, output_vk);
    }
    if let Some(orchard_vk) = orchard_vk {
        tx_extractor = tx_extractor.with_orchard(orchard_vk);
    }
    let transaction = tx_extractor.extract()?;
    let txid = transaction.txid();

    #[allow(clippy::too_many_arguments)]
    fn to_sent_transaction_output<
        AccountId: Copy,
        D: Domain,
        O: ShieldedOutput<D, { ENC_CIPHERTEXT_SIZE }>,
        DbT: WalletRead + WalletCommitmentTrees,
        N,
    >(
        domain: D,
        note: D::Note,
        output: &O,
        output_pool: ShieldedProtocol,
        output_index: usize,
        pczt_recipient: PcztRecipient<AccountId>,
        external_address: Option<ZcashAddress>,
        note_value: impl Fn(&D::Note) -> u64,
        memo_bytes: impl Fn(&D::Memo) -> &[u8; 512],
        wallet_note: impl Fn(D::Note) -> Note,
    ) -> Result<SentTransactionOutput<AccountId>, ExtractErrT<DbT, N>> {
        let pk_d = D::get_pk_d(&note);
        let esk = D::derive_esk(&note).expect("notes are post-ZIP 212");
        let memo = try_output_recovery_with_pkd_esk(&domain, pk_d, esk, output).map(|(_, _, m)| {
            MemoBytes::from_bytes(memo_bytes(&m)).expect("Memo is the correct length.")
        });

        let note_value = Zatoshis::try_from(note_value(&note))?;
        let recipient = match (pczt_recipient, external_address) {
            (PcztRecipient::External, Some(addr)) => Ok(Recipient::External {
                recipient_address: addr,
                output_pool: PoolType::Shielded(output_pool),
            }),
            (PcztRecipient::External, None) => Err(PcztError::Invalid(
                "external recipient needs to have its user_address field set".into(),
            )),
            #[cfg(feature = "transparent-inputs")]
            (PcztRecipient::EphemeralTransparent { .. }, _) => Err(PcztError::Invalid(
                "shielded output cannot be EphemeralTransparent".into(),
            )),
            (PcztRecipient::InternalAccount { receiving_account }, external_address) => {
                Ok(Recipient::InternalAccount {
                    receiving_account,
                    external_address,
                    note: Box::new(wallet_note(note)),
                })
            }
        }?;

        Ok(SentTransactionOutput::from_parts(
            output_index,
            recipient,
            note_value,
            memo,
        ))
    }

    #[cfg(feature = "orchard")]
    let orchard_outputs = transaction
        .orchard_bundle()
        .map(|bundle| {
            assert_eq!(bundle.actions().len(), orchard_output_info.len());
            bundle
                .actions()
                .iter()
                .zip(orchard_output_info)
                .enumerate()
                .filter_map(|(output_index, (action, output_info))| {
                    output_info.map(|((pczt_recipient, external_address), note)| {
                        let domain = OrchardDomain::for_action(action);
                        to_sent_transaction_output::<_, _, _, DbT, _>(
                            domain,
                            note,
                            action,
                            ShieldedProtocol::Orchard,
                            output_index,
                            pczt_recipient,
                            external_address,
                            |note| note.value().inner(),
                            |memo| memo,
                            Note::Orchard,
                        )
                    })
                })
                .collect::<Result<Vec<_>, _>>()
        })
        .transpose()?;

    let sapling_outputs = transaction
        .sapling_bundle()
        .map(|bundle| {
            assert_eq!(bundle.shielded_outputs().len(), sapling_output_info.len());
            bundle
                .shielded_outputs()
                .iter()
                .zip(sapling_output_info)
                .enumerate()
                .filter_map(|(output_index, (action, output_info))| {
                    output_info.map(|((pczt_recipient, external_address), note)| {
                        let domain =
                            SaplingDomain::new(sapling::note_encryption::Zip212Enforcement::On);
                        to_sent_transaction_output::<_, _, _, DbT, _>(
                            domain,
                            note,
                            action,
                            ShieldedProtocol::Sapling,
                            output_index,
                            pczt_recipient,
                            external_address,
                            |note| note.value().inner(),
                            |memo| memo,
                            Note::Sapling,
                        )
                    })
                })
                .collect::<Result<Vec<_>, _>>()
        })
        .transpose()?;

    #[allow(unused_variables)]
    let transparent_outputs = transaction
        .transparent_bundle()
        .map(|bundle| {
            assert_eq!(bundle.vout.len(), transparent_output_info.len());
            bundle
                .vout
                .iter()
                .zip(transparent_output_info)
                .enumerate()
                .filter_map(|(output_index, (output, output_info))| {
                    output_info.map(|(pczt_recipient, external_address)| {
                        // This assumes that transparent outputs are pushed onto `transparent_output_meta`
                        // with the same indices they have in the transaction's transparent outputs.
                        // We do not reorder transparent outputs; there is no reason to do so because it
                        // would not usefully improve privacy.
                        let outpoint = OutPoint::new(txid.into(), output_index as u32);

                        let recipient = match (pczt_recipient, external_address) {
                            (PcztRecipient::External, Some(addr)) => {
                                Ok(Recipient::External {
                                    recipient_address: addr,
                                    output_pool: PoolType::Transparent,
                                })
                            }
                            (PcztRecipient::External, None) => Err(PcztError::Invalid(
                                "external recipient needs to have its user_address field set".into(),
                            )),
                            #[cfg(feature = "transparent-inputs")]
                            (PcztRecipient::EphemeralTransparent { receiving_account }, _) => output
                                .recipient_address()
                                .ok_or(PcztError::Invalid(
                                    "Ephemeral outputs cannot have a non-standard script_pubkey"
                                        .into(),
                                ))
                                .map(|ephemeral_address| Recipient::EphemeralTransparent {
                                    receiving_account,
                                    ephemeral_address,
                                    outpoint,
                                }),
                            (
                                PcztRecipient::InternalAccount {
                                    receiving_account,
                                },
                                _,
                            ) => Err(PcztError::Invalid(
                                "Transparent output cannot be InternalAccount".into(),
                            )),
                        }?;

                        Ok(SentTransactionOutput::from_parts(
                            output_index,
                            recipient,
                            output.value,
                            None,
                        ))
                    })
                })
                .collect::<Result<Vec<_>, ExtractErrT<DbT, _>>>()
        })
        .transpose()?;

    let mut outputs: Vec<SentTransactionOutput<_>> = vec![];
    #[cfg(feature = "orchard")]
    outputs.extend(orchard_outputs.into_iter().flatten());
    outputs.extend(sapling_outputs.into_iter().flatten());
    outputs.extend(transparent_outputs.into_iter().flatten());

    let fee_amount = Zatoshis::try_from(transaction.fee_paid(|outpoint| {
        utxos_map
            .get(outpoint)
            .copied()
            // Error doesn't matter, this can never happen because we constructed the
            // UTXOs map and the transaction from the same PCZT.
            .ok_or(BalanceError::Overflow)
    })?)?;

    // We don't need the spent UTXOs to be in transaction order.
    let utxos_spent = utxos_map.into_keys().collect::<Vec<_>>();

    let created = time::OffsetDateTime::now_utc();

    let transactions = vec![SentTransaction::new(
        &transaction,
        created,
        BlockHeight::from_u32(proposal_info.target_height),
        proposal_info.from_account,
        &outputs,
        fee_amount,
        #[cfg(feature = "transparent-inputs")]
        &utxos_spent,
    )];

    wallet_db
        .store_transactions_to_be_sent(&transactions)
        .map_err(Error::DataSource)?;

    Ok(txid)
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
    shielding_threshold: Zatoshis,
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
