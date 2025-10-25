//! Types related to the process of selecting inputs to be spent given a transaction request.
use core::marker::PhantomData;
use nonempty::NonEmpty;
use std::{
    collections::BTreeMap,
    error,
    fmt::{self, Debug, Display},
};

use ::transparent::bundle::TxOut;
use zcash_address::{ConversionError, ZcashAddress};
use zcash_keys::address::{Address, UnifiedAddress};
use zcash_primitives::transaction::fees::{
    FeeRule,
    transparent::InputSize,
    zip317::{P2PKH_STANDARD_INPUT_SIZE, P2PKH_STANDARD_OUTPUT_SIZE},
};
use zcash_protocol::{
    PoolType, ShieldedProtocol,
    consensus::{self, BlockHeight},
    memo::MemoBytes,
    value::{BalanceError, Zatoshis},
};
use zip321::TransactionRequest;

use crate::{
    data_api::{
        InputSource, MaxSpendMode, ReceivedNotes, SimpleNoteRetention, TargetValue,
        wallet::TargetHeight,
    },
    fees::{ChangeError, ChangeStrategy, EphemeralBalance, TransactionBalance, sapling},
    proposal::{Proposal, ProposalError, ShieldedInputs},
    wallet::WalletTransparentOutput,
};

use super::ConfirmationsPolicy;

#[cfg(feature = "transparent-inputs")]
use {
    crate::{
        fees::ChangeValue,
        proposal::{Step, StepOutput, StepOutputIndex},
    },
    ::transparent::{address::TransparentAddress, bundle::OutPoint},
    std::collections::BTreeSet,
    std::convert::Infallible,
    zip321::Payment,
};

#[cfg(feature = "orchard")]
use crate::fees::orchard as orchard_fees;

/// The type of errors that may be produced in input selection.
#[derive(Debug)]
pub enum InputSelectorError<DbErrT, SelectorErrT, ChangeErrT, N> {
    /// An error occurred accessing the underlying data store.
    DataSource(DbErrT),
    /// An error occurred specific to the provided input selector's selection rules.
    Selection(SelectorErrT),
    /// An error occurred in computing the change or fee for the proposed transfer.
    Change(ChangeError<ChangeErrT, N>),
    /// Input selection attempted to generate an invalid transaction proposal.
    Proposal(ProposalError),
    /// An error occurred parsing the address from a payment request.
    Address(ConversionError<&'static str>),
    /// Insufficient funds were available to satisfy the payment request that inputs were being
    /// selected to attempt to satisfy.
    InsufficientFunds {
        available: Zatoshis,
        required: Zatoshis,
    },
    /// The data source does not have enough information to choose an expiry height
    /// for the transaction.
    SyncRequired,
}

impl<DE: fmt::Display, SE: fmt::Display, CE: fmt::Display, N: fmt::Display> fmt::Display
    for InputSelectorError<DE, SE, CE, N>
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self {
            InputSelectorError::DataSource(e) => {
                write!(
                    f,
                    "The underlying datasource produced the following error: {e}"
                )
            }
            InputSelectorError::Selection(e) => {
                write!(f, "Note selection encountered the following error: {e}")
            }
            InputSelectorError::Change(e) => write!(
                f,
                "Proposal generation failed due to an error in computing change or transaction fees: {e}"
            ),
            InputSelectorError::Proposal(e) => {
                write!(
                    f,
                    "Input selection attempted to generate an invalid proposal: {e}"
                )
            }
            InputSelectorError::Address(e) => {
                write!(
                    f,
                    "An error occurred decoding the address from a payment request: {e}."
                )
            }
            InputSelectorError::InsufficientFunds {
                available,
                required,
            } => write!(
                f,
                "Insufficient balance (have {}, need {} including fee)",
                u64::from(*available),
                u64::from(*required)
            ),
            InputSelectorError::SyncRequired => {
                write!(f, "Insufficient chain data is available, sync required.")
            }
        }
    }
}

impl<DE, SE, CE, N> error::Error for InputSelectorError<DE, SE, CE, N>
where
    DE: Debug + Display + error::Error + 'static,
    SE: Debug + Display + error::Error + 'static,
    CE: Debug + Display + error::Error + 'static,
    N: Debug + Display + 'static,
{
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match &self {
            Self::DataSource(e) => Some(e),
            Self::Selection(e) => Some(e),
            Self::Change(e) => Some(e),
            Self::Proposal(e) => Some(e),
            _ => None,
        }
    }
}

impl<E, S, F, N> From<ConversionError<&'static str>> for InputSelectorError<E, S, F, N> {
    fn from(value: ConversionError<&'static str>) -> Self {
        InputSelectorError::Address(value)
    }
}

impl<E, S, C, N> From<ChangeError<C, N>> for InputSelectorError<E, S, C, N> {
    fn from(err: ChangeError<C, N>) -> Self {
        InputSelectorError::Change(err)
    }
}

/// A strategy for selecting transaction inputs and proposing transaction outputs.
///
/// Proposals should include only economically useful inputs, as determined by `Self::FeeRule`;
/// that is, do not return inputs that cause fees to increase by an amount greater than the value
/// of the input.
pub trait InputSelector {
    /// The type of errors that may be generated in input selection
    type Error;

    /// The type of data source that the input selector expects to access to obtain input notes.
    /// This associated type permits input selectors that may use specialized knowledge of the
    /// internals of a particular backing data store, if the generic API of `InputSource` does not
    /// provide sufficiently fine-grained operations for a particular backing store to optimally
    /// perform input selection.
    type InputSource: InputSource;

    /// Performs input selection and returns a proposal for transaction construction including
    /// change and fee outputs.
    ///
    /// Implementations of this method should return inputs sufficient to satisfy the given
    /// transaction request using a best-effort strategy to preserve user privacy, as follows:
    /// * If it is possible to satisfy the specified transaction request by creating
    ///   a fully-shielded transaction without requiring value to cross pool boundaries,
    ///   return the inputs necessary to construct such a transaction; otherwise
    /// * If it is possible to satisfy the transaction request by creating a fully-shielded
    ///   transaction with some amounts crossing between shielded pools, return the inputs
    ///   necessary.
    ///
    /// If insufficient funds are available to satisfy the required outputs for the shielding
    /// request, this operation must fail and return [`InputSelectorError::InsufficientFunds`].
    #[allow(clippy::type_complexity)]
    #[allow(clippy::too_many_arguments)]
    fn propose_transaction<ParamsT, ChangeT>(
        &self,
        params: &ParamsT,
        wallet_db: &Self::InputSource,
        target_height: TargetHeight,
        anchor_height: BlockHeight,
        confirmations_policy: ConfirmationsPolicy,
        account: <Self::InputSource as InputSource>::AccountId,
        transaction_request: TransactionRequest,
        change_strategy: &ChangeT,
    ) -> Result<
        Proposal<<ChangeT as ChangeStrategy>::FeeRule, <Self::InputSource as InputSource>::NoteRef>,
        InputSelectorError<
            <Self::InputSource as InputSource>::Error,
            Self::Error,
            ChangeT::Error,
            <Self::InputSource as InputSource>::NoteRef,
        >,
    >
    where
        ParamsT: consensus::Parameters,
        ChangeT: ChangeStrategy<MetaSource = Self::InputSource>;
}

/// A strategy for selecting transaction inputs and proposing transaction outputs
/// for shielding-only transactions (transactions which spend transparent UTXOs and
/// send all transaction outputs to the wallet's shielded internal address(es)).
#[cfg(feature = "transparent-inputs")]
pub trait ShieldingSelector {
    /// The type of errors that may be generated in input selection
    type Error;
    /// The type of data source that the input selector expects to access to obtain input
    /// transparent UTXOs. This associated type permits input selectors that may use specialized
    /// knowledge of the internals of a particular backing data store, if the generic API of
    /// [`InputSource`] does not provide sufficiently fine-grained operations for a
    /// particular backing store to optimally perform input selection.
    type InputSource: InputSource;

    /// Performs input selection and returns a proposal for the construction of a shielding
    /// transaction.
    ///
    /// Implementations should return the maximum possible number of economically useful inputs
    /// required to supply at least the requested value, choosing only inputs received at the
    /// specified source addresses. If insufficient funds are available to satisfy the required
    /// outputs for the shielding request, this operation must fail and return
    /// [`InputSelectorError::InsufficientFunds`].
    #[allow(clippy::type_complexity)]
    #[allow(clippy::too_many_arguments)]
    fn propose_shielding<ParamsT, ChangeT>(
        &self,
        params: &ParamsT,
        wallet_db: &Self::InputSource,
        change_strategy: &ChangeT,
        shielding_threshold: Zatoshis,
        source_addrs: &[TransparentAddress],
        to_account: <Self::InputSource as InputSource>::AccountId,
        target_height: TargetHeight,
        confirmations_policy: ConfirmationsPolicy,
    ) -> Result<
        Proposal<<ChangeT as ChangeStrategy>::FeeRule, Infallible>,
        InputSelectorError<
            <Self::InputSource as InputSource>::Error,
            Self::Error,
            ChangeT::Error,
            Infallible,
        >,
    >
    where
        ParamsT: consensus::Parameters,
        ChangeT: ChangeStrategy<MetaSource = Self::InputSource>;
}

/// Errors that can occur as a consequence of greedy input selection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GreedyInputSelectorError {
    /// An intermediate value overflowed or underflowed the valid monetary range.
    Balance(BalanceError),
    /// A unified address did not contain a supported receiver.
    UnsupportedAddress(Box<UnifiedAddress>),
    /// Support for transparent-source-only (TEX) addresses requires the transparent-inputs feature.
    UnsupportedTexAddress,
}

impl fmt::Display for GreedyInputSelectorError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self {
            GreedyInputSelectorError::Balance(e) => write!(
                f,
                "A balance calculation violated amount validity bounds: {e:?}."
            ),
            GreedyInputSelectorError::UnsupportedAddress(_) => {
                // we can't encode the UA to its string representation because we
                // don't have network parameters here
                write!(f, "Unified address contains no supported receivers.")
            }
            GreedyInputSelectorError::UnsupportedTexAddress => {
                write!(
                    f,
                    "Support for transparent-source-only (TEX) addresses requires the transparent-inputs feature."
                )
            }
        }
    }
}

impl<DbErrT, ChangeErrT, N> From<GreedyInputSelectorError>
    for InputSelectorError<DbErrT, GreedyInputSelectorError, ChangeErrT, N>
{
    fn from(err: GreedyInputSelectorError) -> Self {
        InputSelectorError::Selection(err)
    }
}

impl<DbErrT, ChangeErrT, N> From<BalanceError>
    for InputSelectorError<DbErrT, GreedyInputSelectorError, ChangeErrT, N>
{
    fn from(err: BalanceError) -> Self {
        InputSelectorError::Selection(GreedyInputSelectorError::Balance(err))
    }
}

pub(crate) struct SaplingPayment(Zatoshis);

#[cfg(test)]
impl SaplingPayment {
    pub(crate) fn new(amount: Zatoshis) -> Self {
        SaplingPayment(amount)
    }
}

impl sapling::OutputView for SaplingPayment {
    fn value(&self) -> Zatoshis {
        self.0
    }
}

#[cfg(feature = "orchard")]
pub(crate) struct OrchardPayment(Zatoshis);

#[cfg(test)]
#[cfg(feature = "orchard")]
impl OrchardPayment {
    pub(crate) fn new(amount: Zatoshis) -> Self {
        OrchardPayment(amount)
    }
}

#[cfg(feature = "orchard")]
impl orchard_fees::OutputView for OrchardPayment {
    fn value(&self) -> Zatoshis {
        self.0
    }
}

/// An [`InputSelector`] implementation that uses a greedy strategy to select between available
/// notes.
///
/// This implementation performs input selection using methods available via the
/// [`InputSource`] interface.
pub struct GreedyInputSelector<DbT> {
    _ds_type: PhantomData<DbT>,
}

impl<DbT> GreedyInputSelector<DbT> {
    /// Constructs a new greedy input selector that uses the provided change strategy to determine
    /// change values and fee amounts.
    ///
    /// The [`ChangeStrategy`] provided must produce exactly one ephemeral change value when
    /// computing a transaction balance if an [`EphemeralBalance::Output`] value is provided for
    /// its ephemeral balance, or the resulting [`GreedyInputSelector`] will return an error when
    /// attempting to construct a transaction proposal that requires such an output.
    ///
    /// [`EphemeralBalance::Output`]: crate::fees::EphemeralBalance::Output
    pub fn new() -> Self {
        GreedyInputSelector {
            _ds_type: PhantomData,
        }
    }
}

impl<DbT> Default for GreedyInputSelector<DbT> {
    fn default() -> Self {
        Self::new()
    }
}

impl<DbT: InputSource> InputSelector for GreedyInputSelector<DbT> {
    type Error = GreedyInputSelectorError;
    type InputSource = DbT;

    #[allow(clippy::type_complexity)]
    fn propose_transaction<ParamsT, ChangeT>(
        &self,
        params: &ParamsT,
        wallet_db: &Self::InputSource,
        target_height: TargetHeight,
        anchor_height: BlockHeight,
        confirmations_policy: ConfirmationsPolicy,
        account: <DbT as InputSource>::AccountId,
        transaction_request: TransactionRequest,
        change_strategy: &ChangeT,
    ) -> Result<
        Proposal<<ChangeT as ChangeStrategy>::FeeRule, DbT::NoteRef>,
        InputSelectorError<<DbT as InputSource>::Error, Self::Error, ChangeT::Error, DbT::NoteRef>,
    >
    where
        ParamsT: consensus::Parameters,
        Self::InputSource: InputSource,
        ChangeT: ChangeStrategy<MetaSource = DbT>,
    {
        let mut transparent_outputs = vec![];
        let mut sapling_outputs = vec![];
        #[cfg(feature = "orchard")]
        let mut orchard_outputs = vec![];
        let mut payment_pools = BTreeMap::new();

        // In a ZIP 320 pair, tr0 refers to the first transaction request that
        // collects shielded value and sends it to an ephemeral address, and tr1
        // refers to the second transaction request that pays the TEX addresses.
        #[cfg(feature = "transparent-inputs")]
        let mut tr1_transparent_outputs = vec![];
        #[cfg(feature = "transparent-inputs")]
        let mut tr1_payments = vec![];
        #[cfg(feature = "transparent-inputs")]
        let mut tr1_payment_pools = BTreeMap::new();
        // This balance value is just used for overflow checking; the actual value of ephemeral
        // outputs will be computed from the constructed `tr1_transparent_outputs` value
        // constructed below.
        #[cfg(feature = "transparent-inputs")]
        let mut total_ephemeral = Zatoshis::ZERO;

        for (idx, payment) in transaction_request.payments() {
            let recipient_address: Address = payment
                .recipient_address()
                .clone()
                .convert_if_network(params.network_type())?;

            match recipient_address {
                Address::Transparent(addr) => {
                    payment_pools.insert(*idx, PoolType::TRANSPARENT);
                    transparent_outputs.push(TxOut::new(payment.amount(), addr.script().into()));
                }
                #[cfg(feature = "transparent-inputs")]
                Address::Tex(data) => {
                    let p2pkh_addr = TransparentAddress::PublicKeyHash(data);

                    tr1_payment_pools.insert(*idx, PoolType::TRANSPARENT);
                    tr1_transparent_outputs
                        .push(TxOut::new(payment.amount(), p2pkh_addr.script().into()));
                    tr1_payments.push(
                        Payment::new(
                            payment.recipient_address().clone(),
                            payment.amount(),
                            None,
                            payment.label().cloned(),
                            payment.message().cloned(),
                            payment.other_params().to_vec(),
                        )
                        .expect("cannot fail because memo is None"),
                    );
                    total_ephemeral = (total_ephemeral + payment.amount())
                        .ok_or(GreedyInputSelectorError::Balance(BalanceError::Overflow))?;
                }
                #[cfg(not(feature = "transparent-inputs"))]
                Address::Tex(_) => {
                    return Err(InputSelectorError::Selection(
                        GreedyInputSelectorError::UnsupportedTexAddress,
                    ));
                }
                Address::Sapling(_) => {
                    payment_pools.insert(*idx, PoolType::SAPLING);
                    sapling_outputs.push(SaplingPayment(payment.amount()));
                }
                Address::Unified(addr) => {
                    #[cfg(feature = "orchard")]
                    if addr.has_orchard() {
                        payment_pools.insert(*idx, PoolType::ORCHARD);
                        orchard_outputs.push(OrchardPayment(payment.amount()));
                        continue;
                    }

                    if addr.has_sapling() {
                        payment_pools.insert(*idx, PoolType::SAPLING);
                        sapling_outputs.push(SaplingPayment(payment.amount()));
                        continue;
                    }

                    if let Some(addr) = addr.transparent() {
                        payment_pools.insert(*idx, PoolType::TRANSPARENT);
                        transparent_outputs
                            .push(TxOut::new(payment.amount(), addr.script().into()));
                        continue;
                    }

                    return Err(InputSelectorError::Selection(
                        GreedyInputSelectorError::UnsupportedAddress(Box::new(addr)),
                    ));
                }
            }
        }

        let mut shielded_inputs = ReceivedNotes::empty();
        let mut prior_available = Zatoshis::ZERO;
        let mut amount_required = Zatoshis::ZERO;
        let mut exclude: Vec<DbT::NoteRef> = vec![];

        // This loop is guaranteed to terminate because on each iteration we check that the amount
        // of funds selected is strictly increasing. The loop will either return a successful
        // result or the wallet will eventually run out of funds to select.
        loop {
            #[cfg(not(feature = "orchard"))]
            let use_sapling = true;
            #[cfg(feature = "orchard")]
            let (use_sapling, use_orchard) = {
                let (sapling_input_total, orchard_input_total) = (
                    shielded_inputs.sapling_value()?,
                    shielded_inputs.orchard_value()?,
                );

                // Use Sapling inputs if there are no Orchard outputs or if there are insufficient
                // funds from Orchard inputs to cover the amount required.
                let use_sapling =
                    orchard_outputs.is_empty() || amount_required > orchard_input_total;
                // Use Orchard inputs if there are insufficient funds from Sapling inputs to cover
                // the amount required.
                let use_orchard = !use_sapling || amount_required > sapling_input_total;

                (use_sapling, use_orchard)
            };

            let sapling_inputs = if use_sapling {
                shielded_inputs
                    .sapling()
                    .iter()
                    .map(|i| (*i.internal_note_id(), i.note().value()))
                    .collect()
            } else {
                vec![]
            };

            #[cfg(feature = "orchard")]
            let orchard_inputs = if use_orchard {
                shielded_inputs
                    .orchard()
                    .iter()
                    .map(|i| (*i.internal_note_id(), i.note().value()))
                    .collect()
            } else {
                vec![]
            };

            let selected_input_ids = sapling_inputs.iter().map(|(id, _)| id);
            #[cfg(feature = "orchard")]
            let selected_input_ids =
                selected_input_ids.chain(orchard_inputs.iter().map(|(id, _)| id));

            let selected_input_ids = selected_input_ids.cloned().collect::<Vec<_>>();

            let wallet_meta = change_strategy
                .fetch_wallet_meta(wallet_db, account, target_height, &selected_input_ids)
                .map_err(InputSelectorError::DataSource)?;

            #[cfg(not(feature = "transparent-inputs"))]
            let ephemeral_output_value = None;

            #[cfg(feature = "transparent-inputs")]
            let (ephemeral_output_value, tr1_balance_opt) = {
                if tr1_transparent_outputs.is_empty() {
                    (None, None)
                } else {
                    // The ephemeral input going into transaction 1 must be able to pay that
                    // transaction's fee, as well as the TEX address payments.

                    // First compute the required total with an additional zero input,
                    // catching the `InsufficientFunds` error to obtain the required amount
                    // given the provided change strategy. Ignore the change memo in order
                    // to avoid adding a change output.
                    let tr1_required_input_value = match change_strategy
                        .compute_balance::<_, DbT::NoteRef>(
                            params,
                            target_height,
                            &[] as &[WalletTransparentOutput],
                            &tr1_transparent_outputs,
                            &sapling::EmptyBundleView,
                            #[cfg(feature = "orchard")]
                            &orchard_fees::EmptyBundleView,
                            Some(EphemeralBalance::Input(Zatoshis::ZERO)),
                            &wallet_meta,
                        ) {
                        Err(ChangeError::InsufficientFunds { required, .. }) => required,
                        Err(ChangeError::DustInputs { .. }) => {
                            unreachable!("no inputs were supplied")
                        }
                        Err(other) => return Err(InputSelectorError::Change(other)),
                        Ok(_) => Zatoshis::ZERO, // shouldn't happen
                    };

                    // Now recompute to obtain the `TransactionBalance` and verify that it
                    // fully accounts for the required fees.
                    let tr1_balance = change_strategy.compute_balance::<_, DbT::NoteRef>(
                        params,
                        target_height,
                        &[] as &[WalletTransparentOutput],
                        &tr1_transparent_outputs,
                        &sapling::EmptyBundleView,
                        #[cfg(feature = "orchard")]
                        &orchard_fees::EmptyBundleView,
                        Some(EphemeralBalance::Input(tr1_required_input_value)),
                        &wallet_meta,
                    )?;
                    assert_eq!(tr1_balance.total(), tr1_balance.fee_required());

                    (Some(tr1_required_input_value), Some(tr1_balance))
                }
            };

            // In the ZIP 320 case, this is the balance for transaction 0, taking into account
            // the ephemeral output.
            let tr0_balance = change_strategy.compute_balance(
                params,
                target_height,
                &[] as &[WalletTransparentOutput],
                &transparent_outputs,
                &(
                    ::sapling::builder::BundleType::DEFAULT,
                    &sapling_inputs[..],
                    &sapling_outputs[..],
                ),
                #[cfg(feature = "orchard")]
                &(
                    ::orchard::builder::BundleType::DEFAULT,
                    &orchard_inputs[..],
                    &orchard_outputs[..],
                ),
                ephemeral_output_value.map(EphemeralBalance::Output),
                &wallet_meta,
            );

            match tr0_balance {
                Ok(tr0_balance) => {
                    // At this point, we have enough input value to pay for everything, so we
                    // return here.
                    let shielded_inputs =
                        NonEmpty::from_vec(shielded_inputs.into_vec(&SimpleNoteRetention {
                            sapling: use_sapling,
                            #[cfg(feature = "orchard")]
                            orchard: use_orchard,
                        }))
                        .map(|notes| ShieldedInputs::from_parts(anchor_height, notes));

                    return build_proposal(
                        change_strategy.fee_rule(),
                        tr0_balance,
                        target_height,
                        shielded_inputs,
                        transaction_request,
                        payment_pools,
                        #[cfg(feature = "transparent-inputs")]
                        ephemeral_output_value.zip(tr1_balance_opt).map(
                            |(ephemeral_output_value, tr1_balance)| EphemeralStepConfig {
                                ephemeral_output_value,
                                tr1_balance,
                                tr1_payments,
                                tr1_payment_pools,
                            },
                        ),
                    )
                    .map_err(InputSelectorError::Proposal);
                }
                Err(ChangeError::DustInputs {
                    mut sapling,
                    #[cfg(feature = "orchard")]
                    mut orchard,
                    ..
                }) => {
                    exclude.append(&mut sapling);
                    #[cfg(feature = "orchard")]
                    exclude.append(&mut orchard);
                }
                Err(ChangeError::InsufficientFunds { required, .. }) => {
                    amount_required = required;
                }
                Err(other) => return Err(InputSelectorError::Change(other)),
            }

            #[cfg(not(feature = "orchard"))]
            let selectable_pools = &[ShieldedProtocol::Sapling];
            #[cfg(feature = "orchard")]
            let selectable_pools = &[ShieldedProtocol::Sapling, ShieldedProtocol::Orchard];

            shielded_inputs = wallet_db
                .select_spendable_notes(
                    account,
                    TargetValue::AtLeast(amount_required),
                    selectable_pools,
                    target_height,
                    confirmations_policy,
                    &exclude,
                )
                .map_err(InputSelectorError::DataSource)?;

            let new_available = shielded_inputs.total_value()?;
            if new_available <= prior_available {
                return Err(InputSelectorError::InsufficientFunds {
                    required: amount_required,
                    available: new_available,
                });
            } else {
                // If the set of selected inputs has changed after selection, we will loop again
                // and see whether we now have enough funds.
                prior_available = new_available;
            }
        }
    }
}

#[allow(clippy::type_complexity, clippy::too_many_arguments)]
pub(crate) fn propose_send_max<ParamsT, InputSourceT, FeeRuleT>(
    params: &ParamsT,
    wallet_db: &InputSourceT,
    fee_rule: &FeeRuleT,
    source_account: InputSourceT::AccountId,
    spend_pools: &[ShieldedProtocol],
    target_height: TargetHeight,
    anchor_height: BlockHeight,
    mode: MaxSpendMode,
    confirmations_policy: ConfirmationsPolicy,
    recipient: ZcashAddress,
    memo: Option<MemoBytes>,
) -> Result<
    Proposal<FeeRuleT, InputSourceT::NoteRef>,
    InputSelectorError<InputSourceT::Error, BalanceError, FeeRuleT::Error, InputSourceT::NoteRef>,
>
where
    ParamsT: consensus::Parameters,
    InputSourceT: InputSource,
    FeeRuleT: FeeRule + Clone,
{
    let spendable_notes = wallet_db
        .select_spendable_notes(
            source_account,
            TargetValue::AllFunds(mode),
            spend_pools,
            target_height,
            confirmations_policy,
            &[],
        )
        .map_err(InputSelectorError::DataSource)?;

    let input_total = spendable_notes
        .total_value()
        .map_err(InputSelectorError::Selection)?;

    let mut payment_pools = BTreeMap::new();

    let sapling_output_count = {
        // we require a sapling output if the recipient has a Sapling receiver but not an Orchard
        // receiver.
        let requested_sapling_outputs: usize = if recipient.can_receive_as(PoolType::SAPLING)
            && !recipient.can_receive_as(PoolType::ORCHARD)
        {
            payment_pools.insert(0, PoolType::SAPLING);
            1
        } else {
            0
        };

        ::sapling::builder::BundleType::DEFAULT
            .num_outputs(spendable_notes.sapling.len(), requested_sapling_outputs)
            .map_err(|s| InputSelectorError::Change(ChangeError::BundleError(s)))?
    };

    let use_sapling = !spendable_notes.sapling().is_empty() || sapling_output_count > 0;

    #[cfg(feature = "orchard")]
    let orchard_action_count = {
        let requested_orchard_actions: usize = if recipient.can_receive_as(PoolType::ORCHARD) {
            payment_pools.insert(0, PoolType::ORCHARD);
            1
        } else {
            0
        };
        orchard::builder::BundleType::DEFAULT
            .num_actions(spendable_notes.orchard.len(), requested_orchard_actions)
            .map_err(|s| InputSelectorError::Change(ChangeError::BundleError(s)))?
    };
    #[cfg(not(feature = "orchard"))]
    let orchard_action_count: usize = 0;

    #[cfg(feature = "orchard")]
    let use_orchard = orchard_action_count > 0;

    let recipient_address: Address = recipient
        .clone()
        .convert_if_network(params.network_type())?;

    let (tr0_fee, tr1_fee) = match recipient_address {
        Address::Sapling(_) => fee_rule
            .fee_required(
                params,
                BlockHeight::from(target_height),
                [],
                [],
                spendable_notes.sapling().len(),
                sapling_output_count,
                orchard_action_count,
            )
            .map(|fee| (fee, None)),
        Address::Transparent(_) => fee_rule
            .fee_required(
                params,
                BlockHeight::from(target_height),
                [],
                [P2PKH_STANDARD_OUTPUT_SIZE],
                spendable_notes.sapling().len(),
                sapling_output_count,
                orchard_action_count,
            )
            .map(|fee| (fee, None)),
        Address::Unified(addr) => fee_rule
            .fee_required(
                params,
                BlockHeight::from(target_height),
                [],
                if addr.has_transparent() && !(addr.has_sapling() || addr.has_orchard()) {
                    vec![P2PKH_STANDARD_OUTPUT_SIZE]
                } else {
                    vec![]
                },
                spendable_notes.sapling().len(),
                sapling_output_count,
                orchard_action_count,
            )
            .map(|fee| (fee, None)),
        Address::Tex(_) => fee_rule
            .fee_required(
                params,
                BlockHeight::from(target_height),
                [],
                [P2PKH_STANDARD_OUTPUT_SIZE],
                spendable_notes.sapling().len(),
                sapling_output_count,
                orchard_action_count,
            )
            .and_then(|tr0_fee| {
                let tr1_fee = fee_rule.fee_required(
                    params,
                    BlockHeight::from(target_height),
                    [InputSize::Known(P2PKH_STANDARD_INPUT_SIZE)],
                    [P2PKH_STANDARD_OUTPUT_SIZE],
                    0,
                    0,
                    0,
                )?;

                Ok((tr0_fee, Some(tr1_fee)))
            }),
    }
    .map_err(|fee_error| InputSelectorError::Change(ChangeError::StrategyError(fee_error)))?;

    // the total fee required for the all the involved transactions. For the case
    // of TEX it means the fee requied to send the max value to the ephemeral
    // address + the fee to send the value in that ephemeral change address to
    // the TEX address.
    let total_fee_required = (tr0_fee + tr1_fee.unwrap_or(Zatoshis::ZERO))
        .expect("fee value addition does not overflow");

    // the total amount involved in the "send max" operation. This is the total
    // spendable value present in the wallet minus the fees required to perform
    // the send max operation.
    let total_to_recipient =
        (input_total - total_fee_required).ok_or(InputSelectorError::InsufficientFunds {
            available: input_total,
            required: total_fee_required,
        })?;

    // when the recipient of the send max operation is a TEX address this is the
    // amount that will be needed to send the max available amount accounting the
    // fees needed to propose a transaction involving one transparent input and
    // one transparent output (the TEX address recipient.)
    #[cfg(feature = "transparent-inputs")]
    let ephemeral_output_value =
        tr1_fee.map(|fee| (total_to_recipient + fee).expect("overflow already checked"));

    #[cfg(feature = "transparent-inputs")]
    let tr0_change = ephemeral_output_value
        .into_iter()
        .map(ChangeValue::ephemeral_transparent)
        .collect();
    #[cfg(not(feature = "transparent-inputs"))]
    let tr0_change = vec![];

    // The transaction produces no change, unless this is a transaction to a TEX address; in this
    // case, the first transaction produces a single ephemeral change output.
    let tr0_balance = TransactionBalance::new(tr0_change, tr0_fee)
        .expect("the sum of an single-element vector of fee values cannot overflow");

    let payment = zip321::Payment::new(recipient, total_to_recipient, memo, None, None, vec![])
        .ok_or_else(|| {
            InputSelectorError::Proposal(ProposalError::Zip321(
                zip321::Zip321Error::TransparentMemo(0),
            ))
        })?;

    let transaction_request =
        TransactionRequest::new(vec![payment.clone()]).map_err(|payment_error| {
            InputSelectorError::Proposal(ProposalError::Zip321(payment_error))
        })?;

    let shielded_inputs = NonEmpty::from_vec(spendable_notes.into_vec(&SimpleNoteRetention {
        sapling: use_sapling,
        #[cfg(feature = "orchard")]
        orchard: use_orchard,
    }))
    .map(|notes| ShieldedInputs::from_parts(anchor_height, notes));

    build_proposal(
        fee_rule,
        tr0_balance,
        target_height,
        shielded_inputs,
        transaction_request,
        payment_pools,
        #[cfg(feature = "transparent-inputs")]
        ephemeral_output_value
            .zip(tr1_fee)
            .map(|(ephemeral_output_value, tr1_fee)| EphemeralStepConfig {
                ephemeral_output_value,
                tr1_balance: TransactionBalance::new(vec![], tr1_fee)
                    .expect("the sum of an empty vector of fee values cannot overflow"),
                tr1_payments: vec![payment],
                tr1_payment_pools: BTreeMap::from_iter([(0, PoolType::Transparent)]),
            }),
    )
    .map_err(InputSelectorError::Proposal)
}

#[cfg(feature = "transparent-inputs")]
struct EphemeralStepConfig {
    ephemeral_output_value: Zatoshis,
    tr1_balance: TransactionBalance,
    tr1_payments: Vec<Payment>,
    tr1_payment_pools: BTreeMap<usize, PoolType>,
}

fn build_proposal<FeeRuleT: FeeRule + Clone, NoteRef>(
    fee_rule: &FeeRuleT,
    tr0_balance: TransactionBalance,
    target_height: TargetHeight,
    shielded_inputs: Option<ShieldedInputs<NoteRef>>,
    transaction_request: TransactionRequest,
    payment_pools: BTreeMap<usize, PoolType>,
    #[cfg(feature = "transparent-inputs")] ephemeral_step_opt: Option<EphemeralStepConfig>,
) -> Result<Proposal<FeeRuleT, NoteRef>, ProposalError> {
    #[cfg(feature = "transparent-inputs")]
    if let Some(ephemeral_step) = ephemeral_step_opt {
        let tr1_balance = ephemeral_step.tr1_balance;
        // Construct two new `TransactionRequest`s:
        // * `tr0` excludes the TEX outputs, and in their place includes
        //   a single additional ephemeral output to the transparent pool.
        // * `tr1` spends from that ephemeral output to each TEX output.

        // Find exactly one ephemeral change output.
        let ephemeral_outputs = tr0_balance
            .proposed_change()
            .iter()
            .enumerate()
            .filter(|(_, c)| c.is_ephemeral())
            .collect::<Vec<_>>();

        let ephemeral_output_index = match &ephemeral_outputs[..] {
            [(i, change_value)]
                if change_value.value() == ephemeral_step.ephemeral_output_value =>
            {
                Ok(*i)
            }
            _ => Err(ProposalError::EphemeralOutputsInvalid),
        }?;

        let ephemeral_stepoutput =
            StepOutput::new(0, StepOutputIndex::Change(ephemeral_output_index));

        let tr0 = TransactionRequest::from_indexed(
            transaction_request
                .payments()
                .iter()
                .filter(|(idx, _payment)| !ephemeral_step.tr1_payment_pools.contains_key(idx))
                .map(|(k, v)| (*k, v.clone()))
                .collect(),
        )
        .expect("removing payments from a TransactionRequest preserves validity");

        let mut steps = vec![];
        steps.push(Step::from_parts(
            &[],
            tr0,
            payment_pools,
            vec![],
            shielded_inputs,
            vec![],
            tr0_balance,
            false,
        )?);

        let tr1 =
            TransactionRequest::new(ephemeral_step.tr1_payments).expect("valid by construction");
        steps.push(Step::from_parts(
            &steps,
            tr1,
            ephemeral_step.tr1_payment_pools,
            vec![],
            None,
            vec![ephemeral_stepoutput],
            tr1_balance,
            false,
        )?);

        return Proposal::multi_step(
            fee_rule.clone(),
            target_height,
            NonEmpty::from_vec(steps).expect("steps is known to be nonempty"),
        );
    }

    Proposal::single_step(
        transaction_request,
        payment_pools,
        vec![],
        shielded_inputs,
        tr0_balance,
        fee_rule.clone(),
        target_height,
        false,
    )
}

#[cfg(feature = "transparent-inputs")]
impl<DbT: InputSource> ShieldingSelector for GreedyInputSelector<DbT> {
    type Error = GreedyInputSelectorError;
    type InputSource = DbT;

    #[allow(clippy::type_complexity)]
    fn propose_shielding<ParamsT, ChangeT>(
        &self,
        params: &ParamsT,
        wallet_db: &Self::InputSource,
        change_strategy: &ChangeT,
        shielding_threshold: Zatoshis,
        source_addrs: &[TransparentAddress],
        to_account: <Self::InputSource as InputSource>::AccountId,
        target_height: TargetHeight,
        confirmations_policy: ConfirmationsPolicy,
    ) -> Result<
        Proposal<<ChangeT as ChangeStrategy>::FeeRule, Infallible>,
        InputSelectorError<<DbT as InputSource>::Error, Self::Error, ChangeT::Error, Infallible>,
    >
    where
        ParamsT: consensus::Parameters,
        ChangeT: ChangeStrategy<MetaSource = Self::InputSource>,
    {
        let (mut transparent_inputs, _, _) = source_addrs.iter().try_fold(
            (
                vec![],
                BTreeSet::<TransparentAddress>::new(),
                BTreeSet::<TransparentAddress>::new(),
            ),
            |(mut inputs, mut ephemeral_addrs, mut input_addrs), taddr| {
                use transparent::keys::TransparentKeyScope;

                let utxos = wallet_db
                    .get_spendable_transparent_outputs(taddr, target_height, confirmations_policy)
                    .map_err(InputSelectorError::DataSource)?;

                // `InputSource::get_spendable_transparent_outputs` is required to return
                // outputs received by `taddr`, so these `.extend()` calls are guaranteed
                // to add at most a single new address to each set. But it's more
                // convenient this way as we can reuse `utxo.recipient_key_scope()`
                // instead of needing to query the wallet twice for each address to
                // determine their scopes.
                ephemeral_addrs.extend(utxos.iter().filter_map(|utxo| {
                    (utxo.recipient_key_scope() == Some(TransparentKeyScope::EPHEMERAL))
                        .then_some(utxo.recipient_address())
                }));
                input_addrs.extend(utxos.iter().map(|utxo| utxo.recipient_address()));
                inputs.extend(utxos.into_iter().map(|utxo| utxo.into_wallet_output()));

                // Funds may be spent from at most one ephemeral address at a time. If there are no
                // ephemeral addresses, we allow shielding from multiple transparent addresses.
                if !ephemeral_addrs.is_empty() && input_addrs.len() > 1 {
                    Err(InputSelectorError::Proposal(
                        ProposalError::EphemeralAddressLinkability,
                    ))
                } else {
                    Ok((inputs, ephemeral_addrs, input_addrs))
                }
            },
        )?;

        let wallet_meta = change_strategy
            .fetch_wallet_meta(wallet_db, to_account, target_height, &[])
            .map_err(InputSelectorError::DataSource)?;

        let trial_balance = change_strategy.compute_balance(
            params,
            target_height,
            &transparent_inputs,
            &[] as &[TxOut],
            &sapling::EmptyBundleView,
            #[cfg(feature = "orchard")]
            &orchard_fees::EmptyBundleView,
            None,
            &wallet_meta,
        );

        let balance = match trial_balance {
            Ok(balance) => balance,
            Err(ChangeError::DustInputs { transparent, .. }) => {
                let exclusions: BTreeSet<OutPoint> = transparent.into_iter().collect();
                transparent_inputs.retain(|i| !exclusions.contains(i.outpoint()));

                change_strategy.compute_balance(
                    params,
                    target_height,
                    &transparent_inputs,
                    &[] as &[TxOut],
                    &sapling::EmptyBundleView,
                    #[cfg(feature = "orchard")]
                    &orchard_fees::EmptyBundleView,
                    None,
                    &wallet_meta,
                )?
            }
            Err(other) => return Err(InputSelectorError::Change(other)),
        };

        if balance.total() >= shielding_threshold {
            Proposal::single_step(
                TransactionRequest::empty(),
                BTreeMap::new(),
                transparent_inputs,
                None,
                balance,
                (*change_strategy.fee_rule()).clone(),
                target_height,
                true,
            )
            .map_err(InputSelectorError::Proposal)
        } else {
            Err(InputSelectorError::InsufficientFunds {
                available: balance.total(),
                required: shielding_threshold,
            })
        }
    }
}
