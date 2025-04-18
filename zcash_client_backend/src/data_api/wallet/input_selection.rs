//! Types related to the process of selecting inputs to be spent given a transaction request.

use core::marker::PhantomData;
use std::{
    collections::BTreeMap,
    error,
    fmt::{self, Debug, Display},
};

use ::transparent::bundle::TxOut;
use nonempty::NonEmpty;
use zcash_address::{ConversionError, ZcashAddress};
use zcash_keys::address::{Address, UnifiedAddress};
use zcash_primitives::transaction::fees::{
    transparent::InputSize,
    zip317::{P2PKH_STANDARD_INPUT_SIZE, P2PKH_STANDARD_OUTPUT_SIZE},
    FeeRule,
};
use zcash_protocol::{
    consensus::{self, BlockHeight},
    memo::{Memo, MemoBytes},
    value::{BalanceError, TargetValue, Zatoshis},
    PoolType, ShieldedProtocol,
};
use zip321::TransactionRequest;

use crate::{
    data_api::{InputSource, SimpleNoteRetention, SpendableNotes},
    fees::{sapling, ChangeError, ChangeStrategy},
    proposal::{Proposal, ProposalError, ShieldedInputs},
    wallet::WalletTransparentOutput,
};

#[cfg(feature = "transparent-inputs")]
use {
    crate::{
        fees::EphemeralBalance,
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
                    "The underlying datasource produced the following error: {}",
                    e
                )
            }
            InputSelectorError::Selection(e) => {
                write!(f, "Note selection encountered the following error: {}", e)
            }
            InputSelectorError::Change(e) => write!(
                f,
                "Proposal generation failed due to an error in computing change or transaction fees: {}",
                e
            ),
            InputSelectorError::Proposal(e) => {
                write!(
                    f,
                    "Input selection attempted to generate an invalid proposal: {}",
                    e
                )
            }
            InputSelectorError::Address(e) => {
                write!(
                    f,
                    "An error occurred decoding the address from a payment request: {}.",
                    e
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
        target_height: BlockHeight,
        anchor_height: BlockHeight,
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

pub trait SendMaxSelector {
    /// The type of errors that may be generated in input selection
    type Error;
    /// The type of data source that the input selector expects to access to obtain input
    /// from the source pool. This associated type permits input selectors that may use specialized
    /// knowledge of the internals of a particular backing data store, if the generic API of
    /// [`InputSource`] does not provide sufficiently fine-grained operations for a
    /// particular backing store to optimally perform input selection.
    type InputSource: InputSource;

    /// Performs input selection and returns a proposal for the construction of a transaction
    /// that sends the maximum amount possible from a given account to the specified recipient
    /// ignoring notes that are below MARGINAL_FEE amount. This transaction will use all the
    /// funds available minus the resulting fees that will vary according to ZIP-317 specifications.
    ///
    ///
    /// Implementations should return the maximum possible number of economically useful inputs
    /// required to supply at least the requested value, choosing only inputs received at the
    /// specified source addresses. If insufficient funds are available to satisfy the required
    /// outputs for the shielding request, this operation must fail and return
    /// [`InputSelectorError::InsufficientFunds`].
    fn propose_send_max<ParamsT, ChangeT>(
        &self,
        params: &ParamsT,
        wallet_db: &Self::InputSource,
        change_strategy: &ChangeT,
        source_account: <Self::InputSource as InputSource>::AccountId,
        spend_pool: &[ShieldedProtocol],
        anchor_height: BlockHeight,
        target_height: BlockHeight,
        recipient: ZcashAddress,
        memo: Option<MemoBytes>,
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
        target_height: BlockHeight,
        min_confirmations: u32,
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
                "A balance calculation violated amount validity bounds: {:?}.",
                e
            ),
            GreedyInputSelectorError::UnsupportedAddress(_) => {
                // we can't encode the UA to its string representation because we
                // don't have network parameters here
                write!(f, "Unified address contains no supported receivers.")
            }
            GreedyInputSelectorError::UnsupportedTexAddress => {
                write!(f, "Support for transparent-source-only (TEX) addresses requires the transparent-inputs feature.")
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
        target_height: BlockHeight,
        anchor_height: BlockHeight,
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
                    transparent_outputs.push(TxOut {
                        value: payment.amount(),
                        script_pubkey: addr.script(),
                    });
                }
                #[cfg(feature = "transparent-inputs")]
                Address::Tex(data) => {
                    let p2pkh_addr = TransparentAddress::PublicKeyHash(data);

                    tr1_payment_pools.insert(*idx, PoolType::TRANSPARENT);
                    tr1_transparent_outputs.push(TxOut {
                        value: payment.amount(),
                        script_pubkey: p2pkh_addr.script(),
                    });
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
                        transparent_outputs.push(TxOut {
                            value: payment.amount(),
                            script_pubkey: addr.script(),
                        });
                        continue;
                    }

                    return Err(InputSelectorError::Selection(
                        GreedyInputSelectorError::UnsupportedAddress(Box::new(addr)),
                    ));
                }
            }
        }

        let mut shielded_inputs = SpendableNotes::empty();
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
                .fetch_wallet_meta(wallet_db, account, &selected_input_ids)
                .map_err(InputSelectorError::DataSource)?;

            #[cfg(not(feature = "transparent-inputs"))]
            let ephemeral_balance = None;

            #[cfg(feature = "transparent-inputs")]
            let (ephemeral_balance, tr1_balance_opt) = {
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
                            Some(&EphemeralBalance::Input(Zatoshis::ZERO)),
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
                        Some(&EphemeralBalance::Input(tr1_required_input_value)),
                        &wallet_meta,
                    )?;
                    assert_eq!(tr1_balance.total(), tr1_balance.fee_required());

                    (
                        Some(EphemeralBalance::Output(tr1_required_input_value)),
                        Some(tr1_balance),
                    )
                }
            };

            // In the ZIP 320 case, this is the balance for transaction 0, taking into account
            // the ephemeral output.
            let balance = change_strategy.compute_balance(
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
                ephemeral_balance.as_ref(),
                &wallet_meta,
            );

            match balance {
                Ok(balance) => {
                    // At this point, we have enough input value to pay for everything, so we will
                    // return at the end of this block.

                    let shielded_inputs =
                        NonEmpty::from_vec(shielded_inputs.into_vec(&SimpleNoteRetention {
                            sapling: use_sapling,
                            #[cfg(feature = "orchard")]
                            orchard: use_orchard,
                        }))
                        .map(|notes| ShieldedInputs::from_parts(anchor_height, notes));

                    #[cfg(feature = "transparent-inputs")]
                    if let Some(tr1_balance) = tr1_balance_opt {
                        // Construct two new `TransactionRequest`s:
                        // * `tr0` excludes the TEX outputs, and in their place includes
                        //   a single additional ephemeral output to the transparent pool.
                        // * `tr1` spends from that ephemeral output to each TEX output.

                        // Find exactly one ephemeral change output.
                        let ephemeral_outputs = balance
                            .proposed_change()
                            .iter()
                            .enumerate()
                            .filter(|(_, c)| c.is_ephemeral())
                            .collect::<Vec<_>>();

                        let ephemeral_value = ephemeral_balance
                            .and_then(|b| b.ephemeral_output_amount())
                            .expect("ephemeral output balance exists (constructed above)");

                        let ephemeral_output_index = match &ephemeral_outputs[..] {
                            [(i, change_value)] if change_value.value() == ephemeral_value => {
                                Ok(*i)
                            }
                            _ => Err(InputSelectorError::Proposal(
                                ProposalError::EphemeralOutputsInvalid,
                            )),
                        }?;

                        let ephemeral_stepoutput =
                            StepOutput::new(0, StepOutputIndex::Change(ephemeral_output_index));

                        let tr0 = TransactionRequest::from_indexed(
                            transaction_request
                                .payments()
                                .iter()
                                .filter(|(idx, _payment)| !tr1_payment_pools.contains_key(idx))
                                .map(|(k, v)| (*k, v.clone()))
                                .collect(),
                        )
                        .expect("removing payments from a TransactionRequest preserves validity");

                        let mut steps = vec![];
                        steps.push(
                            Step::from_parts(
                                &[],
                                tr0,
                                payment_pools,
                                vec![],
                                shielded_inputs,
                                vec![],
                                balance,
                                false,
                            )
                            .map_err(InputSelectorError::Proposal)?,
                        );

                        let tr1 =
                            TransactionRequest::new(tr1_payments).expect("valid by construction");
                        steps.push(
                            Step::from_parts(
                                &steps,
                                tr1,
                                tr1_payment_pools,
                                vec![],
                                None,
                                vec![ephemeral_stepoutput],
                                tr1_balance,
                                false,
                            )
                            .map_err(InputSelectorError::Proposal)?,
                        );

                        return Proposal::multi_step(
                            change_strategy.fee_rule().clone(),
                            target_height,
                            NonEmpty::from_vec(steps).expect("steps is known to be nonempty"),
                        )
                        .map_err(InputSelectorError::Proposal);
                    }

                    return Proposal::single_step(
                        transaction_request,
                        payment_pools,
                        vec![],
                        shielded_inputs,
                        balance,
                        (*change_strategy.fee_rule()).clone(),
                        target_height,
                        false,
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
                    TargetValue::MinValue(amount_required),
                    selectable_pools,
                    anchor_height,
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
        target_height: BlockHeight,
        min_confirmations: u32,
    ) -> Result<
        Proposal<<ChangeT as ChangeStrategy>::FeeRule, Infallible>,
        InputSelectorError<<DbT as InputSource>::Error, Self::Error, ChangeT::Error, Infallible>,
    >
    where
        ParamsT: consensus::Parameters,
        ChangeT: ChangeStrategy<MetaSource = Self::InputSource>,
    {
        let mut transparent_inputs: Vec<WalletTransparentOutput> = source_addrs
            .iter()
            .map(|taddr| {
                wallet_db.get_spendable_transparent_outputs(taddr, target_height, min_confirmations)
            })
            .collect::<Result<Vec<Vec<_>>, _>>()
            .map_err(InputSelectorError::DataSource)?
            .into_iter()
            .flat_map(|v| v.into_iter())
            .collect();

        let wallet_meta = change_strategy
            .fetch_wallet_meta(wallet_db, to_account, &[])
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

impl<DbT: InputSource> SendMaxSelector for GreedyInputSelector<DbT> {
    type Error = GreedyInputSelectorError;
    type InputSource = DbT;

    fn propose_send_max<ParamsT, ChangeT>(
        &self,
        params: &ParamsT,
        wallet_db: &Self::InputSource,
        change_strategy: &ChangeT,
        source_account: <Self::InputSource as InputSource>::AccountId,
        spend_pools: &[ShieldedProtocol],
        anchor_height: BlockHeight,
        target_height: BlockHeight,
        recipient: ZcashAddress,
        memo: Option<MemoBytes>,
    ) -> Result<
        Proposal<<ChangeT as ChangeStrategy>::FeeRule, DbT::NoteRef>,
        InputSelectorError<<DbT as InputSource>::Error, Self::Error, ChangeT::Error, DbT::NoteRef>,
    >
    where
        ParamsT: consensus::Parameters,
        Self::InputSource: InputSource,
        ChangeT: ChangeStrategy<MetaSource = DbT>,
    {
        let spendable_notes = wallet_db
            .select_spendable_notes(
                source_account,
                TargetValue::MaxSpendable,
                spend_pools,
                anchor_height,
                &vec![],
            )
            .map_err(InputSelectorError::DataSource)?;

        let input_total = spendable_notes.total()?;
        let fee_required = match recipient
            .clone()
            .convert_if_network(params.network_type())?
        {
            Address::Sapling(_) => change_strategy.fee_rule().fee_required(
                params,
                target_height,
                [],
                [],
                spendable_notes.sapling().len(),
                1,
                spendable_notes.orchard().len(),
            ),
            Address::Transparent(_) => change_strategy.fee_rule().fee_required(
                params,
                target_height,
                [],
                [P2PKH_STANDARD_OUTPUT_SIZE],
                spendable_notes.sapling().len(),
                0,
                spendable_notes.orchard().len(),
            ),
            Address::Unified(addr) => {
                if cfg!(feature = "orchard") && addr.has_orchard() {
                    change_strategy.fee_rule().fee_required(
                        params,
                        target_height,
                        [],
                        [],
                        spendable_notes.sapling().len(),
                        0,
                        std::cmp::max(spendable_notes.orchard().len(), 1),
                    )
                } else if addr.has_sapling() {
                    change_strategy.fee_rule().fee_required(
                        params,
                        target_height,
                        [],
                        [],
                        spendable_notes.sapling().len(),
                        1,
                        spendable_notes.orchard().len(),
                    )
                } else if addr.has_transparent() {
                    change_strategy.fee_rule().fee_required(
                        params,
                        target_height,
                        [],
                        [P2PKH_STANDARD_OUTPUT_SIZE],
                        spendable_notes.sapling().len(),
                        0,
                        spendable_notes.orchard().len(),
                    )
                } else {
                    unreachable!()
                }
            }
            Address::Tex(_) => change_strategy
                .fee_rule()
                .fee_required(
                    params,
                    target_height,
                    [],
                    [P2PKH_STANDARD_OUTPUT_SIZE],
                    spendable_notes.sapling().len(),
                    0,
                    spendable_notes.orchard().len(),
                )
                .and_then(|t0_fee| {
                    let t1_fee = change_strategy.fee_rule().fee_required(
                        params,
                        target_height,
                        [InputSize::Known(P2PKH_STANDARD_INPUT_SIZE)],
                        [P2PKH_STANDARD_OUTPUT_SIZE],
                        0,
                        0,
                        0,
                    )?;

                    Ok((t0_fee + t1_fee).expect("fee is in range of valid Zatoshis values"))
                }),
        }
        .map_err(|fee_error| {
            InputSelectorError::Change(ChangeError::StrategyError(ChangeT::Error::from(fee_error)))
        })?;

        let transaction_request = TransactionRequest::new(vec![zip321::Payment::new(
            recipient,
            (input_total - fee_required).ok_or(BalanceError::Underflow)?,
            memo,
            None,
            None,
            vec![],
        )
        .unwrap()])
        .unwrap();

        self.propose_transaction(
            params,
            wallet_db,
            target_height,
            anchor_height,
            source_account,
            transaction_request,
            change_strategy,
        )
    }
}
