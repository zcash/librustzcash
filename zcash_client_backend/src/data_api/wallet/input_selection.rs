//! Types related to the process of selecting inputs to be spent given a transaction request.

use core::marker::PhantomData;
use std::{
    collections::BTreeMap,
    error,
    fmt::{self, Debug, Display},
};

use nonempty::NonEmpty;
use zcash_address::ConversionError;
use zcash_primitives::{
    consensus::{self, BlockHeight},
    transaction::{
        components::{
            amount::{BalanceError, NonNegativeAmount},
            TxOut,
        },
        fees::FeeRule,
    },
};

use crate::{
    address::{Address, UnifiedAddress},
    data_api::{InputSource, SimpleNoteRetention, SpendableNotes},
    fees::{sapling, ChangeError, ChangeStrategy, DustOutputPolicy},
    proposal::{Proposal, ProposalError, ShieldedInputs},
    wallet::WalletTransparentOutput,
    zip321::TransactionRequest,
    PoolType, ShieldedProtocol,
};

#[cfg(feature = "transparent-inputs")]
use {
    crate::{
        fees::ChangeValue,
        proposal::{Step, StepOutput, StepOutputIndex},
        zip321::Payment,
    },
    std::collections::BTreeSet,
    std::convert::Infallible,
    zcash_primitives::{legacy::TransparentAddress, transaction::components::OutPoint},
};

#[cfg(feature = "orchard")]
use crate::fees::orchard as orchard_fees;

/// The type of errors that may be produced in input selection.
#[derive(Debug)]
pub enum InputSelectorError<DbErrT, SelectorErrT> {
    /// An error occurred accessing the underlying data store.
    DataSource(DbErrT),
    /// An error occurred specific to the provided input selector's selection rules.
    Selection(SelectorErrT),
    /// Input selection attempted to generate an invalid transaction proposal.
    Proposal(ProposalError),
    /// An error occurred parsing the address from a payment request.
    Address(ConversionError<&'static str>),
    /// Insufficient funds were available to satisfy the payment request that inputs were being
    /// selected to attempt to satisfy.
    InsufficientFunds {
        available: NonNegativeAmount,
        required: NonNegativeAmount,
    },
    /// The data source does not have enough information to choose an expiry height
    /// for the transaction.
    SyncRequired,
}

impl<E, S> From<ConversionError<&'static str>> for InputSelectorError<E, S> {
    fn from(value: ConversionError<&'static str>) -> Self {
        InputSelectorError::Address(value)
    }
}

impl<DE: fmt::Display, SE: fmt::Display> fmt::Display for InputSelectorError<DE, SE> {
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

impl<DE, SE> error::Error for InputSelectorError<DE, SE>
where
    DE: Debug + Display + error::Error + 'static,
    SE: Debug + Display + error::Error + 'static,
{
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match &self {
            Self::DataSource(e) => Some(e),
            Self::Selection(e) => Some(e),
            Self::Proposal(e) => Some(e),
            _ => None,
        }
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
    /// The type of data source that the input selector expects to access to obtain input Sapling
    /// notes. This associated type permits input selectors that may use specialized knowledge of
    /// the internals of a particular backing data store, if the generic API of
    /// `InputSource` does not provide sufficiently fine-grained operations for a particular
    /// backing store to optimally perform input selection.
    type InputSource: InputSource;
    /// The type of the fee rule that this input selector uses when computing fees.
    type FeeRule: FeeRule;

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
    fn propose_transaction<ParamsT>(
        &self,
        params: &ParamsT,
        wallet_db: &Self::InputSource,
        target_height: BlockHeight,
        anchor_height: BlockHeight,
        account: <Self::InputSource as InputSource>::AccountId,
        transaction_request: TransactionRequest,
    ) -> Result<
        Proposal<Self::FeeRule, <Self::InputSource as InputSource>::NoteRef>,
        InputSelectorError<<Self::InputSource as InputSource>::Error, Self::Error>,
    >
    where
        ParamsT: consensus::Parameters;
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
    /// The type of the fee rule that this input selector uses when computing fees.
    type FeeRule: FeeRule;

    /// Performs input selection and returns a proposal for the construction of a shielding
    /// transaction.
    ///
    /// Implementations should return the maximum possible number of economically useful inputs
    /// required to supply at least the requested value, choosing only inputs received at the
    /// specified source addresses. If insufficient funds are available to satisfy the required
    /// outputs for the shielding request, this operation must fail and return
    /// [`InputSelectorError::InsufficientFunds`].
    #[allow(clippy::type_complexity)]
    fn propose_shielding<ParamsT>(
        &self,
        params: &ParamsT,
        wallet_db: &Self::InputSource,
        shielding_threshold: NonNegativeAmount,
        source_addrs: &[TransparentAddress],
        target_height: BlockHeight,
        min_confirmations: u32,
    ) -> Result<
        Proposal<Self::FeeRule, Infallible>,
        InputSelectorError<<Self::InputSource as InputSource>::Error, Self::Error>,
    >
    where
        ParamsT: consensus::Parameters;
}

/// Errors that can occur as a consequence of greedy input selection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GreedyInputSelectorError<ChangeStrategyErrT, NoteRefT> {
    /// An intermediate value overflowed or underflowed the valid monetary range.
    Balance(BalanceError),
    /// A unified address did not contain a supported receiver.
    UnsupportedAddress(Box<UnifiedAddress>),
    /// Support for transparent-source-only (TEX) addresses requires the transparent-inputs feature.
    UnsupportedTexAddress,
    /// An error was encountered in change selection.
    Change(ChangeError<ChangeStrategyErrT, NoteRefT>),
}

impl<CE: fmt::Display, N: fmt::Display> fmt::Display for GreedyInputSelectorError<CE, N> {
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
            GreedyInputSelectorError::Change(err) => {
                write!(f, "An error occurred computing change and fees: {}", err)
            }
        }
    }
}

impl<DbErrT, ChangeStrategyErrT, NoteRefT>
    From<GreedyInputSelectorError<ChangeStrategyErrT, NoteRefT>>
    for InputSelectorError<DbErrT, GreedyInputSelectorError<ChangeStrategyErrT, NoteRefT>>
{
    fn from(err: GreedyInputSelectorError<ChangeStrategyErrT, NoteRefT>) -> Self {
        InputSelectorError::Selection(err)
    }
}

impl<DbErrT, ChangeStrategyErrT, NoteRefT> From<ChangeError<ChangeStrategyErrT, NoteRefT>>
    for InputSelectorError<DbErrT, GreedyInputSelectorError<ChangeStrategyErrT, NoteRefT>>
{
    fn from(err: ChangeError<ChangeStrategyErrT, NoteRefT>) -> Self {
        InputSelectorError::Selection(GreedyInputSelectorError::Change(err))
    }
}

impl<DbErrT, ChangeStrategyErrT, NoteRefT> From<BalanceError>
    for InputSelectorError<DbErrT, GreedyInputSelectorError<ChangeStrategyErrT, NoteRefT>>
{
    fn from(err: BalanceError) -> Self {
        InputSelectorError::Selection(GreedyInputSelectorError::Balance(err))
    }
}

pub(crate) struct SaplingPayment(NonNegativeAmount);

#[cfg(test)]
impl SaplingPayment {
    pub(crate) fn new(amount: NonNegativeAmount) -> Self {
        SaplingPayment(amount)
    }
}

impl sapling::OutputView for SaplingPayment {
    fn value(&self) -> NonNegativeAmount {
        self.0
    }
}

#[cfg(feature = "orchard")]
pub(crate) struct OrchardPayment(NonNegativeAmount);

#[cfg(test)]
#[cfg(feature = "orchard")]
impl OrchardPayment {
    pub(crate) fn new(amount: NonNegativeAmount) -> Self {
        OrchardPayment(amount)
    }
}

#[cfg(feature = "orchard")]
impl orchard_fees::OutputView for OrchardPayment {
    fn value(&self) -> NonNegativeAmount {
        self.0
    }
}

/// An [`InputSelector`] implementation that uses a greedy strategy to select between available
/// notes.
///
/// This implementation performs input selection using methods available via the
/// [`InputSource`] interface.
pub struct GreedyInputSelector<DbT, ChangeT> {
    change_strategy: ChangeT,
    dust_output_policy: DustOutputPolicy,
    _ds_type: PhantomData<DbT>,
}

impl<DbT, ChangeT: ChangeStrategy> GreedyInputSelector<DbT, ChangeT> {
    /// Constructs a new greedy input selector that uses the provided change strategy to determine
    /// change values and fee amounts.
    pub fn new(change_strategy: ChangeT, dust_output_policy: DustOutputPolicy) -> Self {
        GreedyInputSelector {
            change_strategy,
            dust_output_policy,
            _ds_type: PhantomData,
        }
    }
}

impl<DbT, ChangeT> InputSelector for GreedyInputSelector<DbT, ChangeT>
where
    DbT: InputSource,
    ChangeT: ChangeStrategy,
    ChangeT::FeeRule: Clone,
{
    type Error = GreedyInputSelectorError<ChangeT::Error, DbT::NoteRef>;
    type InputSource = DbT;
    type FeeRule = ChangeT::FeeRule;

    #[allow(clippy::type_complexity)]
    fn propose_transaction<ParamsT>(
        &self,
        params: &ParamsT,
        wallet_db: &Self::InputSource,
        target_height: BlockHeight,
        anchor_height: BlockHeight,
        account: <DbT as InputSource>::AccountId,
        transaction_request: TransactionRequest,
    ) -> Result<
        Proposal<Self::FeeRule, DbT::NoteRef>,
        InputSelectorError<<DbT as InputSource>::Error, Self::Error>,
    >
    where
        ParamsT: consensus::Parameters,
        Self::InputSource: InputSource,
    {
        let mut transparent_outputs = vec![];
        let mut sapling_outputs = vec![];
        #[cfg(feature = "orchard")]
        let mut orchard_outputs = vec![];
        let mut payment_pools = BTreeMap::new();

        #[cfg(feature = "transparent-inputs")]
        let mut tr1_transparent_outputs = vec![];
        #[cfg(feature = "transparent-inputs")]
        let mut tr1_payments = vec![];
        #[cfg(feature = "transparent-inputs")]
        let mut tr1_payment_pools = BTreeMap::new();
        #[cfg(feature = "transparent-inputs")]
        let mut total_ephemeral = NonNegativeAmount::ZERO;

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
                        .ok_or_else(|| GreedyInputSelectorError::Balance(BalanceError::Overflow))?;
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
                    if addr.orchard().is_some() {
                        payment_pools.insert(*idx, PoolType::ORCHARD);
                        orchard_outputs.push(OrchardPayment(payment.amount()));
                        continue;
                    }

                    if addr.sapling().is_some() {
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

        #[cfg(feature = "transparent-inputs")]
        let (ephemeral_output_amounts, tr1_balance_opt) = {
            if tr1_transparent_outputs.is_empty() {
                (vec![], None)
            } else {
                // The ephemeral input going into transaction 1 must be able to pay that
                // transaction's fee, as well as the TEX address payments.

                // First compute the required total without providing any input value,
                // catching the `InsufficientFunds` error to obtain the required amount
                // given the provided change strategy.
                let tr1_required_input_value =
                    match self.change_strategy.compute_balance::<_, DbT::NoteRef>(
                        params,
                        target_height,
                        &[] as &[WalletTransparentOutput],
                        &tr1_transparent_outputs,
                        &sapling::EmptyBundleView,
                        #[cfg(feature = "orchard")]
                        &orchard_fees::EmptyBundleView,
                        &self.dust_output_policy,
                        #[cfg(feature = "transparent-inputs")]
                        true, // ignore change memo to avoid adding a change output
                        #[cfg(feature = "transparent-inputs")]
                        &[NonNegativeAmount::ZERO],
                        #[cfg(feature = "transparent-inputs")]
                        &[],
                    ) {
                        Err(ChangeError::InsufficientFunds { required, .. }) => required,
                        Ok(_) => NonNegativeAmount::ZERO, // shouldn't happen
                        Err(other) => return Err(other.into()),
                    };

                // Now recompute to obtain the `TransactionBalance` and verify that it
                // fully accounts for the required fees.
                let tr1_balance = self.change_strategy.compute_balance::<_, DbT::NoteRef>(
                    params,
                    target_height,
                    &[] as &[WalletTransparentOutput],
                    &tr1_transparent_outputs,
                    &sapling::EmptyBundleView,
                    #[cfg(feature = "orchard")]
                    &orchard_fees::EmptyBundleView,
                    &self.dust_output_policy,
                    #[cfg(feature = "transparent-inputs")]
                    true, // ignore change memo to avoid adding a change output
                    #[cfg(feature = "transparent-inputs")]
                    &[tr1_required_input_value],
                    #[cfg(feature = "transparent-inputs")]
                    &[],
                )?;
                assert_eq!(tr1_balance.total(), tr1_balance.fee_required());

                (vec![tr1_required_input_value], Some(tr1_balance))
            }
        };

        let mut shielded_inputs = SpendableNotes::empty();
        let mut prior_available = NonNegativeAmount::ZERO;
        let mut amount_required = NonNegativeAmount::ZERO;
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

            // In the ZIP 320 case, this is the balance for transaction 0, taking into account
            // the ephemeral output.
            let balance = self.change_strategy.compute_balance(
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
                &self.dust_output_policy,
                #[cfg(feature = "transparent-inputs")]
                false,
                #[cfg(feature = "transparent-inputs")]
                &[],
                #[cfg(feature = "transparent-inputs")]
                &ephemeral_output_amounts,
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
                        //   a single additional "change" output to the transparent pool.
                        // * `tr1` spends from that change output to each TEX output.

                        // The ephemeral output should always be at the last change index.
                        assert_eq!(
                            *balance.proposed_change().last().expect("nonempty"),
                            ChangeValue::ephemeral_transparent(ephemeral_output_amounts[0])
                        );
                        let ephemeral_stepoutput = StepOutput::new(
                            0,
                            StepOutputIndex::Change(balance.proposed_change().len() - 1),
                        );

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
                            self.change_strategy.fee_rule().clone(),
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
                        self.change_strategy.fee_rule().clone(),
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
                Err(other) => return Err(other.into()),
            }

            #[cfg(not(feature = "orchard"))]
            let selectable_pools = &[ShieldedProtocol::Sapling];
            #[cfg(feature = "orchard")]
            let selectable_pools = &[ShieldedProtocol::Sapling, ShieldedProtocol::Orchard];

            shielded_inputs = wallet_db
                .select_spendable_notes(
                    account,
                    amount_required,
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
impl<DbT, ChangeT> ShieldingSelector for GreedyInputSelector<DbT, ChangeT>
where
    DbT: InputSource,
    ChangeT: ChangeStrategy,
    ChangeT::FeeRule: Clone,
{
    type Error = GreedyInputSelectorError<ChangeT::Error, Infallible>;
    type InputSource = DbT;
    type FeeRule = ChangeT::FeeRule;

    #[allow(clippy::type_complexity)]
    fn propose_shielding<ParamsT>(
        &self,
        params: &ParamsT,
        wallet_db: &Self::InputSource,
        shielding_threshold: NonNegativeAmount,
        source_addrs: &[TransparentAddress],
        target_height: BlockHeight,
        min_confirmations: u32,
    ) -> Result<
        Proposal<Self::FeeRule, Infallible>,
        InputSelectorError<<DbT as InputSource>::Error, Self::Error>,
    >
    where
        ParamsT: consensus::Parameters,
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

        let trial_balance = self.change_strategy.compute_balance(
            params,
            target_height,
            &transparent_inputs,
            &[] as &[TxOut],
            &sapling::EmptyBundleView,
            #[cfg(feature = "orchard")]
            &orchard_fees::EmptyBundleView,
            &self.dust_output_policy,
            #[cfg(feature = "transparent-inputs")]
            false,
            #[cfg(feature = "transparent-inputs")]
            &[],
            #[cfg(feature = "transparent-inputs")]
            &[],
        );

        let balance = match trial_balance {
            Ok(balance) => balance,
            Err(ChangeError::DustInputs { transparent, .. }) => {
                let exclusions: BTreeSet<OutPoint> = transparent.into_iter().collect();
                transparent_inputs.retain(|i| !exclusions.contains(i.outpoint()));

                self.change_strategy.compute_balance(
                    params,
                    target_height,
                    &transparent_inputs,
                    &[] as &[TxOut],
                    &sapling::EmptyBundleView,
                    #[cfg(feature = "orchard")]
                    &orchard_fees::EmptyBundleView,
                    &self.dust_output_policy,
                    #[cfg(feature = "transparent-inputs")]
                    false,
                    #[cfg(feature = "transparent-inputs")]
                    &[],
                    #[cfg(feature = "transparent-inputs")]
                    &[],
                )?
            }
            Err(other) => {
                return Err(other.into());
            }
        };

        if balance.total() >= shielding_threshold {
            Proposal::single_step(
                TransactionRequest::empty(),
                BTreeMap::new(),
                transparent_inputs,
                None,
                balance,
                (*self.change_strategy.fee_rule()).clone(),
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
