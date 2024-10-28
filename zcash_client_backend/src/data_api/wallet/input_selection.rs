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
    std::collections::BTreeSet, std::convert::Infallible,
    zcash_primitives::legacy::TransparentAddress,
    zcash_primitives::transaction::components::OutPoint,
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
        for (idx, payment) in transaction_request.payments() {
            let recipient_address: Address = payment
                .recipient_address()
                .clone()
                .convert_if_network(params.network_type())?;

            match recipient_address {
                Address::Transparent(addr) => {
                    payment_pools.insert(*idx, PoolType::Transparent);
                    transparent_outputs.push(TxOut {
                        value: payment.amount(),
                        script_pubkey: addr.script(),
                    });
                }
                Address::Sapling(_) => {
                    payment_pools.insert(*idx, PoolType::Shielded(ShieldedProtocol::Sapling));
                    sapling_outputs.push(SaplingPayment(payment.amount()));
                }
                Address::Unified(addr) => {
                    #[cfg(feature = "orchard")]
                    if addr.orchard().is_some() {
                        payment_pools.insert(*idx, PoolType::Shielded(ShieldedProtocol::Orchard));
                        orchard_outputs.push(OrchardPayment(payment.amount()));
                        continue;
                    }

                    if addr.sapling().is_some() {
                        payment_pools.insert(*idx, PoolType::Shielded(ShieldedProtocol::Sapling));
                        sapling_outputs.push(SaplingPayment(payment.amount()));
                        continue;
                    }

                    if let Some(addr) = addr.transparent() {
                        payment_pools.insert(*idx, PoolType::Transparent);
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

                // Use Sapling inputs if there are no Orchard outputs or there are not sufficient
                // Orchard outputs to cover the amount required.
                let use_sapling =
                    orchard_outputs.is_empty() || amount_required > orchard_input_total;
                // Use Orchard inputs if there are insufficient Sapling funds to cover the amount
                // reqiuired.
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

            let balance = self.change_strategy.compute_balance(
                params,
                target_height,
                &Vec::<WalletTransparentOutput>::new(),
                &transparent_outputs,
                &(
                    ::sapling::builder::BundleType::DEFAULT,
                    &sapling_inputs[..],
                    &sapling_outputs[..],
                ),
                #[cfg(feature = "orchard")]
                &(
                    ::orchard::builder::BundleType::DEFAULT_VANILLA,
                    &orchard_inputs[..],
                    &orchard_outputs[..],
                ),
                &self.dust_output_policy,
            );

            match balance {
                Ok(balance) => {
                    return Proposal::single_step(
                        transaction_request,
                        payment_pools,
                        vec![],
                        NonEmpty::from_vec(shielded_inputs.into_vec(&SimpleNoteRetention {
                            sapling: use_sapling,
                            #[cfg(feature = "orchard")]
                            orchard: use_orchard,
                        }))
                        .map(|notes| ShieldedInputs::from_parts(anchor_height, notes)),
                        balance,
                        (*self.change_strategy.fee_rule()).clone(),
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
                wallet_db.get_unspent_transparent_outputs(
                    taddr,
                    target_height - min_confirmations,
                    &[],
                )
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
            &Vec::<TxOut>::new(),
            &(
                ::sapling::builder::BundleType::DEFAULT,
                &Vec::<Infallible>::new()[..],
                &Vec::<Infallible>::new()[..],
            ),
            #[cfg(feature = "orchard")]
            &(
                orchard::builder::BundleType::DEFAULT_VANILLA,
                &Vec::<Infallible>::new()[..],
                &Vec::<Infallible>::new()[..],
            ),
            &self.dust_output_policy,
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
                    &Vec::<TxOut>::new(),
                    &(
                        ::sapling::builder::BundleType::DEFAULT,
                        &Vec::<Infallible>::new()[..],
                        &Vec::<Infallible>::new()[..],
                    ),
                    #[cfg(feature = "orchard")]
                    &(
                        orchard::builder::BundleType::DEFAULT_VANILLA,
                        &Vec::<Infallible>::new()[..],
                        &Vec::<Infallible>::new()[..],
                    ),
                    &self.dust_output_policy,
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
