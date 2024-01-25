//! Types related to the process of selecting inputs to be spent given a transaction request.

use core::marker::PhantomData;
use std::fmt::{self, Debug, Display};

use nonempty::NonEmpty;
use zcash_primitives::{
    consensus::{self, BlockHeight},
    legacy::TransparentAddress,
    transaction::{
        components::{
            amount::{BalanceError, NonNegativeAmount},
            TxOut,
        },
        fees::FeeRule,
    },
    zip32::AccountId,
};

use crate::{
    address::{Address, UnifiedAddress},
    data_api::InputSource,
    fees::{sapling, ChangeError, ChangeStrategy, DustOutputPolicy, TransactionBalance},
    wallet::{Note, ReceivedNote, WalletTransparentOutput},
    zip321::TransactionRequest,
    ShieldedProtocol,
};

#[cfg(any(feature = "transparent-inputs", feature = "orchard"))]
use std::convert::Infallible;

#[cfg(feature = "transparent-inputs")]
use {std::collections::BTreeSet, zcash_primitives::transaction::components::OutPoint};

#[cfg(feature = "orchard")]
use crate::fees::orchard as orchard_fees;

/// The type of errors that may be produced in input selection.
pub enum InputSelectorError<DbErrT, SelectorErrT> {
    /// An error occurred accessing the underlying data store.
    DataSource(DbErrT),
    /// An error occurred specific to the provided input selector's selection rules.
    Selection(SelectorErrT),
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

/// The inputs to be consumed and outputs to be produced in a proposed transaction.
#[derive(Clone, PartialEq, Eq)]
pub struct Proposal<FeeRuleT, NoteRef> {
    transaction_request: TransactionRequest,
    transparent_inputs: Vec<WalletTransparentOutput>,
    shielded_inputs: Option<ShieldedInputs<NoteRef>>,
    balance: TransactionBalance,
    fee_rule: FeeRuleT,
    min_target_height: BlockHeight,
    is_shielding: bool,
}

/// Errors that can occur in construction of a [`Proposal`].
#[derive(Debug, Clone)]
pub enum ProposalError {
    /// The total output value of the transaction request is not a valid Zcash amount.
    RequestTotalInvalid,
    /// The total of transaction inputs overflows the valid range of Zcash values.
    Overflow,
    /// The input total and output total of the payment request are not equal to one another. The
    /// sum of transaction outputs, change, and fees is required to be exactly equal to the value
    /// of provided inputs.
    BalanceError {
        input_total: NonNegativeAmount,
        output_total: NonNegativeAmount,
    },
    /// The `is_shielding` flag may only be set to `true` under the following conditions:
    /// * The total of transparent inputs is nonzero
    /// * There exist no Sapling inputs
    /// * There provided transaction request is empty; i.e. the only output values specified
    ///   are change and fee amounts.
    ShieldingInvalid,
}

impl Display for ProposalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProposalError::RequestTotalInvalid => write!(
                f,
                "The total requested output value is not a valid Zcash amount."
            ),
            ProposalError::Overflow => write!(
                f,
                "The total of transaction inputs overflows the valid range of Zcash values."
            ),
            ProposalError::BalanceError {
                input_total,
                output_total,
            } => write!(
                f,
                "Balance error: the output total {} was not equal to the input total {}",
                u64::from(*output_total),
                u64::from(*input_total)
            ),
            ProposalError::ShieldingInvalid => write!(
                f,
                "The proposal violates the rules for a shielding transaction."
            ),
        }
    }
}

impl std::error::Error for ProposalError {}

impl<FeeRuleT, NoteRef> Proposal<FeeRuleT, NoteRef> {
    /// Constructs a validated [`Proposal`] from its constituent parts.
    ///
    /// This operation validates the proposal for balance consistency and agreement between
    /// the `is_shielding` flag and the structure of the proposal.
    #[allow(clippy::too_many_arguments)]
    pub fn from_parts(
        transaction_request: TransactionRequest,
        transparent_inputs: Vec<WalletTransparentOutput>,
        shielded_inputs: Option<ShieldedInputs<NoteRef>>,
        balance: TransactionBalance,
        fee_rule: FeeRuleT,
        min_target_height: BlockHeight,
        is_shielding: bool,
    ) -> Result<Self, ProposalError> {
        let transparent_input_total = transparent_inputs
            .iter()
            .map(|out| out.txout().value)
            .fold(Ok(NonNegativeAmount::ZERO), |acc, a| {
                (acc? + a).ok_or(ProposalError::Overflow)
            })?;
        let shielded_input_total = shielded_inputs
            .iter()
            .flat_map(|s_in| s_in.notes().iter())
            .map(|out| out.note().value())
            .fold(Some(NonNegativeAmount::ZERO), |acc, a| (acc? + a))
            .ok_or(ProposalError::Overflow)?;
        let input_total =
            (transparent_input_total + shielded_input_total).ok_or(ProposalError::Overflow)?;

        let request_total = transaction_request
            .total()
            .map_err(|_| ProposalError::RequestTotalInvalid)?;
        let output_total = (request_total + balance.total()).ok_or(ProposalError::Overflow)?;

        if is_shielding
            && (transparent_input_total == NonNegativeAmount::ZERO
                || shielded_input_total > NonNegativeAmount::ZERO
                || request_total > NonNegativeAmount::ZERO)
        {
            return Err(ProposalError::ShieldingInvalid);
        }

        if input_total == output_total {
            Ok(Self {
                transaction_request,
                transparent_inputs,
                shielded_inputs,
                balance,
                fee_rule,
                min_target_height,
                is_shielding,
            })
        } else {
            Err(ProposalError::BalanceError {
                input_total,
                output_total,
            })
        }
    }

    /// Returns the transaction request that describes the payments to be made.
    pub fn transaction_request(&self) -> &TransactionRequest {
        &self.transaction_request
    }
    /// Returns the transparent inputs that have been selected to fund the transaction.
    pub fn transparent_inputs(&self) -> &[WalletTransparentOutput] {
        &self.transparent_inputs
    }
    /// Returns the Sapling inputs that have been selected to fund the transaction.
    pub fn shielded_inputs(&self) -> Option<&ShieldedInputs<NoteRef>> {
        self.shielded_inputs.as_ref()
    }
    /// Returns the change outputs to be added to the transaction and the fee to be paid.
    pub fn balance(&self) -> &TransactionBalance {
        &self.balance
    }
    /// Returns the fee rule to be used by the transaction builder.
    pub fn fee_rule(&self) -> &FeeRuleT {
        &self.fee_rule
    }
    /// Returns the target height for which the proposal was prepared.
    ///
    /// The chain must contain at least this many blocks in order for the proposal to
    /// be executed.
    pub fn min_target_height(&self) -> BlockHeight {
        self.min_target_height
    }
    /// Returns a flag indicating whether or not the proposed transaction
    /// is exclusively wallet-internal (if it does not involve any external
    /// recipients).
    pub fn is_shielding(&self) -> bool {
        self.is_shielding
    }
}

impl<FeeRuleT, NoteRef> Debug for Proposal<FeeRuleT, NoteRef> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Proposal")
            .field("transaction_request", &self.transaction_request)
            .field("transparent_inputs", &self.transparent_inputs)
            .field(
                "shielded_inputs",
                &self.shielded_inputs().map(|i| i.notes.len()),
            )
            .field(
                "anchor_height",
                &self.shielded_inputs().map(|i| i.anchor_height),
            )
            .field("balance", &self.balance)
            //.field("fee_rule", &self.fee_rule)
            .field("min_target_height", &self.min_target_height)
            .field("is_shielding", &self.is_shielding)
            .finish_non_exhaustive()
    }
}

/// The Sapling inputs to a proposed transaction.
#[derive(Clone, PartialEq, Eq)]
pub struct ShieldedInputs<NoteRef> {
    anchor_height: BlockHeight,
    notes: NonEmpty<ReceivedNote<NoteRef, Note>>,
}

impl<NoteRef> ShieldedInputs<NoteRef> {
    /// Constructs a [`ShieldedInputs`] from its constituent parts.
    pub fn from_parts(
        anchor_height: BlockHeight,
        notes: NonEmpty<ReceivedNote<NoteRef, Note>>,
    ) -> Self {
        Self {
            anchor_height,
            notes,
        }
    }

    /// Returns the anchor height for Sapling inputs that should be used when constructing the
    /// proposed transaction.
    pub fn anchor_height(&self) -> BlockHeight {
        self.anchor_height
    }

    /// Returns the list of Sapling notes to be used as inputs to the proposed transaction.
    pub fn notes(&self) -> &NonEmpty<ReceivedNote<NoteRef, Note>> {
        &self.notes
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
        account: AccountId,
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

// TODO: introduce this method when it is needed for testing.
// #[cfg(test)]
// impl OrchardPayment {
//     pub(crate) fn new(amount: NonNegativeAmount) -> Self {
//         OrchardPayment(amount)
//     }
// }

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
        account: AccountId,
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
        for payment in transaction_request.payments() {
            let mut push_transparent = |taddr: TransparentAddress| {
                transparent_outputs.push(TxOut {
                    value: payment.amount,
                    script_pubkey: taddr.script(),
                });
            };
            let mut push_sapling = || {
                sapling_outputs.push(SaplingPayment(payment.amount));
            };
            #[cfg(feature = "orchard")]
            let mut push_orchard = || {
                orchard_outputs.push(OrchardPayment(payment.amount));
            };

            match &payment.recipient_address {
                Address::Transparent(addr) => {
                    push_transparent(*addr);
                }
                Address::Sapling(_) => {
                    push_sapling();
                }
                Address::Unified(addr) => {
                    #[cfg(feature = "orchard")]
                    let has_orchard = addr.orchard().is_some();
                    #[cfg(not(feature = "orchard"))]
                    let has_orchard = false;

                    if has_orchard {
                        #[cfg(feature = "orchard")]
                        push_orchard();
                    } else if addr.sapling().is_some() {
                        push_sapling();
                    } else if let Some(addr) = addr.transparent() {
                        push_transparent(*addr);
                    } else {
                        return Err(InputSelectorError::Selection(
                            GreedyInputSelectorError::UnsupportedAddress(Box::new(addr.clone())),
                        ));
                    }
                }
            }
        }

        let mut shielded_inputs: Vec<ReceivedNote<DbT::NoteRef, Note>> = vec![];
        let mut prior_available = NonNegativeAmount::ZERO;
        let mut amount_required = NonNegativeAmount::ZERO;
        let mut exclude: Vec<DbT::NoteRef> = vec![];
        // This loop is guaranteed to terminate because on each iteration we check that the amount
        // of funds selected is strictly increasing. The loop will either return a successful
        // result or the wallet will eventually run out of funds to select.
        loop {
            let balance = self.change_strategy.compute_balance(
                params,
                target_height,
                &Vec::<WalletTransparentOutput>::new(),
                &transparent_outputs,
                &(
                    ::sapling::builder::BundleType::DEFAULT,
                    &shielded_inputs
                        .iter()
                        .filter_map(|i| {
                            i.clone().traverse_opt(|wn| match wn {
                                Note::Sapling(n) => Some(n),
                                #[cfg(feature = "orchard")]
                                _ => None,
                            })
                        })
                        .collect::<Vec<_>>()[..],
                    &sapling_outputs[..],
                ),
                #[cfg(feature = "orchard")]
                &(
                    ::orchard::builder::BundleType::DEFAULT,
                    &shielded_inputs
                        .iter()
                        .filter_map(|i| {
                            i.clone().traverse_opt(|wn| match wn {
                                Note::Orchard(n) => Some(n),
                                _ => None,
                            })
                        })
                        .collect::<Vec<_>>()[..],
                    &orchard_outputs[..],
                ),
                &self.dust_output_policy,
            );

            match balance {
                Ok(balance) => {
                    return Ok(Proposal {
                        transaction_request,
                        transparent_inputs: vec![],
                        shielded_inputs: NonEmpty::from_vec(shielded_inputs).map(|notes| {
                            ShieldedInputs {
                                anchor_height,
                                notes,
                            }
                        }),
                        balance,
                        fee_rule: (*self.change_strategy.fee_rule()).clone(),
                        min_target_height: target_height,
                        is_shielding: false,
                    });
                }
                Err(ChangeError::DustInputs { mut sapling, .. }) => {
                    exclude.append(&mut sapling);
                }
                Err(ChangeError::InsufficientFunds { required, .. }) => {
                    amount_required = required;
                }
                Err(other) => return Err(other.into()),
            }

            #[cfg(not(zcash_unstable = "orchard"))]
            let selectable_pools = &[ShieldedProtocol::Sapling];
            #[cfg(zcash_unstable = "orchard")]
            let selectable_pools = &[ShieldedProtocol::Sapling, ShieldedProtocol::Orchard];

            shielded_inputs = wallet_db
                .select_spendable_notes(
                    account,
                    amount_required.into(),
                    selectable_pools,
                    anchor_height,
                    &exclude,
                )
                .map_err(InputSelectorError::DataSource)?;

            let new_available = shielded_inputs
                .iter()
                .map(|n| n.note().value())
                .sum::<Option<NonNegativeAmount>>()
                .ok_or(BalanceError::Overflow)?;

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
                orchard::builder::BundleType::DEFAULT,
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
                        orchard::builder::BundleType::DEFAULT,
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
            Ok(Proposal {
                transaction_request: TransactionRequest::empty(),
                transparent_inputs,
                shielded_inputs: None,
                balance,
                fee_rule: (*self.change_strategy.fee_rule()).clone(),
                min_target_height: target_height,
                is_shielding: true,
            })
        } else {
            Err(InputSelectorError::InsufficientFunds {
                available: balance.total(),
                required: shielding_threshold,
            })
        }
    }
}
