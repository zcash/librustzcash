//! Types related to the process of selecting inputs to be spent given a transaction request.

use core::marker::PhantomData;
use std::collections::BTreeSet;
use std::fmt;

use zcash_primitives::{
    consensus::{self, BlockHeight},
    legacy::TransparentAddress,
    transaction::{
        components::{
            amount::{Amount, BalanceError, NonNegativeAmount},
            sapling::fees as sapling,
            OutPoint, TxOut,
        },
        fees::FeeRule,
    },
    zip32::AccountId,
};

use crate::{
    address::{RecipientAddress, UnifiedAddress},
    data_api::WalletRead,
    fees::{ChangeError, ChangeStrategy, DustOutputPolicy, TransactionBalance},
    wallet::{SpendableNote, WalletTransparentOutput},
    zip321::TransactionRequest,
};

/// The type of errors that may be produced in input selection.
pub enum InputSelectorError<DbErrT, SelectorErrT> {
    /// An error occurred accessing the underlying data store.
    DataSource(DbErrT),
    /// An error occurred specific to the provided input selector's selection rules.
    Selection(SelectorErrT),
    /// Insufficient funds were available to satisfy the payment request that inputs were being
    /// selected to attempt to satisfy.
    InsufficientFunds { available: Amount, required: Amount },
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
                i64::from(*available),
                i64::from(*required)
            ),
        }
    }
}

/// A data structure that describes the inputs to be consumed and outputs to
/// be produced in a proposed transaction.
pub struct Proposal<FeeRuleT, NoteRef> {
    transaction_request: TransactionRequest,
    transparent_inputs: Vec<WalletTransparentOutput>,
    sapling_inputs: Vec<SpendableNote<NoteRef>>,
    balance: TransactionBalance,
    fee_rule: FeeRuleT,
    target_height: BlockHeight,
    is_shielding: bool,
}

impl<FeeRuleT, NoteRef> Proposal<FeeRuleT, NoteRef> {
    /// Returns the transaction request that describes the payments to be made.
    pub fn transaction_request(&self) -> &TransactionRequest {
        &self.transaction_request
    }
    /// Returns the transparent inputs that have been selected to fund the transaction.
    pub fn transparent_inputs(&self) -> &[WalletTransparentOutput] {
        &self.transparent_inputs
    }
    /// Returns the Sapling inputs that have been selected to fund the transaction.
    pub fn sapling_inputs(&self) -> &[SpendableNote<NoteRef>] {
        &self.sapling_inputs
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
    pub fn target_height(&self) -> BlockHeight {
        self.target_height
    }
    /// Returns a flag indicating whether or not the proposed transaction
    /// is exclusively wallet-internal (if it does not involve any external
    /// recipients).
    pub fn is_shielding(&self) -> bool {
        self.is_shielding
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
    /// The type of data source that the input selector expects to access to obtain input notes and
    /// UTXOs. This associated type permits input selectors that may use specialized knowledge of
    /// the internals of a particular backing data store, if the generic API of `WalletRead` does
    /// not provide sufficiently fine-grained operations for a particular backing store to
    /// optimally perform input selection.
    type DataSource: WalletRead;
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
    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::type_complexity)]
    fn propose_transaction<ParamsT>(
        &self,
        params: &ParamsT,
        wallet_db: &Self::DataSource,
        account: AccountId,
        anchor_height: BlockHeight,
        target_height: BlockHeight,
        transaction_request: TransactionRequest,
    ) -> Result<
        Proposal<Self::FeeRule, <<Self as InputSelector>::DataSource as WalletRead>::NoteRef>,
        InputSelectorError<<<Self as InputSelector>::DataSource as WalletRead>::Error, Self::Error>,
    >
    where
        ParamsT: consensus::Parameters;

    /// Performs input selection and returns a proposal for the construction of a shielding
    /// transaction.
    ///
    /// Implementations should return the maximum possible number of economically useful inputs
    /// required to supply at least the requested value, choosing only inputs received at the
    /// specified source addresses. If insufficient funds are available to satisfy the required
    /// outputs for the shielding request, this operation must fail and return
    /// [`InputSelectorError::InsufficientFunds`].
    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::type_complexity)]
    fn propose_shielding<ParamsT>(
        &self,
        params: &ParamsT,
        wallet_db: &Self::DataSource,
        shielding_threshold: NonNegativeAmount,
        source_addrs: &[TransparentAddress],
        confirmed_height: BlockHeight,
        target_height: BlockHeight,
    ) -> Result<
        Proposal<Self::FeeRule, <<Self as InputSelector>::DataSource as WalletRead>::NoteRef>,
        InputSelectorError<<<Self as InputSelector>::DataSource as WalletRead>::Error, Self::Error>,
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

pub(crate) struct SaplingPayment(Amount);

#[cfg(test)]
impl SaplingPayment {
    pub(crate) fn new(amount: Amount) -> Self {
        SaplingPayment(amount)
    }
}

impl sapling::OutputView for SaplingPayment {
    fn value(&self) -> Amount {
        self.0
    }
}

/// An [`InputSelector`] implementation that uses a greedy strategy to select between available
/// notes.
///
/// This implementation performs input selection using methods available via the [`WalletRead`]
/// interface.
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
    DbT: WalletRead,
    ChangeT: ChangeStrategy,
    ChangeT::FeeRule: Clone,
{
    type Error = GreedyInputSelectorError<ChangeT::Error, DbT::NoteRef>;
    type DataSource = DbT;
    type FeeRule = ChangeT::FeeRule;

    #[allow(clippy::type_complexity)]
    fn propose_transaction<ParamsT>(
        &self,
        params: &ParamsT,
        wallet_db: &Self::DataSource,
        account: AccountId,
        anchor_height: BlockHeight,
        target_height: BlockHeight,
        transaction_request: TransactionRequest,
    ) -> Result<Proposal<Self::FeeRule, DbT::NoteRef>, InputSelectorError<DbT::Error, Self::Error>>
    where
        ParamsT: consensus::Parameters,
    {
        let mut transparent_outputs = vec![];
        let mut sapling_outputs = vec![];
        let mut output_total = Amount::zero();
        for payment in transaction_request.payments() {
            output_total = (output_total + payment.amount).ok_or(BalanceError::Overflow)?;

            let mut push_transparent = |taddr: TransparentAddress| {
                transparent_outputs.push(TxOut {
                    value: payment.amount,
                    script_pubkey: taddr.script(),
                });
            };
            let mut push_sapling = || {
                sapling_outputs.push(SaplingPayment(payment.amount));
            };

            match &payment.recipient_address {
                RecipientAddress::Transparent(addr) => {
                    push_transparent(*addr);
                }
                RecipientAddress::Shielded(_) => {
                    push_sapling();
                }
                RecipientAddress::Unified(addr) => {
                    if addr.sapling().is_some() {
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

        let mut sapling_inputs: Vec<SpendableNote<DbT::NoteRef>> = vec![];
        let mut prior_available = Amount::zero();
        let mut amount_required = Amount::zero();
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
                &sapling_inputs,
                &sapling_outputs,
                &self.dust_output_policy,
            );

            match balance {
                Ok(balance) => {
                    return Ok(Proposal {
                        transaction_request,
                        transparent_inputs: vec![],
                        sapling_inputs,
                        balance,
                        fee_rule: (*self.change_strategy.fee_rule()).clone(),
                        target_height,
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

            sapling_inputs = wallet_db
                .select_spendable_sapling_notes(account, amount_required, anchor_height, &exclude)
                .map_err(InputSelectorError::DataSource)?;

            let new_available = sapling_inputs
                .iter()
                .map(|n| n.note_value)
                .sum::<Option<Amount>>()
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

    #[allow(clippy::type_complexity)]
    fn propose_shielding<ParamsT>(
        &self,
        params: &ParamsT,
        wallet_db: &Self::DataSource,
        shielding_threshold: NonNegativeAmount,
        source_addrs: &[TransparentAddress],
        confirmed_height: BlockHeight,
        target_height: BlockHeight,
    ) -> Result<Proposal<Self::FeeRule, DbT::NoteRef>, InputSelectorError<DbT::Error, Self::Error>>
    where
        ParamsT: consensus::Parameters,
    {
        let mut transparent_inputs: Vec<WalletTransparentOutput> = source_addrs
            .iter()
            .map(|taddr| wallet_db.get_unspent_transparent_outputs(taddr, confirmed_height, &[]))
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
            &Vec::<SpendableNote<DbT::NoteRef>>::new(),
            &Vec::<SaplingPayment>::new(),
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
                    &Vec::<SpendableNote<DbT::NoteRef>>::new(),
                    &Vec::<SaplingPayment>::new(),
                    &self.dust_output_policy,
                )?
            }
            Err(other) => {
                return Err(other.into());
            }
        };

        if balance.total() >= shielding_threshold.into() {
            Ok(Proposal {
                transaction_request: TransactionRequest::empty(),
                transparent_inputs,
                sapling_inputs: vec![],
                balance,
                fee_rule: (*self.change_strategy.fee_rule()).clone(),
                target_height,
                is_shielding: true,
            })
        } else {
            Err(InputSelectorError::InsufficientFunds {
                available: balance.total(),
                required: shielding_threshold.into(),
            })
        }
    }
}
