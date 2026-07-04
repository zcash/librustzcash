//! Types related to the process of selecting inputs to be spent given a transaction request.
use core::marker::PhantomData;
use nonempty::NonEmpty;
use std::{
    collections::BTreeMap,
    error,
    fmt::{self, Debug, Display},
};

use transparent::bundle::TxOut;
use zcash_address::{ConversionError, ZcashAddress};
use zcash_keys::address::{Address, UnifiedAddress};
use zcash_primitives::transaction::fees::{
    FeeRule,
    transparent::InputSize,
    zip317::{P2PKH_STANDARD_INPUT_SIZE, P2PKH_STANDARD_OUTPUT_SIZE},
};
use zcash_protocol::{
    PoolType, ShieldedPool,
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
        data_api::CoinbaseFilter,
        fees::{ChangeValue, StandardFeeRule},
        proposal::{Step, StepOutput, StepOutputIndex},
    },
    std::collections::BTreeSet,
    std::convert::Infallible,
    transparent::{address::TransparentAddress, bundle::OutPoint},
    zcash_primitives::transaction::fees::transparent as transparent_fees,
    zip321::Payment,
};

#[cfg(feature = "orchard")]
use crate::{data_api::wallet::ironwood_active_at, fees::orchard as orchard_fees};

#[cfg(feature = "unstable")]
use zcash_primitives::transaction::TxVersion;

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

impl<E, S, C, N> From<ProposalError> for InputSelectorError<E, S, C, N> {
    fn from(err: ProposalError) -> Self {
        InputSelectorError::Proposal(err)
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
    ///
    /// `spend_policy` (behind the `transparent-inputs` feature flag) controls whether, and
    /// from which addresses, the account's transparent UTXOs may additionally be spent to
    /// help satisfy the request. Under the default [`TransparentSpendPolicy::ShieldedOnly`],
    /// implementations must not spend transparent UTXOs even as a fallback; other policies
    /// require the caller to have explicitly opted in, since spending transparent funds
    /// links the chosen addresses on-chain.
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
        #[cfg(feature = "transparent-inputs")] spend_policy: &TransparentSpendPolicy,
        #[cfg(feature = "unstable")] proposed_version: Option<TxVersion>,
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
    ///
    /// The `output_filter` parameter controls which transparent outputs are eligible for
    /// inclusion in the proposal. See [`CoinbaseFilter`] for details.
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
        output_filter: CoinbaseFilter,
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

    /// Performs input selection and returns a proposal for the construction of a transaction
    /// that shields coinbase transparent outputs to an arbitrary shielded recipient.
    ///
    /// This method differs from [`Self::propose_shielding`] in the following ways:
    ///
    /// - Only coinbase transparent outputs are eligible for inclusion in the proposal. This
    ///   restriction is hard-coded; callers cannot opt in to selecting non-coinbase outputs
    ///   via this method. Coinbase outputs are uniquely suited to being sent to arbitrary
    ///   shielded recipients because they have no prior transparent transaction graph that
    ///   could be exposed to the recipient.
    /// - The `to_address` argument specifies the destination of the shielded value. It must
    ///   be a shielded address (Sapling, or a Unified Address with a shielded receiver). It
    ///   may be an external address not belonging to any account we control.
    /// - The resulting proposal carries an explicit ZIP-321 payment to `to_address` for the
    ///   full available value (input total minus fee). **No change is produced**, in either
    ///   the transparent or any shielded pool. This is a privacy invariant: producing a
    ///   shielded change output would allow the recipient (or any chain observer) to learn
    ///   the sender's total selected-coinbase value by summing the public transparent input
    ///   values and subtracting the visible payment amount. Since this method targets the
    ///   `z_shieldcoinbase`-style "sweep coinbase to a recipient" workflow, where the
    ///   recipient may not belong to the sender's wallet, change is forbidden by design.
    ///
    /// Because no change is produced, this method takes a `fee_rule` directly rather than a
    /// [`ChangeStrategy`]: there is no change to compute, and no per-account metadata is
    /// required.
    ///
    /// The `memo` parameter is stored in the shielded output's memo field; it is always
    /// permitted because a shielded payment is always present.
    ///
    /// The `limit` parameter, when `Some(n)`, caps the number of transparent inputs to at
    /// most `n`, keeping the highest-value UTXOs (with a stable tiebreaker by outpoint).
    /// `Some(0)` selects no inputs and will therefore return
    /// [`InputSelectorError::InsufficientFunds`].
    ///
    /// If the total value of selected inputs (after any cap imposed by `limit`), minus the
    /// fee, is less than `shielding_threshold`, this method returns
    /// [`InputSelectorError::InsufficientFunds`].
    #[allow(clippy::type_complexity)]
    #[allow(clippy::too_many_arguments)]
    fn propose_shielding_coinbase<ParamsT, FeeRuleT>(
        &self,
        params: &ParamsT,
        wallet_db: &Self::InputSource,
        fee_rule: &FeeRuleT,
        shielding_threshold: Zatoshis,
        source_addrs: &[TransparentAddress],
        to_address: ZcashAddress,
        memo: Option<MemoBytes>,
        limit: Option<usize>,
        target_height: TargetHeight,
    ) -> Result<
        Proposal<FeeRuleT, Infallible>,
        InputSelectorError<
            <Self::InputSource as InputSource>::Error,
            Self::Error,
            FeeRuleT::Error,
            Infallible,
        >,
    >
    where
        ParamsT: consensus::Parameters,
        FeeRuleT: FeeRule + Clone;
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

/// The Zcash consensus maximum block size, in bytes.
#[cfg(feature = "transparent-inputs")]
const MAX_BLOCK_BYTES: usize = 2_000_000;

/// The default maximum fraction of a block's space, as an integer percentage, that a single
/// shielding transaction's transparent inputs may occupy.
#[cfg(feature = "transparent-inputs")]
const DEFAULT_SHIELDING_BLOCK_SPACE_PERCENT: u32 = 10;

#[cfg(feature = "transparent-inputs")]
/// A `BTreeSet` that is guaranteed to contain at least one element.
///
/// Non-emptiness is maintained by construction: every constructor requires at least one
/// element, and no mutating operations are exposed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NonEmptyBTreeSet<T>(BTreeSet<T>);

#[cfg(feature = "transparent-inputs")]
impl<T: Ord> NonEmptyBTreeSet<T> {
    /// Constructs a set containing only the given element.
    pub fn singleton(value: T) -> Self {
        Self(BTreeSet::from_iter([value]))
    }

    /// Constructs a set containing the elements of the given non-empty list, collapsing
    /// duplicates.
    pub fn from_nonempty(values: NonEmpty<T>) -> Self {
        Self(values.into_iter().collect())
    }

    /// Constructs a set from the given `BTreeSet`, or returns `None` if the set is empty.
    pub fn from_set(values: BTreeSet<T>) -> Option<Self> {
        (!values.is_empty()).then_some(Self(values))
    }
}

#[cfg(feature = "transparent-inputs")]
impl<T> NonEmptyBTreeSet<T> {
    /// Returns a reference to the wrapped set.
    pub fn as_set(&self) -> &BTreeSet<T> {
        &self.0
    }

    /// Returns an iterator over the elements of the set, in ascending order.
    pub fn iter(&self) -> std::collections::btree_set::Iter<'_, T> {
        self.0.iter()
    }
}

#[cfg(feature = "transparent-inputs")]
/// Specifies the wallet's intent to spend transparent UTXOs in a transfer.
///
/// Spending transparent funds links the chosen transparent addresses on-chain,
/// reducing privacy; callers must opt in explicitly. Corresponds to the legacy
/// `AllowTransparentAddressLinking` privacy policy / `ANY_TADDR`.
#[derive(Default)]
pub enum TransparentSpendPolicy {
    /// Do not spend any transparent UTXOs (default; fully-shielded behavior).
    #[default]
    ShieldedOnly,
    /// Spend from arbitrary transparent receivers belonging to the account, as
    /// needed to satisfy the request. The proposer chooses the addresses,
    /// potentially linking them. (`ANY_TADDR`)
    AnyAccountTaddr,
    /// Spend only from the specified transparent addresses, intentionally
    /// linking them.
    FromAddresses(NonEmptyBTreeSet<TransparentAddress>),
}

#[cfg(feature = "transparent-inputs")]
impl TransparentSpendPolicy {
    /// Creates a policy that only spends from shielded UTXOs.
    pub fn shielded_only() -> Self {
        Self::ShieldedOnly
    }

    /// Creates a policy that spends from arbitrary transparent receivers
    /// belonging to the account.
    pub fn from_any_account_transparent_addresses() -> Self {
        Self::AnyAccountTaddr
    }

    /// Creates a policy that only spends from the specified transparent addresses,
    /// potentially leaking them. (`ANY_TADDR`)
    pub fn from_specific_transparent_addresses(taddrs: NonEmpty<TransparentAddress>) -> Self {
        Self::FromAddresses(NonEmptyBTreeSet::from_nonempty(taddrs))
    }

    /// Creates a policy that only spends from a single transparent address.
    pub fn from_one_transparent_address(taddr: TransparentAddress) -> Self {
        Self::FromAddresses(NonEmptyBTreeSet::singleton(taddr))
    }
}

/// An [`InputSelector`] implementation that uses a greedy strategy to select between available
/// notes.
///
/// This implementation performs input selection using methods available via the
/// [`InputSource`] interface.
pub struct GreedyInputSelector<DbT> {
    /// The maximum fraction of a block's space, as an integer percentage (0–100), that a
    /// single transaction's transparent inputs may occupy. Bounds both shielding
    /// transactions and the transparent gather performed for general (non-shielding)
    /// transfers when the active [`TransparentSpendPolicy`] requires it.
    #[cfg(feature = "transparent-inputs")]
    shielding_block_space_percent: u32,
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
            #[cfg(feature = "transparent-inputs")]
            shielding_block_space_percent: DEFAULT_SHIELDING_BLOCK_SPACE_PERCENT,
            _ds_type: PhantomData,
        }
    }

    /// Sets the maximum fraction of a block's space, as an integer percentage (0–100), that a
    /// single transaction's transparent inputs may occupy.
    ///
    /// When shielding gathers more spendable transparent outputs than will fit within this
    /// bound, the highest-value outputs are selected first and the remainder are left unspent,
    /// to be consolidated by a subsequent shielding transaction. When a general (non-shielding)
    /// transfer's transparent gather would otherwise require more inputs than fit within this
    /// bound, the gather stops at the cap even if the requested value has not yet been
    /// reached; the caller's input-selection loop surfaces this as an `InsufficientFunds`
    /// error, the same as for any other value shortfall. Values above 100 are clamped to 100.
    /// Defaults to 10.
    #[cfg(feature = "transparent-inputs")]
    pub fn with_shielding_block_space_percent(mut self, percent: u32) -> Self {
        self.shielding_block_space_percent = percent.min(100);
        self
    }

    #[cfg(feature = "transparent-inputs")]
    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::type_complexity)]
    fn gather_transparent<ChangeT>(
        &self,
        wallet_db: &DbT,
        target_height: TargetHeight,
        confirmations_policy: ConfirmationsPolicy,
        account: <DbT as InputSource>::AccountId,
        // The list used to filter addresses.
        // If `None`, any address is allowed.
        address_allow_list: Option<&[TransparentAddress]>,
        transaction_request: &TransactionRequest,
        amount_at_transparent_gather: &mut Zatoshis,
    ) -> Result<
        Vec<WalletTransparentOutput<()>>,
        InputSelectorError<
            <DbT as InputSource>::Error,
            <GreedyInputSelector<DbT> as InputSelector>::Error,
            <ChangeT as ChangeStrategy>::Error,
            <DbT as InputSource>::NoteRef,
        >,
    >
    where
        DbT: InputSource,
        ChangeT: ChangeStrategy<MetaSource = DbT>,
    {
        let max_money = Zatoshis::const_from_u64(zcash_protocol::value::MAX_MONEY);
        let mut total_opt: Option<Zatoshis> = Some(Zatoshis::ZERO);
        for payment in transaction_request.payments().values() {
            let Some(payment_amount) = payment.amount() else {
                total_opt = None;
                break;
            };
            if let Some(t) = total_opt {
                match t + payment_amount {
                    Some(sum) => total_opt = Some(sum),
                    None => {
                        return Err(InputSelectorError::InsufficientFunds {
                            available: Zatoshis::ZERO,
                            required: max_money,
                        });
                    }
                }
            }
        }
        let (target_value, amount_at_gather) = match total_opt {
            Some(z) => (TargetValue::AtLeast(z), z),
            None => (
                TargetValue::AllFunds(MaxSpendMode::MaxSpendable),
                Zatoshis::ZERO,
            ),
        };
        *amount_at_transparent_gather = amount_at_gather;
        Ok(wallet_db
            .select_spendable_transparent_outputs(
                account,
                target_height,
                confirmations_policy,
                CoinbaseFilter::NonCoinbaseOnly,
                address_allow_list,
                target_value,
                shielding_max_inputs(self.shielding_block_space_percent),
                &StandardFeeRule::Zip317,
            )
            .map_err(InputSelectorError::DataSource)?
            .into_iter()
            .map(|utxo| utxo.redact_account_data())
            .collect::<Vec<_>>())
    }
}

/// Returns the maximum number of transparent inputs that a single transaction may select,
/// given the configured fraction of a block's space (as an integer percentage) that its
/// inputs may occupy. Used to bound both shielding transactions and the transparent gather
/// for general (non-shielding) transfers.
#[cfg(feature = "transparent-inputs")]
fn shielding_max_inputs(block_space_percent: u32) -> usize {
    (MAX_BLOCK_BYTES.saturating_mul(block_space_percent as usize) / 100) / P2PKH_STANDARD_INPUT_SIZE
}

/// Returns the set of transparent addresses that `spend_policy` permits the transparent
/// gather to select from, or `None` if any of the account's transparent receivers are
/// eligible.
///
/// This must be applied *within* the gather (not to its results), so that outputs excluded
/// by the policy do not consume the gather's value bound; see
/// [`InputSource::select_spendable_transparent_outputs`].
#[cfg(feature = "transparent-inputs")]
fn transparent_address_allow_list(
    spend_policy: &TransparentSpendPolicy,
) -> Option<Vec<TransparentAddress>> {
    match spend_policy {
        TransparentSpendPolicy::FromAddresses(addrs) => Some(addrs.iter().copied().collect()),
        TransparentSpendPolicy::ShieldedOnly | TransparentSpendPolicy::AnyAccountTaddr => None,
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
        #[cfg(feature = "transparent-inputs")] spend_policy: &TransparentSpendPolicy,
        #[cfg(feature = "unstable")] proposed_version: Option<TxVersion>,
    ) -> Result<
        Proposal<<ChangeT as ChangeStrategy>::FeeRule, DbT::NoteRef>,
        InputSelectorError<<DbT as InputSource>::Error, Self::Error, ChangeT::Error, DbT::NoteRef>,
    >
    where
        ParamsT: consensus::Parameters,
        Self::InputSource: InputSource,
        ChangeT: ChangeStrategy<MetaSource = DbT>,
    {
        #[cfg(feature = "unstable")]
        let (sapling_supported, orchard_supported) =
            proposed_version.map_or(Ok((true, true)), |v| {
                let branch_id =
                    consensus::BranchId::for_height(params, BlockHeight::from(target_height));
                if v.valid_in_branch(branch_id) {
                    Ok((
                        v.has_sapling(),
                        cfg!(feature = "orchard") && v.has_orchard(),
                    ))
                } else {
                    Err(ProposalError::IncompatibleTxVersion(branch_id))
                }
            })?;
        #[cfg(not(feature = "unstable"))]
        let (sapling_supported, orchard_supported) = (true, cfg!(feature = "orchard"));
        // Without the `orchard` feature there are no Orchard-family pools to select from, so
        // `orchard_supported` (always false) is only referenced by Orchard-gated code.
        #[cfg(not(feature = "orchard"))]
        let _ = orchard_supported;

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
            let payment_amount = payment
                .amount()
                .ok_or(ProposalError::PaymentAmountMissing(*idx))?;
            let recipient_address: Address = payment
                .recipient_address()
                .clone()
                .convert_if_network(params.network_type())?;

            match recipient_address {
                Address::Transparent(addr) => {
                    payment_pools.insert(*idx, PoolType::TRANSPARENT);
                    transparent_outputs.push(TxOut::new(payment_amount, addr.script().into()));
                }
                #[cfg(feature = "transparent-inputs")]
                Address::Tex(data) => {
                    let p2pkh_addr = TransparentAddress::PublicKeyHash(data);

                    tr1_payment_pools.insert(*idx, PoolType::TRANSPARENT);
                    tr1_transparent_outputs
                        .push(TxOut::new(payment_amount, p2pkh_addr.script().into()));
                    tr1_payments.push(
                        Payment::new(
                            payment.recipient_address().clone(),
                            payment.amount(),
                            None,
                            payment.label().cloned(),
                            payment.message().cloned(),
                            payment.other_params().to_vec(),
                        )
                        .expect("cannot fail because memo is None and amount is nonzero"),
                    );
                    total_ephemeral = (total_ephemeral + payment_amount)
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
                    sapling_outputs.push(SaplingPayment(payment_amount));
                }
                Address::Unified(addr) => {
                    #[cfg(feature = "orchard")]
                    if addr.has_orchard() && orchard_supported {
                        payment_pools.insert(*idx, PoolType::ORCHARD);
                        orchard_outputs.push(OrchardPayment(payment_amount));
                        continue;
                    }

                    if addr.has_sapling() && sapling_supported {
                        payment_pools.insert(*idx, PoolType::SAPLING);
                        sapling_outputs.push(SaplingPayment(payment_amount));
                        continue;
                    }

                    if let Some(addr) = addr.transparent() {
                        payment_pools.insert(*idx, PoolType::TRANSPARENT);
                        transparent_outputs.push(TxOut::new(payment_amount, addr.script().into()));
                        continue;
                    }

                    return Err(InputSelectorError::Selection(
                        GreedyInputSelectorError::UnsupportedAddress(Box::new(addr)),
                    ));
                }
            }
        }

        #[cfg(not(feature = "transparent-inputs"))]
        let transparent_inputs = vec![];
        #[cfg(feature = "transparent-inputs")]
        let mut amount_at_transparent_gather = Zatoshis::ZERO;
        #[cfg(feature = "transparent-inputs")]
        let mut transparent_inputs = match spend_policy {
            TransparentSpendPolicy::ShieldedOnly => {
                // For `ShieldedOnly`, we don't need any transparent inputs; skip the gather entirely.
                Vec::new()
            }
            TransparentSpendPolicy::AnyAccountTaddr => self.gather_transparent::<ChangeT>(
                wallet_db,
                target_height,
                confirmations_policy,
                account,
                // Pass an empty set as the allow list
                None,
                &transaction_request,
                &mut amount_at_transparent_gather,
            )?,
            TransparentSpendPolicy::FromAddresses(_) => {
                let address_allow_list = transparent_address_allow_list(spend_policy);
                self.gather_transparent::<ChangeT>(
                    wallet_db,
                    target_height,
                    confirmations_policy,
                    account,
                    address_allow_list.as_deref(),
                    &transaction_request,
                    &mut amount_at_transparent_gather,
                )?
            }
        };
        // Outpoints of gathered transparent inputs that the change strategy has identified as
        // dust. Accumulated across loop iterations so that a re-gather (triggered by
        // `ChangeError::InsufficientFunds`, below) does not re-introduce previously pruned
        // outputs.
        #[cfg(feature = "transparent-inputs")]
        let mut transparent_dust: BTreeSet<OutPoint> = BTreeSet::new();

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
            let (use_sapling, use_orchard, use_ironwood) = {
                // The selection step below never mixes Orchard inputs with Sapling or Ironwood
                // inputs: it selects either the Orchard group or the Sapling+Ironwood group.
                // Spending Orchard is a migration that drains the legacy pool, so it must be a pure
                // Orchard-input transaction; Sapling and Ironwood inputs may be combined. The
                // presence of any selected Orchard note therefore means the Orchard group was
                // chosen; otherwise the Sapling and Ironwood notes are spent. If neither group can
                // cover the amount, the loop reports insufficient funds rather than combining
                // Orchard with another pool: the API user must first move the Orchard funds out (to
                // Sapling or Ironwood) in a separate transaction.
                if shielded_inputs.orchard().is_empty() {
                    (true, false, true)
                } else {
                    (false, true, false)
                }
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

            // Ironwood inputs are selected only when the Ironwood pool was chosen (never together
            // with Orchard inputs), and are attributed to the Ironwood bundle for action-count and
            // fee purposes.
            #[cfg(feature = "orchard")]
            let ironwood_inputs = if use_ironwood {
                shielded_inputs
                    .ironwood()
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
            #[cfg(feature = "orchard")]
            let selected_input_ids =
                selected_input_ids.chain(ironwood_inputs.iter().map(|(id, _)| id));

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
                            &[] as &[WalletTransparentOutput<<DbT as InputSource>::AccountId>],
                            &tr1_transparent_outputs,
                            &sapling::EmptyBundleView,
                            #[cfg(feature = "orchard")]
                            &orchard_fees::EmptyBundleView,
                            #[cfg(feature = "orchard")]
                            &orchard_fees::EmptyBundleView,
                            #[cfg(feature = "orchard")]
                            false,
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
                        &[] as &[WalletTransparentOutput<<DbT as InputSource>::AccountId>],
                        &tr1_transparent_outputs,
                        &sapling::EmptyBundleView,
                        #[cfg(feature = "orchard")]
                        &orchard_fees::EmptyBundleView,
                        #[cfg(feature = "orchard")]
                        &orchard_fees::EmptyBundleView,
                        #[cfg(feature = "orchard")]
                        false,
                        Some(EphemeralBalance::Input(tr1_required_input_value)),
                        &wallet_meta,
                    )?;
                    assert_eq!(tr1_balance.total(), tr1_balance.fee_required());

                    (Some(tr1_required_input_value), Some(tr1_balance))
                }
            };

            // The Orchard bundle keeps the Orchard (version 2) spends; its outputs move to the
            // Ironwood bundle when routing is active. The Ironwood bundle takes the Ironwood
            // (version 3) spends, and its outputs when routing is active. Attributing each pool's
            // spends to its own bundle keeps the action counts (and hence the fee) matching the
            // transaction the builder produces.
            #[cfg(feature = "orchard")]
            let orchard_view = (
                orchard_bundle_version_for_height(params, target_height),
                &orchard_inputs[..],
                if ironwood_active_at(params, target_height) {
                    &[]
                } else {
                    &orchard_outputs[..]
                },
            );
            #[cfg(feature = "orchard")]
            let ironwood_view = (
                ::orchard::bundle::BundleVersion::ironwood_v3(),
                &ironwood_inputs[..],
                if ironwood_active_at(params, target_height) {
                    &orchard_outputs[..]
                } else {
                    &[]
                },
            );

            // Tracks whether this iteration's error handling changed the transparent input
            // set, either by re-gathering with a corrected value bound (`InsufficientFunds`)
            // or by pruning dust (`DustInputs`). A changed transparent input set is a valid
            // form of progress in its own right (distinct from the shielded-note progress
            // tracked by `prior_available`/`new_available` below): without this, an account
            // with no spendable shielded notes at all (or none beyond what's already
            // excluded) would spuriously report `InsufficientFunds` on the very next check
            // below, even though the changed transparent input set might already be
            // sufficient to satisfy the request on the next iteration. Termination is
            // preserved: `amount_at_transparent_gather` increases strictly across
            // re-gathers, and each outpoint can be pruned as dust at most once (pruned
            // outpoints accumulate in `transparent_dust` and are never re-gathered).
            #[cfg(not(feature = "transparent-inputs"))]
            let transparent_inputs_changed = false;
            #[cfg(feature = "transparent-inputs")]
            let mut transparent_inputs_changed = false;

            // In the ZIP 320 case, this is the balance for transaction 0, taking into account
            // the ephemeral output.
            let tr0_balance = change_strategy.compute_balance(
                params,
                target_height,
                &transparent_inputs,
                &transparent_outputs,
                &(
                    ::sapling::builder::BundleType::DEFAULT,
                    &sapling_inputs[..],
                    &sapling_outputs[..],
                ),
                #[cfg(feature = "orchard")]
                &orchard_view,
                #[cfg(feature = "orchard")]
                &ironwood_view,
                // TODO: do we want to allow routing of orchard change to ironwood?
                #[cfg(feature = "orchard")]
                false,
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
                            #[cfg(feature = "orchard")]
                            ironwood: use_ironwood,
                        }))
                        .map(|notes| ShieldedInputs::from_parts(anchor_height, notes));

                    return build_proposal(
                        change_strategy.fee_rule(),
                        tr0_balance,
                        target_height,
                        shielded_inputs,
                        transparent_inputs,
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
                    #[cfg(feature = "transparent-inputs")]
                    transparent,
                    mut sapling,
                    #[cfg(feature = "orchard")]
                    mut orchard,
                    ..
                }) => {
                    exclude.append(&mut sapling);
                    #[cfg(feature = "orchard")]
                    exclude.append(&mut orchard);
                    #[cfg(feature = "transparent-inputs")]
                    {
                        let len_before = transparent_inputs.len();
                        transparent_dust.extend(transparent);
                        transparent_inputs.retain(|i| !transparent_dust.contains(i.outpoint()));
                        // Pruning dust changes the balance computation, so give the loop a
                        // chance to re-evaluate the pruned set before concluding that funds
                        // are insufficient.
                        if transparent_inputs.len() != len_before {
                            transparent_inputs_changed = true;
                        }
                    }
                }
                Err(ChangeError::InsufficientFunds { required, .. }) => {
                    amount_required = required;
                    // The initial transparent-input gather was bounded by the payouts
                    // alone, but `required` includes the fee. If the bound was too
                    // low, re-gather transparents with the corrected value as a
                    // defensive fallback. The common case (fee estimate was close) is
                    // a no-op.
                    #[cfg(feature = "transparent-inputs")]
                    {
                        if !matches!(spend_policy, TransparentSpendPolicy::ShieldedOnly)
                            && required > amount_at_transparent_gather
                        {
                            let address_allow_list = transparent_address_allow_list(spend_policy);
                            transparent_inputs = wallet_db
                                .select_spendable_transparent_outputs(
                                    account,
                                    target_height,
                                    confirmations_policy,
                                    CoinbaseFilter::NonCoinbaseOnly,
                                    address_allow_list.as_deref(),
                                    TargetValue::AtLeast(required),
                                    shielding_max_inputs(self.shielding_block_space_percent),
                                    &StandardFeeRule::Zip317,
                                )
                                .map_err(InputSelectorError::DataSource)?
                                .into_iter()
                                // Do not re-introduce outputs previously pruned as dust; the
                                // value they would contribute is (approximately) consumed by
                                // their own fee cost, so their absence does not meaningfully
                                // reduce the gathered value.
                                .filter(|utxo| !transparent_dust.contains(utxo.outpoint()))
                                .map(|utxo| utxo.redact_account_data())
                                .collect::<Vec<_>>();
                            amount_at_transparent_gather = required;
                            transparent_inputs_changed = true;
                        }
                    }
                }
                Err(other) => return Err(InputSelectorError::Change(other)),
            }

            // Orchard inputs are never combined with Sapling or Ironwood, but Sapling and Ironwood
            // may be combined, so we select from one of two mutually-exclusive input groups: the
            // Orchard group alone, or the Sapling+Ironwood group. Prefer the Orchard group when its
            // notes reach the required amount (draining the legacy pool as users migrate to
            // Ironwood); otherwise use the Sapling+Ironwood group when it reaches the amount. If
            // neither group can cover the amount, keep whichever group holds the greater value so
            // the loop reports an accurate insufficient-funds error against a single group (Orchard
            // is never combined with another pool to make up the difference).
            let sapling_ironwood_pools = {
                let mut pools = vec![];
                if sapling_supported {
                    pools.push(ShieldedPool::Sapling);
                }
                // Ironwood notes can be spent once the Ironwood pool is active at the target
                // height, and may be combined with Sapling inputs.
                #[cfg(feature = "orchard")]
                if orchard_supported && super::ironwood_active_at(params, target_height) {
                    pools.push(ShieldedPool::Ironwood);
                }
                pools
            };
            let sapling_ironwood = wallet_db
                .select_spendable_notes(
                    account,
                    TargetValue::AtLeast(amount_required),
                    &sapling_ironwood_pools,
                    target_height,
                    confirmations_policy,
                    &exclude,
                )
                .map_err(InputSelectorError::DataSource)?;

            #[cfg(feature = "orchard")]
            {
                let orchard = if orchard_supported {
                    Some(
                        wallet_db
                            .select_spendable_notes(
                                account,
                                TargetValue::AtLeast(amount_required),
                                &[ShieldedPool::Orchard],
                                target_height,
                                confirmations_policy,
                                &exclude,
                            )
                            .map_err(InputSelectorError::DataSource)?,
                    )
                } else {
                    None
                };

                shielded_inputs = match orchard {
                    Some(orchard) => {
                        let orchard_value = orchard.total_value()?;
                        let sapling_ironwood_value = sapling_ironwood.total_value()?;
                        let orchard_covers = orchard_value >= amount_required;
                        let sapling_ironwood_covers = sapling_ironwood_value >= amount_required;
                        // Prefer the input group that matches the payment's pool, to avoid an
                        // unnecessary cross-pool (turnstile) output: spend the Orchard group when
                        // the payment targets an Orchard receiver, otherwise spend the
                        // Sapling+Ironwood group. Fall back to the other group when the preferred
                        // one cannot cover the amount, and to the larger group when neither covers
                        // (so the insufficient-funds error is accurate). Orchard is never combined
                        // with Sapling or Ironwood to make up a shortfall.
                        let prefer_orchard = !orchard_outputs.is_empty();
                        if prefer_orchard && orchard_covers {
                            orchard
                        } else if !prefer_orchard && sapling_ironwood_covers {
                            sapling_ironwood
                        } else if orchard_covers {
                            orchard
                        } else if sapling_ironwood_covers {
                            sapling_ironwood
                        } else if orchard_value >= sapling_ironwood_value {
                            orchard
                        } else {
                            sapling_ironwood
                        }
                    }
                    None => sapling_ironwood,
                };
            }
            #[cfg(not(feature = "orchard"))]
            {
                shielded_inputs = sapling_ironwood;
            }

            let new_available = shielded_inputs.total_value()?;
            if new_available <= prior_available && !transparent_inputs_changed {
                return Err(InputSelectorError::InsufficientFunds {
                    required: amount_required,
                    available: new_available,
                });
            } else {
                // If the set of selected shielded notes has grown, or the transparent
                // input set changed this iteration, we will loop again and see whether
                // we now have enough funds.
                prior_available = new_available;
            }
        }
    }
}

/// Returns the Orchard bundle version whose action-count policy applies to
/// transactions constructed for the given target height.
#[cfg(feature = "orchard")]
fn orchard_bundle_version_for_height<ParamsT: consensus::Parameters, H: Into<BlockHeight>>(
    params: &ParamsT,
    target_height: H,
) -> ::orchard::bundle::BundleVersion {
    zcash_primitives::transaction::components::orchard::bundle_version_for_branch(
        consensus::BranchId::for_height(params, target_height.into()),
        ::orchard::ValuePool::Orchard,
    )
    // Orchard did not exist prior to NU5, so no Orchard bundle (and no Orchard
    // action) can be produced for a pre-NU5 target height; every bundle version
    // yields the correct action count (zero) for an empty bundle.
    .unwrap_or(::orchard::bundle::BundleVersion::orchard_insecure_v1())
}

#[allow(clippy::type_complexity, clippy::too_many_arguments)]
pub(crate) fn propose_send_max<ParamsT, InputSourceT, FeeRuleT>(
    params: &ParamsT,
    wallet_db: &InputSourceT,
    fee_rule: &FeeRuleT,
    source_account: InputSourceT::AccountId,
    spend_pools: &[ShieldedPool],
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

    // A payment to an Orchard receiver is represented in the proposal as an Orchard-pool output.
    // When Ironwood is active the builder routes that output to the Ironwood bundle instead, so the
    // per-bundle action counts reflect that split even though the payment pool stays `ORCHARD`.
    #[cfg(feature = "orchard")]
    let recipient_wants_orchard = recipient.can_receive_as(PoolType::ORCHARD);
    #[cfg(feature = "orchard")]
    let route_orchard_output_to_ironwood = ironwood_active_at(params, target_height);
    #[cfg(feature = "orchard")]
    if recipient_wants_orchard {
        payment_pools.insert(0, PoolType::ORCHARD);
    }

    #[cfg(feature = "orchard")]
    let orchard_action_count = orchard_fees::transactional_action_count(
        orchard_bundle_version_for_height(params, target_height),
        spendable_notes.orchard.len(),
        usize::from(recipient_wants_orchard && !route_orchard_output_to_ironwood),
    )
    .map_err(|e| InputSelectorError::Change(ChangeError::BundleError(e)))?;
    #[cfg(not(feature = "orchard"))]
    let orchard_action_count: usize = 0;

    #[cfg(feature = "orchard")]
    let use_orchard = orchard_action_count > 0;

    #[cfg(feature = "orchard")]
    let ironwood_action_count = orchard::builder::BundleType::DEFAULT
        .num_actions(
            orchard::bundle::Flags::ENABLED,
            spendable_notes.ironwood.len(),
            usize::from(recipient_wants_orchard && route_orchard_output_to_ironwood),
        )
        .map_err(|s| InputSelectorError::Change(ChangeError::BundleError(s)))?;
    #[cfg(not(feature = "orchard"))]
    let ironwood_action_count: usize = 0;

    #[cfg(feature = "orchard")]
    let use_ironwood = ironwood_action_count > 0;

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
                ironwood_action_count,
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
                ironwood_action_count,
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
                ironwood_action_count,
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
                ironwood_action_count,
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

    let payment = zip321::Payment::new(
        recipient,
        Some(total_to_recipient),
        memo,
        None,
        None,
        vec![],
    )
    .map_err(|e| InputSelectorError::Proposal(ProposalError::Zip321(e.with_index(0))))?;

    let transaction_request =
        TransactionRequest::new(vec![payment.clone()]).map_err(|payment_error| {
            InputSelectorError::Proposal(ProposalError::Zip321(payment_error))
        })?;

    let shielded_inputs = NonEmpty::from_vec(spendable_notes.into_vec(&SimpleNoteRetention {
        sapling: use_sapling,
        #[cfg(feature = "orchard")]
        orchard: use_orchard,
        #[cfg(feature = "orchard")]
        ironwood: use_ironwood,
    }))
    .map(|notes| ShieldedInputs::from_parts(anchor_height, notes));

    build_proposal(
        fee_rule,
        tr0_balance,
        target_height,
        shielded_inputs,
        vec![],
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

#[allow(clippy::too_many_arguments)]
fn build_proposal<FeeRuleT: FeeRule + Clone, NoteRef>(
    fee_rule: &FeeRuleT,
    tr0_balance: TransactionBalance,
    target_height: TargetHeight,
    shielded_inputs: Option<ShieldedInputs<NoteRef>>,
    transparent_inputs: Vec<WalletTransparentOutput<()>>,
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
            transparent_inputs,
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
        transparent_inputs,
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
        output_filter: CoinbaseFilter,
    ) -> Result<
        Proposal<<ChangeT as ChangeStrategy>::FeeRule, Infallible>,
        InputSelectorError<<DbT as InputSource>::Error, Self::Error, ChangeT::Error, Infallible>,
    >
    where
        ParamsT: consensus::Parameters,
        ChangeT: ChangeStrategy<MetaSource = Self::InputSource>,
    {
        let mut transparent_inputs = gather_shielding_inputs::<DbT, ChangeT::Error>(
            wallet_db,
            source_addrs,
            target_height,
            confirmations_policy,
            output_filter,
            shielding_max_inputs(self.shielding_block_space_percent),
        )?;

        let wallet_meta = change_strategy
            .fetch_wallet_meta(wallet_db, to_account, target_height, &[])
            .map_err(InputSelectorError::DataSource)?;

        let balance = compute_shielding_balance_with_dust_retry::<DbT, ChangeT, ParamsT>(
            change_strategy,
            params,
            target_height,
            &mut transparent_inputs,
            &wallet_meta,
        )?;

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

    #[allow(clippy::type_complexity)]
    fn propose_shielding_coinbase<ParamsT, FeeRuleT>(
        &self,
        params: &ParamsT,
        wallet_db: &Self::InputSource,
        fee_rule: &FeeRuleT,
        shielding_threshold: Zatoshis,
        source_addrs: &[TransparentAddress],
        to_address: ZcashAddress,
        memo: Option<MemoBytes>,
        limit: Option<usize>,
        target_height: TargetHeight,
    ) -> Result<
        Proposal<FeeRuleT, Infallible>,
        InputSelectorError<<DbT as InputSource>::Error, Self::Error, FeeRuleT::Error, Infallible>,
    >
    where
        ParamsT: consensus::Parameters,
        FeeRuleT: FeeRule + Clone,
    {
        // Coinbase-only is enforced here at the API boundary: callers cannot bypass
        // it. This is the privacy property that motivates having a dedicated method
        // rather than a more general "shield to address" path; only coinbase
        // outputs are eligible because they have no prior transparent transaction
        // graph that could be exposed to the shielded recipient.
        // The block-space cap and the caller-supplied `limit` (when present) both bound the number
        // of transparent inputs; `gather_shielding_inputs` applies the more restrictive of the two,
        // keeping the highest-value UTXOs first. When `limit` is `Some(0)` this empties the set, and
        // the subsequent `InsufficientFunds` check fires; this is the documented behavior.
        let transparent_inputs = gather_shielding_inputs::<DbT, FeeRuleT::Error>(
            wallet_db,
            source_addrs,
            target_height,
            // It doesn't matter here if we pass a 100 confirmations or 1 confirmations policy,
            // as coinbase txs require 100, which will be enforced by note selection.
            ConfirmationsPolicy::MIN,
            CoinbaseFilter::CoinbaseOnly,
            limit
                .unwrap_or(usize::MAX)
                .min(shielding_max_inputs(self.shielding_block_space_percent)),
        )?;

        let destination_pool =
            resolve_shielded_destination::<DbT, FeeRuleT::Error, ParamsT>(&to_address, params)?;

        let (sapling_output_count, orchard_action_count, ironwood_action_count) =
            match destination_pool {
                PoolType::SAPLING => {
                    let count = ::sapling::builder::BundleType::DEFAULT
                        .num_outputs(0, 1)
                        .expect("sapling DEFAULT bundle type permits any (spends, outputs) count");
                    (count, 0usize, 0usize)
                }
                #[cfg(feature = "orchard")]
                PoolType::ORCHARD => {
                    let count = orchard_fees::transactional_action_count(
                        orchard_bundle_version_for_height(params, target_height),
                        0,
                        1,
                    )
                    .expect("every Orchard bundle version permits spending and output creation");
                    if ironwood_active_at(params, target_height) {
                        (0usize, 0usize, count)
                    } else {
                        (0usize, count, 0usize)
                    }
                }
                // Unreachable: `resolve_shielded_destination` rejects transparent
                // destinations earlier with `ShieldingRequiresShieldedRecipient`.
                _ => {
                    return Err(InputSelectorError::Proposal(
                        ProposalError::ShieldingRequiresShieldedRecipient,
                    ));
                }
            };

        let fee = fee_rule
            .fee_required(
                params,
                BlockHeight::from(target_height),
                transparent_inputs
                    .iter()
                    .map(transparent_fees::InputView::serialized_size),
                std::iter::empty::<usize>(),
                0,
                sapling_output_count,
                orchard_action_count,
                ironwood_action_count,
            )
            // The `InputSelectorError::Change` variant is the only existing
            // carrier capable of holding an arbitrary fee-rule error
            // (`ChangeError::StrategyError` wraps `FeeRuleT::Error` in the
            // generic position). We reuse it here rather than introduce a new
            // top-level variant.
            .map_err(|e| InputSelectorError::Change(ChangeError::StrategyError(e)))?;

        // Route the full available value (input_total - fee) as an explicit
        // payment to the supplied destination. No change is produced.
        let input_total = transparent_inputs
            .iter()
            .map(|utxo| utxo.value())
            .try_fold(Zatoshis::ZERO, |acc, v| acc + v)
            .ok_or(InputSelectorError::Selection(
                GreedyInputSelectorError::Balance(BalanceError::Overflow),
            ))?;
        let payment_amount =
            (input_total - fee).ok_or_else(|| InputSelectorError::InsufficientFunds {
                available: input_total,
                required: fee,
            })?;

        if payment_amount < shielding_threshold {
            return Err(InputSelectorError::InsufficientFunds {
                available: payment_amount,
                required: shielding_threshold,
            });
        }

        let payment = Payment::new(to_address, Some(payment_amount), memo, None, None, vec![])
            .map_err(|payment_error| {
                InputSelectorError::Proposal(ProposalError::Zip321(payment_error.with_index(0)))
            })?;
        let request = TransactionRequest::new(vec![payment]).map_err(|payment_error| {
            InputSelectorError::Proposal(ProposalError::Zip321(payment_error))
        })?;
        let mut payment_pools = BTreeMap::new();
        payment_pools.insert(0usize, destination_pool);
        let final_balance = TransactionBalance::new(vec![], fee).map_err(|_| {
            InputSelectorError::Selection(GreedyInputSelectorError::Balance(BalanceError::Overflow))
        })?;

        // `is_shielding` is `false` because the proposal layer reserves
        // `is_shielding = true` for the legacy "no payment, all value in change"
        // shape produced by `propose_shielding`. From the wallet's perspective
        // this is still a transparent -> shielded transfer of coinbase value.
        Proposal::single_step(
            request,
            payment_pools,
            transparent_inputs,
            None,
            final_balance,
            fee_rule.clone(),
            target_height,
            false,
        )
        .map_err(InputSelectorError::Proposal)
    }
}

/// Gathers spendable transparent UTXOs from each source address, applying the
/// supplied [`CoinbaseFilter`] and rejecting input sets that would
/// link activity on an ephemeral address to other wallet activity.
///
/// Shared between `propose_shielding` and `propose_shielding_coinbase`.
#[cfg(feature = "transparent-inputs")]
#[allow(clippy::type_complexity)]
fn gather_shielding_inputs<DbT, ChangeErrT>(
    wallet_db: &DbT,
    source_addrs: &[TransparentAddress],
    target_height: TargetHeight,
    confirmations_policy: ConfirmationsPolicy,
    output_filter: CoinbaseFilter,
    max_inputs: usize,
) -> Result<
    Vec<WalletTransparentOutput<()>>,
    InputSelectorError<
        <DbT as InputSource>::Error,
        GreedyInputSelectorError,
        ChangeErrT,
        Infallible,
    >,
>
where
    DbT: InputSource,
{
    use transparent::keys::TransparentKeyScope;

    // Gather the spendable UTXOs for every source address in a single query. This avoids issuing
    // one query per address (including for the many addresses that have no spendable outputs),
    // which is prohibitively expensive for wallets that hold large numbers of transparent
    // addresses.
    let mut utxos = wallet_db
        .get_spendable_transparent_outputs_for_addresses(
            source_addrs,
            target_height,
            confirmations_policy,
            output_filter,
        )
        .map_err(InputSelectorError::DataSource)?;

    // Cap the number of transparent inputs that a single shielding transaction may consume,
    // keeping the highest-value UTXOs first (stable tiebreaker by outpoint for determinism). UTXOs
    // beyond the cap are left unspent, to be consolidated by a subsequent shielding transaction.
    // When `max_inputs` is 0 this empties the set, and the caller's `InsufficientFunds` check
    // fires. The cap is applied before the linkability check below so that the check reflects the
    // outputs that will actually be spent.
    utxos.sort_by(|a, b| {
        b.value()
            .cmp(&a.value())
            .then_with(|| a.outpoint().cmp(b.outpoint()))
    });
    utxos.truncate(max_inputs);

    // We use `recipient_key_scope()` and `recipient_address()` from the returned outputs to
    // determine the set of input addresses and which of them are ephemeral, rather than querying
    // the wallet again per address.
    let ephemeral_addrs = utxos
        .iter()
        .filter_map(|utxo| {
            (utxo.recipient_key_scope() == Some(TransparentKeyScope::EPHEMERAL))
                .then_some(utxo.recipient_address())
        })
        .collect::<BTreeSet<_>>();
    let input_addrs = utxos
        .iter()
        .map(|utxo| utxo.recipient_address())
        .collect::<BTreeSet<_>>();

    // Funds may be spent from at most one ephemeral address at a time. If there are no
    // ephemeral addresses, we allow shielding from multiple transparent addresses.
    if !ephemeral_addrs.is_empty() && input_addrs.len() > 1 {
        return Err(InputSelectorError::Proposal(
            ProposalError::EphemeralAddressLinkability,
        ));
    }

    Ok(utxos
        .into_iter()
        .map(|utxo| utxo.redact_account_data())
        .collect())
}

/// Resolves a [`ZcashAddress`] destination for a shielding proposal to the
/// shielded pool it should be received in.
///
/// Rejects transparent and TEX addresses with
/// [`ProposalError::ShieldingRequiresShieldedRecipient`], and rejects Unified
/// Addresses without a shielded receiver with
/// [`GreedyInputSelectorError::UnsupportedAddress`].
#[cfg(feature = "transparent-inputs")]
#[allow(clippy::type_complexity)]
fn resolve_shielded_destination<DbT, ChangeErrT, ParamsT>(
    addr: &ZcashAddress,
    params: &ParamsT,
) -> Result<
    PoolType,
    InputSelectorError<
        <DbT as InputSource>::Error,
        GreedyInputSelectorError,
        ChangeErrT,
        Infallible,
    >,
>
where
    DbT: InputSource,
    ParamsT: consensus::Parameters,
{
    let resolved: Address = addr
        .clone()
        .convert_if_network(params.network_type())
        .map_err(InputSelectorError::Address)?;
    match resolved {
        Address::Sapling(_) => Ok(PoolType::SAPLING),
        #[cfg(feature = "orchard")]
        Address::Unified(ua) if ua.has_orchard() => Ok(PoolType::ORCHARD),
        Address::Unified(ua) if ua.has_sapling() => Ok(PoolType::SAPLING),
        Address::Unified(ua) => Err(InputSelectorError::Selection(
            GreedyInputSelectorError::UnsupportedAddress(Box::new(ua)),
        )),
        Address::Transparent(_) | Address::Tex(_) => Err(InputSelectorError::Proposal(
            ProposalError::ShieldingRequiresShieldedRecipient,
        )),
    }
}

/// Helper that performs the dust-input retry pattern used by `propose_shielding`.
///
/// On the first call to [`ChangeStrategy::compute_balance`], if the strategy
/// reports [`ChangeError::DustInputs`], those inputs are removed from
/// `transparent_inputs` and the balance is recomputed. The resulting proposal
/// directs all available value into change (the legacy `propose_shielding`
/// "all-change" shape).
#[cfg(feature = "transparent-inputs")]
#[allow(clippy::type_complexity)]
fn compute_shielding_balance_with_dust_retry<DbT, ChangeT, ParamsT>(
    change_strategy: &ChangeT,
    params: &ParamsT,
    target_height: TargetHeight,
    transparent_inputs: &mut Vec<WalletTransparentOutput<()>>,
    wallet_meta: &<ChangeT as ChangeStrategy>::AccountMetaT,
) -> Result<
    TransactionBalance,
    InputSelectorError<
        <DbT as InputSource>::Error,
        GreedyInputSelectorError,
        ChangeT::Error,
        Infallible,
    >,
>
where
    DbT: InputSource,
    ChangeT: ChangeStrategy<MetaSource = DbT>,
    ParamsT: consensus::Parameters,
{
    let trial = compute_shielding_balance::<DbT, ChangeT, ParamsT>(
        change_strategy,
        params,
        target_height,
        transparent_inputs,
        wallet_meta,
    );

    match trial {
        Ok(balance) => Ok(balance),
        Err(ChangeError::DustInputs { transparent, .. }) => {
            let exclusions: BTreeSet<OutPoint> = transparent.into_iter().collect();
            transparent_inputs.retain(|i| !exclusions.contains(i.outpoint()));

            compute_shielding_balance::<DbT, ChangeT, ParamsT>(
                change_strategy,
                params,
                target_height,
                transparent_inputs,
                wallet_meta,
            )
            .map_err(InputSelectorError::Change)
        }
        Err(other) => Err(InputSelectorError::Change(other)),
    }
}

/// Helper for `propose_shielding`'s balance computation that calls
/// `change_strategy.compute_balance` with empty Sapling and Orchard bundle
/// views, allowing the change strategy to direct all available transparent
/// input value into change.
#[cfg(feature = "transparent-inputs")]
#[allow(clippy::type_complexity)]
fn compute_shielding_balance<DbT, ChangeT, ParamsT>(
    change_strategy: &ChangeT,
    params: &ParamsT,
    target_height: TargetHeight,
    transparent_inputs: &[WalletTransparentOutput<()>],
    wallet_meta: &<ChangeT as ChangeStrategy>::AccountMetaT,
) -> Result<TransactionBalance, ChangeError<ChangeT::Error, Infallible>>
where
    DbT: InputSource,
    ChangeT: ChangeStrategy<MetaSource = DbT>,
    ParamsT: consensus::Parameters,
{
    change_strategy.compute_balance(
        params,
        target_height,
        transparent_inputs,
        &[] as &[TxOut],
        &sapling::EmptyBundleView,
        #[cfg(feature = "orchard")]
        &orchard_fees::EmptyBundleView,
        #[cfg(feature = "orchard")]
        &orchard_fees::EmptyBundleView,
        #[cfg(feature = "orchard")]
        false,
        None,
        wallet_meta,
    )
}

#[cfg(all(test, feature = "transparent-inputs"))]
mod tests {
    use super::shielding_max_inputs;

    #[test]
    fn shielding_max_inputs_from_block_space_percent() {
        // max_inputs = (MAX_BLOCK_BYTES * percent / 100) / P2PKH_STANDARD_INPUT_SIZE
        //            = (2_000_000 * percent / 100) / 150
        assert_eq!(shielding_max_inputs(0), 0);
        assert_eq!(shielding_max_inputs(1), 133); // 20_000 / 150
        assert_eq!(shielding_max_inputs(10), 1333); // 200_000 / 150
        assert_eq!(shielding_max_inputs(100), 13333); // 2_000_000 / 150
    }
}
