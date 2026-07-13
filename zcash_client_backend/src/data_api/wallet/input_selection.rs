//! Types related to the process of selecting inputs to be spent given a transaction request.
use core::marker::PhantomData;
use nonempty::NonEmpty;
use std::{
    collections::{BTreeMap, BTreeSet},
    error,
    fmt::{self, Debug, Display},
};

use transparent::bundle::TxOut;
use zcash_address::{ConversionError, ZcashAddress};
use zcash_keys::address::{Address, UnifiedAddress};
use zcash_primitives::transaction::fees::{FeeRule, zip317::P2PKH_STANDARD_OUTPUT_SIZE};
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
    std::convert::Infallible,
    transparent::{address::TransparentAddress, bundle::OutPoint},
    zcash_primitives::transaction::fees::{
        transparent as transparent_fees, transparent::InputSize, zip317::P2PKH_STANDARD_INPUT_SIZE,
    },
    zip321::Payment,
};

#[cfg(feature = "orchard")]
use crate::{data_api::wallet::ironwood_active_at, fees::orchard as orchard_fees};

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
    /// `spend_policy` controls which sources of funds the implementation may draw upon. It names
    /// the shielded pools from which notes may be selected — the implementation must not select
    /// notes from a pool the policy does not permit, returning
    /// [`InputSelectorError::InsufficientFunds`] rather than crossing into a non-permitted pool —
    /// and, behind the `transparent-inputs` feature flag, whether and from which addresses the
    /// account's transparent UTXOs may additionally be spent. Spending transparent funds, or
    /// combining notes across shielded pools, reduces privacy, so the caller must opt in
    /// explicitly by naming the permitted sources.
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
        spend_policy: &SpendPolicy,
        proposed_version: Option<TxVersion>,
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
        anchor_height: BlockHeight,
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
        anchor_height: BlockHeight,
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

/// The sources of funds an [`InputSelector`] is permitted to draw upon when satisfying a
/// transaction request.
///
/// Crossing a shielded pool boundary reduces privacy, so it must be an explicit choice of the
/// caller: the selector only spends notes from the shielded pools named in [`Self::shielded`], and
/// only spends transparent UTXOs when a [`TransparentSpendPolicy`] is provided. When a single
/// permitted pool cannot cover the request, the selector may combine the permitted pools (drawing
/// on the legacy Orchard pool last); if no combination of permitted sources suffices it returns
/// [`InputSelectorError::InsufficientFunds`] rather than reaching into a pool the caller did not
/// permit.
///
/// The default permits every shielded pool present in the build and no transparent spending,
/// preserving the historical fully-shielded behavior while letting a caller restrict the set to,
/// for example, `{Orchard}` to forbid pool crossing.
#[derive(Clone, Debug)]
pub struct SpendPolicy {
    shielded: BTreeSet<ShieldedPool>,
    #[cfg(feature = "transparent-inputs")]
    transparent: Option<TransparentSpendPolicy>,
}

impl Default for SpendPolicy {
    fn default() -> Self {
        Self::shielded_pools([
            ShieldedPool::Sapling,
            #[cfg(feature = "orchard")]
            ShieldedPool::Orchard,
            #[cfg(feature = "orchard")]
            ShieldedPool::Ironwood,
        ])
    }
}

impl SpendPolicy {
    /// Constructs a policy permitting selection from exactly the given shielded pools, with no
    /// transparent spending.
    pub fn shielded_pools(pools: impl IntoIterator<Item = ShieldedPool>) -> Self {
        Self {
            shielded: pools.into_iter().collect(),
            #[cfg(feature = "transparent-inputs")]
            transparent: None,
        }
    }

    /// Returns whether notes may be selected from the given shielded pool.
    pub fn permits_shielded(&self, pool: ShieldedPool) -> bool {
        self.shielded.contains(&pool)
    }

    /// Returns the set of shielded pools from which notes may be selected.
    pub fn shielded(&self) -> &BTreeSet<ShieldedPool> {
        &self.shielded
    }

    /// Adds a transparent spend policy, permitting transparent UTXOs to be spent as described.
    #[cfg(feature = "transparent-inputs")]
    pub fn with_transparent(mut self, transparent: TransparentSpendPolicy) -> Self {
        self.transparent = Some(transparent);
        self
    }

    /// Returns the transparent spend policy, or `None` if transparent UTXOs may not be spent.
    #[cfg(feature = "transparent-inputs")]
    pub fn transparent(&self) -> Option<&TransparentSpendPolicy> {
        self.transparent.as_ref()
    }
}

/// The caller's choice of which coinbase transparent outputs a transparent spend may draw upon.
///
/// Consensus requires coinbase funds to be spent to a single shielded output with no change and
/// without being mixed with non-coinbase inputs, so a transparent spend commits to one or the
/// other rather than combining them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CoinbasePolicy {
    /// Spend only coinbase transparent outputs.
    OnlyCoinbase,
    /// Spend only non-coinbase transparent outputs.
    NonCoinbase,
}

#[cfg(feature = "transparent-inputs")]
impl From<CoinbasePolicy> for CoinbaseFilter {
    fn from(policy: CoinbasePolicy) -> Self {
        match policy {
            CoinbasePolicy::OnlyCoinbase => CoinbaseFilter::CoinbaseOnly,
            CoinbasePolicy::NonCoinbase => CoinbaseFilter::NonCoinbaseOnly,
        }
    }
}

/// Specifies how transparent UTXOs may be spent in a transfer, when a [`SpendPolicy`] permits
/// transparent spending.
///
/// Spending transparent funds links the chosen transparent addresses on-chain, reducing privacy,
/// so a caller opts in by attaching this to a [`SpendPolicy`] via [`SpendPolicy::with_transparent`]
/// (the absence of a policy — the default — spends no transparent UTXOs). The policy names the
/// [`TransparentSource`] the UTXOs may be drawn from and, via [`CoinbasePolicy`], whether coinbase
/// or non-coinbase outputs are spent.
#[cfg(feature = "transparent-inputs")]
#[derive(Clone, Debug)]
pub struct TransparentSpendPolicy {
    source: TransparentSource,
    coinbase: CoinbasePolicy,
}

#[cfg(feature = "transparent-inputs")]
impl TransparentSpendPolicy {
    /// Spends non-coinbase UTXOs from arbitrary transparent receivers belonging to the account,
    /// as needed to satisfy the request. The proposer chooses the addresses, potentially linking
    /// them. (The legacy `ANY_TADDR` behavior.)
    pub fn any_account_addr() -> Self {
        Self {
            source: TransparentSource::AnyAccountAddr,
            coinbase: CoinbasePolicy::NonCoinbase,
        }
    }

    /// Spends non-coinbase UTXOs only from the specified transparent addresses, intentionally
    /// linking them.
    pub fn from_addresses(taddrs: NonEmpty<TransparentAddress>) -> Self {
        Self {
            source: TransparentSource::FromAddresses(NonEmptyBTreeSet::from_nonempty(taddrs)),
            coinbase: CoinbasePolicy::NonCoinbase,
        }
    }

    /// Spends non-coinbase UTXOs only from a single transparent address.
    pub fn from_one_address(taddr: TransparentAddress) -> Self {
        Self {
            source: TransparentSource::FromAddresses(NonEmptyBTreeSet::singleton(taddr)),
            coinbase: CoinbasePolicy::NonCoinbase,
        }
    }

    /// Returns a copy of this policy with the given coinbase policy in effect.
    pub fn with_coinbase(mut self, coinbase: CoinbasePolicy) -> Self {
        self.coinbase = coinbase;
        self
    }

    /// Returns the transparent source from which UTXOs may be drawn.
    pub fn source(&self) -> &TransparentSource {
        &self.source
    }

    /// Returns the coinbase policy in effect for this transparent spend.
    pub fn coinbase(&self) -> CoinbasePolicy {
        self.coinbase
    }

    /// Returns the explicit list of transparent addresses UTXOs may be drawn from, or `None` if
    /// any of the account's transparent receivers are permitted.
    fn address_allow_list(&self) -> Option<Vec<TransparentAddress>> {
        match &self.source {
            TransparentSource::FromAddresses(addrs) => Some(addrs.iter().copied().collect()),
            TransparentSource::AnyAccountAddr => None,
        }
    }
}

/// The transparent receivers a [`TransparentSpendPolicy`] may draw UTXOs from.
#[cfg(feature = "transparent-inputs")]
#[derive(Clone, Debug)]
pub enum TransparentSource {
    /// Any transparent receiver belonging to the account. The proposer chooses which, potentially
    /// linking them.
    AnyAccountAddr,
    /// Only the specified transparent addresses.
    FromAddresses(NonEmptyBTreeSet<TransparentAddress>),
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
        // Which coinbase outputs are eligible for selection.
        coinbase: CoinbaseFilter,
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
                coinbase,
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
        spend_policy: &SpendPolicy,
        proposed_version: Option<TxVersion>,
    ) -> Result<
        Proposal<<ChangeT as ChangeStrategy>::FeeRule, DbT::NoteRef>,
        InputSelectorError<<DbT as InputSource>::Error, Self::Error, ChangeT::Error, DbT::NoteRef>,
    >
    where
        ParamsT: consensus::Parameters,
        Self::InputSource: InputSource,
        ChangeT: ChangeStrategy<MetaSource = DbT>,
    {
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
                        // Represent an Orchard-receiver payment as an Ironwood-pool output once
                        // Ironwood is active (its value is accounted to the Ironwood bundle
                        // below), and as an Orchard-pool output otherwise.
                        let pool = if ironwood_active_at(params, target_height) {
                            // After NU6.3 the Orchard turnstile (a consensus rule) forbids adding
                            // value to the Orchard pool, so the payment must be delivered through
                            // the Ironwood bundle, which only a version 6 transaction carries. If a
                            // transaction version was explicitly requested that cannot carry an
                            // Ironwood bundle, reject the proposal here rather than constructing one
                            // that could only fail at build time.
                            if let Some(v) = proposed_version
                                && !v.has_ironwood()
                            {
                                return Err(
                                    ProposalError::OrchardReceiverRequiresIronwood(v).into()
                                );
                            }
                            PoolType::IRONWOOD
                        } else {
                            PoolType::ORCHARD
                        };
                        payment_pools.insert(*idx, pool);
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
        let mut transparent_inputs = match spend_policy.transparent() {
            None => {
                // No transparent spending is permitted; skip the gather entirely.
                Vec::new()
            }
            Some(transparent) => {
                let address_allow_list = transparent.address_allow_list();
                self.gather_transparent::<ChangeT>(
                    wallet_db,
                    target_height,
                    confirmations_policy,
                    account,
                    address_allow_list.as_deref(),
                    transparent.coinbase().into(),
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

        // The single pool-preference order that governs both which pools notes are
        // selected from and which of the selected notes are spent: the pool matching
        // the payment's outputs comes first, and later pools are drawn upon only when
        // the earlier ones cannot cover the required amount, so that pool crossing is
        // minimized. For a payment to an Orchard receiver the Orchard-family pools
        // lead: once NU6.3 is active such payments are constructed in the Ironwood
        // bundle — moving their value into the Ironwood pool — so Ironwood is
        // preferred, with the legacy Orchard pool last within the family.
        #[cfg(feature = "orchard")]
        let mut pool_preference = selectable_pool_preference(
            params,
            target_height,
            sapling_supported,
            orchard_supported,
            !orchard_outputs.is_empty(),
        );
        #[cfg(not(feature = "orchard"))]
        let mut pool_preference = {
            let mut pools = vec![];
            if sapling_supported {
                pools.push(ShieldedPool::Sapling);
            }
            pools
        };

        // Restrict selection to the shielded pools the caller's spend policy permits. Crossing a
        // pool boundary is privacy-breaking, so a pool the policy does not name is never drawn
        // upon — not even as a fallback when the permitted pools cannot cover the request, in
        // which case input selection reports `InsufficientFunds`.
        pool_preference.retain(|pool| spend_policy.permits_shielded(*pool));

        // This loop is guaranteed to terminate because on each iteration we check that the amount
        // of funds selected is strictly increasing. The loop will either return a successful
        // result or the wallet will eventually run out of funds to select.
        loop {
            #[cfg(not(feature = "orchard"))]
            let sapling_bundle_required = true;
            #[cfg(feature = "orchard")]
            let (sapling_bundle_required, orchard_bundle_required, ironwood_bundle_required) = {
                // Trim the selected notes to the pools that are actually needed: the first
                // pool (in `pool_preference` order) whose selected notes cover the required
                // amount is spent alone; otherwise pools are accumulated in preference order
                // until the running total covers the amount, or all pools are in use.
                let pool_values = [
                    (ShieldedPool::Sapling, shielded_inputs.sapling_value()?),
                    (ShieldedPool::Orchard, shielded_inputs.orchard_value()?),
                    (ShieldedPool::Ironwood, shielded_inputs.ironwood_value()?),
                ];
                let value_of = |pool: ShieldedPool| {
                    pool_values
                        .iter()
                        .find(|(p, _)| *p == pool)
                        .map(|(_, v)| *v)
                        .expect("all shielded pools are present in pool_values")
                };

                let use_pools: Vec<ShieldedPool> = if let Some(single) = pool_preference
                    .iter()
                    .find(|p| value_of(**p) >= amount_required)
                {
                    vec![*single]
                } else {
                    let mut running = Zatoshis::ZERO;
                    let mut used = vec![];
                    for pool in &pool_preference {
                        if running >= amount_required {
                            break;
                        }
                        running = (running + value_of(*pool))
                            .ok_or(GreedyInputSelectorError::Balance(BalanceError::Overflow))?;
                        used.push(*pool);
                    }
                    used
                };

                (
                    use_pools.contains(&ShieldedPool::Sapling),
                    use_pools.contains(&ShieldedPool::Orchard),
                    use_pools.contains(&ShieldedPool::Ironwood),
                )
            };

            let sapling_inputs = if sapling_bundle_required {
                shielded_inputs
                    .sapling()
                    .iter()
                    .map(|i| (*i.internal_note_id(), i.note().value()))
                    .collect()
            } else {
                vec![]
            };

            #[cfg(feature = "orchard")]
            let orchard_inputs = if orchard_bundle_required {
                shielded_inputs
                    .orchard()
                    .iter()
                    .map(|i| (*i.internal_note_id(), i.note().value()))
                    .collect()
            } else {
                vec![]
            };

            // Ironwood inputs are attributed to the Ironwood bundle for action-count and fee
            // purposes.
            #[cfg(feature = "orchard")]
            let ironwood_inputs = if ironwood_bundle_required {
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

                    // Transaction 1 carries no shielded spends or outputs, but the change
                    // strategy may still model hypothetical shielded change against these
                    // views, so they carry the bundle versions in effect at the target
                    // height rather than a fixed default.
                    #[cfg(feature = "orchard")]
                    let empty_orchard_view = (
                        orchard_bundle_version_for_height(params, target_height),
                        &[] as &[Infallible],
                        &[] as &[Infallible],
                    );
                    #[cfg(feature = "orchard")]
                    let empty_ironwood_view = (
                        ironwood_bundle_version_for_height(params, target_height),
                        &[] as &[Infallible],
                        &[] as &[Infallible],
                    );

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
                            &empty_orchard_view,
                            #[cfg(feature = "orchard")]
                            &empty_ironwood_view,
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
                        &empty_orchard_view,
                        #[cfg(feature = "orchard")]
                        &empty_ironwood_view,
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
                ironwood_bundle_version_for_height(params, target_height),
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
                ephemeral_output_value.map(EphemeralBalance::Output),
                &wallet_meta,
            );

            match tr0_balance {
                Ok(tr0_balance) => {
                    // At this point, we have enough input value to pay for everything, so we
                    // return here.
                    let shielded_inputs =
                        NonEmpty::from_vec(shielded_inputs.into_vec(&SimpleNoteRetention {
                            sapling: sapling_bundle_required,
                            #[cfg(feature = "orchard")]
                            orchard: orchard_bundle_required,
                            #[cfg(feature = "orchard")]
                            ironwood: ironwood_bundle_required,
                        }))
                        .map(ShieldedInputs::from_parts);

                    return build_proposal(
                        change_strategy.fee_rule(),
                        tr0_balance,
                        target_height,
                        anchor_height,
                        confirmations_policy,
                        shielded_inputs,
                        transparent_inputs,
                        transaction_request,
                        payment_pools,
                        #[cfg(feature = "orchard")]
                        ironwood_active_at(params, target_height),
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
                    #[cfg(feature = "orchard")]
                    mut ironwood,
                    ..
                }) => {
                    exclude.append(&mut sapling);
                    #[cfg(feature = "orchard")]
                    exclude.append(&mut orchard);
                    #[cfg(feature = "orchard")]
                    exclude.append(&mut ironwood);
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
                    if let Some(transparent) = spend_policy.transparent()
                        && required > amount_at_transparent_gather
                    {
                        let address_allow_list = transparent.address_allow_list();
                        transparent_inputs = wallet_db
                            .select_spendable_transparent_outputs(
                                account,
                                target_height,
                                confirmations_policy,
                                transparent.coinbase().into(),
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
                Err(other) => return Err(InputSelectorError::Change(other)),
            }

            // Candidate notes are selected from the pools of `pool_preference` — the
            // same order the pool-usage trimming at the top of the loop applies — so
            // the notes offered for spending and the notes actually spent are governed
            // by one policy: pool crossing is minimized, and a payment to an Orchard
            // receiver draws on the pool its output is constructed in (the Ironwood
            // pool once NU6.3 is active).
            shielded_inputs = wallet_db
                .select_spendable_notes(
                    account,
                    TargetValue::AtLeast(amount_required),
                    &pool_preference,
                    target_height,
                    confirmations_policy,
                    &exclude,
                )
                .map_err(InputSelectorError::DataSource)?;

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

/// Returns the shielded pools from which the greedy input selector may spend at the
/// given target height, in preference order.
///
/// The pool family matching the payment's outputs comes first, so that single-pool
/// coverage avoids unnecessary pool crossings: for an Orchard-family payment this is
/// Ironwood (when active) and then Orchard — an Orchard-receiver payment is delivered
/// via the Ironwood bundle once Ironwood is active — and for other payments it is
/// Sapling. The legacy Orchard pool comes last otherwise, so that it is drawn upon
/// only when the more current pools cannot cover the required amount.
#[cfg(feature = "orchard")]
fn selectable_pool_preference<ParamsT: consensus::Parameters>(
    params: &ParamsT,
    target_height: TargetHeight,
    sapling_supported: bool,
    orchard_supported: bool,
    prefer_orchard_family: bool,
) -> Vec<ShieldedPool> {
    let ironwood_selectable = orchard_supported && ironwood_active_at(params, target_height);
    let mut preference = Vec::with_capacity(3);
    if prefer_orchard_family {
        if ironwood_selectable {
            preference.push(ShieldedPool::Ironwood);
        }
        if orchard_supported {
            preference.push(ShieldedPool::Orchard);
        }
        if sapling_supported {
            preference.push(ShieldedPool::Sapling);
        }
    } else {
        if sapling_supported {
            preference.push(ShieldedPool::Sapling);
        }
        if ironwood_selectable {
            preference.push(ShieldedPool::Ironwood);
        }
        if orchard_supported {
            preference.push(ShieldedPool::Orchard);
        }
    }
    preference
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

/// Returns the Ironwood bundle version whose action-count policy applies to
/// transactions constructed for the given target height.
#[cfg(feature = "orchard")]
fn ironwood_bundle_version_for_height<ParamsT: consensus::Parameters, H: Into<BlockHeight>>(
    params: &ParamsT,
    target_height: H,
) -> ::orchard::bundle::BundleVersion {
    zcash_primitives::transaction::components::orchard::bundle_version_for_branch(
        consensus::BranchId::for_height(params, target_height.into()),
        ::orchard::ValuePool::Ironwood,
    )
    // The Ironwood pool did not exist prior to NU6.3, so no Ironwood bundle (and
    // no Ironwood action) can be produced for an earlier target height; every
    // bundle version yields the correct action count (zero) for an empty bundle.
    .unwrap_or(::orchard::bundle::BundleVersion::ironwood_v3())
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
    InputSelectorError<
        InputSourceT::Error,
        GreedyInputSelectorError,
        FeeRuleT::Error,
        InputSourceT::NoteRef,
    >,
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
        .map_err(|e| InputSelectorError::Selection(GreedyInputSelectorError::Balance(e)))?;

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

    let sapling_bundle_required = !spendable_notes.sapling().is_empty() || sapling_output_count > 0;

    // A payment to an Orchard receiver is represented in the proposal as an Ironwood-pool output
    // once Ironwood is active (delivered to the Orchard receiver via the Ironwood bundle), and as
    // an Orchard-pool output otherwise. The per-bundle action counts below reflect that split.
    #[cfg(feature = "orchard")]
    let orchard_receiver_present = recipient.can_receive_as(PoolType::ORCHARD);
    #[cfg(feature = "orchard")]
    let orchard_receivers_fill_ironwood = ironwood_active_at(params, target_height);
    #[cfg(feature = "orchard")]
    if orchard_receiver_present {
        payment_pools.insert(
            0,
            if orchard_receivers_fill_ironwood {
                PoolType::IRONWOOD
            } else {
                PoolType::ORCHARD
            },
        );
    }

    #[cfg(feature = "orchard")]
    let orchard_action_count = orchard_fees::transactional_action_count(
        // Input selection estimates fees with the padded default bundle type; the
        // unpadded opt-in is applied later by the change strategy.
        ::orchard::builder::BundleType::DEFAULT,
        orchard_bundle_version_for_height(params, target_height),
        spendable_notes.orchard.len(),
        usize::from(orchard_receiver_present && !orchard_receivers_fill_ironwood),
    )
    .map_err(|e| InputSelectorError::Change(ChangeError::BundleError(e)))?;
    #[cfg(not(feature = "orchard"))]
    let orchard_action_count: usize = 0;

    #[cfg(feature = "orchard")]
    let orchard_bundle_required = orchard_action_count > 0;

    #[cfg(feature = "orchard")]
    let ironwood_action_count = orchard::builder::BundleType::DEFAULT
        .num_actions(
            orchard::bundle::Flags::ENABLED,
            spendable_notes.ironwood.len(),
            usize::from(orchard_receiver_present && orchard_receivers_fill_ironwood),
        )
        .map_err(|s| InputSelectorError::Change(ChangeError::BundleError(s)))?;
    #[cfg(not(feature = "orchard"))]
    let ironwood_action_count: usize = 0;

    #[cfg(feature = "orchard")]
    let ironwood_bundle_required = ironwood_action_count > 0;

    let recipient_address: Address = recipient
        .clone()
        .convert_if_network(params.network_type())?;

    // A recipient that can only receive funds via a transparent output — a bare
    // transparent address, or a unified address with no shielded receiver — is paid
    // directly from the proposed transaction. TEX recipients are excluded: their
    // payment is delivered by the ephemeral second step, which carries its own
    // payment pool assignment.
    let pays_transparent_directly = match &recipient_address {
        Address::Transparent(_) => true,
        Address::Unified(addr) => {
            addr.has_transparent() && !(addr.has_sapling() || addr.has_orchard())
        }
        _ => false,
    };
    if pays_transparent_directly {
        payment_pools.insert(0, PoolType::Transparent);
    }

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
        Address::Unified(_) => fee_rule
            .fee_required(
                params,
                BlockHeight::from(target_height),
                [],
                if pays_transparent_directly {
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
        // Paying a TEX recipient requires a second, purely transparent transaction that
        // spends an ephemeral output of the first; constructing that ZIP 320 pair is
        // only supported when the `transparent-inputs` feature is enabled.
        #[cfg(not(feature = "transparent-inputs"))]
        Address::Tex(_) => {
            return Err(InputSelectorError::Selection(
                GreedyInputSelectorError::UnsupportedTexAddress,
            ));
        }
        #[cfg(feature = "transparent-inputs")]
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
        sapling: sapling_bundle_required,
        #[cfg(feature = "orchard")]
        orchard: orchard_bundle_required,
        #[cfg(feature = "orchard")]
        ironwood: ironwood_bundle_required,
    }))
    .map(ShieldedInputs::from_parts);

    build_proposal(
        fee_rule,
        tr0_balance,
        target_height,
        anchor_height,
        confirmations_policy,
        shielded_inputs,
        vec![],
        transaction_request,
        payment_pools,
        #[cfg(feature = "orchard")]
        ironwood_active_at(params, target_height),
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
    anchor_height: BlockHeight,
    confirmations_policy: ConfirmationsPolicy,
    shielded_inputs: Option<ShieldedInputs<NoteRef>>,
    transparent_inputs: Vec<WalletTransparentOutput<()>>,
    transaction_request: TransactionRequest,
    payment_pools: BTreeMap<usize, PoolType>,
    #[cfg(feature = "orchard")] ironwood_active: bool,
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
            Some(anchor_height),
            vec![],
            tr0_balance,
            false,
            #[cfg(feature = "orchard")]
            ironwood_active,
        )?);

        let tr1 =
            TransactionRequest::new(ephemeral_step.tr1_payments).expect("valid by construction");
        steps.push(Step::from_parts(
            &steps,
            tr1,
            ephemeral_step.tr1_payment_pools,
            vec![],
            None,
            Some(anchor_height),
            vec![ephemeral_stepoutput],
            tr1_balance,
            false,
            #[cfg(feature = "orchard")]
            ironwood_active,
        )?);

        return Proposal::multi_step(
            fee_rule.clone(),
            target_height,
            confirmations_policy,
            NonEmpty::from_vec(steps).expect("steps is known to be nonempty"),
        );
    }

    Proposal::single_step(
        transaction_request,
        payment_pools,
        transparent_inputs,
        shielded_inputs,
        anchor_height,
        tr0_balance,
        fee_rule.clone(),
        target_height,
        confirmations_policy,
        false,
        #[cfg(feature = "orchard")]
        ironwood_active,
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
        anchor_height: BlockHeight,
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
                anchor_height,
                balance,
                (*change_strategy.fee_rule()).clone(),
                target_height,
                confirmations_policy,
                true,
                #[cfg(feature = "orchard")]
                ironwood_active_at(params, target_height),
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
        anchor_height: BlockHeight,
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

        let destination_pool = resolve_shielded_destination::<DbT, FeeRuleT::Error, ParamsT>(
            &to_address,
            params,
            target_height,
        )?;

        let (sapling_output_count, orchard_action_count, ironwood_action_count) =
            match destination_pool {
                PoolType::SAPLING => {
                    let count = ::sapling::builder::BundleType::DEFAULT
                        .num_outputs(0, 1)
                        .expect("sapling DEFAULT bundle type permits any (spends, outputs) count");
                    (count, 0usize, 0usize)
                }
                // A pre-NU6.3 payment to an Orchard receiver; after Ironwood activation,
                // `resolve_shielded_destination` assigns such payments to the Ironwood pool.
                #[cfg(feature = "orchard")]
                PoolType::ORCHARD => {
                    let count = orchard_fees::transactional_action_count(
                        ::orchard::builder::BundleType::DEFAULT,
                        orchard_bundle_version_for_height(params, target_height),
                        0,
                        1,
                    )
                    .expect("every Orchard bundle version permits spending and output creation");
                    (0usize, count, 0usize)
                }
                // A post-NU6.3 payment to an Orchard receiver, delivered via the Ironwood
                // bundle and charged to its action count.
                #[cfg(feature = "orchard")]
                PoolType::IRONWOOD => {
                    let count = orchard_fees::transactional_action_count(
                        ::orchard::builder::BundleType::DEFAULT,
                        ironwood_bundle_version_for_height(params, target_height),
                        0,
                        1,
                    )
                    .expect("the Ironwood bundle version permits spending and output creation");
                    (0usize, 0usize, count)
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
            anchor_height,
            final_balance,
            fee_rule.clone(),
            target_height,
            // Coinbase shielding spends no shielded notes, so the anchor the resulting step defers
            // to is resolved from this policy at interpretation; the exact confirmation depth does
            // not matter for an input-less step.
            ConfirmationsPolicy::default(),
            false,
            #[cfg(feature = "orchard")]
            ironwood_active_at(params, target_height),
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
    target_height: TargetHeight,
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
    #[cfg(not(feature = "orchard"))]
    let _ = target_height;

    let resolved: Address = addr
        .clone()
        .convert_if_network(params.network_type())
        .map_err(InputSelectorError::Address)?;
    match resolved {
        Address::Sapling(_) => Ok(PoolType::SAPLING),
        // A payment to an Orchard-protocol receiver is an Ironwood-pool output once
        // Ironwood is active (delivered to the recipient's Orchard receiver via the
        // Ironwood bundle), and an Orchard-pool output otherwise.
        #[cfg(feature = "orchard")]
        Address::Unified(ua) if ua.has_orchard() => {
            Ok(if ironwood_active_at(params, target_height) {
                PoolType::IRONWOOD
            } else {
                PoolType::ORCHARD
            })
        }
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
/// `change_strategy.compute_balance` with empty shielded bundle views, allowing
/// the change strategy to direct all available transparent input value into
/// change.
///
/// The empty Orchard-family views carry the bundle versions in effect at the
/// target height (rather than a fixed default), because the change the strategy
/// directs into a shielded pool is charged against that pool's bundle under its
/// version's action-count policy.
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
    #[cfg(feature = "orchard")]
    let empty_orchard_view = (
        orchard_bundle_version_for_height(params, target_height),
        &[] as &[Infallible],
        &[] as &[Infallible],
    );
    #[cfg(feature = "orchard")]
    let empty_ironwood_view = (
        ironwood_bundle_version_for_height(params, target_height),
        &[] as &[Infallible],
        &[] as &[Infallible],
    );

    change_strategy.compute_balance(
        params,
        target_height,
        transparent_inputs,
        &[] as &[TxOut],
        &sapling::EmptyBundleView,
        #[cfg(feature = "orchard")]
        &empty_orchard_view,
        #[cfg(feature = "orchard")]
        &empty_ironwood_view,
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

#[cfg(test)]
mod spend_policy_tests {
    use super::*;

    // The default spend policy preserves the historical `ShieldedOnly` behavior: notes may be
    // selected from every shielded pool present in the build, and no transparent UTXOs are
    // spent. Restricting the set is what a caller does to prevent pool crossing.
    #[test]
    fn default_permits_all_shielded_pools_and_no_transparent() {
        let policy = SpendPolicy::default();
        assert!(policy.permits_shielded(ShieldedPool::Sapling));
        #[cfg(feature = "orchard")]
        {
            assert!(policy.permits_shielded(ShieldedPool::Orchard));
            assert!(policy.permits_shielded(ShieldedPool::Ironwood));
        }
        #[cfg(feature = "transparent-inputs")]
        assert!(policy.transparent().is_none());
    }

    // A caller can restrict selection to a single pool; other pools are then not permitted.
    #[test]
    fn shielded_pools_restricts_the_permitted_set() {
        let policy = SpendPolicy::shielded_pools([ShieldedPool::Orchard]);
        assert!(policy.permits_shielded(ShieldedPool::Orchard));
        assert!(!policy.permits_shielded(ShieldedPool::Sapling));
        assert!(!policy.permits_shielded(ShieldedPool::Ironwood));
    }

    // The caller-facing coinbase choice maps onto the internal `CoinbaseFilter` query control.
    #[cfg(feature = "transparent-inputs")]
    #[test]
    fn coinbase_policy_maps_to_filter() {
        use crate::data_api::CoinbaseFilter;
        assert_eq!(
            CoinbaseFilter::from(CoinbasePolicy::OnlyCoinbase),
            CoinbaseFilter::CoinbaseOnly
        );
        assert_eq!(
            CoinbaseFilter::from(CoinbasePolicy::NonCoinbase),
            CoinbaseFilter::NonCoinbaseOnly
        );
    }

    // A transparent spend policy spends non-coinbase UTXOs by default, and `with_coinbase`
    // overrides that choice while preserving the source.
    #[cfg(feature = "transparent-inputs")]
    #[test]
    fn transparent_policy_coinbase_defaults_and_override() {
        let policy = TransparentSpendPolicy::any_account_addr();
        assert_eq!(policy.coinbase(), CoinbasePolicy::NonCoinbase);

        let policy = policy.with_coinbase(CoinbasePolicy::OnlyCoinbase);
        assert_eq!(policy.coinbase(), CoinbasePolicy::OnlyCoinbase);
        assert!(matches!(policy.source(), TransparentSource::AnyAccountAddr));
    }
}
