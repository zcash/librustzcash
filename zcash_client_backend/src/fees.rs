use std::{
    fmt::{self, Debug, Display},
    num::{NonZeroU64, NonZeroUsize},
};

use zcash_primitives::{
    consensus::{self, BlockHeight},
    memo::MemoBytes,
    transaction::{
        components::{amount::NonNegativeAmount, OutPoint},
        fees::{transparent, FeeRule},
    },
};
use zcash_protocol::{PoolType, ShieldedProtocol};

use crate::data_api::InputSource;

pub(crate) mod common;
pub mod fixed;
#[cfg(feature = "orchard")]
pub mod orchard;
pub mod sapling;
pub mod standard;
pub mod zip317;

/// `ChangeValue` represents either a proposed change output to a shielded pool
/// (with an optional change memo), or if the "transparent-inputs" feature is
/// enabled, an ephemeral output to the transparent pool.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChangeValue(ChangeValueInner);

#[derive(Clone, Debug, PartialEq, Eq)]
enum ChangeValueInner {
    Shielded {
        protocol: ShieldedProtocol,
        value: NonNegativeAmount,
        memo: Option<MemoBytes>,
    },
    #[cfg(feature = "transparent-inputs")]
    EphemeralTransparent { value: NonNegativeAmount },
}

impl ChangeValue {
    /// Constructs a new ephemeral transparent output value.
    #[cfg(feature = "transparent-inputs")]
    pub fn ephemeral_transparent(value: NonNegativeAmount) -> Self {
        Self(ChangeValueInner::EphemeralTransparent { value })
    }

    /// Constructs a new change value that will be created as a shielded output.
    pub fn shielded(
        protocol: ShieldedProtocol,
        value: NonNegativeAmount,
        memo: Option<MemoBytes>,
    ) -> Self {
        Self(ChangeValueInner::Shielded {
            protocol,
            value,
            memo,
        })
    }

    /// Constructs a new change value that will be created as a Sapling output.
    pub fn sapling(value: NonNegativeAmount, memo: Option<MemoBytes>) -> Self {
        Self::shielded(ShieldedProtocol::Sapling, value, memo)
    }

    /// Constructs a new change value that will be created as an Orchard output.
    #[cfg(feature = "orchard")]
    pub fn orchard(value: NonNegativeAmount, memo: Option<MemoBytes>) -> Self {
        Self::shielded(ShieldedProtocol::Orchard, value, memo)
    }

    /// Returns the pool to which the change or ephemeral output should be sent.
    pub fn output_pool(&self) -> PoolType {
        match &self.0 {
            ChangeValueInner::Shielded { protocol, .. } => PoolType::Shielded(*protocol),
            #[cfg(feature = "transparent-inputs")]
            ChangeValueInner::EphemeralTransparent { .. } => PoolType::Transparent,
        }
    }

    /// Returns the value of the change or ephemeral output to be created, in zatoshis.
    pub fn value(&self) -> NonNegativeAmount {
        match &self.0 {
            ChangeValueInner::Shielded { value, .. } => *value,
            #[cfg(feature = "transparent-inputs")]
            ChangeValueInner::EphemeralTransparent { value } => *value,
        }
    }

    /// Returns the memo to be associated with the output.
    pub fn memo(&self) -> Option<&MemoBytes> {
        match &self.0 {
            ChangeValueInner::Shielded { memo, .. } => memo.as_ref(),
            #[cfg(feature = "transparent-inputs")]
            ChangeValueInner::EphemeralTransparent { .. } => None,
        }
    }

    /// Whether this is to be an ephemeral output.
    #[cfg_attr(
        not(feature = "transparent-inputs"),
        doc = "This is always false because the `transparent-inputs` feature is
               not enabled."
    )]
    pub fn is_ephemeral(&self) -> bool {
        match &self.0 {
            ChangeValueInner::Shielded { .. } => false,
            #[cfg(feature = "transparent-inputs")]
            ChangeValueInner::EphemeralTransparent { .. } => true,
        }
    }
}

/// The amount of change and fees required to make a transaction's inputs and
/// outputs balance under a specific fee rule, as computed by a particular
/// [`ChangeStrategy`] that is aware of that rule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransactionBalance {
    proposed_change: Vec<ChangeValue>,
    fee_required: NonNegativeAmount,

    // A cache for the sum of proposed change and fee; we compute it on construction anyway, so we
    // cache the resulting value.
    total: NonNegativeAmount,
}

impl TransactionBalance {
    /// Constructs a new balance from its constituent parts.
    pub fn new(
        proposed_change: Vec<ChangeValue>,
        fee_required: NonNegativeAmount,
    ) -> Result<Self, ()> {
        let total = proposed_change
            .iter()
            .map(|c| c.value())
            .chain(Some(fee_required).into_iter())
            .sum::<Option<NonNegativeAmount>>()
            .ok_or(())?;

        Ok(Self {
            proposed_change,
            fee_required,
            total,
        })
    }

    /// The change values proposed by the [`ChangeStrategy`] that computed this balance.
    pub fn proposed_change(&self) -> &[ChangeValue] {
        &self.proposed_change
    }

    /// Returns the fee computed for the transaction, assuming that the suggested
    /// change outputs are added to the transaction.
    pub fn fee_required(&self) -> NonNegativeAmount {
        self.fee_required
    }

    /// Returns the sum of the proposed change outputs and the required fee.
    pub fn total(&self) -> NonNegativeAmount {
        self.total
    }
}

/// Errors that can occur in computing suggested change and/or fees.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ChangeError<E, NoteRefT> {
    /// Insufficient inputs were provided to change selection to fund the
    /// required outputs and fees.
    InsufficientFunds {
        /// The total of the inputs provided to change selection
        available: NonNegativeAmount,
        /// The total amount of input value required to fund the requested outputs,
        /// including the required fees.
        required: NonNegativeAmount,
    },
    /// Some of the inputs provided to the transaction have value less than the
    /// marginal fee, and could not be determined to have any economic value in
    /// the context of this input selection.
    ///
    /// This determination is potentially conservative in the sense that inputs
    /// with value less than or equal to the marginal fee might be excluded, even
    /// though in practice they would not cause the fee to increase. Inputs with
    /// value greater than the marginal fee will never be excluded.
    ///
    /// The ordering of the inputs in each list is unspecified.
    DustInputs {
        /// The outpoints for transparent inputs that could not be determined to
        /// have economic value in the context of this input selection.
        transparent: Vec<OutPoint>,
        /// The identifiers for Sapling inputs that could not be determined to
        /// have economic value in the context of this input selection.
        sapling: Vec<NoteRefT>,
        /// The identifiers for Orchard inputs that could not be determined to
        /// have economic value in the context of this input selection.
        #[cfg(feature = "orchard")]
        orchard: Vec<NoteRefT>,
    },
    /// An error occurred that was specific to the change selection strategy in use.
    StrategyError(E),
    /// The proposed bundle structure would violate bundle type construction rules.
    BundleError(&'static str),
}

impl<E, NoteRefT> ChangeError<E, NoteRefT> {
    pub(crate) fn map<E0, F: FnOnce(E) -> E0>(self, f: F) -> ChangeError<E0, NoteRefT> {
        match self {
            ChangeError::InsufficientFunds {
                available,
                required,
            } => ChangeError::InsufficientFunds {
                available,
                required,
            },
            ChangeError::DustInputs {
                transparent,
                sapling,
                #[cfg(feature = "orchard")]
                orchard,
            } => ChangeError::DustInputs {
                transparent,
                sapling,
                #[cfg(feature = "orchard")]
                orchard,
            },
            ChangeError::StrategyError(e) => ChangeError::StrategyError(f(e)),
            ChangeError::BundleError(e) => ChangeError::BundleError(e),
        }
    }
}

impl<CE: fmt::Display, N: fmt::Display> fmt::Display for ChangeError<CE, N> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self {
            ChangeError::InsufficientFunds {
                available,
                required,
            } => write!(
                f,
                "Insufficient funds: required {} zatoshis, but only {} zatoshis were available.",
                u64::from(*required),
                u64::from(*available)
            ),
            ChangeError::DustInputs {
                transparent,
                sapling,
                #[cfg(feature = "orchard")]
                orchard,
            } => {
                #[cfg(feature = "orchard")]
                let orchard_len = orchard.len();
                #[cfg(not(feature = "orchard"))]
                let orchard_len = 0;

                // we can't encode the UA to its string representation because we
                // don't have network parameters here
                write!(
                    f,
                    "Insufficient funds: {} dust inputs were present, but would cost more to spend than they are worth.",
                    transparent.len() + sapling.len() + orchard_len,
                )
            }
            ChangeError::StrategyError(err) => {
                write!(f, "{}", err)
            }
            ChangeError::BundleError(err) => {
                write!(
                    f,
                    "The proposed transaction structure violates bundle type constraints: {}",
                    err
                )
            }
        }
    }
}

impl<E, N> std::error::Error for ChangeError<E, N>
where
    E: Debug + Display + std::error::Error + 'static,
    N: Debug + Display + 'static,
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self {
            ChangeError::StrategyError(e) => Some(e),
            _ => None,
        }
    }
}

/// An enumeration of actions to take when a transaction would potentially create dust
/// outputs (outputs that are likely to be without economic value due to fee rules).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DustAction {
    /// Do not allow creation of dust outputs; instead, require that additional inputs be provided.
    Reject,
    /// Explicitly allow the creation of dust change amounts greater than the specified value.
    AllowDustChange,
    /// Allow dust amounts to be added to the transaction fee.
    AddDustToFee,
}

/// A policy describing how a [`ChangeStrategy`] should treat potentially dust-valued change
/// outputs (outputs that are likely to be without economic value due to fee rules).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DustOutputPolicy {
    action: DustAction,
    dust_threshold: Option<NonNegativeAmount>,
}

impl DustOutputPolicy {
    /// Constructs a new dust output policy.
    ///
    /// A dust policy created with `None` as the dust threshold will delegate determination
    /// of the dust threshold to the change strategy that is evaluating the strategy; this
    /// is recommended, but an explicit value (including zero) may be provided to explicitly
    /// override the determination of the change strategy.
    pub fn new(action: DustAction, dust_threshold: Option<NonNegativeAmount>) -> Self {
        Self {
            action,
            dust_threshold,
        }
    }

    /// Returns the action to take in the event that a dust change amount would be produced.
    pub fn action(&self) -> DustAction {
        self.action
    }
    /// Returns a value that will be used to override the dust determination logic of the
    /// change policy, if any.
    pub fn dust_threshold(&self) -> Option<NonNegativeAmount> {
        self.dust_threshold
    }
}

impl Default for DustOutputPolicy {
    fn default() -> Self {
        DustOutputPolicy::new(DustAction::Reject, None)
    }
}

/// A policy that describes how change output should be split into multiple notes for the purpose
/// of note management.
#[derive(Clone, Copy, Debug)]
pub struct SplitPolicy {
    target_output_count: NonZeroUsize,
    min_split_output_size: NonNegativeAmount,
}

impl SplitPolicy {
    /// Constructs a new [`SplitPolicy`] from its constituent parts.
    pub fn new(
        target_output_count: NonZeroUsize,
        min_split_output_size: NonNegativeAmount,
    ) -> Self {
        Self {
            target_output_count,
            min_split_output_size,
        }
    }

    /// Constructs a [`SplitPolicy`] that prescribes a single output (no splitting).
    pub fn single_output() -> Self {
        Self {
            target_output_count: NonZeroUsize::MIN,
            min_split_output_size: NonNegativeAmount::ZERO,
        }
    }

    /// Returns the minimum value for a note resulting from splitting of change.
    ///
    /// If splitting change would result in notes of value less than the minimum split output size,
    /// a smaller number of splits should be chosen.
    pub fn min_split_output_size(&self) -> NonNegativeAmount {
        self.min_split_output_size
    }

    /// Returns the number of output notes to produce from the given total change value, given the
    /// number of existing unspent notes in the account and this policy.
    pub fn split_count(
        &self,
        existing_notes: usize,
        total_change: NonNegativeAmount,
    ) -> NonZeroUsize {
        let mut split_count =
            NonZeroUsize::new(usize::from(self.target_output_count).saturating_sub(existing_notes))
                .unwrap_or(NonZeroUsize::MIN);

        loop {
            let per_output_change = total_change.div_with_remainder(
                NonZeroU64::new(
                    u64::try_from(usize::from(split_count)).expect("usize fits into u64"),
                )
                .unwrap(),
            );
            if split_count > NonZeroUsize::MIN
                && *per_output_change.quotient() < self.min_split_output_size
            {
                split_count = NonZeroUsize::new(usize::from(split_count) - 1)
                    .expect("split_count checked to be > 1");
            } else {
                return split_count;
            }
        }
    }
}

/// `EphemeralBalance` describes the ephemeral input or output value for a transaction. It is used
/// in fee computation for series of transactions that use an ephemeral transparent output in an
/// intermediate step, such as when sending from a shielded pool to a [ZIP 320] "TEX" address.
///
/// [ZIP 320]: https://zips.z.cash/zip-0320
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EphemeralBalance {
    Input(NonNegativeAmount),
    Output(NonNegativeAmount),
}

impl EphemeralBalance {
    pub fn is_input(&self) -> bool {
        matches!(self, EphemeralBalance::Input(_))
    }

    pub fn is_output(&self) -> bool {
        matches!(self, EphemeralBalance::Output(_))
    }

    pub fn ephemeral_input_amount(&self) -> Option<NonNegativeAmount> {
        match self {
            EphemeralBalance::Input(v) => Some(*v),
            EphemeralBalance::Output(_) => None,
        }
    }

    pub fn ephemeral_output_amount(&self) -> Option<NonNegativeAmount> {
        match self {
            EphemeralBalance::Input(_) => None,
            EphemeralBalance::Output(v) => Some(*v),
        }
    }
}

/// A trait that represents the ability to compute the suggested change and fees that must be paid
/// by a transaction having a specified set of inputs and outputs.
pub trait ChangeStrategy {
    type FeeRule: FeeRule + Clone;
    type Error;

    /// The type of metadata source that this change strategy requires in order to be able to
    /// retrieve required wallet metadata. If more capabilities are required of the backend than
    /// are exposed in the [`InputSource`] trait, the implementer of this trait should define their
    /// own trait that descends from [`InputSource`] and adds the required capabilities there, and
    /// then implement that trait for their desired database backend.
    type MetaSource: InputSource;
    type WalletMeta;

    /// Returns the fee rule that this change strategy will respect when performing
    /// balance computations.
    fn fee_rule(&self) -> &Self::FeeRule;

    /// Uses the provided metadata source to obtain the wallet metadata required for change
    /// creation determinations.
    fn fetch_wallet_meta(
        &self,
        meta_source: &Self::MetaSource,
        account: <Self::MetaSource as InputSource>::AccountId,
        exclude: &[<Self::MetaSource as InputSource>::NoteRef],
    ) -> Result<Self::WalletMeta, <Self::MetaSource as InputSource>::Error>;

    /// Computes the totals of inputs, suggested change amounts, and fees given the
    /// provided inputs and outputs being used to construct a transaction.
    ///
    /// The fee computed as part of this operation should take into account the prospective
    /// change outputs recommended by this operation. If insufficient funds are available to
    /// supply the requested outputs and required fees, implementations should return
    /// [`ChangeError::InsufficientFunds`].
    ///
    /// If the inputs include notes or UTXOs that are not economic to spend in the context
    /// of this input selection, a [`ChangeError::DustInputs`] error can be returned
    /// indicating inputs that should be removed from the selection (all of which will
    /// have value less than or equal to the marginal fee). The caller should order the
    /// inputs from most to least preferred to spend within each pool, so that the most
    /// preferred ones are less likely to be indicated to remove.
    ///
    /// - `ephemeral_balance`: if the transaction is to be constructed with either an
    ///   ephemeral transparent input or an ephemeral transparent output this argument
    ///   may be used to provide the value of that input or output. The value of this
    ///   argument should be `None` in the case that there are no such items.
    /// - `wallet_meta`: Additional wallet metadata that the change strategy may use
    ///   in determining how to construct change outputs. This wallet metadata value
    ///   should be computed excluding the inputs provided in the `transparent_inputs`,
    ///   `sapling`, and `orchard` arguments.
    ///
    /// [ZIP 320]: https://zips.z.cash/zip-0320
    #[allow(clippy::too_many_arguments)]
    fn compute_balance<P: consensus::Parameters, NoteRefT: Clone>(
        &self,
        params: &P,
        target_height: BlockHeight,
        transparent_inputs: &[impl transparent::InputView],
        transparent_outputs: &[impl transparent::OutputView],
        sapling: &impl sapling::BundleView<NoteRefT>,
        #[cfg(feature = "orchard")] orchard: &impl orchard::BundleView<NoteRefT>,
        ephemeral_balance: Option<&EphemeralBalance>,
        wallet_meta: Option<&Self::WalletMeta>,
    ) -> Result<TransactionBalance, ChangeError<Self::Error, NoteRefT>>;
}

#[cfg(test)]
pub(crate) mod tests {
    use zcash_primitives::transaction::{
        components::{
            amount::NonNegativeAmount,
            transparent::{OutPoint, TxOut},
        },
        fees::transparent,
    };

    use super::sapling;

    #[derive(Debug)]
    pub(crate) struct TestTransparentInput {
        pub outpoint: OutPoint,
        pub coin: TxOut,
    }

    impl transparent::InputView for TestTransparentInput {
        fn outpoint(&self) -> &OutPoint {
            &self.outpoint
        }
        fn coin(&self) -> &TxOut {
            &self.coin
        }
    }

    pub(crate) struct TestSaplingInput {
        pub note_id: u32,
        pub value: NonNegativeAmount,
    }

    impl sapling::InputView<u32> for TestSaplingInput {
        fn note_id(&self) -> &u32 {
            &self.note_id
        }
        fn value(&self) -> NonNegativeAmount {
            self.value
        }
    }
}
