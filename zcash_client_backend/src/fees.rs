use std::{
    convert::Infallible,
    fmt::{self, Debug, Display},
    num::{NonZeroU64, NonZeroUsize},
};

#[cfg(feature = "transparent-inputs")]
use ::transparent::address::TransparentAddress;
use ::transparent::bundle::OutPoint;
use zcash_primitives::transaction::fees::{
    FeeRule,
    transparent::{self, InputSize},
    zip317::{self as prim_zip317},
};
use zcash_protocol::{
    PoolType, ShieldedPool,
    consensus::{self, BlockHeight},
    memo::MemoBytes,
    value::{BalanceError, Zatoshis},
};

use crate::data_api::{InputSource, wallet::TargetHeight};

pub mod common;
#[cfg(feature = "non-standard-fees")]
pub mod fixed;
#[cfg(feature = "orchard")]
pub mod orchard;
pub mod sapling;
pub mod standard;
pub mod zip317;

/// An enumeration of the standard fee rules supported by the wallet backend.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum StandardFeeRule {
    Zip317,
}

impl FeeRule for StandardFeeRule {
    type Error = prim_zip317::FeeError;

    fn fee_required<P: consensus::Parameters>(
        &self,
        params: &P,
        target_height: BlockHeight,
        transparent_input_sizes: impl IntoIterator<Item = InputSize>,
        transparent_output_sizes: impl IntoIterator<Item = usize>,
        sapling_input_count: usize,
        sapling_output_count: usize,
        orchard_action_count: usize,
        ironwood_action_count: usize,
    ) -> Result<Zatoshis, Self::Error> {
        #[allow(deprecated)]
        match self {
            Self::Zip317 => prim_zip317::FeeRule::standard().fee_required(
                params,
                target_height,
                transparent_input_sizes,
                transparent_output_sizes,
                sapling_input_count,
                sapling_output_count,
                orchard_action_count,
                ironwood_action_count,
            ),
        }
    }
}

/// A policy that determines how change should be returned to the wallet when the net flows of a
/// transaction under construction are fully transparent.
///
/// This policy has no effect on transactions that have any shielded inputs or outputs; change
/// for such transactions is always returned to a shielded pool, irrespective of the policy in
/// use. When the flows of a transaction are fully transparent, shielding change (the default)
/// reveals the change amount as the value of the shielded output(s) in an otherwise-transparent
/// transaction; returning the change to the transparent pool matches the behavior of
/// transparent-only wallets (including `zcashd`) at the cost of the change remaining unshielded.
///
#[cfg(feature = "transparent-inputs")]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum TransparentChangePolicy {
    /// Change is always returned to a shielded pool, even when the net flows of the transaction
    /// are fully transparent.
    ///
    /// This is the default policy.
    #[default]
    ShieldChange,
    /// When the net flows of the transaction are fully transparent, change is returned to the
    /// transparent pool at an internal-scope (change) transparent address of the wallet, as
    /// described in [BIP 44].
    ///
    /// [BIP 44]: https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki
    TransparentChangeAllowed,
    /// When the net flows of the transaction are fully transparent, change is returned to the
    /// transparent pool at the originating address of the selected transparent inputs, instead
    /// of an internal-scope address of the wallet.
    ///
    /// This is the appropriate policy when spending from a P2SH (e.g. multisig) address: change
    /// sent to an internal-scope P2PKH address would not be spendable under the same multisig
    /// arrangement, so it must instead be returned to the address that funded the transaction.
    ///
    /// If the selected inputs are controlled by more than one transparent address, change is
    /// returned to the single address controlling the largest total input value, with ties
    /// broken deterministically. If no originating address can be determined (for example,
    /// because the selected inputs do not use a standard script), change is instead shielded, as
    /// with [`Self::ShieldChange`].
    ReturnToOriginatingAddress,
}

/// The destination to which a non-ephemeral transparent change output should be sent.
#[cfg(feature = "transparent-inputs")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransparentChangeDestination {
    /// Change is to be sent to an internal-scope (change) transparent address of the wallet,
    /// to be reserved at transaction-construction time. Produced by
    /// [`TransparentChangePolicy::TransparentChangeAllowed`].
    InternalP2pkh,
    /// Change is to be sent to the given transparent address, which originated the transparent
    /// value being spent by the transaction. Produced by
    /// [`TransparentChangePolicy::ReturnToOriginatingAddress`].
    OriginatingAddress(TransparentAddress),
}

/// `ChangeValue` represents either a proposed change output to a shielded pool
/// (with an optional change memo), or if the "transparent-inputs" feature is
/// enabled, an output to the transparent pool: either an ephemeral output as
/// part of a [ZIP 320] transaction pair, or a non-ephemeral change output to
/// the transparent pool (see [`TransparentChangeDestination`] for the possible
/// destinations of such an output).
///
/// [ZIP 320]: https://zips.z.cash/zip-0320
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChangeValue(ChangeValueInner);

#[derive(Clone, Debug, PartialEq, Eq)]
enum ChangeValueInner {
    Shielded {
        protocol: ShieldedPool,
        value: Zatoshis,
        memo: Option<MemoBytes>,
    },
    #[cfg(feature = "transparent-inputs")]
    EphemeralTransparent { value: Zatoshis },
    #[cfg(feature = "transparent-inputs")]
    Transparent {
        value: Zatoshis,
        destination: TransparentChangeDestination,
    },
}

impl ChangeValue {
    /// Constructs a new ephemeral transparent output value.
    #[cfg(feature = "transparent-inputs")]
    pub fn ephemeral_transparent(value: Zatoshis) -> Self {
        Self(ChangeValueInner::EphemeralTransparent { value })
    }

    /// Constructs a new change value that will be created as a non-ephemeral transparent output
    /// sent to the given [`TransparentChangeDestination`].
    #[cfg(feature = "transparent-inputs")]
    pub fn transparent(value: Zatoshis, destination: TransparentChangeDestination) -> Self {
        Self(ChangeValueInner::Transparent { value, destination })
    }

    /// Constructs a new change value that will be created as a shielded output.
    pub fn shielded(protocol: ShieldedPool, value: Zatoshis, memo: Option<MemoBytes>) -> Self {
        Self(ChangeValueInner::Shielded {
            protocol,
            value,
            memo,
        })
    }

    /// Constructs a new change value that will be created as a Sapling output.
    pub fn sapling(value: Zatoshis, memo: Option<MemoBytes>) -> Self {
        Self::shielded(ShieldedPool::Sapling, value, memo)
    }

    /// Constructs a new change value that will be created as an Orchard output.
    #[cfg(feature = "orchard")]
    pub fn orchard(value: Zatoshis, memo: Option<MemoBytes>) -> Self {
        Self::shielded(ShieldedPool::Orchard, value, memo)
    }

    /// Constructs a new change value that will be created as an Ironwood output.
    #[cfg(feature = "orchard")]
    pub fn ironwood(value: Zatoshis, memo: Option<MemoBytes>) -> Self {
        Self::shielded(ShieldedPool::Ironwood, value, memo)
    }

    /// Returns the pool to which the change or ephemeral output should be sent.
    pub fn output_pool(&self) -> PoolType {
        match &self.0 {
            ChangeValueInner::Shielded { protocol, .. } => PoolType::Shielded(*protocol),
            #[cfg(feature = "transparent-inputs")]
            ChangeValueInner::EphemeralTransparent { .. } => PoolType::Transparent,
            #[cfg(feature = "transparent-inputs")]
            ChangeValueInner::Transparent { .. } => PoolType::Transparent,
        }
    }

    /// Returns the value of the change or ephemeral output to be created, in zatoshis.
    pub fn value(&self) -> Zatoshis {
        match &self.0 {
            ChangeValueInner::Shielded { value, .. } => *value,
            #[cfg(feature = "transparent-inputs")]
            ChangeValueInner::EphemeralTransparent { value } => *value,
            #[cfg(feature = "transparent-inputs")]
            ChangeValueInner::Transparent { value, .. } => *value,
        }
    }

    /// Returns the memo to be associated with the output.
    pub fn memo(&self) -> Option<&MemoBytes> {
        match &self.0 {
            ChangeValueInner::Shielded { memo, .. } => memo.as_ref(),
            #[cfg(feature = "transparent-inputs")]
            ChangeValueInner::EphemeralTransparent { .. } => None,
            #[cfg(feature = "transparent-inputs")]
            ChangeValueInner::Transparent { .. } => None,
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
            #[cfg(feature = "transparent-inputs")]
            ChangeValueInner::Transparent { .. } => false,
        }
    }

    /// Returns the destination for a non-ephemeral transparent change output, or `None` for any
    /// other kind of change value.
    #[cfg(feature = "transparent-inputs")]
    pub fn transparent_change_destination(&self) -> Option<&TransparentChangeDestination> {
        match &self.0 {
            ChangeValueInner::Transparent { destination, .. } => Some(destination),
            _ => None,
        }
    }
}

/// The amount of change and fees required to make a transaction's inputs and
/// outputs balance under a specific fee rule, as computed by a particular
/// [`ChangeStrategy`] that is aware of that rule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransactionBalance {
    proposed_change: Vec<ChangeValue>,
    fee_required: Zatoshis,

    // A cache for the sum of proposed change and fee; we compute it on construction anyway, so we
    // cache the resulting value.
    total: Zatoshis,
}

impl TransactionBalance {
    /// Constructs a new balance from its constituent parts.
    pub fn new(
        proposed_change: Vec<ChangeValue>,
        fee_required: Zatoshis,
    ) -> Result<Self, BalanceError> {
        let total = proposed_change
            .iter()
            .map(|c| c.value())
            .chain(Some(fee_required))
            .sum::<Option<Zatoshis>>()
            .ok_or(BalanceError::Overflow)?;

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
    pub fn fee_required(&self) -> Zatoshis {
        self.fee_required
    }

    /// Returns the sum of the proposed change outputs and the required fee.
    pub fn total(&self) -> Zatoshis {
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
        available: Zatoshis,
        /// The total amount of input value required to fund the requested outputs,
        /// including the required fees.
        required: Zatoshis,
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
        /// The identifiers for Ironwood inputs that could not be determined to
        /// have economic value in the context of this input selection.
        #[cfg(feature = "orchard")]
        ironwood: Vec<NoteRefT>,
    },
    /// An error occurred that was specific to the change selection strategy in use.
    StrategyError(E),
    /// The proposed bundle structure would violate bundle type construction rules.
    BundleError(&'static str),
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
                #[cfg(feature = "orchard")]
                ironwood,
            } => {
                #[cfg(feature = "orchard")]
                let orchard_len = orchard.len() + ironwood.len();
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
                write!(f, "{err}")
            }
            ChangeError::BundleError(err) => {
                write!(
                    f,
                    "The proposed transaction structure violates bundle type constraints: {err}"
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
    dust_threshold: Option<Zatoshis>,
}

impl DustOutputPolicy {
    /// Constructs a new dust output policy.
    ///
    /// A dust policy created with `None` as the dust threshold will delegate determination
    /// of the dust threshold to the change strategy that is evaluating the strategy; this
    /// is recommended, but an explicit value (including zero) may be provided to explicitly
    /// override the determination of the change strategy.
    pub fn new(action: DustAction, dust_threshold: Option<Zatoshis>) -> Self {
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
    pub fn dust_threshold(&self) -> Option<Zatoshis> {
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
///
/// If an account contains at least [`Self::target_output_count`] notes having at least value
/// [`Self::min_split_output_value`], this policy will recommend a single output; if the account
/// contains fewer such notes, this policy will recommend that multiple outputs be produced in
/// order to achieve the target.
#[derive(Clone, Copy, Debug)]
pub struct SplitPolicy {
    target_output_count: NonZeroUsize,
    min_split_output_value: Option<Zatoshis>,
}

impl SplitPolicy {
    /// In the case that no other conditions provided by the user are available to fall back on,
    /// a default value of [`MARGINAL_FEE`] * 100 will be used as the "minimum usable note value"
    /// when retrieving wallet metadata.
    ///
    /// [`MARGINAL_FEE`]: zcash_primitives::transaction::fees::zip317::MARGINAL_FEE
    pub(crate) const MIN_NOTE_VALUE: Zatoshis = Zatoshis::const_from_u64(500000);

    /// Constructs a new [`SplitPolicy`] that splits change to ensure the given number of spendable
    /// outputs exists within an account, each having at least the specified minimum note value.
    pub fn with_min_output_value(
        target_output_count: NonZeroUsize,
        min_split_output_value: Zatoshis,
    ) -> Self {
        Self {
            target_output_count,
            min_split_output_value: Some(min_split_output_value),
        }
    }

    /// Constructs a [`SplitPolicy`] that prescribes a single output (no splitting).
    pub fn single_output() -> Self {
        Self {
            target_output_count: NonZeroUsize::MIN,
            min_split_output_value: None,
        }
    }

    /// Returns the number of outputs that this policy will attempt to ensure that the wallet has
    /// available for spending.
    pub fn target_output_count(&self) -> NonZeroUsize {
        self.target_output_count
    }

    /// Returns the minimum value for a note resulting from splitting of change.
    pub fn min_split_output_value(&self) -> Option<Zatoshis> {
        self.min_split_output_value
    }

    /// Returns the number of output notes to produce from the given total change value, given the
    /// total value and number of existing unspent notes in the account and this policy.
    ///
    /// If splitting change to produce [`Self::target_output_count`] would result in notes of value
    /// less than [`Self::min_split_output_value`], then this will suggest a smaller number of
    /// splits so that each resulting change note has sufficient value.
    pub fn split_count(
        &self,
        existing_notes: Option<usize>,
        existing_notes_total: Option<Zatoshis>,
        total_change: Zatoshis,
    ) -> NonZeroUsize {
        fn to_nonzero_u64(value: usize) -> NonZeroU64 {
            NonZeroU64::new(u64::try_from(value).expect("usize fits into u64"))
                .expect("NonZeroU64 input derived from NonZeroUsize")
        }

        let mut split_count = NonZeroUsize::new(
            usize::from(self.target_output_count)
                .saturating_sub(existing_notes.unwrap_or(usize::MAX)),
        )
        .unwrap_or(NonZeroUsize::MIN);

        let min_split_output_value = self.min_split_output_value.or_else(|| {
            // If no minimum split output size is set, we choose the minimum split size to be a
            // quarter of the average value of notes in the wallet after the transaction.
            (existing_notes_total + total_change).map(|total| {
                *total
                    .div_with_remainder(to_nonzero_u64(
                        usize::from(self.target_output_count).saturating_mul(4),
                    ))
                    .quotient()
            })
        });

        if let Some(min_split_output_value) = min_split_output_value {
            loop {
                let per_output_change =
                    total_change.div_with_remainder(to_nonzero_u64(usize::from(split_count)));
                if *per_output_change.quotient() >= min_split_output_value {
                    return split_count;
                } else if let Some(new_count) = NonZeroUsize::new(usize::from(split_count) - 1) {
                    split_count = new_count;
                } else {
                    // We always create at least one change output.
                    return NonZeroUsize::MIN;
                }
            }
        } else {
            NonZeroUsize::MIN
        }
    }
}

/// `EphemeralBalance` describes the ephemeral input or output value for a transaction. It is used
/// in fee computation for series of transactions that use an ephemeral transparent output in an
/// intermediate step, such as when sending from a shielded pool to a [ZIP 320] "TEX" address.
///
/// [ZIP 320]: https://zips.z.cash/zip-0320
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EphemeralBalance {
    Input(Zatoshis),
    Output(Zatoshis),
}

impl EphemeralBalance {
    pub fn is_input(&self) -> bool {
        matches!(self, EphemeralBalance::Input(_))
    }

    pub fn is_output(&self) -> bool {
        matches!(self, EphemeralBalance::Output(_))
    }

    pub fn ephemeral_input_amount(&self) -> Option<Zatoshis> {
        match self {
            EphemeralBalance::Input(v) => Some(*v),
            EphemeralBalance::Output(_) => None,
        }
    }

    pub fn ephemeral_output_amount(&self) -> Option<Zatoshis> {
        match self {
            EphemeralBalance::Input(_) => None,
            EphemeralBalance::Output(v) => Some(*v),
        }
    }
}

/// A trait that defines a set of types used in wallet metadata retrieval. Ordinarily, this will
/// correspond to a type that implements [`InputSource`], and a blanket implementation of this
/// trait is provided for all types that implement [`InputSource`].
///
/// If more capabilities are required of the backend than are exposed in the [`InputSource`] trait,
/// the implementer of this trait should define their own trait that descends from [`InputSource`]
/// and adds the required capabilities there, and then implement that trait for their desired
/// database backend.
pub trait MetaSource {
    type Error;
    type AccountId;
    type NoteRef;
}

impl MetaSource for Infallible {
    type Error = Infallible;
    type AccountId = Infallible;
    type NoteRef = Infallible;
}

impl<I: InputSource> MetaSource for I {
    type Error = I::Error;
    type AccountId = I::AccountId;
    type NoteRef = I::NoteRef;
}

/// A trait that represents the ability to compute the suggested change and fees that must be paid
/// by a transaction having a specified set of inputs and outputs.
pub trait ChangeStrategy {
    type FeeRule: FeeRule + Clone;
    type Error: From<<Self::FeeRule as FeeRule>::Error>;

    /// The type of metadata source that this change strategy requires in order to be able to
    /// retrieve required wallet metadata.
    type MetaSource: MetaSource;

    /// Tye type of wallet metadata that this change strategy relies upon in order to compute
    /// change.
    type AccountMetaT;

    /// Returns the fee rule that this change strategy will respect when performing
    /// balance computations.
    fn fee_rule(&self) -> &Self::FeeRule;

    /// Uses the provided metadata source to obtain the wallet metadata required for change
    /// creation determinations.
    fn fetch_wallet_meta(
        &self,
        meta_source: &Self::MetaSource,
        account: <Self::MetaSource as MetaSource>::AccountId,
        target_height: TargetHeight,
        exclude: &[<Self::MetaSource as MetaSource>::NoteRef],
    ) -> Result<Self::AccountMetaT, <Self::MetaSource as MetaSource>::Error>;

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
    /// - `ironwood`: the Ironwood bundle view (behind the `orchard` feature). A V6
    ///   transaction carries a separate Ironwood bundle, distinct from `orchard`,
    ///   with its own action count; pass an empty view when nothing targets the
    ///   Ironwood pool.
    /// - `ephemeral_balance`: if the transaction is to be constructed with either an
    ///   ephemeral transparent input or an ephemeral transparent output this argument
    ///   may be used to provide the value of that input or output. The value of this
    ///   argument should be `None` in the case that there are no such items.
    /// - `wallet_meta`: Additional wallet metadata that the change strategy may use
    ///   in determining how to construct change outputs. This wallet metadata value
    ///   should be computed excluding the inputs provided in the `transparent_inputs`,
    ///   `sapling`, `orchard`, and `ironwood` arguments.
    ///
    /// [ZIP 320]: https://zips.z.cash/zip-0320
    #[allow(clippy::too_many_arguments)]
    fn compute_balance<P: consensus::Parameters, NoteRefT: Clone>(
        &self,
        params: &P,
        target_height: TargetHeight,
        transparent_inputs: &[impl transparent::InputView],
        transparent_outputs: &[impl transparent::OutputView],
        sapling: &impl sapling::BundleView<NoteRefT>,
        #[cfg(feature = "orchard")] orchard: &impl orchard::BundleView<NoteRefT>,
        #[cfg(feature = "orchard")] ironwood: &impl orchard::BundleView<NoteRefT>,
        ephemeral_balance: Option<EphemeralBalance>,
        wallet_meta: &Self::AccountMetaT,
    ) -> Result<TransactionBalance, ChangeError<Self::Error, NoteRefT>>;
}

#[cfg(test)]
pub(crate) mod tests {
    use ::transparent::address::TransparentAddress;
    use ::transparent::bundle::{OutPoint, TxOut};
    use zcash_primitives::transaction::fees::transparent;
    use zcash_protocol::value::Zatoshis;

    use super::sapling;

    /// An arbitrary stand-in for the serialized size of a P2SH input with a known redeem
    /// script, used so that tests can exercise P2SH inputs without the ZIP 317 fee rule
    /// rejecting them as having an unknown size.
    pub(crate) const TEST_P2SH_INPUT_SIZE: usize = 300;

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
        fn serialized_size(&self) -> transparent::InputSize {
            match self.coin.recipient_address() {
                Some(TransparentAddress::PublicKeyHash(_)) => {
                    transparent::InputSize::STANDARD_P2PKH
                }
                Some(TransparentAddress::ScriptHash(_)) => {
                    transparent::InputSize::Known(TEST_P2SH_INPUT_SIZE)
                }
                None => transparent::InputSize::Unknown(self.outpoint.clone()),
            }
        }
    }

    pub(crate) struct TestSaplingInput {
        pub note_id: u32,
        pub value: Zatoshis,
    }

    impl sapling::InputView<u32> for TestSaplingInput {
        fn note_id(&self) -> &u32 {
            &self.note_id
        }
        fn value(&self) -> Zatoshis {
            self.value
        }
    }

    #[cfg(feature = "orchard")]
    pub(crate) struct TestOrchardInput {
        pub note_id: u32,
        pub value: Zatoshis,
    }

    #[cfg(feature = "orchard")]
    impl super::orchard::InputView<u32> for TestOrchardInput {
        fn note_id(&self) -> &u32 {
            &self.note_id
        }
        fn value(&self) -> Zatoshis {
            self.value
        }
    }
}
