//! Change strategies designed for use with a standard fee.

use zcash_primitives::{
    consensus::{self, BlockHeight},
    memo::MemoBytes,
    transaction::{
        components::amount::NonNegativeAmount,
        fees::{
            fixed::FeeRule as FixedFeeRule,
            transparent,
            zip317::{FeeError as Zip317FeeError, FeeRule as Zip317FeeRule},
            StandardFeeRule,
        },
    },
};

use crate::ShieldedProtocol;

use super::{
    fixed, sapling as sapling_fees, zip317, ChangeError, ChangeStrategy, DustOutputPolicy,
    TransactionBalance,
};

#[cfg(feature = "orchard")]
use super::orchard as orchard_fees;

/// A change strategy that proposes change as a single output to the most current supported
/// shielded pool and delegates fee calculation to the provided fee rule.
pub struct SingleOutputChangeStrategy {
    fee_rule: StandardFeeRule,
    change_memo: Option<MemoBytes>,
    fallback_change_pool: ShieldedProtocol,
}

impl SingleOutputChangeStrategy {
    /// Constructs a new [`SingleOutputChangeStrategy`] with the specified ZIP 317
    /// fee parameters.
    ///
    /// `fallback_change_pool` is used when more than one shielded pool is enabled via
    /// feature flags, and the transaction has no shielded inputs.
    pub fn new(
        fee_rule: StandardFeeRule,
        change_memo: Option<MemoBytes>,
        fallback_change_pool: ShieldedProtocol,
    ) -> Self {
        Self {
            fee_rule,
            change_memo,
            fallback_change_pool,
        }
    }
}

impl ChangeStrategy for SingleOutputChangeStrategy {
    type FeeRule = StandardFeeRule;
    type Error = Zip317FeeError;

    fn fee_rule(&self) -> &Self::FeeRule {
        &self.fee_rule
    }

    fn compute_balance<P: consensus::Parameters, NoteRefT: Clone>(
        &self,
        params: &P,
        target_height: BlockHeight,
        transparent_inputs: &[impl transparent::InputView],
        transparent_outputs: &[impl transparent::OutputView],
        sapling: &impl sapling_fees::BundleView<NoteRefT>,
        #[cfg(feature = "orchard")] orchard: &impl orchard_fees::BundleView<NoteRefT>,
        dust_output_policy: &DustOutputPolicy,
    ) -> Result<TransactionBalance, ChangeError<Self::Error, NoteRefT>> {
        #[allow(deprecated)]
        match self.fee_rule() {
            StandardFeeRule::PreZip313 => fixed::SingleOutputChangeStrategy::new(
                FixedFeeRule::non_standard(NonNegativeAmount::const_from_u64(10000)),
                self.change_memo.clone(),
                self.fallback_change_pool,
            )
            .compute_balance(
                params,
                target_height,
                transparent_inputs,
                transparent_outputs,
                sapling,
                #[cfg(feature = "orchard")]
                orchard,
                dust_output_policy,
            )
            .map_err(|e| e.map(Zip317FeeError::Balance)),
            StandardFeeRule::Zip313 => fixed::SingleOutputChangeStrategy::new(
                FixedFeeRule::non_standard(NonNegativeAmount::const_from_u64(1000)),
                self.change_memo.clone(),
                self.fallback_change_pool,
            )
            .compute_balance(
                params,
                target_height,
                transparent_inputs,
                transparent_outputs,
                sapling,
                #[cfg(feature = "orchard")]
                orchard,
                dust_output_policy,
            )
            .map_err(|e| e.map(Zip317FeeError::Balance)),
            StandardFeeRule::Zip317 => zip317::SingleOutputChangeStrategy::new(
                Zip317FeeRule::standard(),
                self.change_memo.clone(),
                self.fallback_change_pool,
            )
            .compute_balance(
                params,
                target_height,
                transparent_inputs,
                transparent_outputs,
                sapling,
                #[cfg(feature = "orchard")]
                orchard,
                dust_output_policy,
            ),
        }
    }
}
