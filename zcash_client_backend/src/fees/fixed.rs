//! Change strategies designed for use with a fixed fee.

use zcash_primitives::transaction::fees::{fixed::FeeRule as FixedFeeRule, transparent};
use zcash_protocol::{
    ShieldedPool,
    consensus::{self, BlockHeight},
    memo::MemoBytes,
    value::{BalanceError, Zatoshis},
};

use crate::{
    data_api::{anchor_retention::PoolMigrationParams, wallet::TargetHeight},
    note_management::SplitPlan,
};

use super::{
    ChangeError, ChangeStrategy, DustOutputPolicy, EphemeralBalance, TransactionBalance,
    common::{SinglePoolBalanceConfig, single_pool_output_balance},
    sapling as sapling_fees,
};

#[cfg(feature = "transparent-inputs")]
use super::TransparentChangePolicy;
#[cfg(feature = "orchard")]
use {super::orchard as orchard_fees, zcash_primitives::transaction::builder::BundlePadding};

/// A change strategy that proposes change as a single output. The output pool is chosen
/// as the most current pool that avoids unnecessary pool-crossing (with a specified
/// fallback when the transaction has no shielded inputs). Fee calculation is delegated
/// to the provided fee rule.
///
/// This strategy never splits change; a splitting note-management policy has no effect under it.
pub struct SingleOutputChangeStrategy {
    fee_rule: FixedFeeRule,
    change_memo: Option<MemoBytes>,
    fallback_change_pool: ShieldedPool,
    dust_output_policy: DustOutputPolicy,
    #[cfg(feature = "transparent-inputs")]
    transparent_change_policy: TransparentChangePolicy,
}

impl SingleOutputChangeStrategy {
    /// Constructs a new [`SingleOutputChangeStrategy`] with the specified fee rule
    /// and change memo.
    ///
    /// `fallback_change_pool` is used when more than one shielded pool is enabled via
    /// feature flags, and the transaction has no shielded inputs.
    pub fn new(
        fee_rule: FixedFeeRule,
        change_memo: Option<MemoBytes>,
        fallback_change_pool: ShieldedPool,
        dust_output_policy: DustOutputPolicy,
    ) -> Self {
        Self {
            fee_rule,
            change_memo,
            fallback_change_pool,
            dust_output_policy,
            #[cfg(feature = "transparent-inputs")]
            transparent_change_policy: TransparentChangePolicy::ShieldChange,
        }
    }

    /// Sets the [`TransparentChangePolicy`] to be used by this change strategy, determining
    /// whether change may be returned to the transparent pool when the flows of the transaction
    /// under construction are fully transparent.
    ///
    /// The default is [`TransparentChangePolicy::ShieldChange`]. This policy has no effect on
    /// transactions that involve any shielded flows.
    #[cfg(feature = "transparent-inputs")]
    pub fn with_transparent_change_policy(
        mut self,
        transparent_change_policy: TransparentChangePolicy,
    ) -> Self {
        self.transparent_change_policy = transparent_change_policy;
        self
    }
}

impl ChangeStrategy for SingleOutputChangeStrategy {
    type FeeRule = FixedFeeRule;
    type Error = BalanceError;

    fn fee_rule(&self) -> &Self::FeeRule {
        &self.fee_rule
    }

    fn compute_balance<P: consensus::Parameters, NoteRefT: Clone>(
        &self,
        params: &P,
        target_height: TargetHeight,
        anchor_height: BlockHeight,
        zip318: &PoolMigrationParams,
        transparent_inputs: &[impl transparent::InputView],
        transparent_outputs: &[impl transparent::OutputView],
        sapling: &impl sapling_fees::BundleView<NoteRefT>,
        #[cfg(feature = "orchard")] orchard: &impl orchard_fees::BundleView<NoteRefT>,
        #[cfg(feature = "orchard")] ironwood: &impl orchard_fees::BundleView<NoteRefT>,
        ephemeral_balance: Option<EphemeralBalance>,
        _split_plan: &SplitPlan,
    ) -> Result<TransactionBalance, ChangeError<Self::Error, NoteRefT>> {
        let cfg = SinglePoolBalanceConfig::new(
            params,
            &self.fee_rule,
            &self.dust_output_policy,
            self.fee_rule.fixed_fee(),
            self.fallback_change_pool,
            #[cfg(feature = "transparent-inputs")]
            self.transparent_change_policy,
            Zatoshis::ZERO,
            0,
        );

        // This strategy never splits change, whatever the caller's plan asks for.
        single_pool_output_balance(
            cfg,
            &SplitPlan::SingleOutput,
            target_height,
            transparent_inputs,
            transparent_outputs,
            sapling,
            #[cfg(feature = "orchard")]
            orchard,
            #[cfg(feature = "orchard")]
            ironwood,
            // The fixed-fee strategy has no unpadded opt-in; keep the padded default.
            #[cfg(feature = "orchard")]
            BundlePadding::DEFAULT,
            anchor_height,
            zip318,
            self.change_memo.as_ref(),
            ephemeral_balance,
        )
    }
}

#[cfg(test)]
mod tests {
    use crate::data_api::anchor_retention::{AnchorRetentionInterval, PoolMigrationParams};
    use ::transparent::bundle::TxOut;
    use zcash_primitives::transaction::fees::{
        fixed::FeeRule as FixedFeeRule, zip317::MINIMUM_FEE,
    };
    use zcash_protocol::consensus::BlockHeight;
    use zcash_protocol::{
        ShieldedPool,
        consensus::{Network, NetworkUpgrade, Parameters},
        value::Zatoshis,
    };

    use super::SingleOutputChangeStrategy;
    use crate::{
        data_api::wallet::input_selection::SaplingPayment,
        fees::{
            ChangeError, ChangeStrategy, ChangeValue, DustOutputPolicy,
            tests::{TestSaplingInput, TestTransparentInput},
        },
        note_management::SplitPlan,
    };

    #[cfg(feature = "orchard")]
    use crate::fees::orchard as orchard_fees;

    #[test]
    fn change_without_dust() {
        let fee_rule = FixedFeeRule::non_standard(MINIMUM_FEE);
        let change_strategy = SingleOutputChangeStrategy::new(
            fee_rule,
            None,
            ShieldedPool::Sapling,
            DustOutputPolicy::default(),
        );

        // spend a single Sapling note that is sufficient to pay the fee
        let result = change_strategy.compute_balance(
            &Network::TestNetwork,
            Network::TestNetwork
                .activation_height(NetworkUpgrade::Nu5)
                .unwrap()
                .into(),
            BlockHeight::from_u32(1),
            &PoolMigrationParams::new(AnchorRetentionInterval::ZIP_318),
            &[] as &[TestTransparentInput],
            &[] as &[TxOut],
            &(
                sapling::builder::BundleType::DEFAULT,
                &[TestSaplingInput {
                    note_id: 0,
                    value: Zatoshis::const_from_u64(60000),
                }][..],
                &[SaplingPayment::new(Zatoshis::const_from_u64(40000))][..],
            ),
            #[cfg(feature = "orchard")]
            &orchard_fees::EmptyBundleView,
            #[cfg(feature = "orchard")]
            &orchard_fees::EmptyBundleView,
            None,
            &SplitPlan::SingleOutput,
        );

        assert_matches!(
            result,
            Ok(balance) if
                balance.proposed_change() == [ChangeValue::sapling(Zatoshis::const_from_u64(10000), None)] &&
                balance.fee_required() == MINIMUM_FEE
        );
    }

    #[test]
    fn dust_change() {
        let fee_rule = FixedFeeRule::non_standard(MINIMUM_FEE);
        let change_strategy = SingleOutputChangeStrategy::new(
            fee_rule,
            None,
            ShieldedPool::Sapling,
            DustOutputPolicy::default(),
        );

        // spend a single Sapling note that is sufficient to pay the fee
        let result = change_strategy.compute_balance(
            &Network::TestNetwork,
            Network::TestNetwork
                .activation_height(NetworkUpgrade::Nu5)
                .unwrap()
                .into(),
            BlockHeight::from_u32(1),
            &PoolMigrationParams::new(AnchorRetentionInterval::ZIP_318),
            &[] as &[TestTransparentInput],
            &[] as &[TxOut],
            &(
                sapling::builder::BundleType::DEFAULT,
                &[
                    TestSaplingInput {
                        note_id: 0,
                        value: Zatoshis::const_from_u64(40000),
                    },
                    // enough to pay a fee, plus dust
                    TestSaplingInput {
                        note_id: 0,
                        value: Zatoshis::const_from_u64(10100),
                    },
                ][..],
                &[SaplingPayment::new(Zatoshis::const_from_u64(40000))][..],
            ),
            #[cfg(feature = "orchard")]
            &orchard_fees::EmptyBundleView,
            #[cfg(feature = "orchard")]
            &orchard_fees::EmptyBundleView,
            None,
            &SplitPlan::SingleOutput,
        );

        assert_matches!(
            result,
            Err(ChangeError::InsufficientFunds { available, required })
            if available == Zatoshis::const_from_u64(50100) && required == Zatoshis::const_from_u64(60000)
        );
    }
}
