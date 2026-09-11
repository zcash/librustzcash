//! Change strategies designed to implement the ZIP 317 fee rules.
//!
//! Change selection in ZIP 317 requires careful handling of low-valued inputs
//! to ensure that inputs added to a transaction do not cause fees to rise by
//! an amount greater than their value.

use zcash_primitives::transaction::fees::{FeeRule, transparent, zip317 as prim_zip317};
use zcash_protocol::{
    ShieldedPool,
    consensus::{self, BlockHeight},
    memo::MemoBytes,
    value::{BalanceError, Zatoshis},
};

use crate::{
    data_api::{anchor_retention::PoolMigrationParams, wallet::TargetHeight},
    fees::StandardFeeRule,
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

/// An extension to the [`FeeRule`] trait that exposes methods required for
/// ZIP 317 fee calculation.
pub trait Zip317FeeRule: FeeRule {
    /// Returns the ZIP 317 marginal fee.
    fn marginal_fee(&self) -> Zatoshis;

    /// Returns the ZIP 317 number of grace actions
    fn grace_actions(&self) -> usize;
}

impl Zip317FeeRule for prim_zip317::FeeRule {
    fn marginal_fee(&self) -> Zatoshis {
        self.marginal_fee()
    }

    fn grace_actions(&self) -> usize {
        self.grace_actions()
    }
}

impl Zip317FeeRule for StandardFeeRule {
    fn marginal_fee(&self) -> Zatoshis {
        prim_zip317::FeeRule::standard().marginal_fee()
    }

    fn grace_actions(&self) -> usize {
        prim_zip317::FeeRule::standard().grace_actions()
    }
}

/// A change strategy that proposes change as a single output. The output pool is chosen
/// as the most current pool that avoids unnecessary pool-crossing (with a specified
/// fallback when the transaction has no shielded inputs). Fee calculation is delegated
/// to the provided fee rule.
///
/// This strategy never splits change; a splitting note-management policy has no effect under it.
pub struct SingleOutputChangeStrategy<R> {
    fee_rule: R,
    change_memo: Option<MemoBytes>,
    fallback_change_pool: ShieldedPool,
    dust_output_policy: DustOutputPolicy,
    #[cfg(feature = "transparent-inputs")]
    transparent_change_policy: TransparentChangePolicy,
}

impl<R> SingleOutputChangeStrategy<R> {
    /// Constructs a new [`SingleOutputChangeStrategy`] with the specified ZIP 317
    /// fee parameters and change memo.
    ///
    /// `fallback_change_pool` is used when more than one shielded pool is enabled via
    /// feature flags, and the transaction has no shielded inputs.
    pub fn new(
        fee_rule: R,
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

impl<R> ChangeStrategy for SingleOutputChangeStrategy<R>
where
    R: Zip317FeeRule + Clone,
    <R as FeeRule>::Error: From<BalanceError>,
{
    type FeeRule = R;
    type Error = <R as FeeRule>::Error;

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
            self.fee_rule.marginal_fee(),
            self.fallback_change_pool,
            #[cfg(feature = "transparent-inputs")]
            self.transparent_change_policy,
            self.fee_rule.marginal_fee(),
            self.fee_rule.grace_actions(),
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
            // The Orchard bundle is always padded to the default floor. Only the Ironwood
            // bundle's padding varies, and it is derived from the transaction's shape rather
            // than chosen here.
            #[cfg(feature = "orchard")]
            BundlePadding::DEFAULT,
            anchor_height,
            zip318,
            self.change_memo.as_ref(),
            ephemeral_balance,
        )
    }
}

/// A ZIP 317 change strategy that realizes the change pieces a note-management policy asks for;
/// see [`crate::note_management`].
///
/// The [`DustOutputPolicy`] given at construction governs the total change value. How that total
/// is divided into pieces is the note-management policy's responsibility.
pub struct MultiOutputChangeStrategy<R> {
    fee_rule: R,
    change_memo: Option<MemoBytes>,
    fallback_change_pool: ShieldedPool,
    dust_output_policy: DustOutputPolicy,
    #[cfg(feature = "transparent-inputs")]
    transparent_change_policy: TransparentChangePolicy,
}

impl<R> MultiOutputChangeStrategy<R> {
    /// Constructs a new [`MultiOutputChangeStrategy`] with the specified ZIP 317
    /// fee parameters and change memo.
    ///
    /// - `fallback_change_pool`: the pool to which change will be sent if when more than one
    ///   shielded pool is enabled via feature flags, and the transaction has no shielded inputs.
    pub fn new(
        fee_rule: R,
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
    /// transactions that involve any shielded flows. When transparent change is produced, it is
    /// always emitted as a single output; a split plan applies only to shielded change.
    #[cfg(feature = "transparent-inputs")]
    pub fn with_transparent_change_policy(
        mut self,
        transparent_change_policy: TransparentChangePolicy,
    ) -> Self {
        self.transparent_change_policy = transparent_change_policy;
        self
    }
}

impl<R> ChangeStrategy for MultiOutputChangeStrategy<R>
where
    R: Zip317FeeRule + Clone,
    <R as FeeRule>::Error: From<BalanceError>,
{
    type FeeRule = R;
    type Error = <R as FeeRule>::Error;

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
        split_plan: &SplitPlan,
    ) -> Result<TransactionBalance, ChangeError<Self::Error, NoteRefT>> {
        let cfg = SinglePoolBalanceConfig::new(
            params,
            &self.fee_rule,
            &self.dust_output_policy,
            self.fee_rule.marginal_fee(),
            self.fallback_change_pool,
            #[cfg(feature = "transparent-inputs")]
            self.transparent_change_policy,
            self.fee_rule.marginal_fee(),
            self.fee_rule.grace_actions(),
        );

        single_pool_output_balance(
            cfg,
            split_plan,
            target_height,
            transparent_inputs,
            transparent_outputs,
            sapling,
            #[cfg(feature = "orchard")]
            orchard,
            #[cfg(feature = "orchard")]
            ironwood,
            // The Orchard bundle is always padded to the default floor. Only the Ironwood
            // bundle's padding varies, and it is derived from the transaction's shape rather
            // than chosen here.
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
    // `sapling_fees` is named by both the orchard and the transparent-inputs tests.
    #[cfg(any(feature = "orchard", feature = "transparent-inputs"))]
    use crate::fees::sapling as sapling_fees;

    #[cfg(feature = "transparent-inputs")]
    use {
        crate::fees::TransparentChangePolicy,
        ::transparent::{address::TransparentAddress, bundle::OutPoint},
    };

    #[cfg(feature = "orchard")]
    use {
        crate::{
            data_api::wallet::{TargetHeight, input_selection::OrchardPayment},
            fees::{orchard as orchard_fees, tests::TestOrchardInput},
        },
        zcash_protocol::{
            PoolType,
            local_consensus::LocalNetwork,
            zip318::{AnchorBucketInterval, MAX_RESIDUAL_VALUE},
        },
    };

    use crate::{
        data_api::{
            anchor_retention::{AnchorRetentionInterval, PoolMigrationParams},
            wallet::input_selection::SaplingPayment,
        },
        fees::{
            ChangeError, ChangeStrategy, ChangeValue, DustAction, DustOutputPolicy,
            tests::{TestSaplingInput, TestTransparentInput},
            zip317::MultiOutputChangeStrategy,
        },
        note_management::SplitPlan,
    };
    use core::convert::Infallible;
    use zcash_protocol::{
        ShieldedPool,
        consensus::{BlockHeight, Network, NetworkUpgrade, Parameters},
        value::Zatoshis,
    };

    use ::transparent::{address::Script, bundle::TxOut};
    use zcash_primitives::transaction::fees::zip317::FeeRule as Zip317FeeRule;

    use super::SingleOutputChangeStrategy;

    #[test]
    fn change_without_dust() {
        let change_strategy = SingleOutputChangeStrategy::new(
            Zip317FeeRule::standard(),
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
                    value: Zatoshis::const_from_u64(55000),
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
                balance.proposed_change() == [ChangeValue::sapling(Zatoshis::const_from_u64(5000), None)] &&
                balance.fee_required() == Zatoshis::const_from_u64(10000)
        );
    }

    #[test]
    #[cfg(feature = "orchard")]
    fn change_without_dust_multi() {
        let change_strategy = MultiOutputChangeStrategy::new(
            Zip317FeeRule::standard(),
            None,
            ShieldedPool::Orchard,
            DustOutputPolicy::default(),
        );

        {
            // spend a single Orchard note, realizing as many 1,000,000-zatoshi pieces as the
            // change affords
            let balance = |pieces: usize| {
                change_strategy.compute_balance(
                    &Network::TestNetwork,
                    Network::TestNetwork
                        .activation_height(NetworkUpgrade::Nu5)
                        .unwrap()
                        .into(),
                    BlockHeight::from_u32(1),
                    &PoolMigrationParams::new(AnchorRetentionInterval::ZIP_318),
                    &[] as &[TestTransparentInput],
                    &[] as &[TxOut],
                    &sapling_fees::EmptyBundleView,
                    &(
                        ::orchard::bundle::BundleVersion::orchard_v2(),
                        &[TestOrchardInput {
                            note_id: 0,
                            value: Zatoshis::const_from_u64(750_0000),
                        }][..],
                        &[OrchardPayment::new(Zatoshis::const_from_u64(100_0000))][..],
                    ),
                    &orchard_fees::EmptyBundleView,
                    None,
                    &SplitPlan::new(vec![Zatoshis::const_from_u64(100_0000); pieces]),
                )
            };

            // The residual rides on the largest piece: 7,500,000 - 1,000,000 - 30,000 of fee
            // leaves 6,470,000 of change, of which four pieces take 1,000,000 each.
            assert_matches!(
                balance(5),
                Ok(balance) if
                    balance.proposed_change() == [
                        ChangeValue::orchard(Zatoshis::const_from_u64(247_0000), None),
                        ChangeValue::orchard(Zatoshis::const_from_u64(100_0000), None),
                        ChangeValue::orchard(Zatoshis::const_from_u64(100_0000), None),
                        ChangeValue::orchard(Zatoshis::const_from_u64(100_0000), None),
                        ChangeValue::orchard(Zatoshis::const_from_u64(100_0000), None),
                    ] &&
                    balance.fee_required() == Zatoshis::const_from_u64(30000)
            );

            // Three pieces are three change outputs, and the smaller bundle costs less.
            assert_matches!(
                balance(3),
                Ok(balance) if
                    balance.proposed_change() == [
                        ChangeValue::orchard(Zatoshis::const_from_u64(448_0000), None),
                        ChangeValue::orchard(Zatoshis::const_from_u64(100_0000), None),
                        ChangeValue::orchard(Zatoshis::const_from_u64(100_0000), None),
                    ] &&
                    balance.fee_required() == Zatoshis::const_from_u64(20000)
            );
        }

        {
            // spend a single Orchard note and produce 4 outputs, as the value of the note isn't
            // sufficient to produce 5
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
                &sapling_fees::EmptyBundleView,
                &(
                    ::orchard::bundle::BundleVersion::orchard_v2(),
                    &[TestOrchardInput {
                        note_id: 0,
                        value: Zatoshis::const_from_u64(600_0000),
                    }][..],
                    &[OrchardPayment::new(Zatoshis::const_from_u64(100_0000))][..],
                ),
                &orchard_fees::EmptyBundleView,
                None,
                &SplitPlan::new(vec![Zatoshis::const_from_u64(100_0000); 5]),
            );

            assert_matches!(
                result,
                Ok(balance) if
                    balance.proposed_change() == [
                        ChangeValue::orchard(Zatoshis::const_from_u64(197_5000), None),
                        ChangeValue::orchard(Zatoshis::const_from_u64(100_0000), None),
                        ChangeValue::orchard(Zatoshis::const_from_u64(100_0000), None),
                        ChangeValue::orchard(Zatoshis::const_from_u64(100_0000), None),
                    ] &&
                    balance.fee_required() == Zatoshis::const_from_u64(25000)
            );
        }

        {
            // spend a single Sapling note and produce no change outputs, as the value of outputs
            // has been requested such that it exactly empties the wallet
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
                        value: Zatoshis::const_from_u64(50000),
                    }][..],
                    &[SaplingPayment::new(Zatoshis::const_from_u64(40000))][..],
                ),
                #[cfg(feature = "orchard")]
                &orchard_fees::EmptyBundleView,
                #[cfg(feature = "orchard")]
                &orchard_fees::EmptyBundleView,
                None,
                &SplitPlan::new(vec![Zatoshis::const_from_u64(100_0000); 5]),
            );

            assert_matches!(
                result,
                Ok(balance) if
                    balance.proposed_change() == [ChangeValue::sapling(Zatoshis::ZERO, None)] &&
                    balance.fee_required() == Zatoshis::const_from_u64(10000)
            );
        }

        {
            // spend a single Sapling note, with insufficient funds to cover the minimum fee.
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
                        value: Zatoshis::const_from_u64(50000),
                    }][..],
                    &[SaplingPayment::new(Zatoshis::const_from_u64(40001))][..],
                ),
                #[cfg(feature = "orchard")]
                &orchard_fees::EmptyBundleView,
                #[cfg(feature = "orchard")]
                &orchard_fees::EmptyBundleView,
                None,
                &SplitPlan::new(vec![Zatoshis::const_from_u64(100_0000); 5]),
            );

            assert_matches!(
                result,
                Err(ChangeError::InsufficientFunds { available, required })
                    if available == Zatoshis::const_from_u64(50000)
                       && required == Zatoshis::const_from_u64(50001)
            );
        }

        {
            // Spend a single Sapling note, creating two output notes that cause the transaction to
            // balance exactly. This will fail, because even though there are enough funds in the
            // wallet for the transaction to go through, and the fee is correct for a two-output
            // transaction, we prohibit this case in order to prevent the transaction recipients
            // from being able to reason about the value of the input note via knowledge that there
            // is no change output.
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
                        value: Zatoshis::const_from_u64(50000),
                    }][..],
                    &[
                        SaplingPayment::new(Zatoshis::const_from_u64(30000)),
                        SaplingPayment::new(Zatoshis::const_from_u64(10000)),
                    ][..],
                ),
                #[cfg(feature = "orchard")]
                &orchard_fees::EmptyBundleView,
                #[cfg(feature = "orchard")]
                &orchard_fees::EmptyBundleView,
                None,
                &SplitPlan::new(vec![Zatoshis::const_from_u64(100_0000); 5]),
            );

            assert_matches!(
                result,
                Err(ChangeError::InsufficientFunds { available, required })
                    if available == Zatoshis::const_from_u64(50000)
                       && required == Zatoshis::const_from_u64(55000)
            );
        }
    }

    #[test]
    #[cfg(feature = "orchard")]
    fn cross_pool_change_without_dust() {
        let change_strategy = SingleOutputChangeStrategy::new(
            Zip317FeeRule::standard(),
            None,
            ShieldedPool::Orchard,
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
                    value: Zatoshis::const_from_u64(55000),
                }][..],
                &[] as &[Infallible],
            ),
            &(
                ::orchard::bundle::BundleVersion::orchard_v2(),
                &[] as &[Infallible],
                &[OrchardPayment::new(Zatoshis::const_from_u64(30000))][..],
            ),
            &orchard_fees::EmptyBundleView,
            None,
            &SplitPlan::SingleOutput,
        );

        assert_matches!(
            result,
            Ok(balance) if
                balance.proposed_change() == [ChangeValue::orchard(Zatoshis::const_from_u64(5000), None)] &&
                balance.fee_required() == Zatoshis::const_from_u64(20000)
        );
    }

    #[test]
    #[cfg(feature = "orchard")]
    fn orchard_v3_change_counts_spends_and_outputs_separately() {
        let change_strategy = SingleOutputChangeStrategy::new(
            Zip317FeeRule::standard(),
            None,
            ShieldedPool::Orchard,
            DustOutputPolicy::default(),
        );

        // Under the post-NU6.3 Orchard pool restriction (cross-address transfers
        // disabled), every spend and output occupies its own action: one spend plus a
        // payment and a change output make three logical actions, where the legacy
        // policy would count `max(1, 2) == 2`.
        let result = change_strategy.compute_balance(
            &Network::TestNetwork,
            Network::TestNetwork
                .activation_height(NetworkUpgrade::Nu6_3)
                .unwrap()
                .into(),
            BlockHeight::from_u32(1),
            &PoolMigrationParams::new(AnchorRetentionInterval::ZIP_318),
            &[] as &[TestTransparentInput],
            &[] as &[TxOut],
            &sapling_fees::EmptyBundleView,
            &(
                ::orchard::bundle::BundleVersion::orchard_v3(),
                &[TestOrchardInput {
                    note_id: 0,
                    value: Zatoshis::const_from_u64(80000),
                }][..],
                &[OrchardPayment::new(Zatoshis::const_from_u64(30000))][..],
            ),
            &orchard_fees::EmptyBundleView,
            None,
            &SplitPlan::SingleOutput,
        );

        assert_matches!(
            result,
            Ok(balance) if
                balance.proposed_change() == [ChangeValue::orchard(Zatoshis::const_from_u64(35000), None)] &&
                balance.fee_required() == Zatoshis::const_from_u64(15000)
        );
    }

    #[test]
    #[cfg(all(feature = "orchard", feature = "transparent-inputs"))]
    fn orchard_fallback_change_pool_is_promoted_to_ironwood_after_nu6_3() {
        // A caller that names Orchard as its fallback change pool.
        let change_strategy = MultiOutputChangeStrategy::new(
            Zip317FeeRule::standard(),
            None,
            ShieldedPool::Orchard,
            DustOutputPolicy::default(),
        );

        // A single transparent UTXO, shielded to the change pool. The fallback pool only
        // decides where change goes for a transaction whose flows are fully transparent: one
        // with shielded flows infers its change pool from the pool it already uses. So this
        // is the case in which naming Orchard as the fallback can actually direct change
        // into the Orchard pool.
        let transparent_inputs = [TestTransparentInput {
            outpoint: OutPoint::fake(),
            coin: TxOut::new(
                Zatoshis::const_from_u64(63000),
                TransparentAddress::PublicKeyHash([0u8; 20]).script().into(),
            ),
        }];
        let transparent_outputs = [TxOut::new(
            Zatoshis::const_from_u64(40000),
            Script::default(),
        )];

        // The shielded views are empty: the transaction has no shielded flows, so the change
        // output the strategy proposes is the only thing that will populate one of them.
        let sapling_view = sapling_fees::EmptyBundleView;
        let ironwood_view = (
            ::orchard::bundle::BundleVersion::ironwood_v3(),
            &[] as &[Infallible],
            &[] as &[Infallible],
        );

        // This transaction is not one half of a ZIP 320 pair, so it has no ephemeral balance.
        let ephemeral_balance = None;

        // The policy asks for a single change output: the assertions below are about the pool it
        // lands in, not the split.
        let split_plan = SplitPlan::SingleOutput;

        // The Orchard bundle version whose action-count policy applies at each height. The
        // Orchard view is empty in both cases and so contributes no actions, but the version
        // is what the transaction builder will be configured with.
        let pre_nu6_3_orchard_view = (
            ::orchard::bundle::BundleVersion::orchard_v2(),
            &[] as &[Infallible],
            &[] as &[Infallible],
        );
        let post_nu6_3_orchard_view = (
            ::orchard::bundle::BundleVersion::orchard_v3(),
            &[] as &[Infallible],
            &[] as &[Infallible],
        );

        let pre_nu6_3_height: TargetHeight = Network::TestNetwork
            .activation_height(NetworkUpgrade::Nu5)
            .unwrap()
            .into();
        let post_nu6_3_height: TargetHeight = Network::TestNetwork
            .activation_height(NetworkUpgrade::Nu6_3)
            .unwrap()
            .into();

        // Before NU6.3, value may freely enter the Orchard pool, so the fallback is honoured
        // as given and the change is returned to Orchard.
        let pre_nu6_3_balance = change_strategy.compute_balance::<_, Infallible>(
            &Network::TestNetwork,
            pre_nu6_3_height,
            BlockHeight::from_u32(1),
            &PoolMigrationParams::new(AnchorRetentionInterval::ZIP_318),
            &transparent_inputs,
            &transparent_outputs,
            &sapling_view,
            &pre_nu6_3_orchard_view,
            &ironwood_view,
            ephemeral_balance,
            &split_plan,
        );

        assert_matches!(
            pre_nu6_3_balance,
            Ok(balance) if
                balance.proposed_change() == [ChangeValue::orchard(Zatoshis::const_from_u64(8000), None)] &&
                balance.fee_required() == Zatoshis::const_from_u64(15000)
        );

        // After NU6.3, the Orchard turnstile forbids value from entering the Orchard pool.
        // This transaction spends no Orchard notes, so no amount of change may return to
        // Orchard; the strategy promotes the Orchard fallback to Ironwood rather than
        // proposing change that consensus would reject. The fee is unchanged: the change
        // output is charged to the Ironwood bundle instead of the Orchard one, and each pads
        // to the same two-action floor.
        let post_nu6_3_balance = change_strategy.compute_balance::<_, Infallible>(
            &Network::TestNetwork,
            post_nu6_3_height,
            BlockHeight::from_u32(1),
            &PoolMigrationParams::new(AnchorRetentionInterval::ZIP_318),
            &transparent_inputs,
            &transparent_outputs,
            &sapling_view,
            &post_nu6_3_orchard_view,
            &ironwood_view,
            ephemeral_balance,
            &split_plan,
        );

        assert_matches!(
            post_nu6_3_balance,
            Ok(balance) if
                balance.proposed_change() == [ChangeValue::ironwood(Zatoshis::const_from_u64(8000), None)] &&
                balance.fee_required() == Zatoshis::const_from_u64(15000)
        );
    }

    /// The change strategy records the exact dummy outputs it charged the fee against, so the
    /// builder can reproduce that action count. A canonical crossing has no Ironwood dummy output;
    /// a payment one zatoshi off the denomination grid has one.
    #[test]
    #[cfg(feature = "orchard")]
    fn the_change_strategy_records_the_dummy_outputs_it_costed() {
        let change_strategy = SingleOutputChangeStrategy::new(
            Zip317FeeRule::standard(),
            None,
            ShieldedPool::Orchard,
            DustOutputPolicy::default(),
        );
        let zip318 = PoolMigrationParams::new(AnchorRetentionInterval::ZIP_318);
        let interval = AnchorBucketInterval::ZIP_318;

        // An anchor ON the grid, as a canonical crossing requires.
        let anchor = interval.boundary_at_or_below(BlockHeight::from_u32(2_000_000));
        let height = TargetHeight::from(BlockHeight::from_u32(u32::from(anchor) + 10));

        // One Orchard input, large enough that its change stays in Orchard rather than being
        // promoted to Ironwood by the turnstile rule.
        let orchard_inputs = [TestOrchardInput {
            note_id: 0,
            value: Zatoshis::const_from_u64(10_000_000),
        }];
        let orchard_view = (
            ::orchard::bundle::BundleVersion::orchard_v3(),
            &orchard_inputs[..],
            &[] as &[Infallible],
        );
        let sapling_view = (
            sapling::builder::BundleType::DEFAULT,
            &[] as &[Infallible],
            &[] as &[Infallible],
        );

        let recorded_for = |value: Zatoshis| {
            let ironwood_outputs = [OrchardPayment::new(value)];
            let ironwood_view = (
                ::orchard::bundle::BundleVersion::ironwood_v3(),
                &[] as &[Infallible],
                &ironwood_outputs[..],
            );
            change_strategy
                .compute_balance::<_, u32>(
                    &Network::TestNetwork,
                    height,
                    anchor,
                    &zip318,
                    &[] as &[TestTransparentInput],
                    &[] as &[TxOut],
                    &sapling_view,
                    &orchard_view,
                    &ironwood_view,
                    None,
                    &SplitPlan::SingleOutput,
                )
                .expect("the input covers the payment and its fee")
                .dummy_outputs()
                .expect("the change strategy records dummy outputs")
                .ironwood()
        };

        assert_eq!(recorded_for(MAX_RESIDUAL_VALUE), 0);
        assert_eq!(
            recorded_for((MAX_RESIDUAL_VALUE + Zatoshis::const_from_u64(1)).unwrap()),
            1
        );
    }

    #[test]
    #[cfg(feature = "orchard")]
    fn ironwood_outputs_are_charged_actions() {
        // V6 transactions carry a separate Ironwood bundle, so a populated
        // Ironwood view must contribute its own actions to the fee rather than
        // being treated as zero. Compare two otherwise-identical balances that
        // differ only by the presence of an Ironwood output.
        let change_strategy = SingleOutputChangeStrategy::new(
            Zip317FeeRule::standard(),
            None,
            ShieldedPool::Orchard,
            DustOutputPolicy::default(),
        );

        let height = Network::TestNetwork
            .activation_height(NetworkUpgrade::Nu5)
            .unwrap()
            .into();
        let sapling_inputs = [TestSaplingInput {
            note_id: 0,
            value: Zatoshis::const_from_u64(100000),
        }];
        let orchard_outputs = [OrchardPayment::new(Zatoshis::const_from_u64(30000))];
        let sapling_view = (
            sapling::builder::BundleType::DEFAULT,
            &sapling_inputs[..],
            &[] as &[Infallible],
        );
        let orchard_view = (
            ::orchard::bundle::BundleVersion::orchard_v2(),
            &[] as &[Infallible],
            &orchard_outputs[..],
        );

        let without_ironwood = change_strategy
            .compute_balance(
                &Network::TestNetwork,
                height,
                BlockHeight::from_u32(1),
                &PoolMigrationParams::new(AnchorRetentionInterval::ZIP_318),
                &[] as &[TestTransparentInput],
                &[] as &[TxOut],
                &sapling_view,
                &orchard_view,
                &orchard_fees::EmptyBundleView,
                None,
                &SplitPlan::SingleOutput,
            )
            .unwrap();

        let with_ironwood = change_strategy
            .compute_balance(
                &Network::TestNetwork,
                height,
                BlockHeight::from_u32(1),
                &PoolMigrationParams::new(AnchorRetentionInterval::ZIP_318),
                &[] as &[TestTransparentInput],
                &[] as &[TxOut],
                &sapling_view,
                &orchard_view,
                &(
                    ::orchard::bundle::BundleVersion::ironwood_v3(),
                    &[] as &[Infallible],
                    &orchard_outputs[..],
                ),
                None,
                &SplitPlan::SingleOutput,
            )
            .unwrap();

        // ZIP 317 floors each shielded bundle that is used at 2 actions. Without
        // an Ironwood bundle: sapling (2) + orchard (2 outputs) = 4 actions; with
        // an Ironwood output: + ironwood (2) = 6 actions. At 5000 zat/action that
        // is 20000 vs 30000.
        assert_eq!(
            without_ironwood.fee_required(),
            Zatoshis::const_from_u64(20000)
        );
        assert_eq!(
            with_ironwood.fee_required(),
            Zatoshis::const_from_u64(30000)
        );
    }

    #[test]
    fn change_with_transparent_payments_implicitly_allowing_zero_change() {
        change_with_transparent_payments(DustOutputPolicy::default())
    }

    #[test]
    fn change_with_transparent_payments_explicitly_allowing_zero_change() {
        change_with_transparent_payments(DustOutputPolicy::new(
            DustAction::AllowDustChange,
            Some(Zatoshis::ZERO),
        ))
    }

    fn change_with_transparent_payments(dust_output_policy: DustOutputPolicy) {
        let change_strategy = SingleOutputChangeStrategy::new(
            Zip317FeeRule::standard(),
            None,
            ShieldedPool::Sapling,
            dust_output_policy,
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
            &[TxOut::new(
                Zatoshis::const_from_u64(40000),
                Script::default(),
            )],
            &(
                sapling::builder::BundleType::DEFAULT,
                &[TestSaplingInput {
                    note_id: 0,
                    value: Zatoshis::const_from_u64(55000),
                }][..],
                &[] as &[Infallible],
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
                balance.proposed_change() == [ChangeValue::sapling(Zatoshis::ZERO, None)]
                && balance.fee_required() == Zatoshis::const_from_u64(15000)
        );
    }

    #[test]
    #[cfg(feature = "transparent-inputs")]
    fn change_fully_transparent_no_change() {
        let change_strategy = SingleOutputChangeStrategy::new(
            Zip317FeeRule::standard(),
            None,
            ShieldedPool::Sapling,
            DustOutputPolicy::default(),
        );

        // Spend a single transparent UTXO that is exactly sufficient to pay the fee.
        let result = change_strategy.compute_balance::<_, Infallible>(
            &Network::TestNetwork,
            Network::TestNetwork
                .activation_height(NetworkUpgrade::Nu5)
                .unwrap()
                .into(),
            BlockHeight::from_u32(1),
            &PoolMigrationParams::new(AnchorRetentionInterval::ZIP_318),
            &[TestTransparentInput {
                outpoint: OutPoint::fake(),
                coin: TxOut::new(
                    Zatoshis::const_from_u64(50000),
                    TransparentAddress::PublicKeyHash([0u8; 20]).script().into(),
                ),
            }],
            &[TxOut::new(
                Zatoshis::const_from_u64(40000),
                Script::default(),
            )],
            &sapling_fees::EmptyBundleView,
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
                balance.proposed_change().is_empty() &&
                balance.fee_required() == Zatoshis::const_from_u64(10000)
        );
    }

    #[test]
    #[cfg(feature = "transparent-inputs")]
    fn change_transparent_flows_with_shielded_change() {
        let change_strategy = SingleOutputChangeStrategy::new(
            Zip317FeeRule::standard(),
            None,
            ShieldedPool::Sapling,
            DustOutputPolicy::default(),
        );

        // Spend a single transparent UTXO that is sufficient to pay the fee.
        let result = change_strategy.compute_balance::<_, Infallible>(
            &Network::TestNetwork,
            Network::TestNetwork
                .activation_height(NetworkUpgrade::Nu5)
                .unwrap()
                .into(),
            BlockHeight::from_u32(1),
            &PoolMigrationParams::new(AnchorRetentionInterval::ZIP_318),
            &[TestTransparentInput {
                outpoint: OutPoint::fake(),
                coin: TxOut::new(
                    Zatoshis::const_from_u64(63000),
                    TransparentAddress::PublicKeyHash([0u8; 20]).script().into(),
                ),
            }],
            &[TxOut::new(
                Zatoshis::const_from_u64(40000),
                Script::default(),
            )],
            &sapling_fees::EmptyBundleView,
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
                balance.proposed_change() == [ChangeValue::sapling(Zatoshis::const_from_u64(8000), None)] &&
                balance.fee_required() == Zatoshis::const_from_u64(15000)
        );
    }

    #[test]
    #[cfg(feature = "transparent-inputs")]
    fn change_transparent_flows_with_shielded_dust_change() {
        let change_strategy = SingleOutputChangeStrategy::new(
            Zip317FeeRule::standard(),
            None,
            ShieldedPool::Sapling,
            DustOutputPolicy::new(
                DustAction::AllowDustChange,
                Some(Zatoshis::const_from_u64(1000)),
            ),
        );

        // Spend a single transparent UTXO that is sufficient to pay the fee.
        // The change will go to the fallback shielded change pool even though all inputs
        // and payments are transparent, and even though the change amount (1000) would
        // normally be considered dust, because we set the dust policy to allow that.
        let result = change_strategy.compute_balance::<_, Infallible>(
            &Network::TestNetwork,
            Network::TestNetwork
                .activation_height(NetworkUpgrade::Nu5)
                .unwrap()
                .into(),
            BlockHeight::from_u32(1),
            &PoolMigrationParams::new(AnchorRetentionInterval::ZIP_318),
            &[TestTransparentInput {
                outpoint: OutPoint::fake(),
                coin: TxOut::new(
                    Zatoshis::const_from_u64(56000),
                    TransparentAddress::PublicKeyHash([0u8; 20]).script().into(),
                ),
            }],
            &[TxOut::new(
                Zatoshis::const_from_u64(40000),
                Script::default(),
            )],
            &sapling_fees::EmptyBundleView,
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
                balance.proposed_change() == [ChangeValue::sapling(Zatoshis::const_from_u64(1000), None)] &&
                balance.fee_required() == Zatoshis::const_from_u64(15000)
        );
    }

    #[test]
    #[cfg(feature = "transparent-inputs")]
    fn change_fully_transparent_with_transparent_change() {
        let change_strategy = SingleOutputChangeStrategy::new(
            Zip317FeeRule::standard(),
            None,
            ShieldedPool::Sapling,
            DustOutputPolicy::default(),
        )
        .with_transparent_change_policy(TransparentChangePolicy::TransparentChangeAllowed);

        // Spend a single transparent UTXO that is sufficient to pay the fee. The change is
        // returned to the transparent pool: one P2PKH input and two P2PKH outputs (the
        // payment plus the change output) require `5000 * max(1, 2) = 10000` zats in fees,
        // rather than the 15000 zats required when the change is shielded.
        let result = change_strategy.compute_balance::<_, Infallible>(
            &Network::TestNetwork,
            Network::TestNetwork
                .activation_height(NetworkUpgrade::Nu5)
                .unwrap()
                .into(),
            BlockHeight::from_u32(1),
            &PoolMigrationParams::new(AnchorRetentionInterval::ZIP_318),
            &[TestTransparentInput {
                outpoint: OutPoint::fake(),
                coin: TxOut::new(
                    Zatoshis::const_from_u64(63000),
                    TransparentAddress::PublicKeyHash([0u8; 20]).script().into(),
                ),
            }],
            &[TxOut::new(
                Zatoshis::const_from_u64(40000),
                Script::default(),
            )],
            &sapling_fees::EmptyBundleView,
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
                balance.proposed_change() == [ChangeValue::transparent(Zatoshis::const_from_u64(13000))] &&
                balance.fee_required() == Zatoshis::const_from_u64(10000)
        );
    }

    #[test]
    #[cfg(feature = "transparent-inputs")]
    fn change_fully_transparent_exact_match_with_transparent_change() {
        let change_strategy = SingleOutputChangeStrategy::new(
            Zip317FeeRule::standard(),
            None,
            ShieldedPool::Sapling,
            DustOutputPolicy::default(),
        )
        .with_transparent_change_policy(TransparentChangePolicy::TransparentChangeAllowed);

        // Spend a single transparent UTXO that exactly covers the payment plus the minimum
        // fee; no change output should be produced.
        let result = change_strategy.compute_balance::<_, Infallible>(
            &Network::TestNetwork,
            Network::TestNetwork
                .activation_height(NetworkUpgrade::Nu5)
                .unwrap()
                .into(),
            BlockHeight::from_u32(1),
            &PoolMigrationParams::new(AnchorRetentionInterval::ZIP_318),
            &[TestTransparentInput {
                outpoint: OutPoint::fake(),
                coin: TxOut::new(
                    Zatoshis::const_from_u64(50000),
                    TransparentAddress::PublicKeyHash([0u8; 20]).script().into(),
                ),
            }],
            &[TxOut::new(
                Zatoshis::const_from_u64(40000),
                Script::default(),
            )],
            &sapling_fees::EmptyBundleView,
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
                balance.proposed_change().is_empty() &&
                balance.fee_required() == Zatoshis::const_from_u64(10000)
        );
    }

    #[test]
    #[cfg(feature = "transparent-inputs")]
    fn transparent_change_policy_has_no_effect_on_shielded_flows() {
        let change_strategy = SingleOutputChangeStrategy::new(
            Zip317FeeRule::standard(),
            None,
            ShieldedPool::Sapling,
            DustOutputPolicy::default(),
        )
        .with_transparent_change_policy(TransparentChangePolicy::TransparentChangeAllowed);

        // Spend a single Sapling note; because the transaction involves shielded flows, the
        // change must be shielded even though transparent change is allowed by the policy.
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
                    value: Zatoshis::const_from_u64(55000),
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
                balance.proposed_change() == [ChangeValue::sapling(Zatoshis::const_from_u64(5000), None)] &&
                balance.fee_required() == Zatoshis::const_from_u64(10000)
        );
    }

    #[test]
    #[cfg(feature = "transparent-inputs")]
    fn transparent_change_is_not_split() {
        let change_strategy = MultiOutputChangeStrategy::new(
            Zip317FeeRule::standard(),
            None,
            ShieldedPool::Sapling,
            DustOutputPolicy::default(),
        )
        .with_transparent_change_policy(TransparentChangePolicy::TransparentChangeAllowed);

        // Spend a single transparent UTXO with change value sufficient to produce every piece
        // the plan asks for; because the change is returned to the transparent pool, it must
        // nevertheless be emitted as a single output.
        let result = change_strategy.compute_balance::<_, Infallible>(
            &Network::TestNetwork,
            Network::TestNetwork
                .activation_height(NetworkUpgrade::Nu5)
                .unwrap()
                .into(),
            BlockHeight::from_u32(1),
            &PoolMigrationParams::new(AnchorRetentionInterval::ZIP_318),
            &[TestTransparentInput {
                outpoint: OutPoint::fake(),
                coin: TxOut::new(
                    Zatoshis::const_from_u64(750_0000),
                    TransparentAddress::PublicKeyHash([0u8; 20]).script().into(),
                ),
            }],
            &[TxOut::new(
                Zatoshis::const_from_u64(100_0000),
                Script::default(),
            )],
            &sapling_fees::EmptyBundleView,
            #[cfg(feature = "orchard")]
            &orchard_fees::EmptyBundleView,
            #[cfg(feature = "orchard")]
            &orchard_fees::EmptyBundleView,
            None,
            &SplitPlan::new(vec![Zatoshis::const_from_u64(100_0000); 5]),
        );

        assert_matches!(
            result,
            Ok(balance) if
                balance.proposed_change() == [ChangeValue::transparent(Zatoshis::const_from_u64(649_0000))] &&
                balance.fee_required() == Zatoshis::const_from_u64(10000)
        );
    }

    #[test]
    #[cfg(feature = "transparent-inputs")]
    fn transparent_change_rejects_dust() {
        let change_strategy = SingleOutputChangeStrategy::new(
            Zip317FeeRule::standard(),
            None,
            ShieldedPool::Sapling,
            DustOutputPolicy::default(),
        )
        .with_transparent_change_policy(TransparentChangePolicy::TransparentChangeAllowed);

        // Spend a single transparent UTXO that would result in a 100-zat transparent change
        // output; under the default dust policy this must be rejected. The 55000-zat
        // requirement reflects the 5000-zat default dust threshold: adding 4900 zats to the
        // input value would produce change exactly at the threshold.
        let result = change_strategy.compute_balance::<_, Infallible>(
            &Network::TestNetwork,
            Network::TestNetwork
                .activation_height(NetworkUpgrade::Nu5)
                .unwrap()
                .into(),
            BlockHeight::from_u32(1),
            &PoolMigrationParams::new(AnchorRetentionInterval::ZIP_318),
            &[TestTransparentInput {
                outpoint: OutPoint::fake(),
                coin: TxOut::new(
                    Zatoshis::const_from_u64(50100),
                    TransparentAddress::PublicKeyHash([0u8; 20]).script().into(),
                ),
            }],
            &[TxOut::new(
                Zatoshis::const_from_u64(40000),
                Script::default(),
            )],
            &sapling_fees::EmptyBundleView,
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
                if available == Zatoshis::const_from_u64(50100)
                   && required == Zatoshis::const_from_u64(55000)
        );
    }

    #[test]
    #[cfg(feature = "transparent-inputs")]
    fn transparent_change_allows_dust() {
        let change_strategy = SingleOutputChangeStrategy::new(
            Zip317FeeRule::standard(),
            None,
            ShieldedPool::Sapling,
            DustOutputPolicy::new(
                DustAction::AllowDustChange,
                Some(Zatoshis::const_from_u64(1000)),
            ),
        )
        .with_transparent_change_policy(TransparentChangePolicy::TransparentChangeAllowed);

        // Spend a single transparent UTXO that results in a 100-zat transparent change
        // output; the `AllowDustChange` policy permits emitting it even though it is below
        // the 1000-zat dust threshold.
        let result = change_strategy.compute_balance::<_, Infallible>(
            &Network::TestNetwork,
            Network::TestNetwork
                .activation_height(NetworkUpgrade::Nu5)
                .unwrap()
                .into(),
            BlockHeight::from_u32(1),
            &PoolMigrationParams::new(AnchorRetentionInterval::ZIP_318),
            &[TestTransparentInput {
                outpoint: OutPoint::fake(),
                coin: TxOut::new(
                    Zatoshis::const_from_u64(50100),
                    TransparentAddress::PublicKeyHash([0u8; 20]).script().into(),
                ),
            }],
            &[TxOut::new(
                Zatoshis::const_from_u64(40000),
                Script::default(),
            )],
            &sapling_fees::EmptyBundleView,
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
                balance.proposed_change() == [ChangeValue::transparent(Zatoshis::const_from_u64(100))] &&
                balance.fee_required() == Zatoshis::const_from_u64(10000)
        );
    }

    #[test]
    #[cfg(feature = "transparent-inputs")]
    fn transparent_change_dust_added_to_fee() {
        let change_strategy = SingleOutputChangeStrategy::new(
            Zip317FeeRule::standard(),
            None,
            ShieldedPool::Sapling,
            DustOutputPolicy::new(DustAction::AddDustToFee, None),
        )
        .with_transparent_change_policy(TransparentChangePolicy::TransparentChangeAllowed);

        // Spend a single transparent UTXO that would result in a 100-zat transparent change
        // output; under the `AddDustToFee` policy the dust value is instead added to the
        // fee and no change output is produced.
        let result = change_strategy.compute_balance::<_, Infallible>(
            &Network::TestNetwork,
            Network::TestNetwork
                .activation_height(NetworkUpgrade::Nu5)
                .unwrap()
                .into(),
            BlockHeight::from_u32(1),
            &PoolMigrationParams::new(AnchorRetentionInterval::ZIP_318),
            &[TestTransparentInput {
                outpoint: OutPoint::fake(),
                coin: TxOut::new(
                    Zatoshis::const_from_u64(50100),
                    TransparentAddress::PublicKeyHash([0u8; 20]).script().into(),
                ),
            }],
            &[TxOut::new(
                Zatoshis::const_from_u64(40000),
                Script::default(),
            )],
            &sapling_fees::EmptyBundleView,
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
                balance.proposed_change().is_empty() &&
                balance.fee_required() == Zatoshis::const_from_u64(10100)
        );
    }

    #[test]
    fn change_with_allowable_dust_implicitly_allowing_zero_change() {
        change_with_allowable_dust(DustOutputPolicy::default())
    }

    #[test]
    fn change_with_allowable_dust_explicitly_allowing_zero_change() {
        change_with_allowable_dust(DustOutputPolicy::new(
            DustAction::AllowDustChange,
            Some(Zatoshis::ZERO),
        ))
    }

    fn change_with_allowable_dust(dust_output_policy: DustOutputPolicy) {
        let change_strategy = SingleOutputChangeStrategy::new(
            Zip317FeeRule::standard(),
            None,
            ShieldedPool::Sapling,
            dust_output_policy,
        );

        // Spend two Sapling notes, one of them dust. There is sufficient to
        // pay the fee: if only one note is spent then we are 1000 short, but
        // if both notes are spent then the fee stays at 10000 (even with a
        // zero-valued change output), so we have just enough.
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
                        value: Zatoshis::const_from_u64(49000),
                    },
                    TestSaplingInput {
                        note_id: 1,
                        value: Zatoshis::const_from_u64(1000),
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
            Ok(balance) if
                balance.proposed_change() == [ChangeValue::sapling(Zatoshis::ZERO, None)] &&
                balance.fee_required() == Zatoshis::const_from_u64(10000)
        );
    }

    #[test]
    fn change_with_disallowed_dust() {
        let change_strategy = SingleOutputChangeStrategy::new(
            Zip317FeeRule::standard(),
            None,
            ShieldedPool::Sapling,
            DustOutputPolicy::default(),
        );

        // Attempt to spend three Sapling notes, one of them dust. Adding the third
        // note increases the number of actions, and so it is uneconomic to spend it.
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
                        value: Zatoshis::const_from_u64(29000),
                    },
                    TestSaplingInput {
                        note_id: 1,
                        value: Zatoshis::const_from_u64(20000),
                    },
                    TestSaplingInput {
                        note_id: 2,
                        value: Zatoshis::const_from_u64(1000),
                    },
                ][..],
                &[SaplingPayment::new(Zatoshis::const_from_u64(30000))][..],
            ),
            #[cfg(feature = "orchard")]
            &orchard_fees::EmptyBundleView,
            #[cfg(feature = "orchard")]
            &orchard_fees::EmptyBundleView,
            None,
            &SplitPlan::SingleOutput,
        );

        // We will get an error here, because the dust input isn't free to add
        // to the transaction.
        assert_matches!(
            result,
            Err(ChangeError::DustInputs { sapling, .. }) if sapling == vec![2]
        );
    }

    /// Sapling is never the most recent shielded pool, so a plan that would split change five
    /// ways still returns a single Sapling change output.
    #[test]
    fn sapling_change_is_not_split() {
        let change_strategy = MultiOutputChangeStrategy::new(
            Zip317FeeRule::standard(),
            None,
            ShieldedPool::Sapling,
            DustOutputPolicy::default(),
        );
        let balance = change_strategy.compute_balance(
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
                    value: Zatoshis::const_from_u64(750_0000),
                }][..],
                &[SaplingPayment::new(Zatoshis::const_from_u64(100_0000))][..],
            ),
            #[cfg(feature = "orchard")]
            &orchard_fees::EmptyBundleView,
            #[cfg(feature = "orchard")]
            &orchard_fees::EmptyBundleView,
            None,
            &SplitPlan::new(vec![Zatoshis::const_from_u64(100_0000); 5]),
        );
        // One spend, two outputs: the two-action floor, 10_000 zatoshis of fee.
        assert_matches!(
            balance,
            Ok(balance) if
                balance.proposed_change() == [ChangeValue::sapling(Zatoshis::const_from_u64(649_0000), None)] &&
                balance.fee_required() == Zatoshis::const_from_u64(10000)
        );
    }

    /// After NU6.3 the turnstile lets an Orchard spend return change to Orchard, but Orchard is no
    /// longer the most recent pool, so that change is a single output; the same plan still splits
    /// change that lands in Ironwood.
    #[test]
    #[cfg(feature = "orchard")]
    fn only_ironwood_change_is_split_after_nu6_3() {
        let change_strategy = MultiOutputChangeStrategy::new(
            Zip317FeeRule::standard(),
            None,
            ShieldedPool::Ironwood,
            DustOutputPolicy::default(),
        );
        // The height at which every upgrade through NU6.2 activates on the network below.
        const PRE_NU6_3_ACTIVATION: BlockHeight = BlockHeight::from_u32(100_000);
        // The height at which NU6.3 activates on the network below.
        const NU6_3_ACTIVATION: BlockHeight = BlockHeight::from_u32(200_000);
        let network = LocalNetwork {
            overwinter: Some(BlockHeight::from_u32(1)),
            sapling: Some(PRE_NU6_3_ACTIVATION),
            blossom: Some(PRE_NU6_3_ACTIVATION),
            heartwood: Some(PRE_NU6_3_ACTIVATION),
            canopy: Some(PRE_NU6_3_ACTIVATION),
            nu5: Some(PRE_NU6_3_ACTIVATION),
            nu6: Some(NU6_3_ACTIVATION),
            nu6_1: Some(NU6_3_ACTIVATION),
            nu6_2: Some(NU6_3_ACTIVATION),
            nu6_3: Some(NU6_3_ACTIVATION),
            #[cfg(zcash_unstable = "nu7")]
            nu7: None,
            #[cfg(zcash_unstable = "nutachyon")]
            nu_tachyon: None,
        };
        let post_nu6_3_height: TargetHeight = network
            .activation_height(NetworkUpgrade::Nu6_3)
            .expect("NU6.3 activates on this network")
            .into();
        let split_plan = SplitPlan::new(vec![Zatoshis::const_from_u64(100_0000); 5]);
        let payment = [OrchardPayment::new(Zatoshis::const_from_u64(100_0000))];
        let balance_for = |orchard_inputs: &[TestOrchardInput],
                           ironwood_inputs: &[TestOrchardInput]| {
            change_strategy.compute_balance::<_, u32>(
                &network,
                post_nu6_3_height,
                BlockHeight::from_u32(1),
                &PoolMigrationParams::new(AnchorRetentionInterval::ZIP_318),
                &[] as &[TestTransparentInput],
                &[] as &[TxOut],
                &sapling_fees::EmptyBundleView,
                &(
                    ::orchard::bundle::BundleVersion::orchard_v3(),
                    orchard_inputs,
                    &[] as &[OrchardPayment],
                ),
                &(
                    ::orchard::bundle::BundleVersion::ironwood_v3(),
                    ironwood_inputs,
                    &payment[..],
                ),
                None,
                &split_plan,
            )
        };
        let note = [TestOrchardInput {
            note_id: 0,
            value: Zatoshis::const_from_u64(750_0000),
        }];

        // Orchard-funded: change is strictly less than the input, so it may return to Orchard,
        // and it does so as one output.
        let orchard_funded = balance_for(&note, &[]).unwrap();
        assert_eq!(orchard_funded.proposed_change().len(), 1);
        assert_eq!(
            orchard_funded.proposed_change()[0].output_pool(),
            PoolType::ORCHARD
        );

        // Ironwood-funded: the most recent pool, so the five-way split applies.
        let ironwood_funded = balance_for(&[], &note).unwrap();
        assert_eq!(ironwood_funded.proposed_change().len(), 5);
        assert!(
            ironwood_funded
                .proposed_change()
                .iter()
                .all(|change| change.output_pool() == PoolType::IRONWOOD)
        );
    }
}
