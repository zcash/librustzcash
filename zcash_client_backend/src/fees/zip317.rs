//! Change strategies designed to implement the ZIP 317 fee rules.
//!
//! Change selection in ZIP 317 requires careful handling of low-valued inputs
//! to ensure that inputs added to a transaction do not cause fees to rise by
//! an amount greater than their value.

use core::marker::PhantomData;

use zcash_primitives::transaction::fees::{FeeRule, transparent, zip317 as prim_zip317};
use zcash_protocol::{
    ShieldedPool,
    consensus::{self, BlockHeight},
    memo::MemoBytes,
    value::{BalanceError, Zatoshis},
};

use crate::{
    data_api::{
        AccountMeta, ChangeReceivers, InputSource, NoteFilter,
        anchor_retention::PoolMigrationParams,
        wallet::{
            TargetHeight,
            input_selection::{LockFilter, LockedInputPolicy},
        },
    },
    fees::StandardFeeRule,
};

use super::{
    ChangeError, ChangeStrategy, DustOutputPolicy, EphemeralBalance, MetaSource, SplitPolicy,
    TransactionBalance,
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
    /// Returns the ZIP 317 marginal fee in effect for a transaction expected to be mined at
    /// `target_height`.
    fn marginal_fee<P: consensus::Parameters>(
        &self,
        params: &P,
        target_height: BlockHeight,
    ) -> Zatoshis;

    /// Returns the ZIP 317 number of grace actions
    fn grace_actions(&self) -> usize;
}

impl Zip317FeeRule for prim_zip317::FeeRule {
    fn marginal_fee<P: consensus::Parameters>(
        &self,
        params: &P,
        target_height: BlockHeight,
    ) -> Zatoshis {
        prim_zip317::FeeRule::marginal_fee(self, params, target_height)
    }

    fn grace_actions(&self) -> usize {
        self.grace_actions()
    }
}

impl Zip317FeeRule for StandardFeeRule {
    fn marginal_fee<P: consensus::Parameters>(
        &self,
        params: &P,
        target_height: BlockHeight,
    ) -> Zatoshis {
        prim_zip317::marginal_fee(params, target_height)
    }

    fn grace_actions(&self) -> usize {
        prim_zip317::FeeRule::standard().grace_actions()
    }
}

/// A change strategy that proposes change as a single output. The output pool is chosen
/// as the most current pool that avoids unnecessary pool-crossing (with a specified
/// fallback when the transaction has no shielded inputs). Fee calculation is delegated
/// to the provided fee rule.
pub struct SingleOutputChangeStrategy<R, I> {
    fee_rule: R,
    change_memo: Option<MemoBytes>,
    fallback_change_pool: ShieldedPool,
    dust_output_policy: DustOutputPolicy,
    #[cfg(feature = "transparent-inputs")]
    transparent_change_policy: TransparentChangePolicy,
    meta_source: PhantomData<I>,
}

impl<R, I> SingleOutputChangeStrategy<R, I> {
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
            meta_source: PhantomData,
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

impl<R, I> ChangeStrategy for SingleOutputChangeStrategy<R, I>
where
    R: Zip317FeeRule + Clone,
    I: MetaSource,
    <R as FeeRule>::Error: From<BalanceError>,
{
    type FeeRule = R;
    type Error = <R as FeeRule>::Error;
    type MetaSource = I;
    type AccountMetaT = ChangeReceivers;

    fn fee_rule(&self) -> &Self::FeeRule {
        &self.fee_rule
    }

    fn fetch_wallet_meta(
        &self,
        meta_source: &Self::MetaSource,
        account: <Self::MetaSource as MetaSource>::AccountId,
        _target_height: TargetHeight,
        _exclude: &[<Self::MetaSource as MetaSource>::NoteRef],
    ) -> Result<Self::AccountMetaT, <Self::MetaSource as MetaSource>::Error> {
        meta_source.change_receivers(account)
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
        wallet_meta: &Self::AccountMetaT,
    ) -> Result<TransactionBalance, ChangeError<Self::Error, NoteRefT>> {
        let split_policy = SplitPolicy::single_output();
        let marginal_fee = self.fee_rule.marginal_fee(params, target_height.into());
        let cfg = SinglePoolBalanceConfig::new(
            params,
            &self.fee_rule,
            &self.dust_output_policy,
            marginal_fee,
            &split_policy,
            self.fallback_change_pool,
            #[cfg(feature = "transparent-inputs")]
            self.transparent_change_policy,
            marginal_fee,
            self.fee_rule.grace_actions(),
        );

        single_pool_output_balance(
            cfg,
            None,
            wallet_meta,
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

/// A change strategy that attempts to split the change value into some number of equal-sized notes
/// as dictated by the included [`SplitPolicy`] value.
pub struct MultiOutputChangeStrategy<R, I> {
    fee_rule: R,
    change_memo: Option<MemoBytes>,
    fallback_change_pool: ShieldedPool,
    dust_output_policy: DustOutputPolicy,
    split_policy: SplitPolicy,
    #[cfg(feature = "transparent-inputs")]
    transparent_change_policy: TransparentChangePolicy,
    meta_source: PhantomData<I>,
}

impl<R, I> MultiOutputChangeStrategy<R, I> {
    /// Constructs a new [`MultiOutputChangeStrategy`] with the specified ZIP 317
    /// fee parameters, change memo, and change splitting policy.
    ///
    /// This change strategy will fall back to creating a single change output if insufficient
    /// change value is available to create notes with at least the minimum value dictated by the
    /// split policy.
    ///
    /// - `fallback_change_pool`: the pool to which change will be sent if when more than one
    ///   shielded pool is enabled via feature flags, and the transaction has no shielded inputs.
    /// - `split_policy`: A policy value describing how the change value should be returned as
    ///   multiple notes.
    pub fn new(
        fee_rule: R,
        change_memo: Option<MemoBytes>,
        fallback_change_pool: ShieldedPool,
        dust_output_policy: DustOutputPolicy,
        split_policy: SplitPolicy,
    ) -> Self {
        Self {
            fee_rule,
            change_memo,
            fallback_change_pool,
            dust_output_policy,
            split_policy,
            #[cfg(feature = "transparent-inputs")]
            transparent_change_policy: TransparentChangePolicy::ShieldChange,
            meta_source: PhantomData,
        }
    }

    /// Sets the [`TransparentChangePolicy`] to be used by this change strategy, determining
    /// whether change may be returned to the transparent pool when the flows of the transaction
    /// under construction are fully transparent.
    ///
    /// The default is [`TransparentChangePolicy::ShieldChange`]. This policy has no effect on
    /// transactions that involve any shielded flows. When transparent change is produced, it is
    /// always emitted as a single output; the [`SplitPolicy`] configured for this strategy applies
    /// only to shielded change.
    #[cfg(feature = "transparent-inputs")]
    pub fn with_transparent_change_policy(
        mut self,
        transparent_change_policy: TransparentChangePolicy,
    ) -> Self {
        self.transparent_change_policy = transparent_change_policy;
        self
    }
}

impl<R, I> ChangeStrategy for MultiOutputChangeStrategy<R, I>
where
    R: Zip317FeeRule + Clone,
    I: InputSource,
    <R as FeeRule>::Error: From<BalanceError>,
{
    type FeeRule = R;
    type Error = <R as FeeRule>::Error;
    type MetaSource = I;
    type AccountMetaT = AccountMeta;

    fn fee_rule(&self) -> &Self::FeeRule {
        &self.fee_rule
    }

    fn fetch_wallet_meta(
        &self,
        meta_source: &Self::MetaSource,
        account: <Self::MetaSource as InputSource>::AccountId,
        target_height: TargetHeight,
        exclude: &[<Self::MetaSource as InputSource>::NoteRef],
    ) -> Result<Self::AccountMetaT, <Self::MetaSource as InputSource>::Error> {
        let note_selector = NoteFilter::ExceedsMinValue(
            self.split_policy
                .min_split_output_value()
                .unwrap_or(SplitPolicy::MIN_NOTE_VALUE),
        );

        // Account metadata feeds change-splitting decisions, which reason about the
        // notes that selection can actually draw on; locked notes are excluded from
        // selection, so they are excluded here as well.
        meta_source.get_account_metadata(
            account,
            &note_selector,
            target_height,
            exclude,
            LockFilter::Policy(&LockedInputPolicy::Exclude),
        )
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
        wallet_meta: &Self::AccountMetaT,
    ) -> Result<TransactionBalance, ChangeError<Self::Error, NoteRefT>> {
        let marginal_fee = self.fee_rule.marginal_fee(params, target_height.into());
        let cfg = SinglePoolBalanceConfig::new(
            params,
            &self.fee_rule,
            &self.dust_output_policy,
            marginal_fee,
            &self.split_policy,
            self.fallback_change_pool,
            #[cfg(feature = "transparent-inputs")]
            self.transparent_change_policy,
            marginal_fee,
            self.fee_rule.grace_actions(),
        );

        single_pool_output_balance(
            cfg,
            Some(wallet_meta),
            wallet_meta.change_receivers(),
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
    use crate::fees::tests::all_change_receivers;
    // `sapling_fees` is named by both the orchard and the transparent-inputs tests.
    #[cfg(any(feature = "orchard", feature = "transparent-inputs"))]
    use crate::fees::sapling as sapling_fees;

    #[cfg(feature = "transparent-inputs")]
    use {
        crate::{
            data_api::TransparentChangeKind,
            fees::{EphemeralBalance, TransparentChangePolicy},
        },
        ::transparent::{address::TransparentAddress, bundle::OutPoint},
        zcash_primitives::transaction::fees::zip317::MINIMUM_FEE,
    };

    #[cfg(feature = "orchard")]
    use {
        crate::{
            data_api::wallet::{TargetHeight, input_selection::OrchardPayment},
            fees::{canonical_crossing_fee, orchard as orchard_fees, tests::TestOrchardInput},
        },
        zcash_protocol::zip318::{AnchorBucketInterval, MAX_RESIDUAL_VALUE},
    };

    use crate::{
        data_api::{
            AccountMeta, ChangeReceivers, PoolMeta,
            anchor_retention::{AnchorRetentionInterval, PoolMigrationParams},
            testing::MockWalletDb,
            wallet::input_selection::SaplingPayment,
        },
        fees::{
            ChangeError, ChangeStrategy, ChangeValue, DustAction, DustOutputPolicy, SplitPolicy,
            TransactionBalance,
            common::DUST_TO_FEE_CAP_MINIMUM_FEES,
            tests::{TestSaplingInput, TestTransparentInput},
            zip317::MultiOutputChangeStrategy,
        },
    };
    use core::{convert::Infallible, num::NonZeroUsize};
    use zcash_protocol::{
        PoolType, ShieldedPool,
        consensus::{BlockHeight, Network, NetworkUpgrade, Parameters},
        value::Zatoshis,
    };

    use ::transparent::{address::Script, bundle::TxOut};
    use zcash_primitives::transaction::fees::zip317::{
        FeeError as Zip317FeeError, FeeRule as Zip317FeeRule, MAINNET_FEE_REDUCTION_HEIGHT,
        marginal_fee, minimum_fee,
    };

    use super::SingleOutputChangeStrategy;

    #[test]
    fn change_without_dust() {
        let change_strategy = SingleOutputChangeStrategy::<_, MockWalletDb>::new(
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
            &PoolMigrationParams::new(
                zcash_protocol::zip318::BlockSpacing::UNIFORM,
                AnchorRetentionInterval::ZIP_318,
            ),
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
            &all_change_receivers(),
        );

        assert_matches!(
            result,
            Ok(balance) if
                balance.proposed_change() == [ChangeValue::sapling(Zatoshis::const_from_u64(5000), None)] &&
                balance.fee_required() == Zatoshis::const_from_u64(10000)
        );
    }

    #[test]
    fn change_without_dust_multi() {
        let change_strategy = MultiOutputChangeStrategy::<_, MockWalletDb>::new(
            Zip317FeeRule::standard(),
            None,
            ShieldedPool::Sapling,
            DustOutputPolicy::default(),
            SplitPolicy::with_min_output_value(
                NonZeroUsize::new(5).unwrap(),
                Zatoshis::const_from_u64(100_0000),
            ),
        );

        {
            // spend a single Sapling note and produce 5 outputs
            let balance = |existing_notes, total| {
                change_strategy.compute_balance(
                    &Network::TestNetwork,
                    Network::TestNetwork
                        .activation_height(NetworkUpgrade::Nu5)
                        .unwrap()
                        .into(),
                    BlockHeight::from_u32(1),
                    &PoolMigrationParams::new(
                        zcash_protocol::zip318::BlockSpacing::UNIFORM,
                        AnchorRetentionInterval::ZIP_318,
                    ),
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
                    &AccountMeta::new(
                        Some(PoolMeta::new(existing_notes, total)),
                        None,
                        None,
                        all_change_receivers(),
                    ),
                )
            };

            assert_matches!(
                balance(0, Zatoshis::ZERO),
                Ok(balance) if
                    balance.proposed_change() == [
                        ChangeValue::sapling(Zatoshis::const_from_u64(129_4000), None),
                        ChangeValue::sapling(Zatoshis::const_from_u64(129_4000), None),
                        ChangeValue::sapling(Zatoshis::const_from_u64(129_4000), None),
                        ChangeValue::sapling(Zatoshis::const_from_u64(129_4000), None),
                        ChangeValue::sapling(Zatoshis::const_from_u64(129_4000), None),
                    ] &&
                    balance.fee_required() == Zatoshis::const_from_u64(30000)
            );

            assert_matches!(
                balance(2, Zatoshis::const_from_u64(100_0000)),
                Ok(balance) if
                    balance.proposed_change() == [
                        ChangeValue::sapling(Zatoshis::const_from_u64(216_0000), None),
                        ChangeValue::sapling(Zatoshis::const_from_u64(216_0000), None),
                        ChangeValue::sapling(Zatoshis::const_from_u64(216_0000), None),
                    ] &&
                    balance.fee_required() == Zatoshis::const_from_u64(20000)
            );
        }

        {
            // spend a single Sapling note and produce 4 outputs, as the value of the note isn't
            // sufficient to produce 5
            let result = change_strategy.compute_balance(
                &Network::TestNetwork,
                Network::TestNetwork
                    .activation_height(NetworkUpgrade::Nu5)
                    .unwrap()
                    .into(),
                BlockHeight::from_u32(1),
                &PoolMigrationParams::new(
                    zcash_protocol::zip318::BlockSpacing::UNIFORM,
                    AnchorRetentionInterval::ZIP_318,
                ),
                &[] as &[TestTransparentInput],
                &[] as &[TxOut],
                &(
                    sapling::builder::BundleType::DEFAULT,
                    &[TestSaplingInput {
                        note_id: 0,
                        value: Zatoshis::const_from_u64(600_0000),
                    }][..],
                    &[SaplingPayment::new(Zatoshis::const_from_u64(100_0000))][..],
                ),
                #[cfg(feature = "orchard")]
                &orchard_fees::EmptyBundleView,
                #[cfg(feature = "orchard")]
                &orchard_fees::EmptyBundleView,
                None,
                &AccountMeta::new(
                    Some(PoolMeta::new(0, Zatoshis::ZERO)),
                    Some(PoolMeta::new(0, Zatoshis::ZERO)),
                    None,
                    all_change_receivers(),
                ),
            );

            assert_matches!(
                result,
                Ok(balance) if
                    balance.proposed_change() == [
                        ChangeValue::sapling(Zatoshis::const_from_u64(124_3750), None),
                        ChangeValue::sapling(Zatoshis::const_from_u64(124_3750), None),
                        ChangeValue::sapling(Zatoshis::const_from_u64(124_3750), None),
                        ChangeValue::sapling(Zatoshis::const_from_u64(124_3750), None),
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
                &PoolMigrationParams::new(
                    zcash_protocol::zip318::BlockSpacing::UNIFORM,
                    AnchorRetentionInterval::ZIP_318,
                ),
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
                // after excluding the inputs we're spending, we have no notes in the wallet
                &AccountMeta::new(
                    Some(PoolMeta::new(0, Zatoshis::ZERO)),
                    Some(PoolMeta::new(0, Zatoshis::ZERO)),
                    None,
                    all_change_receivers(),
                ),
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
                &PoolMigrationParams::new(
                    zcash_protocol::zip318::BlockSpacing::UNIFORM,
                    AnchorRetentionInterval::ZIP_318,
                ),
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
                // after excluding the inputs we're spending, we have no notes in the wallet
                &AccountMeta::new(
                    Some(PoolMeta::new(0, Zatoshis::ZERO)),
                    Some(PoolMeta::new(0, Zatoshis::ZERO)),
                    None,
                    all_change_receivers(),
                ),
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
                &PoolMigrationParams::new(
                    zcash_protocol::zip318::BlockSpacing::UNIFORM,
                    AnchorRetentionInterval::ZIP_318,
                ),
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
                // after excluding the inputs we're spending, we have no notes in the wallet
                &AccountMeta::new(
                    Some(PoolMeta::new(0, Zatoshis::ZERO)),
                    Some(PoolMeta::new(0, Zatoshis::ZERO)),
                    None,
                    all_change_receivers(),
                ),
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
        let change_strategy = SingleOutputChangeStrategy::<_, MockWalletDb>::new(
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
            &PoolMigrationParams::new(
                zcash_protocol::zip318::BlockSpacing::UNIFORM,
                AnchorRetentionInterval::ZIP_318,
            ),
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
            &all_change_receivers(),
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
        let change_strategy = SingleOutputChangeStrategy::<_, MockWalletDb>::new(
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
            &PoolMigrationParams::new(
                zcash_protocol::zip318::BlockSpacing::UNIFORM,
                AnchorRetentionInterval::ZIP_318,
            ),
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
            &all_change_receivers(),
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
        let change_strategy = MultiOutputChangeStrategy::<_, MockWalletDb>::new(
            Zip317FeeRule::standard(),
            None,
            ShieldedPool::Orchard,
            DustOutputPolicy::default(),
            SplitPolicy::with_min_output_value(
                NonZeroUsize::new(2).unwrap(),
                Zatoshis::const_from_u64(100_0000),
            ),
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

        // No note counts are known for the account, so the split policy proposes a single
        // change output: the assertions below are about the pool it lands in, not the split.
        let wallet_meta = AccountMeta::new(None, None, None, all_change_receivers());

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
            &PoolMigrationParams::new(
                zcash_protocol::zip318::BlockSpacing::UNIFORM,
                AnchorRetentionInterval::ZIP_318,
            ),
            &transparent_inputs,
            &transparent_outputs,
            &sapling_view,
            &pre_nu6_3_orchard_view,
            &ironwood_view,
            ephemeral_balance,
            &wallet_meta,
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
            &PoolMigrationParams::new(
                zcash_protocol::zip318::BlockSpacing::UNIFORM,
                AnchorRetentionInterval::ZIP_318,
            ),
            &transparent_inputs,
            &transparent_outputs,
            &sapling_view,
            &post_nu6_3_orchard_view,
            &ironwood_view,
            ephemeral_balance,
            &wallet_meta,
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
        let change_strategy = SingleOutputChangeStrategy::<_, MockWalletDb>::new(
            Zip317FeeRule::standard(),
            None,
            ShieldedPool::Orchard,
            DustOutputPolicy::default(),
        );
        let zip318 = PoolMigrationParams::new(
            zcash_protocol::zip318::BlockSpacing::UNIFORM,
            AnchorRetentionInterval::ZIP_318,
        );
        let interval = AnchorBucketInterval::ZIP_318;

        // An anchor ON the grid, as a canonical crossing requires.
        let anchor = zcash_protocol::zip318::AnchorGrid::new(
            interval,
            zcash_protocol::zip318::BlockSpacing::UNIFORM,
        )
        .boundary_at_or_below(BlockHeight::from_u32(2_000_000));
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
                    &all_change_receivers(),
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

    /// A canonical crossing whose note leaves dust over the canonical fee in effect at the target
    /// height keeps the canonical shape and fee under `AllowDustChange`, with the dust as its one
    /// Orchard change output; the default policy rejects that change.
    #[test]
    #[cfg(feature = "orchard")]
    fn canonical_crossing_keeps_dust_change_under_allow_dust_change() {
        /// Change below the marginal fee on both sides of the fee reduction height.
        const DUST_CHANGE: Zatoshis = Zatoshis::const_from_u64(500);

        let net = Network::MainNetwork;
        let zip318 = PoolMigrationParams::new(
            zcash_protocol::zip318::BlockSpacing::UNIFORM,
            AnchorRetentionInterval::ZIP_318,
        );
        let sapling_view = (
            sapling::builder::BundleType::DEFAULT,
            &[] as &[Infallible],
            &[] as &[Infallible],
        );
        let ironwood_outputs = [OrchardPayment::new(MAX_RESIDUAL_VALUE)];
        let ironwood_view = (
            ::orchard::bundle::BundleVersion::ironwood_v3(),
            &[] as &[Infallible],
            &ironwood_outputs[..],
        );
        let strategy = |dust_output_policy| {
            SingleOutputChangeStrategy::<_, MockWalletDb>::new(
                Zip317FeeRule::standard(),
                None,
                ShieldedPool::Orchard,
                dust_output_policy,
            )
        };

        for target_height in [
            MAINNET_FEE_REDUCTION_HEIGHT - 1,
            MAINNET_FEE_REDUCTION_HEIGHT,
        ] {
            assert!(DUST_CHANGE < marginal_fee(&net, target_height));
            let canonical_fee = canonical_crossing_fee(&net, target_height)
                .expect("the canonical shape is a valid input to the ZIP 317 rule");
            let anchor = zcash_protocol::zip318::AnchorGrid::new(
                AnchorBucketInterval::ZIP_318,
                zcash_protocol::zip318::BlockSpacing::UNIFORM,
            )
            .boundary_at_or_below(target_height - 1);
            let orchard_inputs = [TestOrchardInput {
                note_id: 0,
                value: (MAX_RESIDUAL_VALUE + canonical_fee)
                    .and_then(|v| v + DUST_CHANGE)
                    .unwrap(),
            }];
            let orchard_view = (
                ::orchard::bundle::BundleVersion::orchard_v3(),
                &orchard_inputs[..],
                &[] as &[Infallible],
            );
            let balance_under = |dust_output_policy| {
                strategy(dust_output_policy).compute_balance::<_, u32>(
                    &net,
                    target_height.into(),
                    anchor,
                    &zip318,
                    &[] as &[TestTransparentInput],
                    &[] as &[TxOut],
                    &sapling_view,
                    &orchard_view,
                    &ironwood_view,
                    None,
                    &all_change_receivers(),
                )
            };

            assert_matches!(
                balance_under(DustOutputPolicy::default()),
                Err(ChangeError::InsufficientFunds { .. }),
                "change of {DUST_CHANGE:?} at {target_height:?} should be dust",
            );
            assert_matches!(
                balance_under(DustOutputPolicy::new(DustAction::AllowDustChange, None)),
                Ok(balance) if
                    balance.proposed_change() == [ChangeValue::orchard(DUST_CHANGE, None)] &&
                    balance.fee_required() == canonical_fee &&
                    balance.dummy_outputs().is_some_and(|d| d.ironwood() == 0),
                "at {target_height:?} the crossing should stay canonical with dust change",
            );
        }
    }

    #[test]
    #[cfg(feature = "orchard")]
    fn ironwood_outputs_are_charged_actions() {
        // V6 transactions carry a separate Ironwood bundle, so a populated
        // Ironwood view must contribute its own actions to the fee rather than
        // being treated as zero. Compare two otherwise-identical balances that
        // differ only by the presence of an Ironwood output.
        let change_strategy = SingleOutputChangeStrategy::<_, MockWalletDb>::new(
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
                &PoolMigrationParams::new(
                    zcash_protocol::zip318::BlockSpacing::UNIFORM,
                    AnchorRetentionInterval::ZIP_318,
                ),
                &[] as &[TestTransparentInput],
                &[] as &[TxOut],
                &sapling_view,
                &orchard_view,
                &orchard_fees::EmptyBundleView,
                None,
                &all_change_receivers(),
            )
            .unwrap();

        let with_ironwood = change_strategy
            .compute_balance(
                &Network::TestNetwork,
                height,
                BlockHeight::from_u32(1),
                &PoolMigrationParams::new(
                    zcash_protocol::zip318::BlockSpacing::UNIFORM,
                    AnchorRetentionInterval::ZIP_318,
                ),
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
                &all_change_receivers(),
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
        let change_strategy = SingleOutputChangeStrategy::<_, MockWalletDb>::new(
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
            &PoolMigrationParams::new(
                zcash_protocol::zip318::BlockSpacing::UNIFORM,
                AnchorRetentionInterval::ZIP_318,
            ),
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
            &all_change_receivers(),
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
        let change_strategy = SingleOutputChangeStrategy::<_, MockWalletDb>::new(
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
            &PoolMigrationParams::new(
                zcash_protocol::zip318::BlockSpacing::UNIFORM,
                AnchorRetentionInterval::ZIP_318,
            ),
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
            &all_change_receivers(),
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
        let change_strategy = SingleOutputChangeStrategy::<_, MockWalletDb>::new(
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
            &PoolMigrationParams::new(
                zcash_protocol::zip318::BlockSpacing::UNIFORM,
                AnchorRetentionInterval::ZIP_318,
            ),
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
            &all_change_receivers(),
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
        let change_strategy = SingleOutputChangeStrategy::<_, MockWalletDb>::new(
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
            &PoolMigrationParams::new(
                zcash_protocol::zip318::BlockSpacing::UNIFORM,
                AnchorRetentionInterval::ZIP_318,
            ),
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
            &all_change_receivers(),
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
        let change_strategy = SingleOutputChangeStrategy::<_, MockWalletDb>::new(
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
            &PoolMigrationParams::new(
                zcash_protocol::zip318::BlockSpacing::UNIFORM,
                AnchorRetentionInterval::ZIP_318,
            ),
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
            &all_change_receivers(),
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
        let change_strategy = SingleOutputChangeStrategy::<_, MockWalletDb>::new(
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
            &PoolMigrationParams::new(
                zcash_protocol::zip318::BlockSpacing::UNIFORM,
                AnchorRetentionInterval::ZIP_318,
            ),
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
            &all_change_receivers(),
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
        let change_strategy = SingleOutputChangeStrategy::<_, MockWalletDb>::new(
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
            &PoolMigrationParams::new(
                zcash_protocol::zip318::BlockSpacing::UNIFORM,
                AnchorRetentionInterval::ZIP_318,
            ),
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
            &all_change_receivers(),
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
        let change_strategy = MultiOutputChangeStrategy::<_, MockWalletDb>::new(
            Zip317FeeRule::standard(),
            None,
            ShieldedPool::Sapling,
            DustOutputPolicy::default(),
            SplitPolicy::with_min_output_value(
                NonZeroUsize::new(5).unwrap(),
                Zatoshis::const_from_u64(100_0000),
            ),
        )
        .with_transparent_change_policy(TransparentChangePolicy::TransparentChangeAllowed);

        // Spend a single transparent UTXO with change value sufficient to produce five
        // split outputs under the split policy; because the change is returned to the
        // transparent pool, it must nevertheless be emitted as a single output.
        let result = change_strategy.compute_balance::<_, Infallible>(
            &Network::TestNetwork,
            Network::TestNetwork
                .activation_height(NetworkUpgrade::Nu5)
                .unwrap()
                .into(),
            BlockHeight::from_u32(1),
            &PoolMigrationParams::new(
                zcash_protocol::zip318::BlockSpacing::UNIFORM,
                AnchorRetentionInterval::ZIP_318,
            ),
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
            &AccountMeta::new(
                Some(PoolMeta::new(0, Zatoshis::ZERO)),
                None,
                None,
                all_change_receivers(),
            ),
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
        let change_strategy = SingleOutputChangeStrategy::<_, MockWalletDb>::new(
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
            &PoolMigrationParams::new(
                zcash_protocol::zip318::BlockSpacing::UNIFORM,
                AnchorRetentionInterval::ZIP_318,
            ),
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
            &all_change_receivers(),
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
        let change_strategy = SingleOutputChangeStrategy::<_, MockWalletDb>::new(
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
            &PoolMigrationParams::new(
                zcash_protocol::zip318::BlockSpacing::UNIFORM,
                AnchorRetentionInterval::ZIP_318,
            ),
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
            &all_change_receivers(),
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
        let change_strategy = SingleOutputChangeStrategy::<_, MockWalletDb>::new(
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
            &PoolMigrationParams::new(
                zcash_protocol::zip318::BlockSpacing::UNIFORM,
                AnchorRetentionInterval::ZIP_318,
            ),
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
            &all_change_receivers(),
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
        let change_strategy = SingleOutputChangeStrategy::<_, MockWalletDb>::new(
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
            &PoolMigrationParams::new(
                zcash_protocol::zip318::BlockSpacing::UNIFORM,
                AnchorRetentionInterval::ZIP_318,
            ),
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
            &all_change_receivers(),
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
        let change_strategy = SingleOutputChangeStrategy::<_, MockWalletDb>::new(
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
            &PoolMigrationParams::new(
                zcash_protocol::zip318::BlockSpacing::UNIFORM,
                AnchorRetentionInterval::ZIP_318,
            ),
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
            &all_change_receivers(),
        );

        // We will get an error here, because the dust input isn't free to add
        // to the transaction.
        assert_matches!(
            result,
            Err(ChangeError::DustInputs { sapling, .. }) if sapling == vec![2]
        );
    }

    /// Computes the balance of a Sapling-only transaction under `change_strategy` at
    /// `target_height` on Mainnet: `inputs` are the values of the notes spent, numbered in order,
    /// and `payment` the single Sapling payment.
    fn sapling_balance_at(
        change_strategy: &SingleOutputChangeStrategy<Zip317FeeRule, MockWalletDb>,
        target_height: BlockHeight,
        inputs: &[Zatoshis],
        payment: Zatoshis,
    ) -> Result<TransactionBalance, ChangeError<Zip317FeeError, u32>> {
        /// Sapling-only flows do not consult the anchor, so any height serves.
        const ANCHOR_HEIGHT: BlockHeight = BlockHeight::from_u32(1);

        let inputs: Vec<_> = inputs
            .iter()
            .enumerate()
            .map(|(note_id, value)| TestSaplingInput {
                note_id: u32::try_from(note_id).expect("a handful of notes"),
                value: *value,
            })
            .collect();
        change_strategy.compute_balance(
            &Network::MainNetwork,
            target_height.into(),
            ANCHOR_HEIGHT,
            &PoolMigrationParams::new(
                zcash_protocol::zip318::BlockSpacing::UNIFORM,
                AnchorRetentionInterval::ZIP_318,
            ),
            &[] as &[TestTransparentInput],
            &[] as &[TxOut],
            &(
                sapling::builder::BundleType::DEFAULT,
                &inputs[..],
                &[SaplingPayment::new(payment)][..],
            ),
            #[cfg(feature = "orchard")]
            &orchard_fees::EmptyBundleView,
            #[cfg(feature = "orchard")]
            &orchard_fees::EmptyBundleView,
            None,
            &all_change_receivers(),
        )
    }

    /// An input is uneconomic iff its value is at most the marginal fee in effect at the target
    /// height, and change is dust iff it is below that fee; both boundaries follow the ZIP 317
    /// schedule across `FEE_REDUCTION_HEIGHT`.
    #[test]
    fn uneconomic_inputs_and_dust_follow_marginal_fee_at_target_height() {
        /// Two notes that are never dust and together cover `FUNDED_PAYMENT`, so a third note
        /// is spent only if it is free to add.
        const FUNDING_NOTES: [Zatoshis; 2] = [
            Zatoshis::const_from_u64(29_000),
            Zatoshis::const_from_u64(20_000),
        ];
        /// The payment made from `FUNDING_NOTES` plus a candidate note.
        const FUNDED_PAYMENT: Zatoshis = Zatoshis::const_from_u64(30_000);
        /// The payment made from a single note when probing the change dust boundary.
        const SINGLE_NOTE_PAYMENT: Zatoshis = Zatoshis::const_from_u64(40_000);
        /// The index of the candidate note in `FUNDING_NOTES ++ [candidate]`.
        const CANDIDATE_NOTE_ID: u32 = 2;
        /// Logical actions in the single-note case: one spend, and a payment plus a change
        /// output; equal to the grace allowance, so the fee is the minimum fee.
        const SINGLE_NOTE_ACTIONS: usize = 2;
        /// Logical actions when the candidate note is spent alongside `FUNDING_NOTES`: three
        /// spends against two outputs.
        const THREE_NOTE_ACTIONS: usize = 3;

        let change_strategy = SingleOutputChangeStrategy::<_, MockWalletDb>::new(
            Zip317FeeRule::standard(),
            None,
            ShieldedPool::Sapling,
            DustOutputPolicy::default(),
        );
        let net = Network::MainNetwork;

        // The schedule itself is pinned by `zip317_rule_charges_fee_in_effect_at_target_height`.
        for target_height in [
            MAINNET_FEE_REDUCTION_HEIGHT - 1,
            MAINNET_FEE_REDUCTION_HEIGHT,
        ] {
            let marginal = marginal_fee(&net, target_height);
            let one_above = (marginal + Zatoshis::const_from_u64(1)).unwrap();
            let one_below = (marginal - Zatoshis::const_from_u64(1)).unwrap();

            // A third note worth exactly the marginal fee is uneconomic: spending it adds a
            // logical action that costs more than the note is worth.
            let funding_plus = |candidate| [FUNDING_NOTES[0], FUNDING_NOTES[1], candidate];
            assert_matches!(
                sapling_balance_at(
                    &change_strategy,
                    target_height,
                    &funding_plus(marginal),
                    FUNDED_PAYMENT,
                ),
                Err(ChangeError::DustInputs { sapling, .. }) if sapling == vec![CANDIDATE_NOTE_ID],
                "input of {marginal:?} at {target_height:?} should be uneconomic",
            );

            // One zatoshi more and it is spent, paying the marginal fee for its action.
            let three_note_fee = (marginal * THREE_NOTE_ACTIONS).unwrap();
            let three_note_in = (FUNDING_NOTES[0] + FUNDING_NOTES[1])
                .and_then(|v| v + one_above)
                .unwrap();
            let three_note_change = (three_note_in - FUNDED_PAYMENT)
                .and_then(|v| v - three_note_fee)
                .unwrap();
            assert_matches!(
                sapling_balance_at(
                    &change_strategy,
                    target_height,
                    &funding_plus(one_above),
                    FUNDED_PAYMENT,
                ),
                Ok(balance) if
                    balance.proposed_change() == [ChangeValue::sapling(three_note_change, None)] &&
                    balance.fee_required() == three_note_fee,
                "input of {one_above:?} at {target_height:?} should be economic",
            );

            // Change one zatoshi below the marginal fee is dust and rejected under the default
            // policy; change of exactly the marginal fee is kept.
            let single_note_fee = (marginal * SINGLE_NOTE_ACTIONS).unwrap();
            assert_eq!(single_note_fee, minimum_fee(&net, target_height));
            let note_leaving = |change| {
                (SINGLE_NOTE_PAYMENT + single_note_fee)
                    .and_then(|v| v + change)
                    .unwrap()
            };
            assert_matches!(
                sapling_balance_at(
                    &change_strategy,
                    target_height,
                    &[note_leaving(one_below)],
                    SINGLE_NOTE_PAYMENT,
                ),
                Err(ChangeError::InsufficientFunds { available, required })
                    if available == note_leaving(one_below) && required == note_leaving(marginal),
                "change of {one_below:?} at {target_height:?} should be dust",
            );
            assert_matches!(
                sapling_balance_at(
                    &change_strategy,
                    target_height,
                    &[note_leaving(marginal)],
                    SINGLE_NOTE_PAYMENT,
                ),
                Ok(balance) if
                    balance.proposed_change() == [ChangeValue::sapling(marginal, None)] &&
                    balance.fee_required() == single_note_fee,
                "change of {marginal:?} at {target_height:?} should be kept",
            );
        }
    }

    /// Under `DustAction::AddDustToFee`, dust is folded into the fee only up to ten times the
    /// minimum fee in effect at the target height; above that it is kept as a change output.
    #[test]
    fn add_dust_to_fee_cap_follows_minimum_fee() {
        /// The payment made from a single note.
        const PAYMENT: Zatoshis = Zatoshis::const_from_u64(40_000);
        /// A dust threshold above every change value probed, so that the cap alone decides.
        const DUST_THRESHOLD: Zatoshis = Zatoshis::const_from_u64(30_000);

        let change_strategy = SingleOutputChangeStrategy::<_, MockWalletDb>::new(
            Zip317FeeRule::standard(),
            None,
            ShieldedPool::Sapling,
            DustOutputPolicy::new(DustAction::AddDustToFee, Some(DUST_THRESHOLD)),
        );
        let net = Network::MainNetwork;
        let target_height = MAINNET_FEE_REDUCTION_HEIGHT;
        // One spend, a payment and a change output: the grace allowance, so the minimum fee.
        let fee = minimum_fee(&net, target_height);
        let cap = (fee * DUST_TO_FEE_CAP_MINIMUM_FEES).unwrap();
        assert_eq!(u64::from(cap), 20_000);
        let one_above_cap = (cap + Zatoshis::const_from_u64(1)).unwrap();
        let note_leaving = |change| (PAYMENT + fee).and_then(|v| v + change).unwrap();

        // Dust of exactly the cap is folded into the fee.
        assert_matches!(
            sapling_balance_at(
                &change_strategy,
                target_height,
                &[note_leaving(cap)],
                PAYMENT,
            ),
            Ok(balance) if
                balance.proposed_change().is_empty() &&
                balance.fee_required() == (fee + cap).unwrap()
        );

        // One zatoshi more and it is returned as change instead.
        assert_matches!(
            sapling_balance_at(
                &change_strategy,
                target_height,
                &[note_leaving(one_above_cap)],
                PAYMENT,
            ),
            Ok(balance) if
                balance.proposed_change() == [ChangeValue::sapling(one_above_cap, None)] &&
                balance.fee_required() == fee
        );

        // Below `FEE_REDUCTION_HEIGHT` the cap is 100 000, so the same dust is still folded.
        let before = MAINNET_FEE_REDUCTION_HEIGHT - 1;
        let fee_before = minimum_fee(&net, before);
        assert_eq!(
            u64::from((fee_before * DUST_TO_FEE_CAP_MINIMUM_FEES).unwrap()),
            100_000
        );
        assert_matches!(
            sapling_balance_at(
                &change_strategy,
                before,
                &[(PAYMENT + fee_before).and_then(|v| v + one_above_cap).unwrap()],
                PAYMENT,
            ),
            Ok(balance) if
                balance.proposed_change().is_empty() &&
                balance.fee_required() == (fee_before + one_above_cap).unwrap()
        );
    }

    #[test]
    #[cfg(feature = "orchard")]
    fn sapling_only_account_paying_orchard_gets_sapling_change() {
        let change_strategy = SingleOutputChangeStrategy::<_, MockWalletDb>::new(
            Zip317FeeRule::standard(),
            None,
            ShieldedPool::Orchard,
            DustOutputPolicy::default(),
        );

        // The account has no Orchard key, so the change from paying an Orchard recipient
        // goes to the Sapling pool that the transaction spends from.
        let result = change_strategy.compute_balance(
            &Network::TestNetwork,
            Network::TestNetwork
                .activation_height(NetworkUpgrade::Nu5)
                .unwrap()
                .into(),
            BlockHeight::from_u32(1),
            &PoolMigrationParams::new(
                zcash_protocol::zip318::BlockSpacing::UNIFORM,
                AnchorRetentionInterval::ZIP_318,
            ),
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
            &ChangeReceivers::new(
                true,
                false,
                #[cfg(feature = "transparent-inputs")]
                None,
            ),
        );

        assert_matches!(
            result,
            Ok(balance) if
                balance.proposed_change() == [ChangeValue::sapling(Zatoshis::const_from_u64(5000), None)] &&
                balance.fee_required() == Zatoshis::const_from_u64(20000)
        );
    }

    #[test]
    fn shielded_change_requires_a_shielded_receiver() {
        let change_strategy = SingleOutputChangeStrategy::<_, MockWalletDb>::new(
            Zip317FeeRule::standard(),
            None,
            ShieldedPool::Sapling,
            DustOutputPolicy::default(),
        );

        // An account with no shielded key cannot receive the change of a shielded spend.
        let result = change_strategy.compute_balance(
            &Network::TestNetwork,
            Network::TestNetwork
                .activation_height(NetworkUpgrade::Nu5)
                .unwrap()
                .into(),
            BlockHeight::from_u32(1),
            &PoolMigrationParams::new(
                zcash_protocol::zip318::BlockSpacing::UNIFORM,
                AnchorRetentionInterval::ZIP_318,
            ),
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
            &ChangeReceivers::new(
                false,
                false,
                #[cfg(feature = "transparent-inputs")]
                Some(TransparentChangeKind::P2pkh),
            ),
        );

        assert_matches!(
            result,
            Err(ChangeError::UnsupportedChangePool(pool)) if pool == PoolType::SAPLING
        );
    }

    #[test]
    #[cfg(feature = "transparent-inputs")]
    fn transparent_change_requires_a_transparent_receiver() {
        let change_strategy = SingleOutputChangeStrategy::<_, MockWalletDb>::new(
            Zip317FeeRule::standard(),
            None,
            ShieldedPool::Sapling,
            DustOutputPolicy::default(),
        )
        .with_transparent_change_policy(TransparentChangePolicy::TransparentChangeAllowed);

        // Transparent change is allowed, but the account has no transparent key.
        let result = change_strategy.compute_balance::<_, Infallible>(
            &Network::TestNetwork,
            Network::TestNetwork
                .activation_height(NetworkUpgrade::Nu5)
                .unwrap()
                .into(),
            BlockHeight::from_u32(1),
            &PoolMigrationParams::new(
                zcash_protocol::zip318::BlockSpacing::UNIFORM,
                AnchorRetentionInterval::ZIP_318,
            ),
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
            &ChangeReceivers::new(true, true, None),
        );

        assert_matches!(
            result,
            Err(ChangeError::UnsupportedChangePool(pool)) if pool == PoolType::TRANSPARENT
        );
    }

    #[test]
    #[cfg(feature = "transparent-inputs")]
    fn missing_transparent_receiver_does_not_hide_insufficient_funds() {
        /// The value of the transparent payment.
        const PAYMENT_VALUE: Zatoshis = Zatoshis::const_from_u64(40000);

        let change_strategy = SingleOutputChangeStrategy::<_, MockWalletDb>::new(
            Zip317FeeRule::standard(),
            None,
            ShieldedPool::Sapling,
            DustOutputPolicy::default(),
        )
        .with_transparent_change_policy(TransparentChangePolicy::TransparentChangeAllowed);

        // Input selection starts with no inputs. A shielded-only account that pays a
        // transparent address must learn that it needs more funds, so that shielded notes
        // can be selected.
        let result = change_strategy.compute_balance::<_, Infallible>(
            &Network::TestNetwork,
            Network::TestNetwork
                .activation_height(NetworkUpgrade::Nu5)
                .unwrap()
                .into(),
            BlockHeight::from_u32(1),
            &PoolMigrationParams::new(
                zcash_protocol::zip318::BlockSpacing::UNIFORM,
                AnchorRetentionInterval::ZIP_318,
            ),
            &[] as &[TestTransparentInput],
            &[TxOut::new(PAYMENT_VALUE, Script::default())],
            &sapling_fees::EmptyBundleView,
            #[cfg(feature = "orchard")]
            &orchard_fees::EmptyBundleView,
            #[cfg(feature = "orchard")]
            &orchard_fees::EmptyBundleView,
            None,
            &ChangeReceivers::new(true, true, None),
        );

        assert_matches!(
            result,
            Err(ChangeError::InsufficientFunds { available, required })
                if available == Zatoshis::ZERO && required == (PAYMENT_VALUE + MINIMUM_FEE).unwrap()
        );
    }

    #[test]
    #[cfg(feature = "transparent-inputs")]
    fn changeless_transparent_transaction_needs_no_transparent_receiver() {
        /// The value of the transparent payment.
        const PAYMENT_VALUE: Zatoshis = Zatoshis::const_from_u64(40000);

        let change_strategy = SingleOutputChangeStrategy::<_, MockWalletDb>::new(
            Zip317FeeRule::standard(),
            None,
            ShieldedPool::Sapling,
            DustOutputPolicy::default(),
        )
        .with_transparent_change_policy(TransparentChangePolicy::TransparentChangeAllowed);

        // The second transaction of a ZIP 320 pair spends the ephemeral output exactly, so it
        // has no change output. The account needs no transparent receiver for it.
        let result = change_strategy.compute_balance::<_, Infallible>(
            &Network::TestNetwork,
            Network::TestNetwork
                .activation_height(NetworkUpgrade::Nu5)
                .unwrap()
                .into(),
            BlockHeight::from_u32(1),
            &PoolMigrationParams::new(
                zcash_protocol::zip318::BlockSpacing::UNIFORM,
                AnchorRetentionInterval::ZIP_318,
            ),
            &[] as &[TestTransparentInput],
            &[TxOut::new(PAYMENT_VALUE, Script::default())],
            &sapling_fees::EmptyBundleView,
            #[cfg(feature = "orchard")]
            &orchard_fees::EmptyBundleView,
            #[cfg(feature = "orchard")]
            &orchard_fees::EmptyBundleView,
            Some(EphemeralBalance::Input(
                (PAYMENT_VALUE + MINIMUM_FEE).unwrap(),
            )),
            &ChangeReceivers::new(true, true, None),
        );

        assert_matches!(
            result,
            Ok(balance) if balance.proposed_change().is_empty() && balance.fee_required() == MINIMUM_FEE
        );
    }

    #[test]
    #[cfg(feature = "transparent-inputs")]
    fn transparent_change_is_sized_by_its_kind() {
        let change_strategy = SingleOutputChangeStrategy::<_, MockWalletDb>::new(
            Zip317FeeRule::standard(),
            None,
            ShieldedPool::Sapling,
            DustOutputPolicy::default(),
        )
        .with_transparent_change_policy(TransparentChangePolicy::TransparentChangeAllowed);

        // Sixteen 32-byte P2SH payments make 512 bytes of outputs. A 32-byte P2SH change
        // output brings this to 544 bytes, which is 16 logical actions of 34 bytes. A
        // 34-byte P2PKH change output brings it to 546 bytes, which is 17 logical actions.
        let payments = vec![
            TxOut::new(
                Zatoshis::const_from_u64(5000),
                TransparentAddress::ScriptHash([0u8; 20]).script().into(),
            );
            16
        ];
        let balance = |kind| {
            change_strategy.compute_balance::<_, Infallible>(
                &Network::TestNetwork,
                Network::TestNetwork
                    .activation_height(NetworkUpgrade::Nu5)
                    .unwrap()
                    .into(),
                BlockHeight::from_u32(1),
                &PoolMigrationParams::new(
                    zcash_protocol::zip318::BlockSpacing::UNIFORM,
                    AnchorRetentionInterval::ZIP_318,
                ),
                &[TestTransparentInput {
                    outpoint: OutPoint::fake(),
                    coin: TxOut::new(
                        Zatoshis::const_from_u64(200000),
                        TransparentAddress::PublicKeyHash([0u8; 20]).script().into(),
                    ),
                }],
                &payments[..],
                &sapling_fees::EmptyBundleView,
                #[cfg(feature = "orchard")]
                &orchard_fees::EmptyBundleView,
                #[cfg(feature = "orchard")]
                &orchard_fees::EmptyBundleView,
                None,
                &ChangeReceivers::new(false, false, Some(kind)),
            )
        };

        assert_matches!(
            balance(TransparentChangeKind::P2sh),
            Ok(balance) if
                balance.proposed_change() == [ChangeValue::transparent(Zatoshis::const_from_u64(40000))] &&
                balance.fee_required() == Zatoshis::const_from_u64(80000)
        );
        assert_matches!(
            balance(TransparentChangeKind::P2pkh),
            Ok(balance) if
                balance.proposed_change() == [ChangeValue::transparent(Zatoshis::const_from_u64(35000))] &&
                balance.fee_required() == Zatoshis::const_from_u64(85000)
        );
    }

    #[test]
    #[cfg(feature = "transparent-inputs")]
    fn ephemeral_output_requires_a_p2pkh_receiver() {
        let change_strategy = SingleOutputChangeStrategy::<_, MockWalletDb>::new(
            Zip317FeeRule::standard(),
            None,
            ShieldedPool::Sapling,
            DustOutputPolicy::default(),
        );

        // The first transaction of a ZIP 320 pair sends value to an ephemeral P2PKH
        // address of the account. An account whose transparent key is a P2SH key has no
        // such address.
        let balance = |kind| {
            change_strategy.compute_balance::<_, Infallible>(
                &Network::TestNetwork,
                Network::TestNetwork
                    .activation_height(NetworkUpgrade::Nu5)
                    .unwrap()
                    .into(),
                BlockHeight::from_u32(1),
                &PoolMigrationParams::new(
                    zcash_protocol::zip318::BlockSpacing::UNIFORM,
                    AnchorRetentionInterval::ZIP_318,
                ),
                &[TestTransparentInput {
                    outpoint: OutPoint::fake(),
                    coin: TxOut::new(
                        Zatoshis::const_from_u64(100000),
                        TransparentAddress::PublicKeyHash([0u8; 20]).script().into(),
                    ),
                }],
                &[] as &[TxOut],
                &sapling_fees::EmptyBundleView,
                #[cfg(feature = "orchard")]
                &orchard_fees::EmptyBundleView,
                #[cfg(feature = "orchard")]
                &orchard_fees::EmptyBundleView,
                Some(EphemeralBalance::Output(Zatoshis::const_from_u64(50000))),
                &ChangeReceivers::new(true, false, Some(kind)),
            )
        };

        assert_matches!(
            balance(TransparentChangeKind::P2sh),
            Err(ChangeError::UnsupportedChangePool(pool)) if pool == PoolType::TRANSPARENT
        );
        assert_matches!(
            balance(TransparentChangeKind::P2pkh),
            Ok(balance) if balance.proposed_change().iter().any(|c| c.is_ephemeral())
        );
    }
}
