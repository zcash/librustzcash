//! Change strategies designed to implement the ZIP 317 fee rules.
//!
//! Change selection in ZIP 317 requires careful handling of low-valued inputs
//! to ensure that inputs added to a transaction do not cause fees to rise by
//! an amount greater than their value.

use core::marker::PhantomData;

use zcash_primitives::transaction::fees::{FeeRule, transparent, zip317 as prim_zip317};
use zcash_protocol::{
    ShieldedPool, consensus,
    memo::MemoBytes,
    value::{BalanceError, Zatoshis},
};

use crate::{
    data_api::{AccountMeta, InputSource, NoteFilter, wallet::TargetHeight},
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
use super::orchard as orchard_fees;

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
pub struct SingleOutputChangeStrategy<R, I> {
    fee_rule: R,
    change_memo: Option<MemoBytes>,
    fallback_change_pool: ShieldedPool,
    dust_output_policy: DustOutputPolicy,
    #[cfg(feature = "orchard")]
    unpadded_orchard_pool_bundles: bool,
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
            #[cfg(feature = "orchard")]
            unpadded_orchard_pool_bundles: false,
            #[cfg(feature = "transparent-inputs")]
            transparent_change_policy: TransparentChangePolicy::ShieldChange,
            meta_source: PhantomData,
        }
    }

    /// Requests unpadded Orchard-pool (Orchard and Ironwood) bundles: fee and
    /// change calculation will count exactly the requested actions instead of
    /// padding each bundle to the 2-action minimum.
    ///
    /// The transaction executing the proposal must be built with the matching
    /// bundle type ([`BundleType::UNPADDED`](orchard::builder::BundleType)),
    /// or the builder's balance check will fail. Intended for transactions whose
    /// shape is already public (e.g. pool migrations); see the orchard
    /// `pad_to_minimum` documentation for the privacy trade-off.
    #[cfg(feature = "orchard")]
    pub fn with_unpadded_orchard_pool_bundles(mut self) -> Self {
        self.unpadded_orchard_pool_bundles = true;
        self
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
    type AccountMetaT = ();

    fn fee_rule(&self) -> &Self::FeeRule {
        &self.fee_rule
    }

    fn fetch_wallet_meta(
        &self,
        _meta_source: &Self::MetaSource,
        _account: <Self::MetaSource as MetaSource>::AccountId,
        _target_height: TargetHeight,
        _exclude: &[<Self::MetaSource as MetaSource>::NoteRef],
    ) -> Result<Self::AccountMetaT, <Self::MetaSource as MetaSource>::Error> {
        Ok(())
    }

    fn compute_balance<P: consensus::Parameters, NoteRefT: Clone>(
        &self,
        params: &P,
        target_height: TargetHeight,
        transparent_inputs: &[impl transparent::InputView],
        transparent_outputs: &[impl transparent::OutputView],
        sapling: &impl sapling_fees::BundleView<NoteRefT>,
        #[cfg(feature = "orchard")] orchard: &impl orchard_fees::BundleView<NoteRefT>,
        #[cfg(feature = "orchard")] ironwood: &impl orchard_fees::BundleView<NoteRefT>,
        ephemeral_balance: Option<EphemeralBalance>,
        _wallet_meta: &Self::AccountMetaT,
    ) -> Result<TransactionBalance, ChangeError<Self::Error, NoteRefT>> {
        let split_policy = SplitPolicy::single_output();
        let cfg = SinglePoolBalanceConfig::new(
            params,
            &self.fee_rule,
            &self.dust_output_policy,
            self.fee_rule.marginal_fee(),
            &split_policy,
            self.fallback_change_pool,
            #[cfg(feature = "transparent-inputs")]
            self.transparent_change_policy,
            self.fee_rule.marginal_fee(),
            self.fee_rule.grace_actions(),
        );

        #[cfg(feature = "orchard")]
        let orchard_pool_bundle_type = if self.unpadded_orchard_pool_bundles {
            ::orchard::builder::BundleType::UNPADDED
        } else {
            ::orchard::builder::BundleType::DEFAULT
        };

        single_pool_output_balance(
            cfg,
            None,
            target_height,
            transparent_inputs,
            transparent_outputs,
            sapling,
            #[cfg(feature = "orchard")]
            orchard,
            #[cfg(feature = "orchard")]
            ironwood,
            #[cfg(feature = "orchard")]
            orchard_pool_bundle_type,
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
    #[cfg(feature = "orchard")]
    unpadded_orchard_pool_bundles: bool,
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
            #[cfg(feature = "orchard")]
            unpadded_orchard_pool_bundles: false,
            #[cfg(feature = "transparent-inputs")]
            transparent_change_policy: TransparentChangePolicy::ShieldChange,
            meta_source: PhantomData,
        }
    }

    /// Requests unpadded Orchard-pool (Orchard and Ironwood) bundles: fee and
    /// change calculation will count exactly the requested actions instead of
    /// padding each bundle to the 2-action minimum.
    ///
    /// The transaction executing the proposal must be built with the matching
    /// bundle type ([`BundleType::UNPADDED`](orchard::builder::BundleType)),
    /// or the builder's balance check will fail. Intended for transactions whose
    /// shape is already public (e.g. pool migrations); see the orchard
    /// `pad_to_minimum` documentation for the privacy trade-off.
    #[cfg(feature = "orchard")]
    pub fn with_unpadded_orchard_pool_bundles(mut self) -> Self {
        self.unpadded_orchard_pool_bundles = true;
        self
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

        meta_source.get_account_metadata(account, &note_selector, target_height, exclude)
    }

    fn compute_balance<P: consensus::Parameters, NoteRefT: Clone>(
        &self,
        params: &P,
        target_height: TargetHeight,
        transparent_inputs: &[impl transparent::InputView],
        transparent_outputs: &[impl transparent::OutputView],
        sapling: &impl sapling_fees::BundleView<NoteRefT>,
        #[cfg(feature = "orchard")] orchard: &impl orchard_fees::BundleView<NoteRefT>,
        #[cfg(feature = "orchard")] ironwood: &impl orchard_fees::BundleView<NoteRefT>,
        ephemeral_balance: Option<EphemeralBalance>,
        wallet_meta: &Self::AccountMetaT,
    ) -> Result<TransactionBalance, ChangeError<Self::Error, NoteRefT>> {
        let cfg = SinglePoolBalanceConfig::new(
            params,
            &self.fee_rule,
            &self.dust_output_policy,
            self.fee_rule.marginal_fee(),
            &self.split_policy,
            self.fallback_change_pool,
            #[cfg(feature = "transparent-inputs")]
            self.transparent_change_policy,
            self.fee_rule.marginal_fee(),
            self.fee_rule.grace_actions(),
        );

        #[cfg(feature = "orchard")]
        let orchard_pool_bundle_type = if self.unpadded_orchard_pool_bundles {
            ::orchard::builder::BundleType::UNPADDED
        } else {
            ::orchard::builder::BundleType::DEFAULT
        };

        single_pool_output_balance(
            cfg,
            Some(wallet_meta),
            target_height,
            transparent_inputs,
            transparent_outputs,
            sapling,
            #[cfg(feature = "orchard")]
            orchard,
            #[cfg(feature = "orchard")]
            ironwood,
            #[cfg(feature = "orchard")]
            orchard_pool_bundle_type,
            self.change_memo.as_ref(),
            ephemeral_balance,
        )
    }
}

#[cfg(test)]
mod tests {
    use core::{convert::Infallible, num::NonZeroUsize};

    use ::transparent::{address::Script, bundle::TxOut};
    use zcash_primitives::transaction::fees::zip317::FeeRule as Zip317FeeRule;
    use zcash_protocol::{
        ShieldedPool,
        consensus::{Network, NetworkUpgrade, Parameters},
        value::Zatoshis,
    };

    use super::SingleOutputChangeStrategy;
    use crate::{
        data_api::{
            AccountMeta, PoolMeta, testing::MockWalletDb, wallet::input_selection::SaplingPayment,
        },
        fees::{
            ChangeError, ChangeStrategy, ChangeValue, DustAction, DustOutputPolicy, SplitPolicy,
            tests::{TestSaplingInput, TestTransparentInput},
            zip317::MultiOutputChangeStrategy,
        },
    };

    #[cfg(feature = "orchard")]
    use {
        crate::data_api::wallet::input_selection::OrchardPayment,
        crate::fees::orchard as orchard_fees,
    };

    #[cfg(all(feature = "orchard", feature = "transparent-inputs"))]
    use crate::data_api::wallet::TargetHeight;

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
            &(),
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
                    &AccountMeta::new(Some(PoolMeta::new(existing_notes, total)), None, None),
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
            &(),
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
        use crate::fees::{sapling as sapling_fees, tests::TestOrchardInput};

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
            &(),
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
        use crate::fees::sapling as sapling_fees;
        use ::transparent::{address::TransparentAddress, bundle::OutPoint};

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
        let wallet_meta = AccountMeta::new(None, None, None);

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
                &[] as &[TestTransparentInput],
                &[] as &[TxOut],
                &sapling_view,
                &orchard_view,
                &orchard_fees::EmptyBundleView,
                None,
                &(),
            )
            .unwrap();

        let with_ironwood = change_strategy
            .compute_balance(
                &Network::TestNetwork,
                height,
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
                &(),
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
    #[cfg(feature = "orchard")]
    fn unpadded_orchard_pool_bundles_lower_the_fee() {
        // `with_unpadded_orchard_pool_bundles` drops the ZIP 317 2-action padding floor
        // for the Orchard and Ironwood bundles. This reuses the
        // `ironwood_outputs_are_charged_actions` scenario, where only the single-output
        // Ironwood bundle is below the floor, so the unpadded strategy charges it 1
        // action instead of 2 and the fee falls by exactly one 5000-zat action.
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
        let ironwood_view = (
            ::orchard::bundle::BundleVersion::ironwood_v3(),
            &[] as &[Infallible],
            &orchard_outputs[..],
        );

        let padded_fee = SingleOutputChangeStrategy::<_, MockWalletDb>::new(
            Zip317FeeRule::standard(),
            None,
            ShieldedPool::Orchard,
            DustOutputPolicy::default(),
        )
        .compute_balance(
            &Network::TestNetwork,
            height,
            &[] as &[TestTransparentInput],
            &[] as &[TxOut],
            &sapling_view,
            &orchard_view,
            &ironwood_view,
            None,
            &(),
        )
        .unwrap()
        .fee_required();

        let unpadded_fee = SingleOutputChangeStrategy::<_, MockWalletDb>::new(
            Zip317FeeRule::standard(),
            None,
            ShieldedPool::Orchard,
            DustOutputPolicy::default(),
        )
        .with_unpadded_orchard_pool_bundles()
        .compute_balance(
            &Network::TestNetwork,
            height,
            &[] as &[TestTransparentInput],
            &[] as &[TxOut],
            &sapling_view,
            &orchard_view,
            &ironwood_view,
            None,
            &(),
        )
        .unwrap()
        .fee_required();

        // Padded default matches `ironwood_outputs_are_charged_actions`: sapling (2) +
        // orchard (1 payment + 1 change = 2) + ironwood (1 output, padded to 2) = 6
        // actions = 30000 zat. Unpadded charges the single-output Ironwood bundle 1
        // action, so the fee drops by one 5000-zat action to 25000.
        assert_eq!(padded_fee, Zatoshis::const_from_u64(30000));
        assert_eq!(unpadded_fee, Zatoshis::const_from_u64(25000));
        assert_eq!(
            padded_fee,
            (unpadded_fee + Zatoshis::const_from_u64(5000)).unwrap()
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
            &(),
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
        use crate::fees::sapling as sapling_fees;
        use ::transparent::{address::TransparentAddress, bundle::OutPoint};

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
            &(),
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
        use crate::fees::sapling as sapling_fees;
        use ::transparent::{address::TransparentAddress, bundle::OutPoint};

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
            &(),
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
        use crate::fees::sapling as sapling_fees;
        use ::transparent::{address::TransparentAddress, bundle::OutPoint};

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
            &(),
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
        use crate::fees::{TransparentChangePolicy, sapling as sapling_fees};
        use ::transparent::{address::TransparentAddress, bundle::OutPoint};

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
            &(),
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
        use crate::fees::{TransparentChangePolicy, sapling as sapling_fees};
        use ::transparent::{address::TransparentAddress, bundle::OutPoint};

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
            &(),
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
    fn change_fully_transparent_returned_to_p2sh_source() {
        use crate::fees::{TransparentChangePolicy, sapling as sapling_fees};
        use crate::wallet::WalletTransparentOutput;
        use ::transparent::{address::TransparentAddress, bundle::OutPoint};

        let change_strategy = SingleOutputChangeStrategy::<_, MockWalletDb>::new(
            Zip317FeeRule::standard(),
            None,
            ShieldedPool::Sapling,
            DustOutputPolicy::default(),
        )
        .with_transparent_change_policy(TransparentChangePolicy::TransparentChangeAllowed);

        let p2sh_addr = TransparentAddress::ScriptHash([7u8; 20]);

        // A single P2SH input (100_000 zats) funds four transparent payments (10_000 zats
        // each). The change is returned to the originating P2SH address. Sizing the change
        // output as a P2SH `TxOut` (32 bytes) yields a total transparent output size of 68
        // bytes => 2 logical actions => a 10_000 zat fee; mis-sizing it as a P2PKH output
        // (34 bytes) would tip the total to 70 bytes => 3 actions => a 15_000 zat fee.
        let inputs = [WalletTransparentOutput::<()>::from_parts(
            OutPoint::fake(),
            TxOut::new(Zatoshis::const_from_u64(100_000), p2sh_addr.script().into()),
            None,
            None,
            None,
            None,
        )
        .expect("valid P2SH output")
        .with_known_input_size(150)];

        let result = change_strategy.compute_balance::<_, Infallible>(
            &Network::TestNetwork,
            Network::TestNetwork
                .activation_height(NetworkUpgrade::Nu5)
                .unwrap()
                .into(),
            &inputs,
            &[
                TxOut::new(Zatoshis::const_from_u64(10_000), Script::default()),
                TxOut::new(Zatoshis::const_from_u64(10_000), Script::default()),
                TxOut::new(Zatoshis::const_from_u64(10_000), Script::default()),
                TxOut::new(Zatoshis::const_from_u64(10_000), Script::default()),
            ],
            &sapling_fees::EmptyBundleView,
            #[cfg(feature = "orchard")]
            &orchard_fees::EmptyBundleView,
            #[cfg(feature = "orchard")]
            &orchard_fees::EmptyBundleView,
            None,
            &(),
        );

        assert_matches!(
            result,
            Ok(balance) if
                balance.proposed_change()
                    == [ChangeValue::transparent_to_address(Zatoshis::const_from_u64(50_000), p2sh_addr)] &&
                balance.fee_required() == Zatoshis::const_from_u64(10_000)
        );
    }

    #[test]
    #[cfg(feature = "transparent-inputs")]
    fn change_fully_transparent_returned_to_p2sh_source_multiple_inputs() {
        use crate::fees::{TransparentChangePolicy, sapling as sapling_fees};
        use crate::wallet::WalletTransparentOutput;
        use ::transparent::{address::TransparentAddress, bundle::OutPoint};

        let change_strategy = SingleOutputChangeStrategy::<_, MockWalletDb>::new(
            Zip317FeeRule::standard(),
            None,
            ShieldedPool::Sapling,
            DustOutputPolicy::default(),
        )
        .with_transparent_change_policy(TransparentChangePolicy::TransparentChangeAllowed);

        let p2sh_addr = TransparentAddress::ScriptHash([7u8; 20]);

        // Two P2SH inputs (50_000 zats each) funded by the *same* P2SH address still resolve
        // to that single originating address; change is returned to it and sized as a P2SH
        // output (32 bytes).
        let p2sh_input = |n: u8| {
            WalletTransparentOutput::<()>::from_parts(
                OutPoint::new([n; 32], 0),
                TxOut::new(Zatoshis::const_from_u64(50_000), p2sh_addr.script().into()),
                None,
                None,
                None,
                None,
            )
            .expect("valid P2SH output")
            .with_known_input_size(150)
        };
        let inputs = [p2sh_input(1), p2sh_input(2)];

        let result = change_strategy.compute_balance::<_, Infallible>(
            &Network::TestNetwork,
            Network::TestNetwork
                .activation_height(NetworkUpgrade::Nu5)
                .unwrap()
                .into(),
            &inputs,
            &[
                TxOut::new(Zatoshis::const_from_u64(10_000), Script::default()),
                TxOut::new(Zatoshis::const_from_u64(10_000), Script::default()),
                TxOut::new(Zatoshis::const_from_u64(10_000), Script::default()),
                TxOut::new(Zatoshis::const_from_u64(10_000), Script::default()),
            ],
            &sapling_fees::EmptyBundleView,
            #[cfg(feature = "orchard")]
            &orchard_fees::EmptyBundleView,
            #[cfg(feature = "orchard")]
            &orchard_fees::EmptyBundleView,
            None,
            &(),
        );

        assert_matches!(
            result,
            Ok(balance) if
                balance.proposed_change()
                    == [ChangeValue::transparent_to_address(Zatoshis::const_from_u64(50_000), p2sh_addr)] &&
                balance.fee_required() == Zatoshis::const_from_u64(10_000)
        );
    }

    #[test]
    #[cfg(feature = "transparent-inputs")]
    fn change_fully_transparent_ambiguous_p2sh_sources() {
        use crate::fees::{TransparentChangePolicy, sapling as sapling_fees};
        use crate::wallet::WalletTransparentOutput;
        use ::transparent::{address::TransparentAddress, bundle::OutPoint};

        let change_strategy = SingleOutputChangeStrategy::<_, MockWalletDb>::new(
            Zip317FeeRule::standard(),
            None,
            ShieldedPool::Sapling,
            DustOutputPolicy::default(),
        )
        .with_transparent_change_policy(TransparentChangePolicy::TransparentChangeAllowed);

        // A P2SH input and a P2PKH input have distinct originating addresses, so no single
        // address exists to which change may be returned. Because the payment is small
        // enough that a non-zero change output must be emitted, resolution fails.
        let inputs = [
            WalletTransparentOutput::<()>::from_parts(
                OutPoint::new([1u8; 32], 0),
                TxOut::new(
                    Zatoshis::const_from_u64(60_000),
                    TransparentAddress::ScriptHash([7u8; 20]).script().into(),
                ),
                None,
                None,
                None,
                None,
            )
            .expect("valid P2SH output")
            .with_known_input_size(150),
            WalletTransparentOutput::<()>::from_parts(
                OutPoint::new([2u8; 32], 0),
                TxOut::new(
                    Zatoshis::const_from_u64(60_000),
                    TransparentAddress::PublicKeyHash([9u8; 20]).script().into(),
                ),
                None,
                None,
                None,
                None,
            )
            .expect("valid P2PKH output"),
        ];

        let result = change_strategy.compute_balance::<_, Infallible>(
            &Network::TestNetwork,
            Network::TestNetwork
                .activation_height(NetworkUpgrade::Nu5)
                .unwrap()
                .into(),
            &inputs,
            &[TxOut::new(
                Zatoshis::const_from_u64(10_000),
                Script::default(),
            )],
            &sapling_fees::EmptyBundleView,
            #[cfg(feature = "orchard")]
            &orchard_fees::EmptyBundleView,
            #[cfg(feature = "orchard")]
            &orchard_fees::EmptyBundleView,
            None,
            &(),
        );

        assert_matches!(
            result,
            Err(ChangeError::TransparentChangeDestinationAmbiguous { input_addresses })
                if input_addresses.len() == 2
        );
    }

    #[test]
    #[cfg(feature = "transparent-inputs")]
    fn change_fully_transparent_distinct_p2pkh_sources_uses_internal_change() {
        use crate::fees::{TransparentChangePolicy, sapling as sapling_fees};
        use crate::wallet::WalletTransparentOutput;
        use ::transparent::{address::TransparentAddress, bundle::OutPoint};

        let change_strategy = SingleOutputChangeStrategy::<_, MockWalletDb>::new(
            Zip317FeeRule::standard(),
            None,
            ShieldedPool::Sapling,
            DustOutputPolicy::default(),
        )
        .with_transparent_change_policy(TransparentChangePolicy::TransparentChangeAllowed);

        // Two P2PKH inputs with distinct originating addresses: no P2SH source is present,
        // so change is returned to an internal-scope address of the wallet (recipient
        // `None`) with the standard P2PKH sizing, exactly as before.
        let inputs = [
            WalletTransparentOutput::<()>::from_parts(
                OutPoint::new([1u8; 32], 0),
                TxOut::new(
                    Zatoshis::const_from_u64(50_000),
                    TransparentAddress::PublicKeyHash([1u8; 20]).script().into(),
                ),
                None,
                None,
                None,
                None,
            )
            .expect("valid P2PKH output"),
            WalletTransparentOutput::<()>::from_parts(
                OutPoint::new([2u8; 32], 0),
                TxOut::new(
                    Zatoshis::const_from_u64(50_000),
                    TransparentAddress::PublicKeyHash([2u8; 20]).script().into(),
                ),
                None,
                None,
                None,
                None,
            )
            .expect("valid P2PKH output"),
        ];

        let result = change_strategy.compute_balance::<_, Infallible>(
            &Network::TestNetwork,
            Network::TestNetwork
                .activation_height(NetworkUpgrade::Nu5)
                .unwrap()
                .into(),
            &inputs,
            &[TxOut::new(
                Zatoshis::const_from_u64(40_000),
                Script::default(),
            )],
            &sapling_fees::EmptyBundleView,
            #[cfg(feature = "orchard")]
            &orchard_fees::EmptyBundleView,
            #[cfg(feature = "orchard")]
            &orchard_fees::EmptyBundleView,
            None,
            &(),
        );

        assert_matches!(
            result,
            Ok(balance) if
                balance.proposed_change()
                    == [ChangeValue::transparent(Zatoshis::const_from_u64(50_000))] &&
                balance.fee_required() == Zatoshis::const_from_u64(10_000)
        );
    }

    #[test]
    #[cfg(feature = "transparent-inputs")]
    fn change_fully_transparent_exact_match_ambiguous_sources_ok() {
        use crate::fees::{TransparentChangePolicy, sapling as sapling_fees};
        use crate::wallet::WalletTransparentOutput;
        use ::transparent::{address::TransparentAddress, bundle::OutPoint};

        let change_strategy = SingleOutputChangeStrategy::<_, MockWalletDb>::new(
            Zip317FeeRule::standard(),
            None,
            ShieldedPool::Sapling,
            DustOutputPolicy::default(),
        )
        .with_transparent_change_policy(TransparentChangePolicy::TransparentChangeAllowed);

        // The inputs have ambiguous (P2SH + P2PKH) sources, but their total exactly covers
        // the payment plus the minimum (changeless) fee. No change output is emitted, so the
        // ambiguity never has to be resolved and the transaction is built successfully. This
        // is the reason the ambiguity error is raised lazily at change emission rather than
        // eagerly at destination resolution.
        let inputs = [
            WalletTransparentOutput::<()>::from_parts(
                OutPoint::new([1u8; 32], 0),
                TxOut::new(
                    Zatoshis::const_from_u64(10_000),
                    TransparentAddress::ScriptHash([7u8; 20]).script().into(),
                ),
                None,
                None,
                None,
                None,
            )
            .expect("valid P2SH output")
            .with_known_input_size(150),
            WalletTransparentOutput::<()>::from_parts(
                OutPoint::new([2u8; 32], 0),
                TxOut::new(
                    Zatoshis::const_from_u64(10_000),
                    TransparentAddress::PublicKeyHash([9u8; 20]).script().into(),
                ),
                None,
                None,
                None,
                None,
            )
            .expect("valid P2PKH output"),
        ];

        let result = change_strategy.compute_balance::<_, Infallible>(
            &Network::TestNetwork,
            Network::TestNetwork
                .activation_height(NetworkUpgrade::Nu5)
                .unwrap()
                .into(),
            &inputs,
            &[TxOut::new(
                Zatoshis::const_from_u64(10_000),
                Script::default(),
            )],
            &sapling_fees::EmptyBundleView,
            #[cfg(feature = "orchard")]
            &orchard_fees::EmptyBundleView,
            #[cfg(feature = "orchard")]
            &orchard_fees::EmptyBundleView,
            None,
            &(),
        );

        assert_matches!(
            result,
            Ok(balance) if
                balance.proposed_change().is_empty() &&
                balance.fee_required() == Zatoshis::const_from_u64(10_000)
        );
    }

    #[test]
    #[cfg(feature = "transparent-inputs")]
    fn transparent_change_policy_has_no_effect_on_shielded_flows() {
        use crate::fees::TransparentChangePolicy;

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
            &(),
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
        use crate::fees::{TransparentChangePolicy, sapling as sapling_fees};
        use ::transparent::{address::TransparentAddress, bundle::OutPoint};

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
            &AccountMeta::new(Some(PoolMeta::new(0, Zatoshis::ZERO)), None, None),
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
        use crate::fees::{TransparentChangePolicy, sapling as sapling_fees};
        use ::transparent::{address::TransparentAddress, bundle::OutPoint};

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
            &(),
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
        use crate::fees::{TransparentChangePolicy, sapling as sapling_fees};
        use ::transparent::{address::TransparentAddress, bundle::OutPoint};

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
            &(),
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
        use crate::fees::{TransparentChangePolicy, sapling as sapling_fees};
        use ::transparent::{address::TransparentAddress, bundle::OutPoint};

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
            &(),
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
            &(),
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
            &(),
        );

        // We will get an error here, because the dust input isn't free to add
        // to the transaction.
        assert_matches!(
            result,
            Err(ChangeError::DustInputs { sapling, .. }) if sapling == vec![2]
        );
    }
}
