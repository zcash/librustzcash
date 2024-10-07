//! Change strategies designed for use with a standard fee.

use std::marker::PhantomData;

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

use crate::{data_api::InputSource, ShieldedProtocol};

use super::{
    fixed, sapling as sapling_fees, zip317, ChangeError, ChangeStrategy, DustOutputPolicy,
    EphemeralBalance, TransactionBalance,
};

#[cfg(feature = "orchard")]
use super::orchard as orchard_fees;

/// A change strategy that proposes change as a single output. The output pool is chosen
/// as the most current pool that avoids unnecessary pool-crossing (with a specified
/// fallback when the transaction has no shielded inputs). Fee calculation is delegated
/// to the provided fee rule.
pub struct SingleOutputChangeStrategy<I> {
    fee_rule: StandardFeeRule,
    change_memo: Option<MemoBytes>,
    fallback_change_pool: ShieldedProtocol,
    dust_output_policy: DustOutputPolicy,
    meta_source: PhantomData<I>,
}

impl<I> SingleOutputChangeStrategy<I> {
    /// Constructs a new [`SingleOutputChangeStrategy`] with the specified ZIP 317
    /// fee parameters.
    ///
    /// `fallback_change_pool` is used when more than one shielded pool is enabled via
    /// feature flags, and the transaction has no shielded inputs.
    pub fn new(
        fee_rule: StandardFeeRule,
        change_memo: Option<MemoBytes>,
        fallback_change_pool: ShieldedProtocol,
        dust_output_policy: DustOutputPolicy,
    ) -> Self {
        Self {
            fee_rule,
            change_memo,
            fallback_change_pool,
            dust_output_policy,
            meta_source: PhantomData,
        }
    }
}

impl<I: InputSource> ChangeStrategy for SingleOutputChangeStrategy<I> {
    type FeeRule = StandardFeeRule;
    type Error = Zip317FeeError;
    type MetaSource = I;
    type WalletMeta = ();

    fn fee_rule(&self) -> &Self::FeeRule {
        &self.fee_rule
    }

    fn fetch_wallet_meta(
        &self,
        _meta_source: &Self::MetaSource,
        _account: <Self::MetaSource as InputSource>::AccountId,
        _exclude: &[<Self::MetaSource as crate::data_api::InputSource>::NoteRef],
    ) -> Result<Self::WalletMeta, <Self::MetaSource as crate::data_api::InputSource>::Error> {
        Ok(())
    }

    fn compute_balance<P: consensus::Parameters, NoteRefT: Clone>(
        &self,
        params: &P,
        target_height: BlockHeight,
        transparent_inputs: &[impl transparent::InputView],
        transparent_outputs: &[impl transparent::OutputView],
        sapling: &impl sapling_fees::BundleView<NoteRefT>,
        #[cfg(feature = "orchard")] orchard: &impl orchard_fees::BundleView<NoteRefT>,
        ephemeral_balance: Option<&EphemeralBalance>,
        wallet_meta: Option<&Self::WalletMeta>,
    ) -> Result<TransactionBalance, ChangeError<Self::Error, NoteRefT>> {
        #[allow(deprecated)]
        match self.fee_rule() {
            StandardFeeRule::PreZip313 => fixed::SingleOutputChangeStrategy::<I>::new(
                FixedFeeRule::non_standard(NonNegativeAmount::const_from_u64(10000)),
                self.change_memo.clone(),
                self.fallback_change_pool,
                self.dust_output_policy,
            )
            .compute_balance(
                params,
                target_height,
                transparent_inputs,
                transparent_outputs,
                sapling,
                #[cfg(feature = "orchard")]
                orchard,
                ephemeral_balance,
                wallet_meta,
            )
            .map_err(|e| e.map(Zip317FeeError::Balance)),
            StandardFeeRule::Zip313 => fixed::SingleOutputChangeStrategy::<I>::new(
                FixedFeeRule::non_standard(NonNegativeAmount::const_from_u64(1000)),
                self.change_memo.clone(),
                self.fallback_change_pool,
                self.dust_output_policy,
            )
            .compute_balance(
                params,
                target_height,
                transparent_inputs,
                transparent_outputs,
                sapling,
                #[cfg(feature = "orchard")]
                orchard,
                ephemeral_balance,
                wallet_meta,
            )
            .map_err(|e| e.map(Zip317FeeError::Balance)),
            StandardFeeRule::Zip317 => zip317::SingleOutputChangeStrategy::<I>::new(
                Zip317FeeRule::standard(),
                self.change_memo.clone(),
                self.fallback_change_pool,
                self.dust_output_policy,
            )
            .compute_balance(
                params,
                target_height,
                transparent_inputs,
                transparent_outputs,
                sapling,
                #[cfg(feature = "orchard")]
                orchard,
                ephemeral_balance,
                wallet_meta,
            ),
        }
    }
}
