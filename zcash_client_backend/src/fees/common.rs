use core::cmp::max;

use zcash_primitives::{
    consensus::{self, BlockHeight},
    memo::MemoBytes,
    transaction::{
        components::amount::{BalanceError, NonNegativeAmount},
        fees::{transparent, zip317::MINIMUM_FEE, FeeRule},
    },
};
use zcash_protocol::ShieldedProtocol;

use super::{
    sapling as sapling_fees, ChangeError, ChangeValue, DustAction, DustOutputPolicy,
    TransactionBalance,
};

#[cfg(feature = "orchard")]
use super::orchard as orchard_fees;

pub(crate) struct NetFlows {
    t_in: NonNegativeAmount,
    t_out: NonNegativeAmount,
    sapling_in: NonNegativeAmount,
    sapling_out: NonNegativeAmount,
    orchard_in: NonNegativeAmount,
    orchard_out: NonNegativeAmount,
}

impl NetFlows {
    fn total_in(&self) -> Result<NonNegativeAmount, BalanceError> {
        (self.t_in + self.sapling_in + self.orchard_in).ok_or(BalanceError::Overflow)
    }
    fn total_out(&self) -> Result<NonNegativeAmount, BalanceError> {
        (self.t_out + self.sapling_out + self.orchard_out).ok_or(BalanceError::Overflow)
    }
    /// Returns true iff the flows excluding change are fully transparent.
    fn is_transparent(&self) -> bool {
        !(self.sapling_in.is_positive()
            || self.sapling_out.is_positive()
            || self.orchard_in.is_positive()
            || self.orchard_out.is_positive())
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn calculate_net_flows<NoteRefT: Clone, F: FeeRule, E>(
    transparent_inputs: &[impl transparent::InputView],
    transparent_outputs: &[impl transparent::OutputView],
    sapling: &impl sapling_fees::BundleView<NoteRefT>,
    #[cfg(feature = "orchard")] orchard: &impl orchard_fees::BundleView<NoteRefT>,
) -> Result<NetFlows, ChangeError<E, NoteRefT>>
where
    E: From<F::Error> + From<BalanceError>,
{
    let overflow = || ChangeError::StrategyError(E::from(BalanceError::Overflow));

    let t_in = transparent_inputs
        .iter()
        .map(|t_in| t_in.coin().value)
        .sum::<Option<_>>()
        .ok_or_else(overflow)?;
    let t_out = transparent_outputs
        .iter()
        .map(|t_out| t_out.value())
        .sum::<Option<_>>()
        .ok_or_else(overflow)?;
    let sapling_in = sapling
        .inputs()
        .iter()
        .map(sapling_fees::InputView::<NoteRefT>::value)
        .sum::<Option<_>>()
        .ok_or_else(overflow)?;
    let sapling_out = sapling
        .outputs()
        .iter()
        .map(sapling_fees::OutputView::value)
        .sum::<Option<_>>()
        .ok_or_else(overflow)?;

    #[cfg(feature = "orchard")]
    let orchard_in = orchard
        .inputs()
        .iter()
        .map(orchard_fees::InputView::<NoteRefT>::value)
        .sum::<Option<_>>()
        .ok_or_else(overflow)?;
    #[cfg(not(feature = "orchard"))]
    let orchard_in = NonNegativeAmount::ZERO;

    #[cfg(feature = "orchard")]
    let orchard_out = orchard
        .outputs()
        .iter()
        .map(orchard_fees::OutputView::value)
        .sum::<Option<_>>()
        .ok_or_else(overflow)?;
    #[cfg(not(feature = "orchard"))]
    let orchard_out = NonNegativeAmount::ZERO;

    Ok(NetFlows {
        t_in,
        t_out,
        sapling_in,
        sapling_out,
        orchard_in,
        orchard_out,
    })
}

/// Decide which shielded pool change should go to if there is any.
pub(crate) fn single_change_output_policy(
    _net_flows: &NetFlows,
    _fallback_change_pool: ShieldedProtocol,
) -> (ShieldedProtocol, usize, usize) {
    // TODO: implement a less naive strategy for selecting the pool to which change will be sent.
    let change_pool = {
        #[cfg(feature = "orchard")]
        if _net_flows.orchard_in.is_positive() || _net_flows.orchard_out.is_positive() {
            // Send change to Orchard if we're spending any Orchard inputs or creating any Orchard outputs.
            ShieldedProtocol::Orchard
        } else if _net_flows.sapling_in.is_positive() || _net_flows.sapling_out.is_positive() {
            // Otherwise, send change to Sapling if we're spending any Sapling inputs or creating any
            // Sapling outputs, so that we avoid pool-crossing.
            ShieldedProtocol::Sapling
        } else {
            // The flows are transparent, so there may not be change. If there is, the caller
            // gets to decide where to shield it.
            _fallback_change_pool
        }
        #[cfg(not(feature = "orchard"))]
        ShieldedProtocol::Sapling
    };
    (
        change_pool,
        (change_pool == ShieldedProtocol::Sapling).into(),
        (change_pool == ShieldedProtocol::Orchard).into(),
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn single_change_output_balance<
    P: consensus::Parameters,
    NoteRefT: Clone,
    F: FeeRule,
    E,
>(
    params: &P,
    fee_rule: &F,
    target_height: BlockHeight,
    transparent_inputs: &[impl transparent::InputView],
    transparent_outputs: &[impl transparent::OutputView],
    sapling: &impl sapling_fees::BundleView<NoteRefT>,
    #[cfg(feature = "orchard")] orchard: &impl orchard_fees::BundleView<NoteRefT>,
    dust_output_policy: &DustOutputPolicy,
    default_dust_threshold: NonNegativeAmount,
    change_memo: Option<MemoBytes>,
    fallback_change_pool: ShieldedProtocol,
) -> Result<TransactionBalance, ChangeError<E, NoteRefT>>
where
    E: From<F::Error> + From<BalanceError>,
{
    let overflow = || ChangeError::StrategyError(E::from(BalanceError::Overflow));
    let underflow = || ChangeError::StrategyError(E::from(BalanceError::Underflow));

    let net_flows = calculate_net_flows::<NoteRefT, F, E>(
        transparent_inputs,
        transparent_outputs,
        sapling,
        #[cfg(feature = "orchard")]
        orchard,
    )?;
    let total_in = net_flows
        .total_in()
        .map_err(|e| ChangeError::StrategyError(E::from(e)))?;
    let total_out = net_flows
        .total_out()
        .map_err(|e| ChangeError::StrategyError(E::from(e)))?;

    #[allow(unused_variables)]
    let (change_pool, sapling_change, orchard_change) =
        single_change_output_policy(&net_flows, fallback_change_pool);

    let sapling_input_count = sapling
        .bundle_type()
        .num_spends(sapling.inputs().len())
        .map_err(ChangeError::BundleError)?;
    let sapling_output_count = sapling
        .bundle_type()
        .num_outputs(sapling.inputs().len(), sapling.outputs().len())
        .map_err(ChangeError::BundleError)?;
    let sapling_output_count_with_change = sapling
        .bundle_type()
        .num_outputs(
            sapling.inputs().len(),
            sapling.outputs().len() + sapling_change,
        )
        .map_err(ChangeError::BundleError)?;

    #[cfg(feature = "orchard")]
    let orchard_action_count = orchard
        .bundle_type()
        .num_actions(orchard.inputs().len(), orchard.outputs().len())
        .map_err(ChangeError::BundleError)?;
    #[cfg(feature = "orchard")]
    let orchard_action_count_with_change = orchard
        .bundle_type()
        .num_actions(
            orchard.inputs().len(),
            orchard.outputs().len() + orchard_change,
        )
        .map_err(ChangeError::BundleError)?;
    #[cfg(not(feature = "orchard"))]
    let orchard_action_count = 0;
    #[cfg(not(feature = "orchard"))]
    let orchard_action_count_with_change = 0;

    // Once we calculate the balance with and without change, there are five cases:
    //
    // 1. Insufficient funds even without change.
    // 2. The fee amount without change exactly cancels out the net flow balance.
    // 3. The fee amount without change is smaller than the change.
    //    3a. Insufficient funds once the change output is added.
    //    3b. The fee amount with change exactly cancels out the net flow balance.
    //    3c. The fee amount with change leaves a non-zero change value.
    //
    // Case 2 happens for the second transaction of a ZIP 320 pair. In that case
    // the transaction will be fully transparent, and there must be no change.
    //
    // If cases 2 or 3b happen for a transaction with any shielded flows, we
    // want there to be a zero-value shielded change output anyway (i.e. treat
    // case 2 as case 3, and case 3b as case 3c), because:
    // * being able to distinguish these cases potentially leaks too much
    //   information (an adversary that knows the number of external recipients
    //   and the sum of their outputs learns the sum of the inputs if no change
    //   output is present); and
    // * we will then always have an shielded output in which to put change_memo,
    //   if one is given.
    //
    // Note that using the `DustAction::AddDustToFee` policy inherently leaks
    // more information.

    let fee_without_change = fee_rule
        .fee_required(
            params,
            target_height,
            transparent_inputs.iter().map(|i| i.serialized_size()),
            transparent_outputs.iter().map(|i| i.serialized_size()),
            sapling_input_count,
            sapling_output_count,
            orchard_action_count,
        )
        .map_err(|fee_error| ChangeError::StrategyError(E::from(fee_error)))?;

    let fee_with_change = max(
        fee_without_change,
        fee_rule
            .fee_required(
                params,
                target_height,
                transparent_inputs.iter().map(|i| i.serialized_size()),
                transparent_outputs.iter().map(|i| i.serialized_size()),
                sapling_input_count,
                sapling_output_count_with_change,
                orchard_action_count_with_change,
            )
            .map_err(|fee_error| ChangeError::StrategyError(E::from(fee_error)))?,
    );

    // We don't create a fully-transparent transaction if a change memo is requested.
    let transparent = net_flows.is_transparent() && change_memo.is_none();

    let total_out_plus_fee_without_change =
        (total_out + fee_without_change).ok_or_else(overflow)?;
    let total_out_plus_fee_with_change = (total_out + fee_with_change).ok_or_else(overflow)?;

    let (change, fee) = {
        if transparent && total_in < total_out_plus_fee_without_change {
            // Case 1 for a tx with all transparent flows.
            return Err(ChangeError::InsufficientFunds {
                available: total_in,
                required: total_out_plus_fee_without_change,
            });
        } else if transparent && total_in == total_out_plus_fee_without_change {
            // Case 2 for a tx with all transparent flows.
            (vec![], fee_without_change)
        } else if total_in < total_out_plus_fee_with_change {
            // Case 3a, or case 1 or 2 with non-transparent flows.
            return Err(ChangeError::InsufficientFunds {
                available: total_in,
                required: total_out_plus_fee_with_change,
            });
        } else {
            // Case 3b or 3c.
            let proposed_change =
                (total_in - total_out_plus_fee_with_change).expect("checked above");
            let simple_case = |memo| {
                (
                    vec![ChangeValue::shielded(change_pool, proposed_change, memo)],
                    fee_with_change,
                )
            };

            let dust_threshold = dust_output_policy
                .dust_threshold()
                .unwrap_or(default_dust_threshold);

            if proposed_change < dust_threshold {
                match dust_output_policy.action() {
                    DustAction::Reject => {
                        // Always allow zero-valued change even for the `Reject` policy:
                        // * it should be allowed in order to record change memos and to improve
                        //   indistinguishability;
                        // * this case occurs in practice when sending all funds from an account;
                        // * zero-valued notes do not require witness tracking;
                        // * the effect on trial decryption overhead is small.
                        if proposed_change.is_zero() {
                            simple_case(change_memo)
                        } else {
                            let shortfall =
                                (dust_threshold - proposed_change).ok_or_else(underflow)?;

                            return Err(ChangeError::InsufficientFunds {
                                available: total_in,
                                required: (total_in + shortfall).ok_or_else(overflow)?,
                            });
                        }
                    }
                    DustAction::AllowDustChange => simple_case(change_memo),
                    DustAction::AddDustToFee => {
                        // Zero-valued change is also always allowed for this policy, but when
                        // no change memo is given, we might omit the change output instead.

                        let fee_with_dust = (total_in - total_out)
                            .expect("we already checked for sufficient funds");
                        // We can add a change output if necessary.
                        assert!(fee_with_change <= fee_with_dust);

                        let reasonable_fee =
                            (fee_with_change + (MINIMUM_FEE * 10).unwrap()).ok_or_else(overflow)?;

                        if fee_with_dust > reasonable_fee {
                            // Defend against losing money by using AddDustToFee with a too-high
                            // dust threshold.
                            simple_case(change_memo)
                        } else if change_memo.is_some() {
                            (
                                vec![ChangeValue::shielded(
                                    change_pool,
                                    NonNegativeAmount::ZERO,
                                    change_memo,
                                )],
                                fee_with_dust,
                            )
                        } else {
                            (vec![], fee_with_dust)
                        }
                    }
                }
            } else {
                simple_case(change_memo)
            }
        }
    };

    TransactionBalance::new(change, fee).map_err(|_| overflow())
}
