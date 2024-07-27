use core::cmp::{max, min};

use zcash_primitives::{
    consensus::{self, BlockHeight},
    memo::MemoBytes,
    transaction::{
        components::amount::{BalanceError, NonNegativeAmount},
        fees::{transparent, zip317::MINIMUM_FEE, zip317::P2PKH_STANDARD_OUTPUT_SIZE, FeeRule},
    },
};
use zcash_protocol::ShieldedProtocol;

use super::{
    sapling as sapling_fees, ChangeError, ChangeValue, DustAction, DustOutputPolicy,
    EphemeralBalance, TransactionBalance,
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
    ephemeral_balance: Option<&EphemeralBalance>,
) -> Result<NetFlows, ChangeError<E, NoteRefT>>
where
    E: From<F::Error> + From<BalanceError>,
{
    let overflow = || ChangeError::StrategyError(E::from(BalanceError::Overflow));

    let t_in = transparent_inputs
        .iter()
        .map(|t_in| t_in.coin().value)
        .chain(ephemeral_balance.and_then(|b| b.ephemeral_input_amount()))
        .sum::<Option<_>>()
        .ok_or_else(overflow)?;
    let t_out = transparent_outputs
        .iter()
        .map(|t_out| t_out.value())
        .chain(ephemeral_balance.and_then(|b| b.ephemeral_output_amount()))
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
    change_memo: Option<&MemoBytes>,
    fallback_change_pool: ShieldedProtocol,
    marginal_fee: NonNegativeAmount,
    grace_actions: usize,
    ephemeral_balance: Option<&EphemeralBalance>,
) -> Result<TransactionBalance, ChangeError<E, NoteRefT>>
where
    E: From<F::Error> + From<BalanceError>,
{
    // The change memo, if any, must be attached to the change in the intermediate step that
    // produces the ephemeral output, and so it should be discarded in the ultimate step; this is
    // distinguished by identifying that this transaction has ephemeral inputs.
    let change_memo = change_memo.filter(|_| ephemeral_balance.map_or(true, |b| !b.is_input()));

    let overflow = || ChangeError::StrategyError(E::from(BalanceError::Overflow));
    let underflow = || ChangeError::StrategyError(E::from(BalanceError::Underflow));

    let net_flows = calculate_net_flows::<NoteRefT, F, E>(
        transparent_inputs,
        transparent_outputs,
        sapling,
        #[cfg(feature = "orchard")]
        orchard,
        ephemeral_balance,
    )?;

    #[allow(unused_variables)]
    let (change_pool, sapling_change, orchard_change) =
        single_change_output_policy(&net_flows, fallback_change_pool);

    #[cfg(not(feature = "orchard"))]
    assert!(change_pool != ShieldedProtocol::Orchard);

    // We don't create a fully-transparent transaction if a change memo is used.
    let transparent = net_flows.is_transparent() && change_memo.is_none();

    // If we have a non-zero marginal fee, we need to check for uneconomic inputs.
    // This is basically assuming that fee rules with non-zero marginal fee are
    // "ZIP 317-like", but we can generalize later if needed.
    if marginal_fee.is_positive() {
        // Is it certain that there will be a change output? If it is not certain,
        // we should call `check_for_uneconomic_inputs` with `possible_change`
        // including both possibilities.
        let possible_change =
            // These are the situations where we might not have a change output.
            if transparent || (dust_output_policy.action() == DustAction::AddDustToFee && change_memo.is_none()) {
                vec![(0, 0, 0), (0, sapling_change, orchard_change)]
            } else {
                vec![(0, sapling_change, orchard_change)]
            };

        check_for_uneconomic_inputs(
            transparent_inputs,
            transparent_outputs,
            sapling,
            #[cfg(feature = "orchard")]
            orchard,
            marginal_fee,
            grace_actions,
            &possible_change[..],
            ephemeral_balance,
        )?;
    }

    let total_in = net_flows
        .total_in()
        .map_err(|e| ChangeError::StrategyError(E::from(e)))?;
    let total_out = net_flows
        .total_out()
        .map_err(|e| ChangeError::StrategyError(E::from(e)))?;

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
    //   if one is used.
    //
    // Note that using the `DustAction::AddDustToFee` policy inherently leaks
    // more information.

    let transparent_input_sizes = transparent_inputs
        .iter()
        .map(|i| i.serialized_size())
        .chain(
            ephemeral_balance
                .and_then(|b| b.ephemeral_input_amount())
                .map(|_| transparent::InputSize::STANDARD_P2PKH),
        );
    let transparent_output_sizes = transparent_outputs
        .iter()
        .map(|i| i.serialized_size())
        .chain(
            ephemeral_balance
                .and_then(|b| b.ephemeral_output_amount())
                .map(|_| P2PKH_STANDARD_OUTPUT_SIZE),
        );

    let fee_without_change = fee_rule
        .fee_required(
            params,
            target_height,
            transparent_input_sizes.clone(),
            transparent_output_sizes.clone(),
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
                transparent_input_sizes,
                transparent_output_sizes,
                sapling_input_count,
                sapling_output_count_with_change,
                orchard_action_count_with_change,
            )
            .map_err(|fee_error| ChangeError::StrategyError(E::from(fee_error)))?,
    );

    let total_out_plus_fee_without_change =
        (total_out + fee_without_change).ok_or_else(overflow)?;
    let total_out_plus_fee_with_change = (total_out + fee_with_change).ok_or_else(overflow)?;

    #[allow(unused_mut)]
    let (mut change, fee) = {
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
            let simple_case = || {
                (
                    vec![ChangeValue::shielded(
                        change_pool,
                        proposed_change,
                        change_memo.cloned(),
                    )],
                    fee_with_change,
                )
            };

            let change_dust_threshold = dust_output_policy
                .dust_threshold()
                .unwrap_or(default_dust_threshold);

            if proposed_change < change_dust_threshold {
                match dust_output_policy.action() {
                    DustAction::Reject => {
                        // Always allow zero-valued change even for the `Reject` policy:
                        // * it should be allowed in order to record change memos and to improve
                        //   indistinguishability;
                        // * this case occurs in practice when sending all funds from an account;
                        // * zero-valued notes do not require witness tracking;
                        // * the effect on trial decryption overhead is small.
                        if proposed_change.is_zero() {
                            simple_case()
                        } else {
                            let shortfall =
                                (change_dust_threshold - proposed_change).ok_or_else(underflow)?;

                            return Err(ChangeError::InsufficientFunds {
                                available: total_in,
                                required: (total_in + shortfall).ok_or_else(overflow)?,
                            });
                        }
                    }
                    DustAction::AllowDustChange => simple_case(),
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
                            simple_case()
                        } else if change_memo.is_some() {
                            (
                                vec![ChangeValue::shielded(
                                    change_pool,
                                    NonNegativeAmount::ZERO,
                                    change_memo.cloned(),
                                )],
                                fee_with_dust,
                            )
                        } else {
                            (vec![], fee_with_dust)
                        }
                    }
                }
            } else {
                simple_case()
            }
        }
    };
    #[cfg(feature = "transparent-inputs")]
    change.extend(
        ephemeral_balance
            .and_then(|b| b.ephemeral_output_amount())
            .map(ChangeValue::ephemeral_transparent),
    );

    // Any error here can only be overflow, because we checked that `change_pool`
    // is supported and only constructed `change` to that pool.
    TransactionBalance::new(change, fee).map_err(|_| overflow())
}

/// Returns a `[ChangeStrategy::DustInputs]` error if some of the inputs provided
/// to the transaction have value less than the marginal fee, and could not be
/// determined to have any economic value in the context of this input selection.
///
/// This determination is potentially conservative in the sense that outputs
/// with value less than the marginal fee might be excluded, even though in
/// practice they would not cause the fee to increase. Outputs with value
/// greater than the marginal fee will never be excluded.
///
/// `possible_change` is a slice of `(transparent_change, sapling_change, orchard_change)`
/// tuples indicating possible combinations of how many change outputs (0 or 1)
/// might be included in the transaction for each pool. The shape of the tuple
/// does not depend on which protocol features are enabled.
#[allow(clippy::too_many_arguments)]
pub(crate) fn check_for_uneconomic_inputs<NoteRefT: Clone, E>(
    transparent_inputs: &[impl transparent::InputView],
    transparent_outputs: &[impl transparent::OutputView],
    sapling: &impl sapling_fees::BundleView<NoteRefT>,
    #[cfg(feature = "orchard")] orchard: &impl orchard_fees::BundleView<NoteRefT>,
    marginal_fee: NonNegativeAmount,
    grace_actions: usize,
    possible_change: &[(usize, usize, usize)],
    ephemeral_balance: Option<&EphemeralBalance>,
) -> Result<(), ChangeError<E, NoteRefT>> {
    let mut t_dust: Vec<_> = transparent_inputs
        .iter()
        .filter_map(|i| {
            // For now, we're just assuming P2PKH inputs, so we don't check the
            // size of the input script.
            if i.coin().value <= marginal_fee {
                Some(i.outpoint().clone())
            } else {
                None
            }
        })
        .collect();

    let mut s_dust: Vec<_> = sapling
        .inputs()
        .iter()
        .filter_map(|i| {
            if sapling_fees::InputView::<NoteRefT>::value(i) <= marginal_fee {
                Some(sapling_fees::InputView::<NoteRefT>::note_id(i).clone())
            } else {
                None
            }
        })
        .collect();

    #[cfg(feature = "orchard")]
    let mut o_dust: Vec<NoteRefT> = orchard
        .inputs()
        .iter()
        .filter_map(|i| {
            if orchard_fees::InputView::<NoteRefT>::value(i) <= marginal_fee {
                Some(orchard_fees::InputView::<NoteRefT>::note_id(i).clone())
            } else {
                None
            }
        })
        .collect();
    #[cfg(not(feature = "orchard"))]
    let mut o_dust: Vec<NoteRefT> = vec![];

    // If we don't have any dust inputs, there is nothing to check.
    if t_dust.is_empty() && s_dust.is_empty() && o_dust.is_empty() {
        return Ok(());
    }

    let (t_inputs_len, t_outputs_len) = (
        transparent_inputs.len() + usize::from(ephemeral_balance.map_or(false, |b| b.is_input())),
        transparent_outputs.len() + usize::from(ephemeral_balance.map_or(false, |b| b.is_output())),
    );
    let (s_inputs_len, s_outputs_len) = (sapling.inputs().len(), sapling.outputs().len());
    #[cfg(feature = "orchard")]
    let (o_inputs_len, o_outputs_len) = (orchard.inputs().len(), orchard.outputs().len());
    #[cfg(not(feature = "orchard"))]
    let (o_inputs_len, o_outputs_len) = (0usize, 0usize);

    let t_non_dust = t_inputs_len.checked_sub(t_dust.len()).unwrap();
    let s_non_dust = s_inputs_len.checked_sub(s_dust.len()).unwrap();
    let o_non_dust = o_inputs_len.checked_sub(o_dust.len()).unwrap();

    // Return the number of allowed dust inputs from each pool.
    let allowed_dust = |(t_change, s_change, o_change): &(usize, usize, usize)| {
        // Here we assume a "ZIP 317-like" fee model in which the existence of an output
        // to a given pool implies that a corresponding input from that pool can be
        // provided without increasing the fee. (This is also likely to be true for
        // future fee models if we do not want to penalize use of Orchard relative to
        // other pools.)
        //
        // Under that assumption, we want to calculate the maximum number of dust inputs
        // from each pool, out of the ones we actually have, that can be economically
        // spent along with the non-dust inputs. Get an initial estimate by calculating
        // the number of dust inputs in each pool that will be allowed regardless of
        // padding or grace.

        let t_allowed = min(
            t_dust.len(),
            (t_outputs_len + t_change).saturating_sub(t_non_dust),
        );
        let s_allowed = min(
            s_dust.len(),
            (s_outputs_len + s_change).saturating_sub(s_non_dust),
        );
        let o_allowed = min(
            o_dust.len(),
            (o_outputs_len + o_change).saturating_sub(o_non_dust),
        );

        // We'll be spending the non-dust and allowed dust in each pool.
        let t_req_inputs = t_non_dust + t_allowed;
        let s_req_inputs = s_non_dust + s_allowed;
        #[cfg(feature = "orchard")]
        let o_req_inputs = o_non_dust + o_allowed;

        // This calculates the hypothetical number of actions with given extra inputs,
        // for ZIP 317 and the padding rules in effect. The padding rules for each
        // pool are subtle (they also depend on `bundle_required` for example), so we
        // must actually call them rather than try to predict their effect. To tell
        // whether we can freely add an extra input from a given pool, we need to call
        // them both with and without that input; if the number of actions does not
        // increase, then the input is free to add.
        let hypothetical_actions = |t_extra, s_extra, _o_extra| {
            let s_spend_count = sapling
                .bundle_type()
                .num_spends(s_req_inputs + s_extra)
                .map_err(ChangeError::BundleError)?;

            let s_output_count = sapling
                .bundle_type()
                .num_outputs(s_req_inputs + s_extra, s_outputs_len + s_change)
                .map_err(ChangeError::BundleError)?;

            #[cfg(feature = "orchard")]
            let o_action_count = orchard
                .bundle_type()
                .num_actions(o_req_inputs + _o_extra, o_outputs_len + o_change)
                .map_err(ChangeError::BundleError)?;
            #[cfg(not(feature = "orchard"))]
            let o_action_count = 0;

            // To calculate the number of unused actions, we assume that transparent inputs
            // and outputs are P2PKH.
            Ok(max(t_req_inputs + t_extra, t_outputs_len + t_change)
                + max(s_spend_count, s_output_count)
                + o_action_count)
        };

        // First calculate the baseline number of logical actions with only the definitely
        // allowed inputs estimated above. If it is less than `grace_actions`, try to allocate
        // a grace input first to transparent dust, then to Sapling dust, then to Orchard dust.
        // If the number of actions increases, it was not possible to allocate that input for
        // free. This approach is sufficient because at most one such input can be allocated,
        // since `grace_actions` is at most 2 for ZIP 317 and there must be at least one
        // logical action. (If `grace_actions` were greater than 2 then the code would still
        // be correct, it would just not find all potential extra inputs.)

        let baseline = hypothetical_actions(0, 0, 0)?;

        let (t_extra, s_extra, o_extra) = if baseline >= grace_actions {
            (0, 0, 0)
        } else if t_dust.len() > t_allowed && hypothetical_actions(1, 0, 0)? <= baseline {
            (1, 0, 0)
        } else if s_dust.len() > s_allowed && hypothetical_actions(0, 1, 0)? <= baseline {
            (0, 1, 0)
        } else if o_dust.len() > o_allowed && hypothetical_actions(0, 0, 1)? <= baseline {
            (0, 0, 1)
        } else {
            (0, 0, 0)
        };
        Ok((
            t_allowed + t_extra,
            s_allowed + s_extra,
            o_allowed + o_extra,
        ))
    };

    // Find the least number of allowed dust inputs for each pool for any `possible_change`.
    let (t_allowed, s_allowed, o_allowed) = possible_change
        .iter()
        .map(allowed_dust)
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .reduce(|(a, b, c), (x, y, z)| (min(a, x), min(b, y), min(c, z)))
        .expect("possible_change is nonempty");

    // The inputs in the tail of each list after the first `*_allowed` are returned as uneconomic.
    // The caller should order the inputs from most to least preferred to spend.
    let t_dust = t_dust.split_off(t_allowed);
    let s_dust = s_dust.split_off(s_allowed);
    let o_dust = o_dust.split_off(o_allowed);

    if t_dust.is_empty() && s_dust.is_empty() && o_dust.is_empty() {
        Ok(())
    } else {
        Err(ChangeError::DustInputs {
            transparent: t_dust,
            sapling: s_dust,
            #[cfg(feature = "orchard")]
            orchard: o_dust,
        })
    }
}
