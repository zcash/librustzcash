use zcash_primitives::{
    consensus::{self, BlockHeight},
    memo::MemoBytes,
    transaction::{
        components::amount::{BalanceError, NonNegativeAmount},
        fees::{transparent, FeeRule},
    },
};

use crate::ShieldedProtocol;

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

pub(crate) fn single_change_output_policy<NoteRefT: Clone, F: FeeRule, E>(
    _net_flows: &NetFlows,
    _fallback_change_pool: ShieldedProtocol,
) -> Result<(ShieldedProtocol, usize, usize), ChangeError<E, NoteRefT>>
where
    E: From<F::Error> + From<BalanceError>,
{
    // TODO: implement a less naive strategy for selecting the pool to which change will be sent.
    #[cfg(feature = "orchard")]
    let (change_pool, sapling_change, orchard_change) =
        if _net_flows.orchard_in.is_positive() || _net_flows.orchard_out.is_positive() {
            // Send change to Orchard if we're spending any Orchard inputs or creating any Orchard outputs
            (ShieldedProtocol::Orchard, 0, 1)
        } else if _net_flows.sapling_in.is_positive() || _net_flows.sapling_out.is_positive() {
            // Otherwise, send change to Sapling if we're spending any Sapling inputs or creating any
            // Sapling outputs, so that we avoid pool-crossing.
            (ShieldedProtocol::Sapling, 1, 0)
        } else {
            // This is a fully-transparent transaction, so the caller gets to decide
            // where to shield change.
            match _fallback_change_pool {
                ShieldedProtocol::Orchard => (_fallback_change_pool, 0, 1),
                ShieldedProtocol::Sapling => (_fallback_change_pool, 1, 0),
            }
        };
    #[cfg(not(feature = "orchard"))]
    let (change_pool, sapling_change, orchard_change) = (ShieldedProtocol::Sapling, 1, 0);

    Ok((change_pool, sapling_change, orchard_change))
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
    _fallback_change_pool: ShieldedProtocol,
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
    let (change_pool, sapling_change, _orchard_change) =
        single_change_output_policy::<NoteRefT, F, E>(&net_flows, _fallback_change_pool)?;

    let sapling_input_count = sapling
        .bundle_type()
        .num_spends(sapling.inputs().len())
        .map_err(ChangeError::BundleError)?;
    let sapling_output_count = sapling
        .bundle_type()
        .num_outputs(
            sapling.inputs().len(),
            sapling.outputs().len() + sapling_change,
        )
        .map_err(ChangeError::BundleError)?;

    #[cfg(feature = "orchard")]
    let orchard_action_count = orchard
        .bundle_type()
        .num_actions(
            orchard.inputs().len(),
            orchard.outputs().len() + _orchard_change,
        )
        .map_err(ChangeError::BundleError)?;
    #[cfg(not(feature = "orchard"))]
    let orchard_action_count = 0;

    let fee_amount = fee_rule
        .fee_required(
            params,
            target_height,
            transparent_inputs,
            transparent_outputs,
            sapling_input_count,
            sapling_output_count,
            orchard_action_count,
        )
        .map_err(|fee_error| ChangeError::StrategyError(E::from(fee_error)))?;

    let total_in =
        (net_flows.t_in + net_flows.sapling_in + net_flows.orchard_in).ok_or_else(overflow)?;
    let total_out = (net_flows.t_out + net_flows.sapling_out + net_flows.orchard_out + fee_amount)
        .ok_or_else(overflow)?;

    let proposed_change = (total_in - total_out).ok_or(ChangeError::InsufficientFunds {
        available: total_in,
        required: total_out,
    })?;

    if proposed_change.is_zero() {
        TransactionBalance::new(vec![], fee_amount).map_err(|_| overflow())
    } else {
        let dust_threshold = dust_output_policy
            .dust_threshold()
            .unwrap_or(default_dust_threshold);

        if proposed_change < dust_threshold {
            match dust_output_policy.action() {
                DustAction::Reject => {
                    let shortfall = (dust_threshold - proposed_change).ok_or_else(underflow)?;

                    Err(ChangeError::InsufficientFunds {
                        available: total_in,
                        required: (total_in + shortfall).ok_or_else(overflow)?,
                    })
                }
                DustAction::AllowDustChange => TransactionBalance::new(
                    vec![ChangeValue::new(change_pool, proposed_change, change_memo)],
                    fee_amount,
                )
                .map_err(|_| overflow()),
                DustAction::AddDustToFee => TransactionBalance::new(
                    vec![],
                    (fee_amount + proposed_change).ok_or_else(overflow)?,
                )
                .map_err(|_| overflow()),
            }
        } else {
            TransactionBalance::new(
                vec![ChangeValue::new(change_pool, proposed_change, change_memo)],
                fee_amount,
            )
            .map_err(|_| overflow())
        }
    }
}
