use core::cmp::{Ordering, max, min};
use std::num::{NonZeroU64, NonZeroUsize};

use zcash_primitives::transaction::fees::{
    FeeRule, transparent, zip317::MINIMUM_FEE, zip317::P2PKH_STANDARD_OUTPUT_SIZE,
};
use zcash_protocol::{
    ShieldedPool,
    consensus::{self, BlockHeight, NetworkUpgrade},
    memo::MemoBytes,
    value::{BalanceError, Zatoshis},
};

use crate::data_api::{AccountMeta, wallet::TargetHeight};

use super::{
    ChangeError, ChangeValue, DustAction, DustOutputPolicy, EphemeralBalance, SplitPolicy,
    TransactionBalance, sapling as sapling_fees,
};

#[cfg(feature = "transparent-inputs")]
use super::TransparentChangePolicy;
#[cfg(feature = "orchard")]
use super::orchard as orchard_fees;
#[cfg(feature = "transparent-inputs")]
use ::transparent::address::{Script, TransparentAddress};
#[cfg(feature = "transparent-inputs")]
use zcash_script::script;

pub(crate) struct NetFlows {
    t_in: Zatoshis,
    t_out: Zatoshis,
    sapling_in: Zatoshis,
    sapling_out: Zatoshis,
    orchard_in: Zatoshis,
    orchard_out: Zatoshis,
    // Value flowing through the Ironwood bundle, accounted separately from
    // Orchard because V6 transactions carry distinct Orchard and Ironwood
    // bundles. Splitting output value between the Orchard and Ironwood views
    // leaves `total_in`/`total_out` unchanged; the separate fields exist so each
    // bundle's action count can be derived from its own inputs and outputs.
    ironwood_in: Zatoshis,
    ironwood_out: Zatoshis,
}

impl NetFlows {
    fn total_in(&self) -> Result<Zatoshis, BalanceError> {
        (self.t_in + self.sapling_in + self.orchard_in + self.ironwood_in)
            .ok_or(BalanceError::Overflow)
    }
    fn total_out(&self) -> Result<Zatoshis, BalanceError> {
        (self.t_out + self.sapling_out + self.orchard_out + self.ironwood_out)
            .ok_or(BalanceError::Overflow)
    }
    /// Returns true iff the flows excluding change are fully transparent.
    fn is_transparent(&self) -> bool {
        !(self.sapling_in.is_positive()
            || self.sapling_out.is_positive()
            || self.orchard_in.is_positive()
            || self.orchard_out.is_positive()
            || self.ironwood_in.is_positive()
            || self.ironwood_out.is_positive())
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn calculate_net_flows<NoteRefT: Clone, F: FeeRule, E>(
    transparent_inputs: &[impl transparent::InputView],
    transparent_outputs: &[impl transparent::OutputView],
    sapling: &impl sapling_fees::BundleView<NoteRefT>,
    #[cfg(feature = "orchard")] orchard: &impl orchard_fees::BundleView<NoteRefT>,
    #[cfg(feature = "orchard")] ironwood: &impl orchard_fees::BundleView<NoteRefT>,
    ephemeral_balance: Option<EphemeralBalance>,
) -> Result<NetFlows, ChangeError<E, NoteRefT>>
where
    E: From<F::Error> + From<BalanceError>,
{
    let overflow = || ChangeError::StrategyError(E::from(BalanceError::Overflow));

    let t_in = transparent_inputs
        .iter()
        .map(|t_in| t_in.coin().value())
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
    let orchard_in = Zatoshis::ZERO;

    #[cfg(feature = "orchard")]
    let orchard_out = orchard
        .outputs()
        .iter()
        .map(orchard_fees::OutputView::value)
        .sum::<Option<_>>()
        .ok_or_else(overflow)?;
    #[cfg(not(feature = "orchard"))]
    let orchard_out = Zatoshis::ZERO;

    #[cfg(feature = "orchard")]
    let ironwood_in = ironwood
        .inputs()
        .iter()
        .map(orchard_fees::InputView::<NoteRefT>::value)
        .sum::<Option<_>>()
        .ok_or_else(overflow)?;
    #[cfg(not(feature = "orchard"))]
    let ironwood_in = Zatoshis::ZERO;

    #[cfg(feature = "orchard")]
    let ironwood_out = ironwood
        .outputs()
        .iter()
        .map(orchard_fees::OutputView::value)
        .sum::<Option<_>>()
        .ok_or_else(overflow)?;
    #[cfg(not(feature = "orchard"))]
    let ironwood_out = Zatoshis::ZERO;

    Ok(NetFlows {
        t_in,
        t_out,
        sapling_in,
        sapling_out,
        orchard_in,
        orchard_out,
        ironwood_in,
        ironwood_out,
    })
}

/// Decide which shielded pool change should go to if there is any.
///
/// `max_change_value` is an upper bound on the value of the change the transaction will
/// produce: the value that would remain if it paid only the minimum (changeless) fee.
/// After Ironwood activation it determines whether change may be returned to the Orchard
/// pool without violating the turnstile requirement that the pool's balance strictly
/// decrease.
pub(crate) fn select_change_pool(
    _net_flows: &NetFlows,
    _fallback_change_pool: ShieldedPool,
    _ironwood_active: bool,
    _max_change_value: Zatoshis,
) -> ShieldedPool {
    // TODO: implement a less naive strategy for selecting the pool to which change will be sent.
    #[cfg(feature = "orchard")]
    {
        let preferred = if _net_flows.orchard_in.is_positive()
            || _net_flows.orchard_out.is_positive()
        {
            // Send change to Orchard if we're spending any Orchard inputs or creating any Orchard outputs.
            ShieldedPool::Orchard
        } else if _net_flows.ironwood_in.is_positive() || _net_flows.ironwood_out.is_positive() {
            // Send change to Ironwood if we're spending Ironwood inputs or creating Ironwood outputs
            // (and no Orchard flows), so that change from an Ironwood spend stays in the Ironwood pool
            // rather than crossing the turnstile back into Orchard.
            ShieldedPool::Ironwood
        } else if _net_flows.sapling_in.is_positive() || _net_flows.sapling_out.is_positive() {
            // Otherwise, send change to Sapling if we're spending any Sapling inputs or creating any
            // Sapling outputs, so that we avoid pool-crossing.
            ShieldedPool::Sapling
        } else {
            // The flows are transparent, so there may not be change. If there is, the caller
            // gets to decide where to shield it.
            _fallback_change_pool
        };

        // After Ironwood activation, the turnstile forbids value from entering the
        // Orchard pool: change may return to Orchard only when the transaction spends
        // Orchard notes, and only if strictly less value returns to the pool than the
        // notes remove from it. Change that cannot go to Orchard flows onward to the
        // Ironwood pool.
        if _ironwood_active
            && preferred == ShieldedPool::Orchard
            && (!_net_flows.orchard_in.is_positive() || _max_change_value >= _net_flows.orchard_in)
        {
            ShieldedPool::Ironwood
        } else {
            preferred
        }
    }
    #[cfg(not(feature = "orchard"))]
    ShieldedPool::Sapling
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct OutputManifest {
    transparent: usize,
    sapling: usize,
    orchard: usize,
    ironwood: usize,
}

impl OutputManifest {
    const ZERO: OutputManifest = OutputManifest {
        transparent: 0,
        sapling: 0,
        orchard: 0,
        ironwood: 0,
    };

    pub(crate) fn sapling(&self) -> usize {
        self.sapling
    }

    pub(crate) fn orchard(&self) -> usize {
        self.orchard
    }

    pub(crate) fn ironwood(&self) -> usize {
        self.ironwood
    }

    pub(crate) fn total_shielded(&self) -> usize {
        self.sapling + self.orchard + self.ironwood
    }
}

pub(crate) struct SinglePoolBalanceConfig<'a, P, F> {
    params: &'a P,
    fee_rule: &'a F,
    dust_output_policy: &'a DustOutputPolicy,
    default_dust_threshold: Zatoshis,
    split_policy: &'a SplitPolicy,
    fallback_change_pool: ShieldedPool,
    #[cfg(feature = "transparent-inputs")]
    transparent_change_policy: TransparentChangePolicy,
    marginal_fee: Zatoshis,
    grace_actions: usize,
}

impl<'a, P, F> SinglePoolBalanceConfig<'a, P, F> {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        params: &'a P,
        fee_rule: &'a F,
        dust_output_policy: &'a DustOutputPolicy,
        default_dust_threshold: Zatoshis,
        split_policy: &'a SplitPolicy,
        fallback_change_pool: ShieldedPool,
        #[cfg(feature = "transparent-inputs")] transparent_change_policy: TransparentChangePolicy,
        marginal_fee: Zatoshis,
        grace_actions: usize,
    ) -> Self {
        Self {
            params,
            fee_rule,
            dust_output_policy,
            default_dust_threshold,
            split_policy,
            fallback_change_pool,
            #[cfg(feature = "transparent-inputs")]
            transparent_change_policy,
            marginal_fee,
            grace_actions,
        }
    }
}

/// Determines the destination for transparent change, when transparent change is to be
/// produced.
///
/// Returns `Ok(None)` if no transparent input was funded via P2SH (change should be sent to
/// an internal-scope address of the wallet), `Ok(Some(addr))` if every transparent input was
/// funded by the single P2SH address `addr` (change should be returned to that address), and
/// `Err(input_addresses)` if P2SH-funded inputs are present but the inputs do not all share a
/// single originating address.
#[cfg(feature = "transparent-inputs")]
fn transparent_change_destination(
    transparent_inputs: &[impl transparent::InputView],
) -> Result<Option<TransparentAddress>, Vec<TransparentAddress>> {
    let mut input_addresses: Vec<Option<TransparentAddress>> = vec![];
    for i in transparent_inputs {
        let addr = script::PubKey::parse(&i.coin().script_pubkey().0)
            .ok()
            .as_ref()
            .and_then(TransparentAddress::from_script_pubkey);
        if !input_addresses.contains(&addr) {
            input_addresses.push(addr);
        }
    }

    let has_p2sh = input_addresses
        .iter()
        .any(|a| matches!(a, Some(TransparentAddress::ScriptHash(_))));
    if !has_p2sh {
        Ok(None)
    } else {
        match &input_addresses[..] {
            [Some(addr)] => Ok(Some(*addr)),
            _ => Err(input_addresses.iter().flatten().copied().collect()),
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn single_pool_output_balance<P: consensus::Parameters, NoteRefT: Clone, F: FeeRule, E>(
    cfg: SinglePoolBalanceConfig<P, F>,
    wallet_meta: Option<&AccountMeta>,
    target_height: TargetHeight,
    transparent_inputs: &[impl transparent::InputView],
    transparent_outputs: &[impl transparent::OutputView],
    sapling: &impl sapling_fees::BundleView<NoteRefT>,
    #[cfg(feature = "orchard")] orchard: &impl orchard_fees::BundleView<NoteRefT>,
    #[cfg(feature = "orchard")] ironwood: &impl orchard_fees::BundleView<NoteRefT>,
    // The transactional bundle type the transaction builder will use for both the
    // Orchard and Ironwood bundles; the action counts computed here must match it so
    // the builder's exact-balance check succeeds (see
    // `orchard_fees::transactional_action_count`).
    #[cfg(feature = "orchard")] orchard_pool_bundle_type: ::orchard::builder::BundleType,
    change_memo: Option<&MemoBytes>,
    ephemeral_balance: Option<EphemeralBalance>,
) -> Result<TransactionBalance, ChangeError<E, NoteRefT>>
where
    E: From<F::Error> + From<BalanceError>,
{
    // The change memo, if any, must be attached to the change in the intermediate step that
    // produces the ephemeral output, and so it should be discarded in the ultimate step; this is
    // distinguished by identifying that this transaction has ephemeral inputs.
    let change_memo = change_memo.filter(|_| ephemeral_balance.is_none_or(|b| !b.is_input()));

    let overflow = || ChangeError::StrategyError(E::from(BalanceError::Overflow));
    let underflow = || ChangeError::StrategyError(E::from(BalanceError::Underflow));

    let net_flows = calculate_net_flows::<NoteRefT, F, E>(
        transparent_inputs,
        transparent_outputs,
        sapling,
        #[cfg(feature = "orchard")]
        orchard,
        #[cfg(feature = "orchard")]
        ironwood,
        ephemeral_balance,
    )?;

    // We don't create a fully-transparent transaction if a change memo is used.
    let fully_transparent = net_flows.is_transparent() && change_memo.is_none();

    // Whether change should be returned to the transparent pool instead of being shielded.
    // Transparent change is only ever produced when the flows of the transaction are fully
    // transparent, so that shielded flows never leak change information to the transparent
    // pool.
    #[cfg(feature = "transparent-inputs")]
    let wants_transparent_change = fully_transparent
        && cfg.transparent_change_policy == TransparentChangePolicy::TransparentChangeAllowed;
    #[cfg(not(feature = "transparent-inputs"))]
    let wants_transparent_change = false;

    // When transparent change is to be produced, determine the address to which it should be
    // returned. Resolution failure (ambiguous P2SH sources) is deferred: it only matters if a
    // non-zero change output actually has to be emitted, so the error is raised lazily at
    // emission rather than here.
    #[cfg(feature = "transparent-inputs")]
    let change_destination = if wants_transparent_change {
        transparent_change_destination(transparent_inputs)
    } else {
        Ok(None)
    };

    let total_in = net_flows
        .total_in()
        .map_err(|e| ChangeError::StrategyError(E::from(e)))?;
    let subtotal_out = net_flows
        .total_out()
        .map_err(|e| ChangeError::StrategyError(E::from(e)))?;

    let sapling_input_count = sapling
        .bundle_type()
        .num_spends(sapling.inputs().len())
        .map_err(ChangeError::BundleError)?;
    let sapling_output_count = |change_count| {
        sapling
            .bundle_type()
            .num_outputs(
                sapling.inputs().len(),
                sapling.outputs().len() + change_count,
            )
            .map_err(ChangeError::BundleError)
    };

    #[cfg(feature = "orchard")]
    let orchard_action_count = |change_count| {
        orchard_fees::transactional_action_count(
            orchard_pool_bundle_type,
            orchard.bundle_version(),
            orchard.inputs().len(),
            orchard.outputs().len() + change_count,
        )
        .map_err(ChangeError::BundleError)
    };
    #[cfg(not(feature = "orchard"))]
    let orchard_action_count = |change_count: usize| -> Result<usize, ChangeError<E, NoteRefT>> {
        if change_count != 0 {
            Err(ChangeError::BundleError(
                "Nonzero Orchard change requested but the `orchard` feature is not enabled.",
            ))
        } else {
            Ok(0)
        }
    };

    // The Ironwood bundle is accounted separately from Orchard: a V6 transaction
    // carries distinct Orchard and Ironwood bundles, each padded to its own
    // action floor. Callers route Ironwood inputs/outputs into the `ironwood`
    // view; it is empty (contributing no actions) when nothing targets the
    // Ironwood pool.
    #[cfg(feature = "orchard")]
    let ironwood_action_count = |change_count| {
        orchard_fees::transactional_action_count(
            orchard_pool_bundle_type,
            ironwood.bundle_version(),
            ironwood.inputs().len(),
            ironwood.outputs().len() + change_count,
        )
        .map_err(ChangeError::BundleError)
    };
    #[cfg(not(feature = "orchard"))]
    let ironwood_action_count = |change_count: usize| -> Result<usize, ChangeError<E, NoteRefT>> {
        if change_count != 0 {
            Err(ChangeError::BundleError(
                "Nonzero Ironwood change requested but the `orchard` feature is not enabled.",
            ))
        } else {
            Ok(0)
        }
    };

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

    // The serialized size of the transparent change output, when change is to be returned to
    // the transparent pool. When the change destination resolves to a single P2SH source
    // address, the true `TxOut` size for that address's script is used; otherwise (an
    // internal-scope P2PKH change address, or an unresolved/ambiguous destination) the
    // standard P2PKH size is used. The P2PKH size is an upper bound on the size of any change
    // output this function will produce, so the fee computed with it remains valid.
    #[cfg(feature = "transparent-inputs")]
    let transparent_change_output_size =
        wants_transparent_change.then(|| match &change_destination {
            // The serialized size of a `TxOut` is the 8-byte value field plus the
            // serialized size of the script pubkey.
            Ok(Some(addr)) => 8 + Script::from(addr.script()).serialized_size(),
            _ => P2PKH_STANDARD_OUTPUT_SIZE,
        });
    #[cfg(not(feature = "transparent-inputs"))]
    let transparent_change_output_size: Option<usize> = None;

    // Once we calculate the balance with minimum fee (i.e. with no change),
    // there are three cases:
    //
    // 1. Insufficient funds even with minimum fee.
    // 2. The minimum fee exactly cancels out the net flow balance.
    // 3. The minimum fee is smaller than the change.
    //
    // If case 2 happens for a transaction with any shielded flows, we want there
    // to be a zero-value shielded change output anyway (i.e. treat this like case 3),
    // because:
    // * being able to distinguish these cases potentially leaks too much
    //   information (an adversary that knows the number of external recipients
    //   and the sum of their outputs learns the sum of the inputs if no change
    //   output is present); and
    // * we will then always have an shielded output in which to put change_memo,
    //   if one is used.
    //
    // Note that using the `DustAction::AddDustToFee` policy inherently leaks
    // more information.

    let min_fee = cfg
        .fee_rule
        .fee_required(
            cfg.params,
            BlockHeight::from(target_height),
            transparent_input_sizes.clone(),
            transparent_output_sizes.clone(),
            sapling_input_count,
            sapling_output_count(0)?,
            orchard_action_count(0)?,
            ironwood_action_count(0)?,
        )
        .map_err(|fee_error| ChangeError::StrategyError(E::from(fee_error)))?;

    let total_out_with_min_fee = (subtotal_out + min_fee).ok_or_else(overflow)?;

    // The value that would remain if the transaction paid only the minimum (changeless)
    // fee is an upper bound on the change value: the fee never falls below `min_fee`.
    let change_pool = select_change_pool(
        &net_flows,
        cfg.fallback_change_pool,
        cfg.params
            .is_nu_active(NetworkUpgrade::Nu6_3, target_height.into()),
        (total_in - total_out_with_min_fee).unwrap_or(Zatoshis::ZERO),
    );

    let (target_change_count, target_change_counts) = if wants_transparent_change {
        // Transparent change is always emitted as a single output; the note-splitting policy
        // exists to improve the spendability of shielded notes and does not apply to
        // transparent outputs.
        (
            1,
            OutputManifest {
                transparent: 1,
                sapling: 0,
                orchard: 0,
                ironwood: 0,
            },
        )
    } else {
        let target_change_count = wallet_meta.map_or(1, |m| {
            usize::from(cfg.split_policy.target_output_count)
                // If we cannot determine a total note count, fall back to a single output
                .saturating_sub(m.total_note_count().unwrap_or(usize::MAX))
                .max(1)
        });
        let target_change_counts = OutputManifest {
            transparent: 0,
            sapling: if change_pool == ShieldedPool::Sapling {
                target_change_count
            } else {
                0
            },
            orchard: if change_pool == ShieldedPool::Orchard {
                target_change_count
            } else {
                0
            },
            ironwood: if change_pool == ShieldedPool::Ironwood {
                target_change_count
            } else {
                0
            },
        };
        assert!(target_change_counts.total_shielded() == target_change_count);
        (target_change_count, target_change_counts)
    };

    // If we have a non-zero marginal fee, we need to check for uneconomic inputs.
    // This is basically assuming that fee rules with non-zero marginal fee are
    // "ZIP 317-like", but we can generalize later if needed.
    if cfg.marginal_fee.is_positive() {
        // Is it certain that there will be a change output? If it is not certain,
        // we should call `check_for_uneconomic_inputs` with `possible_change`
        // including both possibilities.
        let possible_change = {
            // These are the situations where we might not have a change output.
            if fully_transparent
                || (cfg.dust_output_policy.action() == DustAction::AddDustToFee
                    && change_memo.is_none())
            {
                vec![OutputManifest::ZERO, target_change_counts]
            } else {
                vec![target_change_counts]
            }
        };

        check_for_uneconomic_inputs(
            transparent_inputs,
            transparent_outputs,
            sapling,
            #[cfg(feature = "orchard")]
            orchard,
            #[cfg(feature = "orchard")]
            ironwood,
            #[cfg(feature = "orchard")]
            orchard_pool_bundle_type,
            cfg.marginal_fee,
            cfg.grace_actions,
            &possible_change[..],
            ephemeral_balance,
        )?;
    }

    #[allow(unused_mut)]
    let (mut change, fee) = match total_in.cmp(&total_out_with_min_fee) {
        Ordering::Less => {
            // Case 1. Insufficient input value exists to pay the minimum fee; there's no way
            // we can construct the transaction.
            return Err(ChangeError::InsufficientFunds {
                available: total_in,
                required: total_out_with_min_fee,
            });
        }
        Ordering::Equal if fully_transparent => {
            // Case 2 for a tx with all transparent flows and no change memo
            // (e.g. the second transaction of a ZIP 320 pair).
            (vec![], min_fee)
        }
        _ => {
            let max_fee = max(
                min_fee,
                cfg.fee_rule
                    .fee_required(
                        cfg.params,
                        BlockHeight::from(target_height),
                        transparent_input_sizes.clone(),
                        transparent_output_sizes
                            .clone()
                            // Count the size of the transparent change output when change is to
                            // be returned to the transparent pool.
                            .chain(transparent_change_output_size),
                        sapling_input_count,
                        sapling_output_count(target_change_counts.sapling())?,
                        orchard_action_count(target_change_counts.orchard())?,
                        ironwood_action_count(target_change_counts.ironwood())?,
                    )
                    .map_err(|fee_error| ChangeError::StrategyError(E::from(fee_error)))?,
            );

            let total_out_with_max_fee = (subtotal_out + max_fee).ok_or_else(overflow)?;

            // We obtain a split count based on the total number of notes of sufficient size
            // available in the wallet, irrespective of pool. If we don't have any wallet metadata
            // available, we fall back to generating a single change output. Transparent change is
            // always emitted as a single output.
            let split_count = if wants_transparent_change {
                1
            } else {
                usize::from(wallet_meta.map_or(NonZeroUsize::MIN, |wm| {
                    cfg.split_policy.split_count(
                        wm.total_note_count(),
                        wm.total_value(),
                        // We use a saturating subtraction here because there may be insufficient funds to pay
                        // the fee, *if* the requested number of split outputs are created. If there is no
                        // proposed change, the split policy should recommend only a single change output.
                        (total_in - total_out_with_max_fee).unwrap_or(Zatoshis::ZERO),
                    )
                }))
            };

            // If we don't have as many change outputs as we expected, recompute the fee.
            let total_fee = if split_count < target_change_count {
                cfg.fee_rule
                    .fee_required(
                        cfg.params,
                        BlockHeight::from(target_height),
                        transparent_input_sizes,
                        transparent_output_sizes,
                        sapling_input_count,
                        sapling_output_count(if change_pool == ShieldedPool::Sapling {
                            split_count
                        } else {
                            0
                        })?,
                        orchard_action_count(if change_pool == ShieldedPool::Orchard {
                            split_count
                        } else {
                            0
                        })?,
                        ironwood_action_count(if change_pool == ShieldedPool::Ironwood {
                            split_count
                        } else {
                            0
                        })?,
                    )
                    .map_err(|fee_error| ChangeError::StrategyError(E::from(fee_error)))?
            } else {
                max_fee
            };

            let total_out = (subtotal_out + total_fee).ok_or_else(overflow)?;
            let total_change =
                (total_in - total_out).ok_or_else(|| ChangeError::InsufficientFunds {
                    available: total_in,
                    required: total_out,
                })?;

            let per_output_change = total_change.div_with_remainder(
                NonZeroU64::new(u64::try_from(split_count).expect("usize fits into u64")).unwrap(),
            );
            let simple_case = || {
                #[cfg(feature = "transparent-inputs")]
                if wants_transparent_change {
                    return Ok((
                        if total_change.is_zero() {
                            // A zero-valued transparent output would be unspendable, so we omit
                            // it. Unlike the shielded change case, omitting the output does not
                            // reveal additional information, because transparent output values
                            // are already publicly visible.
                            vec![]
                        } else {
                            // A non-zero transparent change output must be emitted; the change
                            // destination must therefore be unambiguous. This is where a failure
                            // to resolve a single originating address becomes an error, so that
                            // exact-match (changeless) spends from ambiguous P2SH sources still
                            // succeed.
                            let recipient = change_destination.as_ref().map_err(|addrs| {
                                ChangeError::TransparentChangeDestinationAmbiguous {
                                    input_addresses: addrs.clone(),
                                }
                            })?;
                            vec![match recipient {
                                // Return the change to the originating P2SH address.
                                Some(addr) => {
                                    ChangeValue::transparent_to_address(total_change, *addr)
                                }
                                // Send the change to an internal-scope address of the wallet.
                                None => ChangeValue::transparent(total_change),
                            }]
                        },
                        total_fee,
                    ));
                }

                Ok((
                    (0usize..split_count)
                        .map(|i| {
                            ChangeValue::shielded(
                                change_pool,
                                if i == 0 {
                                    // Add any remainder to the first output only
                                    (*per_output_change.quotient() + *per_output_change.remainder())
                                        .unwrap()
                                } else {
                                    // For any other output, the change value will just be the
                                    // quotient.
                                    *per_output_change.quotient()
                                },
                                change_memo.cloned(),
                            )
                        })
                        .collect(),
                    total_fee,
                ))
            };

            let change_dust_threshold = cfg
                .dust_output_policy
                .dust_threshold()
                .unwrap_or(cfg.default_dust_threshold);

            if total_change < change_dust_threshold {
                match cfg.dust_output_policy.action() {
                    DustAction::Reject => {
                        // Always allow zero-valued change even for the `Reject` policy:
                        // * it should be allowed in order to record change memos and to improve
                        //   indistinguishability;
                        // * this case occurs in practice when sending all funds from an account;
                        // * zero-valued notes do not require witness tracking;
                        // * the effect on trial decryption overhead is small.
                        if total_change.is_zero() {
                            simple_case()?
                        } else {
                            let shortfall =
                                (change_dust_threshold - total_change).ok_or_else(underflow)?;

                            return Err(ChangeError::InsufficientFunds {
                                available: total_in,
                                required: (total_in + shortfall).ok_or_else(overflow)?,
                            });
                        }
                    }
                    DustAction::AllowDustChange => simple_case()?,
                    DustAction::AddDustToFee => {
                        // Zero-valued change is also always allowed for this policy, but when
                        // no change memo is given, we might omit the change output instead.
                        let fee_with_dust = (total_change + total_fee).ok_or_else(overflow)?;

                        let reasonable_fee =
                            (total_fee + (MINIMUM_FEE * 10u64).unwrap()).ok_or_else(overflow)?;

                        if fee_with_dust > reasonable_fee {
                            // Defend against losing money by using AddDustToFee with a too-high
                            // dust threshold.
                            simple_case()?
                        } else if change_memo.is_some() {
                            (
                                vec![ChangeValue::shielded(
                                    change_pool,
                                    Zatoshis::ZERO,
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
                simple_case()?
            }
        }
    };

    #[cfg(feature = "transparent-inputs")]
    change.extend(
        ephemeral_balance
            .and_then(|b| b.ephemeral_output_amount())
            .map(ChangeValue::ephemeral_transparent),
    );

    TransactionBalance::new(change, fee).map_err(|_| overflow())
}

/// Returns a `[ChangeStrategy::DustInputs]` error if some of the inputs provided
/// to the transaction have value less than or equal to the marginal fee, and could not be
/// determined to have any economic value in the context of this input selection.
///
/// This determination is potentially conservative in the sense that outputs
/// with value less than or equal to the marginal fee might be excluded, even though in
/// practice they would not cause the fee to increase. Outputs with value
/// greater than the marginal fee will never be excluded.
///
/// `possible_change` is a slice of [`OutputManifest`] values indicating possible
/// combinations of how many change outputs (0 or 1) might be included in the
/// transaction for each pool. The shape of the manifest does not depend on which
/// protocol features are enabled.
#[allow(clippy::too_many_arguments)]
pub(crate) fn check_for_uneconomic_inputs<NoteRefT: Clone, E>(
    transparent_inputs: &[impl transparent::InputView],
    transparent_outputs: &[impl transparent::OutputView],
    sapling: &impl sapling_fees::BundleView<NoteRefT>,
    #[cfg(feature = "orchard")] orchard: &impl orchard_fees::BundleView<NoteRefT>,
    #[cfg(feature = "orchard")] ironwood: &impl orchard_fees::BundleView<NoteRefT>,
    // The Orchard-pool bundle type the builder will use; the action counts computed
    // for the grace-input check must match it (see `single_pool_output_balance`).
    #[cfg(feature = "orchard")] orchard_pool_bundle_type: ::orchard::builder::BundleType,
    marginal_fee: Zatoshis,
    grace_actions: usize,
    possible_change: &[OutputManifest],
    ephemeral_balance: Option<EphemeralBalance>,
) -> Result<(), ChangeError<E, NoteRefT>> {
    let mut t_dust: Vec<_> = transparent_inputs
        .iter()
        .filter_map(|i| {
            // For now, we're just assuming P2PKH inputs, so we don't check the
            // size of the input script.
            if i.coin().value() <= marginal_fee {
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

    #[cfg(feature = "orchard")]
    let mut i_dust: Vec<NoteRefT> = ironwood
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
    let mut i_dust: Vec<NoteRefT> = vec![];

    // If we don't have any dust inputs, there is nothing to check.
    if t_dust.is_empty() && s_dust.is_empty() && o_dust.is_empty() && i_dust.is_empty() {
        return Ok(());
    }

    let (t_inputs_len, t_outputs_len) = (
        transparent_inputs.len() + usize::from(ephemeral_balance.is_some_and(|b| b.is_input())),
        transparent_outputs.len() + usize::from(ephemeral_balance.is_some_and(|b| b.is_output())),
    );
    let (s_inputs_len, s_outputs_len) = (sapling.inputs().len(), sapling.outputs().len());
    #[cfg(feature = "orchard")]
    let (o_inputs_len, o_outputs_len) = (orchard.inputs().len(), orchard.outputs().len());
    #[cfg(not(feature = "orchard"))]
    let (o_inputs_len, o_outputs_len) = (0usize, 0usize);
    #[cfg(feature = "orchard")]
    let (i_inputs_len, i_outputs_len) = (ironwood.inputs().len(), ironwood.outputs().len());
    #[cfg(not(feature = "orchard"))]
    let (i_inputs_len, i_outputs_len) = (0usize, 0usize);

    let t_non_dust = t_inputs_len.checked_sub(t_dust.len()).unwrap();
    let s_non_dust = s_inputs_len.checked_sub(s_dust.len()).unwrap();
    let o_non_dust = o_inputs_len.checked_sub(o_dust.len()).unwrap();
    let i_non_dust = i_inputs_len.checked_sub(i_dust.len()).unwrap();

    // Return the number of allowed dust inputs from each pool.
    let allowed_dust = |change: &OutputManifest| {
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
            (t_outputs_len + change.transparent).saturating_sub(t_non_dust),
        );
        let s_allowed = min(
            s_dust.len(),
            (s_outputs_len + change.sapling).saturating_sub(s_non_dust),
        );
        let o_allowed = min(
            o_dust.len(),
            (o_outputs_len + change.orchard).saturating_sub(o_non_dust),
        );
        let i_allowed = min(
            i_dust.len(),
            (i_outputs_len + change.ironwood).saturating_sub(i_non_dust),
        );

        // We'll be spending the non-dust and allowed dust in each pool.
        let t_req_inputs = t_non_dust + t_allowed;
        let s_req_inputs = s_non_dust + s_allowed;
        #[cfg(feature = "orchard")]
        let o_req_inputs = o_non_dust + o_allowed;
        #[cfg(feature = "orchard")]
        let i_req_inputs = i_non_dust + i_allowed;

        // This calculates the hypothetical number of actions with given extra inputs,
        // for ZIP 317 and the padding rules in effect. The padding rules for each
        // pool are subtle (they also depend on `bundle_required` for example), so we
        // must actually call them rather than try to predict their effect. To tell
        // whether we can freely add an extra input from a given pool, we need to call
        // them both with and without that input; if the number of actions does not
        // increase, then the input is free to add.
        let hypothetical_actions = |t_extra, s_extra, _o_extra, _i_extra| {
            let s_spend_count = sapling
                .bundle_type()
                .num_spends(s_req_inputs + s_extra)
                .map_err(ChangeError::BundleError)?;

            let s_output_count = sapling
                .bundle_type()
                .num_outputs(s_req_inputs + s_extra, s_outputs_len + change.sapling)
                .map_err(ChangeError::BundleError)?;

            #[cfg(feature = "orchard")]
            let o_action_count = orchard_fees::transactional_action_count(
                orchard_pool_bundle_type,
                orchard.bundle_version(),
                o_req_inputs + _o_extra,
                o_outputs_len + change.orchard,
            )
            .map_err(ChangeError::BundleError)?;
            #[cfg(not(feature = "orchard"))]
            let o_action_count = 0;

            #[cfg(feature = "orchard")]
            let i_action_count = orchard_fees::transactional_action_count(
                orchard_pool_bundle_type,
                ironwood.bundle_version(),
                i_req_inputs + _i_extra,
                i_outputs_len + change.ironwood,
            )
            .map_err(ChangeError::BundleError)?;
            #[cfg(not(feature = "orchard"))]
            let i_action_count = 0;

            // To calculate the number of unused actions, we assume that transparent inputs
            // and outputs are P2PKH.
            Ok(
                max(t_req_inputs + t_extra, t_outputs_len + change.transparent)
                    + max(s_spend_count, s_output_count)
                    + o_action_count
                    + i_action_count,
            )
        };

        // First calculate the baseline number of logical actions with only the definitely
        // allowed inputs estimated above. If it is less than `grace_actions`, try to allocate
        // a grace input first to transparent dust, then to Sapling dust, then to Orchard
        // dust, then to Ironwood dust. If the number of actions increases, it was not
        // possible to allocate that input for free. This approach is sufficient because at
        // most one such input can be allocated, since `grace_actions` is at most 2 for
        // ZIP 317 and there must be at least one logical action. (If `grace_actions` were
        // greater than 2 then the code would still be correct, it would just not find all
        // potential extra inputs.)

        let baseline = hypothetical_actions(0, 0, 0, 0)?;

        let (t_extra, s_extra, o_extra, i_extra) = if baseline >= grace_actions {
            (0, 0, 0, 0)
        } else if t_dust.len() > t_allowed && hypothetical_actions(1, 0, 0, 0)? <= baseline {
            (1, 0, 0, 0)
        } else if s_dust.len() > s_allowed && hypothetical_actions(0, 1, 0, 0)? <= baseline {
            (0, 1, 0, 0)
        } else if o_dust.len() > o_allowed && hypothetical_actions(0, 0, 1, 0)? <= baseline {
            (0, 0, 1, 0)
        } else if i_dust.len() > i_allowed && hypothetical_actions(0, 0, 0, 1)? <= baseline {
            (0, 0, 0, 1)
        } else {
            (0, 0, 0, 0)
        };
        Ok(OutputManifest {
            transparent: t_allowed + t_extra,
            sapling: s_allowed + s_extra,
            orchard: o_allowed + o_extra,
            ironwood: i_allowed + i_extra,
        })
    };

    // Find the least number of allowed dust inputs for each pool for any `possible_change`.
    let allowed = possible_change
        .iter()
        .map(allowed_dust)
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .reduce(|l, r| OutputManifest {
            transparent: min(l.transparent, r.transparent),
            sapling: min(l.sapling, r.sapling),
            orchard: min(l.orchard, r.orchard),
            ironwood: min(l.ironwood, r.ironwood),
        })
        .expect("possible_change is nonempty");

    // The inputs in the tail of each list after the first `*_allowed` are returned as uneconomic.
    // The caller should order the inputs from most to least preferred to spend.
    let t_dust = t_dust.split_off(allowed.transparent);
    let s_dust = s_dust.split_off(allowed.sapling);
    let o_dust = o_dust.split_off(allowed.orchard);
    let i_dust = i_dust.split_off(allowed.ironwood);

    if t_dust.is_empty() && s_dust.is_empty() && o_dust.is_empty() && i_dust.is_empty() {
        Ok(())
    } else {
        Err(ChangeError::DustInputs {
            transparent: t_dust,
            sapling: s_dust,
            #[cfg(feature = "orchard")]
            orchard: o_dust,
            #[cfg(feature = "orchard")]
            ironwood: i_dust,
        })
    }
}

#[cfg(all(test, feature = "orchard"))]
mod tests {
    use super::{NetFlows, select_change_pool};
    use zcash_protocol::{ShieldedPool, value::Zatoshis};

    fn flows(orchard_in: u64, ironwood_in: u64, sapling_in: u64) -> NetFlows {
        NetFlows {
            t_in: Zatoshis::ZERO,
            t_out: Zatoshis::ZERO,
            sapling_in: Zatoshis::const_from_u64(sapling_in),
            sapling_out: Zatoshis::ZERO,
            orchard_in: Zatoshis::const_from_u64(orchard_in),
            orchard_out: Zatoshis::ZERO,
            ironwood_in: Zatoshis::const_from_u64(ironwood_in),
            ironwood_out: Zatoshis::ZERO,
        }
    }

    #[test]
    fn select_change_pool_routes_ironwood_spend_to_ironwood() {
        // Spending Ironwood funds (no Orchard or Sapling flows) sends change to Ironwood,
        // keeping it in the pool being spent rather than crossing back into Orchard.
        assert_eq!(
            select_change_pool(
                &flows(0, 10_000, 0),
                ShieldedPool::Sapling,
                true,
                Zatoshis::const_from_u64(5_000)
            ),
            ShieldedPool::Ironwood
        );

        // Spending Orchard funds keeps change in Orchard even when Ironwood funds are also
        // spent, so that Ironwood-routed change cannot reveal the spent Orchard notes' balances.
        assert_eq!(
            select_change_pool(
                &flows(10_000, 10_000, 0),
                ShieldedPool::Sapling,
                true,
                Zatoshis::const_from_u64(5_000)
            ),
            ShieldedPool::Orchard
        );

        // A combined Sapling + Ironwood spend routes change to Ironwood (Ironwood is preferred
        // over Sapling).
        assert_eq!(
            select_change_pool(
                &flows(0, 10_000, 10_000),
                ShieldedPool::Sapling,
                true,
                Zatoshis::const_from_u64(5_000)
            ),
            ShieldedPool::Ironwood
        );

        // A Sapling-only spend keeps change in Sapling.
        assert_eq!(
            select_change_pool(
                &flows(0, 0, 10_000),
                ShieldedPool::Orchard,
                true,
                Zatoshis::const_from_u64(5_000)
            ),
            ShieldedPool::Sapling
        );
    }

    #[test]
    fn select_change_pool_enforces_orchard_turnstile() {
        // Before Ironwood activation, Orchard-spend change stays in Orchard regardless of
        // the change bound: value may freely enter the pool.
        assert_eq!(
            select_change_pool(
                &flows(10_000, 0, 10_000),
                ShieldedPool::Sapling,
                false,
                Zatoshis::const_from_u64(15_000)
            ),
            ShieldedPool::Orchard
        );

        // After activation, change may return to Orchard while the pool balance strictly
        // decreases: the change bound is below the Orchard input value.
        assert_eq!(
            select_change_pool(
                &flows(10_000, 0, 10_000),
                ShieldedPool::Sapling,
                true,
                Zatoshis::const_from_u64(9_999)
            ),
            ShieldedPool::Orchard
        );

        // After activation, change that could equal or exceed the Orchard input value would
        // grow the pool, so it flows onward to Ironwood instead.
        assert_eq!(
            select_change_pool(
                &flows(10_000, 0, 10_000),
                ShieldedPool::Sapling,
                true,
                Zatoshis::const_from_u64(10_000)
            ),
            ShieldedPool::Ironwood
        );

        // A post-activation Orchard fallback for transparent-only flows is corrected to
        // Ironwood: with no Orchard inputs, no value may enter the Orchard pool.
        assert_eq!(
            select_change_pool(
                &NetFlows {
                    t_in: Zatoshis::const_from_u64(10_000),
                    t_out: Zatoshis::ZERO,
                    sapling_in: Zatoshis::ZERO,
                    sapling_out: Zatoshis::ZERO,
                    orchard_in: Zatoshis::ZERO,
                    orchard_out: Zatoshis::ZERO,
                    ironwood_in: Zatoshis::ZERO,
                    ironwood_out: Zatoshis::ZERO,
                },
                ShieldedPool::Orchard,
                true,
                Zatoshis::const_from_u64(10_000)
            ),
            ShieldedPool::Ironwood
        );
    }
}
