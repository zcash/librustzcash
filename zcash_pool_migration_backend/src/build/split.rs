//! Building the note-split transaction: a same-pool Orchard send-to-self that fans the spendable
//! balance into one self-funding note per planned denomination (each holding a crossing value plus
//! its fee buffer), plus a plain change output for any leftover. It produces no destination-pool
//! output; the value crossing is built separately.

use alloc::vec::Vec;

use core::convert::Infallible;

use rand_core::{CryptoRng, RngCore};

use orchard::keys::{FullViewingKey, Scope};
use zcash_primitives::transaction::builder::Builder;
use zcash_primitives::transaction::fees::FeeRule;
use zcash_primitives::transaction::fees::zip317::FeeRule as Zip317FeeRule;
use zcash_protocol::consensus::{BlockHeight, Parameters};
use zcash_protocol::memo::MemoBytes;
use zcash_protocol::value::Zatoshis;

use super::{BuildError, build_config, finalize_pczt, output_action_index};
use crate::note_splitting::NoteSplitPlan;

/// The internal-scope diversifier index used for the wallet's own split and change outputs.
const INTERNAL_ADDRESS_INDEX: u32 = 0;

/// The output notes a note-split transaction creates: the self-funding migration notes, and the
/// leftover change output if the split produced one. Each entry is `(output_index, value)`, where
/// `output_index` is the note's real position in the built transaction's Orchard actions (the
/// builder shuffles them), so the wallet can locate each note after the transaction is mined.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SplitOutputs {
    migration_notes: Vec<(u32, u64)>,
    change: Option<(u32, u64)>,
}

impl SplitOutputs {
    /// Constructs the split outputs from their parts.
    pub fn from_parts(migration_notes: Vec<(u32, u64)>, change: Option<(u32, u64)>) -> Self {
        SplitOutputs {
            migration_notes,
            change,
        }
    }

    /// The `(output_index, value)` of each self-funding migration note the split creates.
    pub fn migration_notes(&self) -> &[(u32, u64)] {
        &self.migration_notes
    }

    /// The `(output_index, value)` of the Orchard change output, if the split produced one.
    pub fn change(&self) -> Option<(u32, u64)> {
        self.change
    }
}

/// Exact ZIP-317 fee (in zatoshi) for a note-split transaction at `target_height`, delegating to the
/// transaction's own [`Zip317FeeRule`] so the estimate cannot drift from the builder. The note split
/// is an Orchard-only send-to-self with cross-address transfers disabled, so each spend and each
/// output occupies its own action (paired with a fabricated zero-valued counterpart):
/// `orchard_actions = n_spends + n_outputs`.
fn split_fee<P: Parameters>(
    params: &P,
    target_height: u32,
    n_spends: usize,
    n_outputs: usize,
) -> u64 {
    let orchard_actions = n_spends + n_outputs;
    Zip317FeeRule::standard()
        .fee_required(
            params,
            BlockHeight::from_u32(target_height),
            core::iter::empty(),
            core::iter::empty(),
            0,
            0,
            orchard_actions,
            0,
        )
        .expect("a ZIP-317 fee for a note split never fails")
        .into_u64()
}

/// Resolve the transaction's real balance against the planned migration-note values, deciding
/// whether the split needs an extra plain change output for the leftover, and returning
/// `(fee, change)`.
///
/// The migration notes always keep their exact planned values; drifting one to absorb the
/// fee-estimate difference would leak that drift when the note is later spent. Any leftover
/// (fee-estimate drift plus genuine dust) becomes its own plain change output, unless the leftover
/// is smaller than one marginal action fee, in which case it is cheaper to pay it into the fee.
///
/// # Errors
///
/// Returns [`BuildError::Balance`] if there are no outputs, if the real fee exceeds the selected
/// total, or if the real fee exceeds the plan by more than the selected total (net of the planned
/// outputs) can cover.
fn finalize_split_outputs<P: Parameters>(
    params: &P,
    target_height: u32,
    n_spends: usize,
    selected_total: u64,
    outputs: &[u64],
) -> Result<(u64, Option<u64>), BuildError> {
    if outputs.is_empty() {
        return Err(BuildError::Balance(
            "note split: no outputs to adjust".into(),
        ));
    }
    let planned: u64 = outputs.iter().sum();
    let fee_without_change = split_fee(params, target_height, n_spends, outputs.len());
    let required = selected_total
        .checked_sub(fee_without_change)
        .ok_or_else(|| {
            BuildError::Balance(format!(
                "note split: fee {fee_without_change} exceeds selected total {selected_total}"
            ))
        })?;
    let leftover = required.checked_sub(planned).ok_or_else(|| {
        BuildError::Balance(format!(
            "note split: real fee exceeds the plan by more than the selected total can cover \
             (required {required} zatoshi, planned migration outputs {planned} zatoshi)"
        ))
    })?;
    if leftover == 0 {
        return Ok((fee_without_change, None));
    }
    let fee_with_change = split_fee(params, target_height, n_spends, outputs.len() + 1);
    let extra_action_cost = fee_with_change - fee_without_change;
    if leftover <= extra_action_cost {
        return Ok((fee_without_change + leftover, None));
    }
    Ok((fee_with_change, Some(leftover - extra_action_cost)))
}

/// Build the note-split transaction as an unproven PCZT: spend every supplied Orchard note and fan
/// the value into one same-address change output per planned denomination in `output_values`, plus
/// one further plain change output if the real balance leaves anything over the plan.
///
/// The ingredients (which the wallet backend resolves from its note-commitment tree) are: the
/// Orchard `anchor` and, per spent note, the `(Note, MerklePath)` witness in `spends`; plus the
/// `orchard_fvk` (the split outputs are derived from its internal scope). `output_values` are the
/// self-funding note values ([`NoteSplitPlan::migration_outputs`]).
///
/// Returns the finalized PCZT and the [`SplitOutputs`] mapping each requested output (migration
/// notes first, then any change) to its real post-shuffle Orchard action index.
///
/// # Errors
///
/// Returns [`BuildError`] if there are no spends, if the outputs cannot be balanced against the
/// selected total (fee versus planned outputs), or if the builder/PCZT pipeline fails.
///
/// The caller supplies `rng` (a cryptographically secure RNG in production, e.g. `OsRng`; tests can
/// pass a seeded one), keeping this builder pure.
pub fn build_split_pczt<P, R>(
    params: &P,
    target_height: u32,
    orchard_fvk: &FullViewingKey,
    anchor: orchard::Anchor,
    spends: Vec<(orchard::note::Note, orchard::tree::MerklePath)>,
    output_values: &[u64],
    rng: R,
) -> Result<(pczt::Pczt, SplitOutputs), BuildError>
where
    P: Parameters + Clone,
    R: RngCore + CryptoRng,
{
    if spends.is_empty() {
        return Err(BuildError::Balance("note split: no spendable notes".into()));
    }
    let selected_total: u64 = spends.iter().map(|(note, _)| note.value().inner()).sum();
    let (_fee, change) = finalize_split_outputs(
        params,
        target_height,
        spends.len(),
        selected_total,
        output_values,
    )?;
    let mut requested: Vec<u64> = output_values.to_vec();
    if let Some(change_value) = change {
        requested.push(change_value);
    }

    let mut builder = Builder::new(
        params.clone(),
        BlockHeight::from_u32(target_height),
        build_config(anchor, None),
    );
    for (note, merkle_path) in spends {
        builder
            .add_orchard_spend::<Infallible>(orchard_fvk.clone(), note, merkle_path)
            .map_err(|e| BuildError::Build(format!("note split: add spend: {e:?}")))?;
    }
    let change_address = orchard_fvk.address_at(INTERNAL_ADDRESS_INDEX, Scope::Internal);
    let internal_ovk = orchard_fvk.to_ovk(Scope::Internal);
    for value in &requested {
        builder
            .add_orchard_change_output::<Infallible>(
                orchard_fvk.clone(),
                Some(internal_ovk.clone()),
                change_address,
                Zatoshis::const_from_u64(*value),
                MemoBytes::empty(),
            )
            .map_err(|e| BuildError::Build(format!("note split: add change: {e:?}")))?;
    }

    let build_result = builder
        .build_for_pczt(rng, &Zip317FeeRule::standard())
        .map_err(|e| BuildError::Build(format!("note split: build: {e:?}")))?;

    // Un-shuffle: map each requested output (request order) to its real action index so the caller
    // stores the right (action_index, value) references.
    let placed: Vec<(u32, u64)> = requested
        .iter()
        .enumerate()
        .map(|(i, &value)| output_action_index(&build_result.orchard_meta, i).map(|ai| (ai, value)))
        .collect::<Result<_, _>>()?;
    let (migration_notes, change_out) = if change.is_some() {
        let (notes, change_slice) = placed.split_at(output_values.len());
        (notes.to_vec(), change_slice.first().copied())
    } else {
        (placed, None)
    };

    let finalized = finalize_pczt(build_result.pczt_parts)?;

    Ok((
        finalized,
        SplitOutputs::from_parts(migration_notes, change_out),
    ))
}

/// Build the note-split PCZT directly from a [`NoteSplitPlan`], using its
/// [`migration_outputs`](NoteSplitPlan::migration_outputs) as the self-funding note values. A thin
/// convenience over [`build_split_pczt`].
///
/// # Errors
///
/// See [`build_split_pczt`].
pub fn build_split_pczt_for_plan<P, R>(
    params: &P,
    target_height: u32,
    orchard_fvk: &FullViewingKey,
    anchor: orchard::Anchor,
    spends: Vec<(orchard::note::Note, orchard::tree::MerklePath)>,
    plan: &NoteSplitPlan,
    rng: R,
) -> Result<(pczt::Pczt, SplitOutputs), BuildError>
where
    P: Parameters + Clone,
    R: RngCore + CryptoRng,
{
    build_split_pczt(
        params,
        target_height,
        orchard_fvk,
        anchor,
        spends,
        plan.migration_outputs(),
        rng,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use rand_chacha::ChaCha8Rng;
    use rand_core::SeedableRng;
    use zcash_protocol::local_consensus::LocalNetwork;
    use zcash_protocol::value::COIN;

    use crate::build::test_util::{TARGET_HEIGHT, account, regtest_network, single_note_witness};
    use crate::note_splitting::{
        CanonicalOneTwoFive, DenominationStrategy, MIGRATION_MAX_DENOMINATION_ZEC, NoteSplitPlan,
        RESIDUAL_MIGRATION_MIN_ZATOSHI,
    };

    /// A `finalize_split_outputs` input guaranteed to balance: a spend count, a non-empty set of
    /// planned output values, and a selected total at least large enough to cover the outputs plus
    /// the no-change fee (plus an arbitrary extra leftover).
    fn arb_finalize_input() -> impl Strategy<Value = (usize, Vec<u64>, u64)> {
        (
            1usize..10,
            prop::collection::vec(1u64..1_000_000, 1..8),
            0u64..80_000,
        )
            .prop_map(|(n_spends, outputs, extra)| {
                let params = regtest_network(true);
                let planned: u64 = outputs.iter().sum();
                let fee = split_fee(&params, TARGET_HEIGHT, n_spends, outputs.len());
                let selected_total = planned + fee + extra;
                (n_spends, outputs, selected_total)
            })
    }

    proptest! {
        /// Whatever the split does with the leftover (own change output, or paid into the fee), value
        /// is conserved: `planned outputs + change + fee == selected total`. The migration outputs
        /// always keep their exact planned values, and any change is strictly positive.
        #[test]
        fn finalize_conserves_value((n_spends, outputs, selected_total) in arb_finalize_input()) {
            let params = regtest_network(true);
            let planned: u64 = outputs.iter().sum();
            let (fee, change) =
                finalize_split_outputs(&params, TARGET_HEIGHT, n_spends, selected_total, &outputs)
                    .unwrap();
            prop_assert_eq!(planned + change.unwrap_or(0) + fee, selected_total);
            prop_assert!(fee >= split_fee(&params, TARGET_HEIGHT, n_spends, outputs.len()));
            if let Some(c) = change {
                prop_assert!(c > 0);
            }
        }
    }

    /// The leftover boundary: a leftover of at most one action's fee is paid into the fee (no change
    /// output); one zatoshi more gets its own change output, net of that extra action's cost.
    #[test]
    fn leftover_at_or_below_one_action_is_paid_into_fee() {
        // Two outputs, so adding a change output genuinely costs one more action (with a single
        // output the action count is already floored at the grace count, and change is free).
        let params = regtest_network(true);
        let outputs = [100u64, 100];
        let planned: u64 = outputs.iter().sum();
        let n_spends = 1;
        let fee_without_change = split_fee(&params, TARGET_HEIGHT, n_spends, outputs.len());
        let extra_action_cost =
            split_fee(&params, TARGET_HEIGHT, n_spends, outputs.len() + 1) - fee_without_change;
        assert!(extra_action_cost > 0);

        // Leftover exactly one action fee: folded into the fee, no change output.
        let total = planned + fee_without_change + extra_action_cost;
        assert_eq!(
            finalize_split_outputs(&params, TARGET_HEIGHT, n_spends, total, &outputs).unwrap(),
            (fee_without_change + extra_action_cost, None)
        );
        // One zatoshi more: worth its own change output, of exactly that one zatoshi.
        assert_eq!(
            finalize_split_outputs(&params, TARGET_HEIGHT, n_spends, total + 1, &outputs).unwrap(),
            (fee_without_change + extra_action_cost, Some(1))
        );
    }

    /// A leftover of exactly zero: the outputs plus the no-change fee consume the total exactly.
    #[test]
    fn exact_total_has_no_change() {
        let params = regtest_network(true);
        let outputs = [100u64, 250u64];
        let n_spends = 2;
        let fee = split_fee(&params, TARGET_HEIGHT, n_spends, outputs.len());
        let total = 350 + fee;
        assert_eq!(
            finalize_split_outputs(&params, TARGET_HEIGHT, n_spends, total, &outputs).unwrap(),
            (fee, None)
        );
    }

    #[test]
    fn finalize_rejects_bad_inputs() {
        let params = regtest_network(true);
        // No outputs to size.
        assert!(matches!(
            finalize_split_outputs(&params, TARGET_HEIGHT, 1, 1_000_000, &[]),
            Err(BuildError::Balance(_))
        ));
        // Selected total cannot even cover the fee.
        assert!(matches!(
            finalize_split_outputs(&params, TARGET_HEIGHT, 1, 1, &[100]),
            Err(BuildError::Balance(_))
        ));
        // Fee is affordable but the planned outputs are not.
        let fee = split_fee(&params, TARGET_HEIGHT, 1, 1);
        assert!(matches!(
            finalize_split_outputs(&params, TARGET_HEIGHT, 1, fee + 50, &[100]),
            Err(BuildError::Balance(_))
        ));
    }

    /// The builder rejects an empty spend set before touching any cryptography.
    #[test]
    fn build_rejects_no_spends() {
        let sk = orchard::keys::SpendingKey::from_bytes([1; 32]).unwrap();
        let fvk = FullViewingKey::from(&sk);
        let params = zcash_protocol::consensus::MAIN_NETWORK;
        let target_height = 1_000_000;
        let anchor = orchard::Anchor::empty_tree();
        let spends = Vec::new();
        let outputs = [100u64];
        let rng = ChaCha8Rng::seed_from_u64(0);
        let result = build_split_pczt(&params, target_height, &fvk, anchor, spends, &outputs, rng);
        let err = result.unwrap_err();
        assert!(matches!(err, BuildError::Balance(_)));
    }

    /// Plans a note split with the canonical `{1, 2, 5} * 10^k` strategy, the same decomposition the
    /// `note_splitting` tests exercise.
    fn plan_for(balance: u64, rng: &mut ChaCha8Rng) -> NoteSplitPlan {
        let strategy = CanonicalOneTwoFive::recommended();
        strategy.plan(balance, 0, rng)
    }

    /// Builds a split for `plan`, funded by a single input note worth the plan total plus one ZEC of
    /// headroom (which dwarfs the split fee, so a change output is always present), on `params` at a
    /// height where Orchard is live. Asserts the migration notes reproduce the plan exactly, value is
    /// conserved through the ZIP-317 fee (the build balancing already proves the estimate agreed with
    /// the transaction builder), and every output maps to a distinct Orchard action index.
    fn assert_builds_planned_split(
        fvk: &FullViewingKey,
        plan: &NoteSplitPlan,
        params: &LocalNetwork,
        note_seed: u64,
    ) {
        let outputs = plan.migration_outputs().to_vec();
        let planned: u64 = outputs.iter().sum();
        let change_headroom = COIN;
        let note_value = planned + change_headroom;

        let (note, path, anchor) = single_note_witness(fvk, note_value, note_seed);
        let spends = vec![(note, path)];
        let build_rng = ChaCha8Rng::seed_from_u64(note_seed);
        let result = build_split_pczt(
            params,
            TARGET_HEIGHT,
            fvk,
            anchor,
            spends,
            &outputs,
            build_rng,
        );
        let (pczt, split) = result.expect("a planned split should build and balance");

        let built_values: Vec<u64> = split.migration_notes().iter().map(|&(_, v)| v).collect();
        assert_eq!(built_values, outputs);

        let change = split
            .change()
            .expect("the one-ZEC headroom leaves a change output");
        let (change_index, change_value) = change;
        let implied_fee = note_value - planned - change_value;
        let expected_fee = split_fee(params, TARGET_HEIGHT, 1, outputs.len() + 1);
        assert_eq!(implied_fee, expected_fee);

        let mut indices: Vec<u32> = split.migration_notes().iter().map(|&(i, _)| i).collect();
        indices.push(change_index);
        let output_count = indices.len();
        indices.sort_unstable();
        indices.dedup();
        assert_eq!(
            indices.len(),
            output_count,
            "action indices must be distinct"
        );

        let orchard_bundle = pczt.orchard();
        let actions = orchard_bundle.actions();
        assert!(!actions.is_empty());
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(48))]

        /// The builder turns the note-splitting strategy's plans into balanced split PCZTs across a
        /// range of balances (whole-ZEC and sub-ZEC), on a post-NU6.3 network (the Ironwood
        /// migration's environment). This is the plan-to-PCZT integration over the same decompositions
        /// the `note_splitting` tests cover.
        #[test]
        fn builds_planned_splits(
            balance in RESIDUAL_MIGRATION_MIN_ZATOSHI..=(300 * COIN),
            account_seed in any::<u64>(),
            note_seed in any::<u64>(),
            seed in any::<u64>(),
        ) {
            let fvk = account(account_seed);
            let mut plan_rng = ChaCha8Rng::seed_from_u64(seed);
            let plan = plan_for(balance, &mut plan_rng);
            // A balance below one self-funding note has nothing to split; that case is covered by
            // `below_min_note_migrates_nothing` in `note_splitting`.
            prop_assume!(!plan.migration_outputs().is_empty());

            let params = regtest_network(true);
            assert_builds_planned_split(&fvk, &plan, &params, note_seed);
        }
    }

    /// A concrete near-maximum split (the canonical strategy of a large, above-cap balance yields tens
    /// of cap-sized crossings): the whole many-output bundle builds into one balanced PCZT, post-NU6.3.
    #[test]
    fn builds_a_large_many_output_split() {
        let fvk = account(0);
        // Far above the per-note cap, so the plan fills with cap-sized (10,000 ZEC) crossings.
        let balance = 40 * MIGRATION_MAX_DENOMINATION_ZEC * COIN;
        let mut plan_rng = ChaCha8Rng::seed_from_u64(0);
        let plan = plan_for(balance, &mut plan_rng);
        assert!(
            plan.migration_outputs().len() >= 30,
            "a large balance should produce many crossings"
        );
        let params = regtest_network(true);
        assert_builds_planned_split(&fvk, &plan, &params, 0);
    }
}
