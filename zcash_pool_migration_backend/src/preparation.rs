//! Note-preparation transaction planning: how to restructure a wallet's spendable source-pool notes
//! into the exact self-funding notes a migration run needs, using transactions that each stay within
//! the [ZIP 318] action budget.
//!
//! # The problem
//!
//! The [`note_splitting`](super::note_splitting) planner decides the *values* of the self-funding
//! notes to mint. This module decides the *transactions* that mint them. [ZIP 318] requires each
//! note-preparation transaction to be padded to exactly [`PREP_TX_ACTIONS`] Orchard actions (a
//! mobile-proving-time and on-chain-uniformity constraint). Under NU6.3 a bundle's action count is
//! its spends plus its outputs, so one transaction can consume and produce at most
//! [`PREP_TX_ACTIONS`] notes in total (for example 15 spends and one output when consolidating, or
//! one spend and 15 outputs when splitting).
//!
//! A single transaction therefore cannot always turn the wallet's notes into every funding note: a
//! note that must fan out into more outputs than one transaction holds, or a balance spread across
//! more dust notes than one transaction can consume, needs **layers**. A layer is a set of
//! transactions with no dependencies between them (buildable, provable, and broadcastable in
//! parallel); a later layer may spend the outputs of an earlier one, but only after they are mined
//! and a boundary passes, so each extra layer extends the preparation phase by roughly one anchor
//! bucket. The planner therefore prefers fewer layers (which dominate the wall-clock) over fewer
//! transactions.
//!
//! # The strategy
//!
//! The planner is a largest-first layered greedy. In each layer it feeds each output transaction from
//! the largest available note it can (one big note funds up to [`FUNDING_OUTPUTS_PER_TX`] funding
//! notes), routes every leftover forward as an intermediate ("feeder") note, and consolidates notes
//! too small to fund anything on their own into feeder notes. Once all funding notes are scheduled it
//! consolidates the feeders that no layer spent into a single residual note, matching ZIP 318's
//! "one note per part plus at most one residual note" (a remainder too small to pay a transaction fee
//! is left as change instead). For a typical wallet (a few notes, a handful of funding notes) this is
//! a single layer; extra layers appear only for a lone large note fanning out into many funding notes,
//! or a dust-heavy balance.
//!
//! This greedy is a heuristic, not a layer-count optimiser. For a lone, very large note that must fan
//! out into many funding notes it chains feeder notes linearly (one layer per
//! [`FUNDING_OUTPUTS_PER_TX`] funding notes) rather than first fanning the note into several parallel
//! feeders, so in that extreme it can use more layers than the minimum; the common cases above are
//! already minimal. Fanning the lone-whale case out to parallel first is future work.
//!
//! This is a pure planner: it works in note *values* (in zatoshi) and does no cryptography or I/O. It
//! reserves a fixed per-transaction fee (the caller passes the ZIP-317 fee of a padded
//! [`PREP_TX_ACTIONS`]-action transaction) out of each transaction's inputs; the builder later
//! absorbs the real fee into the change.
//!
//! [ZIP 318]: https://zips.z.cash/zip-0318

use alloc::vec::Vec;

use core::fmt;

/// The exact number of Orchard actions in every note-preparation transaction ([ZIP 318]): each is
/// padded up to this count, so no preparation transaction is distinguishable from another by its
/// action count, and one transaction handles at most this many notes in total (spends plus outputs).
///
/// [ZIP 318]: https://zips.z.cash/zip-0318
pub const PREP_TX_ACTIONS: usize = 16;

/// The most funding (or feeder) outputs one transaction produces from a single input: the action
/// budget less that one input and one change/feeder slot (`16 - 1 - 1`).
pub const FUNDING_OUTPUTS_PER_TX: usize = PREP_TX_ACTIONS - 2;

/// The most notes one transaction consolidates: the action budget less the single output it produces
/// (`16 - 1`).
pub const CONSOLIDATION_INPUTS_PER_TX: usize = PREP_TX_ACTIONS - 1;

/// A note a preparation transaction spends: either one of the wallet's original spendable notes, or a
/// note an earlier layer produced.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrepInput {
    /// The wallet note at this index in the caller-supplied `available` slice.
    Wallet(usize),
    /// The `output`-th output of the `transaction`-th transaction of an earlier `layer`.
    Prior {
        layer: usize,
        transaction: usize,
        output: usize,
    },
}

/// A note a preparation transaction produces.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrepOutput {
    /// A final self-funding note: one of the requested funding values.
    Funding(u64),
    /// An intermediate ("feeder") note, spent by a later layer to route value forward.
    Intermediate(u64),
    /// Leftover value returned to the source pool.
    Change(u64),
}

impl PrepOutput {
    /// The note value this output carries.
    pub fn value(&self) -> u64 {
        match self {
            PrepOutput::Funding(v) | PrepOutput::Intermediate(v) | PrepOutput::Change(v) => *v,
        }
    }
}

/// One note-preparation transaction: a same-pool send-to-self, padded at build time to
/// [`PREP_TX_ACTIONS`] actions. Its logical action count (`inputs.len() + outputs.len()`) never
/// exceeds that budget.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrepTransaction {
    inputs: Vec<PrepInput>,
    outputs: Vec<PrepOutput>,
}

impl PrepTransaction {
    /// The notes this transaction spends.
    pub fn inputs(&self) -> &[PrepInput] {
        &self.inputs
    }

    /// The notes this transaction produces.
    pub fn outputs(&self) -> &[PrepOutput] {
        &self.outputs
    }

    /// The logical Orchard action count before padding (`inputs + outputs`).
    pub fn action_count(&self) -> usize {
        self.inputs.len() + self.outputs.len()
    }
}

/// A schedule of note-preparation transactions grouped into sequential layers. Every transaction in a
/// layer is independent of the others in that layer; a transaction may spend a [`PrepInput::Prior`]
/// output only from a strictly earlier layer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparationPlan {
    layers: Vec<Vec<PrepTransaction>>,
}

impl PreparationPlan {
    /// The layers, in dependency order (later layers may spend earlier layers' outputs).
    pub fn layers(&self) -> &[Vec<PrepTransaction>] {
        &self.layers
    }

    /// The number of sequential layers (the depth that governs the preparation phase's duration).
    pub fn layer_count(&self) -> usize {
        self.layers.len()
    }

    /// The total number of preparation transactions across all layers.
    pub fn transaction_count(&self) -> usize {
        self.layers.iter().map(Vec::len).sum()
    }

    /// The value an input carries, resolved against the wallet's `available` notes (for a
    /// [`PrepInput::Wallet`]) or an earlier layer's output (for a [`PrepInput::Prior`]). Returns
    /// `None` if the reference is out of range.
    pub fn input_value(&self, input: &PrepInput, available: &[u64]) -> Option<u64> {
        match input {
            PrepInput::Wallet(i) => available.get(*i).copied(),
            PrepInput::Prior {
                layer,
                transaction,
                output,
            } => self
                .layers
                .get(*layer)?
                .get(*transaction)?
                .outputs
                .get(*output)
                .map(PrepOutput::value),
        }
    }
}

/// Why a preparation plan could not be produced.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrepError {
    /// The available notes cannot fund every requested funding note plus the per-transaction fees.
    InsufficientFunds,
}

impl fmt::Display for PrepError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PrepError::InsufficientFunds => {
                f.write_str("available notes cannot fund the requested notes plus preparation fees")
            }
        }
    }
}

impl core::error::Error for PrepError {}

/// A note available to spend in the current layer: a reference and its value.
type PoolNote = (PrepInput, u64);

/// Plan the note-preparation transactions that mint `funding` (the self-funding note values, in
/// zatoshi) from `available` (the wallet's spendable source-pool note values, in zatoshi), reserving
/// `fee_per_tx` zatoshi for each transaction (the ZIP-317 fee of a padded [`PREP_TX_ACTIONS`]-action
/// transaction).
///
/// Returns an empty plan when `funding` is empty, and [`PrepError::InsufficientFunds`] when the
/// available value cannot cover the funding notes plus the per-transaction fees.
pub fn plan_preparation(
    available: &[u64],
    funding: &[u64],
    fee_per_tx: u64,
) -> Result<PreparationPlan, PrepError> {
    // Funding values still to produce, largest first (so `last()` is the smallest).
    let mut remaining: Vec<u64> = funding.iter().copied().filter(|&v| v > 0).collect();
    remaining.sort_unstable_by(|a, b| b.cmp(a));

    let mut layers: Vec<Vec<PrepTransaction>> = Vec::new();
    if remaining.is_empty() {
        return Ok(PreparationPlan { layers });
    }

    // The notes available to spend in the current layer (layer 0: the wallet's own notes).
    let mut current: Vec<PoolNote> = available
        .iter()
        .enumerate()
        .map(|(i, &v)| (PrepInput::Wallet(i), v))
        .collect();

    while !remaining.is_empty() {
        if current.is_empty() {
            return Err(PrepError::InsufficientFunds);
        }
        // Largest notes first.
        current.sort_unstable_by(|a, b| b.1.cmp(&a.1));

        // Pass 1: assign funding to the notes that can fund at least the smallest remaining note.
        // `partial` holds a note, the funding values it will mint, and its leftover budget; the rest
        // go to `consolidatable` to be combined into feeder notes.
        let mut partial: Vec<(PrepInput, Vec<u64>, u64)> = Vec::new();
        let mut consolidatable: Vec<PoolNote> = Vec::new();

        for (in_ref, value) in current.drain(..) {
            if remaining.is_empty() {
                // Everything is already scheduled; this note stays unspent in the wallet.
                continue;
            }
            let smallest = *remaining.last().expect("remaining is non-empty");
            if value <= fee_per_tx || value - fee_per_tx < smallest {
                consolidatable.push((in_ref, value));
                continue;
            }
            let budget = value - fee_per_tx;
            let mut assigned = Vec::new();
            let mut used = 0u64;
            let mut i = 0;
            while i < remaining.len() && assigned.len() < FUNDING_OUTPUTS_PER_TX {
                if used + remaining[i] <= budget {
                    used += remaining[i];
                    assigned.push(remaining.remove(i));
                } else {
                    i += 1;
                }
            }
            // `value - fee_per_tx >= smallest` guarantees at least the smallest note was assignable.
            debug_assert!(!assigned.is_empty());
            partial.push((in_ref, assigned, budget - used));
        }

        // Pass 2: mint the funding notes, routing every leftover forward as a feeder so a later layer
        // reuses it rather than scattering change.
        let mut txs: Vec<PrepTransaction> = Vec::new();
        let mut next: Vec<PoolNote> = Vec::new();
        for (in_ref, assigned, leftover) in partial {
            let mut outputs: Vec<PrepOutput> =
                assigned.into_iter().map(PrepOutput::Funding).collect();
            if leftover > 0 {
                next.push((
                    PrepInput::Prior {
                        layer: layers.len(),
                        transaction: txs.len(),
                        output: outputs.len(),
                    },
                    leftover,
                ));
                outputs.push(PrepOutput::Intermediate(leftover));
            }
            txs.push(PrepTransaction {
                inputs: vec![in_ref],
                outputs,
            });
        }

        // Consolidate notes too small to fund anything into feeders for a later layer.
        consolidate(
            consolidatable,
            layers.len(),
            fee_per_tx,
            &mut txs,
            &mut next,
        );

        if txs.is_empty() {
            // No note in this layer could fund or usefully consolidate: the balance is insufficient.
            return Err(PrepError::InsufficientFunds);
        }
        layers.push(txs);
        current = next;
    }

    // The funding notes are all scheduled. Consolidate every leftover feeder that no layer spends into
    // a single residual note (ZIP 318 prepares one note per part plus at most one residual note), for
    // as long as that is worth a transaction; a remainder too small to pay a fee is left as change.
    loop {
        let pool = unconsumed_feeders(&layers);
        if pool.len() <= 1 {
            break;
        }
        let mut txs: Vec<PrepTransaction> = Vec::new();
        let mut next: Vec<PoolNote> = Vec::new();
        consolidate(pool, layers.len(), fee_per_tx, &mut txs, &mut next);
        if txs.is_empty() {
            break; // the remainder is sub-fee dust; leave it as change
        }
        layers.push(txs);
    }
    let _ = current; // the residual pool is recomputed above, so the last `next` is unused

    // Relabel any feeder note that no later layer ends up spending as source-pool change, so the plan
    // has no dangling intermediates and value is conserved end to end.
    let mut spent: Vec<(usize, usize, usize)> = Vec::new();
    for layer in &layers {
        for tx in layer {
            for input in &tx.inputs {
                if let PrepInput::Prior {
                    layer,
                    transaction,
                    output,
                } = input
                {
                    spent.push((*layer, *transaction, *output));
                }
            }
        }
    }
    for (li, layer) in layers.iter_mut().enumerate() {
        for (ti, tx) in layer.iter_mut().enumerate() {
            for (oi, out) in tx.outputs.iter_mut().enumerate() {
                if let PrepOutput::Intermediate(v) = *out {
                    if !spent.contains(&(li, ti, oi)) {
                        *out = PrepOutput::Change(v);
                    }
                }
            }
        }
    }

    Ok(PreparationPlan { layers })
}

/// Split `n` notes into consolidation batches of at most [`CONSOLIDATION_INPUTS_PER_TX`], never
/// leaving a batch of one (which would waste a fee without reducing the note count). Assumes `n >= 2`.
fn consolidation_batch_sizes(mut n: usize) -> Vec<usize> {
    let max = CONSOLIDATION_INPUTS_PER_TX;
    let mut sizes = Vec::new();
    while n > 0 {
        let take = if n <= max {
            n
        } else if n - max == 1 {
            max - 1 // leave 2 for the final batch rather than a lone note
        } else {
            max
        };
        sizes.push(take);
        n -= take;
    }
    sizes
}

/// Consolidate `pool` into feeder notes: append one consolidation transaction per batch (of at most
/// [`CONSOLIDATION_INPUTS_PER_TX`] inputs) to `txs` in layer `layer`, with its feeder pushed to
/// `next`. Returns any notes whose batch could not cover the fee (too small to consolidate).
fn consolidate(
    mut pool: Vec<PoolNote>,
    layer: usize,
    fee: u64,
    txs: &mut Vec<PrepTransaction>,
    next: &mut Vec<PoolNote>,
) -> Vec<PoolNote> {
    if pool.len() < 2 {
        return pool;
    }
    pool.sort_unstable_by(|a, b| b.1.cmp(&a.1));
    let mut leftover = Vec::new();
    for size in consolidation_batch_sizes(pool.len()) {
        let batch: Vec<PoolNote> = pool.drain(..size).collect();
        let sum: u64 = batch.iter().map(|&(_, v)| v).sum();
        if sum <= fee {
            leftover.extend(batch); // too small to pay a fee; leave unspent
            continue;
        }
        let feeder = sum - fee;
        next.push((
            PrepInput::Prior {
                layer,
                transaction: txs.len(),
                output: 0,
            },
            feeder,
        ));
        txs.push(PrepTransaction {
            inputs: batch.into_iter().map(|(r, _)| r).collect(),
            outputs: vec![PrepOutput::Intermediate(feeder)],
        });
    }
    leftover
}

/// Every intermediate ("feeder") output that no transaction spends, as `(reference, value)` pairs.
fn unconsumed_feeders(layers: &[Vec<PrepTransaction>]) -> Vec<PoolNote> {
    let mut spent: Vec<(usize, usize, usize)> = Vec::new();
    for layer in layers {
        for tx in layer {
            for input in &tx.inputs {
                if let PrepInput::Prior {
                    layer,
                    transaction,
                    output,
                } = input
                {
                    spent.push((*layer, *transaction, *output));
                }
            }
        }
    }
    let mut out = Vec::new();
    for (li, layer) in layers.iter().enumerate() {
        for (ti, tx) in layer.iter().enumerate() {
            for (oi, output) in tx.outputs.iter().enumerate() {
                if let PrepOutput::Intermediate(v) = output {
                    if !spent.contains(&(li, ti, oi)) {
                        out.push((
                            PrepInput::Prior {
                                layer: li,
                                transaction: ti,
                                output: oi,
                            },
                            *v,
                        ));
                    }
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// A representative padded 16-action ZIP-317 fee reserve for the tests (16 * 5000-zatoshi marginal
    /// fee). The planner treats it opaquely.
    const FEE_PER_TX: u64 = PREP_TX_ACTIONS as u64 * 5_000;

    /// The multiset of funding values a plan mints, sorted, for comparison against the request.
    fn minted_funding(plan: &PreparationPlan) -> Vec<u64> {
        let mut out: Vec<u64> = plan
            .layers()
            .iter()
            .flatten()
            .flat_map(PrepTransaction::outputs)
            .filter_map(|o| match o {
                PrepOutput::Funding(v) => Some(*v),
                _ => None,
            })
            .collect();
        out.sort_unstable();
        out
    }

    /// The number of final `Change` (residual) outputs across the whole plan.
    fn change_count(plan: &PreparationPlan) -> usize {
        plan.layers()
            .iter()
            .flatten()
            .flat_map(PrepTransaction::outputs)
            .filter(|o| matches!(o, PrepOutput::Change(_)))
            .count()
    }

    /// Assert every structural invariant of a plan against its inputs.
    fn assert_plan_valid(plan: &PreparationPlan, available: &[u64], funding: &[u64], fee: u64) {
        // Every requested funding note is minted exactly once.
        let mut want: Vec<u64> = funding.iter().copied().filter(|&v| v > 0).collect();
        want.sort_unstable();
        assert_eq!(minted_funding(plan), want, "funding multiset");

        let mut wallet_spent = 0u64;
        let mut total_fees = 0u64;
        let mut final_out = 0u64; // funding + change (intermediates are consumed downstream)

        for (li, layer) in plan.layers().iter().enumerate() {
            for (ti, tx) in layer.iter().enumerate() {
                // Action budget.
                assert!(
                    tx.action_count() <= PREP_TX_ACTIONS,
                    "layer {li} tx {ti}: {} actions",
                    tx.action_count()
                );
                assert!(!tx.inputs().is_empty(), "layer {li} tx {ti}: no inputs");
                assert!(!tx.outputs().is_empty(), "layer {li} tx {ti}: no outputs");

                let mut in_sum = 0u64;
                for input in tx.inputs() {
                    // Every reference resolves, and a Prior input points strictly backwards.
                    if let PrepInput::Prior { layer, .. } = input {
                        assert!(*layer < li, "layer {li} tx {ti}: forward/self reference");
                    }
                    let v = plan.input_value(input, available).expect("input resolves");
                    in_sum += v;
                    if let PrepInput::Wallet(_) = input {
                        wallet_spent += v;
                    }
                }
                let out_sum: u64 = tx.outputs().iter().map(PrepOutput::value).sum();
                // Value conservation: inputs = outputs + the reserved fee.
                assert_eq!(in_sum, out_sum + fee, "layer {li} tx {ti}: conservation");
                total_fees += fee;
                for o in tx.outputs() {
                    match o {
                        PrepOutput::Funding(v) | PrepOutput::Change(v) => final_out += v,
                        PrepOutput::Intermediate(_) => {}
                    }
                }
            }
        }

        // Global conservation: the wallet value spent equals what left as funding/change plus fees.
        assert_eq!(wallet_spent, final_out + total_fees, "global conservation");
    }

    fn arb_input() -> impl Strategy<Value = (Vec<u64>, Vec<u64>)> {
        (
            prop::collection::vec(1u64..2_000_000, 0..12),
            prop::collection::vec(1u64..500_000, 1..20),
        )
    }

    /// Funding plus available notes that always include one note large enough to fund everything with
    /// a generous fee budget, so the planner must succeed.
    fn arb_sufficient() -> impl Strategy<Value = (Vec<u64>, Vec<u64>)> {
        prop::collection::vec(1u64..500_000, 1..20).prop_flat_map(|funding| {
            let need: u64 = funding.iter().sum();
            let big = need + (funding.len() as u64 + 64) * FEE_PER_TX + 1;
            (prop::collection::vec(1u64..100_000, 0..8), Just(funding)).prop_map(
                move |(mut extra, funding)| {
                    extra.push(big);
                    (extra, funding)
                },
            )
        })
    }

    proptest! {
        /// Whenever a plan is produced over arbitrary inputs, every structural invariant holds.
        #[test]
        fn valid_whenever_planned((available, funding) in arb_input()) {
            if let Ok(plan) = plan_preparation(&available, &funding, FEE_PER_TX) {
                assert_plan_valid(&plan, &available, &funding, FEE_PER_TX);
            }
        }

        /// With one note large enough to fund everything, the planner always succeeds with a valid
        /// plan (the planner never gives up when the value is amply present).
        #[test]
        fn always_plans_when_amply_funded((available, funding) in arb_sufficient()) {
            let plan = plan_preparation(&available, &funding, FEE_PER_TX)
                .expect("ample funding must plan");
            assert_plan_valid(&plan, &available, &funding, FEE_PER_TX);
            // The leftover is far larger than a fee, so it collapses to a single residual note.
            prop_assert!(change_count(&plan) <= 1, "{} residual notes", change_count(&plan));
        }
    }

    /// A single well-funded note mints a handful of funding notes in one layer, one transaction.
    #[test]
    fn common_case_is_one_layer_one_tx() {
        let funding = [500u64, 200, 100, 20, 5];
        let total: u64 = funding.iter().sum::<u64>() + FEE_PER_TX + 10_000;
        let plan = plan_preparation(&[total], &funding, FEE_PER_TX).unwrap();
        assert_eq!(plan.layer_count(), 1);
        assert_eq!(plan.transaction_count(), 1);
        assert_eq!(change_count(&plan), 1, "one residual note");
        assert_plan_valid(&plan, &[total], &funding, FEE_PER_TX);
    }

    /// One large note fanning out into more funding notes than a single transaction holds needs more
    /// than one layer (the remainder feeds forward), yet every transaction stays within budget.
    #[test]
    fn whale_single_note_fans_out_across_layers() {
        let funding: Vec<u64> = (0..40).map(|_| 100u64).collect();
        let total: u64 = funding.iter().sum::<u64>() + 60 * FEE_PER_TX;
        let plan = plan_preparation(&[total], &funding, FEE_PER_TX).unwrap();
        assert!(
            plan.layer_count() >= 2,
            "40 funding notes cannot fit one tx"
        );
        assert_eq!(change_count(&plan), 1, "one residual note");
        assert_plan_valid(&plan, &[total], &funding, FEE_PER_TX);
    }

    /// Dust smaller than a funding note is consolidated into a feeder before it can fund anything, and
    /// the leftover collapses to a single residual note.
    #[test]
    fn dust_is_consolidated_first() {
        // Twenty notes each far below the single 100-unit funding note (plus fees).
        let per = FEE_PER_TX + 20;
        let available: Vec<u64> = core::iter::repeat_n(per, 20).collect();
        let funding = [100u64];
        let plan = plan_preparation(&available, &funding, FEE_PER_TX).unwrap();
        assert!(plan.layer_count() >= 2, "dust must consolidate first");
        assert_eq!(change_count(&plan), 1, "one residual note");
        assert_plan_valid(&plan, &available, &funding, FEE_PER_TX);
    }

    /// Empty funding yields an empty plan; value below the funding-plus-fee floor is insufficient.
    #[test]
    fn edge_cases() {
        assert_eq!(
            plan_preparation(&[1_000_000], &[], FEE_PER_TX)
                .unwrap()
                .layer_count(),
            0
        );
        assert_eq!(
            plan_preparation(&[10], &[100], FEE_PER_TX),
            Err(PrepError::InsufficientFunds)
        );
    }

    /// The consolidation batching never leaves a lone note and never exceeds the input budget.
    #[test]
    fn consolidation_batches_avoid_singletons() {
        for n in 2..200usize {
            let sizes = consolidation_batch_sizes(n);
            assert_eq!(sizes.iter().sum::<usize>(), n);
            for s in sizes {
                assert!(
                    (2..=CONSOLIDATION_INPUTS_PER_TX).contains(&s),
                    "n={n} size={s}"
                );
            }
        }
    }
}
