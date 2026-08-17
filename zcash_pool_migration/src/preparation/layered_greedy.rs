//! The largest-first layered greedy [`PreparationStrategy`].
//!
//! In each layer it feeds each output transaction from the largest available note it can (one big
//! note funds up to [`FUNDING_OUTPUTS_PER_TX`] funding notes), routes every leftover forward as an
//! intermediate ("feeder") note, and consolidates sub-quantum notes (too small to fund anything on
//! their own) into feeder notes. Once all funding notes are scheduled it consolidates the feeders
//! that no layer spent into a single residual note, matching [ZIP 318]'s "one note per part plus at
//! most one residual note". For a typical wallet (a few notes, a handful of funding notes) this is a
//! single layer; extra layers appear only for a lone large note fanning out into many funding notes,
//! or a sub-quantum-heavy balance.
//!
//! The single-residual goal is only reachable above the fee threshold. When several transactions each
//! strand a remainder smaller than a transaction fee and those remainders together are still worth
//! less than one fee, no consolidation can merge them (its output would be negative), so they remain
//! as multiple sub-fee change notes. The planner therefore guarantees at most one residual note worth
//! a fee; any further residue is sub-fee dust.
//!
//! When a single note can produce every funding note, the planner takes a fan-out fast path: it
//! splits that note through a BALANCED tree (fanning out by [`FUNDING_OUTPUTS_PER_TX`] per layer), so
//! the depth is logarithmic in the funding-note count rather than linear in it. The balanced tree
//! uses more transactions, and so more fee, than a linear feeder chain would; it trades that for
//! fewer layers, which dominate the wall-clock. Every other shape (many notes, mixed sizes,
//! sub-quantum) uses the layered greedy above.
//!
//! Every SPLITTING transaction it builds has exactly one input; several inputs appear only in a
//! consolidation, which produces exactly one output. It therefore reaches only the two extreme
//! shapes of the `spends + outputs <= PREP_TX_ACTIONS` budget, never its interior, and reports a set
//! of funding notes unfundable whenever minting them would need a transaction spending more than one
//! note while producing more than one.
//!
//! [ZIP 318]: https://zips.z.cash/zip-0318

use alloc::vec::Vec;

use zcash_protocol::value::Zatoshis;

use super::{
    CONSOLIDATION_INPUTS_PER_TX, FUNDING_OUTPUTS_PER_TX, PrepError, PrepInput, PrepOutput,
    PrepTransaction, PreparationPlan, PreparationStrategy, validate_instance, zat,
};

/// The largest-first layered greedy described in the [module docs](self).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LayeredGreedy;

impl PreparationStrategy for LayeredGreedy {
    fn name(&self) -> &'static str {
        "layered-greedy"
    }

    fn plan(
        &self,
        available: &[Zatoshis],
        funding: &[Zatoshis],
        fee_per_tx: Zatoshis,
    ) -> Result<PreparationPlan, PrepError> {
        plan_layered(available, funding, fee_per_tx)
    }
}

fn plan_layered(
    available: &[Zatoshis],
    funding: &[Zatoshis],
    fee_per_tx: Zatoshis,
) -> Result<PreparationPlan, PrepError> {
    // Bounds every value the plan constructs by the validated available total, which is what makes
    // the internal `zat` conversions infallible. `plan_preparation` checks this too, but a strategy
    // invoked directly through the trait cannot rely on that.
    validate_instance(available, funding)?;
    // The partition arithmetic below runs in the u64 domain.
    let available: Vec<u64> = available.iter().map(|&v| u64::from(v)).collect();
    let fee_per_tx = u64::from(fee_per_tx);

    // Funding values still to produce, largest first (so `last()` is the smallest).
    let mut remaining: Vec<u64> = funding
        .iter()
        .map(|&v| u64::from(v))
        .filter(|&v| v > 0)
        .collect();
    remaining.sort_unstable_by(|a, b| b.cmp(a));

    // Exact-match pass: a wallet note already equal to a funding value IS that funding note, so it is
    // used directly, with no preparation transaction and no fee. The matched notes are removed from
    // both the funding still to produce and the notes available to spend.
    let mut used = vec![false; available.len()];
    let mut direct_funding: Vec<(usize, Zatoshis)> = Vec::new();
    remaining.retain(|&f| {
        match available
            .iter()
            .enumerate()
            .position(|(i, &v)| !used[i] && v == f)
        {
            Some(i) => {
                used[i] = true;
                direct_funding.push((i, zat(f)));
                false
            }
            None => true,
        }
    });

    let mut layers: Vec<Vec<PrepTransaction>> = Vec::new();
    if remaining.is_empty() {
        return Ok(PreparationPlan {
            layers,
            direct_funding,
        });
    }

    // Fan-out fast path: when a single wallet note can produce every remaining funding note, split it
    // through a balanced tree (depth logarithmic in the note count) rather than the linear feeder chain
    // the layered loop below would build for a lone large note. Only that case takes this path;
    // everything else (many notes, mixed sizes, sub-quantum) falls through to the layered greedy
    // unchanged.
    // Trade-off: the balanced tree uses more transactions (fees) than the chain, buying fewer layers.
    if let Some((idx, big)) = available
        .iter()
        .enumerate()
        .filter(|(i, _)| !used[*i])
        .map(|(i, &v)| (i, v))
        .max_by_key(|&(_, v)| v)
        && big >= subtree_cost(&remaining, fee_per_tx).1
    {
        build_split(
            PrepInput::Wallet {
                index: idx,
                value: zat(big),
            },
            big,
            &remaining,
            fee_per_tx,
            0,
            &mut layers,
        );
        remaining.clear();
    }

    // The notes available to spend in the current layer (layer 0: the wallet's own notes not already
    // used directly as funding notes).
    let mut current: Vec<PrepInput> = available
        .iter()
        .enumerate()
        .filter(|(i, _)| !used[*i])
        .map(|(i, &v)| PrepInput::Wallet {
            index: i,
            value: zat(v),
        })
        .collect();

    while !remaining.is_empty() {
        if current.is_empty() {
            return Err(PrepError::InsufficientFunds);
        }
        // Largest notes first.
        current.sort_unstable_by_key(|n| core::cmp::Reverse(u64::from(n.value())));

        // Pass 1: assign funding to the notes that can fund at least the smallest remaining note.
        // `partial` holds a note, the funding values it will mint, and its leftover budget; the rest
        // go to `consolidatable` to be combined into feeder notes.
        let mut partial: Vec<(PrepInput, Vec<u64>, u64)> = Vec::new();
        let mut consolidatable: Vec<PrepInput> = Vec::new();

        for input in current.drain(..) {
            if remaining.is_empty() {
                // Everything is already scheduled; this note stays unspent in the wallet.
                continue;
            }
            let value = u64::from(input.value());
            let smallest = *remaining.last().expect("remaining is non-empty");
            if value <= fee_per_tx || value - fee_per_tx < smallest {
                consolidatable.push(input);
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
            partial.push((input, assigned, budget - used));
        }

        // Pass 2: mint the funding notes, routing every leftover forward as a feeder so a later layer
        // reuses it rather than scattering change.
        let mut txs: Vec<PrepTransaction> = Vec::new();
        let mut next: Vec<PrepInput> = Vec::new();
        for (input, assigned, leftover) in partial {
            let mut outputs: Vec<PrepOutput> = assigned
                .into_iter()
                .map(|v| PrepOutput::Funding(zat(v)))
                .collect();
            if leftover > 0 {
                next.push(PrepInput::Prior {
                    layer: layers.len(),
                    transaction: txs.len(),
                    output: outputs.len(),
                    value: zat(leftover),
                });
                outputs.push(PrepOutput::Intermediate(zat(leftover)));
            }
            txs.push(PrepTransaction {
                inputs: vec![input],
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
        let mut next: Vec<PrepInput> = Vec::new();
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
                    ..
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
                if let PrepOutput::Intermediate(v) = *out
                    && !spent.contains(&(li, ti, oi))
                {
                    *out = PrepOutput::Change(v);
                }
            }
        }
    }

    Ok(PreparationPlan {
        layers,
        direct_funding,
    })
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
    mut pool: Vec<PrepInput>,
    layer: usize,
    fee: u64,
    txs: &mut Vec<PrepTransaction>,
    next: &mut Vec<PrepInput>,
) -> Vec<PrepInput> {
    if pool.len() < 2 {
        return pool;
    }
    pool.sort_unstable_by_key(|n| core::cmp::Reverse(u64::from(n.value())));
    let mut leftover = Vec::new();
    for size in consolidation_batch_sizes(pool.len()) {
        let batch: Vec<PrepInput> = pool.drain(..size).collect();
        let sum: u64 = batch.iter().map(|n| u64::from(n.value())).sum();
        if sum <= fee {
            leftover.extend(batch); // too small to pay a fee; leave unspent
            continue;
        }
        let feeder = sum - fee;
        next.push(PrepInput::Prior {
            layer,
            transaction: txs.len(),
            output: 0,
            value: zat(feeder),
        });
        txs.push(PrepTransaction {
            inputs: batch,
            outputs: vec![PrepOutput::Intermediate(zat(feeder))],
        });
    }
    leftover
}

/// Every intermediate ("feeder") output that no transaction spends, as [`PrepInput`] references (each
/// carrying its value).
fn unconsumed_feeders(layers: &[Vec<PrepTransaction>]) -> Vec<PrepInput> {
    let mut spent: Vec<(usize, usize, usize)> = Vec::new();
    for layer in layers {
        for tx in layer {
            for input in &tx.inputs {
                if let PrepInput::Prior {
                    layer,
                    transaction,
                    output,
                    ..
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
                if let PrepOutput::Intermediate(v) = output
                    && !spent.contains(&(li, ti, oi))
                {
                    out.push(PrepInput::Prior {
                        layer: li,
                        transaction: ti,
                        output: oi,
                        value: *v,
                    });
                }
            }
        }
    }
    out
}

/// The most funding notes a balanced split subtree of the given `depth` can produce: each level fans
/// out by [`FUNDING_OUTPUTS_PER_TX`] (one input, the rest outputs), so a depth-`d` subtree holds up to
/// `FUNDING_OUTPUTS_PER_TX^d` funding notes (a depth-1 leaf holds one full transaction of them).
fn subtree_capacity(depth: usize) -> usize {
    FUNDING_OUTPUTS_PER_TX.pow(depth as u32)
}

/// The fewest balanced-split layers that produce `n` funding notes from one source note (the depth `d`
/// with `subtree_capacity(d) >= n`). Zero for `n == 0`.
fn split_depth(n: usize) -> usize {
    if n == 0 {
        return 0;
    }
    let mut depth = 1;
    while subtree_capacity(depth) < n {
        depth += 1;
    }
    depth
}

/// Group sizes for splitting `len` targets into `g` contiguous groups as evenly as possible (the first
/// `len % g` groups get one extra).
fn even_group_sizes(len: usize, g: usize) -> Vec<usize> {
    let base = len / g;
    let extra = len % g;
    (0..g).map(|i| base + usize::from(i < extra)).collect()
}

/// The transaction count and the value a single source note must carry to produce exactly `targets`
/// (the funding notes) through a balanced split tree: each transaction costs one `fee`, and the tree
/// fans out by [`FUNDING_OUTPUTS_PER_TX`] until each leaf holds at most that many funding notes.
fn subtree_cost(targets: &[u64], fee: u64) -> (u64, u64) {
    let depth = split_depth(targets.len());
    if depth <= 1 {
        return (1, targets.iter().sum::<u64>() + fee);
    }
    let child_cap = subtree_capacity(depth - 1);
    let g = targets.len().div_ceil(child_cap);
    let mut start = 0;
    let mut txs = 1u64;
    let mut value = fee;
    for size in even_group_sizes(targets.len(), g) {
        let (t, v) = subtree_cost(&targets[start..start + size], fee);
        txs += t;
        value += v;
        start += size;
    }
    (txs, value)
}

/// Build a balanced split of `source` (a note reference worth `source_value`) into the funding notes
/// `targets`, appending transactions to `layers` from `layer` downwards. Each transaction funds up to
/// [`FUNDING_OUTPUTS_PER_TX`] notes directly at a leaf, or fans out into up to that many feeder notes
/// (one per child subtree) at an internal node, so the depth is [`split_depth`] of the target count
/// rather than linear in it. Only the top call (the whole source note) carries a leftover; it is
/// emitted as an intermediate feeder so the residual pass merges it. The internal feeders are exact.
fn build_split(
    source: PrepInput,
    source_value: u64,
    targets: &[u64],
    fee: u64,
    layer: usize,
    layers: &mut Vec<Vec<PrepTransaction>>,
) {
    while layers.len() <= layer {
        layers.push(Vec::new());
    }
    let tx_index = layers[layer].len();
    let depth = split_depth(targets.len());

    if depth <= 1 {
        // Leaf: fund every target directly, with any leftover as an intermediate (residual) note.
        let mut outputs: Vec<PrepOutput> = targets
            .iter()
            .map(|&v| PrepOutput::Funding(zat(v)))
            .collect();
        let spent: u64 = targets.iter().sum();
        let leftover = source_value - fee - spent;
        if leftover > 0 {
            outputs.push(PrepOutput::Intermediate(zat(leftover)));
        }
        layers[layer].push(PrepTransaction {
            inputs: vec![source],
            outputs,
        });
        return;
    }

    // Internal node: fan out into one feeder per child subtree.
    let child_cap = subtree_capacity(depth - 1);
    let g = targets.len().div_ceil(child_cap);
    let sizes = even_group_sizes(targets.len(), g);

    let mut groups: Vec<(usize, usize)> = Vec::new(); // (start, size)
    let mut child_values: Vec<u64> = Vec::new();
    let mut start = 0;
    for size in sizes {
        child_values.push(subtree_cost(&targets[start..start + size], fee).1);
        groups.push((start, size));
        start += size;
    }

    let mut outputs: Vec<PrepOutput> = child_values
        .iter()
        .map(|&v| PrepOutput::Intermediate(zat(v)))
        .collect();
    let spent: u64 = child_values.iter().sum();
    let leftover = source_value - fee - spent;
    if leftover > 0 {
        outputs.push(PrepOutput::Intermediate(zat(leftover)));
    }
    layers[layer].push(PrepTransaction {
        inputs: vec![source],
        outputs,
    });

    for (output, ((gstart, gsize), &cv)) in groups.iter().zip(child_values.iter()).enumerate() {
        let child = PrepInput::Prior {
            layer,
            transaction: tx_index,
            output,
            value: zat(cv),
        };
        build_split(
            child,
            cv,
            &targets[*gstart..*gstart + *gsize],
            fee,
            layer + 1,
            layers,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    use zcash_primitives::transaction::fees::zip317::MARGINAL_FEE;

    use crate::preparation::{PREP_TX_ACTIONS, Portfolio};
    use crate::testing::{Fundability, PREPARATION_VECTORS, preparation_fee_per_tx};

    /// A representative padded [`PREP_TX_ACTIONS`]-action ZIP-317 fee reserve for the tests (each
    /// action costs one ZIP-317 marginal fee). The planner treats it opaquely.
    fn fee_per_tx() -> u64 {
        PREP_TX_ACTIONS as u64 * MARGINAL_FEE.into_u64()
    }

    /// Wrap test values as [`Zatoshis`] at the public boundary; the tables and arithmetic in these
    /// tests stay in the readable u64 domain.
    fn zats(values: &[u64]) -> Vec<Zatoshis> {
        values.iter().map(|&v| zat(v)).collect()
    }

    /// This strategy's plan over the tests' u64 values.
    fn plan_prep(
        available: &[u64],
        funding: &[u64],
        fee_per_tx: u64,
    ) -> Result<PreparationPlan, PrepError> {
        LayeredGreedy.plan(&zats(available), &zats(funding), zat(fee_per_tx))
    }

    /// The funding values a plan mints, sorted, for multiset comparison against the request.
    fn sorted_funding(plan: &PreparationPlan) -> Vec<u64> {
        let mut out: Vec<u64> = plan.funding_notes().iter().map(|&v| u64::from(v)).collect();
        out.sort_unstable();
        out
    }

    /// Assert every structural invariant of a plan against its inputs.
    fn assert_plan_valid(plan: &PreparationPlan, available: &[u64], funding: &[u64], fee: u64) {
        // Every requested funding note is minted exactly once.
        let mut want: Vec<u64> = funding.iter().copied().filter(|&v| v > 0).collect();
        want.sort_unstable();
        assert_eq!(sorted_funding(plan), want, "funding multiset");

        // A k-ary lower bound: a transaction has at least one spend, so it emits at most
        // `PREP_TX_ACTIONS - 1` outputs and thus at most that many funding notes; minting `l` of them
        // (the funding notes not used directly) needs at least `ceil(l / (A - 1))` transactions.
        let minted = want.len() - plan.direct_funding_notes().len();
        if minted > 0 {
            let min_txs = minted.div_ceil(PREP_TX_ACTIONS - 1);
            assert!(
                plan.transaction_count() >= min_txs,
                "transaction count {} below the k-ary lower bound {min_txs}",
                plan.transaction_count()
            );
        }

        let mut wallet_spent = 0u64;
        let mut total_fees = 0u64;
        let mut final_out = 0u64; // funding + change (intermediates are consumed downstream)
        // Every input reference across the whole plan, to prove no note is spent twice.
        let mut seen_inputs: Vec<PrepInput> = Vec::new();

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
                    // Single-spend: an atomic Orchard note is spent by at most one transaction.
                    assert!(
                        !seen_inputs.contains(input),
                        "layer {li} tx {ti}: note spent twice: {input:?}"
                    );
                    seen_inputs.push(*input);
                    // Every reference resolves, and a Prior input points strictly backwards.
                    if let PrepInput::Prior { layer, .. } = input {
                        assert!(*layer < li, "layer {li} tx {ti}: forward/self reference");
                    }
                    let v = u64::from(input.value());
                    in_sum += v;
                    if let PrepInput::Wallet { .. } = input {
                        wallet_spent += v;
                    }
                }
                let out_sum: u64 = tx.outputs().iter().map(|o| u64::from(o.value())).sum();
                // Value conservation: inputs = outputs + the reserved fee.
                assert_eq!(in_sum, out_sum + fee, "layer {li} tx {ti}: conservation");
                total_fees += fee;
                for o in tx.outputs() {
                    match o {
                        PrepOutput::Funding(v) | PrepOutput::Change(v) => {
                            final_out += u64::from(*v)
                        }
                        PrepOutput::Intermediate(_) => {}
                    }
                }
            }
        }

        // Global conservation: the wallet value spent equals what left as funding/change plus fees.
        assert_eq!(wallet_spent, final_out + total_fees, "global conservation");

        // Directly-used wallet notes are untouched: each carries the claimed value and is spent by no
        // transaction (so it is not double-counted against the wallet balance).
        for &(i, v) in plan.direct_funding_notes() {
            assert_eq!(
                available.get(i).copied(),
                Some(u64::from(v)),
                "direct funding note {i} value"
            );
            assert!(
                !seen_inputs.contains(&PrepInput::Wallet { index: i, value: v }),
                "direct funding note {i} also spent by a transaction"
            );
        }

        // Residual: at most one Change note is worth a fee. ZIP 318's "at most one residual note" is
        // only achievable above the fee threshold; when several spends each strand a sub-fee remainder
        // whose total is itself below one transaction fee, no consolidation can merge them (its output
        // would be negative), so they survive as multiple sub-fee Change notes. Two Change notes each
        // >= fee could always be merged, so the planner never leaves more than one.
        let changes: Vec<u64> = plan
            .residual_notes()
            .iter()
            .map(|&v| u64::from(v))
            .collect();
        let fundable_residuals = changes.iter().filter(|&&v| v >= fee).count();
        assert!(
            fundable_residuals <= 1,
            "at most one residual >= fee; got {fundable_residuals} of {changes:?}"
        );
        if changes.len() > 1 {
            let total: u64 = changes.iter().sum();
            assert!(
                total < fee,
                "multiple residuals only when their total is sub-fee; total {total} fee {fee}"
            );
        }
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
            let big = need + (funding.len() as u64 + 64) * fee_per_tx() + 1;
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
            if let Ok(plan) = plan_prep(&available, &funding, fee_per_tx()) {
                assert_plan_valid(&plan, &available, &funding, fee_per_tx());
            }
        }

        /// With one note large enough to fund everything, the planner always succeeds with a valid
        /// plan (the planner never gives up when the value is amply present).
        #[test]
        fn always_plans_when_amply_funded((available, funding) in arb_sufficient()) {
            let plan = plan_prep(&available, &funding, fee_per_tx())
                .expect("ample funding must plan");
            assert_plan_valid(&plan, &available, &funding, fee_per_tx());
            // The leftover is far larger than a fee, so it collapses to a single residual note.
            prop_assert!(plan.residual_count() <= 1, "{} residual notes", plan.residual_count());
        }
    }

    /// One well-funded note mints SEVERAL funding notes in a single preparation transaction: a
    /// preparation transaction produces one output per scheduled part (up to `FUNDING_OUTPUTS_PER_TX`),
    /// not one transaction per part (that is the phase-2 transfer). So this is one layer, one
    /// transaction, with several funding outputs.
    #[test]
    fn common_case_is_one_layer_one_tx() {
        let funding = [500u64, 200, 100, 20, 5];
        let total: u64 = funding.iter().sum::<u64>() + fee_per_tx() + 10_000;
        let plan = plan_prep(&[total], &funding, fee_per_tx()).unwrap();
        assert_eq!(plan.layer_count(), 1);
        assert_eq!(plan.transaction_count(), 1);
        assert_eq!(plan.residual_count(), 1, "one residual note");
        assert_plan_valid(&plan, &[total], &funding, fee_per_tx());
    }

    /// One large note fanning out into more funding notes than a single transaction holds needs more
    /// than one layer (the remainder feeds forward), yet every transaction stays within budget.
    #[test]
    fn whale_single_note_fans_out_across_layers() {
        let funding: Vec<u64> = (0..40).map(|_| 100u64).collect();
        let total: u64 = funding.iter().sum::<u64>() + 60 * fee_per_tx();
        let plan = plan_prep(&[total], &funding, fee_per_tx()).unwrap();
        assert!(
            plan.layer_count() >= 2,
            "40 funding notes cannot fit one tx"
        );
        assert_eq!(plan.residual_count(), 1, "one residual note");
        assert_plan_valid(&plan, &[total], &funding, fee_per_tx());
    }

    /// A sub-quantum note (smaller than any funding note) is consolidated into a feeder before it can
    /// fund anything, and the leftover collapses to a single residual note.
    #[test]
    fn sub_quantum_is_consolidated_first() {
        // Twenty notes each far below the single 100-unit funding note (plus fees).
        let per = fee_per_tx() + 20;
        let available: Vec<u64> = core::iter::repeat_n(per, 20).collect();
        let funding = [100u64];
        let plan = plan_prep(&available, &funding, fee_per_tx()).unwrap();
        assert!(
            plan.layer_count() >= 2,
            "sub-quantum notes must consolidate first"
        );
        assert_eq!(plan.residual_count(), 1, "one residual note");
        assert_plan_valid(&plan, &available, &funding, fee_per_tx());
    }

    /// When several notes each strand a sub-fee remainder whose total is below one transaction fee, the
    /// remainders cannot be consolidated (the output would be negative), so they survive as multiple
    /// sub-fee residual notes. ZIP 318's "at most one residual note" is only achievable above the fee
    /// threshold; this documents the unavoidable corner case.
    #[test]
    fn sub_fee_remainders_leave_multiple_residuals() {
        // Three notes, each funding one 100_000 note and stranding a 100-zatoshi remainder; the three
        // remainders total 300 < fee_per_tx(), so no consolidation can merge them.
        let f = 100_000u64;
        let eps = 100u64;
        let note = f + fee_per_tx() + eps;
        let available = [note, note, note];
        let funding = [f, f, f];
        let plan = plan_prep(&available, &funding, fee_per_tx()).unwrap();
        assert_plan_valid(&plan, &available, &funding, fee_per_tx());
        let changes: Vec<u64> = plan
            .residual_notes()
            .iter()
            .map(|&v| u64::from(v))
            .collect();
        assert!(
            changes.len() > 1,
            "expected multiple sub-fee residuals: {changes:?}"
        );
        assert!(
            changes.iter().all(|&v| v < fee_per_tx()),
            "all residuals sub-fee"
        );
        assert!(
            changes.iter().sum::<u64>() < fee_per_tx(),
            "total residual sub-fee"
        );
    }

    /// Empty funding yields an empty plan; value below the funding-plus-fee floor is insufficient.
    #[test]
    fn edge_cases() {
        assert_eq!(
            plan_prep(&[1_000_000], &[], fee_per_tx())
                .unwrap()
                .layer_count(),
            0
        );
        assert_eq!(
            plan_prep(&[10], &[100], fee_per_tx()),
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

    /// When the total available value is below the funding note plus one transaction fee, no
    /// arrangement of transactions can fund it, and the planner reports insufficiency rather than
    /// emitting a broken plan.
    #[test]
    fn many_tiny_notes_insufficient() {
        // 5 x 30_000 = 150_000 available. Funding one 100_000 note costs at least the note plus one
        // fee: 100_000 + fee_per_tx() (80_000) = 180_000. Since 150_000 < 180_000, it is unfundable.
        let available = vec![30_000u64; 5];
        assert_eq!(
            plan_prep(&available, &[100_000], fee_per_tx()),
            Err(PrepError::InsufficientFunds)
        );
    }

    /// Sub-quantum notes that cannot fund on their own consolidate in batches of at most
    /// `CONSOLIDATION_INPUTS_PER_TX`, never a singleton; the first layer's transactions have exactly
    /// the shape `consolidation_batch_sizes` prescribes.
    #[test]
    fn sub_quantum_consolidation_batch_shapes() {
        for n in [15usize, 16, 17, 30] {
            // Each note is below the 100_000 funding note, so the whole first layer is consolidation.
            let available = vec![50_000u64; n];
            let funding = [100_000u64];
            let plan = plan_prep(&available, &funding, fee_per_tx()).unwrap();
            assert_plan_valid(&plan, &available, &funding, fee_per_tx());
            let mut got: Vec<usize> = plan.layers()[0]
                .iter()
                .map(|tx| tx.inputs().len())
                .collect();
            got.sort_unstable();
            let mut want = consolidation_batch_sizes(n);
            want.sort_unstable();
            assert_eq!(got, want, "n={n}");
        }
    }

    /// A single layer can both split a large note directly into a funding note and consolidate a cloud
    /// of sub-quantum notes that are needed to fund the rest. (Sub-quantum notes the plan does not
    /// need are left untouched, so the large note must be too small to fund everything on its own.)
    #[test]
    fn mixes_split_and_consolidate_in_one_layer() {
        let mut available = vec![40_000u64; 10]; // sub-quantum: needed to fund the 100_000 note
        available.push(400_000); // funds the 300_000 note directly, but not also the 100_000 note
        let funding = [300_000u64, 100_000];
        let plan = plan_prep(&available, &funding, fee_per_tx()).unwrap();
        assert_plan_valid(&plan, &available, &funding, fee_per_tx());
        let layer0 = &plan.layers()[0];
        assert!(
            layer0.iter().any(|tx| tx.inputs().len() == 1),
            "a one-input split transaction"
        );
        assert!(
            layer0.iter().any(|tx| tx.inputs().len() > 1),
            "a multi-input consolidation transaction"
        );
    }

    /// Fee-dominated sub-quantum notes (each only just above the per-transaction fee) cannot overcome
    /// the per-transaction fee to reach a funding note, and the planner terminates with insufficient
    /// funds rather than looping.
    #[test]
    fn fee_dominated_sub_quantum_terminates_insufficient() {
        // Two 90_000 notes: one consolidation nets 100_000, still short of 100_000 + a funding fee.
        let available = vec![90_000u64; 2];
        assert_eq!(
            plan_prep(&available, &[100_000], fee_per_tx()),
            Err(PrepError::InsufficientFunds)
        );
    }

    /// A single sub-quantum note cannot be batched (a lone consolidation only wastes a fee) and cannot
    /// fund a larger note: insufficient when needed, and left untouched (empty plan) when not.
    #[test]
    fn lone_sub_quantum_note() {
        assert_eq!(
            plan_prep(&[50_000], &[100_000], fee_per_tx()),
            Err(PrepError::InsufficientFunds)
        );
        assert_eq!(
            plan_prep(&[50_000], &[], fee_per_tx())
                .unwrap()
                .layer_count(),
            0
        );
    }

    /// A note worth exactly a funding value plus the fee funds it with no leftover, so it leaves no
    /// residual; a note worth only the fee carries no spendable budget.
    #[test]
    fn threshold_notes() {
        let f = 100_000u64;
        let exact = f + fee_per_tx();
        let plan = plan_prep(&[exact], &[f], fee_per_tx()).unwrap();
        assert_plan_valid(&plan, &[exact], &[f], fee_per_tx());
        assert_eq!(plan.transaction_count(), 1);
        assert_eq!(plan.residual_count(), 0, "exact funding leaves no residual");

        // A note worth only the fee has zero spendable budget; on its own it cannot fund anything.
        assert_eq!(
            plan_prep(&[fee_per_tx()], &[f], fee_per_tx()),
            Err(PrepError::InsufficientFunds)
        );
    }

    /// Deep consolidation: 300 sub-quantum notes consolidate 15:1 per layer (300 -> 20 -> 2), then a
    /// funding layer, then one residual-collapse layer: exactly four layers, one residual. The count
    /// grows only logarithmically (base `CONSOLIDATION_INPUTS_PER_TX`) in the sub-quantum-note count.
    #[test]
    fn deep_consolidation_layer_count() {
        let available = vec![50_000u64; 300];
        let funding = [1_000_000u64];
        let plan = plan_prep(&available, &funding, fee_per_tx()).unwrap();
        assert_plan_valid(&plan, &available, &funding, fee_per_tx());
        assert_eq!(
            plan.layer_count(),
            4,
            "300 sub-quantum -> 20 -> 2 -> fund -> residual"
        );
        assert_eq!(plan.residual_count(), 1);
    }

    /// A very large sub-quantum-note count still plans in a small, logarithmically-bounded number of
    /// layers: 3000 -> 200 -> 14 -> 1 feeder, then a funding layer, exactly four layers. This is the
    /// "many small notes" stress case (termination and performance).
    #[test]
    fn thousands_of_sub_quantum_notes_layer_count() {
        let available = vec![50_000u64; 3_000];
        let funding = [10_000_000u64];
        let plan = plan_prep(&available, &funding, fee_per_tx()).unwrap();
        assert_plan_valid(&plan, &available, &funding, fee_per_tx());
        assert_eq!(
            plan.layer_count(),
            4,
            "3000 sub-quantum -> 200 -> 14 -> 1 -> fund"
        );
    }

    /// A lone large note fanning out into many funding notes is split through a BALANCED tree, so the
    /// layer count is `split_depth(p)` (logarithmic in `p`), not linear. This is the fan-out-first
    /// path; the balanced tree uses more transactions than a linear chain in exchange for fewer layers.
    /// The transitions are at 14 -> 15 (depth 1 -> 2) and 196 -> 197 (depth 2 -> 3).
    #[test]
    fn whale_fan_out_layer_counts() {
        for p in [1usize, 14, 15, 28, 100, 196, 197, 500] {
            let funding = vec![100u64; p];
            // The balanced tree costs more than a linear chain; fund exactly that plus a small residual.
            let whale = subtree_cost(&funding, fee_per_tx()).1 + 9_999;
            let plan = plan_prep(&[whale], &funding, fee_per_tx()).unwrap();
            assert_plan_valid(&plan, &[whale], &funding, fee_per_tx());
            assert_eq!(plan.layer_count(), split_depth(p), "p={p} layers");
        }
    }

    proptest! {
        /// A lone note funding an arbitrary set of notes fans out into a balanced tree of exactly
        /// `split_depth` layers, and the plan is valid for any values and count.
        #[test]
        fn whale_fan_out_is_balanced_and_valid(
            funding in prop::collection::vec(1u64..10_000_000, 1..300),
        ) {
            let whale = subtree_cost(&funding, fee_per_tx()).1 + 12_345;
            let plan = plan_prep(&[whale], &funding, fee_per_tx()).unwrap();
            assert_plan_valid(&plan, &[whale], &funding, fee_per_tx());
            prop_assert_eq!(plan.layer_count(), split_depth(funding.len()));
        }
    }

    /// `split_depth` capacity thresholds and `subtree_cost` accounting.
    #[test]
    fn split_helpers() {
        assert_eq!(split_depth(0), 0);
        assert_eq!(split_depth(1), 1);
        assert_eq!(split_depth(FUNDING_OUTPUTS_PER_TX), 1);
        assert_eq!(split_depth(FUNDING_OUTPUTS_PER_TX + 1), 2);
        assert_eq!(
            split_depth(FUNDING_OUTPUTS_PER_TX * FUNDING_OUTPUTS_PER_TX),
            2
        );
        assert_eq!(
            split_depth(FUNDING_OUTPUTS_PER_TX * FUNDING_OUTPUTS_PER_TX + 1),
            3
        );
        // A single leaf: one transaction, value = sum of the funding notes plus one fee.
        assert_eq!(subtree_cost(&[100, 200], 7), (1, 307));
    }

    /// A whale worth exactly the balanced-tree cost leaves no residual: every transaction's value goes
    /// to funding notes and fees, with nothing left over.
    #[test]
    fn exact_split_no_residual() {
        let funding = vec![100u64; 15];
        let whale = subtree_cost(&funding, fee_per_tx()).1; // exact cost, no leftover
        let plan = plan_prep(&[whale], &funding, fee_per_tx()).unwrap();
        assert_plan_valid(&plan, &[whale], &funding, fee_per_tx());
        assert_eq!(plan.layer_count(), split_depth(15));
        assert_eq!(plan.residual_count(), 0, "exact split leaves no residual");
    }

    /// A hundred sub-quantum notes both consolidate and then split into thirty funding notes in a
    /// bounded number of layers, minting every note with at most one residual.
    #[test]
    fn many_sub_quantum_fund_many_notes() {
        let available = vec![50_000u64; 100];
        let funding = vec![100_000u64; 30];
        let plan = plan_prep(&available, &funding, fee_per_tx()).unwrap();
        assert_plan_valid(&plan, &available, &funding, fee_per_tx());
        assert_eq!(
            plan.layer_count(),
            3,
            "100 sub-quantum consolidate then fund 30 notes"
        );
        assert!(plan.residual_count() <= 1);
    }

    /// No available notes cannot fund anything.
    #[test]
    fn empty_available_insufficient() {
        assert_eq!(
            plan_prep(&[], &[100_000], fee_per_tx()),
            Err(PrepError::InsufficientFunds)
        );
    }

    /// Zero-value funding requests are ignored, yielding an empty plan.
    #[test]
    fn zero_value_funding_is_empty() {
        assert_eq!(
            plan_prep(&[1_000_000], &[0], fee_per_tx())
                .unwrap()
                .layer_count(),
            0
        );
        assert_eq!(
            plan_prep(&[1_000_000], &[0, 0], fee_per_tx())
                .unwrap()
                .layer_count(),
            0
        );
    }

    /// Repeated funding values (a multiset) are each minted as their own note.
    #[test]
    fn duplicate_funding_values() {
        let funding = [100u64, 100, 100, 100];
        let whale = 400 + 3 * fee_per_tx();
        let plan = plan_prep(&[whale], &funding, fee_per_tx()).unwrap();
        assert_plan_valid(&plan, &[whale], &funding, fee_per_tx());
        assert_eq!(sorted_funding(&plan), vec![100, 100, 100, 100]);
    }

    /// The planner is deterministic: identical inputs always produce an identical plan.
    #[test]
    fn deterministic() {
        let available = vec![500_000u64, 300_000, 120_000, 60_000, 9_000];
        let funding = vec![100_000u64, 50_000, 50_000, 20_000, 5_000];
        let a = plan_prep(&available, &funding, fee_per_tx()).unwrap();
        let b = plan_prep(&available, &funding, fee_per_tx()).unwrap();
        assert_eq!(a, b);
    }

    /// A wallet note worth exactly a funding value IS that funding note: it is used directly, with no
    /// preparation transaction (re-minting it is impossible anyway, since the fee would leave the
    /// budget below the funding value).
    #[test]
    fn note_equal_to_funding_value_is_used_directly() {
        let f = 100_000u64;
        let plan = plan_prep(&[f], &[f], fee_per_tx()).unwrap();
        assert_plan_valid(&plan, &[f], &[f], fee_per_tx());
        assert_eq!(plan.transaction_count(), 0, "no transaction needed");
        assert_eq!(plan.direct_funding_notes(), &[(0, zat(f))]);
        assert_eq!(plan.funding_notes(), vec![zat(f)]);
    }

    /// A wallet holding some notes already equal to funding values uses those directly and mints only
    /// the rest.
    #[test]
    fn exact_matches_are_used_directly_alongside_minting() {
        let f = 100_000u64;
        // Note 0 exactly matches a funding value; note 1 (large) mints the other two.
        let available = vec![f, 10_000_000];
        let funding = vec![f, 50_000, 20_000];
        let plan = plan_prep(&available, &funding, fee_per_tx()).unwrap();
        assert_plan_valid(&plan, &available, &funding, fee_per_tx());
        assert_eq!(
            plan.direct_funding_notes(),
            &[(0, zat(f))],
            "the exact note is used directly"
        );
        // Only the remaining two funding notes are minted, from the large note, in one transaction.
        assert_eq!(plan.transaction_count(), 1);
        assert_eq!(sorted_funding(&plan), vec![20_000, 50_000, 100_000]);
    }

    /// When wallet notes already equal every funding value, the plan has no transactions at all: each
    /// note is used directly.
    #[test]
    fn all_exact_matches_need_no_transactions() {
        let funding = vec![100_000u64, 50_000, 50_000];
        let available = funding.clone();
        let plan = plan_prep(&available, &funding, fee_per_tx()).unwrap();
        assert_plan_valid(&plan, &available, &funding, fee_per_tx());
        assert_eq!(plan.transaction_count(), 0);
        assert_eq!(plan.layer_count(), 0);
        assert_eq!(plan.direct_funding_notes().len(), 3);
        assert_eq!(sorted_funding(&plan), vec![50_000, 50_000, 100_000]);
    }

    /// One whale funds funding notes of varied sizes in a single transaction, largest first, with the
    /// remainder as the residual.
    #[test]
    fn varied_funding_from_one_whale() {
        let funding = [500_000u64, 200_000, 100_000, 20_000, 5_000, 2_000];
        let whale = funding.iter().sum::<u64>() + fee_per_tx() + 12_345;
        let plan = plan_prep(&[whale], &funding, fee_per_tx()).unwrap();
        assert_plan_valid(&plan, &[whale], &funding, fee_per_tx());
        assert_eq!(plan.layer_count(), 1);
        assert_eq!(plan.transaction_count(), 1);
    }

    /// Many wallet notes, each exactly funding one note, are spent in parallel in a single layer (one
    /// transaction per note) with no chaining, and the single-spend invariant holds across all of them.
    #[test]
    fn parallel_funding_across_notes() {
        let f = 100_000u64;
        let n = 20usize;
        let available = vec![f + fee_per_tx(); n]; // each note funds exactly one f note
        let funding = vec![f; n];
        let plan = plan_prep(&available, &funding, fee_per_tx()).unwrap();
        assert_plan_valid(&plan, &available, &funding, fee_per_tx());
        assert_eq!(plan.layer_count(), 1, "independent notes fund in one layer");
        assert_eq!(plan.transaction_count(), n, "one transaction per note");
        assert_eq!(
            plan.residual_count(),
            0,
            "each note funds exactly, no residual"
        );
    }
    /// Everything the shared corpus requires of ANY strategy holds for this one: whenever it plans,
    /// the plan passes its certificate; it plans every instance whose value is amply present in a
    /// single note; and it never plans one whose value is not there.
    #[test]
    fn conforms_to_the_shared_preparation_corpus() {
        crate::testing::assert_strategy_conformance(&LayeredGreedy);
    }

    /// Which of the corpus's `Fundability::Depends` instances THIS rule funds, and which it turns
    /// away. Those it turns away are the ones whose funding notes need a transaction that both
    /// spends several notes and produces several, the shape this rule cannot build; a strategy that
    /// can will fund them, and the diff to this list is what will show it.
    #[test]
    fn which_shape_dependent_instances_the_greedy_funds() {
        let fee = preparation_fee_per_tx();
        let mut funded = Vec::new();
        let mut turned_away = Vec::new();
        for vector in PREPARATION_VECTORS
            .iter()
            .filter(|v| v.fundability == Fundability::Depends)
        {
            let planned = LayeredGreedy
                .plan(&zats(vector.available), &zats(vector.funding), fee)
                .is_ok();
            if planned {
                funded.push(vector.label);
            } else {
                turned_away.push(vector.label);
            }
        }

        assert_eq!(funded, vec!["ten equal notes", "twelve sub-quantum notes"]);
        assert_eq!(
            turned_away,
            vec!["10 ZEC as 1 + 9", "10 ZEC as 2 + 8", "10 ZEC as 5 + 5"],
        );
    }

    proptest! {
        /// Every plan this rule produces passes its own certificate, so the portfolio never
        /// discards a real plan on a technicality.
        #[test]
        fn planned_plans_carry_a_valid_certificate((available, funding) in arb_input()) {
            let (available, funding, fee) = (zats(&available), zats(&funding), zat(fee_per_tx()));
            if let Ok(plan) = LayeredGreedy.plan(&available, &funding, fee) {
                prop_assert!(plan.is_valid(&available, &funding, fee));
            }
        }

        /// A one-strategy portfolio is exactly that strategy: the seam adds no behaviour.
        #[test]
        fn a_singleton_portfolio_is_the_strategy((available, funding) in arb_input()) {
            let (available, funding, fee) = (zats(&available), zats(&funding), zat(fee_per_tx()));
            prop_assert_eq!(
                (LayeredGreedy, ()).best_plan(&available, &funding, fee),
                LayeredGreedy
                    .plan(&available, &funding, fee)
                    .ok()
                    .map(|plan| ("layered-greedy", plan))
            );
        }
    }

    /// What a whole migration looks like under THIS rule alone: the answer to "what would
    /// `plan_migration` give with only LayeredGreedy?", for every scenario the crate shares.
    ///
    /// Columns are preparation transactions, crossings, Keystone signing rounds, and migrated
    /// value in units of 0.01 ZEC. [`MIGRATION_SCENARIOS`] carries what the whole portfolio
    /// achieves for the same wallets; the gap between the two rows is what this rule costs, or
    /// saves, on its own.
    ///
    /// These are recorded behaviour, not claims of optimality. They move when the rule changes,
    /// and that movement is the point: it is how an improvement is seen.
    const SCENARIOS_UNDER_THIS_RULE: &[(&str, usize, usize, usize, u64)] = &[
        ("small holder, 2 ZEC", 1, 7, 1, 199),
        ("retail, 15 ZEC", 1, 9, 1, 1499),
        ("denominations, 60 ZEC", 1, 10, 1, 5999),
        ("78 ZEC in a single note", 1, 10, 1, 7799),
        (
            "Gwen, 0.0152 ZEC (a single minimum-denomination note)",
            1,
            1,
            1,
            1,
        ),
        (
            "Priya, 7.1101 ZEC (the buffer prunes the trailing crossing)",
            1,
            3,
            1,
            710,
        ),
        ("exchange, ten 5 ZEC notes", 2, 3, 1, 4500),
        ("monotonic, ten 12 ZEC notes", 5, 11, 2, 11999),
        ("dust-heavy, 1 ZEC and twelve 0.02 ZEC notes", 4, 4, 1, 123),
        (
            "whale plus dust, 40 ZEC and a six-note dust tail",
            4,
            6,
            1,
            4033,
        ),
        ("10 ZEC in a single note", 1, 9, 1, 999),
        ("10 ZEC as 1 + 9", 1, 2, 1, 700),
        ("10 ZEC as 2 + 8", 1, 2, 1, 700),
        ("10 ZEC as 5 + 5", 2, 1, 1, 500),
    ];

    /// Replays [`SCENARIOS_UNDER_THIS_RULE`] through a migration planned against this rule alone.
    #[test]
    fn what_a_migration_looks_like_under_this_rule_alone() {
        crate::preparation::tests::assert_scenarios_under(
            &(LayeredGreedy, ()),
            SCENARIOS_UNDER_THIS_RULE,
        );
    }
}
