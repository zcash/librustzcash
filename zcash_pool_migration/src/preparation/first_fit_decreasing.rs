//! A first-fit-decreasing [`PreparationStrategy`] that packs several source notes into one
//! transaction.
//!
//! It walks the funding notes from largest to smallest, keeping one transaction open. When the open
//! transaction's inputs cannot cover the next funding note, it spends another source note, largest
//! first, rather than moving on to a smaller funding note. A transaction closes only when its slots
//! are exhausted, and the next one starts on the source notes that remain.
//!
//! Transactions therefore take the shapes in the interior of the
//! `spends + outputs <= PREP_TX_ACTIONS` budget, not only its two extremes, and a funding note whose
//! value spans several source notes is minted directly instead of through a merge and a split.
//!
//! Every transaction it builds spends source notes only, so they are independent and form a single
//! layer. When the funding notes cannot be covered that way — most often a lone note that must fan
//! out into more outputs than one transaction holds — it reports [`PrepError::InsufficientFunds`]
//! rather than chaining transactions across layers.

use alloc::vec::Vec;

use zcash_protocol::value::Zatoshis;

use super::{
    PREP_TX_ACTIONS, PrepError, PrepInput, PrepOutput, PrepTransaction, PreparationPlan,
    PreparationStrategy, validate_instance, zat,
};

/// The slot every transaction holds back for the change note its packing may leave, so a
/// transaction is sized as though it will need one.
const CHANGE_SLOT: usize = 1;

/// The first-fit-decreasing packing described in the [module docs](self).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FirstFitDecreasing;

impl PreparationStrategy for FirstFitDecreasing {
    fn name(&self) -> &'static str {
        "first-fit-decreasing"
    }

    fn plan(
        &self,
        available: &[Zatoshis],
        funding: &[Zatoshis],
        fee_per_tx: Zatoshis,
    ) -> Result<PreparationPlan, PrepError> {
        plan_first_fit(available, funding, fee_per_tx)
    }
}

/// One transaction under construction: the source notes it spends, their total, the funding notes
/// it mints, and their total.
struct OpenTransaction {
    inputs: Vec<usize>,
    input_total: u64,
    outputs: Vec<u64>,
    output_total: u64,
}

impl OpenTransaction {
    fn new() -> Self {
        OpenTransaction {
            inputs: Vec::new(),
            input_total: 0,
            outputs: Vec::new(),
            output_total: 0,
        }
    }

    /// The slots this transaction has committed so far.
    fn slots(&self) -> usize {
        self.inputs.len() + self.outputs.len()
    }

    /// Whether one more note, spent or minted, still leaves room for a change note.
    fn has_room(&self) -> bool {
        self.slots() + 1 + CHANGE_SLOT <= PREP_TX_ACTIONS
    }

    /// What its inputs can still mint, after the fee and what it has already committed to mint.
    fn unassigned(&self, fee: u64) -> u64 {
        self.input_total
            .saturating_sub(fee)
            .saturating_sub(self.output_total)
    }

    /// Turn this into a transaction, with any value its funding notes did not claim as change.
    fn close(self, available: &[u64], fee: u64) -> PrepTransaction {
        let mut outputs: Vec<PrepOutput> = self
            .outputs
            .into_iter()
            .map(|value| PrepOutput::Funding(zat(value)))
            .collect();
        let change = self.input_total - fee - self.output_total;
        if change > 0 {
            outputs.push(PrepOutput::Change(zat(change)));
        }
        let inputs = self
            .inputs
            .into_iter()
            .map(|index| PrepInput::Wallet {
                index,
                value: zat(available[index]),
            })
            .collect();
        PrepTransaction::from_parts(inputs, outputs)
    }
}

/// This strategy's planning routine; see [`FirstFitDecreasing`] and the [module docs](self).
fn plan_first_fit(
    available: &[Zatoshis],
    funding: &[Zatoshis],
    fee_per_tx: Zatoshis,
) -> Result<PreparationPlan, PrepError> {
    validate_instance(available, funding)?;
    let fee = u64::from(fee_per_tx);
    let available: Vec<u64> = available.iter().map(|&v| u64::from(v)).collect();

    // Largest first, so the transaction open at any moment is working on the funding note that
    // constrains it most.
    let mut targets: Vec<u64> = funding
        .iter()
        .map(|&v| u64::from(v))
        .filter(|&v| v > 0)
        .collect();
    targets.sort_unstable_by(|a, b| b.cmp(a));

    // A wallet note already worth a funding value IS that funding note: used directly, with no
    // transaction and no fee.
    let mut used = vec![false; available.len()];
    let mut direct_funding: Vec<(usize, Zatoshis)> = Vec::new();
    targets.retain(|&target| {
        match available
            .iter()
            .enumerate()
            .position(|(i, &value)| !used[i] && value == target)
        {
            Some(i) => {
                used[i] = true;
                direct_funding.push((i, zat(target)));
                false
            }
            None => true,
        }
    });

    if targets.is_empty() {
        return Ok(PreparationPlan::from_parts(Vec::new(), direct_funding));
    }

    // The notes left to spend, largest first, so one spend serves as many funding notes as it can.
    let mut spendable: Vec<usize> = (0..available.len()).filter(|&i| !used[i]).collect();
    spendable.sort_unstable_by_key(|&i| core::cmp::Reverse(available[i]));
    let mut next_spend = 0;

    let mut transactions: Vec<PrepTransaction> = Vec::new();
    let mut open = OpenTransaction::new();

    for target in targets {
        loop {
            if !open.inputs.is_empty() && open.has_room() && open.unassigned(fee) >= target {
                open.output_total += target;
                open.outputs.push(target);
                break;
            }
            // Not enough value, or no room: spend another note if both allow it.
            if open.has_room() && next_spend < spendable.len() {
                let index = spendable[next_spend];
                next_spend += 1;
                open.input_total += available[index];
                open.inputs.push(index);
                continue;
            }
            // Neither: close what is open and try this funding note in a fresh transaction. With
            // nothing open to close, no transaction this strategy can build mints it.
            if open.outputs.is_empty() {
                return Err(PrepError::InsufficientFunds);
            }
            transactions
                .push(core::mem::replace(&mut open, OpenTransaction::new()).close(&available, fee));
        }
    }
    transactions.push(open.close(&available, fee));

    Ok(PreparationPlan::from_parts(
        alloc::vec![transactions],
        direct_funding,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::testing::{PREPARATION_VECTORS, preparation_fee_per_tx, zats};

    /// Everything the shared corpus requires of any strategy holds for this one.
    #[test]
    fn conforms_to_the_shared_preparation_corpus() {
        crate::testing::assert_strategy_conformance(&FirstFitDecreasing);
    }

    /// The shapes the layered greedy cannot reach, which this strategy exists to cover: each of the
    /// note-shape instances is minted by ONE transaction in ONE layer, spending both source notes.
    #[test]
    fn a_single_transaction_mints_the_canonical_set_from_either_note_shape() {
        let fee = preparation_fee_per_tx();
        for label in [
            "one note funds the 10 ZEC canonical set",
            "10 ZEC as 1 + 9",
            "10 ZEC as 2 + 8",
            "10 ZEC as 5 + 5",
        ] {
            let vector = PREPARATION_VECTORS
                .iter()
                .find(|v| v.label == label)
                .expect("the note-shape vectors exist");
            let (available, funding) = (zats(vector.available), zats(vector.funding));
            let plan = FirstFitDecreasing
                .plan(&available, &funding, fee)
                .unwrap_or_else(|e| panic!("`{label}` must plan, got {e:?}"));

            assert_eq!(plan.layer_count(), 1, "`{label}`: layers");
            assert_eq!(plan.transaction_count(), 1, "`{label}`: transactions");
            assert_eq!(
                plan.funding_notes().len(),
                vector.funding.len(),
                "`{label}`: mints every funding note",
            );
            assert!(plan.is_valid(&available, &funding, fee), "`{label}`: valid");
        }
    }

    /// It funds every shape-dependent instance in the corpus, which is what distinguishes it from
    /// the layered greedy: the value is present in all of them, only the transaction shapes needed
    /// to reach it differ.
    #[test]
    fn it_funds_every_shape_dependent_instance() {
        crate::testing::assert_funds_every_shape_dependent_instance(&FirstFitDecreasing);
    }

    /// A lone note that must fan out into more funding notes than one transaction holds is the
    /// shape this strategy does not cover; it declines rather than chaining across layers, and the
    /// portfolio falls back to a rule that does.
    #[test]
    fn it_declines_a_fan_out_that_needs_layers() {
        let fee = preparation_fee_per_tx();
        let funding = zats(&[1_000_000; PREP_TX_ACTIONS]);
        let available = zats(&[1_000_000 * PREP_TX_ACTIONS as u64 + 10 * u64::from(fee)]);
        assert_eq!(
            FirstFitDecreasing.plan(&available, &funding, fee),
            Err(PrepError::InsufficientFunds),
        );
    }

    /// What a whole migration looks like under THIS rule alone: the answer to "what would
    /// `plan_migration` give with only FirstFitDecreasing?", for every scenario the crate shares.
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
        ("exchange, ten 5 ZEC notes", 1, 5, 1, 4900),
        ("monotonic, ten 12 ZEC notes", 1, 5, 1, 11900),
        ("dust-heavy, 1 ZEC and twelve 0.02 ZEC notes", 1, 2, 1, 120),
        (
            "whale plus dust, 40 ZEC and a six-note dust tail",
            1,
            6,
            1,
            4033,
        ),
        ("10 ZEC in a single note", 1, 9, 1, 999),
        ("10 ZEC as 1 + 9", 1, 9, 1, 999),
        ("10 ZEC as 2 + 8", 1, 9, 1, 999),
        ("10 ZEC as 5 + 5", 1, 9, 1, 999),
    ];

    /// Replays [`SCENARIOS_UNDER_THIS_RULE`] through a migration planned against this rule alone.
    #[test]
    fn what_a_migration_looks_like_under_this_rule_alone() {
        crate::preparation::tests::assert_scenarios_under(
            &(FirstFitDecreasing, ()),
            SCENARIOS_UNDER_THIS_RULE,
        );
    }
}
