//! The backend-agnostic conformance suites: what it MEANS for an implementation to be correct.
//!
//! Two families live here. The store suite pins the [`PoolMigrationRead`] /
//! [`PoolMigrationWrite`] contract (an empty store reads back nothing, a replace/get round-trips,
//! a second replace overwrites, a transaction-state update persists), so any store inherits the
//! same coverage by pointing at it. The signing-round suite pins what a
//! [`SigningRoundStrategy`] must satisfy: valid packing, the optimal round count, and
//! no-worse-than comparisons against a reference implementation.
//!
//! This is the crate's specification written once and reused, rather than each implementation
//! asserting its own idea of correctness.

use core::fmt::Debug;
use core::num::NonZeroU32;

use crate::engine::{
    MigrationState, MigrationTransferId, MigrationTxState, PoolMigrationRead, PoolMigrationWrite,
};
use crate::preparation::PreparationStrategy;
use crate::signing_rounds::{
    PREPARATION_ACTIONS, PlannedTx, SigningRoundBudget, SigningRoundStrategy, TRANSFER_ACTIONS,
    min_signing_rounds,
};

use alloc::vec::Vec;

// The suites assert ABOUT the fixed data next door: the golden vectors they replay, and the
// workload builder they use to construct a run of a given shape.
use super::preparation_vectors::{Fundability, PREPARATION_VECTORS, preparation_fee_per_tx, zats};
use super::scenarios::{SIGNING_ROUND_GOLDEN_VECTORS, planned_txs};

/// Assert that an empty store reports no migration: [`get_migration`](PoolMigrationRead::get_migration)
/// is `None`.
pub fn assert_empty_is_none<S: PoolMigrationRead>(store: &S)
where
    S::Error: Debug,
{
    assert!(
        store
            .get_migration()
            .expect("reading an empty store succeeds")
            .is_none(),
        "an empty store must report no migration"
    );
}

/// Assert a replace/get round-trip: after [`replace_migration`](PoolMigrationWrite::replace_migration), the
/// store reads back exactly the migration that was written — unless the state is TERMINAL, in
/// which case [`get_migration`](PoolMigrationRead::get_migration) reports `None`. The trait's
/// contract is "the migration currently in progress, if any": a terminal migration is retained
/// history, addressed through a store's history accessors rather than through the drive-loop
/// read, and persisting one is precisely how a migration ENTERS that history.
pub fn assert_put_get_roundtrip<S: PoolMigrationWrite>(store: &mut S, state: &MigrationState)
where
    S::Error: Debug,
{
    store
        .replace_migration(state)
        .expect("replace_migration succeeds");
    let loaded = store.get_migration().expect("get_migration succeeds");
    if state.is_terminal() {
        assert_eq!(
            loaded, None,
            "a terminal migration is history, not the migration in progress"
        );
    } else {
        assert_eq!(
            loaded,
            Some(state.clone()),
            "the stored migration must read back unchanged"
        );
    }
}

/// Assert that a second replace supersedes the first as the account's migration IN PROGRESS:
/// after putting `first` then `second`, [`get_migration`](PoolMigrationRead::get_migration)
/// reports exactly `second` — or `None` when `second` is terminal, per the pending-only contract
/// [`assert_put_get_roundtrip`] describes. Whether `first` also remains readable as retained
/// history is a property of the store's history accessors, outside this trait-level suite.
pub fn assert_put_replaces<S: PoolMigrationWrite>(
    store: &mut S,
    first: &MigrationState,
    second: &MigrationState,
) where
    S::Error: Debug,
{
    store
        .replace_migration(first)
        .expect("first replace_migration succeeds");
    store
        .replace_migration(second)
        .expect("second replace_migration succeeds");
    let expected = (!second.is_terminal()).then(|| second.clone());
    assert_eq!(
        store.get_migration().expect("get_migration succeeds"),
        expected,
        "a second put must replace the first migration",
    );
}

/// Assert that a transaction state update persists: after storing `state` and calling
/// [`update_transaction`](PoolMigrationWrite::update_transaction) for `id`, the reloaded transaction
/// with that id carries `new`.
///
/// Call this only with an `id` that `state` actually contains (the store errors on an unknown
/// transaction); [`first_transaction_id`] picks a present one.
///
/// A `new` state that carries a txid is re-pointed at the ROW's own id before the update. A
/// transaction's id belongs to the transaction, not to its lifecycle: a store keeps one id per row
/// and a lifecycle update cannot change which transaction the row is about, so asking one to
/// round-trip a `Broadcast` or `Mined` state naming some other transaction would be asking it to
/// represent something no engine transition can produce.
pub fn assert_update_transaction<S: PoolMigrationWrite>(
    store: &mut S,
    state: &MigrationState,
    id: MigrationTransferId,
    new: MigrationTxState,
) where
    S::Error: Debug,
{
    let row_txid = state
        .transactions()
        .iter()
        .find(|t| t.id() == id)
        .expect("the transaction to update is present")
        .txid();
    let new = match new {
        MigrationTxState::Broadcast { .. } => MigrationTxState::Broadcast { txid: row_txid },
        MigrationTxState::Mined { height, .. } => MigrationTxState::Mined {
            txid: row_txid,
            height,
        },
        other => other,
    };
    store
        .replace_migration(state)
        .expect("replace_migration succeeds");
    if state.is_terminal() {
        // A terminal migration has no pending row to address: nothing will ever drive it, so
        // there is no lifecycle left to update, and `get_migration` reports `None` rather than
        // it. The update half of this assertion applies only to a migration in progress.
        assert_eq!(store.get_migration().expect("get_migration succeeds"), None);
        return;
    }
    store
        .update_transaction(id, new)
        .expect("update_transaction succeeds");
    let loaded = store
        .get_migration()
        .expect("get_migration succeeds")
        .expect("a migration is stored");
    let tx = loaded
        .transactions()
        .iter()
        .find(|t| t.id() == id)
        .expect("the updated transaction is present");
    assert_eq!(tx.state(), new, "the transaction's state must be updated");
}

/// The id of the first transaction of `state`, or `None` if it has no transactions. A convenience
/// for driving [`assert_update_transaction`] from a generated [`MigrationState`].
pub fn first_transaction_id(state: &MigrationState) -> Option<MigrationTransferId> {
    state.transactions().first().map(|t| t.id())
}

// --- preparation strategies: the corpus every implementation is measured on ---

/// Assert what every [`PreparationStrategy`] must satisfy on the shared [`PREPARATION_VECTORS`]
/// corpus, whatever rule it implements:
///
/// - a plan it returns passes its own certificate ([`PreparationPlan::is_valid`](crate::preparation::PreparationPlan::is_valid)), which covers the
///   funding multiset, the action budget, value conservation, and single-spending;
/// - it plans every [`Fundability::Always`] instance and no [`Fundability::Never`] one;
/// - a [`Fundability::Depends`] instance may go either way, since that is what distinguishes one
///   rule from another.
///
/// A new strategy inherits the whole corpus by calling this, rather than restating the properties.
/// The plan SHAPE a rule produces is deliberately not asserted here; that belongs with the rule.
pub fn assert_strategy_conformance<S: PreparationStrategy>(strategy: &S) {
    let name = strategy.name();
    let fee = preparation_fee_per_tx();
    for vector in PREPARATION_VECTORS {
        let (available, funding) = (zats(vector.available), zats(vector.funding));
        let planned = strategy.plan(&available, &funding, fee);
        let label = vector.label;

        if let Ok(plan) = &planned {
            assert!(
                plan.is_valid(&available, &funding, fee),
                "[{name}] `{label}`: planned an invalid plan",
            );
        }
        match vector.fundability {
            Fundability::Always => assert!(
                planned.is_ok(),
                "[{name}] `{label}`: must plan, got {:?}",
                planned.err(),
            ),
            Fundability::Never => assert!(
                planned.is_err(),
                "[{name}] `{label}`: must not plan, the value is not there",
            ),
            Fundability::Depends => {}
        }
    }
}

/// Assert `strategy` plans every [`Fundability::Depends`] instance in the corpus: the instances
/// whose value is present but whose funding is out of some rules' reach, so planning them all is a
/// claim about the strategy, not about the corpus. [`assert_strategy_conformance`] deliberately
/// leaves these unpinned; a strategy that covers the whole shape-dependent family asserts it here.
pub fn assert_funds_every_shape_dependent_instance<S: PreparationStrategy>(strategy: &S) {
    let fee = preparation_fee_per_tx();
    for vector in PREPARATION_VECTORS
        .iter()
        .filter(|v| v.fundability == Fundability::Depends)
    {
        assert!(
            strategy
                .plan(&zats(vector.available), &zats(vector.funding), fee)
                .is_ok(),
            "[{}] `{}` must plan",
            strategy.name(),
            vector.label,
        );
    }
}

/// Assert that `candidate` funds every instance `baseline` funds, and report any it funds that the
/// baseline does not. Use it to show a new strategy DOMINATES an existing one: the portfolio's
/// result can then only improve, since [`Portfolio::best_plan`](crate::preparation::Portfolio::best_plan) is monotone in the
/// strategy set.
///
/// Returns the labels the candidate funds and the baseline does not, so a caller can assert the
/// improvement is the one it expected rather than merely non-empty.
pub fn assert_dominates<A, B>(candidate: &A, baseline: &B) -> Vec<&'static str>
where
    A: PreparationStrategy,
    B: PreparationStrategy,
{
    let fee = preparation_fee_per_tx();
    let mut gained = Vec::new();
    for vector in PREPARATION_VECTORS {
        let (available, funding) = (zats(vector.available), zats(vector.funding));
        let candidate_planned = candidate.plan(&available, &funding, fee).is_ok();
        let baseline_planned = baseline.plan(&available, &funding, fee).is_ok();
        assert!(
            candidate_planned || !baseline_planned,
            "[{}] must fund everything [{}] funds, but did not fund `{}`",
            candidate.name(),
            baseline.name(),
            vector.label,
        );
        if candidate_planned && !baseline_planned {
            gained.push(vector.label);
        }
    }
    gained
}

// --- signing-round packing: reusable strategies + conformance suite ---
//
// A reusable suite so every `SigningRoundStrategy` (the crate's `MinRounds` / `NextFit`, and any a
// downstream crate adds) is exercised the same way: generate transaction sets and budgets, then
// assert the packing invariants hold for the strategy under test.

/// Assert the packing INVARIANTS every [`SigningRoundStrategy`] must satisfy on `txs` under
/// `budget`: every input transaction appears in exactly one round, no round is empty, no multi-tx
/// round exceeds the budget, each round's `total_actions` is accurate, and `pack().len()` equals the
/// strategy's own `round_count` for the same counts. Reusable across strategies and downstream
/// implementations.
pub fn assert_valid_packing<S: SigningRoundStrategy>(
    strategy: &S,
    txs: &[PlannedTx],
    budget: SigningRoundBudget,
) {
    let name = strategy.name();
    let rounds = strategy.pack(txs, budget);

    let mut got: Vec<u32> = rounds
        .iter()
        .flat_map(|r| r.transactions().iter().map(|t| u32::from(t.id())))
        .collect();
    got.sort_unstable();
    let mut want: Vec<u32> = txs.iter().map(|t| u32::from(t.id())).collect();
    want.sort_unstable();
    assert_eq!(
        got, want,
        "[{name}] packing must cover every tx exactly once"
    );

    for r in &rounds {
        assert!(!r.is_empty(), "[{name}] must not produce empty rounds");
        if r.len() > 1 {
            assert!(
                r.total_actions() <= budget.max_actions(),
                "[{name}] a multi-tx round must stay within the budget"
            );
        }
        let summed: u32 = r.transactions().iter().map(|t| t.actions()).sum();
        assert_eq!(
            summed,
            r.total_actions(),
            "[{name}] round total_actions must be accurate"
        );
    }

    let n_prep = txs.iter().filter(|t| t.is_preparation()).count();
    let n_transfer = txs.iter().filter(|t| t.is_transfer()).count();
    assert_eq!(
        rounds.len(),
        strategy.round_count(n_prep, n_transfer, budget),
        "[{name}] pack length must match round_count"
    );
}

/// Assert `strategy` achieves the OPTIMAL (minimum) number of rounds for the given counts, i.e. it
/// matches [`min_signing_rounds`]. Use for strategies that claim optimality (for example
/// `MinRounds`); an approximate strategy such as `NextFit` is not expected to pass this.
pub fn assert_optimal_round_count<S: SigningRoundStrategy>(
    strategy: &S,
    n_prep: usize,
    n_transfer: usize,
    budget: SigningRoundBudget,
) {
    assert_eq!(
        strategy.round_count(n_prep, n_transfer, budget),
        min_signing_rounds(n_prep, n_transfer, budget),
        "[{}] must achieve the optimal round count",
        strategy.name()
    );
}

/// Assert `candidate` never needs more rounds than `baseline` for the given counts (for example
/// `MinRounds` is never worse than `NextFit`).
pub fn assert_no_worse_than<A: SigningRoundStrategy, B: SigningRoundStrategy>(
    candidate: &A,
    baseline: &B,
    n_prep: usize,
    n_transfer: usize,
    budget: SigningRoundBudget,
) {
    assert!(
        candidate.round_count(n_prep, n_transfer, budget)
            <= baseline.round_count(n_prep, n_transfer, budget),
        "[{}] must never need more rounds than [{}]",
        candidate.name(),
        baseline.name()
    );
}

/// A REFERENCE minimum-rounds computation for the two-item-size signing-round packing problem,
/// written independently of the production packer, so a `SigningRoundStrategy` claiming optimality
/// can be cross-checked against it (and a downstream implementer can validate a new strategy).
///
/// It searches upward for the smallest round count that can hold every preparation transaction
/// (16 actions, at most `floor(budget/16)` per round) while leaving room for every transfer
/// (3 actions), maximizing the per-round transfer capacity with a small dynamic program.
pub fn min_rounds_reference(n_prep: usize, n_transfer: usize, budget: SigningRoundBudget) -> usize {
    if n_prep == 0 && n_transfer == 0 {
        return 0;
    }
    let cap = budget.max_actions();
    let (w_hi, w_lo) = (PREPARATION_ACTIONS, TRANSFER_ACTIONS);
    // A single preparation exceeds the budget: each gets its own round; transfers pack under it.
    if cap < w_hi {
        let per = (cap / w_lo).max(1) as usize;
        return n_prep + n_transfer.div_ceil(per);
    }
    let mp = (cap / w_hi) as usize;
    let lo_cap = |k: usize| -> i64 { i64::from((cap - (k as u32) * w_hi) / w_lo) };
    const NEG: i64 = i64::MIN / 2;
    let mut rounds = n_prep.div_ceil(mp).max(1);
    loop {
        // dp[u] = max total transfer capacity having placed `u` preparations across the rounds so far.
        let mut dp = alloc::vec![NEG; n_prep + 1];
        dp[0] = 0;
        for _ in 0..rounds {
            let mut next = alloc::vec![NEG; n_prep + 1];
            for u in 0..=n_prep {
                if dp[u] == NEG {
                    continue;
                }
                for k in 0..=mp.min(n_prep - u) {
                    let cand = dp[u] + lo_cap(k);
                    if cand > next[u + k] {
                        next[u + k] = cand;
                    }
                }
            }
            dp = next;
        }
        if dp[n_prep] >= n_transfer as i64 {
            return rounds;
        }
        rounds += 1;
    }
}

// --- golden vectors for the signing-round packing problem ---
//
// The reusable INPUTS of the NP problem (preparation-tx count, transfer-tx count, per-round action
// budget) paired with the hand-verified expected OPTIMAL round count. Downstream crates and the
// crate's own tests feed each input to a strategy and compare its output to `expected_min_rounds`,
// so a regression in the packer is caught against a fixed, human-checked table rather than only
// against a re-derived oracle. Cases span every regime: empty, singles, exact fills, one-over
// boundaries, gap-filling mixes, whole-run and note-cap sizes, the default and minimum-feasible
// budgets, and the oversized (sub-16, a single transaction exceeds the budget) regime.
//
// These exercise the PACKER in isolation over arbitrary counts, including degenerate transfer-free
// inputs (a preparation-only case) that a real migration never produces: a migration always has at
// least one transfer (see the balance-keyed `MIGRATION_SCENARIOS`).

/// Assert every golden vector's expected optimal round count matches [`min_signing_rounds`] (the
/// `MinRounds` optimum). A regression net over a fixed, human-checked table.
pub fn assert_golden_min_rounds() {
    for gv in SIGNING_ROUND_GOLDEN_VECTORS {
        let budget = SigningRoundBudget::new(
            NonZeroU32::new(gv.budget_actions).expect("golden budget is nonzero"),
        );
        assert_eq!(
            min_signing_rounds(gv.n_prep, gv.n_transfer, budget),
            gv.expected_min_rounds,
            "golden vector `{}`",
            gv.name
        );
    }
}

/// Assert `strategy` produces a valid packing on every golden input AND matches the expected optimal
/// round count. Use for strategies that claim optimality (for example `MinRounds`); an approximate
/// strategy such as `NextFit` should instead be checked with [`assert_valid_packing`] alone.
pub fn assert_golden_vectors_optimal<S: SigningRoundStrategy>(strategy: &S) {
    for gv in SIGNING_ROUND_GOLDEN_VECTORS {
        let budget = SigningRoundBudget::new(
            NonZeroU32::new(gv.budget_actions).expect("golden budget is nonzero"),
        );
        let txs = planned_txs(gv.n_prep, gv.n_transfer);
        assert_valid_packing(strategy, &txs, budget);
        assert_eq!(
            strategy.round_count(gv.n_prep, gv.n_transfer, budget),
            gv.expected_min_rounds,
            "[{}] golden vector `{}`",
            strategy.name(),
            gv.name
        );
    }
}

// --- reusable migration scenarios (keyed on the user's wallet balance) ---
//
// The canonical migration scenarios, defined ONCE here and reused by every whole-migration
// end-to-end test: the real-proving chain simulation (`prove_chain_sim`) and the signing-round
// end-to-end test both consume this same list, so a source balance and its expected outputs live in
// one place.
//
// The model, from the user's point of view: the starting point is the wallet BALANCE. The canonical
// planner quantizes it into `expected_transfers` crossings (the "quanta"), each a canonical
// denomination, AFTER reserving the per-crossing transfer fee buffer and the preparation fees. So a
// 2 ZEC balance is NOT one crossing: it becomes 7 quanta and migrates 1.99 ZEC (the balance less the
// reserved fees). A migration always has at least one crossing (`expected_transfers >= 1`), and every
// funding note the preparation creates is migrated. The number of RUNS then follows from the quanta
// count and the per-run note cap ([`MIGRATION_MAX_PREPARED_NOTES_PER_RUN`]): every scenario here fits
// one run (its quanta are within the cap).
