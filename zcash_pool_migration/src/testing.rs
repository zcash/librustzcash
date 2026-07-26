//! Reusable test utilities for the pool-migration engine.
//!
//! Two things live here, so every store implementation is exercised the same way instead of
//! hand-rolling its own fixtures:
//!
//! - `proptest` strategies (`arb_*`) that generate the engine's persisted types, from a single
//!   [`Zatoshis`] up to a whole [`MigrationState`]. The crate's own codec proptests consume these,
//!   and so does any downstream store crate.
//! - a backend-agnostic conformance suite (`assert_*`) over the [`PoolMigrationRead`] /
//!   [`PoolMigrationWrite`] store traits: an empty store reads back nothing, a replace/get round-trips,
//!   a second replace overwrites the first, and a transaction state update persists. Point any store
//!   (the SQLite store, a future in-memory backend) at these and it inherits the same coverage.
//!
//! Enabled by the `test-dependencies` feature (and by the crate's own `test` build), so a
//! downstream crate reuses these directly rather than duplicating them.

use core::fmt::Debug;
use core::num::NonZeroU32;

use proptest::prelude::*;

use zcash_primitives::transaction::testing::arb_txid;
use zcash_protocol::consensus::testing::arb_block_height;
use zcash_protocol::value::testing::arb_zatoshis;
use zcash_protocol::value::{COIN, Zatoshis};

use crate::denomination::DenominationPlan;
use crate::engine::{
    MigrationState, MigrationStatus, MigrationTransaction, MigrationTransferId, MigrationTxKind,
    MigrationTxState, PoolMigrationRead, PoolMigrationWrite,
};
use crate::preparation::{PrepInput, PrepOutput, PrepTransaction, PreparationPlan};
use crate::scheduling::AnchorBucketInterval;
use crate::signing_rounds::{
    PREPARATION_ACTIONS, PlannedTx, SigningRoundBudget, SigningRoundStrategy, TRANSFER_ACTIONS,
    min_signing_rounds,
};

use alloc::vec::Vec;

/// Convert a bounded `u64` to [`Zatoshis`]; infallible for the ranges the strategies draw from.
fn zat(value: u64) -> Zatoshis {
    Zatoshis::from_u64(value).expect("test amount within the money supply")
}

// --- leaf strategies ---

/// An arbitrary [`MigrationTransferId`] row key.
pub fn arb_migration_transfer_id() -> impl Strategy<Value = MigrationTransferId> {
    (0u32..1000).prop_map(MigrationTransferId::new)
}

// --- preparation-plan strategies (moved from `preparation`'s codec tests) ---

/// An arbitrary [`PrepInput`], exercising both tags.
pub fn arb_prep_input() -> impl Strategy<Value = PrepInput> {
    prop_oneof![
        (0usize..1000, arb_zatoshis())
            .prop_map(|(index, value)| PrepInput::Wallet { index, value }),
        (0usize..1000, 0usize..1000, 0usize..1000, arb_zatoshis()).prop_map(
            |(layer, transaction, output, value)| PrepInput::Prior {
                layer,
                transaction,
                output,
                value,
            }
        ),
    ]
}

/// An arbitrary [`PrepOutput`], exercising all three tags.
pub fn arb_prep_output() -> impl Strategy<Value = PrepOutput> {
    prop_oneof![
        arb_zatoshis().prop_map(PrepOutput::Funding),
        arb_zatoshis().prop_map(PrepOutput::Intermediate),
        arb_zatoshis().prop_map(PrepOutput::Change),
    ]
}

/// An arbitrary [`PrepTransaction`]. Like every transaction a real plan produces, it has at least
/// one input and one output (it spends notes and mints funding or change); a store may rely on this
/// to reconstruct the plan's layers/transactions grid from the input and output rows alone.
pub fn arb_prep_transaction() -> impl Strategy<Value = PrepTransaction> {
    (
        prop::collection::vec(arb_prep_input(), 1..6),
        prop::collection::vec(arb_prep_output(), 1..6),
    )
        .prop_map(|(inputs, outputs)| PrepTransaction::from_parts(inputs, outputs))
}

/// An arbitrary [`PreparationPlan`]: layers of transactions plus direct-funding notes. Like every
/// real plan, each layer is non-empty (a layer exists because transactions were placed in it),
/// though the plan may have no layers at all (all funding notes used directly).
pub fn arb_preparation_plan() -> impl Strategy<Value = PreparationPlan> {
    (
        prop::collection::vec(prop::collection::vec(arb_prep_transaction(), 1..4), 0..4),
        prop::collection::vec((0usize..1000, arb_zatoshis()), 0..5),
    )
        .prop_map(|(layers, direct)| PreparationPlan::from_parts(layers, direct))
}

// --- denomination strategy (moved from `denomination`'s codec tests) ---

/// An arbitrary [`DenominationPlan`], covering all stored fields (an empty or populated crossing set,
/// present or absent change). Bounded so every `crossing + note_fee_buffer` is representable, which
/// is what [`DenominationPlan::from_stored_parts`] requires.
pub fn arb_denomination_plan() -> impl Strategy<Value = DenominationPlan> {
    (
        prop::collection::vec(arb_zatoshis(), 0..8),
        (0u64..1_000_000).prop_map(zat),
        prop::option::of(arb_zatoshis()),
        (0u64..1_000_000).prop_map(zat),
        (0u64..1_000_000_000).prop_map(zat),
        (0u64..1_000_000_000).prop_map(zat),
    )
        .prop_map(
            |(
                crossing_values,
                note_fee_buffer,
                change,
                prep_fees,
                total_input,
                total_migratable,
            )| {
                DenominationPlan::from_stored_parts(
                    crossing_values,
                    note_fee_buffer,
                    change,
                    prep_fees,
                    total_input,
                    total_migratable,
                )
                .expect("crossing + buffer within the money supply")
            },
        )
}

// --- migration-state strategies (moved and extended from `engine`'s codec tests) ---

/// An arbitrary [`MigrationTxKind`], exercising both variants.
pub fn arb_migration_tx_kind() -> impl Strategy<Value = MigrationTxKind> {
    prop_oneof![
        (0usize..1000, 0usize..1000)
            .prop_map(|(layer, index)| MigrationTxKind::Preparation { layer, index }),
        (0usize..1000).prop_map(|crossing| MigrationTxKind::Transfer { crossing }),
    ]
}

/// An arbitrary [`MigrationTxState`], covering every variant (including the
/// [`Broadcast`](MigrationTxState::Broadcast) txid and [`Mined`](MigrationTxState::Mined) height
/// payloads).
pub fn arb_migration_tx_state() -> impl Strategy<Value = MigrationTxState> {
    prop_oneof![
        Just(MigrationTxState::AwaitingSignature),
        Just(MigrationTxState::Signed),
        Just(MigrationTxState::Proved),
        arb_txid().prop_map(|txid| MigrationTxState::Broadcast { txid }),
        arb_block_height().prop_map(|height| MigrationTxState::Mined { height }),
    ]
}

/// An arbitrary [`MigrationStatus`], covering every variant.
pub fn arb_migration_status() -> impl Strategy<Value = MigrationStatus> {
    prop_oneof![
        Just(MigrationStatus::Planning),
        Just(MigrationStatus::Committed),
        Just(MigrationStatus::InProgress),
        Just(MigrationStatus::Complete),
        Just(MigrationStatus::Failed),
    ]
}

/// An arbitrary lock-owner token: `None` (no lock held) or the raw bytes of a
/// `zcash_client_backend::wallet::LockOwner` (opaque here — this crate does not depend on
/// `zcash_client_backend`).
pub fn arb_lock_owner() -> impl Strategy<Value = Option<[u8; 32]>> {
    prop::option::of(any::<[u8; 32]>())
}

/// An arbitrary [`MigrationTransaction`], built through [`MigrationTransaction::from_parts`]. Its id
/// is arbitrary here; [`arb_migration_state`] re-keys the transactions it holds so their ids stay
/// unique within a migration.
pub fn arb_migration_transaction() -> impl Strategy<Value = MigrationTransaction> {
    (
        arb_migration_transfer_id(),
        arb_migration_tx_kind(),
        prop::collection::vec(any::<u8>(), 0..64),
        prop::collection::vec(arb_migration_transfer_id(), 0..4),
        arb_block_height(),
        arb_block_height(),
        prop::option::of(arb_block_height()),
        arb_migration_tx_state(),
        arb_lock_owner(),
    )
        .prop_map(
            |(
                id,
                kind,
                pczt,
                depends_on,
                scheduled_height,
                expiry_height,
                anchor_boundary,
                state,
                lock_owner,
            )| {
                MigrationTransaction::from_parts(
                    id,
                    kind,
                    pczt,
                    depends_on,
                    scheduled_height,
                    expiry_height,
                    anchor_boundary,
                    state,
                    lock_owner,
                )
            },
        )
}

/// An arbitrary [`AnchorBucketInterval`]: the ZIP 318 grid or an arbitrary non-standard one, so a
/// store is exercised on both the value it will almost always see and values it must not special-case.
pub fn arb_anchor_bucket_interval() -> impl Strategy<Value = AnchorBucketInterval> {
    prop_oneof![
        1 => Just(AnchorBucketInterval::ZIP_318),
        1 => (1u32..100_000).prop_map(|blocks| {
            AnchorBucketInterval::custom(NonZeroU32::new(blocks).expect("nonzero"))
        }),
    ]
}

/// An arbitrary whole [`MigrationState`], built through [`MigrationState::from_parts`]: a status, a
/// denomination plan (from which the funding-note values derive), a preparation plan, a small set of
/// transactions re-keyed with sequential [`MigrationTransferId`]s (so their row keys are unique, as a
/// store requires), and the anchor bucket grid it was committed under. Generated values are
/// self-consistent enough to persist and read back unchanged.
pub fn arb_migration_state() -> impl Strategy<Value = MigrationState> {
    (
        arb_migration_status(),
        arb_denomination_plan(),
        arb_preparation_plan(),
        prop::collection::vec(arb_migration_transaction(), 0..6),
        arb_anchor_bucket_interval(),
    )
        .prop_map(
            |(status, denominations, preparation, txs, anchor_bucket_interval)| {
                // Re-key the transactions with sequential ids so their row keys are unique; a store
                // keys transaction rows by id and returns them in id order.
                let transactions = txs
                    .into_iter()
                    .enumerate()
                    .map(|(i, tx)| {
                        MigrationTransaction::from_parts(
                            MigrationTransferId::new(i as u32),
                            tx.kind(),
                            tx.pczt().clone(),
                            tx.depends_on().clone(),
                            tx.scheduled_height(),
                            tx.expiry_height(),
                            tx.anchor_boundary(),
                            tx.state(),
                            tx.lock_owner(),
                        )
                    })
                    .collect();
                MigrationState::from_parts(
                    status,
                    denominations,
                    preparation,
                    transactions,
                    anchor_bucket_interval,
                )
            },
        )
}

// --- conformance suite over the store traits ---

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
/// store reads back exactly the migration that was written.
pub fn assert_put_get_roundtrip<S: PoolMigrationWrite>(store: &mut S, state: &MigrationState)
where
    S::Error: Debug,
{
    store
        .replace_migration(state)
        .expect("replace_migration succeeds");
    let loaded = store.get_migration().expect("get_migration succeeds");
    assert_eq!(
        loaded,
        Some(state.clone()),
        "the stored migration must read back unchanged"
    );
}

/// Assert that a second replace overwrites the first: after putting `first` then `second`, the store holds
/// exactly `second`.
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
    assert_eq!(
        store.get_migration().expect("get_migration succeeds"),
        Some(second.clone()),
        "a second put must replace the first migration",
    );
}

/// Assert that a transaction state update persists: after storing `state` and calling
/// [`update_transaction`](PoolMigrationWrite::update_transaction) for `id`, the reloaded transaction
/// with that id carries `new`.
///
/// Call this only with an `id` that `state` actually contains (the store errors on an unknown
/// transaction); [`first_transaction_id`] picks a present one.
pub fn assert_update_transaction<S: PoolMigrationWrite>(
    store: &mut S,
    state: &MigrationState,
    id: MigrationTransferId,
    new: MigrationTxState,
) where
    S::Error: Debug,
{
    store
        .replace_migration(state)
        .expect("replace_migration succeeds");
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

// --- signing-round packing: reusable strategies + conformance suite ---
//
// A reusable suite so every `SigningRoundStrategy` (the crate's `MinRounds` / `NextFit`, and any a
// downstream crate adds) is exercised the same way: generate transaction sets and budgets, then
// assert the packing invariants hold for the strategy under test.

/// An arbitrary [`SigningRoundBudget`], covering the named [`SigningRoundBudget::KEYSTONE`] and
/// [`SigningRoundBudget::DEFAULT`] values plus a spread from the minimum feasible budget upward.
pub fn arb_signing_round_budget() -> impl Strategy<Value = SigningRoundBudget> {
    let floor = SigningRoundBudget::minimum_feasible().get();
    prop_oneof![
        Just(SigningRoundBudget::KEYSTONE),
        Just(SigningRoundBudget::DEFAULT),
        (floor..=1024u32)
            .prop_map(|n| SigningRoundBudget::new(NonZeroU32::new(n).expect("nonzero"))),
    ]
}

/// An arbitrary `(n_prep, n_transfer)` transaction-count pair for a single migration run, in the
/// realistic range a run produces (bounded by the per-run note cap).
pub fn arb_signing_round_counts() -> impl Strategy<Value = (usize, usize)> {
    (0usize..20, 0usize..60)
}

/// An arbitrary set of [`PlannedTx`] for one run: `n_prep` preparation transactions followed by
/// `n_transfer` transfers, in the canonical commit order with sequential ids (the same order a
/// [`MigrationPlan`](crate::engine::MigrationPlan) enumerates).
pub fn arb_planned_txs() -> impl Strategy<Value = Vec<PlannedTx>> {
    arb_signing_round_counts().prop_map(|(n_prep, n_transfer)| planned_txs(n_prep, n_transfer))
}

/// Build the canonical planned-transaction list for `n_prep` preparation and `n_transfer` transfer
/// transactions (preparation first, then transfers), with sequential ids.
pub fn planned_txs(n_prep: usize, n_transfer: usize) -> Vec<PlannedTx> {
    let mut txs = Vec::with_capacity(n_prep + n_transfer);
    let mut id = 0u32;
    for index in 0..n_prep {
        txs.push(PlannedTx::new(
            MigrationTransferId::new(id),
            MigrationTxKind::Preparation { layer: 0, index },
        ));
        id += 1;
    }
    for crossing in 0..n_transfer {
        txs.push(PlannedTx::new(
            MigrationTransferId::new(id),
            MigrationTxKind::Transfer { crossing },
        ));
        id += 1;
    }
    txs
}

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

/// One golden vector: an input to the signing-round packing problem and its expected optimal
/// (`MinRounds`) number of rounds. `budget_actions` is the per-round action budget.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SigningRoundVector {
    /// A short description of the case (used in assertion messages).
    pub name: &'static str,
    /// The number of preparation transactions (16 actions each).
    pub n_prep: usize,
    /// The number of transfer transactions (3 actions each).
    pub n_transfer: usize,
    /// The per-round action budget.
    pub budget_actions: u32,
    /// The expected minimum number of signing rounds.
    pub expected_min_rounds: usize,
}

/// The golden vectors: reusable inputs and expected optimal outputs for the signing-round packing
/// problem. See [`assert_golden_min_rounds`] and [`assert_golden_vectors_optimal`].
pub const SIGNING_ROUND_GOLDEN_VECTORS: &[SigningRoundVector] = {
    // A local constructor keeps the table terse and column-aligned.
    const fn v(
        name: &'static str,
        n_prep: usize,
        n_transfer: usize,
        budget_actions: u32,
        expected_min_rounds: usize,
    ) -> SigningRoundVector {
        SigningRoundVector {
            name,
            n_prep,
            n_transfer,
            budget_actions,
            expected_min_rounds,
        }
    }
    // The budgets under test, named from the real constants rather than magic numbers.
    const KEYSTONE: u32 = SigningRoundBudget::KEYSTONE.max_actions();
    const DEFAULT: u32 = SigningRoundBudget::DEFAULT.max_actions();
    const MIN: u32 = SigningRoundBudget::minimum_feasible().get();
    // Below the minimum feasible budget: a single preparation (16 actions) no longer fits a round,
    // but transfers still do. Exercises the oversized regime.
    const OVERSIZED: u32 = MIN - TRANSFER_ACTIONS * 2;
    &[
        // Keystone budget: 6 preparations or 32 transfers fill a round exactly.
        v("keystone: empty", 0, 0, KEYSTONE, 0),
        v("keystone: one preparation", 1, 0, KEYSTONE, 1),
        v("keystone: one transfer", 0, 1, KEYSTONE, 1),
        v(
            "keystone: preparations fill a round exactly",
            6,
            0,
            KEYSTONE,
            1,
        ),
        v(
            "keystone: one preparation over a full round",
            7,
            0,
            KEYSTONE,
            2,
        ),
        v(
            "keystone: transfers fill a round exactly",
            0,
            32,
            KEYSTONE,
            1,
        ),
        v(
            "keystone: one transfer over a full round",
            0,
            33,
            KEYSTONE,
            2,
        ),
        v("keystone: mix fills a round exactly", 3, 16, KEYSTONE, 1),
        v("keystone: mix fills a round with slack", 4, 10, KEYSTONE, 1),
        v("keystone: mix just over one round", 4, 11, KEYSTONE, 2),
        v("keystone: two full mixed rounds", 6, 32, KEYSTONE, 2),
        v("keystone: whale run", 2, 25, KEYSTONE, 2),
        v("keystone: preparations dominate", 6, 1, KEYSTONE, 2),
        v("keystone: small run", 1, 5, KEYSTONE, 1),
        v("keystone: run at the note cap", 4, 50, KEYSTONE, 3),
        // Default budget: a whole run signs in a single round.
        v("default: whole run in one round", 2, 25, DEFAULT, 1),
        v("default: larger run still one round", 6, 50, DEFAULT, 1),
        // Minimum feasible budget: a preparation fills a round alone.
        v("min: one preparation", 1, 0, MIN, 1),
        v("min: two preparations need two rounds", 2, 0, MIN, 2),
        v("min: five transfers fit one round", 0, 5, MIN, 1),
        v("min: six transfers need two rounds", 0, 6, MIN, 2),
        v(
            "min: a preparation leaves no room for a transfer",
            1,
            1,
            MIN,
            2,
        ),
        // Oversized regime: a single preparation exceeds the budget.
        v(
            "oversized: one preparation gets its own round",
            1,
            0,
            OVERSIZED,
            1,
        ),
        v(
            "oversized: two preparations, two rounds",
            2,
            0,
            OVERSIZED,
            2,
        ),
        v(
            "oversized: four transfers pack three per round",
            0,
            4,
            OVERSIZED,
            2,
        ),
        v(
            "oversized: a preparation plus four transfers",
            1,
            4,
            OVERSIZED,
            3,
        ),
    ]
};

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

/// A migration scenario keyed on a user's wallet: the source notes and the FEE-AWARE plan shape the
/// migration produces. Reused by every whole-migration end-to-end test.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MigrationScenario {
    /// A human-readable label (some are personas).
    pub label: &'static str,
    /// The wallet's source Orchard note values, in zatoshi (one entry per note).
    pub source_notes: &'static [u64],
    /// The expected number of preparation transactions the migration builds.
    pub expected_preparations: usize,
    /// The expected number of pool crossings (the "quanta"; one transfer transaction each). Always
    /// at least 1.
    pub expected_transfers: usize,
    /// The expected number of Keystone signing rounds ([`SigningRoundBudget::KEYSTONE`], 96 actions)
    /// this migration's one run takes: the optimal packing of its preparation (16 actions each) and
    /// transfer (3 actions each) transactions.
    pub expected_keystone_rounds: usize,
    /// The expected migrated value, in zatoshi: the balance less the reserved transfer buffers and
    /// preparation fees, so a multiple of the 0.01-ZEC minimum denomination.
    pub expected_migrated: u64,
}

/// The canonical migration scenarios, keyed on the user's wallet balance and fee-aware.
pub const MIGRATION_SCENARIOS: &[MigrationScenario] = {
    const fn s(
        label: &'static str,
        source_notes: &'static [u64],
        expected_preparations: usize,
        expected_transfers: usize,
        expected_keystone_rounds: usize,
        expected_migrated: u64,
    ) -> MigrationScenario {
        MigrationScenario {
            label,
            source_notes,
            expected_preparations,
            expected_transfers,
            expected_keystone_rounds,
            expected_migrated,
        }
    }
    // One hundredth of a ZEC: the minimum denomination, and the unit the migrated totals fall on.
    const H: u64 = COIN / 100;
    // Repeated and dusty note shapes whose consolidation drives multi-layer preparation.
    const TEN_FIVES: &[u64] = &[5 * COIN; 10];
    const TEN_TWELVES: &[u64] = &[12 * COIN; 10];
    const DUST: u64 = COIN / 50; // 0.02 ZEC
    const DUST_HEAVY: &[u64] = &[
        COIN, DUST, DUST, DUST, DUST, DUST, DUST, DUST, DUST, DUST, DUST, DUST, DUST,
    ];
    const WHALE_DUST: &[u64] = &[
        40 * COIN,
        DUST,
        DUST,
        COIN / 20,
        COIN / 20,
        COIN / 10,
        COIN / 10,
    ];
    // Columns: label, source notes, preparations, transfers (quanta), Keystone rounds, migrated.
    &[
        // Single-note balances.
        s("small holder, 2 ZEC", &[2 * COIN], 1, 7, 1, 199 * H),
        s("retail, 15 ZEC", &[15 * COIN], 1, 9, 1, 1_499 * H),
        s("denominations, 60 ZEC", &[60 * COIN], 1, 10, 1, 5_999 * H),
        s("78 ZEC in a single note", &[78 * COIN], 1, 10, 1, 7_799 * H),
        s(
            "Gwen, 0.0152 ZEC (a single minimum-denomination note)",
            &[1_520_000],
            1,
            1,
            1,
            H,
        ),
        s(
            "Priya, 7.1101 ZEC (the buffer prunes the trailing crossing)",
            &[711_010_000],
            1,
            3,
            1,
            710 * H,
        ),
        // Many-note shapes, consolidated across preparation layers.
        s("exchange, ten 5 ZEC notes", TEN_FIVES, 2, 3, 1, 4_500 * H),
        // Five preparations (80 actions) plus eleven transfers (33 actions) is 113 actions: the
        // only scenario that needs a second Keystone round.
        s(
            "monotonic, ten 12 ZEC notes",
            TEN_TWELVES,
            5,
            11,
            2,
            11_999 * H,
        ),
        s(
            "dust-heavy, 1 ZEC and twelve 0.02 ZEC notes",
            DUST_HEAVY,
            4,
            4,
            1,
            123 * H,
        ),
        s(
            "whale plus dust, 40 ZEC and a six-note dust tail",
            WHALE_DUST,
            4,
            6,
            1,
            4_033 * H,
        ),
    ]
};

// --- how the Keystone round count evolves with the action total ---
//
// A separate, PLAN-ONLY set (never proved, so it is not part of `MIGRATION_SCENARIOS`, whose
// scenarios the real-proving `prove_chain_sim` test proves end to end). These larger single-note
// balances show how the number of Keystone (96-action) rounds grows as the migration's action total
// grows: a preparation transaction is 16 actions and a transfer is 3, so the round count steps up
// each time the total crosses a multiple of 96. Every case is one run (its quanta are within the
// per-run note cap; 500,000 ZEC fills it exactly).

/// One row of the round-evolution table: a single-note balance (in whole ZEC) and the plan shape it
/// produces, focused on the Keystone round count.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RoundEvolutionCase {
    /// The single source note's value, in whole ZEC.
    pub balance_zec: u64,
    /// The expected number of pool crossings (quanta).
    pub expected_crossings: usize,
    /// The expected number of preparation transactions.
    pub expected_preparations: usize,
    /// The expected total Orchard actions (`crossings * 3 + preparations * 16`).
    pub expected_actions: u32,
    /// The expected number of Keystone (96-action) signing rounds.
    pub expected_keystone_rounds: usize,
}

/// How the Keystone round count evolves as the migration's action total grows. Plan-only (not
/// proved). Captured from the canonical planner on the regtest network.
pub const SIGNING_ROUND_EVOLUTION: &[RoundEvolutionCase] = {
    const fn e(
        balance_zec: u64,
        expected_crossings: usize,
        expected_preparations: usize,
        expected_keystone_rounds: usize,
    ) -> RoundEvolutionCase {
        RoundEvolutionCase {
            balance_zec,
            expected_crossings,
            expected_preparations,
            expected_actions: (expected_crossings as u32) * TRANSFER_ACTIONS
                + (expected_preparations as u32) * PREPARATION_ACTIONS,
            expected_keystone_rounds,
        }
    }
    &[
        //   balance   crossings prep  ->  actions   Keystone rounds
        e(60, 10, 1, 1),      //  46 actions  -> 1 round
        e(50_000, 22, 3, 2),  // 114 actions  -> 2 rounds (crosses 96)
        e(250_000, 42, 4, 2), // 190 actions  -> 2 rounds (still under 192)
        e(300_000, 47, 5, 3), // 221 actions  -> 3 rounds (crosses 192)
        e(500_000, 50, 5, 3), // 230 actions  -> 3 rounds (the 50-note run cap)
    ]
};

// --- how the TOTAL Keystone round count evolves across multiple runs ---
//
// A balance beyond one run's note cap (50 crossings, ~500,000 ZEC) migrates over several runs; the
// runs are serialized (a later run spends notes an earlier run must mine first), so a signer's
// interactions are SUMMED per run, never packed across them. This plan-only table shows how the
// total Keystone rounds grow with the balance: each full run contributes 3 rounds (50 crossings plus
// its preparation is ~230 actions), and the final partial run contributes fewer.

/// One row of the multi-run evolution table: a single-note whale balance (in whole ZEC) and the
/// whole-migration estimate it produces.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MultiRunEvolutionCase {
    /// The single source note's value, in whole ZEC.
    pub balance_zec: u64,
    /// The expected number of migration runs.
    pub expected_runs: usize,
    /// The expected total number of crossings (quanta) across all runs.
    pub expected_total_crossings: usize,
    /// The expected total Orchard actions to sign across all runs (the signing workload; a proxy for
    /// signing time).
    pub expected_total_actions: u32,
    /// The expected total Keystone signing rounds, summed per run (rounds cannot span runs).
    pub expected_total_keystone_rounds: usize,
}

/// How the total Keystone round count evolves across runs. Plan-only (estimate only, nothing built
/// or proved). Captured from the canonical planner on the regtest network.
pub const MULTI_RUN_EVOLUTION: &[MultiRunEvolutionCase] = {
    const fn m(
        balance_zec: u64,
        expected_runs: usize,
        expected_total_crossings: usize,
        expected_total_actions: u32,
        expected_total_keystone_rounds: usize,
    ) -> MultiRunEvolutionCase {
        MultiRunEvolutionCase {
            balance_zec,
            expected_runs,
            expected_total_crossings,
            expected_total_actions,
            expected_total_keystone_rounds,
        }
    }
    &[
        //   balance     runs  quanta  actions  total Keystone rounds (summed per run)
        m(600_000, 2, 77, 359, 5),       // per run [3, 2]
        m(1_000_000, 3, 116, 556, 7),    // [3, 3, 1]
        m(1_200_000, 3, 136, 632, 8),    // [3, 3, 2]
        m(2_000_000, 5, 215, 997, 13),   // [3, 3, 3, 3, 1]
        m(5_000_000, 11, 517, 2399, 32), // ten full runs of 3, then a tail of 2
    ]
};
