//! Fixed test data: the named migration personas and the golden vectors.
//!
//! Defining the scenarios ONCE and sharing them is what lets the fast accounting tests
//! (`signing_rounds_e2e.rs`) and the slow proving tests (`zcash_client_sqlite`'s
//! `pool_migration_prove_chain_sim.rs`) speak about the same balances, so a change in planned
//! behaviour shows up in both rather than drifting silently between them.

use core::fmt::Debug;

use zcash_protocol::value::COIN;

use crate::engine::{MigrationTransferId, MigrationTxKind};
use crate::signing_rounds::{PREPARATION_ACTIONS, PlannedTx, SigningRoundBudget, TRANSFER_ACTIONS};

use alloc::vec::Vec;

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
/// problem. See [`assert_golden_min_rounds`](super::assert_golden_min_rounds) and
/// [`assert_golden_vectors_optimal`](super::assert_golden_vectors_optimal).
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

// --- what a large balance actually plans, as a function of its NOTE SHAPE ---
//
// The two tables above vary the balance and hold the note shape fixed (one note). This one does the
// opposite: it fixes a single large balance and varies how the wallet holds it. That is the
// dimension a user actually notices, because the crossing count is set by the balance's
// {1,2,5}x10^k decomposition (essentially constant here) while the PREPARATION count is set by how
// many notes must be consolidated, so the plan grows with the note count even though the amount
// migrated does not.
//
// The balance is the one from a user report of an unexpectedly large plan. Plan-only (nothing is
// built or proved): funding a wallet with thousands of ZEC is out of reach for the regtest
// proving simulation, which is why these do not live in `MIGRATION_SCENARIOS`.

/// One thousandth of a ZEC, the unit the reported balance is quoted in.
const MILLI: u64 = COIN / 1_000;

/// The balance from the user report: 5887.842 ZEC, in zatoshi.
pub const REPORTED_LARGE_BALANCE: u64 = 5_887_842 * MILLI;

/// One row of the large-balance table: a note shape holding [`REPORTED_LARGE_BALANCE`], and the plan
/// it produces. The whole-migration figures (`expected_runs` and the `expected_total_*` fields) come
/// from the estimate; the rest describe the FIRST run, which is the one `plan_migration` returns.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LargeBalanceCase {
    /// A short description of the note shape.
    pub label: &'static str,
    /// The wallet's source Orchard note values, in zatoshi. These sum to
    /// [`REPORTED_LARGE_BALANCE`].
    pub source_notes: &'static [u64],
    /// The expected number of migration runs the whole balance takes.
    pub expected_runs: usize,
    /// The expected number of crossings (quanta) across all runs.
    pub expected_total_crossings: usize,
    /// The expected total Orchard actions to sign across all runs.
    pub expected_total_actions: u32,
    /// The expected total Keystone signing rounds, summed per run.
    pub expected_total_keystone_rounds: usize,
    /// The expected number of preparation transactions in the first run.
    pub expected_preparations: usize,
    /// The expected number of crossings in the first run.
    pub expected_transfers: usize,
    /// The expected number of transactions in the first run: preparations plus crossings. This is
    /// the "how many transactions is this migration" figure a wallet shows.
    pub expected_transactions: usize,
    /// The expected Orchard actions in the first run
    /// (`preparations * 16 + transfers * 3`).
    pub expected_actions: u32,
    /// The expected number of Keystone ([`SigningRoundBudget::KEYSTONE`], 96 actions) signing rounds
    /// for the first run.
    pub expected_keystone_rounds: usize,
    /// The expected value the first run migrates, in zatoshi.
    pub expected_migrated: u64,
    /// The expected value the first run leaves behind, in zatoshi. A large residual is what forces a
    /// second run.
    pub expected_residual: u64,
}

/// How the plan for [`REPORTED_LARGE_BALANCE`] (5887.842 ZEC) varies with the note shape holding it.
/// Plan-only (never built or proved). Captured from the canonical planner on the regtest network.
pub const LARGE_BALANCE_CASES: &[LargeBalanceCase] = {
    #[allow(clippy::too_many_arguments)]
    const fn c(
        label: &'static str,
        source_notes: &'static [u64],
        expected_runs: usize,
        expected_total_crossings: usize,
        expected_total_actions: u32,
        expected_total_keystone_rounds: usize,
        expected_preparations: usize,
        expected_transfers: usize,
        expected_keystone_rounds: usize,
        expected_migrated: u64,
        expected_residual: u64,
    ) -> LargeBalanceCase {
        LargeBalanceCase {
            label,
            source_notes,
            expected_runs,
            expected_total_crossings,
            expected_total_actions,
            expected_total_keystone_rounds,
            expected_preparations,
            expected_transfers,
            expected_transactions: expected_preparations + expected_transfers,
            expected_actions: (expected_preparations as u32) * PREPARATION_ACTIONS
                + (expected_transfers as u32) * TRANSFER_ACTIONS,
            expected_keystone_rounds,
            expected_migrated,
            expected_residual,
        }
    }
    // The balance divides exactly by each of these, so every note carries the same value.
    const ONE_NOTE: &[u64] = &[REPORTED_LARGE_BALANCE];
    const TWO_NOTES: &[u64] = &[REPORTED_LARGE_BALANCE / 2; 2];
    const FIVE_NOTES: &[u64] = &[REPORTED_LARGE_BALANCE / 5; 5];
    const TEN_NOTES: &[u64] = &[REPORTED_LARGE_BALANCE / 10; 10];
    const HUNDRED_NOTES: &[u64] = &[REPORTED_LARGE_BALANCE / 100; 100];
    // One hundredth of a ZEC: the minimum denomination, and the unit the migrated totals fall on.
    const H: u64 = COIN / 100;
    &[
        // The balance decomposes into fourteen {1,2,5}x10^k crossings
        // (5000 + 500 + 200 + 100 + 50 + 20 + 10 + 5 + 2 + 0.5 + 0.2 + 0.1 + 0.02 + 0.01), and a
        // single source note funds them all from one preparation transaction: 15 transactions, 58
        // actions, ONE Keystone round.
        c(
            "5887.842 ZEC in a single note",
            ONE_NOTE,
            1,
            14,
            58,
            1,
            1,
            14,
            1,
            588_783 * H,
            910_000,
        ),
        // THE DEGENERATE SHAPE. Neither note reaches the leading 5000 ZEC denomination, so funding
        // that one crossing consumes BOTH notes across two preparation layers, and the run ends
        // having migrated only the 5000. The remaining ~887.84 ZEC is left as residual for a whole
        // SECOND run, which is why the same balance costs 90 actions here against 58 above.
        c(
            "5887.842 ZEC in two equal notes",
            TWO_NOTES,
            2,
            14,
            90,
            2,
            2,
            1,
            1,
            500_000 * H,
            88_784_025_000,
        ),
        // From three notes upward the leading crossing is fundable within one run again, so the full
        // fourteen crossings return; only the preparation count (and with it the Keystone rounds)
        // grows with the note count.
        c(
            "5887.842 ZEC in five equal notes",
            FIVE_NOTES,
            1,
            14,
            106,
            2,
            4,
            14,
            2,
            588_783 * H,
            670_000,
        ),
        c(
            "5887.842 ZEC in ten equal notes",
            TEN_NOTES,
            1,
            14,
            122,
            2,
            5,
            14,
            2,
            588_783 * H,
            590_000,
        ),
        // A hundred notes cost thirteen preparation transactions, so preparation now dominates:
        // 247 actions, of which only 39 are the crossings themselves.
        c(
            "5887.842 ZEC in one hundred equal notes",
            HUNDRED_NOTES,
            1,
            13,
            247,
            3,
            13,
            13,
            3,
            588_782 * H,
            965_000,
        ),
    ]
};
