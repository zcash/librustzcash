//! How note PREPARATION scales on messy wallets: hundreds to thousands of source notes.
//!
//! The other end-to-end tests plan hand-written note shapes and pin the exact plan. This one plans
//! RANDOM wallets drawn from [`WalletShape`] across a range of note counts, and asserts the scaling
//! LAWS the preparation planner should obey rather than any individual plan. That is the right
//! shape of assertion here for two reasons: the exact plan for a thousand random notes is not
//! meaningful to a reader, and the reason to look at this regime at all is that the cost is driven
//! by the note count rather than by the balance.
//!
//! The quantities that matter, and why:
//!
//! - TRANSACTIONS. Every wallet note the migration SPENDS must be consumed by some preparation
//!   transaction, and a transaction consumes at most [`CONSOLIDATION_INPUTS_PER_TX`] notes (the ZIP
//!   318 action budget less its one output). So `ceil(spent / 15)` is a hard floor GIVEN the
//!   selection, and the ratio of the plan to it is what the layering strategy costs on top.
//! - SELECTION. That floor is conditional, not absolute: a migration only has to fund its crossings,
//!   so the notes it must spend are the ones needed to COVER that value, not the whole wallet.
//!   `selection_floor` is the smallest number of notes that could cover it (the largest notes
//!   first), and the gap between it and `spent` is the part of the cost that is a choice rather than
//!   a constraint.
//! - LAYERS. Layers are sequential: each waits for the previous to mine, so they set the
//!   preparation phase's wall-clock. Consolidating `n` notes at a fan-in of 15 per transaction is a
//!   15-ary tree, so `ceil(log_15 n)` is the floor.
//! - SIGNING ROUNDS. Preparation costs 16 actions per transaction against a transfer's 3, so on
//!   these wallets it is the preparation, not the migration itself, that the user signs.
//!
//! Run with `--nocapture --test-threads=1` to see the measured tables alongside the assertions (the
//! tests interleave their output otherwise). The heavy end of the sweep (thousands of notes) is
//! `#[ignore]`d: the cost there is building the mock backend's notes, not planning, and it runs in
//! minutes rather than seconds.

#![cfg(all(feature = "orchard", feature = "test-dependencies"))]

use std::time::{Duration, Instant};

use rand_chacha::ChaCha8Rng;
use rand_core::SeedableRng;

use zcash_pool_migration::{
    engine::{MigrationPlan, plan_migration},
    preparation::{CONSOLIDATION_INPUTS_PER_TX, PrepInput},
    signing_rounds::{PREPARATION_ACTIONS, SigningRoundBudget},
    testing::{WalletShape, generate_notes, sub_quantum_count},
};
use zcash_pool_migration_memory::{CommitMock, regtest_network};

/// The note counts the fast sweep covers: hundreds, where a messy wallet already costs an order of
/// magnitude more preparation than a tidy one.
const NOTE_COUNTS: &[usize] = &[100, 250, 500, 1_000];

/// The note counts the `#[ignore]`d heavy sweep adds: thousands.
const HEAVY_NOTE_COUNTS: &[usize] = &[2_000, 5_000];

/// The seeds each (shape, note count) cell is measured at. Several draws per cell keep a single
/// lucky or unlucky wallet from deciding whether a scaling law holds.
const SEEDS: &[u64] = &[1, 2];

/// What one generated wallet's plan cost.
struct Measurement {
    /// The generated source notes.
    notes: Vec<u64>,
    /// How many of them are sub-quantum.
    sub_quantum: usize,
    /// The wallet notes the preparation actually spends.
    spent: usize,
    /// The preparation transactions the plan builds.
    preparations: usize,
    /// The sequential preparation layers.
    layers: usize,
    /// The pool crossings (one transfer transaction each).
    crossings: usize,
    /// The Orchard actions a signer processes for the whole run.
    actions: u32,
    /// The Keystone (96-action) signing rounds the run takes.
    keystone_rounds: usize,
    /// The value the run migrates, in zatoshi.
    migrated: u64,
    /// How long `plan_migration` took. Planning is pure arithmetic with no I/O and no cryptography,
    /// so anything but instant here is the planner's own complexity in the note count.
    planning: Duration,
}

impl Measurement {
    /// The hard floor on preparation transactions GIVEN the notes the plan chose to spend: each must
    /// be consumed, and one transaction consumes at most `CONSOLIDATION_INPUTS_PER_TX` of them.
    fn transaction_floor(&self) -> usize {
        self.spent.div_ceil(CONSOLIDATION_INPUTS_PER_TX)
    }

    /// The smallest number of wallet notes that could cover the migrated value, taking the largest
    /// notes first. A migration must fund its crossings; it does not have to drain the wallet, so
    /// this is the floor on how many notes NEED spending, against which
    /// [`spent`](Self::spent) is the planner's actual choice.
    fn selection_floor(&self) -> usize {
        let mut values: Vec<u64> = self.notes.clone();
        values.sort_unstable_by(|a, b| b.cmp(a));
        let mut covered = 0u64;
        for (taken, value) in values.into_iter().enumerate() {
            if covered >= self.migrated {
                return taken;
            }
            covered = covered.saturating_add(value);
        }
        self.notes.len()
    }

    /// The hard floor on layers: consolidating `spent` notes at a fan-in of
    /// `CONSOLIDATION_INPUTS_PER_TX` per transaction is a 15-ary tree of that depth.
    fn layer_floor(&self) -> usize {
        let mut reachable = CONSOLIDATION_INPUTS_PER_TX;
        let mut depth = 1;
        while reachable < self.spent {
            reachable = reachable.saturating_mul(CONSOLIDATION_INPUTS_PER_TX);
            depth += 1;
        }
        depth
    }

    /// The share of the signing workload that is preparation rather than migration.
    fn preparation_share(&self) -> f64 {
        f64::from(self.preparations as u32 * PREPARATION_ACTIONS) / f64::from(self.actions)
    }
}

/// Generate a wallet and measure the plan it produces.
fn measure(shape: WalletShape, note_count: usize, seed: u64) -> Measurement {
    let mut gen_rng = ChaCha8Rng::seed_from_u64(seed);
    let notes = generate_notes(shape, note_count, &mut gen_rng);

    let backend = CommitMock::new(seed, &notes);
    let mut rng = ChaCha8Rng::seed_from_u64(seed);
    let started = Instant::now();
    let plan: MigrationPlan = plan_migration(&regtest_network(true), &backend, &mut rng)
        .expect("a generated wallet is fundable");
    let planning = started.elapsed();

    Measurement {
        sub_quantum: sub_quantum_count(&notes),
        spent: spent_wallet_notes(&plan),
        preparations: plan.preparation_tx_count(),
        layers: plan.preparation_layer_count(),
        crossings: plan.transfer_tx_count(),
        actions: plan.total_actions(),
        keystone_rounds: plan.signing_round_count(SigningRoundBudget::KEYSTONE),
        migrated: plan.value_migrated().into_u64(),
        planning,
        notes,
    }
}

/// How many distinct WALLET notes (as opposed to notes an earlier layer produced) the preparation
/// spends, plus the notes used directly as funding notes with no preparation at all.
fn spent_wallet_notes(plan: &MigrationPlan) -> usize {
    let mut indices: Vec<usize> = plan
        .preparation()
        .layers()
        .iter()
        .flatten()
        .flat_map(|tx| tx.inputs())
        .filter_map(|input| match input {
            PrepInput::Wallet { index, .. } => Some(*index),
            PrepInput::Prior { .. } => None,
        })
        .chain(
            plan.preparation()
                .direct_funding_notes()
                .iter()
                .map(|&(index, _)| index),
        )
        .collect();
    indices.sort_unstable();
    indices.dedup();
    indices.len()
}

/// Print one measured row of the sweep table.
fn report(shape: WalletShape, m: &Measurement) {
    println!(
        "{:<18} {:>6} {:>7} {:>6} {:>5} {:>6} {:>5} {:>6} {:>5} {:>6} {:>6} {:>5} {:>4.0}% {:>8.0}",
        shape.label(),
        m.notes.len(),
        m.sub_quantum,
        m.spent,
        m.selection_floor(),
        m.preparations,
        m.transaction_floor(),
        m.layers,
        m.layer_floor(),
        m.crossings,
        m.actions,
        m.keystone_rounds,
        m.preparation_share() * 100.0,
        m.planning.as_secs_f64() * 1000.0,
    );
}

/// Print the sweep table's header.
fn report_header() {
    println!(
        "{:<18} {:>6} {:>7} {:>6} {:>5} {:>6} {:>5} {:>6} {:>5} {:>6} {:>6} {:>5} {:>5} {:>8}",
        "shape",
        "notes",
        "sub-qtm",
        "spent",
        "sfloor",
        "preps",
        "tfloor",
        "layers",
        "lfloor",
        "cross",
        "acts",
        "ks",
        "prep%",
        "plan ms",
    );
}

/// Assert the scaling laws on one measured wallet.
fn assert_scaling_laws(shape: WalletShape, note_count: usize, seed: u64, m: &Measurement) {
    let case = format!("{} / {note_count} notes / seed {seed}", shape.label());

    // The floors are floors: no plan may beat them.
    assert!(
        m.preparations >= m.transaction_floor(),
        "{case}: {} preparations beats the {} floor for {} spent notes",
        m.preparations,
        m.transaction_floor(),
        m.spent,
    );
    assert!(
        m.layers >= m.layer_floor(),
        "{case}: {} layers beats the {} floor for {} spent notes",
        m.layers,
        m.layer_floor(),
        m.spent,
    );

    // A migration always migrates something, and it cannot spend a note the wallet does not have.
    assert!(m.crossings >= 1, "{case}: nothing migrated");
    assert!(
        m.spent <= m.notes.len(),
        "{case}: spent more notes than held"
    );

    // Preparation, not migration, is the signing workload here: a preparation is 16 actions to a
    // transfer's 3, and these wallets need far more preparations than crossings.
    assert!(
        m.preparation_share() > 0.5,
        "{case}: preparation is {:.0}% of the signing workload, expected the majority",
        m.preparation_share() * 100.0,
    );

    // Planning is pure arithmetic; it must not become the bottleneck at these note counts.
    assert!(
        m.planning < Duration::from_secs(1),
        "{case}: planning took {:?}",
        m.planning,
    );
}

/// PREPARATION SCALING on messy wallets of a few hundred to a thousand notes.
#[test]
fn preparation_scales_with_the_note_count() {
    report_header();
    for &shape in WalletShape::ALL {
        for &note_count in NOTE_COUNTS {
            for &seed in SEEDS {
                let m = measure(shape, note_count, seed);
                if seed == SEEDS[0] {
                    report(shape, &m);
                }
                assert_scaling_laws(shape, note_count, seed, &m);
            }
        }
    }
}

/// The same sweep at thousands of notes. Ignored by default: generating the mock backend's notes
/// dominates, so this runs in minutes.
#[test]
#[ignore = "minutes: dominated by mock-backend note setup, not by planning"]
fn preparation_scales_into_the_thousands() {
    report_header();
    for &shape in WalletShape::ALL {
        for &note_count in HEAVY_NOTE_COUNTS {
            let seed = SEEDS[0];
            let m = measure(shape, note_count, seed);
            report(shape, &m);
            assert_scaling_laws(shape, note_count, seed, &m);
        }
    }
}

/// The planner spends the WHOLE wallet, not the notes the migration needs.
///
/// A run only has to fund its crossings, so on a heavy-tailed wallet the largest handful of notes
/// already covers the migrated value and the rest could be left for a later run. The planner instead
/// consolidates everything, and since preparation transactions are the dominant signing cost, that
/// choice is what makes a thousand-note wallet expensive. This test records the gap rather than
/// asserting it away: it is the measurement an input-selection change would move.
#[test]
fn preparation_spends_the_whole_wallet_not_the_notes_it_needs() {
    println!(
        "{:<18} {:>6} {:>6} {:>7} {:>7} {:>7}",
        "shape", "notes", "spent", "needed", "preps", "min-tx",
    );
    for &shape in WalletShape::ALL {
        for &note_count in NOTE_COUNTS {
            let m = measure(shape, note_count, SEEDS[0]);
            let needed = m.selection_floor();
            println!(
                "{:<18} {:>6} {:>6} {:>7} {:>7} {:>7}",
                shape.label(),
                m.notes.len(),
                m.spent,
                needed,
                m.preparations,
                needed.div_ceil(CONSOLIDATION_INPUTS_PER_TX).max(1),
            );

            // Covering the migrated value cannot need more notes than the plan actually spent: the
            // spent notes are, by construction, enough to fund the crossings.
            assert!(
                needed <= m.spent,
                "{} / {note_count}: covering {} zatoshi needs {needed} notes but only {} were spent",
                shape.label(),
                m.migrated,
                m.spent,
            );
        }
    }
}
