//! Sizing a run by SIGNER CAPACITY instead of by note count, as an external crate sees it.
//!
//! A wallet picks one of two ways to bound a run, and both are first-class:
//!
//! - by NOTE COUNT (`plan_migration_with`), when the wallet wants a fixed run size;
//! - by SIGNER CAPACITY (`plan_migration_for_signer`), when a hardware signer bounds how much it
//!   will sign in one interaction.
//!
//! Only the second can promise "one run is one signing session", because a run's actions are
//! `16 * preparations + 3 * transfers` and the preparation count follows the wallet's fragmentation,
//! not the note cap. These tests pin that difference: the same wallets that need several Keystone
//! rounds under the default note cap plan in one round when sized for the signer, the note-cap API
//! keeps behaving exactly as before, and the estimate previews the runs the planner will build.
#![cfg(feature = "test-dependencies")]

use core::num::NonZeroUsize;

use proptest::prelude::*;
use rand_chacha::ChaCha8Rng;
use rand_core::SeedableRng;

use zcash_pool_migration::{
    denomination::MIGRATION_MAX_PREPARED_NOTES_PER_RUN,
    engine::{
        MigrationPlan, MigrationRunEstimate, RunSizing, estimate_migration_runs_for_signer,
        plan_migration, plan_migration_for_signer, plan_migration_sized_with, plan_migration_with,
    },
    preparation::default_portfolio,
    signing_rounds::{RunSigningCapacity, SigningRoundBudget},
    testing::{
        MIGRATION_SCENARIOS, MigrationScenario, WalletShape, arb_run_signing_capacity,
        generate_notes,
    },
};
use zcash_pool_migration_memory::{MockBackend, regtest_network};

/// A post-NU6.3 chain tip to plan against.
const TIP: u32 = 2_000_000;
/// Any fixed seed: the canonical decomposition does not consult the RNG, and every comparison below
/// uses this same seed so the schedules match too.
const SEED: u64 = 7;

/// Plan one run for `notes`, sized for a signer of `capacity`.
fn plan_for_signer(notes: &[u64], capacity: RunSigningCapacity) -> MigrationPlan {
    let backend = MockBackend::new(notes.to_vec(), TIP);
    let mut rng = ChaCha8Rng::seed_from_u64(SEED);
    plan_migration_for_signer(capacity, &regtest_network(true), &backend, &mut rng)
        .expect("a fundable balance plans")
}

/// Plan one run for `notes` through the entry point that takes the bound as a value.
fn plan_sized(notes: &[u64], sizing: RunSizing) -> MigrationPlan {
    let backend = MockBackend::new(notes.to_vec(), TIP);
    let mut rng = ChaCha8Rng::seed_from_u64(SEED);
    plan_migration_sized_with(
        &default_portfolio(),
        sizing,
        &regtest_network(true),
        &backend,
        &mut rng,
    )
    .expect("a fundable balance plans")
}

/// Estimate the whole migration of `notes` with every run sized for a signer of `capacity`.
fn estimate_for_signer(notes: &[u64], capacity: RunSigningCapacity) -> MigrationRunEstimate {
    let backend = MockBackend::new(notes.to_vec(), TIP);
    let mut rng = ChaCha8Rng::seed_from_u64(SEED);
    estimate_migration_runs_for_signer(capacity, &regtest_network(true), &backend, &mut rng)
        .expect("a fundable balance estimates")
}

/// The scenarios whose one run takes more than one Keystone round under the default note cap: the
/// wallets the multi-round QR flow was built for.
///
/// Asserts the selection is non-empty, because every caller's assertions live INSIDE a loop over
/// it. Exactly one scenario qualifies today, so a change to the fee model, the packer or that
/// wallet's shape could empty this filter, and each of those tests would then pass while checking
/// nothing at all. Guarding here rather than in each caller is what makes that impossible to
/// forget for the next test that iterates this.
fn multi_round_scenarios() -> Vec<&'static MigrationScenario> {
    let scenarios: Vec<_> = MIGRATION_SCENARIOS
        .iter()
        .filter(|sc| sc.expected_keystone_rounds > 1)
        .collect();
    assert!(
        !scenarios.is_empty(),
        "no scenario needs several Keystone rounds under the note cap, so every test comparing \
         the two sizings would iterate nothing and pass vacuously"
    );
    scenarios
}

/// Sizing for a Keystone turns each of those runs into ONE signing round.
#[test]
fn a_keystone_sized_run_is_one_signing_round() {
    for scenario in multi_round_scenarios() {
        let plan = plan_for_signer(scenario.source_notes, RunSigningCapacity::KEYSTONE);
        assert_eq!(
            plan.signing_round_count(SigningRoundBudget::KEYSTONE),
            1,
            "{}: a Keystone-sized run signs in one round, not {}",
            scenario.label,
            plan.signing_round_count(SigningRoundBudget::KEYSTONE),
        );
        assert!(
            plan.total_actions() <= SigningRoundBudget::KEYSTONE.max_actions(),
            "{}: the run fits the device's per-round budget",
            scenario.label,
        );
    }
}

/// The two sizings coexist: the note-cap API is unchanged, and on a wallet where they differ the
/// signer-sized run is the smaller one — that is the whole trade, fewer notes per run in exchange
/// for one interaction per run.
#[test]
fn note_count_and_signer_capacity_are_both_available() {
    for scenario in multi_round_scenarios() {
        let backend = MockBackend::new(scenario.source_notes.to_vec(), TIP);
        let mut rng = ChaCha8Rng::seed_from_u64(SEED);
        let by_notes = plan_migration(&regtest_network(true), &backend, &mut rng)
            .expect("a fundable balance plans");
        assert_eq!(
            by_notes.signing_round_count(SigningRoundBudget::KEYSTONE),
            scenario.expected_keystone_rounds,
            "{}: the note-cap sizing is unchanged",
            scenario.label,
        );

        let by_capacity = plan_for_signer(scenario.source_notes, RunSigningCapacity::KEYSTONE);
        assert!(
            by_capacity.transfer_tx_count() < by_notes.transfer_tx_count(),
            "{}: fitting one round costs crossings this run defers to the next",
            scenario.label,
        );
        assert!(
            by_capacity.value_migrated() < by_notes.value_migrated(),
            "{}: and defers value with them",
            scenario.label,
        );
    }
}

/// An explicit note cap reaches the same plan the signer sizing chose, so the sizing is a CHOICE OF
/// CAP and nothing else: it never reshapes a run beyond bounding how many notes it prepares.
#[test]
fn signer_sizing_only_chooses_the_cap() {
    for scenario in multi_round_scenarios() {
        let by_capacity = plan_for_signer(scenario.source_notes, RunSigningCapacity::KEYSTONE);
        let cap = NonZeroUsize::new(by_capacity.transfer_tx_count())
            .expect("a planned run crosses at least one note");

        let backend = MockBackend::new(scenario.source_notes.to_vec(), TIP);
        let mut rng = ChaCha8Rng::seed_from_u64(SEED);
        let by_notes = plan_migration_with(
            &default_portfolio(),
            cap,
            &regtest_network(true),
            &backend,
            &mut rng,
        )
        .expect("a fundable balance plans");
        assert_eq!(
            by_capacity.planned_transactions(),
            by_notes.planned_transactions(),
            "{}: the signer-sized plan builds the run the note-capped plan builds at the chosen cap",
            scenario.label,
        );
        assert_eq!(
            (by_capacity.value_migrated(), by_capacity.residual()),
            (by_notes.value_migrated(), by_notes.residual()),
            "{}: and migrates and defers the same value",
            scenario.label,
        );
    }
}

/// One entry point carries either bound, so an application can hold the user's choice as a value
/// and plan through it: each `RunSizing` reaches the same plan its own entry point does.
#[test]
fn one_entry_point_carries_either_bound() {
    for scenario in multi_round_scenarios() {
        let by_notes = plan_sized(scenario.source_notes, RunSizing::default());
        let backend = MockBackend::new(scenario.source_notes.to_vec(), TIP);
        let mut rng = ChaCha8Rng::seed_from_u64(SEED);
        let default_plan = plan_migration(&regtest_network(true), &backend, &mut rng)
            .expect("a fundable balance plans");
        assert_eq!(
            by_notes.planned_transactions(),
            default_plan.planned_transactions(),
            "{}: the note-count bound plans what `plan_migration` plans",
            scenario.label,
        );

        let by_capacity = plan_sized(
            scenario.source_notes,
            RunSizing::Signer(RunSigningCapacity::KEYSTONE),
        );
        assert_eq!(
            by_capacity.planned_transactions(),
            plan_for_signer(scenario.source_notes, RunSigningCapacity::KEYSTONE)
                .planned_transactions(),
            "{}: the signer bound plans what `plan_migration_for_signer` plans",
            scenario.label,
        );
    }
}

/// The estimate previews what the planner will build: its first run is the run
/// `plan_migration_for_signer` plans, and every run it forecasts is one signing round.
#[test]
fn the_estimate_previews_signer_sized_runs() {
    for scenario in MIGRATION_SCENARIOS {
        let estimate = estimate_for_signer(scenario.source_notes, RunSigningCapacity::KEYSTONE);
        let plan = plan_for_signer(scenario.source_notes, RunSigningCapacity::KEYSTONE);

        let first = estimate
            .runs()
            .first()
            .expect("a fundable wallet has a run");
        assert_eq!(
            (first.crossings(), first.prep_transactions()),
            (plan.transfer_tx_count(), plan.preparation_tx_count()),
            "{}: the preview describes the run that gets planned",
            scenario.label,
        );
        for (i, run) in estimate.runs().iter().enumerate() {
            assert_eq!(
                run.signing_rounds(SigningRoundBudget::KEYSTONE),
                1,
                "{}: run {i} is one signing round",
                scenario.label,
            );
        }
        assert_eq!(
            estimate.total_signing_rounds(SigningRoundBudget::KEYSTONE),
            estimate.run_count(),
            "{}: the whole migration is one round per run",
            scenario.label,
        );
    }
}

proptest! {
    // Over arbitrary wallet shapes and signer capacities: a sized run never exceeds the note
    // ceiling, and it stays within the signer's rounds unless a ONE-note run already exceeds them
    // (a wallet so fragmented that minting a single funding note takes more consolidation than a
    // round holds, which no smaller run can fix).
    #![proptest_config(ProptestConfig::with_cases(24))]
    #[test]
    fn a_sized_run_fits_its_signer_or_cannot_be_shrunk(
        shape in prop::sample::select(WalletShape::ALL),
        note_count in 1usize..40,
        capacity in arb_run_signing_capacity(),
        seed in any::<u64>(),
    ) {
        let notes = generate_notes(shape, note_count, &mut ChaCha8Rng::seed_from_u64(seed));
        let backend = MockBackend::new(notes.clone(), TIP);
        let mut rng = ChaCha8Rng::seed_from_u64(SEED);
        let Ok(plan) = plan_migration_for_signer(
            capacity,
            &regtest_network(true),
            &backend,
            &mut rng,
        ) else {
            // Nothing to migrate from this wallet; the sizing has nothing to say about it.
            return Ok(());
        };

        prop_assert!(
            plan.transfer_tx_count() <= capacity.max_notes().get(),
            "{}: the sizing never exceeds the note ceiling",
            shape.label(),
        );
        prop_assert!(
            plan.transfer_tx_count() <= MIGRATION_MAX_PREPARED_NOTES_PER_RUN.get(),
            "{}: and never exceeds the crate's default ceiling",
            shape.label(),
        );
        let rounds = plan.signing_round_count(capacity.budget());
        prop_assert!(
            rounds <= capacity.max_rounds().get() || plan.transfer_tx_count() == 1,
            "{}: {rounds} rounds over {} crossings and {} preparations",
            shape.label(),
            plan.transfer_tx_count(),
            plan.preparation_tx_count(),
        );
    }
}
