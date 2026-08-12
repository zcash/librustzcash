//! The per-run note cap as an EXTERNAL crate sees it: the one denomination knob a wallet may set.
//!
//! A wallet chooses how many notes one migration run prepares; it does NOT choose the denomination
//! scheme. The `{1, 2, 5} * 10^k` set and its `DENOM_CAP` / `MAX_RESIDUAL_VALUE` bounds are
//! normative ZIP 318 values, and the privacy argument rests on every wallet publishing values from
//! that same set. These tests exercise the wallet-facing API from outside the crate, so they see
//! exactly the surface an SDK sees, and they pin both halves of that: the cap MOVES the run's size,
//! and it CANNOT move the scheme or its bounds.
//!
//! [ZIP 318]: https://zips.z.cash/zip-0318
#![cfg(feature = "test-dependencies")]

use proptest::prelude::*;
use rand_chacha::ChaCha8Rng;
use rand_core::SeedableRng;
use zcash_protocol::{
    value::{COIN, Zatoshis},
    zip318::{DENOM_CAP, MAX_RESIDUAL_VALUE, is_canonical_denomination},
};

use zcash_pool_migration::{
    denomination::MIGRATION_MAX_PREPARED_NOTES_PER_RUN,
    engine::{
        MigrationPlan, MigrationRunEstimate, estimate_migration_runs, estimate_migration_runs_with,
        plan_migration, plan_migration_with,
    },
    preparation::default_portfolio,
    testing::{MIGRATION_SCENARIOS, MigrationScenario},
};
use zcash_pool_migration_memory::{MockBackend, regtest_network};

/// A post-NU6.3 chain tip to plan against.
const TIP: u32 = 2_000_000;
/// Any fixed seed: the canonical decomposition does not consult the RNG, and both sides of every
/// comparison below use this same seed so the schedules match too.
const SEED: u64 = 7;

/// A note cap, from a plain count. The caps under test are all small positive literals.
fn cap(n: usize) -> core::num::NonZeroUsize {
    core::num::NonZeroUsize::new(n).expect("the caps under test are positive")
}

/// Plan one run for `scenario`'s wallet under `max_notes`, with the crate's default preparation
/// strategies (so the cap is the only thing that varies across a comparison).
fn plan_at(scenario: &MigrationScenario, max_notes: usize) -> MigrationPlan {
    let backend = MockBackend::new(scenario.source_notes.to_vec(), TIP);
    let mut rng = ChaCha8Rng::seed_from_u64(SEED);
    plan_migration_with(
        &default_portfolio(),
        cap(max_notes),
        &regtest_network(true),
        &backend,
        &mut rng,
    )
    .unwrap_or_else(|e| panic!("{}: cap {max_notes} should plan, got {e}", scenario.label))
}

/// Estimate the whole migration of `notes` under `max_notes`, with the default strategies.
fn estimate_at(notes: &[u64], max_notes: usize) -> MigrationRunEstimate {
    let backend = MockBackend::new(notes.to_vec(), TIP);
    let mut rng = ChaCha8Rng::seed_from_u64(SEED);
    estimate_migration_runs_with(
        &default_portfolio(),
        cap(max_notes),
        &regtest_network(true),
        &backend,
        &mut rng,
    )
    .expect("a fundable balance estimates")
}

/// The scenarios with enough crossings to compare three distinct caps (one, one short of the full
/// split, and the full split).
fn multi_crossing_scenarios() -> impl Iterator<Item = &'static MigrationScenario> {
    MIGRATION_SCENARIOS
        .iter()
        .filter(|sc| sc.expected_transfers >= 3)
}

/// Raising the cap migrates MORE and leaves LESS behind; lowering it migrates less and leaves more.
/// Checked as the full monotone chain over every cap from one up to the scenario's own crossing
/// count: crossings are non-decreasing in the cap, the residual is non-increasing, and the two ends
/// differ strictly. That is the whole user-visible effect of the knob — a bigger run, not different
/// values.
#[test]
fn raising_the_cap_migrates_more_and_lowering_it_migrates_less() {
    for sc in multi_crossing_scenarios() {
        let full = sc.expected_transfers;
        let plans: Vec<MigrationPlan> = (1..=full).map(|c| plan_at(sc, c)).collect();

        for (lower, higher) in plans.iter().zip(plans.iter().skip(1)) {
            assert!(
                lower.transfer_tx_count() <= higher.transfer_tx_count(),
                "{}: crossings must not shrink as the cap grows",
                sc.label
            );
            assert!(
                lower.residual() >= higher.residual(),
                "{}: the residual must not grow as the cap grows",
                sc.label
            );
        }

        let (lowest, highest) = (&plans[0], &plans[full - 1]);
        assert!(
            highest.transfer_tx_count() > lowest.transfer_tx_count(),
            "{}: the raised cap should cross more, got {} at cap {full} vs {} at cap 1",
            sc.label,
            highest.transfer_tx_count(),
            lowest.transfer_tx_count()
        );
        assert!(
            highest.residual() < lowest.residual(),
            "{}: the raised cap should leave a smaller residual, got {:?} vs {:?}",
            sc.label,
            highest.residual(),
            lowest.residual()
        );
        // The cap is a cap, not a target: at the scenario's own crossing count it reproduces the
        // default plan exactly.
        assert_eq!(
            highest.transfer_tx_count(),
            sc.expected_transfers,
            "{}: the full cap reproduces the default split",
            sc.label
        );
    }
}

/// The preview and the plan describe the SAME run under a custom cap: passed the same knobs, the
/// estimate's first run is exactly what `plan_migration_with` plans (same crossings, same
/// preparation transactions, same migrated value). This is the claim both `_with` docs make, and it
/// is what breaks if an application passes its cap to only one of them.
#[test]
fn the_estimate_previews_the_run_the_plan_builds_under_a_custom_cap() {
    /// A cap well below every scenario's crossing count, so it actually binds.
    const CUSTOM_CAP: usize = 2;

    for sc in multi_crossing_scenarios() {
        let plan = plan_at(sc, CUSTOM_CAP);
        let est = estimate_at(sc.source_notes, CUSTOM_CAP);
        let first = est.runs().first().expect("a fundable balance has a run");

        assert_eq!(
            first.crossings(),
            plan.transfer_tx_count(),
            "{}: previewed crossings",
            sc.label
        );
        assert_eq!(
            first.prep_transactions(),
            plan.preparation_tx_count(),
            "{}: previewed preparation transactions",
            sc.label
        );
        assert_eq!(
            first.migratable(),
            plan.value_migrated(),
            "{}: previewed migrated value",
            sc.label
        );
    }
}

/// A capped run is a smaller bite, so the whole migration takes more of them: a whale that the
/// default cap clears in a few runs needs strictly more under a tighter cap, and every run honours
/// the cap it was given. (The two do NOT migrate the same total: more runs pay more per-run
/// preparation and transfer fees, so a tighter cap migrates slightly less value overall.)
#[test]
fn a_tighter_cap_takes_more_runs_to_migrate_the_same_whale() {
    /// A balance well beyond one default run's capacity (50 notes of at most 10,000 ZEC).
    const WHALE: u64 = 1_200_000 * COIN;
    /// A cap far below the default, so each run is a much smaller bite.
    const TIGHT_CAP: usize = 5;

    let whale = [WHALE];
    let default = estimate_at(&whale, MIGRATION_MAX_PREPARED_NOTES_PER_RUN.get());
    let tight = estimate_at(&whale, TIGHT_CAP);

    assert!(
        tight.run_count() > default.run_count(),
        "a tighter cap should take more runs, got {} vs {}",
        tight.run_count(),
        default.run_count()
    );
    assert!(
        tight.runs().iter().all(|r| r.crossings() <= TIGHT_CAP),
        "every run must honour the cap it was given"
    );
    assert_eq!(
        default.runs()[0].crossings(),
        MIGRATION_MAX_PREPARED_NOTES_PER_RUN.get(),
        "the default run fills the default cap for a whale"
    );
}

/// A scenario index and a note cap: the input shape of the law that the cap cannot move the scheme.
fn arb_scenario_and_cap() -> impl Strategy<Value = (usize, usize)> {
    /// The largest cap sampled. Above the biggest scenario's crossing count, so the sampled range
    /// spans both the binding and the non-binding regime.
    const MAX_SAMPLED_CAP: usize = 16;

    (0..MIGRATION_SCENARIOS.len(), 1usize..=MAX_SAMPLED_CAP)
}

proptest! {
    /// THE key law: the one knob a wallet may set moves how MANY notes a run prepares and nothing
    /// else. For any wallet and any cap, the run publishes at most `max_notes` crossings, and every
    /// crossing is still a canonical ZIP 318 denomination — on the `{1, 2, 5} * 10^k` series and
    /// within `[MAX_RESIDUAL_VALUE, DENOM_CAP]`, which is exactly what
    /// `is_canonical_denomination` decides. No cap can push a value out of the set every other
    /// wallet publishes from, which is where the anonymity set lives.
    #[test]
    fn the_cap_bounds_the_count_and_never_moves_the_scheme(
        (index, max_notes) in arb_scenario_and_cap(),
    ) {
        let sc = &MIGRATION_SCENARIOS[index];
        let backend = MockBackend::new(sc.source_notes.to_vec(), TIP);
        let mut rng = ChaCha8Rng::seed_from_u64(SEED);
        let planned = plan_migration_with(
            &default_portfolio(),
            cap(max_notes),
            &regtest_network(true),
            &backend,
            &mut rng,
        );
        // A cap too small for this wallet's notes to fund anything is a legitimate empty outcome,
        // not a violation: the law below constrains what a run PUBLISHES.
        let Ok(plan) = planned else { return Ok(()) };

        let crossings = plan.denominations().crossing_values();
        prop_assert!(
            crossings.len() <= max_notes,
            "{}: {} crossings exceed the cap {}",
            sc.label,
            crossings.len(),
            max_notes
        );
        for &crossing in crossings {
            prop_assert!(
                is_canonical_denomination(crossing),
                "{}: {} is not a canonical ZIP 318 denomination",
                sc.label,
                u64::from(crossing)
            );
            prop_assert!(
                crossing >= MAX_RESIDUAL_VALUE && crossing <= DENOM_CAP,
                "{}: {} is outside the ZIP 318 bounds",
                sc.label,
                u64::from(crossing)
            );
        }
    }
}

/// The default path is unchanged: `plan_migration` still plans exactly what the crate's defaults
/// plan — the default portfolio at `MIGRATION_MAX_PREPARED_NOTES_PER_RUN` — and still reproduces
/// every shared scenario's pinned shape. The Android SDK calls this signature, so it is
/// load-bearing that adding the knob did not move it.
#[test]
fn the_default_path_is_unchanged() {
    for sc in MIGRATION_SCENARIOS {
        let backend = MockBackend::new(sc.source_notes.to_vec(), TIP);
        let mut rng = ChaCha8Rng::seed_from_u64(SEED);
        let plan = plan_migration(&regtest_network(true), &backend, &mut rng)
            .unwrap_or_else(|e| panic!("{}: should plan, got {e}", sc.label));

        let explicit = plan_at(sc, MIGRATION_MAX_PREPARED_NOTES_PER_RUN.get());
        assert_eq!(
            plan.denominations(),
            explicit.denominations(),
            "{}: the default path must equal the explicit defaults",
            sc.label
        );
        assert_eq!(
            plan.funding_notes(),
            explicit.funding_notes(),
            "{}: funding notes",
            sc.label
        );

        // And the scenario's own pinned shape still holds.
        assert_eq!(
            plan.preparation_tx_count(),
            sc.expected_preparations,
            "{}: preparations",
            sc.label
        );
        assert_eq!(
            plan.transfer_tx_count(),
            sc.expected_transfers,
            "{}: crossings",
            sc.label
        );
        assert_eq!(
            plan.value_migrated(),
            Zatoshis::const_from_u64(sc.expected_migrated),
            "{}: migrated value",
            sc.label
        );
    }
}

/// `estimate_migration_runs` likewise still previews the defaults: the same estimate as
/// `estimate_migration_runs_with` given the default portfolio and note cap.
#[test]
fn the_default_estimate_is_unchanged() {
    for sc in MIGRATION_SCENARIOS {
        let backend = MockBackend::new(sc.source_notes.to_vec(), TIP);
        let mut rng = ChaCha8Rng::seed_from_u64(SEED);
        let est = estimate_migration_runs(&regtest_network(true), &backend, &mut rng)
            .expect("a fundable balance estimates");
        let explicit = estimate_at(sc.source_notes, MIGRATION_MAX_PREPARED_NOTES_PER_RUN.get());

        assert_eq!(est.run_count(), explicit.run_count(), "{}: runs", sc.label);
        assert_eq!(
            est.total_crossings(),
            explicit.total_crossings(),
            "{}: crossings",
            sc.label
        );
        assert_eq!(
            est.final_residual(),
            explicit.final_residual(),
            "{}: residual",
            sc.label
        );
    }
}
