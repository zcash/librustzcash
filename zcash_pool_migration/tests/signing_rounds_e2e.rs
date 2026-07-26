//! End-to-end USAGE examples for the signing-round interface.
//!
//! These read as a tutorial for the public API a wallet (for example a mobile app driving a Keystone
//! hardware wallet) uses to migrate funds between pools while respecting the signer's per-interaction
//! action budget. Each test walks the real flow against the in-memory `CommitMock` crypto backend
//! from the `zcash_pool_migration_memory` test-support crate.
//!
//! The flow a wallet follows:
//!   1. `plan_migration` (unchanged: the wallet does NOT pass a signer budget here).
//!   2. `plan.signing_rounds(budget)` to PREVIEW, for the user's signer, how many interactions the
//!      migration needs and what each one contains (the consent screen).
//!   3. `build_preparation_unsigned` to build every transaction unsigned, in one pass.
//!   4. `plan.group_unsigned(unsigned, budget)` to split them into the SAME rounds the preview
//!      showed.
//!   5. sign each round on the device and `state.apply_signature` the result back.
//!
//! The budget is the ONLY signer-specific input, and it is a query parameter: the same plan is
//! evaluated for any signer without re-planning.

#![cfg(feature = "orchard")]

use core::num::NonZeroU32;

use rand_chacha::ChaCha8Rng;
use rand_core::SeedableRng;
use zcash_protocol::consensus::BlockHeight;
use zcash_protocol::value::COIN;

#[cfg(feature = "test-dependencies")]
use zcash_pool_migration::denomination::MIGRATION_MAX_PREPARED_NOTES_PER_RUN;
use zcash_pool_migration::engine::{
    MigrationCrypto, MigrationPlan, MigrationState, MigrationTxState, PoolMigrationWrite,
    UnsignedMigrationTx, build_preparation_unsigned, estimate_migration_runs, plan_migration,
};
use zcash_pool_migration::signing_rounds::{MinRounds, NextFit, SigningRoundBudget};
#[cfg(feature = "test-dependencies")]
use zcash_pool_migration::testing::MIGRATION_SCENARIOS;
use zcash_pool_migration_memory::{CommitMock, TARGET_HEIGHT, regtest_network};

/// Plan a migration for a wallet holding the given raw note values (in zatoshi).
fn plan_notes(seed: u64, notes: &[u64]) -> (CommitMock, MigrationPlan) {
    let backend = CommitMock::new(seed, notes);
    let mut rng = ChaCha8Rng::seed_from_u64(seed);
    let plan = plan_migration(&regtest_network(true), &backend, &mut rng)
        .expect("a fundable balance plans");
    (backend, plan)
}

/// Plan a migration for a wallet holding notes of the given `values` (in ZEC).
fn plan_for(seed: u64, values_zec: &[u64]) -> (CommitMock, MigrationPlan) {
    let notes: Vec<u64> = values_zec.iter().map(|v| v * COIN).collect();
    plan_notes(seed, &notes)
}

/// Sign one round's unsigned PCZTs with the wallet's signer and apply the signatures back. The
/// `signer` is anything implementing [`MigrationCrypto`] — the trait a wallet plugs its Orchard
/// spend authority into (here the `CommitMock` backend; a real wallet passes its own implementation,
/// or routes the bytes to a hardware device that returns the signed PCZT).
fn sign_round_and_apply<C>(signer: &C, state: &mut MigrationState, round: Vec<UnsignedMigrationTx>)
where
    C: MigrationCrypto,
    C::Error: std::fmt::Debug,
{
    for unsigned_tx in round {
        // The wallet keeps the id to match the signed PCZT back; the bytes go to the signer.
        let (id, bytes) = unsigned_tx.into_parts();
        let unsigned = pczt::Pczt::parse(&bytes).expect("the unsigned PCZT parses");
        let signed = signer
            .sign(unsigned)
            .expect("the signer authorizes the transaction");
        assert!(state.apply_signature(id, signed.serialize().expect("serializes the signed PCZT")));
    }
}

/// FULL FLOW with a Keystone (a 96-action-per-round signer): plan, preview the rounds, build,
/// group into those rounds, sign each round, apply. The migration is fully signed at the end,
/// having respected the 96-action budget on every interaction.
#[test]
fn keystone_external_signing_end_to_end() {
    // A migration large enough to need several Keystone interactions (25 pool crossings plus its
    // preparation is ~107 Orchard actions, more than one 96-action round).
    let seed = 101;
    let (mut backend, plan) = plan_for(seed, &[250_000]);
    let params = regtest_network(true);

    // The wallet's signer is a Keystone: 96 total Orchard actions per interaction.
    let budget = SigningRoundBudget::KEYSTONE;

    // 2. PREVIEW: how many signer interactions, and what each contains. A consent screen renders
    //    this before anything is built or signed.
    let preview = plan.signing_rounds(budget);
    assert_eq!(preview.len(), plan.signing_round_count(budget));
    assert!(
        preview.len() > 1,
        "this migration needs several Keystone rounds"
    );
    for round in &preview {
        // Never more than the budget, and the wallet can show the mix and how full the round is.
        assert!(round.total_actions() <= budget.max_actions());
        assert_eq!(
            round.preparation_count() + round.transfer_count(),
            round.len()
        );
        assert!(round.fill_fraction(budget) <= 1.0);
    }
    // The whole plan's headline numbers a wallet displays.
    assert_eq!(
        plan.total_transactions(),
        plan.preparation_tx_count() + plan.transfer_tx_count()
    );
    assert!(u64::from(plan.value_migrated()) > 0);

    // 3. Build every transaction unsigned, in one pass.
    let mut rng = ChaCha8Rng::seed_from_u64(seed + 1);
    let (mut state, unsigned) = build_preparation_unsigned(
        &params,
        BlockHeight::from_u32(TARGET_HEIGHT),
        &mut backend,
        &plan,
        &mut rng,
    )
    .expect("builds the migration unsigned");
    assert_eq!(unsigned.len(), plan.total_transactions());

    // 4. Group into the SAME rounds the preview showed (matched back by transaction id).
    let rounds = plan.group_unsigned(unsigned, budget);
    assert_eq!(
        rounds.len(),
        preview.len(),
        "signing matches the preview exactly"
    );

    // 5. Sign each round with the wallet's signer (its `MigrationCrypto` impl) and apply the
    //    signatures. A hardware wallet routes each round's bytes to the device instead.
    for round in rounds {
        // Each round honours the signer's 96-action budget.
        assert!(round.iter().map(|u| u.actions()).sum::<usize>() <= budget.max_actions() as usize);
        sign_round_and_apply(&backend, &mut state, round);
    }

    // The whole migration is signed, without anything having been broadcast or mined.
    backend
        .replace_migration(&state)
        .expect("persists the signed migration");
    for tx in state.transactions() {
        assert_eq!(tx.state(), MigrationTxState::Signed);
    }
}

/// A software / in-process signer has no tight per-round limit, so the default budget signs a whole
/// run in a single interaction.
#[test]
fn software_signer_signs_a_run_in_one_round() {
    let (_backend, plan) = plan_for(202, &[78]);

    // No signer-specific cap: use the default budget.
    let rounds = plan.signing_rounds(SigningRoundBudget::DEFAULT);
    assert_eq!(rounds.len(), 1, "a whole run fits one default-budget round");
    assert_eq!(rounds[0].len(), plan.total_transactions());
    assert!(rounds[0].total_actions() <= SigningRoundBudget::DEFAULT.max_actions());
}

/// PREVIEW-ONLY interface: estimate the signer interactions for any budget, and answer the inverse
/// "what budget signs this in a single round" question, WITHOUT building or signing anything. This
/// is what a wallet calls to help the user pick or understand their signer.
#[test]
fn preview_signer_interactions_without_building() {
    let seed = 303;
    let backend = CommitMock::new(seed, &[78 * COIN]);
    let mut rng = ChaCha8Rng::seed_from_u64(seed);

    // Whole-migration estimate (a large balance spans several runs); ask it for a signer budget.
    let est = estimate_migration_runs(&regtest_network(true), &backend, &mut rng)
        .expect("estimates the migration");
    let with_keystone = est.total_signing_rounds(SigningRoundBudget::KEYSTONE);
    let with_software = est.total_signing_rounds(SigningRoundBudget::DEFAULT);
    assert!(est.run_count() >= 1);
    assert!(
        with_keystone >= with_software,
        "a tighter signer never needs fewer interactions"
    );

    // The signing WORKLOAD: the total Orchard actions the user must sign across the whole migration.
    // A wallet multiplies this by the device's per-action time to show a signing-time estimate; it is
    // independent of the signer's per-round budget (that only splits the work into interactions). It
    // is the sum of the per-run workloads.
    let actions_to_sign = est.total_actions();
    assert!(actions_to_sign > 0);
    let summed_per_run: u32 = est.runs().iter().map(|r| r.actions()).sum();
    assert_eq!(actions_to_sign, summed_per_run);

    // For a single planned run, the inverse query: the smallest budget that signs it in one round.
    let (_backend, plan) = plan_for(seed, &[78]);
    let need = plan.min_budget_for_single_round();
    assert_eq!(
        plan.signing_round_count(SigningRoundBudget::new(need)),
        1,
        "a signer supporting `need` actions per round does this run in one interaction"
    );
    // One action less needs more than one round (unless the run is already a single transaction).
    if need.get() > SigningRoundBudget::minimum_feasible().get() && plan.total_transactions() > 1 {
        let smaller = SigningRoundBudget::new(NonZeroU32::new(need.get() - 1).unwrap());
        assert!(plan.signing_round_count(smaller) >= 1);
    }
}

/// Choosing a packing STRATEGY: `MinRounds` (the default, fewest interactions) is never worse than
/// the order-preserving `NextFit`, and either can be selected explicitly.
#[test]
fn choosing_a_packing_strategy() {
    let (_backend, plan) = plan_for(404, &[250_000]);
    let budget = SigningRoundBudget::KEYSTONE;

    let optimal = plan.signing_rounds_with(&MinRounds, budget);
    let greedy = plan.signing_rounds_with(&NextFit, budget);

    // The default `signing_rounds` uses `MinRounds`.
    assert_eq!(optimal.len(), plan.signing_rounds(budget).len());
    assert!(
        optimal.len() <= greedy.len(),
        "MinRounds never needs more interactions than NextFit"
    );
    // Both are valid: every round is within the budget.
    for round in optimal.iter().chain(greedy.iter()) {
        assert!(round.total_actions() <= budget.max_actions());
    }
}
/// GOLDEN VECTORS keyed on the USER'S WALLET BALANCE, reusing the shared `MIGRATION_SCENARIOS` (the
/// SAME scenarios the real-proving `prove_chain_sim` test drives). For each wallet, plan the
/// migration and assert the FEE-AWARE shape: the number of quanta (crossings), the preparation
/// transactions, and the migrated value all match the scenario, and the signing rounds for a
/// Keystone and a default signer follow from those counts. Enforces the invariant that a migration
/// always migrates every funding note it prepares (transfers == funding notes, never zero). Gated on
/// `test-dependencies`, which exposes the reusable fixtures.
#[cfg(feature = "test-dependencies")]
#[test]
fn migration_scenarios_end_to_end() {
    // Any fixed seed works: the canonical strategy is RNG-independent, so the plan shape (quanta,
    // preparations, migrated value, rounds) does not depend on this value.
    let seed = 7;

    for sc in MIGRATION_SCENARIOS {
        let (_backend, plan) = plan_notes(seed, sc.source_notes);

        // The starting point is the balance; the planner quantizes it into crossings AFTER reserving
        // the transfer buffers and preparation fees.
        assert_eq!(
            plan.transfer_tx_count(),
            sc.expected_transfers,
            "{}: quanta (crossings)",
            sc.label
        );
        assert_eq!(
            plan.preparation_tx_count(),
            sc.expected_preparations,
            "{}: preparation transactions",
            sc.label
        );
        assert_eq!(
            u64::from(plan.value_migrated()),
            sc.expected_migrated,
            "{}: migrated value (balance less reserved fees)",
            sc.label
        );

        // Invariant: a migration always migrates something, and every prepared funding note is
        // migrated (transfers == funding notes, never zero).
        assert!(
            plan.transfer_tx_count() >= 1,
            "{}: a migration must migrate at least one output",
            sc.label
        );
        assert_eq!(
            plan.transfer_tx_count(),
            plan.funding_notes().len(),
            "{}: every funding note the preparation creates is migrated",
            sc.label
        );

        // Every scenario's quanta fit one run (within the per-run note cap).
        assert!(
            sc.expected_transfers <= MIGRATION_MAX_PREPARED_NOTES_PER_RUN,
            "{}: quanta fit one run",
            sc.label
        );

        // The EXACT number of Keystone (96-action) signing rounds this run takes: the countable
        // golden value from the scenario. The whole run fits one default-budget round.
        assert_eq!(
            plan.signing_round_count(SigningRoundBudget::KEYSTONE),
            sc.expected_keystone_rounds,
            "{}: Keystone signing rounds",
            sc.label
        );
        assert_eq!(
            plan.signing_round_count(SigningRoundBudget::DEFAULT),
            1,
            "{}: one default-budget round",
            sc.label
        );
    }
}

/// The quanta -> RUNS -> total-rounds evolution: a balance beyond one run's note cap migrates over
/// several runs (each within the cap), and the signer interactions are SUMMED per run because rounds
/// cannot span runs. Reuses the plan-only `MULTI_RUN_EVOLUTION` table to show the total Keystone
/// rounds grow with the balance (2 runs / 5 rounds, up to 11 runs / 32 rounds).
#[cfg(feature = "test-dependencies")]
#[test]
fn total_keystone_rounds_evolve_across_runs() {
    use zcash_pool_migration::testing::MULTI_RUN_EVOLUTION;

    let seed = 7;
    for case in MULTI_RUN_EVOLUTION {
        let backend = CommitMock::new(seed, &[case.balance_zec * COIN]);
        let mut rng = ChaCha8Rng::seed_from_u64(seed);
        let est = estimate_migration_runs(&regtest_network(true), &backend, &mut rng)
            .expect("estimates the whale migration");

        assert_eq!(
            est.run_count(),
            case.expected_runs,
            "{} ZEC: runs",
            case.balance_zec
        );
        assert_eq!(
            est.total_crossings(),
            case.expected_total_crossings,
            "{} ZEC: total quanta",
            case.balance_zec
        );
        // The total ACTIONS to sign across the whole migration: the signing workload the app turns
        // into a time estimate for the user.
        assert_eq!(
            est.total_actions(),
            case.expected_total_actions,
            "{} ZEC: total actions to sign",
            case.balance_zec
        );
        assert_eq!(
            est.total_signing_rounds(SigningRoundBudget::KEYSTONE),
            case.expected_total_keystone_rounds,
            "{} ZEC: total Keystone rounds",
            case.balance_zec
        );

        // Each run migrates at least one quantum, stays within the note cap, and the total is the
        // per-run sum (rounds cannot span runs).
        for run in est.runs() {
            assert!(run.crossings() >= 1);
            assert!(run.crossings() <= MIGRATION_MAX_PREPARED_NOTES_PER_RUN);
        }
        let summed: usize = est
            .runs()
            .iter()
            .map(|r| r.signing_rounds(SigningRoundBudget::KEYSTONE))
            .sum();
        assert_eq!(summed, case.expected_total_keystone_rounds);
    }

    // The total round count is non-decreasing in the balance across the table.
    for pair in MULTI_RUN_EVOLUTION.windows(2) {
        assert!(pair[0].expected_total_keystone_rounds <= pair[1].expected_total_keystone_rounds);
    }
}

/// How the Keystone (96-action) round count EVOLVES as the migration's action total grows: larger
/// balances produce more quanta and preparations, so the round count steps up each time the action
/// total crosses a multiple of 96 (1 round at 46 actions, 2 at 114-190, 3 at 221-230). Reuses the
/// plan-only `SIGNING_ROUND_EVOLUTION` table.
#[cfg(feature = "test-dependencies")]
#[test]
fn keystone_rounds_evolve_with_actions() {
    use zcash_pool_migration::testing::SIGNING_ROUND_EVOLUTION;

    let seed = 7;
    for case in SIGNING_ROUND_EVOLUTION {
        let (_backend, plan) = plan_notes(seed, &[case.balance_zec * COIN]);

        assert_eq!(
            plan.transfer_tx_count(),
            case.expected_crossings,
            "{} ZEC: crossings",
            case.balance_zec
        );
        assert_eq!(
            plan.preparation_tx_count(),
            case.expected_preparations,
            "{} ZEC: preparations",
            case.balance_zec
        );
        assert_eq!(
            plan.total_actions(),
            case.expected_actions,
            "{} ZEC: total actions",
            case.balance_zec
        );
        assert_eq!(
            plan.signing_round_count(SigningRoundBudget::KEYSTONE),
            case.expected_keystone_rounds,
            "{} ZEC: Keystone rounds",
            case.balance_zec
        );
    }

    // The round count is non-decreasing in the action total across the table.
    for pair in SIGNING_ROUND_EVOLUTION.windows(2) {
        assert!(pair[0].expected_actions <= pair[1].expected_actions);
        assert!(pair[0].expected_keystone_rounds <= pair[1].expected_keystone_rounds);
    }
}
