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

use orchard::keys::SpendAuthorizingKey;
use rand_chacha::ChaCha8Rng;
use rand_core::SeedableRng;
use zcash_protocol::consensus::BlockHeight;
use zcash_protocol::value::COIN;

use zcash_pool_migration::build::sign_pczt;
use zcash_pool_migration::engine::{
    MigrationPlan, MigrationTxState, PoolMigrationWrite, build_preparation_unsigned,
    estimate_migration_runs, plan_migration,
};
use zcash_pool_migration::signing_rounds::{MinRounds, NextFit, SigningRoundBudget};
use zcash_pool_migration_memory::{CommitMock, TARGET_HEIGHT, regtest_network, spending_key};

/// Plan a migration for a wallet holding notes of the given `values` (in ZEC).
fn plan_for(seed: u64, values_zec: &[u64]) -> (CommitMock, MigrationPlan) {
    let notes: Vec<u64> = values_zec.iter().map(|v| v * COIN).collect();
    let backend = CommitMock::new(seed, &notes);
    let mut rng = ChaCha8Rng::seed_from_u64(seed);
    let plan = plan_migration(&regtest_network(true), &backend, &mut rng)
        .expect("a fundable balance plans");
    (backend, plan)
}

/// Sign one round's unsigned PCZTs on the "device" and apply the signatures back, exactly as a
/// wallet does with the bytes a Keystone returns.
fn sign_round_and_apply(
    seed: u64,
    state: &mut zcash_pool_migration::engine::MigrationState,
    round: Vec<zcash_pool_migration::engine::UnsignedMigrationTx>,
) {
    let ask = SpendAuthorizingKey::from(&spending_key(seed));
    for unsigned_tx in round {
        // The wallet keeps the id to match the signed PCZT back; the bytes go to the device.
        let (id, bytes) = unsigned_tx.into_parts();
        let signed = sign_pczt(
            pczt::Pczt::parse(&bytes).expect("the unsigned PCZT parses"),
            &ask,
        )
        .expect("the device signs the transaction");
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

    // 5. Sign each round on the device and apply the signatures.
    for round in rounds {
        // Each round honours the signer's 96-action budget.
        assert!(round.iter().map(|u| u.actions()).sum::<usize>() <= budget.max_actions() as usize);
        sign_round_and_apply(seed, &mut state, round);
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
