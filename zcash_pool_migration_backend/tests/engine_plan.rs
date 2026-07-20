//! Integration tests for the migration planner and store, driven by the in-memory `MockBackend`
//! from the `zcash_pool_migration_memory` test-support crate.
//!
//! These are integration tests rather than `#[cfg(test)]` unit tests because the mock implements the
//! engine's traits from `zcash_pool_migration_backend`. A dev-dependency cycle cannot be consumed by
//! the backend's own unit tests: the unit-test build recompiles the library as a distinct instance,
//! so the mock's trait impls (built against the plain library) would not satisfy the trait as seen
//! inside the test binary. An integration test links the same library instance the mock was built
//! against, so the types unify.

use rand_chacha::ChaCha8Rng;
use rand_core::SeedableRng;
use zcash_protocol::consensus::BlockHeight;
use zcash_protocol::value::{COIN, Zatoshis};

use zcash_pool_migration_backend::engine::{
    MigrationBackend, MigrationError, MigrationState, MigrationStatus, MigrationTransaction,
    MigrationTxId, MigrationTxKind, MigrationTxState, PoolMigrationRead, PoolMigrationWrite,
    plan_migration,
};
use zcash_pool_migration_backend::note_splitting::{NoteSplitPlan, plan_note_split};
use zcash_pool_migration_backend::preparation::{
    FUNDING_OUTPUTS_PER_TX, PreparationPlan, plan_preparation,
};
use zcash_pool_migration_memory::{MockBackend, regtest_network};

/// Wrap a raw zatoshi amount as [`Zatoshis`] for the tests.
fn zat(n: u64) -> Zatoshis {
    Zatoshis::from_u64(n).expect("valid amount")
}

/// A count-only preparation-layout stub for the reconciliation baseline: one padded transaction per
/// [`FUNDING_OUTPUTS_PER_TX`] funding notes, always fundable (never returns `None`).
fn prep_tx_count_stub(notes: &[Zatoshis]) -> Option<usize> {
    Some(notes.len().div_ceil(FUNDING_OUTPUTS_PER_TX))
}

#[test]
fn plans_a_migration_from_a_balance() {
    let backend = MockBackend::new(vec![100 * COIN, 40 * COIN], 2_000_000);
    let mut rng = ChaCha8Rng::seed_from_u64(1);
    let plan = plan_migration(&regtest_network(true), &backend, &mut rng)
        .expect("a fundable balance plans");

    // Something is migrated; the schedule has one entry per funding note; the preparation mints
    // exactly the (reconciled) funding notes; and reconciliation only ever drops, never adds.
    assert!(!plan.funding_notes().is_empty());
    assert_eq!(plan.schedule().len(), plan.funding_notes().len());
    assert_eq!(
        plan.preparation().funding_notes().len(),
        plan.funding_notes().len()
    );
    assert!(plan.funding_notes().len() <= plan.note_split().migration_outputs().len());
}

#[test]
fn empty_balance_has_nothing_to_migrate() {
    let backend = MockBackend::new(Vec::new(), 2_000_000);
    let mut rng = ChaCha8Rng::seed_from_u64(1);
    assert!(matches!(
        plan_migration(&regtest_network(true), &backend, &mut rng),
        Err(MigrationError::NothingToMigrate)
    ));
}

/// Reconciliation on a many-equal-note source (the "exchange" wallet shape). Ten identical 5-ZEC
/// notes (50 ZEC) decompose into `[20, 20, 5, 2, 2, 0.5, ...]`, but equal source notes cannot fund
/// that whole split: each funding note is its crossing plus a transfer buffer and costs a
/// preparation fee, so a lone 5-ZEC note cannot even self-fund a 5-ZEC crossing. The split
/// consults the preparation planner against the source notes at every step, so it reconciles
/// inline, dropping the smallest funding notes (smallest first) and leaving those denominations
/// in the source pool as residual. We reconstruct the UNCONSTRAINED split (the same strategy with
/// an always-fundable preparation stub) as the baseline the source-constrained split is measured
/// against, and pin the documented behavior end to end: the source constraint actually drops for
/// this shape, drops only from the bottom, never invents a denomination, never creates value, and
/// yields a preparation that is fundable from the source notes.
#[test]
fn reconciliation_drops_the_unfundable_tail_for_a_many_equal_note_source() {
    let balance = 50 * COIN;
    let backend = MockBackend::new(vec![5 * COIN; 10], 2_000_000); // ten equal 5-ZEC notes
    let mut rng = ChaCha8Rng::seed_from_u64(1);
    let plan = plan_migration(&regtest_network(true), &backend, &mut rng)
        .expect("a fundable balance plans");

    let kept = plan.funding_notes();

    // The baseline: the same split with an always-fundable preparation stub, i.e. what the strategy
    // proposes for this balance absent the equal-note source's fundability constraint. Recover the
    // exact fees `plan_migration` used from the produced note split so the baseline matches.
    let transfer_buffer = plan.note_split().note_fee_buffer();
    let prep_tx_fee = plan.note_split().prep_fees();
    let mut ref_rng = ChaCha8Rng::seed_from_u64(1);
    let proposed = plan_note_split(
        zat(balance),
        transfer_buffer,
        prep_tx_fee,
        &prep_tx_count_stub,
        &mut ref_rng,
    )
    .migration_outputs();

    // The unconstrained split proposes more funding notes than the equal-note source can fund, so
    // the source-constrained split must drop some. This is the case this test exists to cover: the
    // general `plans_a_migration_from_a_balance` test uses a shape that happens to drop nothing.
    assert!(
        kept.len() < proposed.len(),
        "the many-equal-note source should force a drop: kept {} of {}",
        kept.len(),
        proposed.len()
    );

    // Only ever DROPS: every kept funding note is one the unconstrained split proposed (a
    // sub-multiset of it), so no denomination or value is invented. Removing the kept notes from a
    // copy of the proposed outputs leaves exactly the dropped notes.
    let mut dropped = proposed.clone();
    for &k in kept {
        let pos = dropped
            .iter()
            .position(|&v| v == k)
            .expect("every kept funding note came from the proposed outputs");
        dropped.swap_remove(pos);
    }

    // The drop is from the BOTTOM: every kept note is at least as large as every dropped one.
    let smallest_kept = kept
        .iter()
        .copied()
        .min()
        .expect("at least one note is kept");
    assert!(
        dropped.iter().all(|&d| d <= smallest_kept),
        "reconciliation must drop the smallest denominations first"
    );

    // No value is created: the reconciled funding notes never exceed the balance.
    assert!(kept.iter().map(|z| z.into_u64()).sum::<u64>() <= balance);

    // The reconciled plan is actually fundable from the source notes.
    let source = backend
        .spendable_orchard_note_values()
        .expect("the mock source notes are available");
    assert!(
        plan_preparation(&source, kept, prep_tx_fee).is_ok(),
        "the reconciled funding set must be preparable from the source notes"
    );
}

#[test]
fn stores_loads_and_updates_a_migration() {
    let mut backend = MockBackend::new(Vec::new(), 0);
    assert!(backend.get_migration().unwrap().is_none());

    // A consistent stored note split (its exact values are immaterial to the store round-trip).
    let note_split = NoteSplitPlan::from_stored_parts(
        vec![zat(100 * COIN)],
        zat(10_000),
        None,
        zat(1_000),
        zat(100 * COIN),
        zat(100 * COIN),
    )
    .expect("a consistent stored split reconstructs");
    let tx = MigrationTransaction::from_parts(
        MigrationTxId::new(0),
        MigrationTxKind::Transfer { crossing: 0 },
        vec![1, 2, 3], // a stand-in for the serialized pre-signed PCZT
        Vec::new(),
        BlockHeight::from_u32(2_000_100),
        BlockHeight::from_u32(2_069_220),
        None,
        MigrationTxState::Signed,
    );
    let state = MigrationState::from_parts(
        MigrationStatus::Committed,
        note_split,
        Vec::new(),
        PreparationPlan::from_parts(Vec::new(), Vec::new()),
        vec![tx],
    );
    backend.replace_migration(&state).unwrap();

    // The stored transactions round-trip, and a state update persists.
    let loaded = backend
        .get_migration()
        .unwrap()
        .expect("a migration is stored");
    assert_eq!(loaded.status(), MigrationStatus::Committed);
    assert_eq!(loaded.transactions(), state.transactions());

    backend
        .update_transaction(
            MigrationTxId::new(0),
            MigrationTxState::Mined {
                height: BlockHeight::from_u32(2_000_105),
            },
        )
        .unwrap();
    let loaded = backend.get_migration().unwrap().unwrap();
    assert_eq!(
        loaded.transactions()[0].state(),
        MigrationTxState::Mined {
            height: BlockHeight::from_u32(2_000_105)
        }
    );
}
