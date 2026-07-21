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
    MigrationError, MigrationState, MigrationStatus, MigrationTransaction, MigrationTxId,
    MigrationTxKind, MigrationTxState, PoolMigrationRead, PoolMigrationWrite, plan_migration,
};
use zcash_pool_migration_backend::note_splitting::NoteSplitPlan;
use zcash_pool_migration_backend::preparation::PreparationPlan;
use zcash_pool_migration_memory::{MockBackend, regtest_network};

/// Wrap a raw zatoshi amount as [`Zatoshis`] for the tests.
fn zat(n: u64) -> Zatoshis {
    Zatoshis::from_u64(n).expect("valid amount")
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
    backend.put_migration(&state).unwrap();

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
