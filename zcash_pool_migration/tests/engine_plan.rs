//! Integration tests for the migration planner and store, driven by the in-memory `MockBackend`
//! from the `zcash_pool_migration_memory` test-support crate.
//!
//! These are integration tests rather than `#[cfg(test)]` unit tests because the mock implements the
//! engine's traits from `zcash_pool_migration`. A dev-dependency cycle cannot be consumed by
//! the backend's own unit tests: the unit-test build recompiles the library as a distinct instance,
//! so the mock's trait impls (built against the plain library) would not satisfy the trait as seen
//! inside the test binary. An integration test links the same library instance the mock was built
//! against, so the types unify.

use rand_chacha::ChaCha8Rng;
use rand_core::SeedableRng;
use zcash_protocol::TxId;
use zcash_protocol::consensus::BlockHeight;
use zcash_protocol::value::{COIN, Zatoshis};

use zcash_pool_migration::denomination::{
    DenominationPlan, MIGRATION_MAX_PREPARED_NOTES_PER_RUN, plan_denominations,
};
use zcash_pool_migration::engine::{
    MigrationBackend, MigrationError, MigrationState, MigrationStatus, MigrationTransaction,
    MigrationTransferId, MigrationTxKind, MigrationTxState, PoolMigrationRead, PoolMigrationWrite,
    plan_migration,
};
use zcash_pool_migration::preparation::{
    FUNDING_OUTPUTS_PER_TX, PreparationPlan, plan_preparation,
};
use zcash_pool_migration::satisfiability::ReplanThreshold;
use zcash_pool_migration::scheduling::AnchorBucketInterval;
#[cfg(feature = "test-dependencies")]
use zcash_pool_migration::testing::{MIGRATION_SCENARIOS, NOTE_SHAPE_SPLITS};
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
    assert!(plan.funding_notes().len() <= plan.denominations().migration_outputs().len());
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

/// The full migration pipeline (denomination planning then preparation) for the smallest migratable
/// balance: a lone source note of exactly one quantum plus its fees. A quantum is a canonical
/// `{1, 2, 5} * 10^k` denomination; its fees are the ZIP-317 transfer buffer that funds the crossing
/// note plus one padded preparation-transaction fee. Such a balance migrates that one denomination
/// as a single crossing note, minted by exactly one preparation transaction in exactly one
/// preparation layer, leaving no source-pool change.
#[test]
fn full_migration_of_one_quantum_is_one_layer_one_transaction() {
    let params = regtest_network(true);
    let tip = 2_000_000;

    // The canonical fees depend only on the network and height, not the balance. Discover them from
    // a probe migration of a lone 0.02 ZEC note, which funds exactly one 0.01 ZEC minimum-denomination
    // note in a single padded preparation transaction (so its reserved prep fee is one tx fee).
    let probe = MockBackend::new(vec![2 * (COIN / 100)], tip);
    let mut rng = ChaCha8Rng::seed_from_u64(1);
    let probe_plan = plan_migration(&params, &probe, &mut rng).expect("the probe balance plans");
    assert_eq!(probe_plan.preparation().transaction_count(), 1);
    let buffer = u64::from(probe_plan.denominations().note_fee_buffer());
    let prep_tx_fee = u64::from(probe_plan.denominations().prep_fees());

    // A few example quanta spanning the series from the 0.01 ZEC minimum to the 10,000 ZEC cap.
    let quanta = [
        COIN / 100,    // 0.01 ZEC, the minimum denomination
        COIN / 20,     // 0.05 ZEC
        COIN,          // 1 ZEC
        100 * COIN,    // 100 ZEC
        10_000 * COIN, // 10,000 ZEC, the cap
    ];
    for quantum in quanta {
        let balance = quantum + buffer + prep_tx_fee;
        let backend = MockBackend::new(vec![balance], tip);
        let mut rng = ChaCha8Rng::seed_from_u64(1);
        let plan =
            plan_migration(&params, &backend, &mut rng).expect("a one-quantum balance plans");

        // The split: one crossing of exactly the quantum, and the whole balance consumed (no change).
        assert_eq!(
            plan.denominations()
                .crossing_values()
                .iter()
                .map(|&v| u64::from(v))
                .collect::<Vec<u64>>(),
            vec![quantum],
            "quantum {quantum}",
        );
        assert_eq!(plan.denominations().change(), None, "quantum {quantum}");

        // The preparation: exactly one layer holding exactly one transaction, minting exactly the
        // single funding note (the crossing plus its transfer buffer).
        let prep = plan.preparation();
        assert_eq!(prep.layer_count(), 1, "quantum {quantum}");
        assert_eq!(prep.transaction_count(), 1, "quantum {quantum}");
        assert_eq!(prep.layers()[0].len(), 1, "quantum {quantum}");
        assert_eq!(
            plan.funding_notes()
                .iter()
                .map(|&v| u64::from(v))
                .collect::<Vec<u64>>(),
            vec![quantum + buffer],
            "quantum {quantum}",
        );

        // One funding note is one scheduled transfer.
        assert_eq!(plan.schedule().len(), 1, "quantum {quantum}");
    }
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
    let source_notes = vec![5 * COIN; 10]; // ten equal 5-ZEC notes
    let source_note_count = source_notes.len();
    let backend = MockBackend::new(source_notes, 2_000_000);
    let mut rng = ChaCha8Rng::seed_from_u64(1);
    let plan = plan_migration(&regtest_network(true), &backend, &mut rng)
        .expect("a fundable balance plans");

    let kept = plan.funding_notes();

    // The baseline: the same denominations with an always-fundable preparation stub, i.e. what the
    // strategy proposes for this balance absent the equal-note source's fundability constraint.
    // Recover the exact fees `plan_migration` used from the produced plan, and pass the same
    // per-run note cap it defaults to, so the baseline matches the plan it is compared against.
    let transfer_buffer = plan.denominations().note_fee_buffer();
    let prep_tx_fee = plan.denominations().prep_fees();
    let mut ref_rng = ChaCha8Rng::seed_from_u64(1);
    let proposed = plan_denominations(
        zat(balance),
        source_note_count,
        MIGRATION_MAX_PREPARED_NOTES_PER_RUN,
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
    for &k in &kept {
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
        plan_preparation(&source, &kept, prep_tx_fee).is_ok(),
        "the reconciled funding set must be preparable from the source notes"
    );
}

/// The wallet's NOTE SHAPE does not move the split of a fixed balance.
///
/// The crossing values are a function of the BALANCE alone (ZIP 318 canonical quantization of the
/// migratable 9.99 ZEC is `5 + 2 + 2 + 0.5 + 0.2 + 0.2 + 0.05 + 0.02 + 0.02`), which is what makes
/// them collide across wallets. Every funding note still has to be minted out of the wallet's
/// actual notes, so this holds only while the preparation planner can build a transaction that
/// spends several notes and mints several: one 10 ZEC balance held four ways, one split.
#[cfg(feature = "test-dependencies")]
#[test]
fn note_shape_does_not_change_the_split_of_a_ten_zec_balance() {
    // One hundredth of a ZEC: the minimum denomination, and the unit every crossing falls on.
    const H: u64 = COIN / 100;

    let mut migrated = Vec::new();
    for split in NOTE_SHAPE_SPLITS {
        let scenario = MIGRATION_SCENARIOS
            .iter()
            .find(|sc| sc.label == split.scenario_label)
            .expect("every split names a scenario");
        let backend = MockBackend::new(scenario.source_notes.to_vec(), 2_000_000);
        let mut rng = ChaCha8Rng::seed_from_u64(1);
        let plan = plan_migration(&regtest_network(true), &backend, &mut rng)
            .expect("a fundable balance plans");
        let label = scenario.label;

        assert_eq!(
            plan.crossing_values()
                .iter()
                .map(|&v| u64::from(v) / H)
                .collect::<Vec<u64>>(),
            split.crossings,
            "{label}: crossings (in 0.01 ZEC)",
        );
        assert_eq!(
            plan.preparation_tx_count(),
            split.preparations,
            "{label}: preparation transactions",
        );

        // Whatever the shape, the plan never spends more than the balance.
        let balance: u64 = scenario.source_notes.iter().sum();
        assert!(
            u64::from(plan.value_migrated()) + u64::from(plan.residual()) <= balance,
            "{label}: the plan cannot create value",
        );
        migrated.push((label, u64::from(plan.value_migrated())));
    }

    // Every shape migrates the same value: the whole canonical decomposition of the balance, with
    // nothing stranded by how the notes happen to be held.
    for (label, value) in &migrated {
        assert_eq!(*value, 999 * H, "{label}: migrated value");
    }
}

#[test]
fn stores_loads_and_updates_a_migration() {
    let mut backend = MockBackend::new(Vec::new(), 0);
    assert!(backend.get_migration().unwrap().is_none());

    // A consistent stored denomination plan (its exact values are immaterial to the store round-trip).
    let denominations = DenominationPlan::from_stored_parts(
        vec![zat(100 * COIN)],
        zat(10_000),
        None,
        zat(1_000),
        zat(100 * COIN),
        zat(100 * COIN),
    )
    .expect("a consistent stored split reconstructs");
    let tx = MigrationTransaction::from_parts(
        MigrationTransferId::new(0),
        MigrationTxKind::Transfer { crossing: 0 },
        vec![1, 2, 3], // a stand-in for the serialized pre-signed PCZT
        Vec::new(),
        BlockHeight::from_u32(2_000_100),
        BlockHeight::from_u32(2_069_220),
        None,
        TxId::from_bytes([0; 32]),
        MigrationTxState::Signed,
        None,
        None,
        Vec::new(),
        None,
    );
    let state = MigrationState::from_parts(
        MigrationStatus::Committed,
        denominations,
        PreparationPlan::from_parts(Vec::new(), Vec::new()),
        vec![tx],
        AnchorBucketInterval::ZIP_318,
        ReplanThreshold::DEFAULT,
    );
    backend.replace_migration(&state).unwrap();

    // The stored transactions round-trip, and a state update persists.
    let loaded = backend
        .get_migration()
        .unwrap()
        .expect("a migration is stored");
    assert_eq!(loaded.status(), MigrationStatus::Committed);
    assert_eq!(loaded.transactions(), state.transactions());

    // One binding for the state written and the state expected back, under a distinctive txid, so
    // the round-trip cannot pass on a zeroed or absent stored value.
    let mined = MigrationTxState::Mined {
        txid: TxId::from_bytes([0xA7; 32]),
        height: BlockHeight::from_u32(2_000_105),
    };
    backend
        .update_transaction(MigrationTransferId::new(0), mined)
        .unwrap();
    let loaded = backend.get_migration().unwrap().unwrap();
    assert_eq!(loaded.transactions()[0].state(), mined);
}
