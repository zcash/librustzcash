//! Integration tests for the one-pass migration commit, driven by the in-memory `CommitMock` crypto
//! backend from the `zcash_pool_migration_memory` test-support crate.
//!
//! These are integration tests rather than `#[cfg(test)]` unit tests for the same reason as
//! `engine_plan.rs`: the mock implements the engine's traits, so it must link the same library
//! instance the test binary uses, which a dev-dependency cycle only provides to integration tests.
//!
//! The whole file is gated on the `orchard` feature (the crypto commit path); without it, it
//! compiles to nothing.
#![cfg(feature = "orchard")]

use orchard::keys::SpendAuthorizingKey;
use rand_chacha::ChaCha8Rng;
use rand_core::SeedableRng;
use zcash_protocol::consensus::BlockHeight;
use zcash_protocol::value::COIN;

use zcash_pool_migration_backend::build::sign_pczt;
use zcash_pool_migration_backend::engine::{
    MigrationPlan, MigrationStatus, MigrationTxKind, MigrationTxState, PoolMigrationRead,
    PoolMigrationWrite, ProveError, batch_unsigned_by_action_budget, build_preparation_unsigned,
    commit_preparation, plan_migration, prove_transfer,
};
use zcash_pool_migration_backend::preparation::PREP_TX_ACTIONS;
use zcash_pool_migration_backend::state::AdvanceStep;
use zcash_pool_migration_memory::{CommitMock, TARGET_HEIGHT, regtest_network, spending_key};

/// A planned single-note migration and the mock wallet that holds the note.
fn single_note_setup(seed: u64, balance: u64) -> (CommitMock, MigrationPlan) {
    let backend = CommitMock::new(seed, &[balance]);
    let mut rng = ChaCha8Rng::seed_from_u64(seed);
    let plan = plan_migration(&regtest_network(true), &backend, &mut rng)
        .expect("a fundable balance plans");
    (backend, plan)
}

/// The WHOLE migration, every preparation transaction and every transfer, is built and SIGNED in the
/// one commit pass, before anything is broadcast or mined: the funding notes are recovered from the
/// built preparation bundles, and every stored PCZT carries ABSENT anchors (ZIP 374), to be
/// installed at proving time against each transaction's anchor.
#[test]
fn commits_the_whole_migration_in_one_pass() {
    let seed = 7u64;
    let (mut backend, plan) = single_note_setup(seed, 78 * COIN);
    // A single note funding a handful of denominations needs one preparation layer.
    assert_eq!(plan.preparation().layers().len(), 1);
    let params = regtest_network(true);
    let prep_count: usize = plan.preparation().layers().iter().map(|l| l.len()).sum();
    let transfer_count = plan.funding_notes().len();
    assert!(transfer_count >= 2, "several transfers: {transfer_count}");

    let mut rng = ChaCha8Rng::seed_from_u64(seed + 1);
    let state = commit_preparation(
        &params,
        BlockHeight::from_u32(TARGET_HEIGHT),
        &mut backend,
        &plan,
        &mut rng,
    )
    .expect("commits the migration");
    assert_eq!(state.status(), MigrationStatus::Committed);
    assert_eq!(state.transactions().len(), prep_count + transfer_count);

    for tx in state.transactions() {
        // ONE signing phase: everything is signed at commit, before anything mines.
        assert_eq!(tx.state(), MigrationTxState::Signed, "signed at commit");
        assert!(!tx.pczt().is_empty());
        let parsed = pczt::Pczt::parse(tx.pczt()).expect("the stored PCZT parses");
        // Anchors are deferred (ZIP 374): every stored PCZT carries ABSENT anchors, and the
        // pre-signature commits to the stored canonical expiry for the drawn schedule.
        assert!(parsed.orchard().anchor().is_none());
        assert!(parsed.ironwood().anchor().is_none());
        assert_eq!(
            *parsed.global().expiry_height(),
            u32::from(tx.expiry_height()),
            "the embedded expiry matches the stored schedule expiry"
        );
        match tx.kind() {
            MigrationTxKind::Preparation { .. } => {
                assert!(
                    tx.depends_on().is_empty(),
                    "single-layer preps are independent"
                );
                assert!(tx.anchor_boundary().is_none());
            }
            MigrationTxKind::Transfer { .. } => {
                // A transfer depends only on the ONE preparation transaction that mints its funding
                // note, so it releases as soon as its own note is mined, not once the whole last
                // layer mines.
                assert_eq!(
                    tx.depends_on().len(),
                    1,
                    "a transfer waits on exactly its funding note's producer"
                );
                let producer = tx.depends_on()[0];
                assert!(
                    state.transactions().iter().any(|p| p.id() == producer
                        && matches!(p.kind(), MigrationTxKind::Preparation { .. })),
                    "the dependency is a preparation transaction"
                );
                assert!(
                    tx.anchor_boundary().is_some(),
                    "every transfer carries its boundary"
                );
            }
        }
    }
    assert!(backend.get_migration().unwrap().is_some());
}

/// A lone whale fanning out into more funding notes than one transaction holds needs a MULTI-LAYER
/// preparation, and it still signs in the SAME single pass: the later layer's feeder spends and the
/// transfers' funding notes are recovered from the earlier layers' built (unmined) bundles. Mining
/// then gates only the broadcast order, which the state machine walks layer by layer.
#[test]
fn commits_a_multi_layer_migration_in_one_pass() {
    // A 1000 ZEC whale splits into 15 funding notes, one more than a single transaction holds, so
    // the preparation fans out across two layers.
    let seed = 11u64;
    let (mut backend, plan) = single_note_setup(seed, 1_000 * COIN);
    assert_eq!(
        plan.preparation().layers().len(),
        2,
        "the whale fans out across two layers"
    );
    let params = regtest_network(true);
    let prep_count = plan.preparation().transaction_count();
    let transfer_count = plan.funding_notes().len();

    // ONE pass builds and signs both layers and every transfer.
    let mut rng = ChaCha8Rng::seed_from_u64(seed + 1);
    let state = commit_preparation(
        &params,
        BlockHeight::from_u32(TARGET_HEIGHT),
        &mut backend,
        &plan,
        &mut rng,
    )
    .expect("commits the migration");
    assert_eq!(state.transactions().len(), prep_count + transfer_count);
    for tx in state.transactions() {
        assert_eq!(tx.state(), MigrationTxState::Signed, "signed at commit");
        assert!(!tx.pczt().is_empty());
    }
    let layer0_ids: Vec<_> = state
        .transactions()
        .iter()
        .filter(|t| matches!(t.kind(), MigrationTxKind::Preparation { layer: 0, .. }))
        .map(|t| t.id())
        .collect();
    assert_eq!(layer0_ids.len(), 1, "one root transaction in layer 0");
    for tx in state.transactions() {
        if let MigrationTxKind::Preparation { layer, .. } = tx.kind() {
            if layer > 0 {
                assert_eq!(
                    tx.depends_on(),
                    &layer0_ids,
                    "a later layer broadcasts only after its predecessor mines"
                );
            }
        }
    }

    // The state machine walks the broadcasts in dependency order: layer 0 first; layer 1 only once
    // layer 0 mines; the transfers only once the whole preparation mines.
    let mut state = state;
    let target = BlockHeight::from_u32(2_100_000);
    match state.next_step(target) {
        AdvanceStep::Broadcast { id } => {
            assert!(layer0_ids.contains(&id), "layer 0 broadcasts first")
        }
        other => panic!("expected a broadcast step, got {other:?}"),
    }
    for id in &layer0_ids {
        state.mark_mined(*id, BlockHeight::from_u32(2_000_010));
    }
    let layer1_ids: Vec<_> = state
        .transactions()
        .iter()
        .filter(|t| matches!(t.kind(), MigrationTxKind::Preparation { layer: 1, .. }))
        .map(|t| t.id())
        .collect();
    match state.next_step(target) {
        AdvanceStep::Broadcast { id } => {
            assert!(
                layer1_ids.contains(&id),
                "layer 1 broadcasts once layer 0 mines"
            )
        }
        other => panic!("expected a broadcast step, got {other:?}"),
    }
    for id in &layer1_ids {
        state.mark_mined(*id, BlockHeight::from_u32(2_000_020));
    }
    match state.next_step(target) {
        AdvanceStep::Broadcast { id } => {
            let tx = state
                .transactions()
                .iter()
                .find(|t| t.id() == id)
                .expect("the step names a stored transaction");
            assert!(
                matches!(tx.kind(), MigrationTxKind::Transfer { .. }),
                "the transfers broadcast once the whole preparation mines"
            );
        }
        other => panic!("expected a broadcast step, got {other:?}"),
    }
}

/// The EXTERNAL path builds the whole migration unsigned in the same one pass, and the unsigned
/// transactions split into signing sessions bounded by the device's action budget: consecutive
/// topological prefixes, never gated on mining.
#[test]
fn external_signing_batches_by_action_budget() {
    let seed = 19u64;
    let (mut backend, plan) = single_note_setup(seed, 78 * COIN);
    let params = regtest_network(true);

    let mut rng = ChaCha8Rng::seed_from_u64(seed + 1);
    let (mut state, unsigned) = build_preparation_unsigned(
        &params,
        BlockHeight::from_u32(TARGET_HEIGHT),
        &mut backend,
        &plan,
        &mut rng,
    )
    .expect("builds the migration unsigned");
    assert_eq!(unsigned.len(), state.transactions().len());
    for tx in state.transactions() {
        assert_eq!(tx.state(), MigrationTxState::AwaitingSignature);
    }

    // Sessions are consecutive prefixes bounded by the action budget; a preparation is
    // PREP_TX_ACTIONS actions and a transfer is three (two source, one destination), so a budget of
    // one preparation plus one transfer splits the list without ever exceeding the budget (every
    // batch is non-empty and within budget).
    const ACTIONS_PER_TRANSFER: usize = 3;
    let budget = PREP_TX_ACTIONS + ACTIONS_PER_TRANSFER;
    let total = unsigned.len();
    let sessions = batch_unsigned_by_action_budget(unsigned, budget);
    assert!(sessions.len() > 1, "several sessions: {}", sessions.len());
    assert_eq!(sessions.iter().map(|s| s.len()).sum::<usize>(), total);
    for session in &sessions {
        assert!(!session.is_empty());
        assert!(session.iter().map(|tx| tx.actions()).sum::<usize>() <= budget);
    }

    // Sign every session out of band and apply the signatures back; the whole migration is then
    // Signed without anything having been broadcast or mined.
    let ask = SpendAuthorizingKey::from(&spending_key(seed));
    for session in sessions {
        for unsigned_tx in session {
            let (id, bytes) = unsigned_tx.into_parts();
            let signed = sign_pczt(
                pczt::Pczt::parse(&bytes).expect("the unsigned PCZT parses"),
                &ask,
            )
            .expect("the device signs the transaction");
            assert!(state.apply_signature(id, signed.serialize().expect("serializes")));
        }
    }
    backend.replace_migration(&state).unwrap();
    for tx in state.transactions() {
        assert_eq!(tx.state(), MigrationTxState::Signed);
    }
}

/// Proving a due transfer consults the anchor boundary the schedule DREW and persisted on the
/// transaction (not the tip), moving it `Signed -> Proved`. This exercises the engine orchestration
/// of [`prove_transfer`]: it reads the persisted `anchor_boundary`, hands it to the crypto backend
/// (here the in-memory mock stands in for the real prover), stores the returned PCZT, and advances
/// the state. It also checks the guards: a preparation transaction is not a transfer, and an
/// already-proved transfer is not re-proved.
#[test]
fn prove_transfer_consults_the_persisted_anchor_boundary() {
    let seed = 7u64;
    let (mut backend, plan) = single_note_setup(seed, 78 * COIN);
    let params = regtest_network(true);
    let mut rng = ChaCha8Rng::seed_from_u64(seed + 1);
    let mut state = commit_preparation(
        &params,
        BlockHeight::from_u32(TARGET_HEIGHT),
        &mut backend,
        &plan,
        &mut rng,
    )
    .expect("commits the migration");

    // Every transfer is Signed and carries a drawn anchor boundary after commit.
    let transfer_id = state
        .transactions()
        .iter()
        .find(|t| matches!(t.kind(), MigrationTxKind::Transfer { .. }))
        .map(|t| {
            assert!(
                t.anchor_boundary().is_some(),
                "a transfer carries the boundary its schedule drew"
            );
            assert!(matches!(t.state(), MigrationTxState::Signed));
            t.id()
        })
        .expect("a committed migration has transfers");

    // Proving reads the persisted boundary, proves, and advances Signed -> Proved.
    prove_transfer(&backend, &mut state, transfer_id).expect("proves the due transfer");
    let proved = state
        .transactions()
        .iter()
        .find(|t| t.id() == transfer_id)
        .expect("the transfer is still present");
    assert!(
        matches!(proved.state(), MigrationTxState::Proved),
        "the transfer is proved"
    );

    // An already-proved transfer is not re-proved.
    assert!(matches!(
        prove_transfer(&backend, &mut state, transfer_id),
        Err(ProveError::NotReady(_))
    ));

    // A preparation transaction is not a transfer: it anchors to its dependencies, not a drawn
    // boundary, so it is rejected rather than proved.
    let prep_id = state
        .transactions()
        .iter()
        .find(|t| matches!(t.kind(), MigrationTxKind::Preparation { .. }))
        .expect("a committed migration has preparation transactions")
        .id();
    assert!(matches!(
        prove_transfer(&backend, &mut state, prep_id),
        Err(ProveError::NotATransfer(_))
    ));
}
