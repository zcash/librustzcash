//! Integration tests for the two-phase migration commit, driven by the in-memory `CommitMock` and
//! `LayeredMock` crypto backends from the `zcash_pool_migration_memory` test-support crate.
//!
//! These are integration tests rather than `#[cfg(test)]` unit tests for the same reason as
//! `engine_plan.rs`: the mocks implement the engine's traits, so they must link the same library
//! instance the test binary uses, which a dev-dependency cycle only provides to integration tests.
//!
//! The whole file is gated on the `orchard` feature (the crypto commit path); without it, it
//! compiles to nothing.
#![cfg(feature = "orchard")]

use core::cell::RefCell;

use orchard::keys::{FullViewingKey, SpendAuthorizingKey};
use rand_chacha::ChaCha8Rng;
use rand_core::SeedableRng;
use zcash_protocol::value::COIN;

use zcash_pool_migration_backend::engine::{
    MigrationPlan, MigrationStatus, MigrationTransaction, MigrationTxId, MigrationTxKind,
    MigrationTxState, PoolMigrationRead, PoolMigrationWrite, commit_pending_preparation,
    commit_preparation, commit_transfers, plan_migration,
};
use zcash_pool_migration_backend::note_splitting::{FeePolicy, NoteSplitPlan, Zip317FeePolicy};
use zcash_pool_migration_backend::preparation::{PrepInput, plan_preparation};
use zcash_pool_migration_backend::scheduling::schedule;
use zcash_pool_migration_memory::{
    CommitMock, LayeredMock, TARGET_HEIGHT, prep_fee, regtest_network, shared_anchor_witnesses,
    single_note_witness, spending_key,
};

#[test]
fn commits_preparation_then_transfers() {
    let seed = 7u64;
    let sk = spending_key(seed);
    let fvk = FullViewingKey::from(&sk);
    let balance = 78 * COIN;

    // Plan the migration from the single source note.
    let plan = {
        let (note, path, anchor) = single_note_witness(&fvk, balance, seed);
        let planner = CommitMock {
            notes: vec![balance],
            witnesses: vec![(note, path)],
            anchor,
            fvk: fvk.clone(),
            ask: SpendAuthorizingKey::from(&sk),
            stored: None,
        };
        let mut rng = ChaCha8Rng::seed_from_u64(seed);
        plan_migration(&planner, prep_fee(), &mut rng).expect("plans a migration")
    };
    // A single note funding a handful of denominations needs one preparation layer.
    assert_eq!(plan.preparation().layers().len(), 1);
    let funding_notes = plan.funding_notes().to_vec();

    // Witness the source note (index 0) and the funding notes against one shared anchor.
    let mut values = vec![balance];
    values.extend_from_slice(&funding_notes);
    let (witnesses, anchor) = shared_anchor_witnesses(&fvk, &values, seed);

    let mut backend = CommitMock {
        notes: vec![balance],
        witnesses,
        anchor,
        fvk: fvk.clone(),
        ask: SpendAuthorizingKey::from(&sk),
        stored: None,
    };
    let params = regtest_network(true);
    let prep_count: usize = plan.preparation().layers().iter().map(|l| l.len()).sum();
    let transfer_count = funding_notes.len();

    // Phase 1: commit the preparation. It signs the preparation transactions and records the
    // transfers as planned placeholders (no PCZT yet).
    let mut rng = ChaCha8Rng::seed_from_u64(seed + 1);
    let state = commit_preparation(&params, TARGET_HEIGHT, &mut backend, &plan, &mut rng)
        .expect("commits the preparation");
    assert_eq!(state.status, MigrationStatus::Committed);
    assert_eq!(state.transactions.len(), prep_count + transfer_count);
    for tx in &state.transactions {
        match tx.kind {
            MigrationTxKind::Preparation { .. } => {
                assert_eq!(tx.state, MigrationTxState::Signed);
                assert!(tx.pczt.is_some());
            }
            MigrationTxKind::Transfer { .. } => {
                assert_eq!(tx.state, MigrationTxState::Planned);
                assert!(tx.pczt.is_none());
                assert!(
                    !tx.depends_on.is_empty(),
                    "a transfer waits for the preparation to mine"
                );
            }
        }
    }

    // Phase 2: once the preparation is mined, commit the transfers.
    let mut rng = ChaCha8Rng::seed_from_u64(seed + 2);
    let state = commit_transfers(&params, TARGET_HEIGHT, &mut backend, &mut rng)
        .expect("commits the transfers");

    // Every transaction is now built, pre-signed, and persisted.
    assert_eq!(state.transactions.len(), prep_count + transfer_count);
    for tx in &state.transactions {
        assert_eq!(
            tx.state,
            MigrationTxState::Signed,
            "every transaction is signed"
        );
        assert!(tx.pczt.as_ref().is_some_and(|b| !b.is_empty()));
    }
    assert!(backend.get_migration().unwrap().is_some());
}

/// A lone whale fanning out into more funding notes than one transaction holds needs a MULTI-LAYER
/// preparation. Layer 0 (spending the whale) is signed at commit time; the later layer, which
/// spends layer 0's feeder notes, is a placeholder until layer 0 mines, at which point
/// `commit_pending_preparation` builds and signs it; then the transfers build once the whole
/// preparation is mined. This exercises the phased per-layer commit end to end.
#[test]
fn commits_multi_layer_preparation_phase_by_phase() {
    let seed = 11u64;
    let sk = spending_key(seed);
    let fvk = FullViewingKey::from(&sk);

    // 15 funding notes (one more than a single transaction's FUNDING_OUTPUTS_PER_TX) force a
    // two-layer balanced fan-out. Each is a valid self-funding note (a crossing value plus the
    // transfer fee buffer), so its transfer balances.
    let buffer = Zip317FeePolicy.transfer_fee_buffer_zatoshi();
    let crossing = COIN; // 1 ZEC crossing per note
    let funding_note = crossing + buffer;
    let funding: Vec<u64> = core::iter::repeat_n(funding_note, 15).collect();

    // A whale generously larger than the balanced-tree cost, so the fan-out fast path triggers.
    let whale = funding.iter().sum::<u64>() + 16 * prep_fee();
    let preparation =
        plan_preparation(&[whale], &funding, prep_fee()).expect("a fundable whale plans");
    assert_eq!(
        preparation.layers().len(),
        2,
        "15 funding notes fan out across two layers"
    );

    // A note split whose outputs are the funding notes and whose crossings are those less the
    // buffer, so the engine derives the same buffer and each transfer crosses one ZEC.
    let crossings: Vec<u64> = funding.iter().map(|&f| f - buffer).collect();
    let note_split = NoteSplitPlan::from_stored_parts(
        crossings.clone(),
        buffer,
        None,
        prep_fee(),
        whale,
        crossings.iter().sum(),
    );
    let mut rng = ChaCha8Rng::seed_from_u64(seed);
    let schedule = schedule(2_000_000, funding.len(), &mut rng);
    let plan = MigrationPlan::from_parts(note_split, funding.clone(), preparation, schedule);

    // The shared-anchor witness pool: the whale, then every feeder a later layer spends (in the
    // order `commit_pending_preparation` requests them), then the funding notes. All are leaves of
    // one tree, so every spend across every layer and transfer anchors to the same root.
    let mut feeder_values: Vec<u64> = Vec::new();
    for (li, layer) in plan.preparation().layers().iter().enumerate() {
        if li == 0 {
            continue;
        }
        for tx in layer {
            for input in tx.inputs() {
                if let PrepInput::Prior { value, .. } = input {
                    feeder_values.push(*value);
                }
            }
        }
    }
    let mut pool_values = vec![whale];
    pool_values.extend_from_slice(&feeder_values);
    pool_values.extend_from_slice(&funding);
    let (witnesses, anchor) = shared_anchor_witnesses(&fvk, &pool_values, seed);

    let used = RefCell::new(vec![false; witnesses.len()]);
    let mut backend = LayeredMock {
        n_wallet: 1, // the whale
        witnesses,
        used,
        anchor,
        fvk: fvk.clone(),
        ask: SpendAuthorizingKey::from(&sk),
        stored: None,
    };
    let params = regtest_network(true);

    let prep_count = plan.preparation().transaction_count();
    let transfer_count = funding.len();

    // Phase 1: commit the preparation. Layer 0 is signed; the later layer and the transfers are
    // planned placeholders.
    let mut rng = ChaCha8Rng::seed_from_u64(seed + 1);
    let state = commit_preparation(&params, TARGET_HEIGHT, &mut backend, &plan, &mut rng)
        .expect("commits the preparation");
    assert_eq!(state.transactions.len(), prep_count + transfer_count);
    let layer0: Vec<&MigrationTransaction> = state
        .transactions
        .iter()
        .filter(|t| matches!(t.kind, MigrationTxKind::Preparation { layer: 0, .. }))
        .collect();
    assert_eq!(layer0.len(), 1, "one root transaction in layer 0");
    assert_eq!(layer0[0].state, MigrationTxState::Signed);
    assert!(layer0[0].pczt.is_some());
    for tx in &state.transactions {
        if let MigrationTxKind::Preparation { layer, .. } = tx.kind {
            if layer > 0 {
                assert_eq!(tx.state, MigrationTxState::Planned, "later layer deferred");
                assert!(tx.pczt.is_none());
                assert!(
                    !tx.depends_on.is_empty(),
                    "later layer waits for its predecessor"
                );
            }
        }
    }

    // The plan round-trips through the persisted state.
    assert_eq!(state.preparation.layers().len(), 2);

    // Before layer 0 is mined, there is nothing to build.
    let mut rng = ChaCha8Rng::seed_from_u64(seed + 2);
    let state = commit_pending_preparation(&params, TARGET_HEIGHT, &mut backend, &mut rng)
        .expect("no ready layer is a no-op");
    assert!(
        state.transactions.iter().any(
            |t| matches!(t.kind, MigrationTxKind::Preparation { layer, .. } if layer > 0)
                && matches!(t.state, MigrationTxState::Planned)
        ),
        "the later layer is still planned until layer 0 mines"
    );

    // Mine layer 0.
    let layer0_ids: Vec<MigrationTxId> = state
        .transactions
        .iter()
        .filter(|t| matches!(t.kind, MigrationTxKind::Preparation { layer: 0, .. }))
        .map(|t| t.id)
        .collect();
    for id in &layer0_ids {
        backend
            .update_transaction(*id, MigrationTxState::Mined { height: 2_000_010 })
            .unwrap();
    }

    // Phase 2: the later layer is now ready; build and sign it.
    let mut rng = ChaCha8Rng::seed_from_u64(seed + 3);
    let state = commit_pending_preparation(&params, TARGET_HEIGHT + 5, &mut backend, &mut rng)
        .expect("builds the ready layer");
    for tx in &state.transactions {
        if let MigrationTxKind::Preparation { layer, .. } = tx.kind {
            if layer > 0 {
                assert_eq!(tx.state, MigrationTxState::Signed, "later layer now signed");
                assert!(tx.pczt.as_ref().is_some_and(|b| !b.is_empty()));
            }
        }
    }

    // Calling again with no further ready layer is a no-op.
    let mut rng = ChaCha8Rng::seed_from_u64(seed + 4);
    let state = commit_pending_preparation(&params, TARGET_HEIGHT + 6, &mut backend, &mut rng)
        .expect("no further ready layer");
    assert!(
        state.transactions.iter().all(|t| !matches!(
            t.kind,
            MigrationTxKind::Preparation { layer, .. } if layer > 0
        ) || matches!(t.state, MigrationTxState::Signed)),
        "every preparation layer is signed"
    );

    // Mine the whole preparation, then commit the transfers.
    let prep_ids: Vec<MigrationTxId> = state
        .transactions
        .iter()
        .filter(|t| matches!(t.kind, MigrationTxKind::Preparation { .. }))
        .map(|t| t.id)
        .collect();
    for id in &prep_ids {
        backend
            .update_transaction(*id, MigrationTxState::Mined { height: 2_000_020 })
            .unwrap();
    }

    let mut rng = ChaCha8Rng::seed_from_u64(seed + 5);
    let state = commit_transfers(&params, TARGET_HEIGHT + 7, &mut backend, &mut rng)
        .expect("commits the transfers");
    assert_eq!(state.transactions.len(), prep_count + transfer_count);
    for tx in &state.transactions {
        match tx.kind {
            MigrationTxKind::Transfer { .. } => {
                assert_eq!(tx.state, MigrationTxState::Signed, "transfer signed");
                assert!(tx.pczt.as_ref().is_some_and(|b| !b.is_empty()));
            }
            MigrationTxKind::Preparation { .. } => {
                assert!(tx.pczt.as_ref().is_some_and(|b| !b.is_empty()));
            }
        }
    }
}
