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
use zcash_protocol::TxId;
use zcash_protocol::consensus::BlockHeight;
use zcash_protocol::value::COIN;

use zcash_pool_migration::build::sign_pczt;
use zcash_pool_migration::engine::{
    MigrationPlan, MigrationState, MigrationStatus, MigrationTxKind, MigrationTxState,
    PoolMigrationRead, PoolMigrationWrite, batch_unsigned_by_action_budget,
    build_preparation_unsigned, commit_preparation, plan_migration,
};
use zcash_pool_migration::pczt_txid::{pczt_txid, stored_pczt_txid};
use zcash_pool_migration::preparation::PREP_TX_ACTIONS;
use zcash_pool_migration::satisfiability::{
    AdvanceConfig, DuenessTargets, ReorgSettleDepth, ReplanThreshold, advance_migration,
};
use zcash_pool_migration::signing_rounds::SigningRoundBudget;
use zcash_pool_migration::state::AdvanceStep;
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
        ReplanThreshold::DEFAULT,
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
                assert!(
                    !tx.depends_on().is_empty(),
                    "a transfer BROADCASTS only after the preparation mines"
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
        ReplanThreshold::DEFAULT,
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
        if let MigrationTxKind::Preparation { layer, .. } = tx.kind()
            && layer > 0
        {
            assert_eq!(
                tx.depends_on(),
                &layer0_ids,
                "a later layer broadcasts only after its predecessor mines"
            );
        }
    }

    // Driven the way a consumer drives it — through `advance_migration`, against the mock store,
    // which vouches for every candidate — the migration walks the broadcasts in dependency order:
    // layer 0 first; layer 1 only once layer 0 mines; the transfers only once the whole preparation
    // mines.
    let mut state = state;
    let config = AdvanceConfig::new(ReorgSettleDepth::new(10));
    // A height past every scheduled broadcast (so each transaction is due, not blocked on the
    // schedule) but within every expiry window (so none is expired and offered for rebuild): the
    // latest scheduled height. This exercises the dependency-ordering walk, not schedule
    // handling — and because the drive layer RE-SPREADS a schedule this overdue (the whole
    // pending schedule shifts forward before the first step of each backlog is served), the
    // target is recomputed from the current schedule before every call rather than fixed once.
    let latest_scheduled = |state: &MigrationState| {
        state
            .transactions()
            .iter()
            .map(|t| t.scheduled_height())
            .max()
            .expect("the committed migration has transactions")
    };
    let targets = DuenessTargets::at(latest_scheduled(&state));
    match advance_migration(&mut backend, &mut state, targets, &config, &mut rng)
        .expect("the store answers")
        .step()
        .clone()
    {
        AdvanceStep::Prove { transactions } => {
            assert!(
                transactions.iter().all(|t| layer0_ids.contains(&t.id())),
                "layer 0 proves first"
            )
        }
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
    let targets = DuenessTargets::at(latest_scheduled(&state));
    match advance_migration(&mut backend, &mut state, targets, &config, &mut rng)
        .expect("the store answers")
        .step()
        .clone()
    {
        AdvanceStep::Prove { transactions } => {
            assert!(
                transactions.iter().all(|t| layer1_ids.contains(&t.id())),
                "layer 1 proves once layer 0 mines"
            )
        }
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
    let targets = DuenessTargets::at(latest_scheduled(&state));
    match advance_migration(&mut backend, &mut state, targets, &config, &mut rng)
        .expect("the store answers")
        .step()
        .clone()
    {
        step @ (AdvanceStep::Prove { .. } | AdvanceStep::Broadcast { .. }) => {
            let id = match &step {
                AdvanceStep::Prove { transactions } => transactions[0].id(),
                AdvanceStep::Broadcast { id } => *id,
                _ => unreachable!(),
            };
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
        ReplanThreshold::DEFAULT,
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
    let budget_actions = PREP_TX_ACTIONS + ACTIONS_PER_TRANSFER;
    let budget = SigningRoundBudget::new(
        core::num::NonZeroU32::new(budget_actions as u32).expect("nonzero budget"),
    );
    let total = unsigned.len();
    let sessions = batch_unsigned_by_action_budget(unsigned, budget);
    assert!(sessions.len() > 1, "several rounds: {}", sessions.len());
    assert_eq!(sessions.iter().map(|s| s.len()).sum::<usize>(), total);
    for session in &sessions {
        assert!(!session.is_empty());
        assert!(session.iter().map(|tx| tx.actions()).sum::<usize>() <= budget_actions);
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

/// Every committed transaction's txid is derivable from its stored SIGNED PCZT, before anything is
/// proved or broadcast, and each one is distinct.
///
/// This is what lets [`advance_migration`] recognize a transaction the wallet has seen mine even
/// when the consumer never recorded broadcasting it. The derivation is over real committed
/// artifacts — absent anchors, deferred witnesses — because that is the state the sweep meets them
/// in. That the id survives proving is forced by the signatures made here: they commit to the
/// txid, so a transaction whose id moved when its proof was installed could not be broadcast at
/// all.
///
/// [`advance_migration`]: zcash_pool_migration::satisfiability::advance_migration
#[test]
fn every_committed_transaction_has_a_derivable_txid() {
    let seed = 11u64;
    let (mut backend, plan) = single_note_setup(seed, 78 * COIN);
    let mut rng = ChaCha8Rng::seed_from_u64(seed + 1);
    let state = commit_preparation(
        &regtest_network(true),
        BlockHeight::from_u32(TARGET_HEIGHT),
        &mut backend,
        &plan,
        &mut rng,
        ReplanThreshold::DEFAULT,
    )
    .expect("commits the migration");

    let mut seen: Vec<TxId> = Vec::new();
    for tx in state.transactions() {
        assert_eq!(tx.state(), MigrationTxState::Signed, "signed, not proved");
        let parsed = pczt::Pczt::parse(tx.pczt()).expect("the stored PCZT parses");
        assert!(
            parsed.orchard().anchor().is_none(),
            "the anchor is still deferred, which is the point",
        );
        let txid = pczt_txid(&parsed).expect("a signed migration PCZT yields its txid");
        assert_eq!(
            stored_pczt_txid(tx.pczt()).expect("and so do the stored bytes"),
            txid,
            "the bytes-level helper agrees with the parsed one",
        );
        assert!(
            !seen.contains(&txid),
            "each transaction has its own id: {txid:?} repeated",
        );
        seen.push(txid);
    }
    assert_eq!(seen.len(), state.transactions().len());
}

/// The unrecorded-broadcast sweep, end to end over real artifacts: a `Proved` transaction whose
/// broadcast was never recorded, but which the wallet's scan has seen mine, is promoted by
/// [`advance_migration`] — THROUGH `Broadcast`, since that is the state the lost record would have
/// written — with nothing but its stored PCZT to identify it by.
///
/// [`advance_migration`]: zcash_pool_migration::satisfiability::advance_migration
#[test]
fn advance_promotes_a_proved_transaction_whose_broadcast_was_never_recorded() {
    let seed = 13u64;
    let (mut backend, plan) = single_note_setup(seed, 78 * COIN);
    let mut rng = ChaCha8Rng::seed_from_u64(seed + 1);
    let mut state = commit_preparation(
        &regtest_network(true),
        BlockHeight::from_u32(TARGET_HEIGHT),
        &mut backend,
        &plan,
        &mut rng,
        ReplanThreshold::DEFAULT,
    )
    .expect("commits the migration");

    // The crashed submission: a preparation was proved, submitted, and mined, but the process
    // died before `mark_broadcast` — so the stored row still says `Proved` and carries no txid.
    let victim = state.transactions()[0].id();
    let victim_txid = stored_pczt_txid(
        state
            .transactions()
            .iter()
            .find(|t| t.id() == victim)
            .expect("the row is stored")
            .pczt(),
    )
    .expect("the stored PCZT yields its txid");
    state.set_transaction_proved(victim, state.transactions()[0].pczt().to_vec(), None);
    assert_eq!(
        state
            .transactions()
            .iter()
            .find(|t| t.id() == victim)
            .unwrap()
            .state(),
        MigrationTxState::Proved,
        "precondition: the row is proved and NOT recorded broadcast",
    );

    let mined_at = BlockHeight::from_u32(TARGET_HEIGHT + 5);
    backend.mined.insert(victim_txid, mined_at);
    backend.replace_migration(&state).unwrap();

    advance_migration(
        &mut backend,
        &mut state,
        DuenessTargets::at(BlockHeight::from_u32(TARGET_HEIGHT + 10)),
        &AdvanceConfig::new(ReorgSettleDepth::new(10)),
        &mut rng,
    )
    .expect("the mock store never fails");

    assert_eq!(
        state
            .transactions()
            .iter()
            .find(|t| t.id() == victim)
            .unwrap()
            .state(),
        MigrationTxState::Mined {
            txid: victim_txid,
            height: mined_at,
        },
        "the lost broadcast is recovered from the stored PCZT alone",
    );
}
