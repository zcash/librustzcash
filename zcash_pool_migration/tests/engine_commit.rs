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
#[cfg(feature = "test-dependencies")]
use zcash_pool_migration::engine::MigrationTransferId;
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

/// The account's Orchard SPENDING key, as a caller now hands it to the entry points that sign
/// (`commit_preparation`, `rebuild_expired_transfer`). Derived from the same `seed` the mock
/// wallet's key is, so it is that account's own — which those entry points check.
fn sk(seed: u64) -> orchard::keys::SpendingKey {
    spending_key(seed)
}

/// A planned single-note migration and the mock wallet that holds the note.
fn single_note_setup(seed: u64, balance: u64) -> (CommitMock, MigrationPlan) {
    notes_setup(seed, &[balance])
}

/// A planned migration and the mock wallet holding the notes it is planned over.
fn notes_setup(seed: u64, balances: &[u64]) -> (CommitMock, MigrationPlan) {
    let backend = CommitMock::new(seed, balances);
    let mut rng = ChaCha8Rng::seed_from_u64(seed);
    let plan = plan_migration(&regtest_network(true), &backend, &mut rng)
        .expect("a fundable balance plans");
    (backend, plan)
}

/// Commit `plan` and assert that the run it committed is the run
/// [`MigrationPlan::planned_transactions`] described.
///
/// Be precise about what this can and cannot catch. `commit_preparation` now COPIES each row's id,
/// dependencies and scheduled height onto the transaction it builds, so those three per-row
/// comparisons assert that copies are copies — they cannot detect a disagreement, because there is
/// no longer a second derivation to disagree. What they do pin is everything around the copying:
///
/// - LENGTH: the plan enumerated exactly the transactions the commit built, no more and no fewer.
/// - ORDER: the rows and the built transactions correspond POSITION for position, and each row's
///   id is the id its transaction carries — so the preview a user consented to can be matched back
///   to the stored run by id.
/// - ACCEPTANCE: the plan the preview describes is one the commit will actually build. A row whose
///   height or funding note the plan never named is refused outright, so reaching these assertions
///   at all means the previewed run was buildable.
/// - PURITY: previewing did not perturb the plan — the same enumeration is available, unchanged,
///   after the commit.
///
/// The one thing the two sides still derive separately is the funding note's PLAINTEXT, which only
/// the commit can know; `assert_transfers_spend_their_producers_notes` covers that seam.
///
/// Returns the committed state, for a caller that wants to assert more about the run.
fn assert_preview_matches_commit(
    seed: u64,
    backend: &mut CommitMock,
    plan: &MigrationPlan,
) -> MigrationState {
    let previewed = plan.planned_transactions();

    let mut rng = ChaCha8Rng::seed_from_u64(seed + 1);
    let state = commit_preparation(
        &regtest_network(true),
        BlockHeight::from_u32(TARGET_HEIGHT),
        backend,
        &sk(seed),
        plan,
        &mut rng,
        ReplanThreshold::DEFAULT,
    )
    .expect("commits the migration");

    assert_eq!(
        previewed.len(),
        state.transactions().len(),
        "the preview lists exactly the transactions the commit builds",
    );
    for (preview, committed) in previewed.iter().zip(state.transactions()) {
        assert_eq!(
            preview.id(),
            committed.id(),
            "the preview's ordinals are the commit's, in the commit's order",
        );
        assert_eq!(preview.kind(), committed.kind(), "tx {:?}", preview.id());
        assert_eq!(
            preview.depends_on(),
            committed.depends_on(),
            "tx {:?} waits on what the preview said it would",
            preview.id(),
        );
        // A committed transaction always has a height; the preview's `None` is the malformed-plan
        // case the commit refuses outright, so reaching here at all means it was `Some`.
        assert_eq!(
            preview.scheduled_height(),
            Some(committed.scheduled_height()),
            "tx {:?} is scheduled where the preview said it would be",
            preview.id(),
        );
    }

    // `planned_transactions` is a pure function of the plan: committing it neither consumed nor
    // altered the plan, so the same preview is still available (and identical) afterwards.
    assert_eq!(
        plan.planned_transactions(),
        previewed,
        "planned_transactions is a pure function of the plan",
    );

    state
}

/// Assert that every transfer spends a note MINTED BY the transaction its `depends_on` names — and
/// that a transfer that waits on nothing spends a note no preparation transaction in the run
/// minted (a wallet note the plan funds directly).
///
/// This is the seam the row-by-row comparison cannot reach. The plan decides which minted note
/// each crossing spends and derives that crossing's dependency from whichever transaction mints
/// it; the commit resolves the note's PLAINTEXT for itself. If those two ever named different
/// notes, a crossing would be recorded waiting on a transaction that does not mint what it
/// spends — the migration would broadcast a transfer whose funding note is not yet on chain.
///
/// The link is checked through the note's `rho`, which for a note minted by a preparation
/// transaction IS the nullifier of the action that created it. So a funding note belongs to
/// exactly the transaction among whose action nullifiers its `rho` appears — no value matching
/// involved, which is the point.
#[cfg(feature = "test-dependencies")]
fn assert_transfers_spend_their_producers_notes(
    state: &MigrationState,
    transfer_funding: &[(MigrationTransferId, orchard::note::Note)],
) {
    assert!(!transfer_funding.is_empty(), "the run has transfers");

    // Every action nullifier of each committed preparation transaction: the set of rhos its
    // outputs can carry.
    let mint_actions = |tx: &zcash_pool_migration::engine::MigrationTransaction| -> Vec<[u8; 32]> {
        pczt::Pczt::parse(tx.pczt())
            .expect("the stored PCZT parses")
            .orchard()
            .actions()
            .iter()
            .map(|action| *action.spend().nullifier())
            .collect()
    };

    for (id, note) in transfer_funding {
        let transfer = state
            .transactions()
            .iter()
            .find(|t| t.id() == *id)
            .expect("the funding pairing names a committed transaction");
        let rho = note.rho().to_bytes();

        match transfer.depends_on().as_slice() {
            [] => {
                for tx in state.transactions() {
                    if matches!(tx.kind(), MigrationTxKind::Preparation { .. }) {
                        assert!(
                            !mint_actions(tx).contains(&rho),
                            "transfer {id:?} waits on nothing, so its funding note must not be \
                             minted by preparation transaction {:?}",
                            tx.id(),
                        );
                    }
                }
            }
            [producer_id] => {
                let producer = state
                    .transactions()
                    .iter()
                    .find(|t| t.id() == *producer_id)
                    .expect("the dependency names a committed transaction");
                assert!(
                    matches!(producer.kind(), MigrationTxKind::Preparation { .. }),
                    "a transfer waits on a preparation transaction",
                );
                assert!(
                    mint_actions(producer).contains(&rho),
                    "transfer {id:?} spends a note minted by {producer_id:?}, the transaction it \
                     waits on",
                );
            }
            many => panic!(
                "a transfer waits on at most one producer, not {}",
                many.len()
            ),
        }
    }
}

/// The funding-note seam, over the three funding shapes one run can mix: notes minted by a single
/// layer, notes minted by the LAST of several layers, and a note the wallet already holds.
///
/// Driven through `commit_preparation_with_funding`, the entry point that returns each transfer
/// paired with the funding note it actually built against — the only place the note the commit
/// resolved is observable from outside.
#[cfg(feature = "test-dependencies")]
#[test]
fn every_transfer_spends_the_note_its_producer_mints() {
    for (name, seed, balances) in [
        ("one layer", 7u64, alloc_balances(&[78])),
        ("two layers", 11, alloc_balances(&[1_000])),
        ("a directly-funded crossing", 29, direct_funding_balances()),
    ] {
        let (mut backend, plan) = notes_setup(seed, &balances);
        let mut rng = ChaCha8Rng::seed_from_u64(seed + 1);
        let (state, transfer_funding) =
            zcash_pool_migration::engine::commit_preparation_with_funding(
                &regtest_network(true),
                BlockHeight::from_u32(TARGET_HEIGHT),
                &mut backend,
                &sk(seed),
                &plan,
                &mut rng,
                ReplanThreshold::DEFAULT,
            )
            .unwrap_or_else(|e| panic!("{name}: commits the migration: {e:?}"));

        assert_eq!(
            transfer_funding.len(),
            plan.transfer_tx_count(),
            "{name}: one funding note per crossing",
        );
        assert_transfers_spend_their_producers_notes(&state, &transfer_funding);
    }
}

/// Note values in ZEC as the mock wallet takes them (zatoshi).
#[cfg(feature = "test-dependencies")]
fn alloc_balances(zec: &[u64]) -> Vec<u64> {
    zec.iter().map(|z| z * COIN).collect()
}

/// A wallet holding one note that is already exactly a funding note (a denomination plus the fee
/// buffer) beside a note that must be prepared, so one crossing is directly funded and the rest
/// are minted.
#[cfg(feature = "test-dependencies")]
fn direct_funding_balances() -> Vec<u64> {
    let (_probe_backend, probe) = single_note_setup(2, 2 * (COIN / 100));
    let buffer = u64::from(probe.denominations().note_fee_buffer());
    vec![COIN + buffer, 78 * COIN]
}

/// A single-layer run: every transfer waits on the one preparation transaction that mints the
/// funding notes, and the preview says so before anything is built.
#[test]
fn plan_previews_a_single_layer_run() {
    let seed = 7u64;
    let (mut backend, plan) = single_note_setup(seed, 78 * COIN);
    assert_eq!(plan.preparation().layer_count(), 1);
    assert!(plan.transfer_tx_count() >= 2, "several crossings");

    let previewed = plan.planned_transactions();
    let prep_ids: Vec<_> = previewed
        .iter()
        .filter(|tx| tx.is_preparation())
        .map(|tx| tx.id())
        .collect();
    assert_eq!(prep_ids.len(), 1, "one preparation transaction");
    for transfer in previewed.iter().filter(|tx| tx.is_transfer()) {
        assert_eq!(
            transfer.depends_on(),
            &prep_ids[..],
            "every crossing waits on the transaction that mints its funding note",
        );
    }

    assert_preview_matches_commit(seed, &mut backend, &plan);
}

/// A multi-layer run: the preview carries the whole-preceding-layer dependency of each later
/// preparation transaction, and resolves each crossing to the ONE transaction that mints its own
/// funding note — the two dependency rules the commit applies, in the case that distinguishes
/// them.
#[test]
fn plan_previews_a_multi_layer_run() {
    let seed = 11u64;
    let (mut backend, plan) = single_note_setup(seed, 1_000 * COIN);
    assert_eq!(
        plan.preparation().layer_count(),
        2,
        "the whale fans out across two layers",
    );

    let previewed = plan.planned_transactions();
    let layer_ids = |layer: usize| -> Vec<_> {
        previewed
            .iter()
            .filter(|tx| matches!(tx.kind(), MigrationTxKind::Preparation { layer: l, .. } if l == layer))
            .map(|tx| tx.id())
            .collect()
    };
    let layer0 = layer_ids(0);
    let layer1 = layer_ids(1);
    assert!(!layer0.is_empty() && !layer1.is_empty());

    for tx in previewed.iter() {
        match tx.kind() {
            MigrationTxKind::Preparation { layer: 0, .. } => {
                assert!(tx.depends_on().is_empty(), "layer 0 waits on nothing");
            }
            MigrationTxKind::Preparation { .. } => {
                assert_eq!(
                    tx.depends_on(),
                    &layer0[..],
                    "a later layer waits on the WHOLE layer before it",
                );
            }
            MigrationTxKind::Transfer { .. } => {
                assert_eq!(
                    tx.depends_on().len(),
                    1,
                    "a crossing waits on its own funding note's producer, and only that",
                );
                assert!(
                    layer0.contains(&tx.depends_on()[0]) || layer1.contains(&tx.depends_on()[0]),
                    "and that producer is one of the preparation transactions",
                );
            }
        }
    }
    assert!(
        previewed
            .iter()
            .any(|tx| tx.is_transfer() && layer1.contains(&tx.depends_on()[0])),
        "at least one crossing is funded by the LAST layer, so the resolution is not trivially \
         layer 0",
    );

    assert_preview_matches_commit(seed, &mut backend, &plan);
}

/// A crossing whose funding note the wallet already holds is spent DIRECTLY: no preparation
/// transaction mints it, so it waits on nothing. The preview must not hand it a dependency
/// belonging to some other crossing of the same value, which is the mistake a value-matched walk
/// makes if it does not track which notes are already claimed.
#[test]
fn plan_previews_a_directly_funded_crossing() {
    // The fee buffer a crossing's funding note carries on top of its denomination, discovered from
    // a probe plan exactly as the planner computes it. A wallet note of a denomination PLUS that
    // buffer is already a funding note, so the planner spends it directly.
    let (_probe_backend, probe) = single_note_setup(2, 2 * (COIN / 100));
    let buffer = u64::from(probe.denominations().note_fee_buffer());

    let seed = 29u64;
    let (mut backend, plan) = notes_setup(seed, &[COIN + buffer, 78 * COIN]);
    assert_eq!(
        plan.preparation().direct_funding_notes().len(),
        1,
        "one crossing is funded straight from the wallet",
    );
    assert!(
        plan.preparation_tx_count() >= 1,
        "and the rest are minted, so both kinds of funding are in one run",
    );

    let previewed = plan.planned_transactions();
    assert_eq!(
        previewed
            .iter()
            .filter(|tx| tx.is_transfer() && tx.depends_on().is_empty())
            .count(),
        1,
        "exactly the directly-funded crossing waits on nothing",
    );

    assert_preview_matches_commit(seed, &mut backend, &plan);
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
        &sk(seed),
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
        &sk(seed),
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
        &sk(seed),
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
        &sk(seed),
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
