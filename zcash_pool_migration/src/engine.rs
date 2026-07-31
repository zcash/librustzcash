//! The migration engine: orchestrating a pool migration end to end through a wallet backend.
//!
//! The crate's other modules are the individual planners and builders: [`denomination`] decides the
//! denominations, [`preparation`] plans the transactions that mint them, [`scheduling`] shuffles and
//! times the phase-2 transfers, and the `build` module turns plans into PCZTs. This module ties
//! them together behind a [`MigrationBackend`] trait, so the engine drives the whole flow
//! (plan -> build -> sign -> schedule -> persist) without knowing how the wallet stores notes, resolves
//! witnesses, holds keys, or persists state.
//!
//! [`plan_migration`] decomposes the account's spendable balance into canonical denominations, plans the
//! preparation transactions, schedules the transfers, and reconciles the split against the preparation
//! fees (dropping the smallest denominations when the fees do not fit the balance), producing a
//! [`MigrationPlan`] preview for the user to consent to (ZIP 318 requires consent before any funds leave
//! the pool). After consent, [`commit_preparation`] builds and pre-signs EVERY transaction in one
//! pass, reading the account's note plaintexts and signing through the backend traits, and
//! persisting each transaction through the store traits. The concrete durable store, proving, and
//! reconciliation-on-launch are grown by a later slice.
//!
//! # The committed migration is stored as its transactions' PCZTs
//!
//! Planning is only the first phase, and the application that broadcasts is separate from the engine that
//! plans and signs. Once the user consents, the engine builds each preparation and transfer transaction
//! as a PCZT and pre-signs it (anchors and witnesses are deferred to proving time per ZIP 374, so a
//! spent note's PLAINTEXT fully determines the signed data — even for a note minted by an earlier,
//! still-unmined migration transaction, whose plaintext the engine recovers from the built bundle),
//! then hands each to the backend to PERSIST alongside its schedule: broadcast height, expiry, layer
//! and dependencies, drawn anchor boundary, and state. The whole migration — every preparation
//! layer, in topological order, and every transfer — is therefore built and signed in ONE signing
//! phase, before anything is broadcast; an external hardware signer receives the same transactions
//! UNSIGNED, split into sessions bounded only by its per-interaction action budget (see
//! [`batch_unsigned_by_action_budget`]), never by mining. The durable artifact is each transaction's PCZT
//! plus its schedule and state, not just the plan. The consuming application later reads the due
//! transactions back from the store, proves each transfer against its drawn boundary anchor —
//! installing the anchor and the funding note's witness through the PCZT Updater role (ZIP 374
//! defers both past signing) — broadcasts them at their scheduled heights, and reports the outcome
//! so the engine can advance each transaction's state. A
//! wallet closed between planning and broadcast, or restarted partway through, resumes from the stored
//! PCZTs.
//!
//! [`denomination`]: crate::denomination
//! [`preparation`]: crate::preparation
//! [`scheduling`]: crate::scheduling

use alloc::vec::Vec;
use core::{
    fmt,
    num::{NonZeroU32, NonZeroUsize},
};
#[cfg(feature = "orchard")]
use {
    crate::{
        build::{AccountDerivation, build_prep_tx, build_transfer_pczt},
        preparation::PrepOutput,
    },
    alloc::collections::BTreeMap,
};

use corez::io;

use getset::{CopyGetters, Getters};
use rand_core::RngCore;
use zcash_protocol::{
    TxId,
    consensus::BlockHeight,
    value::{BalanceError, Zatoshis},
};

use zcash_primitives::transaction::fees::{FeeRule as _, transparent, zip317};

use crate::state::AdvanceStep;
use crate::{
    denomination::{
        DESTINATION_ACTIONS_PER_TRANSFER, DenominationPlan, SOURCE_ACTIONS_PER_TRANSFER,
        plan_denominations,
    },
    preparation::{PREP_TX_ACTIONS, PrepError, PrepInput, PreparationPlan, plan_preparation},
    scheduling::{self, Schedule},
    signing_rounds::{
        MinRounds, PlannedSigningRound, PlannedTx, SigningRoundBudget, SigningRoundStrategy,
        min_budget_for_rounds, min_signing_rounds,
    },
};

/// The estimated number of blocks for a preparation layer's LAST scheduled transaction to mine and
/// become spendable: mining latency plus the wallet's witness-sync and next-broadcast turnaround, a
/// few 75-second block intervals. Preparation transactions are fully shielded self-sends, so
/// successive layers need only TEMPORAL serialization (the predecessor mined and witnessable) —
/// they do not wait for anchor-bucket boundaries, which only the pool-crossing transfers anchor to.
/// Appended after each layer's last scheduled broadcast to base the next layer's schedule, and
/// after the final layer's to lower-bound the transfer schedule (see [`plan_migration`]); an
/// under-estimate is self-healing (the commit-time anchor draw re-checks and reports a stale plan),
/// an over-estimate merely delays the follow-on schedule.
const EST_PREP_LAYER_MINING_BLOCKS: u32 = 10;

/// What the migration engine needs from a wallet to PLAN a migration: the account's spendable notes and
/// the chain state. Following the `zcash_client_backend` pattern, a later slice replaces this with the
/// wallet's own note-source and chain-view traits (`WalletRead` / `InputSource`), so any such wallet is a
/// migration wallet; for now a backend implements it directly over its note store and chain view.
pub trait MigrationBackend {
    /// The backend's own error type (a store or chain-access failure).
    type Error;

    /// The values of the account's spendable source-pool (Orchard) notes. The migration decomposes
    /// their total into denominations; the same notes are later spent by the preparation
    /// transactions, so the values must line up with what the build step will resolve to witnesses.
    fn spendable_orchard_note_values(&self) -> Result<Vec<Zatoshis>, Self::Error>;

    /// The current chain-tip height, from which the transfer schedule's delays accumulate.
    fn chain_tip_height(&self) -> Result<BlockHeight, Self::Error>;

    /// The parameters this backend's migrations are scheduled under: the anchor bucket grid and the
    /// transfer and preparation inter-arrival delays.
    ///
    /// The engine never takes these as its own argument; it asks the backend, because the anchor
    /// bucket interval is not free to choose. A transfer proves against the note commitment tree
    /// state at the boundary it anchored to, which requires the wallet to have RETAINED that
    /// boundary's checkpoint. Sourcing the interval from the same backend that performs the
    /// retention is what makes the two grids incapable of disagreeing; a backend that returns an
    /// interval it does not retain on will produce transfers it cannot prove.
    ///
    /// A backend on the production network must return [`SchedulingParams::ZIP_318`].
    ///
    /// [`SchedulingParams::ZIP_318`]: crate::scheduling::SchedulingParams::ZIP_318
    fn scheduling_params(&self) -> crate::scheduling::SchedulingParams;
}

/// Read access to a persisted pool migration: the store side of the migration interface, mirroring
/// `zcash_client_backend`'s `WalletRead`. A store implements this over its own tables
/// (`zcash_client_sqlite`'s `pool_migration` module does so over tables registered into its
/// `WalletDb` schema). The committed migration is a set of pre-signed PCZTs plus their schedule and
/// lifecycle state, so a wallet resumes a migration entirely from the store after being closed or
/// restarted.
pub trait PoolMigrationRead {
    /// The store's own error type.
    type Error;

    /// The migration currently in progress, if any.
    fn get_migration(&self) -> Result<Option<MigrationState>, Self::Error>;

    /// Report whether the environment this store lives in obstructs the given pre-signed
    /// transaction, as observed at the wallet's fully-scanned height. Implementations answer the
    /// MECHANICAL question — per cached spend nullifier
    /// ([`spend_nullifiers`](MigrationTransaction::spend_nullifiers)): is the note unspent, seen
    /// spent in a mined transaction, known with a dead unmined creator, or unknown; plus the
    /// transaction-level expiry judgment, and, for a broadcast-unmined transaction, whether its
    /// installed anchor survives on the current chain judged settled per `settle` — and compose
    /// [`classify_input_observations`]. The judgment of what to DO with an answer is made once,
    /// in this crate. An empty nullifier cache on a non-mined transaction is CORRUPTION (see
    /// [`classify_input_observations`]) and surfaces the store's own error, never an answer.
    ///
    /// # Precondition
    ///
    /// The store answers for the environment of the WALLET THAT COMMITTED the migration, and that
    /// wallet's scanned height does not regress in normal operation: a chain rollback reaches this
    /// state through [`MigrationState::truncate_to_height`], which withdraws the determinations
    /// resting on the discarded region rather than leaving the store to answer as though they were
    /// still backed. An implementation may therefore treat its `as_of` as monotone between
    /// truncations, and every answer it gives rests on evidence at or below that height. Asking a
    /// store about a migration committed by some other wallet is outside the contract: the two
    /// have neither the same notes nor the same scan history, so the answers would describe a
    /// different environment than the one the transaction must execute in.
    fn check_step_satisfiability(
        &self,
        tx: &MigrationTransaction,
        settle: ReorgSettleDepth,
    ) -> Result<StepSatisfiability, Self::Error>;
}

/// Write access to a persisted pool migration, mirroring `zcash_client_backend`'s `WalletWrite`.
pub trait PoolMigrationWrite: PoolMigrationRead {
    /// Persist a committed migration: every transaction as its pre-signed PCZT plus the metadata the
    /// application needs to prove, schedule, and broadcast it. Storing the pre-signed transactions, not
    /// just the plan, is what lets a wallet resume a migration after being closed or restarted.
    fn replace_migration(&mut self, state: &MigrationState) -> Result<(), Self::Error>;

    /// Advance one stored transaction's lifecycle state (for example after the application broadcasts
    /// it, or the chain mines it).
    fn update_transaction(
        &mut self,
        id: MigrationTransferId,
        state: MigrationTxState,
    ) -> Result<(), Self::Error>;
}

/// Drive-level policy for [`advance_migration`]: a struct, so future knobs join without signature
/// churn.
#[derive(Clone, Copy, Debug)]
pub struct AdvanceConfig {
    /// The caller's reorg-settlement policy; see [`ReorgSettleDepth`]. Explicitly required — no
    /// `Default` — because the right value tracks the chain's block spacing, and keeping it
    /// current is the caller's responsibility, not this crate's.
    pub reorg_settle_depth: ReorgSettleDepth,
}

/// Decide the next step to advance a committed migration and VERIFY it against the store before
/// surfacing it: the entry point a consuming application drives a migration with, at
/// `target_height` (`chain_tip + 1`, the height of the next block a transaction could be mined
/// in).
///
/// A single call plans, verifies, records, and persists:
///
/// 0. It adjudicates any standing BROADCAST-FAILURE REPORT
///    ([`MigrationState::report_broadcast_failure`]) — a node rejected a broadcast, and the
///    rejection is another observer's testimony until this wallet has scanned the chain state it
///    rests on. While the oracle still answers from below the reported tip the call surfaces
///    [`AdvanceStep::Reevaluate`] and does nothing else; once it answers from at or above that
///    tip the report is discharged, either recording the ordinary evidence-backed mark or
///    finding the rejection transient and returning the transaction to the broadcast queue in
///    this same call.
/// 1. It asks the planning kernel what to do next, decided purely from the persisted state.
/// 2. It puts the transaction the kernel names to the store's satisfiability oracle
///    ([`PoolMigrationRead::check_step_satisfiability`]) — the wallet's live view of whether that
///    pre-signed artifact can still execute.
/// 3. A candidate the wallet reports PERMANENTLY obstructed (its inputs seen spent elsewhere, or
///    unable to ever exist) is recorded through [`MigrationState::record_satisfiability`], and the
///    kernel is asked again — the recorded marks, and everything stranded behind them, now
///    filtered out of its queues. A candidate the wallet cannot YET vouch for is set aside for the
///    rest of this call (no mark: the honest reading of "retry after further sync"), so the
///    migration's other work still surfaces, and the kernel is asked again.
/// 4. The step that survives verification is returned, with every determination made along the way
///    already written back to the store.
///
/// So a consumer never spends proving or broadcast work on a transaction whose inputs are gone,
/// and a migration whose plan has been undercut — most often by an ordinary wallet spend consuming
/// notes it had allocated — surfaces [`AdvanceStep::Replan`] instead of retrying a dead
/// transaction forever.
///
/// # The drive loop
///
/// One call returns ONE step. The consumer performs that step's I/O, records the outcome in the
/// state, persists it, and calls this again; until the state records the step's completion, the
/// same step is offered again. The steps map onto the crate's operations as follows:
///
/// - [`AdvanceStep::Prove`]: install the transaction's deferred anchor and witnesses and store the
///   proven PCZT — [`prove_transfer`] / [`prove_preparation`], which also record the
///   `Signed -> Proved` transition. Proving needs a SYNCED wallet and mutable access to its
///   commitment trees, but only the account's viewing key. The step carries the transaction's kind
///   so the consumer can tell, without a lookup, whether the broadcast follows in the same session
///   (a preparation) or in its own later one (a transfer).
/// - [`AdvanceStep::Broadcast`]: submit the stored proven transaction to the network, then record
///   it with [`MigrationState::mark_broadcast`]. Its mining is later detected through the
///   consumer's own chain view and recorded with [`MigrationState::mark_mined`], which is what
///   unblocks the transactions depending on it.
/// - [`AdvanceStep::Rebuild`]: construct and sign a replacement for an expired transfer —
///   [`rebuild_expired_transfer`] or its unsigned (external-signer) variant. The only step that
///   needs the account's SPEND AUTHORITY.
/// - [`AdvanceStep::Replan`]: the migration itself needs replacing — mark it superseded
///   ([`MigrationState::mark_superseded`]), persist, and re-plan the remaining balance through the
///   ordinary planning flow. Surfaced when the unsatisfiable share of planned transfer value
///   strictly exceeds the committed [`ReplanThreshold`], and — once no live work remains at all —
///   when dead value would otherwise be stranded.
/// - [`AdvanceStep::Reevaluate`]: SYNC the wallet to at least the tip reported alongside a
///   rejected broadcast, then call this again. Surfaced ahead of every step but
///   [`Complete`](AdvanceStep::Complete), and unconditionally: a rejection means another observer
///   saw chain state this wallet has not, and same-seed activity invalidates the whole store
///   view rather than one transaction's answer.
/// - [`AdvanceStep::Waiting`]: nothing is actionable at this height. Consult
///   [`MigrationState::transaction_statuses`] for what each transaction is blocked on, and register
///   the heights at which to wake and re-check: [`MigrationState::sync_wakeup_schedule`] for the
///   proving wake-ups, plus each transaction's own scheduled broadcast height.
/// - [`AdvanceStep::Complete`]: the migration is terminal (every transaction mined, or the
///   migration failed/cancelled); nothing will ever be actionable again, so stop polling.
///
/// A transaction that can never mine is never named: those marked unsatisfiable, those expired
/// without mining, and everything stranded behind either are excluded from the prove, broadcast,
/// and rebuild queues alike. And a DUE BROADCAST is named ahead of any proving work, which is what
/// makes a broadcast-only waking session possible (see the ZIP 318 note below).
///
/// # The `target_height` contract
///
/// `target_height` must come from the consumer's CHAIN VIEW — its synced or otherwise observed
/// block data — and never from a wall-clock ESTIMATE of where the tip has probably reached. The
/// height is not merely a scheduling cursor: it is the height every judgment in this call is made
/// at, and each of those judgments is destructive if made too high.
///
/// - EXPIRY is `expiry_height < target_height`, so an estimate that overshoots condemns a live
///   pre-signed transfer as expired, and its remedy is a rebuild that must be SIGNED ANEW.
/// - Expired-and-unmined transactions SEED the kernel's dead set, so the same overshoot strands
///   every dependent behind them.
/// - The durable dependency closure ([`MigrationState::record_satisfiability`]) stamps inherited
///   marks off those seeds, writing them into the store.
/// - The drain-time [`Replan`](AdvanceStep::Replan) fires once every unmined transaction is dead,
///   and the consumer's contracted response to it — [`MigrationState::mark_superseded`] — is
///   terminal.
/// - [`Rebuild`](AdvanceStep::Rebuild) eligibility is judged the same way.
///
/// Nothing here compensates for an estimate, because nothing can: the state machine cannot tell a
/// guess from an observation. Accelerating the SCHEDULE from an estimate — waking early because
/// the tip has probably arrived — is a coherent thing to want and deliberately out of scope here;
/// it belongs in a dedicated, clamped parameter that can reach the dueness comparison without
/// touching expiry, the dead set, or the rebuild queue.
///
/// # What a call costs
///
/// Checking is LAZY UNTIL FIRST DISCOVERY and BROAD AT DISCOVERY, so a healthy migration pays
/// almost nothing:
///
/// - the in-flight sweep — one query per broadcast-but-unmined transaction, judging whether a
///   settled reorg has permanently invalidated the anchor it was proven against. The broadcast
///   schedule keeps that set tiny (typically none to two transactions sit between broadcast and
///   mining), and it is the only check for transactions the kernel will never name as a step;
/// - one query for the candidate the kernel names — and none at all when the kernel answers
///   [`Waiting`](AdvanceStep::Waiting), [`Complete`](AdvanceStep::Complete), or
///   [`Replan`](AdvanceStep::Replan), which name no transaction.
///
/// A discovery costs more, deliberately: it also checks every pending transaction whose
/// dependencies have mined. That is what makes the migration's remaining value re-assessed in the
/// call that finds the first dead transaction — a send-max that consumed the funding notes trips
/// the replan threshold immediately, rather than one transfer at a time over the weeks a
/// privacy-preserving broadcast schedule spans.
///
/// # Persistence, and what the consumer owns
///
/// This function owns the persistence of the determinations it makes: whenever a check recorded
/// anything, the state is written back with [`PoolMigrationWrite::replace_migration`] BEFORE the
/// step is returned, so the store already agrees with the returned `state` when the consumer acts.
/// Nothing is written when nothing was discovered.
///
/// On an `Err`, treat the passed `state` as UNTRUSTED and re-read it with
/// [`get_migration`](PoolMigrationRead::get_migration) before driving again. A failing store
/// leaves the two views free to disagree in one direction: the store never holds a determination
/// the returned state lacks, but the reverse can happen — a write that failed, or in-flight-sweep
/// marks left unpersisted by a later oracle failure, live only in the in-memory state. Discarding
/// it costs nothing, because marks are re-derivable: the next call asks the same questions again.
///
/// Everything else remains the consumer's: it performs the returned step's I/O and records the
/// outcome through the ordinary mutators ([`MigrationState::mark_broadcast`],
/// [`MigrationState::mark_mined`], the prove and rebuild functions), persisting afterwards as
/// usual, then calls this again. In particular, the ZIP 318 separation of SYNC wake-ups from
/// BROADCAST wake-ups is the consumer's runtime policy. Broadcasting a stored proven transaction
/// needs no sync at all, while proving is inherently sync-bound, so surfacing every due broadcast
/// first is what lets a wallet wake, submit, and end the session without initiating sync
/// operations. But this function itself has no notion of a session — once every due broadcast is
/// dispatched it offers proving work in the same loop — so a wallet honoring the separation stops
/// driving the migration after broadcasting and leaves the offered proving work to its next sync
/// wake-up.
pub fn advance_migration<St: PoolMigrationWrite>(
    store: &mut St,
    state: &mut MigrationState,
    target_height: BlockHeight,
    config: &AdvanceConfig,
) -> Result<AdvanceStep, St::Error> {
    // Whether any determination has been recorded, and so whether the state must be written back
    // before a step is surfaced.
    let mut dirty = false;
    // This call's deferrals: candidates the wallet answered `NotYetSatisfiable` for. They carry no
    // mark — the answer is "retry after further sync", not an obstruction — so the list lives only
    // for this call.
    let mut set_aside: Vec<MigrationTransferId> = Vec::new();

    // The IN-FLIGHT SWEEP. A broadcast-but-unmined transaction is never named as a step, so no
    // candidate check would ever reach it; its liveness question is whether the anchor it was
    // PROVEN against still exists on the chain, which only a settled reorg answers no to. That is
    // `AnchorInvalidated`, and it is the ONLY cause this sweep records:
    //
    // - `InputsSpent` about an in-flight transaction is most likely the transaction ITSELF, seen
    //   spending its own inputs in the block that mined it while this state still says
    //   `Broadcast` (the consumer's `mark_mined` lags the wallet's scan). Marking on it would
    //   kill a transaction that is mining.
    // - `InputsInvalidated` and `Expired` are DELIBERATELY deferred rather than acted on here.
    //   Their loss is bounded: a producer inside the migration reaches its victim through the
    //   dependency closure, and a victim of an EXTERNAL producer self-heals at its own expiry,
    //   when the kernel's derived expiry makes it a dead-set seed. The pending-side channel — a
    //   candidate check, or the broaden sweep after any discovery — is where an input-level cause
    //   is a determination.
    //
    // One consequence to keep in view: the answer precedence puts `InputsSpent` above the
    // anchor-level cause, so a store that observes BOTH a spent input and a dead anchor reports
    // `InputsSpent`, which this sweep drops. That transaction's death then surfaces at its expiry
    // rather than now — later, never wrong.
    let mut findings: Vec<(MigrationTransferId, StepSatisfiability)> = Vec::new();
    for tx in state.transactions() {
        if !matches!(tx.state(), MigrationTxState::Broadcast { .. })
            || tx.unsatisfiable_at().is_some()
        {
            continue;
        }
        let answer = store.check_step_satisfiability(tx, config.reorg_settle_depth)?;
        if matches!(
            &answer,
            StepSatisfiability::Unsatisfiable {
                cause: UnsatisfiableCause::AnchorInvalidated,
                ..
            }
        ) {
            findings.push((tx.id(), answer));
        }
    }
    if !findings.is_empty() {
        state.record_satisfiability(target_height, &findings);
        dirty = true;
    }

    // ADJUDICATING THE BROADCAST-FAILURE REPORTS. A report says a node refused a broadcast at a
    // tip this wallet may not have reached; it is testimony, so nothing is concluded from it
    // until the wallet's own answers rest at or above that tip. One query per reported
    // transaction, and none at all for the overwhelmingly common case of no reports.
    //
    // Skipped entirely for a TERMINAL migration: it is never driven further, so there is no
    // broadcast to withhold and no benefit in holding the loop at `Reevaluate` instead of the
    // `Complete` the kernel is about to return.
    let mut reevaluation_pending = false;
    if !state.is_terminal() {
        let mut adjudicated: Vec<MigrationTransferId> = Vec::new();
        let mut verdicts: Vec<(MigrationTransferId, StepSatisfiability)> = Vec::new();
        for tx in state.transactions() {
            let Some(reported_tip) = tx.broadcast_failure_at() else {
                continue;
            };
            let answer = store.check_step_satisfiability(tx, config.reorg_settle_depth)?;
            if answer_as_of(&answer) < reported_tip {
                // The wallet has not scanned every block that could hold the spend behind the
                // rejection, so neither answer it could give would be about the right chain.
                reevaluation_pending = true;
                continue;
            }
            // At or above the reported tip the question is settled, whichever way it fell: a
            // marking cause records the ordinary evidence-backed determination, and anything
            // else means the rejection was transient (a mempool conflict, a node-local policy)
            // and the transaction returns to the broadcast queue in this same call. Either way
            // the testimony has been discharged and must not withhold the transaction again.
            adjudicated.push(tx.id());
            if records_a_determination(&answer) {
                verdicts.push((tx.id(), answer));
            }
        }
        if !verdicts.is_empty() {
            // A DISCOVERY here broadens exactly as one at a candidate check does: what killed
            // this transaction is a fact about the migration's environment — same-seed spending
            // typically kills several transfers at once — so the whole damage is assessed in the
            // call that finds the first of it, and the replan threshold trips here rather than
            // one broadcast attempt at a time.
            broaden_after_discovery(store, state, &mut verdicts, config.reorg_settle_depth)?;
            state.record_satisfiability(target_height, &verdicts);
        }
        for id in &adjudicated {
            state.clear_broadcast_failure(*id);
        }
        dirty |= !adjudicated.is_empty();
    }
    if reevaluation_pending {
        // Unconditional: a rejection means some other observer saw chain state this wallet has
        // not, and same-seed activity invalidates the whole store view rather than one
        // transaction's answer. Whatever was adjudicated above is still persisted first.
        if dirty {
            store.replace_migration(state)?;
        }
        return Ok(AdvanceStep::Reevaluate);
    }

    // Plan, verify, record, plan again. Every iteration either breaks, grows `set_aside`, or
    // strictly grows the marked set — strictly, because the kernel never names an already-marked
    // transaction (they are in its dead set), so a recorded discovery marks at least the candidate
    // that produced it. Both are bounded by the transaction count, so the loop terminates.
    let step = loop {
        let step = state.next_step(target_height, &set_aside);
        let candidate = match step {
            AdvanceStep::Prove { id, .. }
            | AdvanceStep::Broadcast { id }
            | AdvanceStep::Rebuild { id } => id,
            // These name no transaction, so there is nothing to verify. `Reevaluate` is decided
            // above, by this function, and the kernel never returns it — but it is a step like
            // any other here, and matching it explicitly keeps that fact from resting on the
            // absence of an arm.
            AdvanceStep::Waiting
            | AdvanceStep::Complete
            | AdvanceStep::Replan
            | AdvanceStep::Reevaluate => break step,
        };
        let Some(tx) = state.transactions().iter().find(|t| t.id() == candidate) else {
            // The kernel names its candidates out of `state.transactions()`, so an id that is not
            // there means the state is corrupt. Nothing can be verified about it and nothing may
            // be surfaced unverified, so the call reports `Waiting` — the safe degradation, and a
            // BREAK rather than another iteration, which leaves no way for a corrupt state to
            // spin the loop. Anything already recorded is still persisted below.
            break AdvanceStep::Waiting;
        };
        let answer = store.check_step_satisfiability(tx, config.reorg_settle_depth)?;
        match answer {
            StepSatisfiability::Satisfiable { .. } => break step,
            // Not an obstruction: the wallet cannot yet vouch for the inputs (their source is
            // unmined, or mined but unscanned). Take the candidate out of this call's queues so
            // the migration's other work still surfaces, and leave no mark — a false mark would
            // strand live value behind an observation only a reorg can clear.
            StepSatisfiability::NotYetSatisfiable { .. } => set_aside.push(candidate),
            answer @ StepSatisfiability::Unsatisfiable { .. } => {
                if !records_a_determination(&answer) {
                    // `Expired`: never overrides the kernel, which derives expiry itself from the
                    // same `expiry_height`. The two can disagree only under caller/store height
                    // skew, and there the kernel's `target_height` governs, so the step stands
                    // exactly as planned (for a transfer, the rebuild that is expiry's remedy).
                    break step;
                }
                // A DISCOVERY, so BROADEN, then record as ONE batch so the durable closure runs
                // once over the whole discovery.
                let mut batch = vec![(candidate, answer)];
                broaden_after_discovery(store, state, &mut batch, config.reorg_settle_depth)?;
                state.record_satisfiability(target_height, &batch);
                dirty = true;
            }
        }
    };

    // A determination is durable by the time the step it produced is surfaced: the consumer acts
    // on that step and persists its own outcome, and must not be able to lose the marks this call
    // discovered along the way.
    if dirty {
        store.replace_migration(state)?;
    }
    Ok(step)
}

/// Whether a satisfiability answer is a DISCOVERY for [`advance_migration`] to record and broaden
/// on: an obstruction whose cause marks ([`UnsatisfiableCause::marks`], the single definition of
/// that decision). The satisfiable and not-yet answers are not determinations at all.
fn records_a_determination(answer: &StepSatisfiability) -> bool {
    matches!(answer, StepSatisfiability::Unsatisfiable { cause, .. } if cause.marks())
}

/// The fully-scanned height a satisfiability answer rests on, whichever answer it is: the height
/// that decides whether the answer is ABOUT the chain state a question was raised at.
fn answer_as_of(answer: &StepSatisfiability) -> BlockHeight {
    match answer {
        StepSatisfiability::Satisfiable { as_of }
        | StepSatisfiability::NotYetSatisfiable { as_of }
        | StepSatisfiability::Unsatisfiable { as_of, .. } => *as_of,
    }
}

/// Grows `batch` — the determinations [`advance_migration`] has already discovered this call —
/// with every OTHER determination the store will report right now, so a whole discovery is
/// assessed at once.
///
/// What killed one transaction is a fact about the migration's ENVIRONMENT, not about that
/// transaction alone: the ordinary cause is a wallet spend consuming notes the migration had
/// allocated, which typically kills several transfers together. Finding the rest of the damage in
/// the same call is what lets the replan threshold trip immediately rather than one transfer at a
/// time over the weeks a privacy-preserving broadcast schedule spans.
///
/// Every PENDING transaction whose dependencies have mined is checked, and nothing else: a
/// transaction already in `batch` has been answered, mined ones are final, in-flight ones belong
/// to the drive API's own in-flight sweep, already-marked ones would learn nothing, and one whose
/// dependencies are still unmined could only answer "not yet" (its death, if any, arrives through
/// the durable dependency closure).
fn broaden_after_discovery<St: PoolMigrationRead>(
    store: &St,
    state: &MigrationState,
    batch: &mut Vec<(MigrationTransferId, StepSatisfiability)>,
    settle: ReorgSettleDepth,
) -> Result<(), St::Error> {
    for tx in state.transactions() {
        if batch.iter().any(|(id, _)| *id == tx.id())
            || matches!(
                tx.state(),
                MigrationTxState::Broadcast { .. } | MigrationTxState::Mined { .. }
            )
            || tx.unsatisfiable_at().is_some()
            || !state.deps_mined(tx.depends_on())
        {
            continue;
        }
        let answer = store.check_step_satisfiability(tx, settle)?;
        if records_a_determination(&answer) {
            batch.push((tx.id(), answer));
        }
    }
    Ok(())
}

/// A stable ordinal identifier for a migration transaction within a migration. This is a ROW KEY
/// into the persisted migration (usable before a transaction is built, when no [`TxId`] exists yet:
/// deferred preparation layers and transfers are recorded as unbuilt placeholders); it is NOT a
/// Zcash transaction id. The real [`TxId`] becomes available once a transaction is built and signed
/// (it commits only effecting data), and is carried by [`MigrationTxState::Broadcast`].
///
/// The two identities are not interchangeable, and this one is the one to key on. A [`TxId`]
/// identifies a single broadcast ATTEMPT: [`rebuild_expired_transfer`] keeps this id while
/// producing a new transaction with a new [`TxId`], so a consumer that keyed its own records on
/// the [`TxId`] loses track of the transfer exactly when it most needs to follow it. Use the
/// [`TxId`] to talk to the network about a transaction, and this id to talk about the transfer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MigrationTransferId(pub(crate) u32);

impl MigrationTransferId {
    /// Wrap a stored ordinal as a migration-transaction row key (for a store reading a persisted
    /// migration back).
    pub const fn new(index: u32) -> Self {
        MigrationTransferId(index)
    }

    /// Writes this id as an unsigned 32-bit little-endian integer.
    pub fn write<W: io::Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_all(&self.0.to_le_bytes())
    }

    /// Reads an id written by [`write`](Self::write).
    pub fn read<R: io::Read>(mut reader: R) -> io::Result<Self> {
        let mut bytes = [0u8; 4];
        reader.read_exact(&mut bytes)?;
        Ok(MigrationTransferId::new(u32::from_le_bytes(bytes)))
    }
}

impl From<MigrationTransferId> for u32 {
    fn from(id: MigrationTransferId) -> u32 {
        id.0
    }
}

/// What a migration transaction does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MigrationTxKind {
    /// A note-preparation transaction: the `index`-th transaction of preparation `layer`.
    Preparation { layer: usize, index: usize },
    /// A phase-2 pool-crossing transfer of the `crossing`-th funding note.
    Transfer { crossing: usize },
}

impl AsRef<str> for MigrationTxKind {
    /// The stable lowercase wire name of this kind, as a store persists it (the queryable
    /// discriminant); the per-variant indices are stored alongside and reattached by
    /// [`from_stored`](Self::from_stored).
    fn as_ref(&self) -> &str {
        match self {
            MigrationTxKind::Preparation { .. } => "preparation",
            MigrationTxKind::Transfer { .. } => "transfer",
        }
    }
}

impl MigrationTxKind {
    /// The `(layer, index)` of a [`Preparation`](Self::Preparation) kind (its stored indices), or
    /// `None` for a [`Transfer`](Self::Transfer).
    pub fn preparation_indices(&self) -> Option<(usize, usize)> {
        match self {
            MigrationTxKind::Preparation { layer, index } => Some((*layer, *index)),
            MigrationTxKind::Transfer { .. } => None,
        }
    }

    /// The `crossing` of a [`Transfer`](Self::Transfer) kind (its stored index), or `None` for a
    /// [`Preparation`](Self::Preparation).
    pub fn transfer_crossing(&self) -> Option<usize> {
        match self {
            MigrationTxKind::Transfer { crossing } => Some(*crossing),
            MigrationTxKind::Preparation { .. } => None,
        }
    }

    /// Reconstruct a kind from the stored discriminant (the [`AsRef<str>`](AsRef) value) and the
    /// per-variant index columns (each `None` for the variant that does not carry it). Errors on an
    /// unrecognized discriminant, or a discriminant whose index columns are absent.
    pub fn from_stored(
        kind: &str,
        layer: Option<usize>,
        index: Option<usize>,
        crossing: Option<usize>,
    ) -> Result<Self, ParseMigrationTxKindError> {
        Ok(match kind {
            "preparation" => MigrationTxKind::Preparation {
                layer: layer.ok_or(ParseMigrationTxKindError)?,
                index: index.ok_or(ParseMigrationTxKindError)?,
            },
            "transfer" => MigrationTxKind::Transfer {
                crossing: crossing.ok_or(ParseMigrationTxKindError)?,
            },
            _ => return Err(ParseMigrationTxKindError),
        })
    }
}

/// The error returned when a stored `(kind, layer, index, crossing)` tuple does not reconstruct a
/// [`MigrationTxKind`] (its [`from_stored`](MigrationTxKind::from_stored) constructor): an
/// unrecognized discriminant, or a variant missing its index columns.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParseMigrationTxKindError;

impl fmt::Display for ParseMigrationTxKindError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("unrecognized or incomplete migration transaction kind")
    }
}

/// Where a migration transaction is in its lifecycle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MigrationTxState {
    /// Built and awaiting an EXTERNAL signature: its UNSIGNED PCZT is held in
    /// [`pczt`](MigrationTransaction::pczt), exported for a hardware or offline signer.
    /// [`apply_signature`](MigrationState::apply_signature) moves it to [`Signed`](Self::Signed) once the
    /// signed PCZT is returned. Only the external-signing path
    /// ([`build_preparation_unsigned`]) produces this state; the in-process commit function signs
    /// immediately and goes straight to [`Signed`](Self::Signed).
    AwaitingSignature,
    /// Pre-signed (the account's spend authorization is attached), not yet proved.
    Signed,
    /// Proved against a real anchor, ready to broadcast.
    Proved,
    /// Broadcast to the network, with its transaction id.
    Broadcast { txid: TxId },
    /// Mined at the given height, with the transaction id it was broadcast under.
    Mined { txid: TxId, height: BlockHeight },
}

/// One transaction of a committed migration: its pre-signed PCZT plus the metadata the consuming
/// application needs to prove it against a fresh anchor, wait for its dependencies, broadcast it at
/// its scheduled height, and track its state.
#[derive(Clone, Debug, PartialEq, Eq, Getters, CopyGetters)]
pub struct MigrationTransaction {
    /// This transaction's stable id.
    #[getset(get_copy = "pub")]
    pub(crate) id: MigrationTransferId,
    /// What it does (a preparation transaction or a transfer).
    #[getset(get_copy = "pub")]
    pub(crate) kind: MigrationTxKind,
    /// The serialized PCZT (`pczt::Pczt::serialize`), whose contents track the transaction's
    /// lifecycle: unsigned bytes while the transaction awaits an external signature
    /// ([`AwaitingSignature`](MigrationTxState::AwaitingSignature)), then the pre-signed PCZT
    /// with anchors and witnesses still deferred (ZIP 374), then — once the application proves
    /// it — the PROVEN PCZT, witnesses and anchors installed and proofs attached, ready to
    /// broadcast. Every transaction is built when the migration is committed — one signing
    /// phase — so this is always present.
    #[getset(get = "pub")]
    pub(crate) pczt: Vec<u8>,
    /// The transactions that must be mined before this one may be broadcast (the preparation layer
    /// dependency graph; empty for an independent transaction).
    #[getset(get = "pub")]
    pub(crate) depends_on: Vec<MigrationTransferId>,
    /// The height at which to broadcast (for a transfer; a preparation transaction waits for its
    /// dependencies to mine and a boundary to pass rather than a fixed height).
    #[getset(get_copy = "pub")]
    pub(crate) scheduled_height: BlockHeight,
    /// The height after which the transaction can no longer be mined (ZIP 203) and its part must
    /// be carried by an entirely new, freshly signed transaction: a transfer via
    /// [`rebuild_expired_transfer`] / [`rebuild_expired_transfer_unsigned`] (detection via
    /// [`MigrationState::expired_transactions`]); an expired preparation awaits its own
    /// remediation slice.
    #[getset(get_copy = "pub")]
    pub(crate) expiry_height: BlockHeight,
    /// The boundary height whose tree state the transaction proves against. For a transfer this is
    /// always present, drawn at SCHEDULING time: `plan_migration` floors the schedule so a
    /// candidate boundary exists for every transfer. `None` only for a preparation transaction
    /// (which waits on its dependencies rather than anchoring to a drawn boundary).
    #[getset(get_copy = "pub")]
    pub(crate) anchor_boundary: Option<BlockHeight>,
    /// The standing determination that this transaction is UNSATISFIABLE — its inputs can never
    /// again all exist unspent on chain — as ONE value: the height of the chain state the
    /// observation rests on, paired with WHAT was observed. `None` while no such determination
    /// stands. Orthogonal to the lifecycle state (a `Proved` transfer keeps its proof and renders
    /// as "proved, inputs spent"), mirroring how expiry is orthogonal to lifecycle.
    ///
    /// The height is the one the observation RESTS ON rather than the one it was recorded at,
    /// which is what gives reorg truncation exact semantics: a rewind below it invalidates the
    /// observation itself. The kind rides along so a wallet can say what killed a transaction
    /// without re-consulting the oracle (whose answer would by then rest on a later chain state
    /// anyway): a direct observation records its cause's [`kind`](UnsatisfiableCause::kind), a
    /// mark applied by the dependency closure records
    /// [`Inherited`](UnsatisfiableKind::Inherited). Holding them as one pair is what makes a
    /// stamp without a kind — or a kind without a stamp — unrepresentable.
    pub(crate) unsatisfiable: Option<(BlockHeight, UnsatisfiableKind)>,
    /// The standing BROADCAST-FAILURE REPORT: the chain tip the application observed from the
    /// node that REJECTED a broadcast of this transaction, or `None` while no rejection is
    /// outstanding. Recorded by [`MigrationState::report_broadcast_failure`] and discharged by
    /// the drive API once the wallet has scanned to that tip and could adjudicate the rejection.
    ///
    /// This is TESTIMONY, not evidence: another observer's report of chain state this wallet has
    /// not seen. It never produces an [`unsatisfiable`](Self::unsatisfiable) mark — marks rest on
    /// scanned state at or below an answer's `as_of`, which is what makes reorg truncation exact
    /// — and it carries no cause, because the engine verifies a rejection through channels it
    /// owns rather than trusting the node's stated reason. Its whole effect is to withhold the
    /// transaction from the broadcast queue and to hold the drive loop at
    /// [`Reevaluate`](crate::state::AdvanceStep::Reevaluate) until the wallet can answer.
    #[getset(get_copy = "pub")]
    pub(crate) broadcast_failure_at: Option<BlockHeight>,
    /// The nullifiers of this transaction's REAL spends — the deferred-witness actions; the
    /// padded dummy spends carry their own witnesses (ZIP 374) — extracted from the built PCZT
    /// when the migration is committed, BEFORE any proof. Proving replaces the stored bytes
    /// with the proven PCZT, whose real spends all carry installed witnesses and so are no
    /// longer identifiable there; from commit onward this cache is therefore the SOLE
    /// real-spend authority for the transaction's remaining life — consumers (the rebuild path,
    /// the unsatisfiability machinery) read it and never re-derive from the stored bytes. It
    /// also spares the feature-free state machine the `orchard`-gated `pczt` parsing.
    #[getset(get = "pub")]
    pub(crate) spend_nullifiers: Vec<[u8; 32]>,
    /// The transaction's lifecycle state.
    #[getset(get_copy = "pub")]
    pub(crate) state: MigrationTxState,
    /// The opaque lock-owner token under which this transaction's input notes are locked, or
    /// `None` if it holds no lock. These are the raw bytes of a wallet's
    /// `zcash_client_backend::wallet::LockOwner` (its `LockOwner::as_bytes()` /
    /// `LockOwner::new()` round-trip) — carried here as an opaque `[u8; 32]` rather than the typed
    /// `LockOwner` because this `orchard`-gated engine module must not depend on
    /// `zcash_client_backend` (only `wallet`-feature code does); the conversion to/from `LockOwner`
    /// happens at that boundary, not here. The migration flow does not yet acquire locks, so every
    /// transaction the engine itself builds carries `None`; a store still round-trips whatever a
    /// caller sets.
    #[getset(get_copy = "pub")]
    pub(crate) lock_owner: Option<[u8; 32]>,
}

impl MigrationTransaction {
    /// The standing unsatisfiability mark: the height of the chain state the observation rests on
    /// paired with what was observed, or `None` while this transaction is not determined
    /// unsatisfiable. [`unsatisfiable_at`](Self::unsatisfiable_at) and
    /// [`unsatisfiable_kind`](Self::unsatisfiable_kind) project its halves.
    pub fn unsatisfiable(&self) -> Option<(BlockHeight, UnsatisfiableKind)> {
        self.unsatisfiable
    }

    /// The height of the chain state a standing unsatisfiability observation rests on: the stamp
    /// half of [`unsatisfiable`](Self::unsatisfiable), and the height a truncation must reach
    /// below to clear the mark.
    pub fn unsatisfiable_at(&self) -> Option<BlockHeight> {
        self.unsatisfiable.map(|(at, _)| at)
    }

    /// WHY this transaction can never mine: the kind half of
    /// [`unsatisfiable`](Self::unsatisfiable), which a wallet renders without re-consulting the
    /// satisfiability oracle.
    pub fn unsatisfiable_kind(&self) -> Option<UnsatisfiableKind> {
        self.unsatisfiable.map(|(_, kind)| kind)
    }

    /// Reassemble a stored migration transaction from its persisted parts, exactly as a store read
    /// them back (the inverse of the accessors). A store that persists the unsatisfiability mark's
    /// halves in separate places must reject a row holding one without the other as corrupt on
    /// read, rather than reconstitute a pair here from half of one.
    ///
    /// `broadcast_failure_at` is independent of that mark in both directions: a rejected
    /// broadcast the wallet cannot yet explain carries no mark, and an adjudicated one carries a
    /// mark and no report.
    #[allow(clippy::too_many_arguments)]
    pub fn from_parts(
        id: MigrationTransferId,
        kind: MigrationTxKind,
        pczt: Vec<u8>,
        depends_on: Vec<MigrationTransferId>,
        scheduled_height: BlockHeight,
        expiry_height: BlockHeight,
        anchor_boundary: Option<BlockHeight>,
        state: MigrationTxState,
        lock_owner: Option<[u8; 32]>,
        unsatisfiable: Option<(BlockHeight, UnsatisfiableKind)>,
        spend_nullifiers: Vec<[u8; 32]>,
        broadcast_failure_at: Option<BlockHeight>,
    ) -> Self {
        Self {
            id,
            kind,
            pczt,
            depends_on,
            scheduled_height,
            expiry_height,
            anchor_boundary,
            state,
            lock_owner,
            unsatisfiable,
            spend_nullifiers,
            broadcast_failure_at,
        }
    }
}

/// The overall status of a migration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MigrationStatus {
    /// Planned and previewed, not yet committed (nothing built or signed).
    Planning,
    /// Built, pre-signed, and persisted; ready for the application to prove and broadcast.
    Committed,
    /// Some transactions have been broadcast or mined.
    InProgress,
    /// Every crossing has been mined. Chain-derived — exactly as revocable as the chain it was
    /// derived from — unlike the policy determinations `Failed` and `Superseded`.
    Complete,
    /// The migration failed and needs attention.
    Failed,
    /// Superseded by a re-plan of the remaining balance: terminal, set by
    /// [`MigrationState::mark_superseded`] as the consumer's response to a migration whose
    /// remaining value must be carried by a new plan. Like `Failed`, a POLICY determination —
    /// never revisited by chain state.
    Superseded,
}

impl AsRef<str> for MigrationStatus {
    /// The stable lowercase wire name of the status, as stored by a backend and parsed back with
    /// [`TryFrom<&str>`](Self). Borrow-free: it returns a `&'static str`, so encoding a status
    /// allocates nothing.
    fn as_ref(&self) -> &str {
        match self {
            MigrationStatus::Planning => "planning",
            MigrationStatus::Committed => "committed",
            MigrationStatus::InProgress => "in_progress",
            MigrationStatus::Complete => "complete",
            MigrationStatus::Failed => "failed",
            MigrationStatus::Superseded => "superseded",
        }
    }
}

/// The error returned when a string does not name a [`MigrationStatus`] (its [`TryFrom<&str>`] impl).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParseMigrationStatusError;

impl fmt::Display for ParseMigrationStatusError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("unrecognized migration status")
    }
}

impl TryFrom<&str> for MigrationStatus {
    type Error = ParseMigrationStatusError;

    /// Parses the lowercase wire name produced by [`AsRef<str>`](AsRef).
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Ok(match s {
            "planning" => MigrationStatus::Planning,
            "committed" => MigrationStatus::Committed,
            "in_progress" => MigrationStatus::InProgress,
            "complete" => MigrationStatus::Complete,
            "failed" => MigrationStatus::Failed,
            "superseded" => MigrationStatus::Superseded,
            _ => return Err(ParseMigrationStatusError),
        })
    }
}

/// The share of planned transfer value (an integer percent) above which a migration with
/// unsatisfiable transfers should be re-planned IMMEDIATELY rather than after satisfiable work
/// drains. Stamped on the migration at commit (like the anchor bucket grid), so every consumer
/// of the same state applies the same policy: the threshold governs a determination derived
/// from persisted marks, and two consumers of one migration must not disagree about it.
///
/// The two endpoints have distinct meanings: `0` triggers a replan as soon as ANY value is marked
/// unsatisfiable, however small; `100` never triggers immediately (the strict `>` in
/// [`MigrationState::replan_required`] can never be satisfied), so an unsatisfiable migration is
/// only ever re-planned once satisfiable work drains.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReplanThreshold(u8);

impl ReplanThreshold {
    /// The default policy: strictly more than 20% of planned transfer value unsatisfiable
    /// triggers an immediate replan.
    pub const DEFAULT: Self = Self(20);

    /// A threshold of `percent` (0 ..= 100), or `None` if `percent > 100`.
    pub const fn new(percent: u8) -> Option<Self> {
        if percent <= 100 {
            Some(Self(percent))
        } else {
            None
        }
    }

    /// The integer percent.
    pub const fn percent(&self) -> u8 {
        self.0
    }
}

/// How many blocks the chain must advance past a divergence before a displacement is treated as
/// PERMANENT. Caller policy, supplied to [`PoolMigrationRead::check_step_satisfiability`]: the
/// right value tracks the chain's block spacing (on the order of the sync wake-up settle margin —
/// minutes, not hours — at the current 75-second target), and keeping it current is the caller's
/// responsibility; this crate deliberately ships no default and never persists it. A displacement
/// judged settled under an aggressive depth self-corrects: the marks it produces are cleared by
/// reorg truncation if the chain swings back.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReorgSettleDepth(pub u32);

/// A store's answer to "does the environment this store lives in obstruct this pre-signed
/// transaction?" — see [`PoolMigrationRead::check_step_satisfiability`]. Deliberately EXHAUSTIVE:
/// executable now, not yet, or never is a complete classification of a step's disposition, and
/// the consumers' cause-dependent responses are compiler-forced over it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StepSatisfiability {
    /// Every queried input is among the account's unspent notes, and nothing else obstructs.
    Satisfiable {
        /// The fully-scanned height the observation rests on.
        as_of: BlockHeight,
    },
    /// Some input's nullifier corresponds to no note the wallet has seen — its source is not yet
    /// mined, or not yet scanned — or a known creator is unmined but still viable. Not an
    /// obstruction: retry after further sync.
    NotYetSatisfiable {
        /// The fully-scanned height the observation rests on.
        as_of: BlockHeight,
    },
    /// Permanently obstructed.
    Unsatisfiable {
        /// Why the step can never execute.
        cause: UnsatisfiableCause,
        /// The fully-scanned height the observation rests on.
        as_of: BlockHeight,
    },
}

/// Why a step can never execute. `#[non_exhaustive]`: new reasons a step can never execute (a
/// retention-grid change, note-lock conflicts) have a home without breaking consumers' matches.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UnsatisfiableCause {
    /// The wallet has seen these inputs spent: their nullifiers were recognized in mined
    /// transactions.
    InputsSpent {
        /// The affected inputs' nullifiers, in the cache's action order.
        nullifiers: Vec<[u8; 32]>,
    },
    /// The wallet knows notes for these inputs, but their creating transaction is unmined and can
    /// never mine: it was proven against an anchor a settled reorg permanently invalidated. The
    /// inputs will never exist on chain. Carries the invalidated anchor (raw root bytes) —
    /// evidence the caller cannot recover from the checked transaction itself, since it belongs
    /// to the producer.
    InputsInvalidated {
        /// The dead anchor's raw root bytes.
        anchor: [u8; 32],
    },
    /// The transaction's expiry height has passed without it mining (ZIP 203): the pre-signed
    /// artifact can never be included in a block.
    Expired,
    /// The transaction is broadcast but unmined, its installed anchor is no longer a root on the
    /// current chain, and the invalidating reorg is settled per the caller's
    /// [`ReorgSettleDepth`]: as proven, it can never be mined.
    AnchorInvalidated,
}

impl UnsatisfiableCause {
    /// The [`UnsatisfiableKind`] recorded alongside the mark this cause applies, or `None` for a
    /// cause that applies no mark ([`Expired`](Self::Expired), which only confirms a derivation
    /// the kernel already makes from the same
    /// [`expiry_height`](MigrationTransaction::expiry_height)).
    ///
    /// This is the single definition of BOTH decisions — whether to mark, and under which kind —
    /// so the stamp and the kind stored beside it cannot disagree about whether there is a mark at
    /// all. [`Inherited`](UnsatisfiableKind::Inherited) is never returned here: it names a mark
    /// that arrived through the dependency closure rather than from any observed cause.
    pub const fn kind(&self) -> Option<UnsatisfiableKind> {
        // Compiler-forced over the (in-crate exhaustive) cause vocabulary: a new cause must decide
        // here whether it is an observation to store — and under which kind — or a derivation to
        // confirm.
        match self {
            UnsatisfiableCause::InputsSpent { .. } => Some(UnsatisfiableKind::InputsSpent),
            UnsatisfiableCause::InputsInvalidated { .. } => {
                Some(UnsatisfiableKind::InputsInvalidated)
            }
            UnsatisfiableCause::AnchorInvalidated => Some(UnsatisfiableKind::AnchorInvalidated),
            UnsatisfiableCause::Expired => None,
        }
    }

    /// Whether this cause records a DURABLE mark: it reports chain state the state machine cannot
    /// re-derive (the input-level causes, and the anchor-level one), as opposed to
    /// [`Expired`](Self::Expired), which only confirms a derivation the kernel already makes from
    /// the same [`expiry_height`](MigrationTransaction::expiry_height).
    ///
    /// Derived from [`kind`](Self::kind) rather than restating its match, deliberately: both
    /// [`MigrationState::record_satisfiability`] (which applies the mark) and
    /// [`advance_migration`] (which decides whether an answer is a discovery worth recording and
    /// broadening on) must agree, because the drive loop's TERMINATION rests on their agreement —
    /// each recorded discovery must mark at least the candidate that produced it, or the loop
    /// could re-plan onto the same candidate forever. A second copy of this match could drift into
    /// exactly that hang.
    pub(crate) const fn marks(&self) -> bool {
        self.kind().is_some()
    }
}

/// WHY a transaction can never mine, as persisted beside its
/// [`unsatisfiable_at`](MigrationTransaction::unsatisfiable_at) stamp and rendered by a wallet: a
/// reduced discriminant of the [`UnsatisfiableCause`] that produced the mark, plus
/// [`Inherited`](Self::Inherited) for a mark the dependency closure applied.
///
/// The full cause is deliberately NOT persisted. Its variants carry evidence payloads — a spent
/// nullifier list, a dead anchor root — that nothing in the state machine ever reads back, and
/// that a store can re-derive by asking its oracle again; storing them would grow every marked row
/// by an unbounded list to answer a question consumers ask only in words. What a consumer needs
/// durably is which of these happened, which is what this records.
///
/// `#[non_exhaustive]`: this tracks the cause vocabulary, which is itself open, so a new marking
/// cause is expected to bring a new kind with it.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnsatisfiableKind {
    /// The wallet saw this transaction's own inputs spent: their nullifiers were recognized in
    /// mined transactions ([`UnsatisfiableCause::InputsSpent`]).
    InputsSpent,
    /// This transaction's own inputs will never exist on chain: the wallet knows notes for them,
    /// but their creating transaction is unmined and was proven against an anchor a settled reorg
    /// permanently invalidated ([`UnsatisfiableCause::InputsInvalidated`]).
    InputsInvalidated,
    /// This transaction is broadcast and unmined, and the anchor its OWN proof installed is no
    /// longer a root of the chain the wallet has scanned
    /// ([`UnsatisfiableCause::AnchorInvalidated`]).
    AnchorInvalidated,
    /// Nothing was observed about this transaction itself: the mark arrived through the DEPENDENCY
    /// CLOSURE (see [`MigrationState::record_satisfiability`]), because a transaction it depends
    /// on can never mine. Which dependency, and what killed it, is read off that dependency's own
    /// mark.
    Inherited,
}

impl AsRef<str> for UnsatisfiableKind {
    /// The stable lowercase wire name of this kind, as a store persists it. Borrow-free: it
    /// returns a `&'static str`, so encoding a kind allocates nothing.
    fn as_ref(&self) -> &str {
        match self {
            UnsatisfiableKind::InputsSpent => "inputs_spent",
            UnsatisfiableKind::InputsInvalidated => "inputs_invalidated",
            UnsatisfiableKind::AnchorInvalidated => "anchor_invalidated",
            UnsatisfiableKind::Inherited => "inherited",
        }
    }
}

/// The error returned when a string does not name an [`UnsatisfiableKind`] (its
/// [`TryFrom<&str>`] impl).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParseUnsatisfiableKindError;

impl fmt::Display for ParseUnsatisfiableKindError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("unrecognized unsatisfiability kind")
    }
}

impl TryFrom<&str> for UnsatisfiableKind {
    type Error = ParseUnsatisfiableKindError;

    /// Parses the lowercase wire name produced by [`AsRef<str>`](AsRef).
    ///
    /// The vocabulary is open — this enum is `#[non_exhaustive]` — but an unrecognized name is
    /// still an ERROR here, and a store surfaces it as corruption exactly as it does an
    /// unrecognized [`MigrationStatus`] or [`MigrationTxState`] discriminant. A name written by a
    /// future release is not a value this one can render or reason about, and treating it as
    /// "unmarked" would resurrect a dead transaction into the prove and broadcast queues, so it is
    /// reported rather than smoothed over.
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Ok(match s {
            "inputs_spent" => UnsatisfiableKind::InputsSpent,
            "inputs_invalidated" => UnsatisfiableKind::InputsInvalidated,
            "anchor_invalidated" => UnsatisfiableKind::AnchorInvalidated,
            "inherited" => UnsatisfiableKind::Inherited,
            _ => return Err(ParseUnsatisfiableKindError),
        })
    }
}

/// A store implementation's observation for one queried nullifier, fed to
/// [`classify_input_observations`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InputObservation {
    /// The note is known and unspent.
    Unspent,
    /// The note is known and the wallet has seen it spent in a mined transaction.
    SeenSpent,
    /// The note is known, its creating transaction is unmined, and that transaction's anchor was
    /// permanently invalidated (settled per the caller's policy). Carries the dead anchor root.
    Invalidated([u8; 32]),
    /// No note with this nullifier has been scanned, or its unmined creator is still viable.
    Unknown,
}

/// Fold per-nullifier observations, plus the transaction-level expiry judgment, into a
/// [`StepSatisfiability`], encoding the answer precedence: `InputsSpent` over
/// `InputsInvalidated` (both are permanent input-level deaths, and a recognized spend is the
/// definitive on-chain fact) over `Expired` (expiry's remedy — a rebuild, fresh proof included —
/// cannot cure missing inputs, so the input-level causes must dominate it) over
/// `NotYetSatisfiable` (anything definite dominates "try later") over `Satisfiable`.
///
/// Pure: an implementation supplies only its data access and composes with this, so the
/// classification is defined once. `AnchorInvalidated` is a transaction-level observation on
/// broadcast-unmined transactions, answered by the implementation directly rather than through
/// this per-input fold, and takes the precedence position below `Expired`. The observation set
/// must come from the transaction's [`spend_nullifiers`] cache, which is non-empty for every
/// validly committed transaction; implementations surface their corruption error for an empty
/// cache on a non-mined transaction rather than calling this with no observations (an empty
/// cache means a backfill-exempted mined row re-entered the watched set after a chain rewind, or
/// deeper corruption — never vacuous satisfiability).
///
/// [`spend_nullifiers`]: MigrationTransaction::spend_nullifiers
pub fn classify_input_observations(
    as_of: BlockHeight,
    expired: bool,
    observations: &[([u8; 32], InputObservation)],
) -> StepSatisfiability {
    let spent: Vec<[u8; 32]> = observations
        .iter()
        .filter(|(_, o)| matches!(o, InputObservation::SeenSpent))
        .map(|(nf, _)| *nf)
        .collect();
    if !spent.is_empty() {
        return StepSatisfiability::Unsatisfiable {
            cause: UnsatisfiableCause::InputsSpent { nullifiers: spent },
            as_of,
        };
    }
    if let Some(anchor) = observations.iter().find_map(|(_, o)| match o {
        InputObservation::Invalidated(a) => Some(*a),
        _ => None,
    }) {
        return StepSatisfiability::Unsatisfiable {
            cause: UnsatisfiableCause::InputsInvalidated { anchor },
            as_of,
        };
    }
    if expired {
        return StepSatisfiability::Unsatisfiable {
            cause: UnsatisfiableCause::Expired,
            as_of,
        };
    }
    if observations
        .iter()
        .any(|(_, o)| matches!(o, InputObservation::Unknown))
    {
        return StepSatisfiability::NotYetSatisfiable { as_of };
    }
    StepSatisfiability::Satisfiable { as_of }
}

impl AsRef<str> for MigrationTxState {
    /// The stable lowercase wire name of the lifecycle state, as a store persists it (the queryable
    /// discriminant); the `Broadcast` txid and `Mined` height are stored alongside and reattached by
    /// [`from_stored`](Self::from_stored).
    fn as_ref(&self) -> &str {
        match self {
            MigrationTxState::AwaitingSignature => "awaiting_signature",
            MigrationTxState::Signed => "signed",
            MigrationTxState::Proved => "proved",
            MigrationTxState::Broadcast { .. } => "broadcast",
            MigrationTxState::Mined { .. } => "mined",
        }
    }
}

/// The error returned when a stored `(state, txid, mined_height)` triple does not reconstruct a
/// [`MigrationTxState`] (its [`from_stored`](MigrationTxState::from_stored) constructor): an
/// unrecognized discriminant, or a `broadcast`/`mined` row missing its txid/height payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParseMigrationTxStateError;

impl fmt::Display for ParseMigrationTxStateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("unrecognized or incomplete migration transaction state")
    }
}

impl MigrationTxState {
    /// The transaction id of a [`Broadcast`](Self::Broadcast) or [`Mined`](Self::Mined) state (its
    /// stored payload), or `None` for any other state.
    pub fn broadcast_txid(&self) -> Option<[u8; 32]> {
        match self {
            MigrationTxState::Broadcast { txid } | MigrationTxState::Mined { txid, .. } => {
                Some(*txid.as_ref())
            }
            _ => None,
        }
    }

    /// The block height of a [`Mined`](Self::Mined) state (its stored payload), or `None` for any
    /// other state.
    pub fn mined_height(&self) -> Option<BlockHeight> {
        match self {
            MigrationTxState::Mined { height, .. } => Some(*height),
            _ => None,
        }
    }

    /// Reconstruct a state from a store: the lowercase discriminant produced by
    /// [`AsRef<str>`](AsRef), plus the `broadcast`/`mined` txid and `mined` height columns (each
    /// `None` for a state that does not carry it). Errors on an unrecognized discriminant, a
    /// `broadcast` discriminant missing its txid, or a `mined` discriminant missing either payload
    /// (a mined transaction is always broadcast under a txid first, so both are required together).
    pub fn from_stored(
        state: &str,
        txid: Option<[u8; 32]>,
        mined_height: Option<BlockHeight>,
    ) -> Result<Self, ParseMigrationTxStateError> {
        Ok(match state {
            "awaiting_signature" => MigrationTxState::AwaitingSignature,
            "signed" => MigrationTxState::Signed,
            "proved" => MigrationTxState::Proved,
            "broadcast" => MigrationTxState::Broadcast {
                txid: TxId::from_bytes(txid.ok_or(ParseMigrationTxStateError)?),
            },
            "mined" => MigrationTxState::Mined {
                txid: TxId::from_bytes(txid.ok_or(ParseMigrationTxStateError)?),
                height: mined_height.ok_or(ParseMigrationTxStateError)?,
            },
            _ => return Err(ParseMigrationTxStateError),
        })
    }
}

/// The persisted state of a migration: the denomination plan (for the preview and residual accounting) and
/// every transaction, each as its pre-signed PCZT and metadata. A wallet resumes a migration entirely
/// from this state after being closed or restarted; this is what a [`MigrationBackend`] stores.
#[derive(Clone, Debug, PartialEq, Eq, Getters, CopyGetters)]
pub struct MigrationState {
    /// The overall status.
    #[getset(get_copy = "pub")]
    pub(crate) status: MigrationStatus,
    /// The denomination decomposition (the denominations and residual).
    #[getset(get = "pub")]
    pub(crate) denominations: DenominationPlan,
    /// The preparation plan (its layers and direct-funding notes), retained for auditability and
    /// for rebuilding expired PREPARATION transactions (a follow-on slice). A
    /// `Preparation { layer, index }` transaction's spends resolve against
    /// `preparation.layers()[layer][index]`.
    #[getset(get = "pub")]
    pub(crate) preparation: PreparationPlan,
    /// Every migration transaction, in dependency order.
    #[getset(get = "pub")]
    pub(crate) transactions: Vec<MigrationTransaction>,
    /// The anchor bucket grid this migration was COMMITTED under, recorded so a later change to the
    /// wallet's anchor retention interval is caught as a typed error rather than surfacing as an
    /// unexplained missing checkpoint.
    ///
    /// Every transfer's [`anchor_boundary`](MigrationTransaction::anchor_boundary) lies on this
    /// grid. If the wallet is subsequently reconfigured, it stops retaining these boundaries'
    /// checkpoints and they are pruned, at which point the committed transfers become unprovable —
    /// so [`prove_transfer`] and the rebuild path reject the mismatch up front.
    #[getset(get_copy = "pub")]
    pub(crate) anchor_bucket_interval: crate::scheduling::AnchorBucketInterval,
    /// The replan threshold stamped when this migration was committed.
    #[getset(get_copy = "pub")]
    pub(crate) replan_threshold: ReplanThreshold,
}

impl MigrationState {
    /// Reassemble a persisted migration from its stored parts, exactly as a store read them back
    /// (the inverse of the accessors).
    pub fn from_parts(
        status: MigrationStatus,
        denominations: DenominationPlan,
        preparation: PreparationPlan,
        transactions: Vec<MigrationTransaction>,
        anchor_bucket_interval: crate::scheduling::AnchorBucketInterval,
        replan_threshold: ReplanThreshold,
    ) -> Self {
        Self {
            status,
            denominations,
            preparation,
            transactions,
            anchor_bucket_interval,
            replan_threshold,
        }
    }

    /// The self-funding note values (in zatoshi), one per crossing: a `Transfer { crossing }`
    /// transaction SPENDS `funding_notes()[crossing]`, of which the fee buffer pays that
    /// transaction's own fee and the remainder crosses into the destination pool. Derived from the
    /// denomination plan (each crossing value plus the fee buffer), so a store persists only that
    /// plan.
    ///
    /// This is a SPEND-side value: it is neither what arrives in the destination pool nor the round
    /// denomination the user consented to. To report what a transfer moves, use
    /// [`crossing_values`](Self::crossing_values), or
    /// [`transfer_crossing_value`](Self::transfer_crossing_value) for a single transaction.
    pub fn funding_notes(&self) -> Vec<Zatoshis> {
        self.denominations.migration_outputs()
    }

    /// The values (in zatoshi) that cross into the destination pool, one per crossing and
    /// index-aligned with [`funding_notes`](Self::funding_notes): each is its funding note less the
    /// fee buffer that funds the transfer's own fee, and so is one of the round denominations the
    /// user was shown at proposal time.
    ///
    /// This is the value to display for a transfer, and the one the receiving wallet's own
    /// accounting will agree with once the transfer mines.
    pub fn crossing_values(&self) -> &[Zatoshis] {
        self.denominations.crossing_values()
    }

    /// The value transaction `tx` crosses into the destination pool, or `None` when `tx` is not a
    /// transfer (a preparation transaction crosses nothing).
    ///
    /// Equivalent to indexing [`crossing_values`](Self::crossing_values) by the transaction's
    /// [`transfer_crossing`](MigrationTxKind::transfer_crossing) — the accessor to reach for when
    /// marshaling one stored transaction into a user-facing amount, so consumers do not re-derive
    /// the funding-note-minus-buffer arithmetic and get it wrong by a fee.
    pub fn transfer_crossing_value(&self, tx: &MigrationTransaction) -> Option<Zatoshis> {
        tx.kind()
            .transfer_crossing()
            .and_then(|crossing| self.crossing_values().get(crossing).copied())
    }

    /// Replace transfer `id`'s stored PCZT with its proven bytes and move it to
    /// [`Proved`](MigrationTxState::Proved). Called after [`prove_transfer`] installs the drawn
    /// anchor and witnesses and proves the transaction, so the durable artifact becomes the proven,
    /// ready-to-broadcast PCZT.
    #[cfg(feature = "orchard")]
    pub fn set_transaction_proved(&mut self, id: MigrationTransferId, proven_pczt: Vec<u8>) {
        for tx in &mut self.transactions {
            if tx.id() == id {
                tx.pczt = proven_pczt;
                tx.state = MigrationTxState::Proved;
                break;
            }
        }
    }
}

/// A planned migration, before anything is built, signed, or broadcast: the denomination split, the
/// preparation transactions that mint the funding notes, and the phase-2 transfer schedule. This is the
/// preview a wallet shows the user for consent (ZIP 318) to the pool-crossing amounts.
#[derive(Clone, Debug)]
pub struct MigrationPlan {
    denominations: DenominationPlan,
    preparation: PreparationPlan,
    prep_schedule: Vec<Vec<BlockHeight>>,
    schedule: Vec<Schedule>,
}

impl MigrationPlan {
    /// The denomination decomposition (the denominations and residual). It already reflects
    /// reconciliation against the preparation fees: when the fees did not fit the balance, the
    /// smallest denominations were dropped (left in the source pool) during the decomposition.
    pub fn denominations(&self) -> &DenominationPlan {
        &self.denominations
    }

    /// The funding-note values this migration will mint, one per phase-2 crossing. Derived from the
    /// denomination plan (each crossing value plus the fee buffer).
    ///
    /// A SPEND-side value, as on [`MigrationState::funding_notes`]: to display what a transfer
    /// moves, use [`crossing_values`](Self::crossing_values).
    pub fn funding_notes(&self) -> Vec<Zatoshis> {
        self.denominations.migration_outputs()
    }

    /// The values that cross into the destination pool, one per phase-2 crossing, index-aligned
    /// with both [`funding_notes`](Self::funding_notes) and [`schedule`](Self::schedule): each is
    /// its funding note less the fee buffer, and so is one of the round denominations to show the
    /// user for consent.
    pub fn crossing_values(&self) -> &[Zatoshis] {
        self.denominations.crossing_values()
    }

    /// The preparation transactions (in dependency layers) that mint the funding notes.
    pub fn preparation(&self) -> &PreparationPlan {
        &self.preparation
    }

    /// The preparation broadcast schedule, one height per preparation transaction, in the same
    /// `[layer][index]` shape as [`preparation`](Self::preparation)'s layers: exponential
    /// inter-arrival delays with the tighter preparation spacing (see
    /// [`SchedulingParams::preparation_delay`](scheduling::SchedulingParams::preparation_delay)),
    /// each layer based past
    /// the previous layer's last height plus a mining margin, so the transactions are temporally
    /// decoupled from one another while the layers stay serialized.
    pub fn prep_schedule(&self) -> &[Vec<BlockHeight>] {
        &self.prep_schedule
    }

    /// The phase-2 transfer schedule, one entry per funding note (its broadcast height and
    /// expiry), in SHUFFLED broadcast order (ZIP 318): the heights are deliberately not monotone
    /// in crossing index, so the on-chain temporal sequence of denominations is independent of
    /// the balance.
    pub fn schedule(&self) -> &[Schedule] {
        &self.schedule
    }

    /// Every transaction this plan will build, enumerated BEFORE building in the exact order the
    /// commit assigns [`MigrationTransferId`]s (each preparation layer in order, then each transfer by
    /// crossing), so a [`PlannedTx`]'s id equals the id the built transaction will carry. Each
    /// carries its [`action_weight`](crate::signing_rounds::action_weight). This is a pure function
    /// of the plan, recomputed on demand, so planning stays unchanged.
    pub fn planned_transactions(&self) -> Vec<PlannedTx> {
        let mut txs = Vec::with_capacity(self.total_transactions());
        let mut next = 0u32;
        for (layer, layer_txs) in self.preparation.layers().iter().enumerate() {
            for index in 0..layer_txs.len() {
                txs.push(PlannedTx::new(
                    MigrationTransferId::new(next),
                    MigrationTxKind::Preparation { layer, index },
                ));
                next += 1;
            }
        }
        for crossing in 0..self.transfer_tx_count() {
            txs.push(PlannedTx::new(
                MigrationTransferId::new(next),
                MigrationTxKind::Transfer { crossing },
            ));
            next += 1;
        }
        txs
    }

    /// The total number of transactions this plan builds and signs: its preparation transactions
    /// plus one pool-crossing transfer per funding note.
    pub fn total_transactions(&self) -> usize {
        self.preparation_tx_count() + self.transfer_tx_count()
    }

    /// The number of preparation transactions across all layers.
    pub fn preparation_tx_count(&self) -> usize {
        self.preparation.transaction_count()
    }

    /// The number of pool-crossing transfers (one per funding note).
    pub fn transfer_tx_count(&self) -> usize {
        self.denominations.migration_outputs().len()
    }

    /// The number of sequential preparation layers (the phase's wall-clock depth).
    pub fn preparation_layer_count(&self) -> usize {
        self.preparation.layer_count()
    }

    /// The total Orchard-family actions across every transaction this plan builds.
    pub fn total_actions(&self) -> u32 {
        let prep = (self.preparation_tx_count() as u64)
            .saturating_mul(u64::from(crate::signing_rounds::PREPARATION_ACTIONS));
        let xfer = (self.transfer_tx_count() as u64)
            .saturating_mul(u64::from(crate::signing_rounds::TRANSFER_ACTIONS));
        u32::try_from(prep.saturating_add(xfer)).unwrap_or(u32::MAX)
    }

    /// The total value that migrates to the destination pool (the sum of the crossing values).
    pub fn value_migrated(&self) -> Zatoshis {
        self.denominations.total_migratable()
    }

    /// The source-pool value left untouched by this plan (change plus dust below a self-funding
    /// note); zero when the balance decomposed exactly.
    pub fn residual(&self) -> Zatoshis {
        self.denominations.change().unwrap_or(Zatoshis::ZERO)
    }

    /// Group this plan's transactions into signing ROUNDS for a signer bounded by `budget` total
    /// Orchard actions per interaction, using the optimal [`MinRounds`] packing (fewest signer
    /// interactions). The `budget` is the caller's per-round capacity (for example
    /// [`SigningRoundBudget::KEYSTONE`]); it is a QUERY parameter, so a plan can be evaluated for any
    /// signer without re-planning. See [`signing_rounds_with`](Self::signing_rounds_with) to choose
    /// a different [`SigningRoundStrategy`].
    pub fn signing_rounds(&self, budget: SigningRoundBudget) -> Vec<PlannedSigningRound> {
        self.signing_rounds_with(&MinRounds, budget)
    }

    /// Like [`signing_rounds`](Self::signing_rounds) but with an explicit packing `strategy` (the
    /// named solution of the round-packing problem).
    pub fn signing_rounds_with<S: SigningRoundStrategy>(
        &self,
        strategy: &S,
        budget: SigningRoundBudget,
    ) -> Vec<PlannedSigningRound> {
        strategy.pack(&self.planned_transactions(), budget)
    }

    /// The number of signing rounds this plan needs for a signer bounded by `budget` (the optimal
    /// [`MinRounds`] count), without materializing the packing.
    pub fn signing_round_count(&self, budget: SigningRoundBudget) -> usize {
        min_signing_rounds(
            self.preparation_tx_count(),
            self.transfer_tx_count(),
            budget,
        )
    }

    /// The smallest per-round budget that signs this whole plan in ONE round: the plan's total
    /// actions (never below [`SigningRoundBudget::minimum_feasible`]). For the signer-selection UX
    /// ("a signer supporting at least this many actions per round signs this in one interaction").
    pub fn min_budget_for_single_round(&self) -> NonZeroU32 {
        min_budget_for_rounds(
            self.preparation_tx_count(),
            self.transfer_tx_count(),
            NonZeroUsize::MIN,
        )
    }
}

/// Why a migration could not be planned.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MigrationError<E> {
    /// The wallet backend failed (a store or chain-access error).
    Backend(E),
    /// The spendable notes cannot fund the planned migration (see [`PrepError`]).
    Preparation(PrepError),
    /// The account has no migratable balance.
    NothingToMigrate,
    /// The backend's note values do not form a valid balance (their sum exceeds the maximum money
    /// supply).
    InvalidBalance(BalanceError),
    /// Computing the canonical ZIP-317 fees from the canonical transaction shapes failed.
    Fee(zip317::FeeError),
    /// NU6.3 is not active on this network, so there is no destination pool to migrate into (and
    /// no anchor bucket above its activation to schedule against).
    Nu63NotActive,
}

impl<E: fmt::Display> fmt::Display for MigrationError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MigrationError::Backend(e) => write!(f, "wallet backend error: {e}"),
            MigrationError::Preparation(e) => write!(f, "cannot prepare the migration: {e}"),
            MigrationError::NothingToMigrate => f.write_str("no migratable balance"),
            MigrationError::InvalidBalance(e) => write!(f, "invalid balance: {e}"),
            MigrationError::Fee(e) => write!(f, "fee computation failed: {e}"),
            MigrationError::Nu63NotActive => f.write_str("NU6.3 is not active on this network"),
        }
    }
}

impl<E: core::error::Error + 'static> core::error::Error for MigrationError<E> {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            MigrationError::Backend(e) => Some(e),
            MigrationError::Preparation(e) => Some(e),
            MigrationError::NothingToMigrate => None,
            // `BalanceError` (and `FeeError`, which wraps it) implements `Error` only with
            // `zcash_protocol/std`; the Display text above carries their messages instead.
            MigrationError::InvalidBalance(_) => None,
            MigrationError::Fee(_) => None,
            MigrationError::Nu63NotActive => None,
        }
    }
}

/// The two canonical ZIP-317 fees of a migration, computed from the canonical transaction shapes:
/// the fee of one padded [`PREP_TX_ACTIONS`](crate::preparation::PREP_TX_ACTIONS)-action preparation
/// transaction, and the transfer-fee buffer each prepared note carries (the fee of the canonical
/// 2-Orchard + 1-Ironwood-action transfer: the Ironwood side is a single unpadded action).
fn canonical_fees<P: zcash_protocol::consensus::Parameters>(
    params: &P,
    height: BlockHeight,
) -> Result<(Zatoshis, Zatoshis), zip317::FeeError> {
    let fee_rule = zip317::FeeRule::standard();
    let prep_tx_fee = fee_rule.fee_required(
        params,
        height,
        core::iter::empty::<transparent::InputSize>(),
        core::iter::empty::<usize>(),
        0,
        0,
        PREP_TX_ACTIONS,
        0,
    )?;
    let transfer_fee_buffer = fee_rule.fee_required(
        params,
        height,
        core::iter::empty::<transparent::InputSize>(),
        core::iter::empty::<usize>(),
        0,
        0,
        SOURCE_ACTIONS_PER_TRANSFER,
        DESTINATION_ACTIONS_PER_TRANSFER,
    )?;
    Ok((prep_tx_fee, transfer_fee_buffer))
}

/// Plan a migration for the account the `backend` represents: decompose its spendable balance into
/// canonical denominations, plan the preparation transactions that mint the self-funding notes, and
/// schedule the phase-2 transfers. The canonical ZIP-317 fees are computed here, once, from the two
/// canonical transaction shapes — the padded [`PREP_TX_ACTIONS`](crate::preparation::PREP_TX_ACTIONS)-action preparation transaction and
/// the 2-Orchard + 1-Ironwood-action transfer — and reused throughout planning; the fee rule is fixed (ZIP 318 requires
/// the canonical fee, since a nonstandard fee would partition the anonymity set), so it is not a
/// parameter. The decomposition reserves the TRUE preparation cost at each step, consulting the
/// preparation planner as it grows the split. `rng` must be a cryptographically secure RNG (the
/// schedule's shuffle, delays, and the denomination plan's optional randomization draw from it).
///
/// This is pure orchestration of the denomination, preparation, and scheduling planners: no cryptography,
/// and nothing is built, signed, or persisted. The result is the [`MigrationPlan`] preview to present
/// for user consent before committing the migration.
pub fn plan_migration<P, B, R>(
    params: &P,
    backend: &B,
    rng: &mut R,
) -> Result<MigrationPlan, MigrationError<B::Error>>
where
    P: zcash_protocol::consensus::Parameters,
    B: MigrationBackend,
    R: RngCore + rand_core::CryptoRng,
{
    let notes = backend
        .spendable_orchard_note_values()
        .map_err(MigrationError::Backend)?;
    // Validate the balance once; every value the planners derive from it is bounded by it, so the
    // internal (planner-domain) u64 arithmetic below cannot re-exceed the money-supply cap.
    let balance = notes
        .iter()
        .copied()
        .sum::<Option<Zatoshis>>()
        .ok_or(MigrationError::InvalidBalance(BalanceError::Overflow))?;
    if balance == Zatoshis::ZERO {
        return Err(MigrationError::NothingToMigrate);
    }
    let commit_height = backend
        .chain_tip_height()
        .map_err(MigrationError::Backend)?;
    // The anchor grid and delay distributions come from the backend, not from this function's
    // caller: the grid must be the one the backend retains its anchor checkpoints on.
    let sched_params = backend.scheduling_params();

    // The canonical fees, computed once from the canonical transaction shapes and reused throughout.
    let (prep_tx_fee, transfer_fee_buffer) =
        canonical_fees(params, commit_height).map_err(MigrationError::Fee)?;

    // The preparation-layout capability the decomposition consults at each step: how many
    // preparation transactions minting a candidate funding multiset takes, or `None` when the
    // wallet's notes cannot mint it (so the split stops or steps down a denomination).
    let prep_tx_count = |funding: &[Zatoshis]| {
        plan_preparation(&notes, funding, prep_tx_fee)
            .ok()
            .map(|plan| plan.transaction_count())
    };
    let denominations = plan_denominations(
        balance,
        transfer_fee_buffer,
        prep_tx_fee,
        &prep_tx_count,
        rng,
    );
    let funding_notes = denominations.migration_outputs();
    if funding_notes.is_empty() {
        return Err(MigrationError::NothingToMigrate);
    }

    // The decomposition verified this multiset against the preparation planner at every step, so
    // this final planning pass succeeds by construction; the error path is kept for safety.
    let preparation = plan_preparation(&notes, &funding_notes, prep_tx_fee)
        .map_err(MigrationError::Preparation)?;

    // Schedule the PREPARATION broadcasts: each transaction gets its own drawn height (temporal
    // decoupling — a burst of identically shaped transactions from one wallet is a linkable
    // cluster), with the tighter preparation spacing since no anchor bucketing constrains them.
    // Each later layer's schedule bases past the previous layer's last height plus a mining
    // margin, keeping the layers serialized.
    let mut prep_schedule: Vec<Vec<BlockHeight>> = Vec::with_capacity(preparation.layer_count());
    let mut layer_base = commit_height;
    for layer in preparation.layers() {
        let heights = scheduling::schedule_prep_broadcast_heights(
            &sched_params,
            layer_base,
            layer.len(),
            rng,
        );
        layer_base = heights.last().copied().unwrap_or(layer_base) + EST_PREP_LAYER_MINING_BLOCKS;
        prep_schedule.push(heights);
    }
    // After the loop, `layer_base` estimates the height at which the last preparation transaction
    // has mined and its funding notes are witnessable.
    let est_last_prep_height = layer_base;

    // Lower-bound the FIRST scheduled transfer so that every transfer is guaranteed a candidate
    // anchor boundary: the funding notes exist only once the preparation has mined, and a boundary
    // must then exist above their creation (see [`scheduling::earliest_broadcast_height`]). Basing
    // the schedule at this bound, rather than the raw commit height, keeps the drawn inter-arrival
    // gaps intact while making an empty candidate set impossible for a plan committed at (or
    // reasonably near) its planning height.
    let nu63_activation = params
        .activation_height(zcash_protocol::consensus::NetworkUpgrade::Nu6_3)
        .ok_or(MigrationError::Nu63NotActive)?;
    let schedule_base = commit_height.max(scheduling::earliest_broadcast_height(
        sched_params.anchor_bucket_interval(),
        nu63_activation,
        est_last_prep_height,
    ));
    // SHUFFLE (ZIP 318 MUST): the cumulative broadcast heights are non-decreasing in draw
    // order, and the split's crossing values are a non-increasing function of the balance, so
    // pairing them in order would broadcast the denominations largest-first — an on-chain
    // temporal sequence an observer could read the balance back out of. Drawing a uniform
    // permutation and assigning the i-th drawn slot to the permuted crossing makes the
    // broadcast order of denominations independent of the balance.
    let slots = scheduling::schedule(&sched_params, schedule_base, funding_notes.len(), rng);
    let mut schedule = slots.clone();
    for (slot, &crossing) in scheduling::shuffle_indices(funding_notes.len(), rng)
        .iter()
        .enumerate()
    {
        schedule[crossing] = slots[slot];
    }

    Ok(MigrationPlan {
        denominations,
        preparation,
        prep_schedule,
        schedule,
    })
}

/// A per-run entry of a [`MigrationRunEstimate`]: what one migration run migrates (the denomination
/// side) and what preparing it costs (the note-preparation side), so the two can be compared.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RunEstimate {
    migratable: Zatoshis,
    crossings: usize,
    prep_layers: usize,
    prep_transactions: usize,
}

impl RunEstimate {
    /// The total value that crosses the turnstile in this run (the sum of its crossing denominations).
    pub fn migratable(&self) -> Zatoshis {
        self.migratable
    }

    /// The number of pool-crossing transfers this run makes: one per self-funding note the denomination plan
    /// produced for it.
    pub fn crossings(&self) -> usize {
        self.crossings
    }

    /// The number of sequential note-preparation layers this run needs — its wall-clock depth, since
    /// each layer waits for the previous one to mine before it can be broadcast.
    pub fn prep_layers(&self) -> usize {
        self.prep_layers
    }

    /// The number of note-preparation transactions this run builds across all its layers.
    pub fn prep_transactions(&self) -> usize {
        self.prep_transactions
    }

    /// The total number of transactions this run builds and signs: its preparation transactions plus
    /// one pool-crossing transfer per funding note.
    pub fn transactions(&self) -> usize {
        self.prep_transactions + self.crossings
    }

    /// The total Orchard-family ACTIONS a signer processes for this run: 16 per preparation
    /// transaction and 3 per transfer. This is the signing WORKLOAD (a proxy for signing time),
    /// distinct from the number of interactions ([`signing_rounds`](Self::signing_rounds)): combine
    /// it with the device's per-action time to estimate how long signing this run will take.
    pub fn actions(&self) -> u32 {
        let prep = (self.prep_transactions as u64)
            .saturating_mul(u64::from(crate::signing_rounds::PREPARATION_ACTIONS));
        let xfer = (self.crossings as u64)
            .saturating_mul(u64::from(crate::signing_rounds::TRANSFER_ACTIONS));
        u32::try_from(prep.saturating_add(xfer)).unwrap_or(u32::MAX)
    }

    /// The number of signing ROUNDS this run needs when an external signer is bounded by `budget`
    /// total Orchard ACTIONS per interaction (for example a Keystone,
    /// [`SigningRoundBudget::KEYSTONE`]). This is the per-round-total-action model, NOT a
    /// per-transaction cap: a round holds any mix of preparation (16-action) and transfer (3-action)
    /// transactions summing to at most the budget. Computed as the optimal (minimum) packing, since
    /// all of a run's transactions are built and signed together (anchors and witnesses deferred to
    /// proving, [ZIP 374]) and are free to be grouped in any order.
    ///
    /// [ZIP 374]: https://zips.z.cash/zip-0374
    pub fn signing_rounds(&self, budget: SigningRoundBudget) -> usize {
        min_signing_rounds(self.prep_transactions, self.crossings, budget)
    }
}

/// An estimate of migrating a wallet's whole spendable balance across successive migration RUNS
/// ("rounds"): one [`RunEstimate`] per run and the value left un-migrated at the end.
///
/// A balance beyond one run's capacity (the note cap times the maximum denomination) migrates over
/// several runs, each run's spent notes and preparation residuals forming the next run's note
/// structure (see [`estimate_migration_runs`]). Each run carries BOTH sides so an application can
/// compare them: the denomination crossings it migrates and the note-preparation layers and
/// transactions it costs.
///
/// A capacity-limited external signer adds a third dimension: given the signer's per-interaction
/// action budget, [`total_signing_rounds`](Self::total_signing_rounds) gives the number of signing
/// interactions the whole migration requires. That budget is a query parameter, not part of the
/// estimate, so an SDK can evaluate it for any signer capacity without re-running the planners.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MigrationRunEstimate {
    runs: Vec<RunEstimate>,
    final_residual: Zatoshis,
}

impl MigrationRunEstimate {
    /// The expected number of migration runs ("rounds") to migrate the whole balance: zero when the
    /// balance is below the smallest self-funding note, so nothing migrates.
    pub fn run_count(&self) -> usize {
        self.runs.len()
    }

    /// The per-run estimates, in run order.
    pub fn runs(&self) -> &[RunEstimate] {
        &self.runs
    }

    /// The value left in the source pool after the last run — below the smallest self-funding note, so
    /// it never migrates. Zero when the balance divides exactly into self-funding notes and fees.
    pub fn final_residual(&self) -> Zatoshis {
        self.final_residual
    }

    /// The total value that migrates across all runs (the sum of each run's
    /// [`migratable`](RunEstimate::migratable)).
    pub fn total_migratable(&self) -> Zatoshis {
        self.runs
            .iter()
            .map(RunEstimate::migratable)
            .sum::<Option<Zatoshis>>()
            .expect("the per-run migratable totals sum to at most the validated balance")
    }

    /// The total number of pool-crossing transfers across all runs (the sum of each run's
    /// [`crossings`](RunEstimate::crossings)).
    pub fn total_crossings(&self) -> usize {
        self.runs.iter().map(RunEstimate::crossings).sum()
    }

    /// The total number of note-preparation layers across all runs (the sum of each run's
    /// [`prep_layers`](RunEstimate::prep_layers)).
    pub fn total_prep_layers(&self) -> usize {
        self.runs.iter().map(RunEstimate::prep_layers).sum()
    }

    /// The total number of note-preparation transactions across all runs (the sum of each run's
    /// [`prep_transactions`](RunEstimate::prep_transactions)).
    pub fn total_prep_transactions(&self) -> usize {
        self.runs.iter().map(RunEstimate::prep_transactions).sum()
    }

    /// The total number of transactions the whole migration builds and signs across all runs (the sum
    /// of each run's [`transactions`](RunEstimate::transactions); equivalently
    /// [`total_prep_transactions`](Self::total_prep_transactions) plus
    /// [`total_crossings`](Self::total_crossings)).
    pub fn total_transactions(&self) -> usize {
        self.runs.iter().map(RunEstimate::transactions).sum()
    }

    /// The total Orchard-family ACTIONS the whole migration asks the user to sign, across all runs
    /// (the sum of each run's [`actions`](RunEstimate::actions)). This is the total signing WORKLOAD,
    /// a proxy for how long the user will spend signing: multiply it by the device's per-action time
    /// to show a time estimate. Distinct from [`total_signing_rounds`](Self::total_signing_rounds),
    /// which counts the number of separate interactions.
    pub fn total_actions(&self) -> u32 {
        self.runs
            .iter()
            .map(RunEstimate::actions)
            .fold(0u32, |acc, a| acc.saturating_add(a))
    }

    /// The total number of signing ROUNDS the whole migration needs when an external signer is
    /// bounded by `budget` total Orchard actions per interaction — the number of times the user must
    /// interact with a capacity-limited hardware signer (for example a Keystone, whose limit the SDK
    /// passes in here).
    ///
    /// This is the SUM of each run's [`signing_rounds`](RunEstimate::signing_rounds), NOT the packing
    /// of `total_transactions` at once, because rounds cannot span runs: a later run's transactions
    /// spend notes an earlier run must mine first, so each run is signed on its own.
    pub fn total_signing_rounds(&self, budget: SigningRoundBudget) -> usize {
        self.runs.iter().map(|run| run.signing_rounds(budget)).sum()
    }
}

/// Estimate how the account the `backend` represents will migrate its whole spendable balance: the
/// number of migration RUNS ("rounds") it takes, and for each run BOTH what it migrates (the
/// denomination crossings) and what preparing it costs (the note-preparation layers and transactions),
/// so an application can preview and compare the two before anything is planned or committed.
///
/// A run prepares a bounded number of capped self-funding notes, so a balance beyond one run's
/// capacity migrates over several runs. The estimate depends on the wallet's NOTE STRUCTURE, not just
/// its total value: each run is decomposed with the REAL preparation planner over the current notes
/// (so its feasibility and fees are exact, exactly as [`plan_migration`] plans one run), and the notes
/// that run spends and the residuals it leaves form the next run's structure.
///
/// The denomination run count itself does NOT depend on an external signer's capacity. When a
/// capacity-limited hardware signer (for example a Keystone) is bounded by a per-interaction action
/// budget, pass that user-configured [`SigningRoundBudget`] to
/// [`MigrationRunEstimate::total_signing_rounds`] to get the number of signing interactions the
/// migration requires (each run is signed on its own; see that method). Because this iterates the
/// denomination and preparation planners once per run, its cost is roughly one [`plan_migration`] per
/// run.
///
/// A zero (or fully sub-quantum) balance yields a zero-run estimate rather than an error, since this
/// is a preview. `rng` is drawn from only by a randomized denomination strategy; the recommended
/// canonical strategy ignores it.
pub fn estimate_migration_runs<P, B, R>(
    params: &P,
    backend: &B,
    rng: &mut R,
) -> Result<MigrationRunEstimate, MigrationError<B::Error>>
where
    P: zcash_protocol::consensus::Parameters,
    B: MigrationBackend,
    R: RngCore + rand_core::CryptoRng,
{
    let height = backend
        .chain_tip_height()
        .map_err(MigrationError::Backend)?;
    let (prep_tx_fee, transfer_fee_buffer) =
        canonical_fees(params, height).map_err(MigrationError::Fee)?;
    // The note structure the migration works on, evolving run by run: initially the wallet's own
    // spendable notes, then each run's unspent notes plus its preparation residuals.
    let mut notes = backend
        .spendable_orchard_note_values()
        .map_err(MigrationError::Backend)?;

    let mut runs: Vec<RunEstimate> = Vec::new();
    loop {
        let balance = notes
            .iter()
            .copied()
            .sum::<Option<Zatoshis>>()
            .ok_or(MigrationError::InvalidBalance(BalanceError::Overflow))?;

        // This run's denomination plan, decomposing the CURRENT note set. Its per-step preparation cost and
        // feasibility are backed by the real preparation planner over the current notes, so the split
        // — and hence the whole run count — depends on the wallet's note structure, not just its
        // total value. The closure's borrow of `notes` is released with the block, before `notes` is
        // reassigned below.
        let denominations = {
            let prep_tx_count = |funding: &[Zatoshis]| {
                plan_preparation(&notes, funding, prep_tx_fee)
                    .ok()
                    .map(|plan| plan.transaction_count())
            };
            plan_denominations(
                balance,
                transfer_fee_buffer,
                prep_tx_fee,
                &prep_tx_count,
                rng,
            )
        };

        let funding = denominations.migration_outputs();
        if funding.is_empty() {
            // Nothing more migrates from this note set: the remaining balance is the final residual
            // and the migration is complete.
            return Ok(MigrationRunEstimate {
                runs,
                final_residual: balance,
            });
        }

        // The preparation that mints this run's funding notes: its layer and transaction counts are
        // the note-preparation side of the estimate, and which notes it spends and which residuals it
        // leaves give the next run's note structure. The denomination plan only ever proposes a funding
        // multiset the preparation planner accepted, so this plan succeeds by construction.
        let preparation =
            plan_preparation(&notes, &funding, prep_tx_fee).map_err(MigrationError::Preparation)?;
        runs.push(RunEstimate {
            migratable: denominations.total_migratable(),
            crossings: funding.len(),
            prep_layers: preparation.layer_count(),
            prep_transactions: preparation.transaction_count(),
        });
        notes = source_pool_notes_after_run(&notes, &preparation);
    }
}

/// The source-pool notes that remain after a migration run, forming the next run's note structure: the
/// wallet notes the run's preparation did not spend (and did not use directly as a funding note, which
/// crosses out), plus the residual notes the preparation leaves behind. The run's minted funding notes
/// are crossed out by the transfers, so they do not remain.
fn source_pool_notes_after_run(
    wallet: &[Zatoshis],
    preparation: &PreparationPlan,
) -> Vec<Zatoshis> {
    let mut spent = vec![false; wallet.len()];
    for layer in preparation.layers() {
        for tx in layer {
            for input in tx.inputs() {
                if let PrepInput::Wallet { index, .. } = input
                    && let Some(flag) = spent.get_mut(*index)
                {
                    *flag = true;
                }
            }
        }
    }
    // Notes used directly as a funding note cross out with the transfers, so they do not remain.
    for &(index, _) in preparation.direct_funding_notes() {
        if let Some(flag) = spent.get_mut(index) {
            *flag = true;
        }
    }
    let mut remaining: Vec<Zatoshis> = wallet
        .iter()
        .copied()
        .zip(spent)
        .filter_map(|(value, is_spent)| (!is_spent).then_some(value))
        .collect();
    remaining.extend(preparation.residual_notes());
    remaining
}

/// The Orchard-specific wallet operations the engine needs to BUILD and PRE-SIGN a migration: the
/// account's viewing key, its spendable notes' plaintexts, and spend-authorization signing. Kept
/// separate from [`MigrationBackend`] so the planning and persistence parts stay pure; one wallet
/// implements both over the same account. Behind the `orchard` feature.
///
/// No anchors and no witnesses appear here: every migration transaction is built and signed with
/// its anchor and witnesses DEFERRED to proving time ([ZIP 374]) — a spent note's plaintext fully
/// determines the signed data, and its tree position matters only to the proof, which the consumer
/// creates through the PCZT `Updater` role once the note is mined.
///
/// [ZIP 374]: https://zips.z.cash/zip-0374
#[cfg(feature = "orchard")]
pub trait MigrationCrypto {
    /// The backend's error type (shared with its [`MigrationBackend`] impl).
    type Error;

    /// The account's Orchard full viewing key.
    fn orchard_fvk(&self) -> Result<orchard::keys::FullViewingKey, Self::Error>;

    /// The ZIP 32 account the migration's notes belong to, or `None` if the account has no known
    /// derivation (an imported viewing key, say).
    ///
    /// The builders stamp this onto every spend a migration transaction still needs a signature
    /// for, which is how an EXTERNAL Signer recognizes those spends as the account's. A backend
    /// that returns `None` while signing is delegated to an external signer produces
    /// transactions no derivation-matching Signer can authorize, so return the derivation whenever
    /// the wallet knows it, even if it currently signs in process.
    fn account_derivation(&self) -> Result<Option<AccountDerivation>, Self::Error>;

    /// The plaintext of the spendable wallet note at `index` (into
    /// `spendable_orchard_note_values`).
    fn resolve_wallet_note(&self, index: usize) -> Result<orchard::note::Note, Self::Error>;

    /// Add the account's Orchard spend-authorization signatures to a finalized, unproven PCZT.
    fn sign(&self, pczt: pczt::Pczt) -> Result<pczt::Pczt, Self::Error>;
}

/// A prover's typed failure: the one condition the engine handles — an input not among the
/// unspent set — distinguished from everything else. This seam observes only MEMBERSHIP, which
/// conflates "spent" with "not yet scanned"; the engine's dependency-coverage guard against
/// `as_of` sharpens it into positive spend evidence or a retry.
#[cfg(feature = "orchard")]
#[derive(Debug)]
pub enum ProveFailure<E> {
    /// A spend's nullifier matched no unspent note, as of the wallet's fully-scanned height.
    InputNotAvailable {
        /// The nullifier whose note was not among the unspent set.
        nullifier: [u8; 32],
        /// The fully-scanned height the absence observation rests on.
        as_of: BlockHeight,
    },
    /// Any other prover error.
    Other(E),
}

/// The outcome of a prove attempt the engine HANDLED — an error return would invite blind
/// retries of conditions that are not errors.
#[cfg(feature = "orchard")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProveOutcome {
    /// The proof was created; the transaction is `Proved` and the proven PCZT stored.
    Proved,
    /// An input was not available, and the wallet has not yet scanned past every dependency's
    /// mined height: nothing can be concluded. No state change; retry after further sync.
    NotYetProvable,
    /// An input was not available with every dependency's mined height covered by the wallet's
    /// scan — positive evidence of a spend. The transaction was marked unsatisfiable (with the
    /// dependency closure recorded); `replan_required` is the derived accessor's value after
    /// marking, so the caller can react without re-consulting the state.
    MarkedUnsatisfiable {
        /// [`MigrationState::replan_required`] as it stands after the mark.
        replan_required: bool,
    },
}

/// The proving seam for a migration transfer: install a transfer's deferred anchors and witnesses
/// (ZIP 374) against the boundary its schedule drew, then prove it.
///
/// This is deliberately SEPARATE from [`MigrationCrypto`]. Signing needs only the account's spend
/// authority and is a cheap, read-only (`&self`) operation; proving needs MUTABLE access to the
/// wallet's Orchard commitment tree at a historical checkpoint (resolving a witness caches into the
/// tree) plus the Orchard and Ironwood proving keys, a heavier capability with a different lifetime.
/// Keeping proving in its own trait lets a wallet expose signing without dragging commitment-tree
/// access and proving parameters into the same type, and lets a consumer supply a prover
/// independently of the signer.
#[cfg(feature = "orchard")]
pub trait MigrationProver {
    /// The prover's error type.
    type Error;

    /// Prove a pre-signed transfer against the boundary its schedule drew.
    ///
    /// This is where a transfer's DEFERRED anchors and witnesses (ZIP 374) are finally resolved and
    /// installed: the implementation reads the Orchard source-tree root at the `anchor_boundary`
    /// checkpoint (the source anchor) and the funding note's Merkle witness against it, installs both
    /// through the PCZT `Updater` role (`set_anchor` / `set_spend_witness`), installs the Ironwood
    /// destination anchor for the output bundle, then proves both bundles and returns the proven
    /// PCZT, ready to broadcast. The `anchor_boundary` is the boundary height drawn at SCHEDULING
    /// time and persisted on the transaction ([`MigrationTransaction::anchor_boundary`]); passing it
    /// here is what makes the drawn boundary, not the tip, the tree state the transfer proves
    /// against.
    ///
    /// Resolving the funding note's witness requires the boundary checkpoint to still exist in the
    /// wallet's commitment tree at proving time; a wallet backend keeps it alive through migration
    /// anchor-checkpoint retention (see issue #2700).
    ///
    /// Failure is typed: an implementation reports a spend whose nullifier matched no note in the
    /// account's UNSPENT set as [`ProveFailure::InputNotAvailable`], carrying that nullifier and
    /// the fully-scanned height the absence rests on, and every other failure as
    /// [`ProveFailure::Other`]. The distinction matters because absence from the unspent set is
    /// only a membership observation — a spent note and a note whose creator is not yet scanned
    /// look alike — so the engine, not the prover, decides what it means (see [`prove_transfer`]).
    /// The reported height must be one the observation genuinely rests on: it becomes the stamp a
    /// resulting unsatisfiability mark is truncated against on a reorg.
    fn prove_transfer(
        &mut self,
        pczt: pczt::Pczt,
        anchor_boundary: BlockHeight,
    ) -> Result<pczt::Pczt, ProveFailure<Self::Error>>;

    /// Prove a pre-signed PREPARATION transaction against a checkpoint at which its spent notes are
    /// witnessable.
    ///
    /// Like a transfer, a preparation transaction defers its Orchard anchor and its spends'
    /// witnesses to proving time (ZIP 374), but it carries NO drawn
    /// [`anchor_boundary`](MigrationTransaction::anchor_boundary) (it anchors to its already-mined
    /// dependencies, not to a bucketed boundary), so the `anchor` height is passed in: the caller
    /// proves a preparation once its inputs are mined and picks a checkpoint at or after that (for
    /// example the current chain tip). A preparation spends the wallet's own notes (layer 0) or
    /// feeder notes minted by an earlier layer — one or MANY, unlike a transfer's single funding
    /// note — and produces only an Orchard bundle (no Ironwood output), so the implementation
    /// installs the anchor and every real spend's witness through the PCZT `Updater` role and proves
    /// the single Orchard bundle.
    ///
    /// Failure is typed exactly as for [`prove_transfer`](Self::prove_transfer): a spend absent
    /// from the account's unspent set is [`ProveFailure::InputNotAvailable`] with the height that
    /// observation rests on, anything else is [`ProveFailure::Other`].
    fn prove_preparation(
        &mut self,
        pczt: pczt::Pczt,
        anchor: BlockHeight,
    ) -> Result<pczt::Pczt, ProveFailure<Self::Error>>;

    /// The anchor bucket grid the wallet backing this prover currently retains its durable anchor
    /// checkpoints on.
    ///
    /// [`prove_transfer`] compares this against the grid the migration was committed under and
    /// refuses to prove a transfer whose boundary is no longer retained, so a reconfiguration
    /// mid-migration surfaces as [`ProveError::AnchorIntervalMismatch`] rather than as a bare
    /// missing checkpoint at witness-resolution time.
    fn anchor_bucket_interval(&self) -> crate::scheduling::AnchorBucketInterval;
}

/// Why committing a migration's preparation failed.
#[cfg(feature = "orchard")]
#[derive(Debug)]
pub enum CommitError<E> {
    /// A wallet backend operation (witness, key, signing, or storage) failed.
    Backend(E),
    /// Building a migration transaction failed. Carries the structured builder error.
    Build(crate::build::BuildError),
    /// A built migration PCZT presents no well-formed set of real spends, so the real-spend
    /// nullifier cache ([`MigrationTransaction::spend_nullifiers`]) cannot be extracted from it.
    RealSpends(crate::pczt_spends::RealSpendError),
    /// Serializing a built migration PCZT (for storage or an external signer) failed.
    Serialize(pczt::EncodingError),
    /// NU6.3 is not active on this network, so there is no destination pool to migrate into. The
    /// planning side models the same recoverable condition as
    /// [`MigrationError::Nu63NotActive`].
    Nu63NotActive,
    /// No committed migration was found to build the transfers for (nothing was loaded from storage).
    NoMigrationInProgress,
    /// The plan is stale and must be re-planned. Either a resolved wallet note's value no longer
    /// matches the value the plan recorded for it (the plan captures notes by their index into the
    /// spendable set at planning time, so any receipt or spend since planning shifts them), or the
    /// build height has advanced past every candidate anchor boundary the schedule can prove
    /// against.
    StalePlan,
    /// A non-terminal migration is already stored. A committed migration is resumed from the
    /// store (or cancelled), never rebuilt over: overwriting it would orphan its pre-signed —
    /// and possibly already broadcast — transactions, and a rebuilt layer 0 would double-spend
    /// the same wallet notes.
    MigrationInProgress,
    /// The migration plan is internally inconsistent: two of its parallel structures disagree
    /// (for example a preparation layer has no matching entry in the preparation schedule), so
    /// it cannot be committed. A plan assembled through `from_parts` is not validated, so a
    /// malformed one reaches the commit boundary as this typed error rather than a panic; the
    /// string names which structure and index disagreed, for diagnosis.
    InconsistentPlan(alloc::string::String),
}

#[cfg(feature = "orchard")]
impl<E: fmt::Display> fmt::Display for CommitError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CommitError::Backend(e) => write!(f, "wallet backend error: {e}"),
            CommitError::Build(e) => write!(f, "building the migration failed: {e}"),
            CommitError::RealSpends(e) => {
                write!(f, "a built migration transaction has no real spends: {e}")
            }
            CommitError::Serialize(e) => {
                write!(f, "serializing a migration transaction failed: {e:?}")
            }
            CommitError::Nu63NotActive => f.write_str("NU6.3 is not active on this network"),
            CommitError::NoMigrationInProgress => {
                f.write_str("no committed migration is in progress")
            }
            CommitError::StalePlan => f.write_str(
                "the plan no longer matches the wallet or the build height and must be re-planned",
            ),
            CommitError::MigrationInProgress => f.write_str(
                "a non-terminal migration is already stored; resume or cancel it instead of \
                 committing a new one",
            ),
            CommitError::InconsistentPlan(m) => {
                write!(f, "the migration plan is internally inconsistent: {m}")
            }
        }
    }
}

#[cfg(feature = "orchard")]
impl<E: core::error::Error> core::error::Error for CommitError<E> {}

/// Why proving a migration transfer failed.
#[cfg(feature = "orchard")]
#[derive(Debug)]
pub enum ProveError<E> {
    /// No transaction with the given id belongs to the migration.
    UnknownTransaction(MigrationTransferId),
    /// The transaction is a preparation transaction, not a transfer; only transfers are proved
    /// against a drawn anchor boundary (a preparation transaction carries no boundary).
    NotATransfer(MigrationTransferId),
    /// The transaction is a transfer, not a preparation transaction; only preparation transactions
    /// are proved against a caller-supplied anchor (a transfer proves against its drawn boundary).
    NotAPreparation(MigrationTransferId),
    /// The transaction is not in the [`Signed`](MigrationTxState::Signed) state, so it is not ready
    /// to prove (it is unsigned, already proved, or already broadcast).
    NotReady(MigrationTransferId),
    /// A transfer carries no anchor boundary. Every transfer draws one at scheduling time, so this
    /// indicates a corrupt stored state rather than a normal condition.
    NoAnchorBoundary(MigrationTransferId),
    /// The wallet's anchor retention grid has changed since this migration was committed, so the
    /// boundaries its transfers anchored to are no longer retained and their checkpoints will have
    /// been pruned. The migration cannot be proved and must be re-planned under the current grid
    /// (or the wallet reconfigured back to the committed one).
    AnchorIntervalMismatch {
        /// The grid the migration was committed under.
        committed: crate::scheduling::AnchorBucketInterval,
        /// The grid the wallet retains on now.
        configured: crate::scheduling::AnchorBucketInterval,
    },
    /// The stored PCZT could not be parsed.
    Parse(pczt::ParseError),
    /// The proven PCZT could not be serialized.
    Serialize(pczt::EncodingError),
    /// The prover failed to resolve, install, or prove the transfer.
    Prover(E),
}

#[cfg(feature = "orchard")]
impl<E: fmt::Display> fmt::Display for ProveError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProveError::UnknownTransaction(id) => {
                write!(f, "no migration transaction with id {}", u32::from(*id))
            }
            ProveError::NotATransfer(id) => write!(
                f,
                "transaction {} is a preparation transaction, not a transfer",
                u32::from(*id)
            ),
            ProveError::NotAPreparation(id) => write!(
                f,
                "transaction {} is a transfer, not a preparation transaction",
                u32::from(*id)
            ),
            ProveError::NotReady(id) => {
                write!(
                    f,
                    "transaction {} is not signed and ready to prove",
                    u32::from(*id)
                )
            }
            ProveError::NoAnchorBoundary(id) => write!(
                f,
                "transfer {} has no drawn anchor boundary; the stored state is inconsistent",
                u32::from(*id)
            ),
            ProveError::AnchorIntervalMismatch {
                committed,
                configured,
            } => write!(
                f,
                "the migration was committed against a {}-block anchor bucket grid, but the wallet \
                 now retains anchors on a {}-block grid; its transfers' anchors are no longer \
                 retained",
                committed.block_count(),
                configured.block_count()
            ),
            ProveError::Parse(e) => write!(f, "parsing the stored PCZT failed: {e:?}"),
            ProveError::Serialize(e) => write!(f, "serializing the proven PCZT failed: {e:?}"),
            ProveError::Prover(e) => write!(f, "proving the transfer failed: {e}"),
        }
    }
}

#[cfg(feature = "orchard")]
impl<E: core::error::Error> core::error::Error for ProveError<E> {}

/// Prove a pre-signed migration transfer against the boundary its schedule drew, moving it
/// `Signed -> Proved`.
///
/// This is the step that finally consults a transfer's PERSISTED
/// [`anchor_boundary`](MigrationTransaction::anchor_boundary), drawn at scheduling time: it reads
/// that boundary and hands the stored PCZT and the boundary to
/// [`MigrationProver::prove_transfer`], which installs the Orchard source anchor and the funding
/// note's witness against that boundary and the Ironwood destination anchor (through the PCZT
/// `Updater` role), then proves both bundles. The proven PCZT replaces the stored one and the
/// transaction becomes [`Proved`](MigrationTxState::Proved), ready to broadcast.
///
/// The CALLER decides WHEN to prove each transfer (once its funding note is mined and its drawn
/// anchor boundary has settled — [`advance_migration`] surfaces this as [`AdvanceStep::Prove`],
/// typically at a sync wake-up well before the broadcast height); this function performs the proof
/// for the one transfer `id`. It is idempotent only in the sense that a transaction not in
/// [`Signed`](MigrationTxState::Signed) is rejected with [`ProveError::NotReady`] rather than
/// re-proved.
///
/// A prover that reports the funding note ABSENT from the account's unspent set
/// ([`ProveFailure::InputNotAvailable`]) is not an error: absence is a membership observation
/// that cannot by itself distinguish a SPENT input from one whose creating transaction the wallet
/// has not scanned yet, so the engine sharpens it into a [`ProveOutcome`] by DEPENDENCY COVERAGE.
/// If every transaction this one waits on is mined at or below the height the observation rests
/// on, the input note was necessarily scanned and its absence is positive evidence of a spend:
/// the observation is recorded (marking this transaction and, through the dependency closure,
/// everything stranded behind it) and answered
/// [`MarkedUnsatisfiable`](ProveOutcome::MarkedUnsatisfiable). Anything less — a dependency mined
/// above that height, or an unmined one — concludes nothing and answers
/// [`NotYetProvable`](ProveOutcome::NotYetProvable) with no state change; a false mark would
/// strand live value behind an observation only a reorg can clear, so the conservative reading is
/// always a retry.
///
/// The caller PERSISTS the state afterwards, as for a successful proof — a `MarkedUnsatisfiable`
/// outcome changed the marks and the closure, and an unpersisted mark would be lost on the next
/// launch.
#[cfg(feature = "orchard")]
pub fn prove_transfer<P>(
    prover: &mut P,
    state: &mut MigrationState,
    id: MigrationTransferId,
) -> Result<ProveOutcome, ProveError<P::Error>>
where
    P: MigrationProver,
{
    let tx = state
        .transactions()
        .iter()
        .find(|t| t.id() == id)
        .ok_or(ProveError::UnknownTransaction(id))?;
    if !matches!(tx.kind(), MigrationTxKind::Transfer { .. }) {
        return Err(ProveError::NotATransfer(id));
    }
    if !matches!(tx.state(), MigrationTxState::Signed) {
        return Err(ProveError::NotReady(id));
    }
    let anchor_boundary = tx
        .anchor_boundary()
        .ok_or(ProveError::NoAnchorBoundary(id))?;

    // The stored boundary is only provable while the wallet still retains its checkpoint, which it
    // does only if it is still retaining on the grid the migration was committed under.
    let committed = state.anchor_bucket_interval();
    let configured = prover.anchor_bucket_interval();
    if committed != configured {
        return Err(ProveError::AnchorIntervalMismatch {
            committed,
            configured,
        });
    }

    let pczt = pczt::Pczt::parse(tx.pczt()).map_err(ProveError::Parse)?;
    match prover.prove_transfer(pczt, anchor_boundary) {
        Ok(proven) => {
            let bytes = proven.serialize().map_err(ProveError::Serialize)?;
            state.set_transaction_proved(id, bytes);
            Ok(ProveOutcome::Proved)
        }
        Err(ProveFailure::InputNotAvailable { nullifier, as_of }) => {
            Ok(interpret_input_not_available(state, id, nullifier, as_of))
        }
        Err(ProveFailure::Other(e)) => Err(ProveError::Prover(e)),
    }
}

/// Decide what a prover's membership-only "input not among the unspent set" observation means for
/// the transaction `id`, and record it when it is conclusive.
///
/// The observation alone cannot distinguish a SPENT input from one whose creating transaction the
/// wallet has not yet scanned. What separates the two is DEPENDENCY COVERAGE: if every transaction
/// this one waits on is mined at a height the wallet has already scanned past (`<= as_of`), the
/// input note was necessarily scanned, so its absence from the unspent set is positive evidence
/// that it was spent. A transaction with no dependencies is covered trivially — it spends notes
/// that were spendable when the migration was committed, hence long since scanned. Anything less
/// (a dependency mined above `as_of`, or an UNMINED dependency, which means the drive layer
/// offered this transaction before its inputs existed) concludes nothing: the conservative reading
/// is a retry, never a mark, since a false mark strands live value behind a durable observation
/// only a reorg can clear.
///
/// A conclusive observation is recorded through the ordinary satisfiability mutator
/// ([`MigrationState::record_satisfiability`]), so it marks and closes over the dependency graph
/// exactly as an oracle-driven one does. Its `target_height` argument judges expiry for the
/// closure's expired sources; `as_of + 1` is the honest next-block judgment at the height this
/// observation rests on.
#[cfg(feature = "orchard")]
fn interpret_input_not_available(
    state: &mut MigrationState,
    id: MigrationTransferId,
    nullifier: [u8; 32],
    as_of: BlockHeight,
) -> ProveOutcome {
    let txs = state.transactions();
    let deps_covered = txs
        .iter()
        .find(|t| t.id() == id)
        // A transaction the state does not hold is unreachable here — every caller locates it
        // before proving — and reads as uncovered rather than panicking, the same conservative
        // reading a dangling dependency gets below.
        .is_some_and(|tx| {
            tx.depends_on().iter().all(|dep| {
                txs.iter()
                    .find(|d| d.id() == *dep)
                    .and_then(|d| d.state().mined_height())
                    .is_some_and(|mined| mined <= as_of)
            })
        });
    if !deps_covered {
        return ProveOutcome::NotYetProvable;
    }

    state.record_satisfiability(
        as_of + 1,
        &[(
            id,
            StepSatisfiability::Unsatisfiable {
                cause: UnsatisfiableCause::InputsSpent {
                    nullifiers: vec![nullifier],
                },
                as_of,
            },
        )],
    );
    ProveOutcome::MarkedUnsatisfiable {
        replan_required: state.replan_required(),
    }
}

/// Prove a pre-signed migration PREPARATION transaction against a checkpoint at which its spent
/// notes are witnessable, moving it `Signed -> Proved`.
///
/// A preparation transaction carries no drawn
/// [`anchor_boundary`](MigrationTransaction::anchor_boundary) (it anchors to its already-mined
/// dependencies, not to a bucketed boundary), so the `anchor` height is supplied by the caller: it
/// proves a preparation once the notes it spends are mined and picks a checkpoint at or after that
/// (for example the current chain tip). It hands the stored PCZT and the `anchor` to
/// [`MigrationProver::prove_preparation`], which installs the Orchard source anchor and every real
/// spend's witness against that checkpoint (through the PCZT `Updater` role) and proves the single
/// Orchard bundle. The proven PCZT replaces the stored one and the transaction becomes
/// [`Proved`](MigrationTxState::Proved), ready to broadcast.
///
/// A transaction not in [`Signed`](MigrationTxState::Signed) is rejected with
/// [`ProveError::NotReady`] rather than re-proved; a transfer is rejected with
/// [`ProveError::NotAPreparation`].
///
/// As for [`prove_transfer`], a prover reporting a spend ABSENT from the account's unspent set
/// ([`ProveFailure::InputNotAvailable`]) is answered with a [`ProveOutcome`] rather than an error,
/// under the same dependency-coverage rule — which a layer-0 preparation, depending on nothing,
/// satisfies vacuously: the notes it spends were spendable when the migration was committed, hence
/// long since scanned. The caller PERSISTS the state afterwards, including after
/// [`MarkedUnsatisfiable`](ProveOutcome::MarkedUnsatisfiable), which changed the marks and the
/// dependency closure.
#[cfg(feature = "orchard")]
pub fn prove_preparation<P>(
    prover: &mut P,
    state: &mut MigrationState,
    id: MigrationTransferId,
    anchor: BlockHeight,
) -> Result<ProveOutcome, ProveError<P::Error>>
where
    P: MigrationProver,
{
    let tx = state
        .transactions()
        .iter()
        .find(|t| t.id() == id)
        .ok_or(ProveError::UnknownTransaction(id))?;
    if !matches!(tx.kind(), MigrationTxKind::Preparation { .. }) {
        return Err(ProveError::NotAPreparation(id));
    }
    if !matches!(tx.state(), MigrationTxState::Signed) {
        return Err(ProveError::NotReady(id));
    }

    let pczt = pczt::Pczt::parse(tx.pczt()).map_err(ProveError::Parse)?;
    match prover.prove_preparation(pczt, anchor) {
        Ok(proven) => {
            let bytes = proven.serialize().map_err(ProveError::Serialize)?;
            state.set_transaction_proved(id, bytes);
            Ok(ProveOutcome::Proved)
        }
        Err(ProveFailure::InputNotAvailable { nullifier, as_of }) => {
            Ok(interpret_input_not_available(state, id, nullifier, as_of))
        }
        Err(ProveFailure::Other(e)) => Err(ProveError::Prover(e)),
    }
}

/// Why rebuilding an expired migration transfer failed.
#[cfg(feature = "orchard")]
#[derive(Debug)]
pub enum RebuildError<E> {
    /// No transaction with the given id belongs to the migration.
    UnknownTransaction(MigrationTransferId),
    /// The transaction is a preparation transaction, not a transfer. Only a transfer — a leaf of
    /// the dependency graph — is rebuilt this way (with a fresh boundary anchor and canonical
    /// expiry). An expired preparation has no single-transaction rebuild: its dependents'
    /// pre-signatures commit to the notes it would have minted, so its remediation (re-signing the
    /// affected subtree) is a follow-on slice.
    NotATransfer(MigrationTransferId),
    /// The transaction has not expired at the current chain tip, so there is nothing to rebuild: it is
    /// still valid, or it has already mined. Guards against reissuing a live transaction as a second,
    /// double-spending copy.
    NotExpired(MigrationTransferId),
    /// The transfer's inputs can never again all exist unspent on chain: it is itself marked
    /// [`unsatisfiable_at`](MigrationTransaction::unsatisfiable_at), or a transaction it depends on
    /// is. A rebuild re-spends the SAME funding note under a fresh anchor and expiry, so it cannot
    /// cure a missing input — nothing a rebuild produces could ever be mined either. The remedy is
    /// the migration-level replan ([`AdvanceStep::Replan`]): mark the migration superseded and
    /// re-plan its remaining balance.
    ///
    /// Reported in preference to [`NotExpired`](Self::NotExpired) and ahead of the expiry check,
    /// because a dead transfer is usually also an expired one, and the more specific condition is
    /// the one a caller must act on.
    Unsatisfiable(MigrationTransferId),
    /// The stored migration state is internally inconsistent: the denomination plan carries no crossing or
    /// funding value for this transfer's crossing index, or the transfer's persisted nullifier
    /// cache ([`MigrationTransaction::spend_nullifiers`]) does not hold exactly the one funding
    /// nullifier a transfer spends.
    InconsistentPlan(alloc::string::String),
    /// The transfer's funding note — the EXACT note its expired PCZT spends, matched by nullifier
    /// among the wallet's spendable notes — is no longer available. It should still be unspent
    /// (the expired transfer never mined); if it is gone (spent outside the migration), the
    /// remaining balance must be re-planned instead of this part rebuilt. A different spendable
    /// note of coincidentally equal value is deliberately not substituted: denominations repeat,
    /// so it may be a sibling transfer's funding note, and spending it would make the rebuilt
    /// transfer a double-spend of that still-valid sibling.
    FundingNoteUnavailable(Zatoshis),
    /// NU6.3 is not active on this network, so there is no destination pool and no boundary grid to
    /// draw an anchor from.
    Nu63NotActive,
    /// No candidate anchor boundary exists for the rebuilt schedule (the same stale condition
    /// [`CommitError::StalePlan`] models at commit time): the migration must be re-planned.
    NoCandidateAnchor,
    /// The backend's anchor bucket grid has changed since this migration was committed. Rebuilding
    /// would draw the replacement transfer's anchor from the NEW grid while its siblings remain on
    /// the old one, leaving the migration anchored to two grids of which the wallet retains only
    /// one. The migration must be re-planned instead.
    AnchorIntervalMismatch {
        /// The grid the migration was committed under.
        committed: crate::scheduling::AnchorBucketInterval,
        /// The grid the backend schedules against now.
        configured: crate::scheduling::AnchorBucketInterval,
    },
    /// Building the fresh transfer PCZT failed.
    Build(crate::build::BuildError),
    /// The rebuilt transfer PCZT presents no well-formed set of real spends, so the real-spend
    /// nullifier cache ([`MigrationTransaction::spend_nullifiers`]) cannot be refreshed from it.
    RealSpends(crate::pczt_spends::RealSpendError),
    /// Serializing the rebuilt PCZT failed.
    Serialize(pczt::EncodingError),
    /// A wallet backend or signing operation failed.
    Backend(E),
}

#[cfg(feature = "orchard")]
impl<E: fmt::Display> fmt::Display for RebuildError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RebuildError::UnknownTransaction(id) => {
                write!(f, "no migration transaction with id {}", u32::from(*id))
            }
            RebuildError::NotATransfer(id) => write!(
                f,
                "transaction {} is a preparation transaction, not a transfer",
                u32::from(*id)
            ),
            RebuildError::NotExpired(id) => write!(
                f,
                "transaction {} has not expired; there is nothing to rebuild",
                u32::from(*id)
            ),
            RebuildError::Unsatisfiable(id) => write!(
                f,
                "transfer {}'s inputs can never again all exist unspent, so no rebuild can revive \
                 it; the migration must be re-planned",
                u32::from(*id)
            ),
            RebuildError::InconsistentPlan(m) => {
                write!(f, "the migration plan is internally inconsistent: {m}")
            }
            RebuildError::FundingNoteUnavailable(v) => write!(
                f,
                "the transfer's funding note (funding value {}) is no longer spendable; the \
                 remaining balance must be re-planned",
                u64::from(*v)
            ),
            RebuildError::Nu63NotActive => f.write_str("NU6.3 is not active on this network"),
            RebuildError::NoCandidateAnchor => f.write_str(
                "no candidate anchor boundary exists for the rebuilt schedule; the migration must \
                 be re-planned",
            ),
            RebuildError::AnchorIntervalMismatch {
                committed,
                configured,
            } => write!(
                f,
                "the migration was committed against a {}-block anchor bucket grid, but the backend \
                 now schedules against a {}-block grid; the migration must be re-planned",
                committed.block_count(),
                configured.block_count()
            ),
            RebuildError::Build(e) => write!(f, "rebuilding the transfer failed: {e}"),
            RebuildError::RealSpends(e) => {
                write!(f, "the rebuilt transfer has no real spends: {e}")
            }
            RebuildError::Serialize(e) => {
                write!(f, "serializing the rebuilt transfer failed: {e:?}")
            }
            RebuildError::Backend(e) => write!(f, "wallet backend error: {e}"),
        }
    }
}

#[cfg(feature = "orchard")]
impl<E: core::error::Error> core::error::Error for RebuildError<E> {}

/// Rebuild an EXPIRED migration transfer as an entirely NEW pre-signed transaction, signed anew
/// IN-PROCESS with the wallet's spend authority and stored back in the transfer's slot as
/// [`Signed`](MigrationTxState::Signed), with a fresh boundary anchor and canonical expiry and an
/// unchanged denomination.
///
/// A transfer can only be included in a block at or below its expiry height (ZIP 203); once the
/// chain passes it, the pre-signed transaction is dead and [`advance_migration`] surfaces it as
/// [`AdvanceStep::Rebuild`]. NOTHING of the expired artifact is reusable — the signature hash
/// covers the expiry height, so its signatures cannot authorize any rescheduled copy. This is
/// ZIP 318's expired-transaction handling: "a new transaction with a fresh anchor and expiry is
/// constructed for the affected part, with its denomination unchanged".
///
/// This function performs that reconstruction: it reschedules the part from the current tip with a
/// fresh memoryless delay, derives the new canonical expiry, draws a fresh boundary anchor, builds
/// a new transfer PCZT against the same funding note and crossing value, signs it anew, and
/// replaces the stored PCZT. Anchors and witnesses stay DEFERRED (ZIP 374): the fresh anchor is
/// installed at proving time, exactly as for an originally committed transfer.
///
/// Signing anew is what distinguishes this step from proving and broadcasting: it needs the
/// account's SPEND AUTHORITY, not just the viewing key and the network. This entry point signs
/// in-process via [`MigrationCrypto::sign`], for a wallet that holds the spend authority; a
/// migration signed by an EXTERNAL (hardware or offline) signer uses
/// [`rebuild_expired_transfer_unsigned`] instead, which leaves the rebuilt transfer awaiting the
/// device's signature.
///
/// The funding note is recovered by IDENTITY, not by value: the expired PCZT's one real spend
/// reveals the note's nullifier, which is matched among the wallet's spendable Orchard notes. The
/// note is still unspent (the expired transfer never mined), so the rebuilt transfer re-spends
/// exactly it — never a different spendable note of coincidentally equal value, which (since
/// denominations repeat) could be a sibling transfer's funding note and would make the rebuild a
/// double-spend of that sibling. If the exact note is gone (spent outside the migration), this
/// returns [`RebuildError::FundingNoteUnavailable`] and the remaining balance should be re-planned
/// rather than this part rebuilt.
///
/// The caller persists the updated state afterwards (`replace_migration`), exactly as after proving.
#[cfg(feature = "orchard")]
pub fn rebuild_expired_transfer<P, B, R>(
    params: &P,
    backend: &B,
    state: &mut MigrationState,
    id: MigrationTransferId,
    rng: &mut R,
) -> Result<(), RebuildError<<B as MigrationBackend>::Error>>
where
    P: zcash_protocol::consensus::Parameters,
    B: MigrationBackend + MigrationCrypto<Error = <B as MigrationBackend>::Error>,
    R: RngCore + rand_core::CryptoRng,
{
    rebuild_expired_transfer_inner(params, backend, state, id, rng, Signing::InProcess).map(|_| ())
}

/// Rebuild an EXPIRED migration transfer for an EXTERNAL signer: construct the same entirely new
/// transaction as [`rebuild_expired_transfer`], but leave it UNSIGNED in the
/// [`AwaitingSignature`](MigrationTxState::AwaitingSignature) state and return it as an
/// [`UnsignedMigrationTx`] to route to the signing device (split device-sized sessions with
/// [`batch_unsigned_by_action_budget`]), mirroring [`build_preparation_unsigned`].
///
/// An expired transaction must be signed ANEW — its signature hash covers the expiry height — and
/// for an externally signed migration the spend authority is on the device, not in-process: the
/// rebuild therefore requires a new signing session, unlike proving and broadcasting.
/// [`MigrationCrypto::sign`] is never called. After the device signs, call
/// [`MigrationState::apply_signature`] with the returned PCZT (matched by
/// [`UnsignedMigrationTx::id`]) to move the transfer to [`Signed`](MigrationTxState::Signed), and
/// persist with `replace_migration`.
#[cfg(feature = "orchard")]
pub fn rebuild_expired_transfer_unsigned<P, B, R>(
    params: &P,
    backend: &B,
    state: &mut MigrationState,
    id: MigrationTransferId,
    rng: &mut R,
) -> Result<UnsignedMigrationTx, RebuildError<<B as MigrationBackend>::Error>>
where
    P: zcash_protocol::consensus::Parameters,
    B: MigrationBackend + MigrationCrypto<Error = <B as MigrationBackend>::Error>,
    R: RngCore + rand_core::CryptoRng,
{
    rebuild_expired_transfer_inner(params, backend, state, id, rng, Signing::External)
        .map(|unsigned| unsigned.expect("the external signing path always returns the unsigned tx"))
}

/// Shared body of [`rebuild_expired_transfer`] (with [`Signing::InProcess`]) and
/// [`rebuild_expired_transfer_unsigned`] (with [`Signing::External`]). Returns the
/// [`UnsignedMigrationTx`] for the external path, `None` for the in-process path.
#[cfg(feature = "orchard")]
fn rebuild_expired_transfer_inner<P, B, R>(
    params: &P,
    backend: &B,
    state: &mut MigrationState,
    id: MigrationTransferId,
    rng: &mut R,
    signing: Signing,
) -> Result<Option<UnsignedMigrationTx>, RebuildError<<B as MigrationBackend>::Error>>
where
    P: zcash_protocol::consensus::Parameters,
    B: MigrationBackend + MigrationCrypto<Error = <B as MigrationBackend>::Error>,
    R: RngCore + rand_core::CryptoRng,
{
    // A rebuilt transfer draws a fresh anchor. If the backend's grid has moved since the commit,
    // that anchor would sit on a different grid from its siblings', leaving the migration anchored
    // to two grids of which the wallet retains only one — so the whole migration must be re-planned.
    // This invalidates every transfer, not just this one, so it is checked before any condition
    // specific to `id`.
    let sched_params = backend.scheduling_params();
    let committed_interval = state.anchor_bucket_interval();
    if committed_interval != sched_params.anchor_bucket_interval() {
        return Err(RebuildError::AnchorIntervalMismatch {
            committed: committed_interval,
            configured: sched_params.anchor_bucket_interval(),
        });
    }

    // The height of the next block this transfer could be mined into, against which expiry is judged.
    let target_height = backend.chain_tip_height().map_err(RebuildError::Backend)? + 1;

    // Read everything the rebuild needs from the persisted state before the mutable borrow below.
    let tx = state
        .transactions
        .iter()
        .find(|t| t.id == id)
        .ok_or(RebuildError::UnknownTransaction(id))?;
    let crossing = match tx.kind {
        MigrationTxKind::Transfer { crossing } => crossing,
        MigrationTxKind::Preparation { .. } => return Err(RebuildError::NotATransfer(id)),
    };
    // A transfer whose inputs are gone is beyond rebuilding, and that is checked BEFORE expiry: a
    // dead transfer is usually an expired one too, and answering `NotExpired` (or, worse,
    // rebuilding) would send the caller down a remedy that cannot work. The rebuild re-spends the
    // SAME funding note — recovered by identity from the nullifier cache below — so it cannot cure
    // a missing input, and its own dead dependency would leave it re-anchored to notes that never
    // arrive. `advance_migration` never surfaces such a transfer as `AdvanceStep::Rebuild`, but
    // `expired_transactions` is public and a consumer may drive the rebuild from it directly, so
    // the guard belongs here rather than only in the planning kernel.
    let dead_dependency = tx.depends_on.iter().any(|d| {
        state
            .transactions
            .iter()
            .any(|t| t.id == *d && t.unsatisfiable.is_some())
    });
    if tx.unsatisfiable.is_some() || dead_dependency {
        return Err(RebuildError::Unsatisfiable(id));
    }
    // Only an expired, not-yet-mined transfer is rebuilt (the same condition the state machine reports
    // as expired): a still-valid or already-mined transfer is a typed error, not a silently reissued
    // double spend.
    let expiry = u32::from(tx.expiry_height);
    let expired = !matches!(tx.state, MigrationTxState::Mined { .. })
        && expiry != 0
        && expiry < u32::from(target_height);
    if !expired {
        return Err(RebuildError::NotExpired(id));
    }
    let nu63_activation = params
        .activation_height(zcash_protocol::consensus::NetworkUpgrade::Nu6_3)
        .ok_or(RebuildError::Nu63NotActive)?;
    // The candidate anchor set starts at or after the funding note's creation height: the height its
    // producing preparation mined, or the NU6.3 activation for a wallet note used directly (no
    // producer).
    let funding_creation = tx
        .depends_on
        .iter()
        .filter_map(|dep| state.transactions.iter().find(|t| t.id == *dep))
        .filter_map(|producer| match producer.state {
            MigrationTxState::Mined { height, .. } => Some(height),
            _ => None,
        })
        .max()
        .unwrap_or(nu63_activation);

    let crossing_value = *state
        .denominations
        .crossing_values()
        .get(crossing)
        .ok_or_else(|| {
            RebuildError::InconsistentPlan(format!("no crossing value for transfer {crossing}"))
        })?;
    let funding_value = *state
        .denominations
        .migration_outputs()
        .get(crossing)
        .ok_or_else(|| {
            RebuildError::InconsistentPlan(format!("no funding value for transfer {crossing}"))
        })?;

    // Recover the funding note's IDENTITY from the transaction's persisted nullifier cache: its
    // one real spend's nullifier names the exact note this part is funded by. Denominations
    // repeat across a migration, so matching the wallet's spendable notes by value alone could
    // grab a sibling transfer's funding note and turn the rebuilt transfer into a double-spend of
    // that still-valid sibling. The CACHE, not the stored PCZT, is the authority: proving
    // replaces the stored bytes with the PROVEN PCZT, whose real spend carries an installed
    // witness, so the deferred-witness rule no longer identifies it there — while the cache is
    // extracted at commit (and refreshed below), before any proof.
    let funding_nullifier = match tx.spend_nullifiers.as_slice() {
        &[nf] => nf,
        _ => {
            return Err(RebuildError::InconsistentPlan(
                "the transfer's nullifier cache does not hold exactly one funding nullifier".into(),
            ));
        }
    };

    // The exact note must still be among the wallet's spendable notes; if it is gone (spent
    // outside the migration), the remaining balance must be re-planned rather than this part
    // rebuilt, so a different note of coincidentally equal value is deliberately NOT substituted.
    let fvk = backend.orchard_fvk().map_err(RebuildError::Backend)?;
    let account_derivation = backend
        .account_derivation()
        .map_err(RebuildError::Backend)?;
    let spendable_values = backend
        .spendable_orchard_note_values()
        .map_err(RebuildError::Backend)?;
    let mut note = None;
    for (index, value) in spendable_values.iter().enumerate() {
        if *value != funding_value {
            continue;
        }
        let candidate = backend
            .resolve_wallet_note(index)
            .map_err(RebuildError::Backend)?;
        if candidate.nullifier(&fvk).to_bytes() == funding_nullifier {
            note = Some(candidate);
            break;
        }
    }
    let note = note.ok_or(RebuildError::FundingNoteUnavailable(funding_value))?;

    // Reschedule the part with a fresh memoryless delay from the current tip, and derive its new
    // canonical expiry and a fresh boundary anchor for that schedule.
    let scheduled_height = target_height + sched_params.transfer_delay().draw(&mut *rng);
    let expiry_height = scheduling::expiry_height(scheduled_height);
    let anchor_boundary = scheduling::draw_anchor_boundary(
        sched_params.anchor_bucket_interval(),
        nu63_activation,
        funding_creation,
        scheduled_height,
        rng,
    )
    .ok_or(RebuildError::NoCandidateAnchor)?;

    // Build the entirely new transfer against the same funding note and crossing value; anchors
    // and witnesses stay deferred (installed at proving time, ZIP 374). The expired artifact
    // contributes nothing: the new expiry is covered by the signature hash, so the transaction is
    // signed anew below (in-process) or by the external signer.
    let pczt = crate::build::build_transfer_pczt(
        params,
        u32::from(target_height),
        u32::from(expiry_height),
        &fvk,
        note,
        crossing_value,
        account_derivation.as_ref(),
        &mut *rng,
    )
    .map_err(RebuildError::Build)?;
    // Refresh the nullifier cache from the rebuilt PCZT, for uniformity with the commit path; the
    // rebuild spends the same funding note, so the cached value is in fact stable.
    let spend_nullifiers: Vec<[u8; 32]> = crate::pczt_spends::real_spend_nullifiers(&pczt)
        .map_err(RebuildError::RealSpends)?
        .into_iter()
        .map(|(_, nf)| nf.to_bytes())
        .collect();
    let (bytes, new_state, unsigned) = match signing {
        Signing::InProcess => {
            let signed = backend.sign(pczt).map_err(RebuildError::Backend)?;
            let bytes = signed.serialize().map_err(RebuildError::Serialize)?;
            (bytes, MigrationTxState::Signed, None)
        }
        Signing::External => {
            let bytes = pczt.serialize().map_err(RebuildError::Serialize)?;
            let unsigned = UnsignedMigrationTx {
                id,
                pczt: bytes.clone(),
                actions: crate::denomination::SOURCE_ACTIONS_PER_TRANSFER
                    + crate::denomination::DESTINATION_ACTIONS_PER_TRANSFER,
            };
            (bytes, MigrationTxState::AwaitingSignature, Some(unsigned))
        }
    };

    // Replace the expired transaction's PCZT and reschedule it on the fresh schedule.
    let tx = state
        .transactions
        .iter_mut()
        .find(|t| t.id == id)
        .expect("the transaction was found above");
    tx.pczt = bytes;
    tx.scheduled_height = scheduled_height;
    tx.expiry_height = expiry_height;
    tx.anchor_boundary = Some(anchor_boundary);
    tx.state = new_state;
    tx.spend_nullifiers = spend_nullifiers;
    Ok(unsigned)
}

/// How a freshly built migration PCZT is finished by the commit functions: signed in-process with the
/// wallet's spend authority, or left unsigned for an external (hardware or offline) signer.
#[cfg(feature = "orchard")]
#[derive(Clone, Copy)]
enum Signing {
    /// Sign in-process via [`MigrationCrypto::sign`].
    InProcess,
    /// Leave the PCZT unsigned for an external signer; the caller receives it to sign out of band.
    External,
}

/// An UNSIGNED migration transaction PCZT to route to an external (hardware or offline) signer, paired
/// with the id that [`MigrationState::apply_signature`] uses to store the signed PCZT it returns as.
///
/// Produced by [`build_preparation_unsigned`]. The `(id, pczt)` pairing MUST survive the
/// round-trip to the signer, because `apply_signature` matches the returned signed PCZT back to
/// its transaction by id; [`batch_unsigned_by_action_budget`] splits a migration's worth of these
/// into device-sized signing sessions.
#[cfg(feature = "orchard")]
#[derive(Clone, Debug, Getters, CopyGetters)]
pub struct UnsignedMigrationTx {
    /// The transaction's id in the committed migration.
    #[getset(get_copy = "pub")]
    pub(crate) id: MigrationTransferId,
    /// The serialized UNSIGNED PCZT to sign out of band.
    #[getset(get = "pub")]
    pub(crate) pczt: Vec<u8>,
    /// The number of Orchard-family actions the signer processes for this transaction (its
    /// padded action count), so signing sessions can be bounded by a device's action budget
    /// (see [`batch_unsigned_by_action_budget`]).
    #[getset(get_copy = "pub")]
    pub(crate) actions: usize,
}

#[cfg(feature = "orchard")]
impl UnsignedMigrationTx {
    /// Take the id and the unsigned PCZT bytes (to route the bytes to the external signer while
    /// keeping the id to match the signed result back; see
    /// [`MigrationState::apply_signature`](crate::engine::MigrationState)).
    pub fn into_parts(self) -> (MigrationTransferId, Vec<u8>) {
        (self.id, self.pczt)
    }
}

/// Split unsigned migration transactions into SIGNING ROUNDS: consecutive batches, preserving the
/// given order (the commit functions emit topological order), each holding at most `budget` total
/// [`actions`](UnsignedMigrationTx::actions) — except that a batch always holds at least one
/// transaction, so a single transaction larger than the budget still gets a round of its own. This
/// is the order-preserving [`NextFit`](crate::signing_rounds::NextFit) packing; for the fewest
/// signer interactions, use [`MigrationPlan::group_unsigned`], which packs optimally with the plan's
/// transaction kinds.
///
/// Every transaction is fully built and independent at signing time (anchors and witnesses are
/// deferred to proving; nothing waits on the chain), so a round boundary reflects only the signer's
/// per-interaction capacity — a hardware device's action budget — and each round's results are
/// applied back with [`MigrationState::apply_signature`] in any order.
#[cfg(feature = "orchard")]
pub fn batch_unsigned_by_action_budget(
    unsigned: Vec<UnsignedMigrationTx>,
    budget: SigningRoundBudget,
) -> Vec<Vec<UnsignedMigrationTx>> {
    let cap = budget.max_actions() as usize;
    let mut rounds: Vec<Vec<UnsignedMigrationTx>> = Vec::new();
    let mut current: Vec<UnsignedMigrationTx> = Vec::new();
    let mut current_actions = 0usize;
    for tx in unsigned {
        if !current.is_empty() && current_actions.saturating_add(tx.actions) > cap {
            rounds.push(core::mem::take(&mut current));
            current_actions = 0;
        }
        current_actions = current_actions.saturating_add(tx.actions);
        current.push(tx);
    }
    if !current.is_empty() {
        rounds.push(current);
    }
    rounds
}

#[cfg(feature = "orchard")]
impl MigrationPlan {
    /// Group this plan's built UNSIGNED transactions into signing rounds bounded by `budget`, using
    /// the optimal [`MinRounds`] packing (fewest signer interactions). The `unsigned` come from
    /// [`build_preparation_unsigned`] in commit order; each is matched back to its round by
    /// [`UnsignedMigrationTx::id`], so the rounds reflect the SAME grouping the plan's
    /// [`signing_rounds`](Self::signing_rounds) preview showed the user. Prefer this to
    /// [`batch_unsigned_by_action_budget`] (which packs order-preserving, not optimally) when driving
    /// a real signer.
    pub fn group_unsigned(
        &self,
        unsigned: Vec<UnsignedMigrationTx>,
        budget: SigningRoundBudget,
    ) -> Vec<Vec<UnsignedMigrationTx>> {
        let rounds = self.signing_rounds(budget);
        let mut round_of: BTreeMap<u32, usize> = BTreeMap::new();
        for (i, round) in rounds.iter().enumerate() {
            for tx in round.transactions() {
                round_of.insert(u32::from(tx.id()), i);
            }
        }
        let mut buckets: Vec<Vec<UnsignedMigrationTx>> =
            (0..rounds.len()).map(|_| Vec::new()).collect();
        // Any unsigned transaction the plan did not enumerate (never expected) becomes its own
        // trailing round rather than being dropped.
        let mut leftover: Vec<UnsignedMigrationTx> = Vec::new();
        for tx in unsigned {
            match round_of.get(&u32::from(tx.id())) {
                Some(&i) => buckets[i].push(tx),
                None => leftover.push(tx),
            }
        }
        if !leftover.is_empty() {
            buckets.push(leftover);
        }
        buckets.retain(|b| !b.is_empty());
        buckets
    }
}

/// Serialize a freshly built PCZT for storage. For [`Signing::InProcess`], sign it with the backend and
/// return the signed bytes as [`Signed`](MigrationTxState::Signed); for [`Signing::External`], return the
/// unsigned bytes as [`AwaitingSignature`](MigrationTxState::AwaitingSignature) (the caller also routes a
/// copy of those bytes to the external signer).
#[cfg(feature = "orchard")]
fn finish_built_pczt<B>(
    backend: &mut B,
    pczt: ::pczt::Pczt,
    signing: Signing,
) -> Result<(Vec<u8>, MigrationTxState), CommitError<<B as MigrationBackend>::Error>>
where
    B: MigrationBackend + MigrationCrypto<Error = <B as MigrationBackend>::Error>,
{
    match signing {
        Signing::InProcess => {
            let signed = backend.sign(pczt).map_err(CommitError::Backend)?;
            let bytes = signed.serialize().map_err(CommitError::Serialize)?;
            Ok((bytes, MigrationTxState::Signed))
        }
        Signing::External => {
            let bytes = pczt.serialize().map_err(CommitError::Serialize)?;
            Ok((bytes, MigrationTxState::AwaitingSignature))
        }
    }
}

/// A spendable note recovered from an already-built preparation transaction, or a direct-funding
/// wallet note, tracked by the commit so a later transaction can spend it BY VALUE before it is
/// mined. Its signable plaintext is fixed at build time (its `rho` is the paired spend's nullifier
/// and its `rseed` is drawn by the builder); only its tree position awaits mining, and that matters
/// only to the proof (deferred to proving time, ZIP 374). `consumed` guards against spending it
/// twice, and `producer` is the preparation transaction that mints it (or `None` for a
/// direct-funding wallet note), so a transfer depends only on its own funding note's producer.
#[cfg(feature = "orchard")]
struct MintedNote {
    value: Zatoshis,
    note: orchard::note::Note,
    consumed: bool,
    producer: Option<MigrationTransferId>,
}

/// Commit a planned migration: build and pre-sign EVERY transaction — each preparation layer, in
/// topological order, then every transfer — in this one pass, and persist the whole committed
/// migration through the backend. Anchors and witnesses are deferred to proving time (ZIP 374), so
/// a spent note's plaintext is all the builder needs: layer 0 spends the wallet's own notes, and
/// each later layer's feeders and each transfer's funding note are recovered from the built (still
/// unmined) bundles of the transactions that mint them. Mining gates only the BROADCAST order,
/// which the state machine walks by dependencies and scheduled heights; nothing is ever signed in
/// a second session because of on-chain state.
///
/// For an EXTERNAL signer (a hardware wallet), use [`build_preparation_unsigned`] instead, which
/// builds the same transactions but leaves them unsigned for the device.
///
/// Refuses to overwrite a stored non-terminal migration
/// ([`CommitError::MigrationInProgress`]): a committed migration is resumed from the store, or
/// cancelled, never rebuilt over.
///
/// `params` is the network, `target_height` the height the transactions are built at (post-NU6.3),
/// `rng` a cryptographically secure RNG, and `replan_threshold` the policy stamped on the committed
/// migration (see [`MigrationState::replan_threshold`]) — pass [`ReplanThreshold::DEFAULT`] absent
/// a specific policy.
#[cfg(feature = "orchard")]
pub fn commit_preparation<P, B, R>(
    params: &P,
    target_height: BlockHeight,
    backend: &mut B,
    plan: &MigrationPlan,
    rng: &mut R,
    replan_threshold: ReplanThreshold,
) -> Result<MigrationState, CommitError<<B as MigrationBackend>::Error>>
where
    P: zcash_protocol::consensus::Parameters + Clone,
    B: MigrationBackend
        + MigrationCrypto<Error = <B as MigrationBackend>::Error>
        + PoolMigrationRead<Error = <B as MigrationBackend>::Error>
        + PoolMigrationWrite,
    R: RngCore + rand_core::CryptoRng,
{
    commit_preparation_inner(
        params,
        target_height,
        backend,
        plan,
        rng,
        Signing::InProcess,
        replan_threshold,
    )
    .map(|output| output.state)
}

/// Commit a planned migration for an EXTERNAL signer: build EVERY transaction exactly as
/// [`commit_preparation`] does, but leave them UNSIGNED (in the
/// [`AwaitingSignature`](MigrationTxState::AwaitingSignature) state), persist the committed
/// migration, and return the state together with the unsigned PCZTs, in topological order, to
/// route to the signing device — split them into device-sized sessions with
/// [`batch_unsigned_by_action_budget`].
///
/// After the device signs, call [`MigrationState::apply_signature`] for each returned PCZT (matched by
/// [`UnsignedMigrationTx::id`]) to move it to [`Signed`](MigrationTxState::Signed), persist with
/// `replace_migration`, and drive the broadcasts through the normal state machine (proving remains a
/// consumer responsibility, at broadcast time).
///
/// `params` is the network, `target_height` the height the transactions are built at (post-NU6.3),
/// `rng` a cryptographically secure RNG, and `replan_threshold` the policy stamped on the committed
/// migration (see [`MigrationState::replan_threshold`]) — pass [`ReplanThreshold::DEFAULT`] absent
/// a specific policy.
#[cfg(feature = "orchard")]
pub fn build_preparation_unsigned<P, B, R>(
    params: &P,
    target_height: BlockHeight,
    backend: &mut B,
    plan: &MigrationPlan,
    rng: &mut R,
    replan_threshold: ReplanThreshold,
) -> Result<(MigrationState, Vec<UnsignedMigrationTx>), CommitError<<B as MigrationBackend>::Error>>
where
    P: zcash_protocol::consensus::Parameters + Clone,
    B: MigrationBackend
        + MigrationCrypto<Error = <B as MigrationBackend>::Error>
        + PoolMigrationRead<Error = <B as MigrationBackend>::Error>
        + PoolMigrationWrite,
    R: RngCore + rand_core::CryptoRng,
{
    commit_preparation_inner(
        params,
        target_height,
        backend,
        plan,
        rng,
        Signing::External,
        replan_threshold,
    )
    .map(|output| (output.state, output.unsigned))
}

/// Shared body of [`commit_preparation`] (with [`Signing::InProcess`]) and
/// [`build_preparation_unsigned`] (with [`Signing::External`]). Layer-0 transactions are finished via
/// [`finish_built_pczt`]; the returned `Vec<UnsignedMigrationTx>` is empty for the in-process path.
#[cfg(feature = "orchard")]
fn commit_preparation_inner<P, B, R>(
    params: &P,
    target_height: BlockHeight,
    backend: &mut B,
    plan: &MigrationPlan,
    rng: &mut R,
    signing: Signing,
    replan_threshold: ReplanThreshold,
) -> Result<CommitOutput, CommitError<<B as MigrationBackend>::Error>>
where
    P: zcash_protocol::consensus::Parameters + Clone,
    B: MigrationBackend
        + MigrationCrypto<Error = <B as MigrationBackend>::Error>
        + PoolMigrationRead<Error = <B as MigrationBackend>::Error>
        + PoolMigrationWrite,
    R: RngCore + rand_core::CryptoRng,
{
    let mut committer = Committer::start(params, target_height, backend, rng, signing)?;
    committer.build_preparation_layers(plan)?;
    committer.add_direct_funding(plan)?;
    committer.build_transfers(plan)?;
    // `into_state` consumes the committer, releasing its `&mut backend` reborrow, so the store
    // write below can borrow `backend` again.
    let output = committer.into_state(plan, replan_threshold);
    backend
        .replace_migration(&output.state)
        .map_err(CommitError::Backend)?;
    Ok(output)
}

/// Commit a planned migration in-process (as [`commit_preparation`]) and additionally return each
/// transfer paired with the funding note it spends. The funding notes are what a prover needs to
/// locate each transfer's spend in the wallet's Orchard commitment tree at proving time; a
/// production consumer recovers them from its own scanned note store, so this entry point exists
/// for tests (and downstream test harnesses) that drive real proving without a scanning wallet.
///
/// `replan_threshold` is the policy stamped on the committed migration (see
/// [`MigrationState::replan_threshold`]) — pass [`ReplanThreshold::DEFAULT`] absent a specific
/// policy; the other parameters are as [`commit_preparation`]'s.
#[cfg(all(feature = "orchard", any(test, feature = "test-dependencies")))]
pub fn commit_preparation_with_funding<P, B, R>(
    params: &P,
    target_height: BlockHeight,
    backend: &mut B,
    plan: &MigrationPlan,
    rng: &mut R,
    replan_threshold: ReplanThreshold,
) -> Result<(MigrationState, TransferFunding), CommitError<<B as MigrationBackend>::Error>>
where
    P: zcash_protocol::consensus::Parameters + Clone,
    B: MigrationBackend
        + MigrationCrypto<Error = <B as MigrationBackend>::Error>
        + PoolMigrationRead<Error = <B as MigrationBackend>::Error>
        + PoolMigrationWrite,
    R: RngCore + rand_core::CryptoRng,
{
    commit_preparation_inner(
        params,
        target_height,
        backend,
        plan,
        rng,
        Signing::InProcess,
        replan_threshold,
    )
    .map(|output| (output.state, output.transfer_funding))
}

/// Hosts the shared mutable state that building a whole committed migration threads through its
/// stages: the accumulating `transactions`/`unsigned` outputs, the `next_id` counter, the per-layer
/// `layer_ids` (so a later layer, and the transfers, can depend on the layer before them), and the
/// `minted` pool of notes that already-built preparation transactions (and direct-funding wallet
/// notes) mint for later spends. Owning the backend, rng, and resolved `fvk` lets each stage of
/// [`commit_preparation_inner`] be a method: [`Committer::start`] then
/// [`Committer::build_preparation_layers`], [`Committer::add_direct_funding`],
/// [`Committer::build_transfers`], and finally [`Committer::into_state`], which consumes the
/// committer and returns the assembled state (releasing the `&mut backend` reborrow so the caller
/// can persist it). `plan` is deliberately NOT a field: passing it as a method parameter avoids
/// borrowing `self` both immutably (to iterate the plan) and mutably (to call `next_id`/the
/// resolvers) at once.
#[cfg(feature = "orchard")]
struct Committer<'a, P, B, R> {
    params: &'a P,
    target_height: BlockHeight,
    backend: &'a mut B,
    rng: &'a mut R,
    signing: Signing,
    fvk: orchard::keys::FullViewingKey,
    /// The ZIP 32 account every built transaction's spends are stamped with, so an external Signer
    /// can identify them. Resolved once in [`Committer::start`], alongside `fvk`.
    account_derivation: Option<AccountDerivation>,
    transactions: Vec<MigrationTransaction>,
    unsigned: Vec<UnsignedMigrationTx>,
    next_id: u32,
    layer_ids: Vec<Vec<MigrationTransferId>>,
    minted: Vec<MintedNote>,
    /// Each transfer paired with the funding note it spends, captured as the transfer is built.
    /// The commit path already recovers every funding note's plaintext to build the transfer; a
    /// prover needs it at proving time to locate the note in the wallet's commitment tree (in
    /// production the wallet finds it by nullifier in its own note store). Surfaced through
    /// [`commit_preparation_with_funding`]; the normal commit path drops it.
    transfer_funding: TransferFunding,
}

#[cfg(feature = "orchard")]
impl<'a, P, B, R> Committer<'a, P, B, R>
where
    P: zcash_protocol::consensus::Parameters + Clone,
    B: MigrationBackend
        + MigrationCrypto<Error = <B as MigrationBackend>::Error>
        + PoolMigrationRead<Error = <B as MigrationBackend>::Error>
        + PoolMigrationWrite,
    R: RngCore + rand_core::CryptoRng,
{
    /// Open a commit: guard against overwriting a live migration, resolve the account's Orchard FVK,
    /// and initialize the empty accumulators.
    fn start(
        params: &'a P,
        target_height: BlockHeight,
        backend: &'a mut B,
        rng: &'a mut R,
        signing: Signing,
    ) -> Result<Self, CommitError<<B as MigrationBackend>::Error>> {
        // A committed migration is resumed from the store (or cancelled), never rebuilt over (see
        // [`MigrationState::is_terminal`]): checked FIRST, before any signing work, so a crashed or
        // re-run consumer cannot orphan in-flight pre-signed transactions by re-committing.
        if backend
            .get_migration()
            .map_err(CommitError::Backend)?
            .is_some_and(|existing| !existing.is_terminal())
        {
            return Err(CommitError::MigrationInProgress);
        }

        let fvk = backend.orchard_fvk().map_err(CommitError::Backend)?;
        let account_derivation = backend.account_derivation().map_err(CommitError::Backend)?;

        Ok(Self {
            params,
            target_height,
            backend,
            rng,
            signing,
            fvk,
            account_derivation,
            transactions: Vec::new(),
            unsigned: Vec::new(),
            next_id: 0,
            layer_ids: Vec::new(),
            minted: Vec::new(),
            transfer_funding: Vec::new(),
        })
    }

    /// Assign and consume the next sequential transaction id.
    fn next_id(&mut self) -> MigrationTransferId {
        let id = MigrationTransferId(self.next_id);
        self.next_id += 1;
        id
    }

    /// Resolve the Orchard notes a preparation transaction spends: wallet notes from the backend
    /// (checking each against its planned value), and feeder notes from the `minted` pool (marking
    /// each consumed).
    fn resolve_prep_spends(
        &mut self,
        prep_tx: &crate::preparation::PrepTransaction,
        layer: usize,
    ) -> Result<Vec<orchard::note::Note>, CommitError<<B as MigrationBackend>::Error>> {
        let mut spends = Vec::with_capacity(prep_tx.inputs().len());
        for input in prep_tx.inputs() {
            match input {
                PrepInput::Wallet { index, value } => {
                    let note = self
                        .backend
                        .resolve_wallet_note(*index)
                        .map_err(CommitError::Backend)?;
                    // The plan captured this note by its index into the spendable set at
                    // PLANNING time; any receipt or spend since then shifts the indices,
                    // so a resolved note whose value differs from the planned one means
                    // the plan is stale — caught here as a typed error rather than as an
                    // opaque balance failure (or, for an equal-valued interloper, a
                    // silently signed spend of a note the plan reserved elsewhere).
                    if note.value().inner() != u64::from(*value) {
                        return Err(CommitError::StalePlan);
                    }
                    spends.push(note);
                }
                PrepInput::Prior { value, .. } => {
                    // A feeder minted by an earlier layer, recovered when that layer was
                    // built above (the plan's layers are in topological order).
                    let feeder = self
                        .minted
                        .iter_mut()
                        .find(|m| !m.consumed && m.value == *value)
                        .ok_or_else(|| {
                            CommitError::InconsistentPlan(format!(
                                "layer {layer} spends a feeder note of value {} that no \
                                 earlier layer mints",
                                u64::from(*value)
                            ))
                        })?;
                    feeder.consumed = true;
                    spends.push(feeder.note);
                }
            }
        }
        Ok(spends)
    }

    /// Build and pre-sign every preparation transaction, layer by layer in topological order,
    /// growing the `minted` pool with each transaction's recovered spendable outputs.
    fn build_preparation_layers(
        &mut self,
        plan: &MigrationPlan,
    ) -> Result<(), CommitError<<B as MigrationBackend>::Error>> {
        for (layer, prep_layer) in plan.preparation().layers().iter().enumerate() {
            let mut this_layer_ids: Vec<MigrationTransferId> = Vec::with_capacity(prep_layer.len());
            for (index, prep_tx) in prep_layer.iter().enumerate() {
                let id = self.next_id();
                this_layer_ids.push(id);

                let spends = self.resolve_prep_spends(prep_tx, layer)?;

                let depends_on = if layer == 0 {
                    Vec::new()
                } else {
                    self.layer_ids
                        .last()
                        .cloned()
                        .expect("a layer after layer 0 has a preceding layer")
                };
                // The drawn preparation schedule temporally decouples the transactions of a layer
                // from one another (see `MigrationPlan::prep_schedule`). The expiry the
                // pre-signature commits to must match that schedule, not the build height: the
                // canonical rolling window at the scheduled height.
                let scheduled_height = *plan
                    .prep_schedule()
                    .get(layer)
                    .and_then(|layer_schedule| layer_schedule.get(index))
                    .ok_or_else(|| {
                        CommitError::InconsistentPlan(format!(
                            "preparation schedule has no entry for layer {layer} transaction {index}"
                        ))
                    })?;
                let expiry_height = crate::scheduling::expiry_height(scheduled_height);
                // The field accesses `self.params`/`self.fvk`/`self.account_derivation`/`self.rng`
                // are DISJOINT, so the borrow checker accepts them together here — as long as no
                // whole-`self` method call (like `next_id`/`resolve_prep_spends` above) is
                // interleaved.
                let (pczt, placed) = build_prep_tx(
                    self.params,
                    u32::from(self.target_height),
                    u32::from(expiry_height),
                    &self.fvk,
                    spends,
                    prep_tx.outputs(),
                    self.account_derivation.as_ref(),
                    &mut *self.rng,
                )
                .map_err(CommitError::Build)?;

                // Grow the minted pool with this transaction's recovered spendable outputs. Change
                // outputs are excluded: they stay in the source pool and must never be matched to a
                // feeder or funding request of a coincidentally equal value.
                for (_action_index, output, note) in placed {
                    match output {
                        PrepOutput::Funding(value) | PrepOutput::Intermediate(value) => {
                            self.minted.push(MintedNote {
                                value,
                                note,
                                consumed: false,
                                producer: Some(id),
                            });
                        }
                        PrepOutput::Change(_) => {}
                    }
                }

                // Cache the real-spend nullifiers off the built PCZT before it is consumed by
                // signing/serialization, so the feature-free state machine never re-parses the
                // stored bytes.
                let spend_nullifiers = crate::pczt_spends::real_spend_nullifiers(&pczt)
                    .map_err(CommitError::RealSpends)?
                    .into_iter()
                    .map(|(_, nf)| nf.to_bytes())
                    .collect();
                let (bytes, tx_state) = finish_built_pczt(self.backend, pczt, self.signing)?;
                if matches!(self.signing, Signing::External) {
                    self.unsigned.push(UnsignedMigrationTx {
                        id,
                        pczt: bytes.clone(),
                        actions: crate::preparation::PREP_TX_ACTIONS,
                    });
                }
                self.transactions.push(MigrationTransaction {
                    id,
                    kind: MigrationTxKind::Preparation { layer, index },
                    pczt: bytes,
                    depends_on,
                    scheduled_height,
                    expiry_height,
                    anchor_boundary: None,
                    state: tx_state,
                    // The engine does not yet acquire locks; a later slice that draws a
                    // `LockOwner` for the commit would set this here.
                    lock_owner: None,
                    // A freshly committed transaction carries no spent-input observation.
                    unsatisfiable: None,
                    spend_nullifiers,
                    // Nor a rejected broadcast: it has not been broadcast at all.
                    broadcast_failure_at: None,
                });
            }
            self.layer_ids.push(this_layer_ids);
        }
        Ok(())
    }

    /// Add the direct-funding wallet notes (already exactly a funding value; no preparation
    /// transaction mints them) to the `minted` pool the transfers draw from.
    fn add_direct_funding(
        &mut self,
        plan: &MigrationPlan,
    ) -> Result<(), CommitError<<B as MigrationBackend>::Error>> {
        for &(wallet_index, value) in plan.preparation().direct_funding_notes() {
            let note = self
                .backend
                .resolve_wallet_note(wallet_index)
                .map_err(CommitError::Backend)?;
            if note.value().inner() != u64::from(value) {
                return Err(CommitError::StalePlan);
            }
            // A direct-funding wallet note already exists on-chain, so its transfer has no producer
            // to wait on.
            self.minted.push(MintedNote {
                value,
                note,
                consumed: false,
                producer: None,
            });
        }
        Ok(())
    }

    /// Build and pre-sign every transfer, spending each crossing's funding note out of the `minted`
    /// pool and drawing the boundary anchor it will prove against.
    fn build_transfers(
        &mut self,
        plan: &MigrationPlan,
    ) -> Result<(), CommitError<<B as MigrationBackend>::Error>> {
        // Each transfer waits only for the preparation transaction that MINTS ITS OWN funding note
        // to be mined (recorded as that note's producer in `minted`), not for the whole last layer:
        // as soon as a transfer's own funding note is on-chain it may broadcast at its scheduled
        // height, independently of the other crossings' preparation. This follows ZIP 318's
        // per-note availability MUST ("wait until the boundary that closes the anchor-height bucket
        // in which a note-preparation transaction was mined has passed before treating ITS output
        // notes as available for migration") and consciously RELAXES the more conservative SHOULD
        // that all note preparation complete before Phase 2 begins. The relaxation is safe: the
        // schedule is already floored at the estimated last-preparation height, and the
        // boundary-passed half of the MUST is still enforced downstream, since `draw_anchor_boundary`
        // yields an anchor only once a boundary at or after the note's creation exists, so a transfer
        // cannot be proved (hence broadcast) before then. A funding note used directly from the
        // wallet has no producer, so that transfer's dependency set is empty.

        // The boundary anchor each transfer will PROVE against is drawn here, at scheduling time,
        // because the schedule fully determines it: the candidate set lies strictly above the NU6.3
        // activation, at or after the height the funding notes exist on-chain (the last drawn
        // preparation height plus the mining margin — the estimate `plan_migration` floored the
        // schedule on), and strictly below the most recent boundary at the transfer's scheduled
        // broadcast height. The anchor and the funding note's witness are installed against that
        // boundary through the PCZT Updater role at proving time (ZIP 374); nothing here needs them.
        //
        // `plan_migration` floors the first scheduled transfer on this same estimate, so every
        // transfer has a candidate boundary by construction; an empty draw therefore means the plan
        // has gone STALE (committed at a height far past the estimate the schedule was floored on)
        // and must be re-planned — it is an error, never a deferred fallback.
        let est_last_prep_height = plan
            .prep_schedule()
            .last()
            .and_then(|layer| layer.last())
            .map_or(self.target_height, |&h| h + EST_PREP_LAYER_MINING_BLOCKS);
        // The anchor draw needs the NU6.3 activation height; derive it from `params` here rather
        // than carrying it as a field (it is a pure function of the network).
        let nu63_activation = self
            .params
            .activation_height(zcash_protocol::consensus::NetworkUpgrade::Nu6_3)
            .ok_or(CommitError::Nu63NotActive)?;
        // The grid to draw from is the backend's, so the boundary each transfer anchors to is one
        // whose checkpoint that backend retains.
        let anchor_bucket_interval = self.backend.scheduling_params().anchor_bucket_interval();
        for (crossing, schedule) in plan.schedule().iter().enumerate() {
            let id = self.next_id();

            let funding_value = *plan.funding_notes().get(crossing).ok_or_else(|| {
                CommitError::InconsistentPlan(format!(
                    "no funding note value for crossing {crossing}"
                ))
            })?;
            // Copy `note`/`producer` (both `Copy`) out of the `minted` borrow so it ends before the
            // disjoint-field build call below.
            let (note, producer) = {
                let funding_note = self
                    .minted
                    .iter_mut()
                    .find(|m| !m.consumed && m.value == funding_value)
                    .ok_or_else(|| {
                        CommitError::InconsistentPlan(format!(
                            "no minted funding note for crossing {crossing}"
                        ))
                    })?;
                funding_note.consumed = true;
                (funding_note.note, funding_note.producer)
            };
            // Depend only on the preparation transaction that mints this funding note (or nothing,
            // for a direct-funding wallet note), so this crossing releases as soon as its own note
            // is mined.
            let depends_on: Vec<MigrationTransferId> = producer.into_iter().collect();
            let crossing_value = *plan
                .denominations()
                .crossing_values()
                .get(crossing)
                .ok_or_else(|| {
                    CommitError::InconsistentPlan(format!(
                        "no stored crossing value for transfer {crossing}"
                    ))
                })?;

            let pczt = build_transfer_pczt(
                self.params,
                u32::from(self.target_height),
                u32::from(schedule.expiry_height()),
                &self.fvk,
                note,
                crossing_value,
                self.account_derivation.as_ref(),
                &mut *self.rng,
            )
            .map_err(CommitError::Build)?;
            let anchor_boundary = scheduling::draw_anchor_boundary(
                anchor_bucket_interval,
                nu63_activation,
                est_last_prep_height,
                schedule.broadcast_height(),
                self.rng,
            )
            .ok_or(CommitError::StalePlan)?;
            // Cache the real-spend nullifiers off the built PCZT before it is consumed by
            // signing/serialization, so the feature-free state machine never re-parses the
            // stored bytes.
            let spend_nullifiers = crate::pczt_spends::real_spend_nullifiers(&pczt)
                .map_err(CommitError::RealSpends)?
                .into_iter()
                .map(|(_, nf)| nf.to_bytes())
                .collect();
            let (bytes, tx_state) = finish_built_pczt(self.backend, pczt, self.signing)?;
            if matches!(self.signing, Signing::External) {
                self.unsigned.push(UnsignedMigrationTx {
                    id,
                    pczt: bytes.clone(),
                    actions: crate::denomination::SOURCE_ACTIONS_PER_TRANSFER
                        + crate::denomination::DESTINATION_ACTIONS_PER_TRANSFER,
                });
            }
            self.transactions.push(MigrationTransaction {
                id,
                kind: MigrationTxKind::Transfer { crossing },
                pczt: bytes,
                depends_on,
                scheduled_height: schedule.broadcast_height(),
                expiry_height: schedule.expiry_height(),
                anchor_boundary: Some(anchor_boundary),
                state: tx_state,
                // The engine does not yet acquire locks; a later slice that draws a
                // `LockOwner` for the commit would set this here.
                lock_owner: None,
                // A freshly committed transaction carries no spent-input observation.
                unsatisfiable: None,
                spend_nullifiers,
                // Nor a rejected broadcast: it has not been broadcast at all.
                broadcast_failure_at: None,
            });
            self.transfer_funding.push((id, note));
        }
        Ok(())
    }

    /// Assemble the committed [`MigrationState`] from the accumulated transactions and return it
    /// with the unsigned PCZTs and each transfer's funding note. Consuming `self` releases the
    /// `&mut backend` reborrow, so the caller can persist the state through the backend afterward.
    fn into_state(self, plan: &MigrationPlan, replan_threshold: ReplanThreshold) -> CommitOutput {
        let state = MigrationState {
            status: MigrationStatus::Committed,
            denominations: plan.denominations().clone(),
            preparation: plan.preparation().clone(),
            transactions: self.transactions,
            // Stamp the grid the transfers were anchored to, so a later reconfiguration of the
            // backend is detectable rather than silently invalidating them.
            anchor_bucket_interval: self.backend.scheduling_params().anchor_bucket_interval(),
            // Stamp the replan policy in effect at commit, so every consumer of this migration
            // applies the same threshold.
            replan_threshold,
        };
        CommitOutput {
            state,
            unsigned: self.unsigned,
            transfer_funding: self.transfer_funding,
        }
    }
}

/// Each transfer paired with the funding note it spends, recovered from the built preparation
/// bundles during a commit pass. A prover needs it to locate each transfer's spend in the wallet's
/// commitment tree at proving time.
#[cfg(feature = "orchard")]
type TransferFunding = Vec<(MigrationTransferId, orchard::note::Note)>;

/// What one commit pass produces. The public commit entry points drop the parts they do not
/// surface.
#[cfg(feature = "orchard")]
struct CommitOutput {
    state: MigrationState,
    unsigned: Vec<UnsignedMigrationTx>,
    #[cfg_attr(not(any(test, feature = "test-dependencies")), allow(dead_code))]
    transfer_funding: TransferFunding,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        denomination::{DENOM_CAP, MIGRATION_MAX_PREPARED_NOTES_PER_RUN},
        preparation::FUNDING_OUTPUTS_PER_TX,
        signing_rounds::{SigningRoundBudget, min_signing_rounds},
    };
    use rand_chacha::ChaCha8Rng;
    use rand_core::SeedableRng;
    use zcash_protocol::{local_consensus::LocalNetwork, value::COIN};

    /// Every `MigrationStatus` variant's wire name is pinned to its literal string, and
    /// `TryFrom<&str>` recovers the variant from the name `AsRef<str>` produces for it. Pinning the
    /// literal (rather than only round-tripping through the enum) is what catches a shared
    /// writer/reader typo in the two impls, which a round trip generated from the enum itself
    /// cannot. An unrecognized string is rejected.
    #[test]
    fn migration_status_wire_names_are_pinned() {
        assert_eq!(MigrationStatus::Planning.as_ref(), "planning");
        assert_eq!(MigrationStatus::Committed.as_ref(), "committed");
        assert_eq!(MigrationStatus::InProgress.as_ref(), "in_progress");
        assert_eq!(MigrationStatus::Complete.as_ref(), "complete");
        assert_eq!(MigrationStatus::Failed.as_ref(), "failed");
        assert_eq!(MigrationStatus::Superseded.as_ref(), "superseded");

        for status in [
            MigrationStatus::Planning,
            MigrationStatus::Committed,
            MigrationStatus::InProgress,
            MigrationStatus::Complete,
            MigrationStatus::Failed,
            MigrationStatus::Superseded,
        ] {
            assert_eq!(MigrationStatus::try_from(status.as_ref()), Ok(status));
        }

        assert!(MigrationStatus::try_from("not_a_status").is_err());
    }

    /// Every `UnsatisfiableKind` variant's wire name is pinned to its literal string, and
    /// `TryFrom<&str>` recovers the variant from the name `AsRef<str>` produces for it — pinning
    /// the literal is what catches a shared writer/reader typo. A name this build does not know is
    /// rejected, so a store reports it as corruption rather than reading it as "unmarked".
    #[test]
    fn unsatisfiable_kind_wire_names_are_pinned() {
        assert_eq!(UnsatisfiableKind::InputsSpent.as_ref(), "inputs_spent");
        assert_eq!(
            UnsatisfiableKind::InputsInvalidated.as_ref(),
            "inputs_invalidated"
        );
        assert_eq!(
            UnsatisfiableKind::AnchorInvalidated.as_ref(),
            "anchor_invalidated"
        );
        assert_eq!(UnsatisfiableKind::Inherited.as_ref(), "inherited");

        for kind in [
            UnsatisfiableKind::InputsSpent,
            UnsatisfiableKind::InputsInvalidated,
            UnsatisfiableKind::AnchorInvalidated,
            UnsatisfiableKind::Inherited,
        ] {
            assert_eq!(UnsatisfiableKind::try_from(kind.as_ref()), Ok(kind));
        }

        assert!(UnsatisfiableKind::try_from("not_a_kind").is_err());
    }

    /// Each cause maps to the kind a mark records for it, and `marks` agrees with `kind` by
    /// construction: the drive loop's termination rests on the mark decision being made once, and
    /// a cause that reports a kind but no mark (or the reverse) would break it. `Inherited` is
    /// never a cause's kind — it names a mark the dependency closure applied, not one observed.
    #[test]
    fn unsatisfiable_cause_kind_agrees_with_marks() {
        let cases = [
            (
                UnsatisfiableCause::InputsSpent {
                    nullifiers: vec![[1; 32]],
                },
                Some(UnsatisfiableKind::InputsSpent),
            ),
            (
                UnsatisfiableCause::InputsInvalidated { anchor: [2; 32] },
                Some(UnsatisfiableKind::InputsInvalidated),
            ),
            (
                UnsatisfiableCause::AnchorInvalidated,
                Some(UnsatisfiableKind::AnchorInvalidated),
            ),
            (UnsatisfiableCause::Expired, None),
        ];
        for (cause, kind) in cases {
            assert_eq!(cause.kind(), kind, "{cause:?}");
            assert_eq!(
                cause.marks(),
                kind.is_some(),
                "{cause:?}: marking and the recorded kind must agree"
            );
            assert_ne!(
                cause.kind(),
                Some(UnsatisfiableKind::Inherited),
                "{cause:?}: Inherited names a closure-applied mark, never an observed cause"
            );
        }
    }

    /// A `Mined` state's txid round-trips through `from_stored` alongside its height, and a stored
    /// `mined` row missing the txid payload is rejected rather than silently reconstructed
    /// without it.
    #[test]
    fn mined_state_round_trips_with_txid() {
        let txid = TxId::from_bytes([7; 32]);
        let s = MigrationTxState::Mined {
            txid,
            height: BlockHeight::from_u32(10),
        };
        assert_eq!(s.as_ref(), "mined");
        assert_eq!(
            MigrationTxState::from_stored("mined", s.broadcast_txid(), s.mined_height()),
            Ok(s)
        );
        // A mined row missing its txid does not reconstruct.
        assert!(
            MigrationTxState::from_stored("mined", None, Some(BlockHeight::from_u32(10))).is_err()
        );
    }

    /// A `SeenSpent` observation dominates every other answer, including the other PERMANENT
    /// input-level death: a recognized spend is the definitive on-chain fact, so it is the cause
    /// reported even when a dead anchor is also observed (and even when the transaction has
    /// expired besides).
    #[test]
    fn classify_seen_spent_dominates_invalidated() {
        let as_of = BlockHeight::from_u32(100);
        let got = classify_input_observations(
            as_of,
            true,
            &[
                ([1; 32], InputObservation::Invalidated([9; 32])),
                ([2; 32], InputObservation::SeenSpent),
            ],
        );
        assert_eq!(
            got,
            StepSatisfiability::Unsatisfiable {
                cause: UnsatisfiableCause::InputsSpent {
                    nullifiers: vec![[2; 32]]
                },
                as_of,
            }
        );
    }

    /// An `Invalidated` observation dominates expiry: a rebuild (expiry's remedy) cannot cure
    /// inputs that will never exist on chain, so the input-level cause is the one reported.
    #[test]
    fn classify_invalidated_dominates_expired() {
        let as_of = BlockHeight::from_u32(100);
        let got = classify_input_observations(
            as_of,
            true,
            &[
                ([1; 32], InputObservation::Unknown),
                ([2; 32], InputObservation::Invalidated([9; 32])),
            ],
        );
        assert_eq!(
            got,
            StepSatisfiability::Unsatisfiable {
                cause: UnsatisfiableCause::InputsInvalidated { anchor: [9; 32] },
                as_of,
            }
        );
    }

    /// Expiry dominates an `Unknown` observation: a definite permanent obstruction outranks
    /// "retry after further sync".
    #[test]
    fn classify_expired_dominates_unknown() {
        let as_of = BlockHeight::from_u32(100);
        let got = classify_input_observations(
            as_of,
            true,
            &[
                ([1; 32], InputObservation::Unknown),
                ([2; 32], InputObservation::Unspent),
            ],
        );
        assert_eq!(
            got,
            StepSatisfiability::Unsatisfiable {
                cause: UnsatisfiableCause::Expired,
                as_of,
            }
        );
    }

    /// An `Unknown` observation dominates all-`Unspent`: until every input's note is known
    /// unspent, the answer is "not yet", never "satisfiable".
    #[test]
    fn classify_unknown_dominates_unspent() {
        let as_of = BlockHeight::from_u32(100);
        let got = classify_input_observations(
            as_of,
            false,
            &[
                ([1; 32], InputObservation::Unspent),
                ([2; 32], InputObservation::Unknown),
            ],
        );
        assert_eq!(got, StepSatisfiability::NotYetSatisfiable { as_of });
    }

    /// All inputs known unspent and the transaction unexpired: satisfiable, at the observation
    /// height.
    #[test]
    fn classify_all_unspent_is_satisfiable() {
        let as_of = BlockHeight::from_u32(100);
        let got = classify_input_observations(
            as_of,
            false,
            &[
                ([1; 32], InputObservation::Unspent),
                ([2; 32], InputObservation::Unspent),
            ],
        );
        assert_eq!(got, StepSatisfiability::Satisfiable { as_of });
    }

    /// A mixed observation set collects ALL seen-spent nullifiers, in the cache's order, not just
    /// the first: the caller reports the complete set of dead inputs.
    #[test]
    fn classify_collects_every_spent_nullifier() {
        let as_of = BlockHeight::from_u32(100);
        let got = classify_input_observations(
            as_of,
            false,
            &[
                ([1; 32], InputObservation::SeenSpent),
                ([2; 32], InputObservation::Unspent),
                ([3; 32], InputObservation::SeenSpent),
            ],
        );
        assert_eq!(
            got,
            StepSatisfiability::Unsatisfiable {
                cause: UnsatisfiableCause::InputsSpent {
                    nullifiers: vec![[1; 32], [3; 32]]
                },
                as_of,
            }
        );
    }

    /// All four observation kinds at once, expired besides: `InputsSpent` still wins, pinning
    /// every precedence comparison against the top of the order in a single case (the pairwise
    /// tests above each pin one adjacent edge).
    #[test]
    fn classify_omnibus_seen_spent_tops_everything() {
        let as_of = BlockHeight::from_u32(100);
        let got = classify_input_observations(
            as_of,
            true,
            &[
                ([1; 32], InputObservation::Unspent),
                ([2; 32], InputObservation::SeenSpent),
                ([3; 32], InputObservation::Invalidated([9; 32])),
                ([4; 32], InputObservation::Unknown),
            ],
        );
        assert_eq!(
            got,
            StepSatisfiability::Unsatisfiable {
                cause: UnsatisfiableCause::InputsSpent {
                    nullifiers: vec![[2; 32]]
                },
                as_of,
            }
        );
    }

    /// The fold is TOTAL: empty observations and no expiry classify as satisfiable. Guarding
    /// against an empty nullifier cache (which is corruption on a non-mined transaction, never
    /// vacuous satisfiability) is the CALLER's obligation, per the function's contract.
    #[test]
    fn classify_empty_observations_unexpired_is_satisfiable() {
        let as_of = BlockHeight::from_u32(100);
        assert_eq!(
            classify_input_observations(as_of, false, &[]),
            StepSatisfiability::Satisfiable { as_of }
        );
    }

    /// A local network with NU6.3 active at a low height, matching the build test network, so the
    /// canonical fees and activation checks compute in planning tests.
    fn test_net() -> LocalNetwork {
        LocalNetwork {
            overwinter: Some(BlockHeight::from_u32(1)),
            sapling: Some(BlockHeight::from_u32(2)),
            blossom: Some(BlockHeight::from_u32(3)),
            heartwood: Some(BlockHeight::from_u32(4)),
            canopy: Some(BlockHeight::from_u32(5)),
            nu5: Some(BlockHeight::from_u32(6)),
            nu6: Some(BlockHeight::from_u32(7)),
            nu6_1: Some(BlockHeight::from_u32(8)),
            nu6_2: Some(BlockHeight::from_u32(9)),
            nu6_3: Some(BlockHeight::from_u32(10)),
            #[cfg(zcash_unstable = "nu7")]
            nu7: None,
        }
    }

    /// The canonical fees on the test network, computed exactly as `plan_migration` computes them.
    fn test_fees() -> (Zatoshis, Zatoshis) {
        canonical_fees(&test_net(), BlockHeight::from_u32(2_000_000))
            .expect("the canonical fees compute")
    }

    /// A count-only preparation-layout stub for tests that exercise the split in isolation: one
    /// padded transaction per [`FUNDING_OUTPUTS_PER_TX`] funding notes.
    fn prep_tx_count_stub(notes: &[Zatoshis]) -> Option<usize> {
        Some(notes.len().div_ceil(FUNDING_OUTPUTS_PER_TX))
    }

    /// A minimal in-memory backend: a fixed set of note values and a chain tip.
    struct MockBackend {
        notes: Vec<Zatoshis>,
        tip: BlockHeight,
        stored: Option<MigrationState>,
        sched_params: crate::scheduling::SchedulingParams,
    }

    impl MockBackend {
        fn new(notes: Vec<u64>, tip: u32) -> Self {
            MockBackend {
                notes: notes
                    .into_iter()
                    .map(|v| Zatoshis::from_u64(v).expect("test note values are valid"))
                    .collect(),
                tip: BlockHeight::from_u32(tip),
                stored: None,
                sched_params: crate::scheduling::SchedulingParams::ZIP_318,
            }
        }
    }

    impl MigrationBackend for MockBackend {
        type Error = core::convert::Infallible;

        fn spendable_orchard_note_values(&self) -> Result<Vec<Zatoshis>, Self::Error> {
            Ok(self.notes.clone())
        }

        fn chain_tip_height(&self) -> Result<BlockHeight, Self::Error> {
            Ok(self.tip)
        }

        fn scheduling_params(&self) -> crate::scheduling::SchedulingParams {
            self.sched_params
        }
    }

    impl PoolMigrationRead for MockBackend {
        type Error = core::convert::Infallible;

        fn get_migration(&self) -> Result<Option<MigrationState>, Self::Error> {
            Ok(self.stored.clone())
        }

        fn check_step_satisfiability(
            &self,
            _tx: &MigrationTransaction,
            _settle: ReorgSettleDepth,
        ) -> Result<StepSatisfiability, Self::Error> {
            // This mock models a wallet whose environment never obstructs a step; tests that
            // exercise the oracle configure the `zcash_pool_migration_memory` mocks instead.
            Ok(StepSatisfiability::Satisfiable { as_of: self.tip })
        }
    }

    impl PoolMigrationWrite for MockBackend {
        fn replace_migration(&mut self, state: &MigrationState) -> Result<(), Self::Error> {
            self.stored = Some(state.clone());
            Ok(())
        }

        fn update_transaction(
            &mut self,
            id: MigrationTransferId,
            state: MigrationTxState,
        ) -> Result<(), Self::Error> {
            if let Some(stored) = &mut self.stored
                && let Some(tx) = stored.transactions.iter_mut().find(|t| t.id == id)
            {
                tx.state = state;
            }
            Ok(())
        }
    }

    #[test]
    fn plans_a_migration_from_a_balance() {
        let backend = MockBackend::new(vec![100 * COIN, 40 * COIN], 2_000_000);
        let mut rng = ChaCha8Rng::seed_from_u64(1);
        let plan =
            plan_migration(&test_net(), &backend, &mut rng).expect("a fundable balance plans");

        // Something is migrated; the schedule has one entry per funding note; the preparation mints
        // exactly the (reconciled) funding notes; and reconciliation only ever drops, never adds.
        assert!(!plan.funding_notes().is_empty());
        assert_eq!(plan.schedule().len(), plan.funding_notes().len());

        // The preparation schedule mirrors the layers' shape, is non-decreasing within each
        // layer, and each layer starts past the previous one (temporal decoupling with layer
        // serialization).
        assert_eq!(plan.prep_schedule().len(), plan.preparation().layer_count());
        let mut prev_layer_end = BlockHeight::from_u32(2_000_000);
        for (layer, heights) in plan.preparation().layers().iter().zip(plan.prep_schedule()) {
            assert_eq!(heights.len(), layer.len());
            let mut prev = prev_layer_end;
            for &h in heights {
                assert!(h >= prev, "prep schedule is non-decreasing across layers");
                prev = h;
            }
            prev_layer_end = prev;
        }

        // The schedule floor: no transfer is scheduled before the earliest height at which a
        // candidate anchor boundary exists, given the drawn preparation schedule plus the mining
        // margin.
        let est_last_prep = plan
            .prep_schedule()
            .last()
            .and_then(|layer| layer.last())
            .copied()
            .unwrap_or(BlockHeight::from_u32(2_000_000))
            + EST_PREP_LAYER_MINING_BLOCKS;
        let earliest = crate::scheduling::earliest_broadcast_height(
            crate::scheduling::SchedulingParams::ZIP_318.anchor_bucket_interval(),
            BlockHeight::from_u32(10),
            est_last_prep,
        );
        assert!(
            plan.schedule()
                .iter()
                .all(|s| s.broadcast_height() >= earliest),
            "every scheduled transfer is at or after the anchor-viability floor"
        );
        assert_eq!(
            plan.preparation().funding_notes().len(),
            plan.funding_notes().len()
        );
    }

    /// SHUFFLE (ZIP 318): the crossings are non-increasing, so an unshuffled schedule would
    /// pair them with non-decreasing broadcast heights and the on-chain temporal sequence of
    /// denominations would spell out the balance. The drawn permutation makes the heights
    /// non-monotone in crossing index (deterministic for this seed).
    #[test]
    fn transfer_schedule_is_shuffled() {
        // A balance that splits into several denominations, so the order is observable.
        let backend = MockBackend::new(vec![78 * COIN], 2_000_000);
        let mut rng = ChaCha8Rng::seed_from_u64(3);
        let plan =
            plan_migration(&test_net(), &backend, &mut rng).expect("a fundable balance plans");
        assert!(
            plan.funding_notes().len() >= 4,
            "the balance splits into several transfers: {}",
            plan.funding_notes().len()
        );
        let heights: Vec<u32> = plan
            .schedule()
            .iter()
            .map(|s| u32::from(s.broadcast_height()))
            .collect();
        assert!(
            heights.windows(2).any(|w| w[0] > w[1]),
            "the transfer broadcast order is shuffled: {heights:?}"
        );
    }

    #[test]
    fn empty_balance_has_nothing_to_migrate() {
        let backend = MockBackend::new(Vec::new(), 2_000_000);
        let mut rng = ChaCha8Rng::seed_from_u64(1);
        assert!(matches!(
            plan_migration(&test_net(), &backend, &mut rng),
            Err(MigrationError::NothingToMigrate)
        ));
    }

    /// A typical balance migrates in a single run, whose entry carries BOTH the denomination side
    /// (migratable value and crossing count) and the note-preparation side (layers and transactions),
    /// and the aggregates match the single run.
    #[test]
    fn estimates_a_single_run_with_both_sides() {
        let mut rng = ChaCha8Rng::seed_from_u64(1);
        let backend = MockBackend::new(vec![142 * COIN], 2_000_000);
        let est = estimate_migration_runs(&test_net(), &backend, &mut rng)
            .expect("a valid balance estimates");

        assert_eq!(est.run_count(), 1);
        let run = est.runs()[0];
        // Denomination side: it crosses value in one or more canonical denominations.
        assert!(u64::from(run.migratable()) > 0);
        assert!(run.crossings() >= 1);
        // Note-preparation side: minting those notes costs at least one layer and one transaction.
        assert!(run.prep_layers() >= 1);
        assert!(run.prep_transactions() >= 1);
        // The aggregates reduce to the single run.
        assert_eq!(est.total_migratable(), run.migratable());
        assert_eq!(est.total_crossings(), run.crossings());
        assert_eq!(est.total_prep_layers(), run.prep_layers());
        assert_eq!(est.total_prep_transactions(), run.prep_transactions());
    }

    /// An empty (or fully sub-quantum) balance is a zero-run estimate, a preview rather than an error.
    #[test]
    fn empty_balance_estimates_zero_runs() {
        let mut rng = ChaCha8Rng::seed_from_u64(1);
        let empty = MockBackend::new(Vec::new(), 2_000_000);
        let est = estimate_migration_runs(&test_net(), &empty, &mut rng)
            .expect("an empty balance estimates");
        assert_eq!(est.run_count(), 0);
        assert!(est.runs().is_empty());
        assert_eq!(est.total_migratable(), Zatoshis::ZERO);
        assert_eq!(est.final_residual(), Zatoshis::ZERO);
    }

    /// A whale beyond one run's capacity migrates over several runs; its first run crosses the per-run
    /// cap of 50 * 10,000 ZEC in 50 notes, and the aggregate crossings sum the per-run counts.
    #[test]
    fn whale_migrates_over_several_runs() {
        let mut rng = ChaCha8Rng::seed_from_u64(1);
        let whale = MockBackend::new(vec![1_200_000 * COIN], 2_000_000);
        let est = estimate_migration_runs(&test_net(), &whale, &mut rng)
            .expect("a whale balance estimates");

        assert!(
            est.run_count() >= 2,
            "a whale migrates over several runs, got {}",
            est.run_count()
        );
        let per_run_cap = MIGRATION_MAX_PREPARED_NOTES_PER_RUN as u64 * u64::from(DENOM_CAP);
        assert_eq!(u64::from(est.runs()[0].migratable()), per_run_cap);
        assert_eq!(
            est.runs()[0].crossings(),
            MIGRATION_MAX_PREPARED_NOTES_PER_RUN
        );
        let summed: usize = est.runs().iter().map(|r| r.crossings()).sum();
        assert_eq!(est.total_crossings(), summed);
    }

    /// The estimate depends on the wallet's NOTE STRUCTURE, not just its total value: the same balance
    /// held as one note versus as many small notes migrates the same value in one run, but the
    /// fragmented wallet costs strictly more note-preparation work (consolidation).
    #[test]
    fn estimate_depends_on_wallet_note_structure() {
        let mut rng = ChaCha8Rng::seed_from_u64(1);
        let one_note = MockBackend::new(vec![200 * COIN], 2_000_000);
        let fragmented = MockBackend::new(vec![COIN; 200], 2_000_000); // 200 ZEC as 200 x 1 ZEC

        let est_one = estimate_migration_runs(&test_net(), &one_note, &mut rng).expect("estimates");
        let est_frag =
            estimate_migration_runs(&test_net(), &fragmented, &mut rng).expect("estimates");

        assert_eq!(est_one.run_count(), 1);
        assert_eq!(est_frag.run_count(), 1);
        assert!(
            est_frag.total_prep_transactions() > est_one.total_prep_transactions(),
            "a fragmented wallet needs more preparation: {} vs {}",
            est_frag.total_prep_transactions(),
            est_one.total_prep_transactions()
        );
    }

    /// The number of signing ROUNDS follows a capacity-limited signer's per-interaction ACTION budget
    /// (a Keystone-style hard limit, not a per-transaction cap): one round per run when the budget
    /// exceeds a whole run, monotonically more rounds as the budget tightens, and each run's rounds
    /// match the optimal packer. Rounds are summed per run (they cannot span runs).
    #[test]
    fn signing_rounds_follow_the_signer_budget() {
        let mut rng = ChaCha8Rng::seed_from_u64(1);
        // A whale, so there are several runs, each with several transactions.
        let whale = MockBackend::new(vec![1_200_000 * COIN], 2_000_000);
        let est = estimate_migration_runs(&test_net(), &whale, &mut rng).expect("estimates");

        // Total transactions reconcile with the per-side aggregates.
        assert_eq!(
            est.total_transactions(),
            est.total_prep_transactions() + est.total_crossings()
        );

        let huge = SigningRoundBudget::new(NonZeroU32::new(1_000_000).unwrap());
        let keystone = SigningRoundBudget::KEYSTONE;
        let tiny = SigningRoundBudget::new(SigningRoundBudget::minimum_feasible());

        // A budget larger than any run's total actions: one round per run.
        assert_eq!(est.total_signing_rounds(huge), est.run_count());
        // A tighter budget never needs fewer rounds than a looser one.
        assert!(est.total_signing_rounds(keystone) >= est.total_signing_rounds(huge));
        assert!(est.total_signing_rounds(tiny) >= est.total_signing_rounds(keystone));

        // Per-run consistency: the total is the per-run sum, and each run matches the packer.
        let summed: usize = est.runs().iter().map(|r| r.signing_rounds(keystone)).sum();
        assert_eq!(est.total_signing_rounds(keystone), summed);
        for run in est.runs() {
            assert_eq!(
                run.transactions(),
                run.prep_transactions() + run.crossings()
            );
            assert_eq!(
                run.signing_rounds(keystone),
                min_signing_rounds(run.prep_transactions(), run.crossings(), keystone)
            );
        }
    }

    #[test]
    fn stores_loads_and_updates_a_migration() {
        let mut backend = MockBackend::new(Vec::new(), 0);
        assert!(backend.get_migration().unwrap().is_none());

        let mut rng = ChaCha8Rng::seed_from_u64(1);
        let (prep_tx_fee, transfer_buffer) = test_fees();
        let denominations = crate::denomination::plan_denominations(
            Zatoshis::from_u64(100 * COIN).expect("test balance is valid"),
            transfer_buffer,
            prep_tx_fee,
            &prep_tx_count_stub,
            &mut rng,
        );
        let tx = MigrationTransaction {
            id: MigrationTransferId(0),
            kind: MigrationTxKind::Transfer { crossing: 0 },
            pczt: vec![1, 2, 3], // a stand-in for the serialized pre-signed PCZT
            depends_on: Vec::new(),
            scheduled_height: BlockHeight::from_u32(2_000_100),
            expiry_height: BlockHeight::from_u32(2_069_220),
            anchor_boundary: None,
            state: MigrationTxState::Signed,
            lock_owner: None,
            unsatisfiable: None,
            spend_nullifiers: Vec::new(),
            broadcast_failure_at: None,
        };
        let state = MigrationState {
            status: MigrationStatus::Committed,
            denominations,
            preparation: crate::preparation::PreparationPlan::from_parts(Vec::new(), Vec::new()),
            transactions: vec![tx],
            anchor_bucket_interval: crate::scheduling::AnchorBucketInterval::ZIP_318,
            replan_threshold: ReplanThreshold::DEFAULT,
        };
        backend.replace_migration(&state).unwrap();

        // The stored transactions round-trip, and a state update persists.
        let loaded = backend
            .get_migration()
            .unwrap()
            .expect("a migration is stored");
        assert_eq!(loaded.status, MigrationStatus::Committed);
        assert_eq!(loaded.transactions, state.transactions);

        backend
            .update_transaction(
                MigrationTransferId(0),
                MigrationTxState::Mined {
                    txid: TxId::from_bytes([0; 32]),
                    height: BlockHeight::from_u32(2_000_105),
                },
            )
            .unwrap();
        let loaded = backend.get_migration().unwrap().unwrap();
        assert_eq!(
            loaded.transactions[0].state,
            MigrationTxState::Mined {
                txid: TxId::from_bytes([0; 32]),
                height: BlockHeight::from_u32(2_000_105)
            }
        );
    }
}

/// The drive API's tests, over a minimal in-crate store with a configurable answer set: what
/// [`advance_migration`] surfaces, what it records, how much it asks, and what it persists.
#[cfg(test)]
mod advance_tests {
    use super::*;
    use alloc::collections::BTreeMap;
    use core::cell::Cell;
    use zcash_protocol::value::Zatoshis;

    use crate::denomination::DenominationPlan;
    use crate::preparation::PreparationPlan;

    /// A store that answers satisfiability from a fixed table — anything absent is satisfiable at
    /// `as_of`, the healthy default — and counts what the drive loop asks of it.
    struct TestStore {
        stored: Option<MigrationState>,
        satisfiability: BTreeMap<MigrationTransferId, StepSatisfiability>,
        as_of: BlockHeight,
        queries: Cell<usize>,
        replaced: Cell<usize>,
    }

    impl TestStore {
        fn new(
            as_of: u32,
            answers: impl IntoIterator<Item = (MigrationTransferId, StepSatisfiability)>,
        ) -> Self {
            TestStore {
                stored: None,
                satisfiability: answers.into_iter().collect(),
                as_of: BlockHeight::from_u32(as_of),
                queries: Cell::new(0),
                replaced: Cell::new(0),
            }
        }

        /// Replace one transaction's answer, standing in for the wallet's view changing between
        /// calls (a dependency scanned, a reorg settled).
        fn set_answer(&mut self, id: MigrationTransferId, answer: StepSatisfiability) {
            self.satisfiability.insert(id, answer);
        }
    }

    impl PoolMigrationRead for TestStore {
        type Error = core::convert::Infallible;

        fn get_migration(&self) -> Result<Option<MigrationState>, Self::Error> {
            Ok(self.stored.clone())
        }

        fn check_step_satisfiability(
            &self,
            tx: &MigrationTransaction,
            _settle: ReorgSettleDepth,
        ) -> Result<StepSatisfiability, Self::Error> {
            self.queries.set(self.queries.get() + 1);
            Ok(self
                .satisfiability
                .get(&tx.id())
                .cloned()
                .unwrap_or(StepSatisfiability::Satisfiable { as_of: self.as_of }))
        }
    }

    impl PoolMigrationWrite for TestStore {
        fn replace_migration(&mut self, state: &MigrationState) -> Result<(), Self::Error> {
            self.replaced.set(self.replaced.get() + 1);
            self.stored = Some(state.clone());
            Ok(())
        }

        fn update_transaction(
            &mut self,
            id: MigrationTransferId,
            state: MigrationTxState,
        ) -> Result<(), Self::Error> {
            if let Some(stored) = &mut self.stored
                && let Some(tx) = stored.transactions.iter_mut().find(|t| t.id == id)
            {
                tx.state = state;
            }
            Ok(())
        }
    }

    // The state constructors mirror `state.rs`'s test helpers, so a drive-loop test and a kernel
    // test describe the same migration the same way.

    fn tx(id: u32, kind: MigrationTxKind, state: MigrationTxState) -> MigrationTransaction {
        MigrationTransaction {
            id: MigrationTransferId(id),
            kind,
            pczt: Vec::new(),
            depends_on: Vec::new(),
            scheduled_height: BlockHeight::from_u32(0),
            expiry_height: BlockHeight::from_u32(0),
            anchor_boundary: None,
            state,
            lock_owner: None,
            unsatisfiable: None,
            spend_nullifiers: Vec::new(),
            broadcast_failure_at: None,
        }
    }

    fn prep(layer: usize, index: usize) -> MigrationTxKind {
        MigrationTxKind::Preparation { layer, index }
    }

    fn transfer(crossing: usize) -> MigrationTxKind {
        MigrationTxKind::Transfer { crossing }
    }

    fn mined(height: u32) -> MigrationTxState {
        MigrationTxState::Mined {
            txid: TxId::from_bytes([0; 32]),
            height: BlockHeight::from_u32(height),
        }
    }

    fn broadcast() -> MigrationTxState {
        MigrationTxState::Broadcast {
            txid: TxId::from_bytes([1; 32]),
        }
    }

    /// A transfer with the given anchor boundary and scheduled broadcast height, in the given
    /// lifecycle state (never expiring, like `tx`).
    fn scheduled_transfer(
        id: u32,
        crossing: usize,
        anchor: u32,
        broadcast: u32,
        state: MigrationTxState,
    ) -> MigrationTransaction {
        let mut t = tx(id, transfer(crossing), state);
        t.anchor_boundary = Some(BlockHeight::from_u32(anchor));
        t.scheduled_height = BlockHeight::from_u32(broadcast);
        t
    }

    /// A state whose denomination plan carries the given crossing values, so each transfer's
    /// contribution to the replan threshold is exactly the value at its crossing index.
    fn state_with_crossings(
        crossings: &[u64],
        transactions: Vec<MigrationTransaction>,
    ) -> MigrationState {
        let zats = |v: u64| Zatoshis::from_u64(v).expect("test values are valid");
        let total = zats(crossings.iter().sum());
        MigrationState {
            status: MigrationStatus::Committed,
            denominations: DenominationPlan::from_stored_parts(
                crossings.iter().copied().map(zats).collect(),
                zats(15_000),
                None,
                Zatoshis::ZERO,
                total,
                total,
            )
            .expect("a consistent stored plan reconstructs"),
            preparation: PreparationPlan::from_parts(Vec::new(), Vec::new()),
            transactions,
            anchor_bucket_interval: crate::scheduling::AnchorBucketInterval::ZIP_318,
            replan_threshold: ReplanThreshold::DEFAULT,
        }
    }

    fn spent(as_of: u32) -> StepSatisfiability {
        StepSatisfiability::Unsatisfiable {
            cause: UnsatisfiableCause::InputsSpent {
                nullifiers: vec![[9; 32]],
            },
            as_of: BlockHeight::from_u32(as_of),
        }
    }

    fn config() -> AdvanceConfig {
        AdvanceConfig {
            reorg_settle_depth: ReorgSettleDepth(10),
        }
    }

    /// Which half of the store interface fails, for the error-propagation test.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Failure {
        /// The satisfiability oracle fails.
        Oracle,
        /// Persisting fails.
        Write,
    }

    /// A store whose failing half is chosen up front. `TestStore` is infallible, so error
    /// propagation needs a store that can actually fail.
    #[derive(Debug, PartialEq, Eq)]
    struct StoreFailed;

    struct FailingStore {
        stored: Option<MigrationState>,
        satisfiability: BTreeMap<MigrationTransferId, StepSatisfiability>,
        as_of: BlockHeight,
        fails: Failure,
        queries: Cell<usize>,
        replaced: Cell<usize>,
    }

    impl FailingStore {
        fn new(
            fails: Failure,
            as_of: u32,
            answers: impl IntoIterator<Item = (MigrationTransferId, StepSatisfiability)>,
        ) -> Self {
            FailingStore {
                stored: None,
                satisfiability: answers.into_iter().collect(),
                as_of: BlockHeight::from_u32(as_of),
                fails,
                queries: Cell::new(0),
                replaced: Cell::new(0),
            }
        }
    }

    impl PoolMigrationRead for FailingStore {
        type Error = StoreFailed;

        fn get_migration(&self) -> Result<Option<MigrationState>, Self::Error> {
            Ok(self.stored.clone())
        }

        fn check_step_satisfiability(
            &self,
            tx: &MigrationTransaction,
            _settle: ReorgSettleDepth,
        ) -> Result<StepSatisfiability, Self::Error> {
            self.queries.set(self.queries.get() + 1);
            if self.fails == Failure::Oracle {
                return Err(StoreFailed);
            }
            Ok(self
                .satisfiability
                .get(&tx.id())
                .cloned()
                .unwrap_or(StepSatisfiability::Satisfiable { as_of: self.as_of }))
        }
    }

    impl PoolMigrationWrite for FailingStore {
        fn replace_migration(&mut self, state: &MigrationState) -> Result<(), Self::Error> {
            self.replaced.set(self.replaced.get() + 1);
            if self.fails == Failure::Write {
                return Err(StoreFailed);
            }
            self.stored = Some(state.clone());
            Ok(())
        }

        fn update_transaction(
            &mut self,
            _id: MigrationTransferId,
            _state: MigrationTxState,
        ) -> Result<(), Self::Error> {
            Err(StoreFailed)
        }
    }

    /// The invariant the drive API exists for: a step is surfaced only after the store has
    /// vouched for it. The kernel plans A's due broadcast; the check discovers A's inputs spent,
    /// which broadens into a sweep that also finds C dead, and the call surfaces B's prove — never
    /// A's broadcast — with both discoveries recorded and persisted in ONE write. A's and C's
    /// value stays below the replan threshold, so the migration keeps draining.
    #[test]
    fn advance_never_surfaces_a_dead_candidate_and_broadens_on_discovery() {
        let mut state = state_with_crossings(
            &[5_000_000, 90_000_000, 5_000_000],
            vec![
                tx(0, prep(0, 0), mined(10)),
                // A: proved and due at the target height.
                scheduled_transfer(1, 0, 1440, 1500, MigrationTxState::Proved),
                // B and C: signed, boundaries long settled, broadcasts weeks out.
                scheduled_transfer(2, 1, 1440, 90_000, MigrationTxState::Signed),
                scheduled_transfer(3, 2, 1440, 90_000, MigrationTxState::Signed),
            ],
        );
        let mut store = TestStore::new(
            1600,
            [
                (MigrationTransferId(1), spent(1600)),
                (MigrationTransferId(3), spent(1600)),
            ],
        );

        let step = advance_migration(
            &mut store,
            &mut state,
            BlockHeight::from_u32(1601),
            &config(),
        )
        .expect("the store never fails");

        assert!(
            matches!(step, AdvanceStep::Prove { id, .. } if id == MigrationTransferId(2)),
            "the live transfer's prove is surfaced, not the dead transfer's broadcast: {step:?}"
        );
        let marked = BlockHeight::from_u32(1600);
        assert_eq!(
            state.transactions()[1].unsatisfiable_at(),
            Some(marked),
            "the dead candidate is marked at the answer's height"
        );
        assert_eq!(
            state.transactions()[3].unsatisfiable_at(),
            Some(marked),
            "the broaden sweep marks a transfer whose own broadcast is weeks away"
        );
        assert_eq!(
            state.transactions()[2].unsatisfiable_at(),
            None,
            "the satisfiable transfer is untouched"
        );
        assert_eq!(
            store.replaced.get(),
            1,
            "one dirty write persisted the marks"
        );
        assert_eq!(
            store.stored.as_ref().expect("persisted").transactions()[3].unsatisfiable_at(),
            Some(marked),
            "the store holds the marks by the time the step is surfaced"
        );
    }

    /// Broadening is what makes the threshold trip promptly: the marks discovered in one call
    /// carry the unsatisfiable share past the committed threshold, so that SAME call re-plans and
    /// returns `Replan` rather than another step.
    #[test]
    fn advance_replan_when_threshold_crossed() {
        let mut state = state_with_crossings(
            &[30_000_000, 40_000_000, 30_000_000],
            vec![
                tx(0, prep(0, 0), mined(10)),
                scheduled_transfer(1, 0, 1440, 1500, MigrationTxState::Proved),
                scheduled_transfer(2, 1, 1440, 90_000, MigrationTxState::Signed),
                scheduled_transfer(3, 2, 1440, 90_000, MigrationTxState::Signed),
            ],
        );
        let mut store = TestStore::new(
            1600,
            [
                (MigrationTransferId(1), spent(1600)),
                (MigrationTransferId(3), spent(1600)),
            ],
        );

        let step = advance_migration(
            &mut store,
            &mut state,
            BlockHeight::from_u32(1601),
            &config(),
        )
        .expect("the store never fails");

        assert_eq!(
            step,
            AdvanceStep::Replan,
            "60% of the planned crossing value is unsatisfiable, past the 20% threshold"
        );
        assert!(state.replan_required());
        assert_eq!(store.replaced.get(), 1);
        let stored = store.stored.as_ref().expect("persisted");
        assert!(
            stored.transactions()[1].unsatisfiable_at().is_some()
                && stored.transactions()[3].unsatisfiable_at().is_some(),
            "the marks the replan decision rests on are durable before it is surfaced"
        );
    }

    /// A `NotYetSatisfiable` answer is a retry, not an obstruction: the candidate is set aside for
    /// the rest of the call — nothing marked — its sibling surfaces instead, and a FRESH call
    /// offers the deferred transaction again once the wallet can vouch for it.
    #[test]
    fn advance_not_yet_satisfiable_sets_aside_without_marking() {
        let mut state = state_with_crossings(
            &[50_000_000, 50_000_000],
            vec![
                tx(0, prep(0, 0), mined(10)),
                scheduled_transfer(1, 0, 1440, 1500, MigrationTxState::Proved),
                scheduled_transfer(2, 1, 1440, 1500, MigrationTxState::Proved),
            ],
        );
        let mut store = TestStore::new(
            1600,
            [(
                MigrationTransferId(1),
                StepSatisfiability::NotYetSatisfiable {
                    as_of: BlockHeight::from_u32(1600),
                },
            )],
        );

        let step = advance_migration(
            &mut store,
            &mut state,
            BlockHeight::from_u32(1601),
            &config(),
        )
        .expect("the store never fails");

        assert_eq!(
            step,
            AdvanceStep::Broadcast {
                id: MigrationTransferId(2)
            },
            "the sibling's due broadcast surfaces while the lagging candidate waits"
        );
        assert!(
            state
                .transactions()
                .iter()
                .all(|t| t.unsatisfiable_at().is_none()),
            "a not-yet answer marks nothing"
        );
        assert_eq!(
            store.replaced.get(),
            0,
            "nothing was recorded, so nothing is written"
        );

        // The deferral was call-local: once the wallet can vouch for it, the next call offers the
        // same transaction again.
        store.set_answer(
            MigrationTransferId(1),
            StepSatisfiability::Satisfiable {
                as_of: BlockHeight::from_u32(1700),
            },
        );
        let step = advance_migration(
            &mut store,
            &mut state,
            BlockHeight::from_u32(1701),
            &config(),
        )
        .expect("the store never fails");
        assert_eq!(
            step,
            AdvanceStep::Broadcast {
                id: MigrationTransferId(1)
            },
            "set_aside does not persist across calls"
        );
        assert_eq!(store.replaced.get(), 0);
    }

    /// The laziness profile a healthy migration pays: one query for the candidate the kernel
    /// names, no write at all — and, when nothing is actionable, not even that.
    #[test]
    fn advance_is_lazy_when_healthy() {
        let mut state = state_with_crossings(
            &[100_000_000],
            vec![
                tx(0, prep(0, 0), mined(10)),
                scheduled_transfer(1, 0, 1440, 1500, MigrationTxState::Proved),
            ],
        );
        let mut store = TestStore::new(1600, []);

        let step = advance_migration(
            &mut store,
            &mut state,
            BlockHeight::from_u32(1601),
            &config(),
        )
        .expect("the store never fails");

        assert_eq!(
            step,
            AdvanceStep::Broadcast {
                id: MigrationTransferId(1)
            }
        );
        assert_eq!(store.queries.get(), 1, "exactly the candidate is checked");
        assert_eq!(store.replaced.get(), 0, "a healthy call writes nothing");

        // Nothing in flight and nothing actionable — the transfer's boundary has yet to settle —
        // so there is nothing to check at all.
        let mut waiting = state_with_crossings(
            &[100_000_000],
            vec![
                tx(0, prep(0, 0), mined(10)),
                scheduled_transfer(1, 0, 1700, 90_000, MigrationTxState::Signed),
            ],
        );
        let mut store = TestStore::new(1600, []);
        let step = advance_migration(
            &mut store,
            &mut waiting,
            BlockHeight::from_u32(1601),
            &config(),
        )
        .expect("the store never fails");
        assert_eq!(step, AdvanceStep::Waiting);
        assert_eq!(store.queries.get(), 0, "a waiting call asks nothing");
        assert_eq!(store.replaced.get(), 0);
    }

    /// The in-flight sweep is the only check a broadcast-but-unmined transaction ever gets, and it
    /// records exactly one cause. A settled reorg invalidates a broadcast preparation's anchor;
    /// its pending dependents die through the closure, carrying the migration past the threshold.
    /// A sibling in flight whose answer is an INPUT-level cause is left alone: an in-flight
    /// transaction's inputs are spent by itself, so that answer says nothing about its fate.
    #[test]
    fn advance_in_flight_anchor_invalidated_flows_to_replan() {
        let mut dependent_a = scheduled_transfer(1, 0, 1440, 90_000, MigrationTxState::Signed);
        dependent_a.depends_on = vec![MigrationTransferId(0)];
        let mut dependent_b = scheduled_transfer(2, 1, 1440, 90_000, MigrationTxState::Signed);
        dependent_b.depends_on = vec![MigrationTransferId(0)];
        let mut state = state_with_crossings(
            &[50_000_000, 50_000_000, 10_000_000],
            vec![
                tx(0, prep(0, 0), broadcast()),
                dependent_a,
                dependent_b,
                // In flight, independent, and answering an input-level cause.
                scheduled_transfer(3, 2, 1440, 1500, broadcast()),
            ],
        );
        let mut store = TestStore::new(
            1600,
            [
                (
                    MigrationTransferId(0),
                    StepSatisfiability::Unsatisfiable {
                        cause: UnsatisfiableCause::AnchorInvalidated,
                        as_of: BlockHeight::from_u32(1600),
                    },
                ),
                (MigrationTransferId(3), spent(1600)),
            ],
        );

        let step = advance_migration(
            &mut store,
            &mut state,
            BlockHeight::from_u32(1601),
            &config(),
        )
        .expect("the store never fails");

        assert_eq!(
            step,
            AdvanceStep::Replan,
            "the stranded dependents carry the migration past the threshold"
        );
        let marked = BlockHeight::from_u32(1600);
        assert_eq!(state.transactions()[0].unsatisfiable_at(), Some(marked));
        assert_eq!(
            state.transactions()[1].unsatisfiable_at(),
            Some(marked),
            "a dependent of the dead preparation inherits its stamp"
        );
        assert_eq!(state.transactions()[2].unsatisfiable_at(), Some(marked));
        assert_eq!(
            state.transactions()[3].unsatisfiable_at(),
            None,
            "an input-level answer about an in-flight transaction is not a determination"
        );
        assert_eq!(
            store.queries.get(),
            2,
            "one query per in-flight transaction"
        );
        assert_eq!(store.replaced.get(), 1);
        assert_eq!(
            store.stored.as_ref().expect("persisted").transactions()[1].unsatisfiable_at(),
            Some(marked)
        );
    }

    /// An `Expired` answer confirms a derivation the kernel already makes from the same
    /// `expiry_height`, so it never overrides the planned step: the rebuild the kernel surfaced —
    /// expiry's remedy — stands, and nothing is marked (a mark would make the transfer dead
    /// rather than rebuildable).
    #[test]
    fn advance_expired_answer_never_overrides_the_kernel() {
        let mut expired = scheduled_transfer(1, 0, 1440, 1500, MigrationTxState::Signed);
        expired.expiry_height = BlockHeight::from_u32(1550);
        let mut state =
            state_with_crossings(&[100_000_000], vec![tx(0, prep(0, 0), mined(10)), expired]);
        let mut store = TestStore::new(
            1600,
            [(
                MigrationTransferId(1),
                StepSatisfiability::Unsatisfiable {
                    cause: UnsatisfiableCause::Expired,
                    as_of: BlockHeight::from_u32(1600),
                },
            )],
        );

        let step = advance_migration(
            &mut store,
            &mut state,
            BlockHeight::from_u32(1601),
            &config(),
        )
        .expect("the store never fails");

        assert_eq!(
            step,
            AdvanceStep::Rebuild {
                id: MigrationTransferId(1)
            },
            "the kernel's rebuild stands"
        );
        assert_eq!(
            state.transactions()[1].unsatisfiable_at(),
            None,
            "expiry is derived, never recorded"
        );
        assert_eq!(store.queries.get(), 1);
        assert_eq!(
            store.replaced.get(),
            0,
            "nothing was recorded, so nothing is written"
        );
    }

    /// The broaden sweep is scoped to transactions the oracle can actually answer about: one
    /// whose dependencies have yet to mine is never asked (it could only answer "not yet", and
    /// its death, if any, arrives through the closure), while its unblocked sibling is.
    #[test]
    fn advance_broaden_sweep_skips_a_transaction_behind_an_unmined_dependency() {
        // A transfer funded by a preparation layer that has not been broadcast yet, alongside one
        // whose funding preparation is already mined.
        let mut behind_unmined_dep =
            scheduled_transfer(3, 1, 1440, 90_000, MigrationTxState::Signed);
        behind_unmined_dep.depends_on = vec![MigrationTransferId(2)];
        let mut unblocked = scheduled_transfer(4, 2, 1440, 90_000, MigrationTxState::Signed);
        unblocked.depends_on = vec![MigrationTransferId(0)];
        let mut state = state_with_crossings(
            &[5_000_000, 90_000_000, 5_000_000],
            vec![
                tx(0, prep(0, 0), mined(10)),
                // The candidate: proved, due, and dead.
                scheduled_transfer(1, 0, 1440, 1500, MigrationTxState::Proved),
                // A second preparation layer, not yet due, so not itself actionable.
                {
                    let mut t = tx(2, prep(1, 0), MigrationTxState::Signed);
                    t.scheduled_height = BlockHeight::from_u32(90_000);
                    t
                },
                behind_unmined_dep,
                unblocked,
            ],
        );
        let mut store = TestStore::new(
            1600,
            [
                (MigrationTransferId(1), spent(1600)),
                // Answered only if asked — and the sweep must not ask.
                (MigrationTransferId(3), spent(1600)),
                (MigrationTransferId(4), spent(1600)),
            ],
        );

        let step = advance_migration(
            &mut store,
            &mut state,
            BlockHeight::from_u32(1601),
            &config(),
        )
        .expect("the store never fails");

        assert_eq!(
            step,
            AdvanceStep::Waiting,
            "the live work is all undue, and the marked share stays below the threshold"
        );
        assert_eq!(
            store.queries.get(),
            3,
            "the candidate, then the two transactions the sweep can answer about"
        );
        assert_eq!(
            state.transactions()[3].unsatisfiable_at(),
            None,
            "a transaction behind an unmined dependency is never asked, so never marked"
        );
        assert_eq!(
            state.transactions()[4].unsatisfiable_at(),
            Some(BlockHeight::from_u32(1600)),
            "its unblocked sibling is swept and marked"
        );
        assert_eq!(store.replaced.get(), 1);
    }

    /// A store error propagates, and the call's contract on the way out: nothing is left half
    /// written. An oracle failure records nothing and writes nothing; a WRITE failure surfaces the
    /// error with the discovery live only in the in-memory state, which is exactly why the caller
    /// must re-read after an error rather than trusting what it holds.
    #[test]
    fn advance_store_errors_propagate_without_recording() {
        let migration = || {
            state_with_crossings(
                &[100_000_000],
                vec![
                    tx(0, prep(0, 0), mined(10)),
                    scheduled_transfer(1, 0, 1440, 1500, MigrationTxState::Proved),
                ],
            )
        };

        // The oracle fails on the candidate check.
        let mut state = migration();
        let mut store = FailingStore::new(Failure::Oracle, 1600, []);
        assert_eq!(
            advance_migration(
                &mut store,
                &mut state,
                BlockHeight::from_u32(1601),
                &config()
            ),
            Err(StoreFailed)
        );
        assert!(
            state
                .transactions()
                .iter()
                .all(|t| t.unsatisfiable_at().is_none()),
            "an unanswered check determines nothing"
        );
        assert_eq!(
            store.replaced.get(),
            0,
            "and nothing is written on the way out"
        );

        // The oracle answers — the candidate is dead, and it is the only checkable transaction —
        // but persisting the discovery fails.
        let mut state = migration();
        let mut store = FailingStore::new(
            Failure::Write,
            1600,
            [(MigrationTransferId(1), spent(1600))],
        );
        assert_eq!(
            advance_migration(
                &mut store,
                &mut state,
                BlockHeight::from_u32(1601),
                &config()
            ),
            Err(StoreFailed)
        );
        assert_eq!(
            store.queries.get(),
            1,
            "the candidate, and nothing to broaden to"
        );
        assert_eq!(store.replaced.get(), 1, "the write was attempted");
        assert!(
            state.transactions()[1].unsatisfiable_at().is_some(),
            "the discovery is in the in-memory state"
        );
        assert!(
            store.stored.is_none(),
            "but not in the store: after an error the caller must re-read, not trust this state"
        );
    }

    /// A rejected broadcast whose explanation lies above the wallet's scanned region: the call
    /// surfaces `Reevaluate` and nothing else, records nothing, and does not fall through to the
    /// migration's other due work — a rejection means another observer saw chain state this
    /// wallet has not, which is a fact about the whole view rather than one transaction.
    #[test]
    fn advance_holds_at_reevaluate_until_the_oracle_reaches_the_reported_tip() {
        let mut state = state_with_crossings(
            &[50_000_000, 50_000_000],
            vec![
                tx(0, prep(0, 0), mined(10)),
                scheduled_transfer(1, 0, 1440, 1500, MigrationTxState::Proved),
                scheduled_transfer(2, 1, 1440, 1500, MigrationTxState::Proved),
            ],
        );
        // The node that refused the broadcast reported a tip 100 blocks above the wallet's
        // fully-scanned height.
        state.report_broadcast_failure(MigrationTransferId(1), BlockHeight::from_u32(1700));
        let mut store = TestStore::new(1600, []);

        assert_eq!(
            advance_migration(
                &mut store,
                &mut state,
                BlockHeight::from_u32(1601),
                &config()
            )
            .expect("the store never fails"),
            AdvanceStep::Reevaluate,
            "the sibling's due broadcast waits behind the unanswered rejection",
        );
        assert_eq!(store.queries.get(), 1, "one query, for the reported row");
        assert_eq!(store.replaced.get(), 0, "nothing was determined to persist");
        assert_eq!(
            state.transactions()[1].broadcast_failure_at(),
            Some(BlockHeight::from_u32(1700)),
            "the report stands until it can be answered",
        );
        assert!(
            state
                .transactions()
                .iter()
                .all(|t| t.unsatisfiable_at().is_none()),
            "testimony never marks",
        );
        assert_eq!(
            state.transaction_statuses(BlockHeight::from_u32(1601))[1].blocked_on(),
            Some(crate::state::Blocker::AwaitingReevaluation),
        );

        // The wallet syncs past the reported tip and the same answer now decides the question:
        // nothing obstructs, so the rejection was transient, the report is discharged, and the
        // broadcast is offered again IN THIS CALL.
        store.as_of = BlockHeight::from_u32(1700);
        assert_eq!(
            advance_migration(
                &mut store,
                &mut state,
                BlockHeight::from_u32(1701),
                &config()
            )
            .expect("the store never fails"),
            AdvanceStep::Broadcast {
                id: MigrationTransferId(1)
            },
        );
        assert_eq!(state.transactions()[1].broadcast_failure_at(), None);
        assert_eq!(
            store
                .stored
                .as_ref()
                .expect("the discharge was persisted")
                .transactions()[1]
                .broadcast_failure_at(),
            None,
            "the discharge is durable before the step is surfaced",
        );
    }

    /// The other adjudication: once the wallet has scanned to the reported tip it finds the spend
    /// behind the rejection, and that becomes an ORDINARY evidence-backed mark — closure,
    /// threshold, and `Replan` exactly as any other discovery. The report is discharged either
    /// way; the mark is what stands afterwards.
    #[test]
    fn advance_adjudicates_a_reported_broadcast_into_marks_and_a_replan() {
        let mut prep_layer_1 = tx(1, prep(1, 0), MigrationTxState::Proved);
        prep_layer_1.depends_on = vec![MigrationTransferId(0)];
        prep_layer_1.scheduled_height = BlockHeight::from_u32(1500);
        let mut first = scheduled_transfer(2, 0, 1440, 90_000, MigrationTxState::Signed);
        first.depends_on = vec![MigrationTransferId(1)];
        let mut second = scheduled_transfer(3, 1, 1440, 90_000, MigrationTxState::Signed);
        second.depends_on = vec![MigrationTransferId(1)];

        let mut state = state_with_crossings(
            &[50_000_000, 50_000_000],
            vec![tx(0, prep(0, 0), mined(10)), prep_layer_1, first, second],
        );
        state.report_broadcast_failure(MigrationTransferId(1), BlockHeight::from_u32(1700));

        // Another wallet on the same seed spent the notes this preparation was built over, and
        // the wallet has now scanned the block that did it.
        let mut store = TestStore::new(1700, [(MigrationTransferId(1), spent(1700))]);
        assert_eq!(
            advance_migration(
                &mut store,
                &mut state,
                BlockHeight::from_u32(1701),
                &config()
            )
            .expect("the store never fails"),
            AdvanceStep::Replan,
        );

        let marked = BlockHeight::from_u32(1700);
        assert_eq!(
            state.transactions()[1].unsatisfiable(),
            Some((marked, UnsatisfiableKind::InputsSpent)),
            "the rejection is adjudicated into an evidence-backed mark at the answer's height",
        );
        assert_eq!(
            state.transactions()[1].broadcast_failure_at(),
            None,
            "and the testimony it rested on is discharged",
        );
        for stranded in [2, 3] {
            assert_eq!(
                state.transactions()[stranded].unsatisfiable(),
                Some((marked, UnsatisfiableKind::Inherited)),
                "the durable closure strands the crossings behind the dead preparation",
            );
        }
        assert!(state.replan_required());
        assert_eq!(
            store.replaced.get(),
            1,
            "the marks and the discharge persist in one write"
        );
        let stored = store.stored.as_ref().expect("persisted");
        assert_eq!(
            stored.transactions()[1].unsatisfiable(),
            Some((marked, UnsatisfiableKind::InputsSpent))
        );
        assert_eq!(stored.transactions()[1].broadcast_failure_at(), None);
    }

    /// A TERMINAL migration is never driven further, so a report left standing on it neither
    /// costs a query nor holds the driver at `Reevaluate`: there is no broadcast to withhold.
    #[test]
    fn advance_ignores_a_report_on_a_terminal_migration() {
        let mut state = state_with_crossings(
            &[100_000_000],
            vec![
                tx(0, prep(0, 0), mined(10)),
                scheduled_transfer(1, 0, 1440, 1500, MigrationTxState::Proved),
            ],
        );
        state.report_broadcast_failure(MigrationTransferId(1), BlockHeight::from_u32(1700));
        state.mark_superseded();
        let mut store = TestStore::new(1600, []);

        assert_eq!(
            advance_migration(
                &mut store,
                &mut state,
                BlockHeight::from_u32(1601),
                &config()
            )
            .expect("the store never fails"),
            AdvanceStep::Complete,
        );
        assert_eq!(store.queries.get(), 0);
        assert_eq!(store.replaced.get(), 0);
    }

    /// `Reevaluate` is a RETURN like any other, so the determinations made on the way to it are
    /// durable before it is surfaced. Here the in-flight sweep marks a broadcast crossing whose
    /// anchor a settled reorg displaced, while a second crossing's rejection cannot yet be
    /// answered: the call ends at `Reevaluate`, and the mark is in the STORE, not only in the
    /// returned state — a consumer that syncs, restarts, and drives again must not have to
    /// rediscover it.
    #[test]
    fn advance_persists_sweep_marks_before_returning_reevaluate() {
        let mut in_flight = scheduled_transfer(
            1,
            0,
            1440,
            1500,
            MigrationTxState::Broadcast {
                txid: TxId::from_bytes([4; 32]),
            },
        );
        in_flight.depends_on = vec![MigrationTransferId(0)];
        let mut reported = scheduled_transfer(2, 1, 1440, 1500, MigrationTxState::Proved);
        reported.depends_on = vec![MigrationTransferId(0)];

        let mut state = state_with_crossings(
            &[50_000_000, 50_000_000],
            vec![tx(0, prep(0, 0), mined(10)), in_flight, reported],
        );
        state.report_broadcast_failure(MigrationTransferId(2), BlockHeight::from_u32(1700));

        let mut store = TestStore::new(
            1600,
            [(
                MigrationTransferId(1),
                StepSatisfiability::Unsatisfiable {
                    cause: UnsatisfiableCause::AnchorInvalidated,
                    as_of: BlockHeight::from_u32(1600),
                },
            )],
        );

        assert_eq!(
            advance_migration(
                &mut store,
                &mut state,
                BlockHeight::from_u32(1601),
                &config()
            )
            .expect("the store never fails"),
            AdvanceStep::Reevaluate,
        );
        let marked = BlockHeight::from_u32(1600);
        assert_eq!(
            state.transactions()[1].unsatisfiable(),
            Some((marked, UnsatisfiableKind::AnchorInvalidated)),
        );
        assert_eq!(
            store.replaced.get(),
            1,
            "one write carries every determination this call made"
        );
        assert_eq!(
            store
                .stored
                .as_ref()
                .expect("the sweep's mark was persisted before the step was surfaced")
                .transactions()[1]
                .unsatisfiable(),
            Some((marked, UnsatisfiableKind::AnchorInvalidated)),
        );
    }

    /// The same durability, for the adjudication's own half: with two rejections outstanding and
    /// only one of them answerable, the answerable one is discharged and that discharge is
    /// PERSISTED even though the call still ends at `Reevaluate`. Losing it would leave the
    /// crossing withheld from the broadcast queue on a question already settled.
    #[test]
    fn advance_persists_a_discharged_report_before_returning_reevaluate() {
        let mut answerable = scheduled_transfer(1, 0, 1440, 1500, MigrationTxState::Proved);
        answerable.depends_on = vec![MigrationTransferId(0)];
        let mut pending = scheduled_transfer(2, 1, 1440, 1500, MigrationTxState::Proved);
        pending.depends_on = vec![MigrationTransferId(0)];

        let mut state = state_with_crossings(
            &[50_000_000, 50_000_000],
            vec![tx(0, prep(0, 0), mined(10)), answerable, pending],
        );
        // The first rejection came from a node whose tip the wallet has since scanned past; the
        // second from one reporting a tip it has not reached.
        state.report_broadcast_failure(MigrationTransferId(1), BlockHeight::from_u32(1500));
        state.report_broadcast_failure(MigrationTransferId(2), BlockHeight::from_u32(1700));
        let mut store = TestStore::new(1600, []);

        assert_eq!(
            advance_migration(
                &mut store,
                &mut state,
                BlockHeight::from_u32(1601),
                &config()
            )
            .expect("the store never fails"),
            AdvanceStep::Reevaluate,
            "one unanswerable rejection still holds the whole loop",
        );
        assert_eq!(state.transactions()[1].broadcast_failure_at(), None);
        assert_eq!(
            state.transactions()[2].broadcast_failure_at(),
            Some(BlockHeight::from_u32(1700)),
        );
        assert_eq!(store.replaced.get(), 1);
        let stored = store
            .stored
            .as_ref()
            .expect("the discharge was persisted before the step was surfaced");
        assert_eq!(
            stored.transactions()[1].broadcast_failure_at(),
            None,
            "the settled question does not withhold the crossing again after a restart",
        );
        assert_eq!(
            stored.transactions()[2].broadcast_failure_at(),
            Some(BlockHeight::from_u32(1700)),
            "and the open one still stands",
        );
    }
}

#[cfg(all(test, feature = "orchard"))]
mod commit_tests {
    use super::*;
    use crate::{
        build::{
            sign_pczt,
            test_util::{
                TARGET_HEIGHT, account_derivation, assert_every_spend_is_identifiable,
                regtest_network, single_note_witness, spend_signability, spending_key,
            },
        },
        denomination::{
            DESTINATION_ACTIONS_PER_TRANSFER, DenominationPlan, SOURCE_ACTIONS_PER_TRANSFER,
        },
        preparation::{PREP_TX_ACTIONS, plan_preparation},
        scheduling::{AnchorBucketInterval, SchedulingParams},
    };
    use rand_chacha::ChaCha8Rng;
    use rand_core::SeedableRng;
    use zcash_protocol::{
        consensus::{NetworkUpgrade, Parameters as _},
        value::COIN,
    };

    use orchard::keys::{FullViewingKey, SpendAuthorizingKey};

    /// The canonical fees on the regtest network at the build height, computed exactly as
    /// `plan_migration` computes them.
    fn commit_test_fees() -> (Zatoshis, Zatoshis) {
        canonical_fees(&regtest_network(true), BlockHeight::from_u32(TARGET_HEIGHT))
            .expect("the canonical fees compute")
    }

    fn prep_fee() -> Zatoshis {
        commit_test_fees().0
    }

    /// A wallet mock holding the account's key and its spendable notes' PLAINTEXTS — nothing
    /// more: with anchors and witnesses deferred to proving time (ZIP 374), building and signing
    /// an entire migration needs no tree access at all. It signs with its own spend-authorizing
    /// key and stores the migration in memory.
    struct CommitMock {
        wallet_notes: Vec<orchard::note::Note>,
        fvk: FullViewingKey,
        ask: SpendAuthorizingKey,
        account_derivation: Option<AccountDerivation>,
        stored: Option<MigrationState>,
        tip: BlockHeight,
        sched_params: crate::scheduling::SchedulingParams,
    }

    impl CommitMock {
        /// A mock wallet holding single notes of the given values, derived from `seed`.
        fn new(seed: u64, values: &[u64]) -> Self {
            let sk = spending_key(seed);
            let fvk = FullViewingKey::from(&sk);
            let wallet_notes = values
                .iter()
                .enumerate()
                .map(|(i, &v)| single_note_witness(&fvk, v, seed.wrapping_add(i as u64)).0)
                .collect();
            CommitMock {
                wallet_notes,
                fvk,
                ask: SpendAuthorizingKey::from(&sk),
                account_derivation: Some(account_derivation(seed)),
                stored: None,
                tip: BlockHeight::from_u32(2_000_000),
                sched_params: crate::scheduling::SchedulingParams::ZIP_318,
            }
        }
    }

    impl MigrationBackend for CommitMock {
        type Error = core::convert::Infallible;

        fn spendable_orchard_note_values(&self) -> Result<Vec<Zatoshis>, Self::Error> {
            Ok(self
                .wallet_notes
                .iter()
                .map(|n| Zatoshis::from_u64(n.value().inner()).expect("test note values are valid"))
                .collect())
        }

        fn chain_tip_height(&self) -> Result<BlockHeight, Self::Error> {
            Ok(self.tip)
        }

        fn scheduling_params(&self) -> crate::scheduling::SchedulingParams {
            self.sched_params
        }
    }

    impl PoolMigrationRead for CommitMock {
        type Error = core::convert::Infallible;

        fn get_migration(&self) -> Result<Option<MigrationState>, Self::Error> {
            Ok(self.stored.clone())
        }

        fn check_step_satisfiability(
            &self,
            _tx: &MigrationTransaction,
            _settle: ReorgSettleDepth,
        ) -> Result<StepSatisfiability, Self::Error> {
            // This mock models a wallet whose environment never obstructs a step; tests that
            // exercise the oracle configure the `zcash_pool_migration_memory` mocks instead.
            Ok(StepSatisfiability::Satisfiable { as_of: self.tip })
        }
    }

    impl PoolMigrationWrite for CommitMock {
        fn replace_migration(&mut self, state: &MigrationState) -> Result<(), Self::Error> {
            self.stored = Some(state.clone());
            Ok(())
        }

        fn update_transaction(
            &mut self,
            id: MigrationTransferId,
            state: MigrationTxState,
        ) -> Result<(), Self::Error> {
            if let Some(stored) = &mut self.stored
                && let Some(tx) = stored.transactions.iter_mut().find(|t| t.id == id)
            {
                tx.state = state;
            }
            Ok(())
        }
    }

    impl MigrationCrypto for CommitMock {
        type Error = core::convert::Infallible;

        fn orchard_fvk(&self) -> Result<FullViewingKey, Self::Error> {
            Ok(self.fvk.clone())
        }

        fn account_derivation(&self) -> Result<Option<AccountDerivation>, Self::Error> {
            Ok(self.account_derivation.clone())
        }

        fn resolve_wallet_note(&self, index: usize) -> Result<orchard::note::Note, Self::Error> {
            Ok(self.wallet_notes[index])
        }

        fn sign(&self, pczt: pczt::Pczt) -> Result<pczt::Pczt, Self::Error> {
            Ok(sign_pczt(pczt, &self.ask).expect("signs the migration PCZT"))
        }
    }

    /// Install a stand-in witness on every still-deferred spend of `pczt`, mimicking the one
    /// structural effect of real proving the engine itself can observe: a PROVEN PCZT carries no
    /// unwitnessed spends, so the deferred-witness rule no longer identifies its real spends.
    /// The path is arbitrary (a single-leaf tree), exactly like the builder's dummy witnesses;
    /// anchors and proofs need the commitment tree the mock does not model, and nothing in the
    /// engine inspects them.
    fn install_stand_in_witnesses(pczt: pczt::Pczt) -> pczt::Pczt {
        use incrementalmerkletree::{Hashable, Level};
        use orchard::tree::{MerkleHashOrchard, MerklePath};

        let witnesses: Vec<(usize, MerklePath)> = crate::pczt_spends::real_spend_nullifiers(&pczt)
            .expect("an unproven migration PCZT has real spends")
            .into_iter()
            .map(|(index, _)| {
                let auth_path = core::array::from_fn(|level| {
                    MerkleHashOrchard::empty_root(Level::from(level as u8))
                });
                (index, MerklePath::from_parts(0, auth_path))
            })
            .collect();
        pczt::roles::updater::Updater::new(pczt)
            .set_orchard_spend_witnesses(witnesses)
            .expect("the stand-in witnesses install on the deferred spends")
            .finish()
    }

    impl MigrationProver for CommitMock {
        type Error = core::convert::Infallible;

        fn prove_transfer(
            &mut self,
            pczt: pczt::Pczt,
            _anchor_boundary: BlockHeight,
        ) -> Result<pczt::Pczt, ProveFailure<Self::Error>> {
            // A stand-in for proving. A real prover resolves the funding note's witness against
            // `anchor_boundary`, installs it and the Orchard source and Ironwood destination
            // anchors through the PCZT `Updater` role, and runs the Orchard + Ironwood provers.
            // Resolving the real witness requires commitment-tree access this mock does not
            // model, so it installs only a stand-in witness on each deferred spend
            // ([`install_stand_in_witnesses`]) — enough that the stored proven bytes, like real
            // proven bytes, no longer identify their real spends by deferred witness. The
            // engine's `prove_transfer` orchestration (reading and passing the persisted
            // `anchor_boundary`, and the Signed -> Proved transition) is what the tests exercise.
            Ok(install_stand_in_witnesses(pczt))
        }

        fn anchor_bucket_interval(&self) -> crate::scheduling::AnchorBucketInterval {
            self.sched_params.anchor_bucket_interval()
        }

        fn prove_preparation(
            &mut self,
            pczt: pczt::Pczt,
            _anchor: BlockHeight,
        ) -> Result<pczt::Pczt, ProveFailure<Self::Error>> {
            // A stand-in for proving, as `prove_transfer` above: a real prover installs the Orchard
            // anchor and every spend's witness and runs the Orchard prover (see
            // `WalletMigrationProver`). This mock models no commitment tree, so it installs only
            // the stand-in witnesses; the engine's `prove_preparation` orchestration is what the
            // tests exercise.
            Ok(install_stand_in_witnesses(pczt))
        }
    }

    /// A planned single-note migration and the mock wallet that holds the note.
    fn single_note_setup(seed: u64, balance: u64) -> (CommitMock, MigrationPlan) {
        let backend = CommitMock::new(seed, &[balance]);
        let mut rng = ChaCha8Rng::seed_from_u64(seed);
        let plan = plan_migration(&regtest_network(true), &backend, &mut rng)
            .expect("a fundable balance plans");
        (backend, plan)
    }

    /// The WHOLE migration — every preparation transaction and every transfer — is built and
    /// SIGNED in the one commit pass, before anything is broadcast or mined: the funding notes
    /// are recovered from the built preparation bundles, and every stored PCZT carries ABSENT
    /// anchors (ZIP 374), to be installed at proving time against each transaction's anchor.
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
        assert_eq!(state.status, MigrationStatus::Committed);
        assert_eq!(state.transactions.len(), prep_count + transfer_count);

        // The funding notes exist only once the last preparation transaction has mined; every
        // drawn boundary must lie at or after that estimate, exactly as the draw is floored.
        let est_last_prep = state
            .transactions
            .iter()
            .filter(|t| matches!(t.kind, MigrationTxKind::Preparation { .. }))
            .map(|t| t.scheduled_height)
            .max()
            .expect("the plan has a preparation")
            + EST_PREP_LAYER_MINING_BLOCKS;

        for tx in &state.transactions {
            // ONE signing phase: everything is signed at commit, before anything mines.
            assert_eq!(tx.state, MigrationTxState::Signed, "signed at commit");
            assert!(!tx.pczt.is_empty());
            let parsed = pczt::Pczt::parse(&tx.pczt).expect("the stored PCZT parses");
            // Anchors are deferred (ZIP 374): every stored PCZT carries ABSENT anchors, and the
            // pre-signature commits to the stored canonical expiry for the drawn schedule.
            assert!(parsed.orchard().anchor().is_none());
            assert!(parsed.ironwood().anchor().is_none());
            assert_eq!(
                *parsed.global().expiry_height(),
                u32::from(tx.expiry_height),
                "the embedded expiry matches the stored schedule expiry"
            );
            match tx.kind {
                MigrationTxKind::Preparation { .. } => {
                    assert!(
                        tx.depends_on.is_empty(),
                        "single-layer preps are independent"
                    );
                    assert!(tx.anchor_boundary.is_none());
                }
                MigrationTxKind::Transfer { .. } => {
                    // A transfer depends only on the ONE preparation transaction that mints its
                    // funding note, so it releases as soon as its own note is mined, not once the
                    // whole last layer mines.
                    assert_eq!(
                        tx.depends_on.len(),
                        1,
                        "a transfer waits on exactly its funding note's producer"
                    );
                    let producer = tx.depends_on[0];
                    assert!(
                        state.transactions.iter().any(|p| p.id == producer
                            && matches!(p.kind, MigrationTxKind::Preparation { .. })),
                        "the dependency is a preparation transaction"
                    );
                    // The boundary anchor the transfer will PROVE against is drawn at commit
                    // time: on the boundary grid, strictly above the NU6.3 activation, at or
                    // after the estimated height the last preparation has mined, and strictly
                    // below the most recent boundary at the scheduled broadcast height.
                    let b = u32::from(
                        tx.anchor_boundary
                            .expect("every transfer carries its boundary"),
                    );
                    let interval =
                        crate::scheduling::SchedulingParams::ZIP_318.anchor_bucket_interval();
                    assert!(interval.is_boundary(BlockHeight::from_u32(b)));
                    assert!(b > 10, "boundary above the regtest NU6.3 activation");
                    assert!(b >= u32::from(interval.boundary_at_or_above(est_last_prep)));
                    assert!(b < u32::from(interval.boundary_at_or_below(tx.scheduled_height)));
                }
            }
        }

        // Every committed transaction caches its real-spend nullifiers, matching the
        // deferred-witness identification the prover uses (ZIP 374: dummies carry witnesses).
        for tx in &state.transactions {
            let parsed = pczt::Pczt::parse(&tx.pczt).expect("stored PCZT parses");
            let expected: Vec<[u8; 32]> = crate::pczt_spends::real_spend_nullifiers(&parsed)
                .expect("a committed transaction's stored PCZT has real spends")
                .into_iter()
                .map(|(_, nf)| nf.to_bytes())
                .collect();
            assert_eq!(tx.spend_nullifiers, expected);
            // The cache is non-empty by an independent count: a transfer spends exactly its one
            // funding note, and a preparation transaction spends at least one note.
            match tx.kind {
                MigrationTxKind::Transfer { .. } => assert_eq!(
                    tx.spend_nullifiers.len(),
                    1,
                    "a transfer's one real spend is its funding note"
                ),
                MigrationTxKind::Preparation { .. } => assert!(
                    !tx.spend_nullifiers.is_empty(),
                    "a preparation transaction has at least one real spend"
                ),
            }
        }
        assert!(backend.get_migration().unwrap().is_some());
    }

    /// Every transaction a commit hands to an EXTERNAL signer is identifiable to it: each spend
    /// still awaiting a signature carries the account's ZIP 32 derivation, and the only actions
    /// without it are the padding dummies the IO Finalizer already signed. A signer that matches
    /// spends by derivation path skips what it cannot recognize, so an unstamped spend is one no
    /// signature ever arrives for and the transaction can never be extracted.
    ///
    /// Covers the whole commit path — preparation layers and transfers alike — and its converse:
    /// a backend that reports no derivation produces transactions only an in-process signer, which
    /// matches by key, can authorize.
    #[test]
    fn externally_signed_migrations_identify_every_spend_to_the_signer() {
        let seed = 77u64;
        let params = regtest_network(true);
        // A balance large enough to need preparation, so both builders are exercised.
        let mut backend = CommitMock::new(seed, &[400 * COIN]);

        let mut rng = ChaCha8Rng::seed_from_u64(seed);
        let plan = plan_migration(&params, &backend, &mut rng).expect("a fundable balance plans");
        assert!(
            plan.preparation().transaction_count() > 0,
            "the balance needs preparation, so preparation transactions are built",
        );

        let mut rng = ChaCha8Rng::seed_from_u64(seed + 1);
        let (state, unsigned) = build_preparation_unsigned(
            &params,
            BlockHeight::from_u32(TARGET_HEIGHT),
            &mut backend,
            &plan,
            &mut rng,
            ReplanThreshold::DEFAULT,
        )
        .expect("commits the migration for external signing");
        assert!(
            !unsigned.is_empty(),
            "there is work for the external signer"
        );

        let mut spends_awaiting_signature = 0;
        for tx in &state.transactions {
            let pczt = pczt::Pczt::parse(&tx.pczt).expect("a stored PCZT parses");
            spends_awaiting_signature += assert_every_spend_is_identifiable(&pczt);
        }
        assert!(
            spends_awaiting_signature > 0,
            "the external signer has spends to authorize",
        );

        // Without a known derivation nothing is stamped, so the same spends are left unidentifiable.
        let mut anonymous = CommitMock::new(seed, &[400 * COIN]);
        anonymous.account_derivation = None;
        let mut rng = ChaCha8Rng::seed_from_u64(seed + 1);
        let (anonymous_state, _) = build_preparation_unsigned(
            &params,
            BlockHeight::from_u32(TARGET_HEIGHT),
            &mut anonymous,
            &plan,
            &mut rng,
            ReplanThreshold::DEFAULT,
        )
        .expect("commits the migration for external signing");
        let unidentifiable = anonymous_state
            .transactions
            .iter()
            .map(|tx| {
                let pczt = pczt::Pczt::parse(&tx.pczt).expect("a stored PCZT parses");
                spend_signability(&pczt).1
            })
            .sum::<usize>();
        assert_eq!(
            unidentifiable, spends_awaiting_signature,
            "a backend with no derivation leaves every awaiting spend unidentifiable",
        );
    }

    /// An expired transfer is rebuilt in place: rescheduled forward with a fresh boundary anchor and
    /// canonical expiry and re-signed against the same funding note, its denomination unchanged, and
    /// moved back to `Signed` ready to prove and broadcast on the new schedule (ZIP 318 error
    /// handling). A wallet holding exactly one funding note funds the transfer DIRECTLY (no
    /// preparation), so the note stays spendable for the rebuild to re-resolve by value.
    #[test]
    fn rebuild_expired_transfer_reschedules_and_resigns_in_place() {
        let seed = 99u64;
        let params = regtest_network(true);
        let buffer = u64::from(commit_test_fees().1);
        let funding_note = COIN + buffer; // one 1-ZEC crossing plus its fee buffer
        let mut backend = CommitMock::new(seed, &[funding_note]);

        let mut rng = ChaCha8Rng::seed_from_u64(seed);
        let plan = plan_migration(&params, &backend, &mut rng).expect("a fundable balance plans");
        // Direct funding: exactly one transfer, no preparation transactions.
        assert_eq!(
            plan.preparation()
                .layers()
                .iter()
                .map(|l| l.len())
                .sum::<usize>(),
            0,
            "the wallet note funds the transfer directly"
        );
        assert_eq!(plan.funding_notes().len(), 1);

        let mut rng = ChaCha8Rng::seed_from_u64(seed + 1);
        let mut state = commit_preparation(
            &params,
            BlockHeight::from_u32(TARGET_HEIGHT),
            &mut backend,
            &plan,
            &mut rng,
            ReplanThreshold::DEFAULT,
        )
        .expect("commits the migration");
        assert_eq!(state.transactions.len(), 1);
        let id = state.transactions[0].id;
        let old = state.transactions[0].clone();
        assert_eq!(old.state, MigrationTxState::Signed);
        assert!(
            old.depends_on.is_empty(),
            "a directly funded transfer has no producer"
        );

        // Advance the chain tip past the transfer's expiry, so it can no longer be mined.
        backend.tip = old.expiry_height + 1;
        let target = backend.chain_tip_height().unwrap() + 1;
        assert!(
            state.expired_transactions(target).contains(&id),
            "the transfer has expired at the new tip"
        );

        // Rebuild it.
        let mut rng = ChaCha8Rng::seed_from_u64(seed + 2);
        rebuild_expired_transfer(&params, &backend, &mut state, id, &mut rng)
            .expect("rebuilds the expired transfer");

        let new = &state.transactions[0];
        // Same denomination and kind, back to Signed, with a fresh schedule, expiry, anchor, and PCZT.
        assert_eq!(
            new.kind, old.kind,
            "the denomination (crossing) is unchanged"
        );
        assert_eq!(new.state, MigrationTxState::Signed);
        assert!(
            new.scheduled_height > old.scheduled_height,
            "rescheduled forward from the new tip"
        );
        assert!(
            new.expiry_height > old.expiry_height,
            "a fresh, later canonical expiry"
        );
        assert_ne!(new.pczt, old.pczt, "a freshly built and re-signed PCZT");
        // The refreshed nullifier cache equals the expired transaction's: rebuilding re-funds the
        // transfer with the same note IDENTITY, and a note's nullifier is schedule-independent.
        assert!(!new.spend_nullifiers.is_empty());
        assert_eq!(
            new.spend_nullifiers, old.spend_nullifiers,
            "the same funding note yields the same real-spend nullifier"
        );
        // The fresh anchor boundary is on the grid and within the rebuilt schedule's candidate set.
        let boundary = u32::from(
            new.anchor_boundary
                .expect("the rebuilt transfer carries a boundary"),
        );
        let interval = crate::scheduling::SchedulingParams::ZIP_318.anchor_bucket_interval();
        assert!(interval.is_boundary(BlockHeight::from_u32(boundary)));
        assert!(boundary < u32::from(interval.boundary_at_or_below(new.scheduled_height)));

        // The rebuilt PCZT is a valid pre-signed transfer with deferred anchors and the new expiry.
        let parsed = pczt::Pczt::parse(&new.pczt).expect("the rebuilt PCZT parses");
        assert!(parsed.orchard().anchor().is_none());
        assert!(parsed.ironwood().anchor().is_none());
        assert_eq!(
            *parsed.global().expiry_height(),
            u32::from(new.expiry_height)
        );

        // It is no longer expired at the tip it was rebuilt against.
        assert!(!state.expired_transactions(target).contains(&id));
    }

    /// A transfer that was PROVED before it expired is still rebuildable. Proving replaces the
    /// stored bytes with the proven PCZT, whose real spend carries an installed witness, so the
    /// deferred-witness rule no longer identifies the funding note there — the rebuild must read
    /// the persisted nullifier cache instead. This is exactly the resumed-wallet scenario in
    /// which broadcast windows lapse after proving; were the rebuild to fail here, `next_step`
    /// would keep surfacing the same `Rebuild` for a permanently failing call (a livelock).
    #[test]
    fn rebuild_reads_the_nullifier_cache_for_a_proved_transfer() {
        let seed = 101u64;
        let params = regtest_network(true);
        let buffer = u64::from(commit_test_fees().1);
        let mut backend = CommitMock::new(seed, &[COIN + buffer]);

        let mut rng = ChaCha8Rng::seed_from_u64(seed);
        let plan = plan_migration(&params, &backend, &mut rng).expect("a fundable balance plans");
        let mut rng = ChaCha8Rng::seed_from_u64(seed + 1);
        let mut state = commit_preparation(
            &params,
            BlockHeight::from_u32(TARGET_HEIGHT),
            &mut backend,
            &plan,
            &mut rng,
            ReplanThreshold::DEFAULT,
        )
        .expect("commits the migration");
        assert_eq!(state.transactions.len(), 1, "one directly funded transfer");
        let id = state.transactions[0].id;

        // Prove the transfer: the PROVEN bytes replace the stored ones, and their real spend now
        // carries a witness, so it is no longer identifiable from the bytes.
        assert_eq!(
            prove_transfer(&mut backend, &mut state, id).expect("proves the transfer"),
            ProveOutcome::Proved
        );
        let old = state.transactions[0].clone();
        assert!(matches!(old.state, MigrationTxState::Proved));
        let proven = pczt::Pczt::parse(&old.pczt).expect("the proven PCZT parses");
        assert!(
            matches!(
                crate::pczt_spends::real_spend_nullifiers(&proven),
                Err(crate::pczt_spends::RealSpendError::NoRealSpends)
            ),
            "a proven PCZT's real spends are not identifiable by deferred witness"
        );

        // The proof went unused: the broadcast window lapsed and the transfer expired.
        backend.tip = old.expiry_height + 1;
        let target = backend.chain_tip_height().unwrap() + 1;
        assert!(state.expired_transactions(target).contains(&id));

        // The rebuild recovers the funding note from the persisted nullifier cache.
        let mut rng = ChaCha8Rng::seed_from_u64(seed + 2);
        rebuild_expired_transfer(&params, &backend, &mut state, id, &mut rng)
            .expect("rebuilds the expired proved transfer");
        let new = &state.transactions[0];
        assert_eq!(new.state, MigrationTxState::Signed);
        assert!(!new.spend_nullifiers.is_empty());
        assert_eq!(
            new.spend_nullifiers, old.spend_nullifiers,
            "the rebuilt transfer spends the same funding note"
        );
    }

    /// The nullifier of the one real spend (the action with no witness; ZIP 374 deferral leaves
    /// the padding dummy its arbitrary witness) of a stored transfer PCZT.
    fn real_spend_nullifier(pczt_bytes: &[u8]) -> [u8; 32] {
        let parsed = pczt::Pczt::parse(pczt_bytes).expect("the stored PCZT parses");
        let real: Vec<[u8; 32]> = parsed
            .orchard()
            .actions()
            .iter()
            .filter(|a| a.spend().witness().is_none())
            .map(|a| *a.spend().nullifier())
            .collect();
        assert_eq!(real.len(), 1, "a transfer has exactly one real spend");
        real[0]
    }

    /// Rebuilding re-funds the transfer with EXACTLY the note its expired PCZT spends (matched by
    /// nullifier), not whichever spendable note happens to share its value: migration
    /// denominations repeat, and re-funding from a sibling transfer's identical-value note would
    /// make the rebuilt transfer a double-spend of that still-valid sibling.
    #[test]
    fn rebuild_resolves_the_exact_funding_note_not_an_equal_value_sibling() {
        let seed = 103u64;
        let params = regtest_network(true);
        let buffer = u64::from(commit_test_fees().1);
        let funding_note = COIN + buffer;
        // TWO identical-denomination funding notes: two transfers of the same funding value.
        let mut backend = CommitMock::new(seed, &[funding_note, funding_note]);

        let mut rng = ChaCha8Rng::seed_from_u64(seed);
        let plan = plan_migration(&params, &backend, &mut rng).expect("a fundable balance plans");
        let mut rng = ChaCha8Rng::seed_from_u64(seed + 1);
        let mut state = commit_preparation(
            &params,
            BlockHeight::from_u32(TARGET_HEIGHT),
            &mut backend,
            &plan,
            &mut rng,
            ReplanThreshold::DEFAULT,
        )
        .expect("commits the migration");
        // Direct funding: two transfers, no preparation transactions.
        assert_eq!(state.transactions.len(), 2);
        let victim = state
            .transactions
            .iter()
            .find(|t| matches!(t.kind, MigrationTxKind::Transfer { crossing: 1 }))
            .expect("the second crossing's transfer exists")
            .clone();

        // Expire every transfer.
        let latest_expiry = state
            .transactions
            .iter()
            .map(|t| t.expiry_height)
            .max()
            .expect("transactions exist");
        backend.tip = latest_expiry + 1;

        let mut rng = ChaCha8Rng::seed_from_u64(seed + 2);
        rebuild_expired_transfer(&params, &backend, &mut state, victim.id, &mut rng)
            .expect("rebuilds the expired transfer");

        let rebuilt = state
            .transactions
            .iter()
            .find(|t| t.id == victim.id)
            .expect("the rebuilt transfer is still stored");
        assert_eq!(
            real_spend_nullifier(&rebuilt.pczt),
            real_spend_nullifier(&victim.pczt),
            "the rebuilt transfer spends the same funding note its expired PCZT spent"
        );
    }

    /// When the exact funding note is gone (spent outside the migration), rebuilding fails with
    /// `FundingNoteUnavailable` even if the wallet holds a DIFFERENT spendable note of equal
    /// value: re-funding a part from an arbitrary note is re-planning, not a rebuild.
    #[test]
    fn rebuild_rejects_a_replaced_funding_note_of_equal_value() {
        let seed = 105u64;
        let params = regtest_network(true);
        let buffer = u64::from(commit_test_fees().1);
        let funding_note = COIN + buffer;
        let mut backend = CommitMock::new(seed, &[funding_note]);

        let mut rng = ChaCha8Rng::seed_from_u64(seed);
        let plan = plan_migration(&params, &backend, &mut rng).expect("a fundable balance plans");
        let mut rng = ChaCha8Rng::seed_from_u64(seed + 1);
        let mut state = commit_preparation(
            &params,
            BlockHeight::from_u32(TARGET_HEIGHT),
            &mut backend,
            &plan,
            &mut rng,
            ReplanThreshold::DEFAULT,
        )
        .expect("commits the migration");
        let tx = state.transactions[0].clone();

        // Replace the funding note with a different note of the SAME value, as if the original
        // was spent outside the migration and equal-value change arrived in its place.
        let replacement = single_note_witness(&backend.fvk, funding_note, seed + 777).0;
        backend.wallet_notes[0] = replacement;
        backend.tip = tx.expiry_height + 1;

        let mut rng = ChaCha8Rng::seed_from_u64(seed + 2);
        assert!(matches!(
            rebuild_expired_transfer(&params, &backend, &mut state, tx.id, &mut rng),
            Err(RebuildError::FundingNoteUnavailable(v))
                if v == Zatoshis::from_u64(funding_note).expect("test value is valid")
        ));
    }

    /// For an EXTERNALLY signed migration (a hardware or offline signer), an expired transfer is
    /// rebuilt UNSIGNED, mirroring [`build_preparation_unsigned`]: it moves to
    /// `AwaitingSignature` holding the fresh unsigned PCZT, the same bytes come back as an
    /// [`UnsignedMigrationTx`] to route to the device (batchable by action budget), and
    /// [`MigrationState::apply_signature`] completes it to `Signed`. In-process signing never
    /// runs: the spend authority stays on the device.
    #[test]
    fn rebuild_expired_transfer_unsigned_awaits_the_external_signature() {
        let seed = 107u64;
        let params = regtest_network(true);
        let buffer = u64::from(commit_test_fees().1);
        let funding_note = COIN + buffer;
        let mut backend = CommitMock::new(seed, &[funding_note]);

        let mut rng = ChaCha8Rng::seed_from_u64(seed);
        let plan = plan_migration(&params, &backend, &mut rng).expect("a fundable balance plans");
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
        // Sign out of band and apply, exactly as the external-signing caller does.
        for u in unsigned {
            let (id, bytes) = u.into_parts();
            let signed = sign_pczt(
                pczt::Pczt::parse(&bytes).expect("the unsigned PCZT parses"),
                &backend.ask,
            )
            .expect("the external signer signs");
            assert!(state.apply_signature(id, signed.serialize().expect("serializes")));
        }
        let old = state.transactions[0].clone();
        assert_eq!(old.state, MigrationTxState::Signed);

        // Expire the transfer, then rebuild it UNSIGNED.
        backend.tip = old.expiry_height + 1;
        let mut rng = ChaCha8Rng::seed_from_u64(seed + 2);
        let unsigned_rebuild =
            rebuild_expired_transfer_unsigned(&params, &backend, &mut state, old.id, &mut rng)
                .expect("rebuilds the expired transfer unsigned");

        // The transfer awaits the external signature, holding the fresh UNSIGNED bytes that were
        // also returned for routing to the signer.
        let rebuilt = state.transactions[0].clone();
        assert_eq!(rebuilt.state, MigrationTxState::AwaitingSignature);
        assert_eq!(unsigned_rebuild.id(), old.id);
        assert_eq!(*unsigned_rebuild.pczt(), rebuilt.pczt);
        assert_eq!(
            unsigned_rebuild.actions(),
            SOURCE_ACTIONS_PER_TRANSFER + DESTINATION_ACTIONS_PER_TRANSFER
        );
        let parsed = pczt::Pczt::parse(&rebuilt.pczt).expect("the rebuilt PCZT parses");
        assert_eq!(
            *parsed.global().expiry_height(),
            u32::from(rebuilt.expiry_height)
        );
        assert!(
            rebuilt.expiry_height > old.expiry_height,
            "a fresh, later canonical expiry"
        );
        // The builder signs its fabricated dummy spends with their throwaway keys; the account's
        // one REAL spend (the unwitnessed one, ZIP 374) is what must await the external signer.
        assert!(
            parsed
                .orchard()
                .actions()
                .iter()
                .filter(|a| a.spend().witness().is_none())
                .all(|a| a.spend().spend_auth_sig().is_none()),
            "the account's spend authorization was not attached in-process"
        );
        // Awaiting an external signer is only useful if that signer can RECOGNIZE the spend as
        // the account's: the rebuild stamps the account's ZIP 32 derivation on the one spend it
        // leaves unsigned.
        assert_eq!(assert_every_spend_is_identifiable(&parsed), 1);
        assert_eq!(
            real_spend_nullifier(&rebuilt.pczt),
            real_spend_nullifier(&old.pczt),
            "the same funding note funds the rebuilt transfer"
        );

        // The externally produced signature completes it back to Signed.
        let signed = sign_pczt(parsed, &backend.ask).expect("the external signer signs");
        assert!(state.apply_signature(old.id, signed.serialize().expect("serializes")));
        assert_eq!(state.transactions[0].state, MigrationTxState::Signed);
    }

    /// Rebuilding rejects a transaction that has not expired, a preparation transaction, and an
    /// unknown id, so a caller cannot reissue a still-valid transfer as a double-spending copy.
    #[test]
    fn rebuild_expired_transfer_rejects_ineligible_transactions() {
        let seed = 101u64;
        let params = regtest_network(true);
        let buffer = u64::from(commit_test_fees().1);
        let mut backend = CommitMock::new(seed, &[COIN + buffer]);
        let mut rng = ChaCha8Rng::seed_from_u64(seed);
        let plan = plan_migration(&params, &backend, &mut rng).expect("a fundable balance plans");
        let mut rng = ChaCha8Rng::seed_from_u64(seed + 1);
        let mut state = commit_preparation(
            &params,
            BlockHeight::from_u32(TARGET_HEIGHT),
            &mut backend,
            &plan,
            &mut rng,
            ReplanThreshold::DEFAULT,
        )
        .expect("commits the migration");
        let id = state.transactions[0].id;

        // Not expired yet (the tip is far below the expiry): rejected.
        let mut rng = ChaCha8Rng::seed_from_u64(seed + 2);
        assert!(matches!(
            rebuild_expired_transfer(&params, &backend, &mut state, id, &mut rng),
            Err(RebuildError::NotExpired(rejected)) if rejected == id
        ));
        // An unknown id: rejected.
        let unknown = MigrationTransferId::new(9999);
        assert!(matches!(
            rebuild_expired_transfer(&params, &backend, &mut state, unknown, &mut rng),
            Err(RebuildError::UnknownTransaction(rejected)) if rejected == unknown
        ));

        // A preparation transaction, even an expired one: rejected. Only a transfer (a leaf of the
        // dependency graph) is rebuilt this way; an expired preparation invalidates its dependents'
        // pre-signatures and needs its own remediation.
        state.transactions[0].kind = MigrationTxKind::Preparation { layer: 0, index: 0 };
        backend.tip = state.transactions[0].expiry_height + 1;
        assert!(matches!(
            rebuild_expired_transfer(&params, &backend, &mut state, id, &mut rng),
            Err(RebuildError::NotATransfer(rejected)) if rejected == id
        ));
    }

    /// A transfer whose inputs can never again all exist unspent is beyond rebuilding, and is
    /// refused SPECIFICALLY: the rebuild re-spends the same funding note, so a fresh anchor and
    /// expiry cure nothing, and the caller must re-plan instead. The guard runs ahead of the
    /// expiry check, so a marked transfer reports `Unsatisfiable` whether or not it has expired —
    /// a dead transfer is usually an expired one too, and `NotExpired` would send the caller down
    /// a remedy that cannot work. A marked DEPENDENCY disqualifies an unmarked transfer the same
    /// way: the rebuild would re-anchor to inputs that never arrive.
    #[test]
    fn rebuild_rejects_an_unsatisfiable_transfer_or_dependency() {
        let seed = 109u64;
        let params = regtest_network(true);
        let buffer = u64::from(commit_test_fees().1);
        let mut backend = CommitMock::new(seed, &[COIN + buffer]);
        let mut rng = ChaCha8Rng::seed_from_u64(seed);
        let plan = plan_migration(&params, &backend, &mut rng).expect("a fundable balance plans");
        let mut rng = ChaCha8Rng::seed_from_u64(seed + 1);
        let mut state = commit_preparation(
            &params,
            BlockHeight::from_u32(TARGET_HEIGHT),
            &mut backend,
            &plan,
            &mut rng,
            ReplanThreshold::DEFAULT,
        )
        .expect("commits the migration");
        assert_eq!(state.transactions.len(), 1, "one directly funded transfer");
        let id = state.transactions[0].id;
        let mark = BlockHeight::from_u32(TARGET_HEIGHT);

        // Marked while still UNEXPIRED: the specific condition wins over `NotExpired`.
        state.transactions[0].unsatisfiable = Some((mark, UnsatisfiableKind::InputsSpent));
        let mut rng = ChaCha8Rng::seed_from_u64(seed + 2);
        assert!(matches!(
            rebuild_expired_transfer(&params, &backend, &mut state, id, &mut rng),
            Err(RebuildError::Unsatisfiable(rejected)) if rejected == id
        ));

        // Marked AND expired — the ordinary shape of a dead transfer, and the one a consumer
        // driving from `expired_transactions` would hand to the rebuild. Still refused, rather
        // than rebuilt against a note the wallet has seen spent.
        backend.tip = state.transactions[0].expiry_height + 1;
        let target = backend.chain_tip_height().unwrap() + 1;
        assert!(
            state.expired_transactions(target).contains(&id),
            "the marked transfer is also expired, as a dead transfer usually is"
        );
        let before = state.transactions[0].clone();
        assert!(matches!(
            rebuild_expired_transfer(&params, &backend, &mut state, id, &mut rng),
            Err(RebuildError::Unsatisfiable(rejected)) if rejected == id
        ));
        assert_eq!(
            state.transactions[0], before,
            "a refused rebuild leaves the transfer untouched"
        );

        // An UNMARKED expired transfer whose producer is marked: the funding note it would
        // re-spend is minted by a transaction that can never mine.
        state.transactions[0].unsatisfiable = None;
        let producer_id = MigrationTransferId::new(77);
        state.transactions[0].depends_on = vec![producer_id];
        state.transactions.push(MigrationTransaction::from_parts(
            producer_id,
            MigrationTxKind::Preparation { layer: 0, index: 0 },
            Vec::new(),
            Vec::new(),
            BlockHeight::from_u32(0),
            BlockHeight::from_u32(0),
            None,
            MigrationTxState::Broadcast {
                txid: TxId::from_bytes([7; 32]),
            },
            None,
            Some((mark, UnsatisfiableKind::InputsSpent)),
            vec![[7u8; 32]],
            None,
        ));
        assert!(matches!(
            rebuild_expired_transfer(&params, &backend, &mut state, id, &mut rng),
            Err(RebuildError::Unsatisfiable(rejected)) if rejected == id
        ));
    }

    /// A lone whale fanning out into more funding notes than one transaction holds needs a
    /// MULTI-LAYER preparation — and it still signs in the SAME single pass: the later layer's
    /// feeder spends and the transfers' funding notes are recovered from the earlier layers'
    /// built (unmined) bundles. Mining then gates only the broadcast order, which the state
    /// machine walks layer by layer.
    #[test]
    fn commits_a_multi_layer_migration_in_one_pass() {
        let seed = 11u64;
        let sk = spending_key(seed);
        let fvk = FullViewingKey::from(&sk);

        // 15 funding notes (one more than a single transaction's FUNDING_OUTPUTS_PER_TX) force a
        // two-layer balanced fan-out. Each is a valid self-funding note (a crossing value plus
        // the transfer fee buffer), so its transfer balances.
        let buffer = u64::from(commit_test_fees().1);
        let crossing = COIN; // 1 ZEC crossing per note
        let funding_note = crossing + buffer;
        let funding: Vec<u64> = core::iter::repeat_n(funding_note, 15).collect();

        // A whale generously larger than the balanced-tree cost, so the fan-out fast path
        // triggers.
        let whale = funding.iter().sum::<u64>() + 16 * u64::from(prep_fee());
        let whale_zats = [Zatoshis::from_u64(whale).expect("test whale is valid")];
        let funding_zats: Vec<Zatoshis> = funding
            .iter()
            .map(|&v| Zatoshis::from_u64(v).expect("test funding values are valid"))
            .collect();
        let preparation = plan_preparation(&whale_zats, &funding_zats, prep_fee())
            .expect("a fundable whale plans");
        assert_eq!(
            preparation.layers().len(),
            2,
            "15 funding notes fan out across two layers"
        );

        // A denomination plan whose outputs are the funding notes and whose crossings are those less
        // the buffer, so each transfer crosses one ZEC.
        let crossings: Vec<u64> = funding.iter().map(|&f| f - buffer).collect();
        let denominations = DenominationPlan::from_stored_parts(
            crossings
                .iter()
                .map(|&v| Zatoshis::from_u64(v).expect("test crossings are valid"))
                .collect(),
            Zatoshis::from_u64(buffer).expect("the buffer is valid"),
            None,
            Zatoshis::from_u64(preparation.transaction_count() as u64 * u64::from(prep_fee()))
                .expect("the reserved fees are valid"),
            whale_zats[0],
            Zatoshis::from_u64(crossings.iter().sum()).expect("the crossing total is valid"),
        )
        .expect("a consistent stored plan reconstructs");
        let mut rng = ChaCha8Rng::seed_from_u64(seed);
        // A drawn preparation schedule in the layers' shape, each layer based past the previous
        // one, exactly as `plan_migration` draws it.
        let mut prep_schedule: Vec<Vec<BlockHeight>> = Vec::new();
        let mut layer_base = BlockHeight::from_u32(2_000_000);
        for layer in preparation.layers() {
            let heights = crate::scheduling::schedule_prep_broadcast_heights(
                &crate::scheduling::SchedulingParams::ZIP_318,
                layer_base,
                layer.len(),
                &mut rng,
            );
            layer_base =
                heights.last().copied().unwrap_or(layer_base) + EST_PREP_LAYER_MINING_BLOCKS;
            prep_schedule.push(heights);
        }
        // Floor the transfer schedule so every transfer has a candidate anchor boundary above
        // the estimated last-preparation mining height, exactly as `plan_migration` floors it.
        let nu63_activation = {
            regtest_network(true)
                .activation_height(NetworkUpgrade::Nu6_3)
                .expect("NU6.3 is active on the test network")
        };
        let schedule_base = crate::scheduling::earliest_broadcast_height(
            crate::scheduling::SchedulingParams::ZIP_318.anchor_bucket_interval(),
            nu63_activation,
            layer_base,
        );
        let schedule = crate::scheduling::schedule(
            &crate::scheduling::SchedulingParams::ZIP_318,
            schedule_base,
            funding.len(),
            &mut rng,
        );
        let plan = MigrationPlan {
            denominations,
            preparation,
            prep_schedule,
            schedule,
        };

        let mut backend = CommitMock {
            wallet_notes: vec![single_note_witness(&fvk, whale, seed).0],
            fvk,
            ask: SpendAuthorizingKey::from(&sk),
            account_derivation: Some(account_derivation(seed)),
            stored: None,
            tip: BlockHeight::from_u32(2_000_000),
            sched_params: crate::scheduling::SchedulingParams::ZIP_318,
        };
        let params = regtest_network(true);
        let prep_count = plan.preparation().transaction_count();
        let transfer_count = funding.len();

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
        assert_eq!(state.transactions.len(), prep_count + transfer_count);
        for tx in &state.transactions {
            assert_eq!(tx.state, MigrationTxState::Signed, "signed at commit");
            assert!(!tx.pczt.is_empty());
        }
        let layer0_ids: Vec<MigrationTransferId> = state
            .transactions
            .iter()
            .filter(|t| matches!(t.kind, MigrationTxKind::Preparation { layer: 0, .. }))
            .map(|t| t.id)
            .collect();
        assert_eq!(layer0_ids.len(), 1, "one root transaction in layer 0");
        for tx in &state.transactions {
            match tx.kind {
                MigrationTxKind::Preparation { layer, .. } if layer > 0 => {
                    assert_eq!(
                        tx.depends_on, layer0_ids,
                        "a later layer broadcasts only after its predecessor mines"
                    );
                }
                _ => {}
            }
        }

        // The state machine walks the broadcasts in dependency order: layer 0 first; layer 1
        // only once layer 0 mines; each transfer once its own funding note's producer mines (here
        // the whole last layer is mined at once, so every transfer becomes broadcastable).
        let mut state = state;
        // A height past every scheduled broadcast (so each transaction is due, not blocked on the
        // schedule) but within every expiry window (so none is expired and offered for rebuild): the
        // latest scheduled height. This exercises the dependency-ordering walk, not expiry handling.
        let target = state
            .transactions
            .iter()
            .map(|t| t.scheduled_height)
            .max()
            .expect("the committed migration has transactions");
        match state.next_step(target, &[]) {
            crate::state::AdvanceStep::Prove { id, .. }
            | crate::state::AdvanceStep::Broadcast { id } => {
                assert!(layer0_ids.contains(&id), "layer 0 broadcasts first")
            }
            other => panic!("expected a broadcast step, got {other:?}"),
        }
        for id in &layer0_ids {
            state.mark_mined(
                *id,
                TxId::from_bytes([0; 32]),
                BlockHeight::from_u32(2_000_010),
            );
        }
        let layer1_ids: Vec<MigrationTransferId> = state
            .transactions
            .iter()
            .filter(|t| matches!(t.kind, MigrationTxKind::Preparation { layer: 1, .. }))
            .map(|t| t.id)
            .collect();
        match state.next_step(target, &[]) {
            crate::state::AdvanceStep::Prove { id, .. }
            | crate::state::AdvanceStep::Broadcast { id } => {
                assert!(
                    layer1_ids.contains(&id),
                    "layer 1 broadcasts once layer 0 mines"
                )
            }
            other => panic!("expected a broadcast step, got {other:?}"),
        }
        for id in &layer1_ids {
            state.mark_mined(
                *id,
                TxId::from_bytes([0; 32]),
                BlockHeight::from_u32(2_000_020),
            );
        }
        match state.next_step(target, &[]) {
            crate::state::AdvanceStep::Prove { id, .. }
            | crate::state::AdvanceStep::Broadcast { id } => {
                let tx = state
                    .transactions
                    .iter()
                    .find(|t| t.id == id)
                    .expect("the step names a stored transaction");
                assert!(
                    matches!(tx.kind, MigrationTxKind::Transfer { .. }),
                    "a transfer broadcasts once its funding note's producer mines"
                );
            }
            other => panic!("expected a broadcast step, got {other:?}"),
        }
    }

    /// A crossing releases as soon as ITS OWN funding note's producer mines — not once the whole
    /// preparation completes. A two-layer whale's funding notes come from more than one producer, so
    /// mining ONE producer makes the crossings it funds releasable while the crossings funded by the
    /// other, still-unmined producer stay blocked.
    #[test]
    fn a_crossing_releases_when_its_own_producer_mines() {
        let seed = 11u64;
        let (mut backend, plan) = single_note_setup(seed, 1_000 * COIN);
        assert_eq!(
            plan.preparation().layers().len(),
            2,
            "the whale fans out across two layers"
        );
        let params = regtest_network(true);
        let mut rng = ChaCha8Rng::seed_from_u64(seed + 1);
        let mut state = commit_preparation(
            &params,
            BlockHeight::from_u32(TARGET_HEIGHT),
            &mut backend,
            &plan,
            &mut rng,
            ReplanThreshold::DEFAULT,
        )
        .expect("commits the migration");

        // The crossings are funded by more than one preparation transaction (each transfer depends
        // on exactly its own producer).
        let mut producers: Vec<MigrationTransferId> = state
            .transactions
            .iter()
            .filter(|t| matches!(t.kind, MigrationTxKind::Transfer { .. }))
            .map(|t| t.depends_on[0])
            .collect();
        producers.sort_by_key(|p| u32::from(*p));
        producers.dedup();
        assert!(
            producers.len() >= 2,
            "the whale's crossings come from at least two producers, got {}",
            producers.len()
        );
        let (p1, p2) = (producers[0], producers[1]);
        // Each producer funds at least one crossing.
        assert!(state
            .transactions
            .iter()
            .any(|t| matches!(t.kind, MigrationTxKind::Transfer { .. }) && t.depends_on == [p1]));
        assert!(state
            .transactions
            .iter()
            .any(|t| matches!(t.kind, MigrationTxKind::Transfer { .. }) && t.depends_on == [p2]));

        // Before anything mines, crossings from neither producer are releasable.
        assert!(!state.deps_mined(&[p1]));
        assert!(!state.deps_mined(&[p2]));

        // Mine ONLY the first producer.
        state.mark_mined(
            p1,
            TxId::from_bytes([0; 32]),
            BlockHeight::from_u32(2_000_000),
        );

        // Crossings funded by p1 are releasable; crossings funded by the still-unmined p2 stay
        // blocked — a crossing does NOT wait for the whole preparation.
        assert!(
            state.deps_mined(&[p1]),
            "a crossing releases once its own producer mines"
        );
        assert!(
            !state.deps_mined(&[p2]),
            "a crossing whose producer has not mined stays blocked"
        );
    }

    /// Consolidating many small notes needs a DEEP preparation — here four layers — and the state
    /// machine still walks the broadcasts strictly layer by layer: each preparation layer depends on
    /// the whole layer before it and broadcasts only once that predecessor mines, and the transfers
    /// come only after the last layer.
    #[test]
    fn commits_a_deep_multi_layer_migration() {
        let seed = 11u64;
        // Thirty 100-ZEC notes consolidate through four preparation layers.
        let mut backend = CommitMock::new(seed, &[100 * COIN; 30]);
        let params = regtest_network(true);
        let mut rng = ChaCha8Rng::seed_from_u64(seed);
        let plan = plan_migration(&params, &backend, &mut rng).expect("a fundable balance plans");
        let layer_count = plan.preparation().layers().len();
        assert_eq!(
            layer_count, 4,
            "deep consolidation fans through four layers"
        );

        let mut rng2 = ChaCha8Rng::seed_from_u64(seed + 1);
        let state = commit_preparation(
            &params,
            BlockHeight::from_u32(TARGET_HEIGHT),
            &mut backend,
            &plan,
            &mut rng2,
            ReplanThreshold::DEFAULT,
        )
        .expect("commits the migration");

        let layer_ids = |s: &MigrationState, layer: usize| -> Vec<MigrationTransferId> {
            s.transactions
                .iter()
                .filter(|t| {
                    matches!(t.kind, MigrationTxKind::Preparation { layer: l, .. } if l == layer)
                })
                .map(|t| t.id)
                .collect()
        };

        // Every preparation layer after the first depends on the WHOLE layer before it.
        for layer in 1..layer_count {
            let prev = layer_ids(&state, layer - 1);
            for tx in state.transactions.iter().filter(
                |t| matches!(t.kind, MigrationTxKind::Preparation { layer: l, .. } if l == layer),
            ) {
                assert_eq!(
                    tx.depends_on,
                    prev,
                    "layer {layer} depends on the whole layer {}",
                    layer - 1
                );
            }
        }

        // The state machine broadcasts each preparation layer in order — a layer only once its
        // predecessor has mined — then, once the last layer mines, the transfers.
        let mut state = state;
        // A height past every scheduled broadcast (so each transaction is due, not blocked on the
        // schedule) but within every expiry window (so none is expired and offered for rebuild): the
        // latest scheduled height. This exercises the dependency-ordering walk, not expiry handling.
        let target = state
            .transactions
            .iter()
            .map(|t| t.scheduled_height)
            .max()
            .expect("the committed migration has transactions");
        let mut height = 2_000_000u32;
        for layer in 0..layer_count {
            let ids = layer_ids(&state, layer);
            match state.next_step(target, &[]) {
                crate::state::AdvanceStep::Prove { id, .. }
                | crate::state::AdvanceStep::Broadcast { id } => assert!(
                    ids.contains(&id),
                    "layer {layer} is proved or broadcast once its predecessor has mined"
                ),
                other => panic!("expected a layer-{layer} broadcast, got {other:?}"),
            }
            // The others stay BLOCKED: every LATER preparation layer still depends (transitively)
            // on a layer that has not mined, so none of them is broadcastable yet.
            for later in (layer + 1)..layer_count {
                for later_id in layer_ids(&state, later) {
                    let deps = state
                        .transactions
                        .iter()
                        .find(|t| t.id == later_id)
                        .expect("a stored preparation transaction")
                        .depends_on
                        .clone();
                    assert!(
                        !state.deps_mined(&deps),
                        "layer {later} must not be broadcastable before layer {layer} mines"
                    );
                }
            }
            height += 10;
            for id in &ids {
                state.mark_mined(
                    *id,
                    TxId::from_bytes([0; 32]),
                    BlockHeight::from_u32(height),
                );
            }
        }
        match state.next_step(target, &[]) {
            crate::state::AdvanceStep::Prove { id, .. }
            | crate::state::AdvanceStep::Broadcast { id } => {
                let tx = state.transactions.iter().find(|t| t.id == id).unwrap();
                assert!(
                    matches!(tx.kind, MigrationTxKind::Transfer { .. }),
                    "the transfers broadcast after the last preparation layer mines"
                );
            }
            other => panic!("expected a transfer broadcast, got {other:?}"),
        }
    }

    /// The EXTERNAL path builds the whole migration unsigned in the same one pass, and the
    /// unsigned transactions split into signing sessions bounded by the device's action budget —
    /// consecutive topological prefixes, never gated on mining.
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
        assert_eq!(unsigned.len(), state.transactions.len());
        for tx in &state.transactions {
            assert_eq!(tx.state, MigrationTxState::AwaitingSignature);
        }

        // Rounds are consecutive prefixes bounded by the action budget; a preparation is
        // PREP_TX_ACTIONS actions, so a budget of one preparation plus one transfer splits the
        // list without ever exceeding the budget (every round is non-empty and within budget).
        let budget_actions = PREP_TX_ACTIONS
            + crate::denomination::SOURCE_ACTIONS_PER_TRANSFER
            + crate::denomination::DESTINATION_ACTIONS_PER_TRANSFER;
        let budget = crate::signing_rounds::SigningRoundBudget::new(
            core::num::NonZeroU32::new(budget_actions as u32).unwrap(),
        );
        let total = unsigned.len();
        let sessions = batch_unsigned_by_action_budget(unsigned, budget);
        assert!(sessions.len() > 1, "several rounds: {}", sessions.len());
        assert_eq!(sessions.iter().map(|s| s.len()).sum::<usize>(), total);
        for session in &sessions {
            assert!(!session.is_empty());
            assert!(session.iter().map(|tx| tx.actions()).sum::<usize>() <= budget_actions);
        }

        // Sign every session out of band and apply the signatures back; the whole migration is
        // then Signed without anything having been broadcast or mined.
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
        for tx in &state.transactions {
            assert_eq!(tx.state, MigrationTxState::Signed);
        }
    }

    /// The plan exposes its transactions and signing rounds as a QUERY (no re-planning): the
    /// enumerated `PlannedTx` ids match the ids the build assigns, `signing_rounds(budget)` is a
    /// valid partition within the budget, and `group_unsigned` buckets the built PCZTs into that
    /// same grouping.
    #[test]
    fn plan_exposes_signing_rounds_and_groups_unsigned() {
        let seed = 23u64;
        let (mut backend, plan) = single_note_setup(seed, 78 * COIN);
        let params = regtest_network(true);

        let mut rng = ChaCha8Rng::seed_from_u64(seed + 1);
        let (_state, unsigned) = build_preparation_unsigned(
            &params,
            BlockHeight::from_u32(TARGET_HEIGHT),
            &mut backend,
            &plan,
            &mut rng,
            ReplanThreshold::DEFAULT,
        )
        .expect("builds the migration unsigned");

        // The planned enumeration matches the built transactions one-for-one, in id order.
        let planned = plan.planned_transactions();
        assert_eq!(planned.len(), plan.total_transactions());
        assert_eq!(planned.len(), unsigned.len());
        let planned_ids: Vec<u32> = planned.iter().map(|t| u32::from(t.id())).collect();
        let mut built_ids: Vec<u32> = unsigned.iter().map(|u| u32::from(u.id())).collect();
        built_ids.sort_unstable();
        assert_eq!(planned_ids, (0..planned.len() as u32).collect::<Vec<_>>());
        assert_eq!(built_ids, planned_ids);

        // A tight budget (one preparation + one transfer) forces several rounds.
        let budget = SigningRoundBudget::new(
            NonZeroU32::new(
                crate::preparation::PREP_TX_ACTIONS as u32
                    + crate::signing_rounds::TRANSFER_ACTIONS,
            )
            .unwrap(),
        );
        let rounds = plan.signing_rounds(budget);
        assert_eq!(rounds.len(), plan.signing_round_count(budget));

        // The rounds are a valid partition of every planned transaction, within the budget.
        let mut round_ids: Vec<u32> = rounds
            .iter()
            .flat_map(|r| r.transactions().iter().map(|t| u32::from(t.id())))
            .collect();
        round_ids.sort_unstable();
        assert_eq!(round_ids, planned_ids);
        for r in &rounds {
            assert!(!r.is_empty());
            if r.len() > 1 {
                assert!(r.total_actions() <= budget.max_actions());
            }
        }

        // group_unsigned buckets the built PCZTs into the SAME rounds (same ids per round).
        let grouped = plan.group_unsigned(unsigned, budget);
        assert_eq!(grouped.len(), rounds.len());
        for (bucket, round) in grouped.iter().zip(rounds.iter()) {
            let bucket_ids: Vec<u32> = bucket.iter().map(|u| u32::from(u.id())).collect();
            let round_ids: Vec<u32> = round
                .transactions()
                .iter()
                .map(|t| u32::from(t.id()))
                .collect();
            assert_eq!(
                bucket_ids, round_ids,
                "each unsigned round matches the planned round"
            );
            assert!(
                bucket.iter().map(|u| u.actions()).sum::<usize>() <= budget.max_actions() as usize
            );
        }
    }

    /// A committed migration must be resumed, never rebuilt over: a second commit while the
    /// stored migration is non-terminal is refused (its pre-signed transactions may already be
    /// broadcast, and a rebuilt migration would double-spend the same notes); a terminal
    /// (failed/cancelled) migration may be replaced.
    #[test]
    fn commit_preparation_refuses_to_overwrite_a_live_migration() {
        let seed = 13u64;
        let (mut backend, plan) = single_note_setup(seed, 78 * COIN);
        let params = regtest_network(true);

        let mut rng = ChaCha8Rng::seed_from_u64(seed + 1);
        commit_preparation(
            &params,
            BlockHeight::from_u32(TARGET_HEIGHT),
            &mut backend,
            &plan,
            &mut rng,
            ReplanThreshold::DEFAULT,
        )
        .expect("commits the migration");

        let mut rng = ChaCha8Rng::seed_from_u64(seed + 2);
        assert!(matches!(
            commit_preparation(
                &params,
                BlockHeight::from_u32(TARGET_HEIGHT),
                &mut backend,
                &plan,
                &mut rng,
                ReplanThreshold::DEFAULT,
            ),
            Err(CommitError::MigrationInProgress)
        ));

        // A terminal (cancelled) migration may be replaced.
        let mut stored = backend.get_migration().unwrap().expect("stored");
        stored.status = MigrationStatus::Failed;
        backend.replace_migration(&stored).unwrap();
        let mut rng = ChaCha8Rng::seed_from_u64(seed + 3);
        commit_preparation(
            &params,
            BlockHeight::from_u32(TARGET_HEIGHT),
            &mut backend,
            &plan,
            &mut rng,
            ReplanThreshold::DEFAULT,
        )
        .expect("replaces a terminal migration");
    }

    /// A wallet note is resolved by its index into the CURRENT spendable set; if that set
    /// changed since planning (the value at the planned index no longer matches), the commit
    /// reports a stale plan instead of building against the wrong note.
    #[test]
    fn commit_preparation_detects_a_stale_plan() {
        let seed = 17u64;
        let (_, plan) = single_note_setup(seed, 78 * COIN);

        // The spendable set shifted between planning and commit: the note at index 0 now has a
        // different value than the plan recorded.
        let mut backend = CommitMock::new(seed, &[78 * COIN + COIN]);
        let mut rng = ChaCha8Rng::seed_from_u64(seed + 1);
        assert!(matches!(
            commit_preparation(
                &regtest_network(true),
                BlockHeight::from_u32(TARGET_HEIGHT),
                &mut backend,
                &plan,
                &mut rng,
                ReplanThreshold::DEFAULT,
            ),
            Err(CommitError::StalePlan)
        ));
    }

    /// Proving a due transfer consults the anchor boundary the schedule DREW and persisted on the
    /// transaction (not the tip), moving it `Signed -> Proved`. This exercises the engine
    /// orchestration of [`prove_transfer`]: it reads the persisted `anchor_boundary`, hands it to
    /// the crypto backend (here the in-memory mock stands in for the real prover), stores the
    /// returned PCZT, and advances the state. It also checks the guards: a preparation transaction
    /// is not a transfer, and an already-proved transfer is not re-proved.
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
            ReplanThreshold::DEFAULT,
        )
        .expect("commits the migration");

        // Every transfer is Signed and carries a drawn anchor boundary after commit.
        let transfer_id = state
            .transactions
            .iter()
            .find(|t| matches!(t.kind, MigrationTxKind::Transfer { .. }))
            .map(|t| {
                assert!(
                    t.anchor_boundary.is_some(),
                    "a transfer carries the boundary its schedule drew"
                );
                assert!(matches!(t.state, MigrationTxState::Signed));
                t.id
            })
            .expect("a committed migration has transfers");

        // Proving reads the persisted boundary, proves, and advances Signed -> Proved.
        assert_eq!(
            prove_transfer(&mut backend, &mut state, transfer_id).expect("proves the due transfer"),
            ProveOutcome::Proved
        );
        let proved = state
            .transactions
            .iter()
            .find(|t| t.id == transfer_id)
            .expect("the transfer is still present");
        assert!(
            matches!(proved.state, MigrationTxState::Proved),
            "the transfer is proved"
        );

        // An already-proved transfer is not re-proved.
        assert!(matches!(
            prove_transfer(&mut backend, &mut state, transfer_id),
            Err(ProveError::NotReady(_))
        ));

        // A preparation transaction is not a transfer: it anchors to its dependencies, not a drawn
        // boundary, so it is rejected rather than proved.
        let prep_id = state
            .transactions
            .iter()
            .find(|t| matches!(t.kind, MigrationTxKind::Preparation { .. }))
            .expect("a committed migration has preparation transactions")
            .id;
        assert!(matches!(
            prove_transfer(&mut backend, &mut state, prep_id),
            Err(ProveError::NotATransfer(_))
        ));
    }

    /// A committed migration records the anchor bucket grid it was scheduled against, and both the
    /// proving and rebuild paths refuse to act once the backend's grid has moved.
    ///
    /// Without this, a wallet reconfigured mid-migration would stop retaining the boundaries its
    /// transfers anchored to; the failure would only appear much later, as an unexplained missing
    /// checkpoint at witness-resolution time.
    #[test]
    fn a_changed_anchor_grid_is_rejected_rather_than_left_unprovable() {
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
            ReplanThreshold::DEFAULT,
        )
        .expect("commits the migration");

        // The grid the backend was committed under is recorded on the state.
        let committed = AnchorBucketInterval::ZIP_318;
        assert_eq!(state.anchor_bucket_interval(), committed);

        // Reconfigure the backend onto a different grid, as an application would by changing its
        // wallet's anchor retention interval.
        let moved = AnchorBucketInterval::custom(NonZeroU32::new(12).expect("nonzero"));
        backend.sched_params = SchedulingParams::new(
            moved,
            SchedulingParams::ZIP_318.transfer_delay(),
            SchedulingParams::ZIP_318.preparation_delay(),
        );

        let transfer_id = state
            .transactions
            .iter()
            .find(|t| matches!(t.kind, MigrationTxKind::Transfer { .. }))
            .expect("a committed migration has transfers")
            .id;

        // Proving reports the mismatch instead of resolving a boundary the wallet no longer retains.
        assert!(matches!(
            prove_transfer(&mut backend, &mut state, transfer_id),
            Err(ProveError::AnchorIntervalMismatch {
                committed: c,
                configured: g,
            }) if c == committed && g == moved
        ));

        // Rebuilding is rejected too, ahead of any per-transfer condition: a fresh anchor would
        // come from the new grid while the siblings' remain on the old one, so the whole migration
        // is invalid rather than this transfer being repairable.
        let mut rng = ChaCha8Rng::seed_from_u64(seed + 2);
        assert!(matches!(
            rebuild_expired_transfer(&params, &backend, &mut state, transfer_id, &mut rng),
            Err(RebuildError::AnchorIntervalMismatch {
                committed: c,
                configured: g,
            }) if c == committed && g == moved
        ));

        // Restoring the committed grid makes the migration provable again.
        backend.sched_params = SchedulingParams::ZIP_318;
        assert_eq!(
            prove_transfer(&mut backend, &mut state, transfer_id)
                .expect("the transfer proves once the grid matches again"),
            ProveOutcome::Proved
        );
    }

    /// The `FailingProver`'s "anything else went wrong" error, which the engine must pass through
    /// untouched.
    #[derive(Debug, PartialEq, Eq)]
    struct MockProveError;

    impl fmt::Display for MockProveError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("the mock prover failed")
        }
    }

    /// A prover that never proves, standing in for one whose wallet cannot locate a spend's note:
    /// it reports [`ProveFailure::InputNotAvailable`] for the configured nullifier and backing
    /// height, or [`ProveFailure::Other`] when none is configured. It answers the anchor-grid
    /// question with the grid these tests commit under, so a transfer reaches the prove call rather
    /// than being turned back by the grid guard.
    struct FailingProver {
        input_not_available: Option<([u8; 32], BlockHeight)>,
    }

    impl FailingProver {
        fn input_not_available(nullifier: [u8; 32], as_of: u32) -> Self {
            FailingProver {
                input_not_available: Some((nullifier, BlockHeight::from_u32(as_of))),
            }
        }

        fn other() -> Self {
            FailingProver {
                input_not_available: None,
            }
        }

        fn failure(&self) -> ProveFailure<MockProveError> {
            match self.input_not_available {
                Some((nullifier, as_of)) => ProveFailure::InputNotAvailable { nullifier, as_of },
                None => ProveFailure::Other(MockProveError),
            }
        }
    }

    impl MigrationProver for FailingProver {
        type Error = MockProveError;

        fn prove_transfer(
            &mut self,
            _pczt: pczt::Pczt,
            _anchor_boundary: BlockHeight,
        ) -> Result<pczt::Pczt, ProveFailure<Self::Error>> {
            Err(self.failure())
        }

        fn prove_preparation(
            &mut self,
            _pczt: pczt::Pczt,
            _anchor: BlockHeight,
        ) -> Result<pczt::Pczt, ProveFailure<Self::Error>> {
            Err(self.failure())
        }

        fn anchor_bucket_interval(&self) -> crate::scheduling::AnchorBucketInterval {
            crate::scheduling::SchedulingParams::ZIP_318.anchor_bucket_interval()
        }
    }

    /// A freshly committed migration over one wallet note: its state, one layer-0 preparation
    /// transaction (which depends on nothing), and the transfers that preparation funds.
    fn committed_for_prove_failures() -> (
        MigrationState,
        MigrationTransferId,
        Vec<MigrationTransferId>,
    ) {
        let seed = 7u64;
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

        let prep_id = state
            .transactions
            .iter()
            .find(|t| matches!(t.kind, MigrationTxKind::Preparation { .. }))
            .expect("a committed migration has preparation transactions")
            .id;
        assert!(
            state
                .transactions
                .iter()
                .all(|t| t.depends_on.is_empty() || t.depends_on == vec![prep_id]),
            "this fixture has a single preparation layer, so every dependent waits on it alone"
        );
        let transfer_ids: Vec<MigrationTransferId> = state
            .transactions
            .iter()
            .filter(|t| matches!(t.kind, MigrationTxKind::Transfer { .. }))
            .map(|t| t.id)
            .collect();
        assert!(!transfer_ids.is_empty());
        (state, prep_id, transfer_ids)
    }

    fn stamp(state: &MigrationState, id: MigrationTransferId) -> Option<BlockHeight> {
        state
            .transactions
            .iter()
            .find(|t| t.id == id)
            .expect("the transaction is present")
            .unsatisfiable_at()
    }

    /// A prover reporting an input ABSENT from the unspent set, with every dependency's mined
    /// height inside the wallet's scan, is positive evidence that the input was spent: the engine
    /// records it through the ordinary satisfiability mutator instead of surfacing an error, so
    /// the transaction is marked at the observation's height and the dependency closure strands
    /// its dependents at the same stamp. A layer-0 preparation depends on nothing, which is
    /// coverage vacuously: the notes it spends were spendable when the migration was committed.
    #[test]
    fn prove_input_not_available_with_deps_covered_marks_unsatisfiable() {
        let (mut state, prep_id, transfer_ids) = committed_for_prove_failures();
        let nullifier = state
            .transactions
            .iter()
            .find(|t| t.id == prep_id)
            .expect("the preparation is present")
            .spend_nullifiers[0];
        const AS_OF: u32 = 1_500_000;

        let mut prover = FailingProver::input_not_available(nullifier, AS_OF);
        let outcome = prove_preparation(
            &mut prover,
            &mut state,
            prep_id,
            BlockHeight::from_u32(AS_OF),
        )
        .expect("an unavailable input is handled, not surfaced as an error");

        let ProveOutcome::MarkedUnsatisfiable { replan_required } = outcome else {
            panic!("expected the observation to be recorded, got {outcome:?}");
        };
        // The payload is the derived accessor's value AFTER marking, so a caller can act on it
        // without re-consulting the state.
        assert_eq!(replan_required, state.replan_required());
        assert!(
            replan_required,
            "the whole migration's transfer value is stranded behind the one preparation"
        );
        assert_eq!(stamp(&state, prep_id), Some(BlockHeight::from_u32(AS_OF)));
        for id in transfer_ids {
            assert_eq!(
                stamp(&state, id),
                Some(BlockHeight::from_u32(AS_OF)),
                "the closure strands every transfer the dead preparation funds"
            );
        }
        // The preparation kept its lifecycle state: unsatisfiability is orthogonal to it, and no
        // proof was produced.
        assert!(matches!(
            state
                .transactions
                .iter()
                .find(|t| t.id == prep_id)
                .expect("the preparation is present")
                .state,
            MigrationTxState::Signed
        ));
    }

    /// With a dependency mined ABOVE the height the observation rests on, the input's absence is
    /// equally consistent with a note the wallet has not scanned yet: nothing is concluded and
    /// nothing is marked. One block further of scan — the dependency's mined height exactly — and
    /// the same observation becomes conclusive, which pins the coverage comparison at its
    /// boundary.
    #[test]
    fn prove_input_not_available_with_a_dep_above_as_of_concludes_nothing() {
        let (mut state, prep_id, transfer_ids) = committed_for_prove_failures();
        let transfer_id = transfer_ids[0];
        let nullifier = state
            .transactions
            .iter()
            .find(|t| t.id == transfer_id)
            .expect("the transfer is present")
            .spend_nullifiers[0];
        const MINED: u32 = 1_500_000;
        state.mark_mined(
            prep_id,
            TxId::from_bytes([3; 32]),
            BlockHeight::from_u32(MINED),
        );

        let mut prover = FailingProver::input_not_available(nullifier, MINED - 1);
        assert_eq!(
            prove_transfer(&mut prover, &mut state, transfer_id)
                .expect("an unavailable input is handled, not surfaced as an error"),
            ProveOutcome::NotYetProvable
        );
        assert_eq!(stamp(&state, transfer_id), None, "nothing is marked");
        assert_eq!(stamp(&state, prep_id), None);

        // Scanned exactly as far as the dependency's mined height, the input was necessarily
        // scanned, so its absence is conclusive.
        let mut prover = FailingProver::input_not_available(nullifier, MINED);
        assert!(matches!(
            prove_transfer(&mut prover, &mut state, transfer_id)
                .expect("an unavailable input is handled, not surfaced as an error"),
            ProveOutcome::MarkedUnsatisfiable { .. }
        ));
        assert_eq!(
            stamp(&state, transfer_id),
            Some(BlockHeight::from_u32(MINED))
        );
    }

    /// An UNMINED dependency means the drive layer offered this transaction before its inputs
    /// could exist: the absence says nothing about a spend, so it is read conservatively as a
    /// retry rather than as evidence.
    #[test]
    fn prove_input_not_available_with_an_unmined_dep_concludes_nothing() {
        let (mut state, prep_id, transfer_ids) = committed_for_prove_failures();
        let transfer_id = transfer_ids[0];

        let mut prover = FailingProver::input_not_available([9; 32], 1_500_000);
        assert_eq!(
            prove_transfer(&mut prover, &mut state, transfer_id)
                .expect("an unavailable input is handled, not surfaced as an error"),
            ProveOutcome::NotYetProvable
        );
        assert_eq!(stamp(&state, transfer_id), None);
        assert_eq!(stamp(&state, prep_id), None);
    }

    /// Every other prover failure is still an error, carried through untouched: only the one
    /// condition the engine can interpret is handled.
    #[test]
    fn prove_other_prover_failures_still_surface_as_errors() {
        let (mut state, prep_id, transfer_ids) = committed_for_prove_failures();
        let transfer_id = transfer_ids[0];

        let mut prover = FailingProver::other();
        assert!(matches!(
            prove_transfer(&mut prover, &mut state, transfer_id),
            Err(ProveError::Prover(MockProveError))
        ));
        assert!(matches!(
            prove_preparation(
                &mut prover,
                &mut state,
                prep_id,
                BlockHeight::from_u32(TARGET_HEIGHT)
            ),
            Err(ProveError::Prover(MockProveError))
        ));
        assert_eq!(stamp(&state, transfer_id), None);
        assert_eq!(stamp(&state, prep_id), None);
    }
}
