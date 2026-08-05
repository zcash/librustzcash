//! Migration state logic: the pure, backend-agnostic decisions that advance a committed migration
//! and render its progress.
//!
//! These are methods on [`MigrationState`] that operate only on the persisted state and never touch a
//! wallet, a prover, or the network, so every consumer (a mobile wallet using these crates directly,
//! or a server like Zallet) makes the SAME decisions from the SAME state. The consumer supplies the
//! I/O: it detects that a broadcast transaction has mined (via its own chain view) and calls
//! [`MigrationState::mark_mined`], it broadcasts a transaction and calls
//! [`MigrationState::mark_broadcast`], and it performs the build/prove/broadcast work that
//! [`advance_migration`](crate::satisfiability::advance_migration) — the drive API, which puts each
//! planned step to the store's satisfiability oracle before surfacing it — tells it to do. The
//! decision of WHAT to do next, and the transaction status a wallet shows the user, live here.
//!
//! Every transaction is built and pre-signed when the migration is committed (one signing phase;
//! anchors and witnesses are deferred to proving time per ZIP 374), so the state machine's only
//! job is to ORDER the remaining work: a transaction is proved — installing its anchor and
//! witnesses — once its anchor is resolvable (for a transfer, once its drawn boundary settles),
//! and becomes broadcastable once it is proved, its dependencies (the preparation layers that
//! mint its inputs) have mined, and its scheduled height has arrived. See
//! [`advance_migration`](crate::satisfiability::advance_migration) for what each step asks of the
//! consumer and the sync/broadcast session separation the ordering is designed around.

use alloc::collections::BTreeSet;
use alloc::vec::Vec;

use getset::{CopyGetters, Getters};
use rand_core::{CryptoRng, RngCore};
use zcash_protocol::TxId;
use zcash_protocol::consensus::BlockHeight;

use crate::engine::{
    MigrationState, MigrationStatus, MigrationTransaction, MigrationTransferId, MigrationTxKind,
    MigrationTxState,
};
use crate::satisfiability::{DuenessTargets, StepSatisfiability, UnsatisfiableKind};
use crate::scheduling::{self, SyncWakeup, WakeupParams, WakeupScheduleError};

/// The next thing to do to advance a committed migration, decided purely from its state. The consumer
/// performs the corresponding I/O and updates the state (via the commit functions and
/// [`MigrationState::mark_broadcast`] / [`MigrationState::mark_mined`]), then calls
/// [`advance_migration`](crate::satisfiability::advance_migration) again, which documents the work each
/// step names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AdvanceStep {
    /// Prove EVERY one of these pre-signed transactions (install each one's deferred Orchard
    /// anchor and spend witnesses and store the proof through the store's
    /// `PoolMigrationWrite::store_proved_transaction`, one transaction at a time), WITHOUT
    /// broadcasting: each has its dependencies mined and, for a transfer, its drawn anchor
    /// boundary settled (the boundary block sits at least
    /// [`PROVABLE_ANCHOR_DEPTH`](crate::scheduling::PROVABLE_ANCHOR_DEPTH) blocks below the
    /// scanned chain tip, so the checkpoint proved against exists in the wallet's commitment
    /// tree and is reorg-stable).
    ///
    /// The step carries the WHOLE provable set rather than one candidate, because proving —
    /// unlike broadcasting — has no privacy implications to space out: it emits nothing a
    /// network observer can see, so there is no reason to leave provable work on the table when
    /// a synced session is already open, and a wallet that proves everything offered here needs
    /// no further sync wake-up for transfers whose boundaries have already settled. Broadcast
    /// remains a separate later step, surfaced one transaction at a time on the privacy
    /// schedule.
    ///
    /// The set orders earliest-ready first (a transfer by its anchor boundary, a due
    /// preparation by its scheduled height, ties by id) and can MIX the two kinds: a due
    /// preparation — provable only once its broadcast schedule is due, and ready to broadcast
    /// the moment it is proved — may sit alongside transfers whose settled boundaries make them
    /// provable well before their broadcast windows. Each entry is a [`ProveTarget`], carrying
    /// the transaction's [`kind`](ProveTarget::kind) beside its id so the consumer can act on
    /// the distinction — which engine call proves it, and whether its broadcast follows
    /// immediately — without a lookup; the outlook returned alongside this step
    /// ([`Advance::next`](crate::satisfiability::Advance::next)) says what the session holds
    /// once the proofs land — a due preparation's own broadcast, or nothing until a later
    /// window.
    ///
    /// Proving is not time-critical: the wallet durably retains the boundary checkpoints its
    /// committed transfers anchor to (they are exempt from ordinary checkpoint pruning; see
    /// [`MigrationBackend::scheduling_params`](crate::engine::MigrationBackend::scheduling_params)),
    /// so a transfer remains provable from the moment its boundary settles until it is broadcast.
    /// Proving EARLY — at a sync wake-up well before the broadcast height — is what keeps the
    /// sync-heavy work out of the broadcast session.
    Prove {
        /// The transactions to prove, earliest-ready first; never empty, and each id distinct.
        transactions: Vec<ProveTarget>,
    },
    /// Broadcast this already-proven transaction: it is `Proved`, its dependencies are mined, and its
    /// scheduled broadcast height has arrived.
    Broadcast {
        /// The transaction to broadcast.
        id: MigrationTransferId,
    },
    /// Rebuild this TRANSFER: its [`expiry_height`](MigrationTransaction::expiry_height) has passed
    /// without it mining, so it can no longer be included in a block (ZIP 203). The pre-signed
    /// artifact is dead — the signature hash covers the expiry height, so no part of it can be
    /// reused — and an entirely new transaction must be constructed and SIGNED ANEW with a fresh
    /// anchor and expiry, its denomination unchanged. Unlike proving and broadcasting (which need
    /// only the viewing key, the commitment tree, and the network), acting on this step needs the
    /// account's SPEND AUTHORITY: in-process where the wallet holds it, or a new external signing
    /// session for a hardware or offline signer.
    ///
    /// Only a transfer is surfaced: it is a leaf of the dependency graph, so it can be rebuilt on
    /// its own. An expired PREPARATION is reported via [`Blocker::Expired`] but never as this step
    /// (see [`MigrationState::expired_transactions`]). A migration is never stuck silently on an
    /// expired transfer: this step is returned in preference to [`Waiting`](Self::Waiting) whenever
    /// one is holding up the schedule.
    Rebuild {
        /// The transaction to rebuild.
        id: MigrationTransferId,
    },
    /// The migration needs RE-PLANNING: enough of its planned value can never mine (the share
    /// strictly exceeds the committed [`ReplanThreshold`](crate::satisfiability::ReplanThreshold)), or
    /// dead value is stranded with no live work left. The consumer's response:
    /// [`MigrationState::mark_superseded`], persist, and re-plan the remaining balance through
    /// the ordinary planning flow — whose commit guard accepts the replacement, the superseded
    /// migration being terminal. Named `Replan` (not "rebuild") because [`Self::Rebuild`] already
    /// means the per-transfer expired rebuild, and this step's remedy is re-planning, never
    /// re-signing the same notes.
    Replan,
    /// A broadcast this application attempted was REJECTED by the node it submitted to (recorded
    /// with [`MigrationState::report_broadcast_failure`]), and the wallet cannot yet say why: its
    /// answers still rest on chain state below the tip that node reported. The consumer's
    /// response is to SYNC — at its next sync wake-up, to at least that tip — and call
    /// [`advance_migration`](crate::satisfiability::advance_migration) again, which adjudicates the
    /// report against the store's oracle and either marks the transaction or re-offers its
    /// broadcast.
    ///
    /// Nothing else is offered while a report stands: this step outranks every other but
    /// [`Complete`](Self::Complete). A rejection means some OTHER observer saw chain state this
    /// wallet has not, and same-seed activity invalidates the whole store view rather than one
    /// transaction's answer, so proceeding on the rest of the plan would act on a view already
    /// known to be stale. Only the drive API returns this; the planning kernel, which has no
    /// oracle to adjudicate against, never does.
    Reevaluate,
    /// Nothing to do now: waiting for one or more transactions to mine, for an anchor boundary to
    /// settle, or for a scheduled height to arrive.
    Waiting,
    /// Nothing will ever be actionable again: every transaction is mined, or the migration has
    /// reached a terminal status (complete, failed/cancelled, or superseded by a re-plan — see
    /// [`MigrationState::is_terminal`]), so a driver can stop polling it.
    Complete,
}

/// One transaction of a [`Prove`](AdvanceStep::Prove) batch: the transaction to prove, with the
/// [`kind`](Self::kind) that decides how the consumer acts on it. The kind rides along so no
/// lookup stands between the step and that decision: it selects the engine call
/// ([`prove_preparation`](crate::engine::prove_preparation) against a fresh checkpoint at the
/// tip, or [`prove_transfer`](crate::engine::prove_transfer) against the drawn boundary), and it
/// carries the session handling — a PREPARATION is provable only once its broadcast schedule is
/// due, so it is by construction ready to broadcast the moment it is proved, while a TRANSFER's
/// broadcast waits for its own later session.
#[derive(Clone, Copy, Debug, PartialEq, Eq, CopyGetters)]
pub struct ProveTarget {
    /// The transaction to prove.
    #[getset(get_copy = "pub")]
    pub(crate) id: MigrationTransferId,
    /// What the transaction is: the preparation/transfer distinction described on the type.
    #[getset(get_copy = "pub")]
    pub(crate) kind: MigrationTxKind,
}

/// The kind of work an [`AdvanceStep`] names, shorn of the step's payload: the discriminant a
/// consumer schedules wake-ups and renders progress by, obtained through [`AdvanceStep::kind`].
/// The drive API's outlook ([`Advance`](crate::satisfiability::Advance)) pairs one of these with
/// the earliest target height at which a step of that kind becomes serviceable — the kind alone,
/// because the outlook is advisory: WHICH transaction the step names is decided by the
/// [`advance_migration`](crate::satisfiability::advance_migration) call that actually serves it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StepKind {
    /// An [`AdvanceStep::Prove`].
    Prove,
    /// An [`AdvanceStep::Broadcast`].
    Broadcast,
    /// An [`AdvanceStep::Rebuild`].
    Rebuild,
    /// An [`AdvanceStep::Replan`].
    Replan,
    /// An [`AdvanceStep::Reevaluate`].
    Reevaluate,
    /// An [`AdvanceStep::Waiting`].
    Waiting,
    /// An [`AdvanceStep::Complete`].
    Complete,
}

impl AdvanceStep {
    /// This step's [`StepKind`]: the variant without its payload.
    pub const fn kind(&self) -> StepKind {
        match self {
            AdvanceStep::Prove { .. } => StepKind::Prove,
            AdvanceStep::Broadcast { .. } => StepKind::Broadcast,
            AdvanceStep::Rebuild { .. } => StepKind::Rebuild,
            AdvanceStep::Replan => StepKind::Replan,
            AdvanceStep::Reevaluate => StepKind::Reevaluate,
            AdvanceStep::Waiting => StepKind::Waiting,
            AdvanceStep::Complete => StepKind::Complete,
        }
    }
}

/// The action a wallet takes next on a ready migration transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NextAction {
    /// Prove this pre-signed transaction now (install its deferred anchor and witnesses and store the
    /// proven PCZT): its dependencies are mined and, for a transfer, its anchor boundary has
    /// settled. It is not broadcast yet.
    Prove,
    /// Broadcast this already-proven transaction now: it is `Proved` and its scheduled broadcast
    /// height has arrived.
    Broadcast,
}

/// Why a migration transaction is not yet actionable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Blocker {
    /// Waiting for its dependency transactions (the earlier preparation layer that mints its input
    /// notes, or for a transfer, the preparation transaction that mints its funding note) to mine,
    /// so those notes exist in the commitment tree and their spends can be witnessed. Every
    /// transaction is already pre-signed (witnesses are deferred to proving time per ZIP 374);
    /// mining its dependencies is all a later layer waits for before it can be proved and
    /// broadcast.
    Dependencies,
    /// Built and due only at a later height (the privacy broadcast schedule): waiting for the chain tip
    /// to reach its scheduled height.
    Schedule,
    /// A transfer whose drawn anchor boundary has not yet settled: waiting for the chain tip to move
    /// strictly past the boundary block, so the boundary checkpoint exists and the transfer can be
    /// proved against it.
    AnchorBoundary,
    /// Built but awaiting an EXTERNAL signature: its unsigned PCZT was exported to a hardware or offline
    /// signer, and this transaction cannot advance until
    /// [`MigrationState::apply_signature`](MigrationState::apply_signature) stores the signed PCZT
    /// returned by the device.
    Signature,
    /// Its [`expiry_height`](MigrationTransaction::expiry_height) lies in the DOOMED WINDOW: at or
    /// above the caller's scanned target and below its effective one ([`DuenessTargets`]). Nothing
    /// has determined that this transaction lapsed — the wallet has not scanned far enough to see
    /// it either way — but submitting it would very likely be refused by the node, and proving it
    /// would very likely be wasted work, so the kernel WITHHOLDS it from the broadcast and prove
    /// queues.
    ///
    /// Reported behind [`Expired`](Self::Expired), which is the same fact once the wallet can
    /// actually observe it, and the two are disjoint by construction. Purely protective: nothing
    /// is recorded and no artifact is discarded, so a transaction reported this way either becomes
    /// `Expired` (and rebuildable) or returns to the ordinary queues as the wallet's scan reaches
    /// the expiry height. Neither `ready` nor carrying an action, exactly as the kernel withholds
    /// it — the agreement a consumer's `ready && action == Broadcast` sync gate rests on.
    ExpiryImminent,
    /// Its [`expiry_height`](MigrationTransaction::expiry_height) has passed without it mining, so it
    /// can no longer be included in a block (ZIP 203): the pre-signed artifact is dead, and an
    /// entirely new transaction must be constructed and signed anew (with a fresh anchor and
    /// expiry, its denomination unchanged) before this part can advance. For a TRANSFER the
    /// consumer performs that rebuild when
    /// [`advance_migration`](crate::satisfiability::advance_migration) returns [`AdvanceStep::Rebuild`].
    /// For a PREPARATION no single-transaction rebuild exists (its dependents' pre-signatures
    /// commit to the notes it would have minted), so this blocker is the signal that the migration
    /// needs a new signing ceremony over the affected subtree. Reported so a wallet can show the
    /// transaction as needing attention rather than as merely waiting.
    ///
    /// A DETERMINATION, so it is judged only against chain data the wallet holds
    /// ([`DuenessTargets::scanned`]); an expiry the caller's ESTIMATE has passed but its scan has
    /// not reports [`ExpiryImminent`](Self::ExpiryImminent) instead.
    Expired,
    /// A broadcast of this transaction was rejected by the node it was submitted to
    /// ([`MigrationState::report_broadcast_failure`]), and the wallet has not yet scanned far
    /// enough to say why: it is withheld from the broadcast queue until
    /// [`advance_migration`](crate::satisfiability::advance_migration) adjudicates the report against
    /// evidence (see [`AdvanceStep::Reevaluate`]).
    ///
    /// Reported BEHIND [`Unsatisfiable`](Self::Unsatisfiable) — a determination the wallet has
    /// made outranks a question it has not yet answered — and AHEAD of
    /// [`Expired`](Self::Expired), [`ExpiryImminent`](Self::ExpiryImminent), and the
    /// state-derived blockers, every one of which describes a transaction whose broadcast is
    /// merely pending or lapsing; this one is being actively withheld on another observer's
    /// testimony, which is the more specific thing to show. Transient by construction: the next
    /// drive call at a sufficiently synced wallet replaces it with a mark, or with nothing.
    AwaitingReevaluation,
    /// Determined unsatisfiable: its inputs can never again all exist unspent on chain, directly
    /// observed ([`unsatisfiable_at`](MigrationTransaction::unsatisfiable_at)) or inherited from a
    /// dead dependency. Resolved only by the migration-level replan ([`AdvanceStep::Replan`]);
    /// reported ahead of [`Expired`](Self::Expired) because expiry's remedy — a rebuild — cannot
    /// cure missing inputs. Expiry alone never reports this, though it seeds the kernel's dead
    /// set: an expired but otherwise-live transaction reports `Expired`, its rebuild remedy
    /// intact.
    Unsatisfiable,
}

/// The status of one migration transaction, as a wallet renders it and decides the next step. This is
/// the machine-readable view a mobile wallet needs: it wakes intermittently, and may be killed and
/// restarted between wake-ups, so it decides which transaction to prove or broadcast next, and what
/// the rest are waiting on, from this view of the persisted state alone.
#[derive(Clone, Debug, Getters, CopyGetters)]
pub struct TransactionStatus {
    /// This transaction's stable id.
    #[getset(get_copy = "pub")]
    pub(crate) id: MigrationTransferId,
    /// What it does (a preparation transaction, carrying its layer / anchor bucket, or a transfer).
    #[getset(get_copy = "pub")]
    pub(crate) kind: MigrationTxKind,
    /// Its current lifecycle state.
    #[getset(get_copy = "pub")]
    pub(crate) state: MigrationTxState,
    /// The transactions that must be mined before this one can be built or broadcast.
    #[getset(get = "pub")]
    pub(crate) depends_on: Vec<MigrationTransferId>,
    /// The height at or after which it is due to broadcast.
    #[getset(get_copy = "pub")]
    pub(crate) scheduled_height: BlockHeight,
    /// The height after which the transaction can no longer be mined (ZIP 203); `0` means it never
    /// expires. Surfaced so a wallet can show how close a transaction is to expiring, and recognize
    /// the [`Blocker::Expired`] state.
    #[getset(get_copy = "pub")]
    pub(crate) expiry_height: BlockHeight,
    /// Whether the wallet can act on it right now.
    #[getset(get_copy = "pub")]
    pub(crate) ready: bool,
    /// The action available now, when `ready` is true.
    #[getset(get_copy = "pub")]
    pub(crate) action: Option<NextAction>,
    /// Why it is not yet actionable, when it is waiting. An in-flight broadcast row is normally
    /// blocker-free, but reports [`Blocker::Unsatisfiable`] when it can never mine (marked, or
    /// dependent on a dead transaction); a mined row never carries a blocker.
    ///
    /// The precedence, highest first: [`Blocker::Unsatisfiable`] (a determination),
    /// [`Blocker::AwaitingReevaluation`] (a rejected broadcast the wallet cannot yet explain),
    /// [`Blocker::Expired`] (a determination the wallet's own scan supports),
    /// [`Blocker::ExpiryImminent`] (a lapse only the caller's tip estimate believes in, which the
    /// kernel withholds on but never records), then the state-derived blockers.
    #[getset(get_copy = "pub")]
    pub(crate) blocked_on: Option<Blocker>,
    /// WHY it can never mine, populated exactly when [`Blocker::Unsatisfiable`] is reported and
    /// `None` otherwise — the rendering detail behind that blocker.
    ///
    /// For a transaction carrying its own mark this is the stored
    /// [`unsatisfiable_kind`](MigrationTransaction::unsatisfiable_kind). But `Unsatisfiable` is
    /// also reported for an UNMARKED transaction whose direct dependency is merely DERIVED dead —
    /// expired and unmined, a deadness the state machine re-derives at every call and never stores
    /// (see [`MigrationState::record_satisfiability`]) — and there is no stored kind for that
    /// case. It reports [`Inherited`](UnsatisfiableKind::Inherited), which is exactly what it is:
    /// nothing was observed about the transaction itself.
    #[getset(get_copy = "pub")]
    pub(crate) unsatisfiable_kind: Option<UnsatisfiableKind>,
    /// The height it was mined at, once mined.
    #[getset(get_copy = "pub")]
    pub(crate) mined_height: Option<BlockHeight>,
    /// The transaction id (raw internal bytes), from broadcast onward: a transaction keeps the
    /// txid it was broadcast under when it mines, so this stays populated through mining rather
    /// than lapsing at it.
    #[getset(get_copy = "pub")]
    pub(crate) txid: Option<TxId>,
}

impl MigrationState {
    /// Whether every transaction in `depends_on` is mined.
    pub fn deps_mined(&self, depends_on: &[MigrationTransferId]) -> bool {
        depends_on.iter().all(|dep| {
            self.transactions
                .iter()
                .find(|t| t.id == *dep)
                .map(|t| matches!(t.state, MigrationTxState::Mined { .. }))
                .unwrap_or(false)
        })
    }

    /// Whether transaction `t` can no longer be mined at `target_height` (`chain_tip + 1`, the height
    /// of the next block it could be included in) and so must be rebuilt. A transaction may be mined
    /// only in a block whose height is at or below its
    /// [`expiry_height`](MigrationTransaction::expiry_height) (ZIP 203), so it is expired once
    /// `expiry_height < target_height`. An `expiry_height` of `0` disables expiry (the transaction
    /// never expires), and an already-`Mined` transaction is never expired: it was included before its
    /// expiry and is final.
    ///
    /// This is the PRIMITIVE, and deliberately takes a bare height rather than the caller's
    /// [`DuenessTargets`]: which of the two targets expiry is judged at is precisely what
    /// distinguishes a determination from a protective withhold, so that choice belongs to each
    /// call site (where it is stated) and never to this predicate.
    fn is_expired(t: &MigrationTransaction, target_height: BlockHeight) -> bool {
        if matches!(t.state, MigrationTxState::Mined { .. }) {
            return false;
        }
        let expiry = u32::from(t.expiry_height);
        expiry != 0 && expiry < u32::from(target_height)
    }

    /// The ids of every transaction that has expired without mining. This is the detection a wallet
    /// runs on launch to reconcile a schedule whose broadcast windows were missed: each id it
    /// returns is a pre-signed transaction the node would now reject, whose part must be carried by
    /// an entirely new transaction, constructed and signed anew with a fresh anchor and expiry
    /// while keeping its denomination. A TRANSFER here is also surfaced as
    /// [`AdvanceStep::Rebuild`]; a PREPARATION is not (rebuilding it means re-signing its whole
    /// dependent subtree, a remediation beyond a single advance step), so a wallet uses this list
    /// to tell the user the migration needs a new signing ceremony.
    ///
    /// Judged at [`targets.scanned()`](DuenessTargets::scanned): this is a DETERMINATION, whose
    /// remedy is a fresh signing, so it may rest only on chain data the wallet holds. A transfer
    /// whose expiry has probably passed but whose lapse the wallet cannot yet observe is NOT
    /// listed here; it is withheld from the broadcast queue and rendered
    /// [`Blocker::ExpiryImminent`] instead. The pair is taken rather than a bare height so the
    /// caller never picks the field (see [`DuenessTargets`]).
    pub fn expired_transactions(&self, targets: DuenessTargets) -> Vec<MigrationTransferId> {
        self.transactions
            .iter()
            .filter(|t| Self::is_expired(t, targets.scanned()))
            .map(|t| t.id)
            .collect()
    }

    /// The ids of every transaction that can never mine: the marked transactions
    /// ([`MigrationTransaction::unsatisfiable_at`]) and the expired-and-unmined ones (both judged
    /// states are seeds), closed transitively over dependents — pending or in-flight alike, since
    /// a broadcast dependent of a transaction that can never mine can never mine either. Derived on
    /// demand and never stored: durable marks are recorded through a separate mutator
    /// ([`Self::record_satisfiability`]), and applying the same closure at decision time is what
    /// keeps a derivable-but-unrecorded death from ever surfacing as a step.
    ///
    /// Expiry is judged at [`targets.scanned()`](DuenessTargets::scanned), never the estimate.
    /// Membership here is a DEATH: it strands every dependent, it feeds the drain-time
    /// [`Replan`](AdvanceStep::Replan) whose contracted response is terminal, and the same
    /// derivation drives the durable closure in [`Self::record_satisfiability`]. Nothing that
    /// consequential may rest on where the tip has probably reached.
    fn dead_set(&self, targets: DuenessTargets) -> BTreeSet<MigrationTransferId> {
        let mut dead: BTreeSet<MigrationTransferId> = self
            .transactions
            .iter()
            .filter(|t| {
                !matches!(t.state, MigrationTxState::Mined { .. })
                    && (t.unsatisfiable.is_some() || Self::is_expired(t, targets.scanned()))
            })
            .map(|t| t.id)
            .collect();
        // Close over dependents to a fixpoint: each pass adds every unmined transaction with a
        // dead dependency, and the set only grows, so it terminates within `transactions.len()`
        // passes.
        loop {
            let mut grew = false;
            for t in &self.transactions {
                if !matches!(t.state, MigrationTxState::Mined { .. })
                    && !dead.contains(&t.id)
                    && t.depends_on.iter().any(|d| dead.contains(d))
                {
                    dead.insert(t.id);
                    grew = true;
                }
            }
            if !grew {
                break;
            }
        }
        dead
    }

    /// The id of the next TRANSFER that must be rebuilt because it has expired (see
    /// [`Self::is_expired`]). Only a transfer is surfaced: it is a leaf of the dependency graph, so
    /// it can be reconstructed and signed anew on its own. An expired PREPARATION has no
    /// single-transaction remediation — its dependents' pre-signatures commit to the notes it would
    /// have minted, so rebuilding it means re-signing the whole dependent subtree (a follow-on
    /// slice); it stays visible through [`Blocker::Expired`] and [`Self::expired_transactions`].
    ///
    /// `dead` is the dead set [`Self::next_step`] derives ([`Self::dead_set`]) — but expiry alone
    /// never disqualifies a transfer here, even though every expired transfer is a dead-set seed:
    /// rebuilding is exactly expiry's remedy. What disqualifies it is a death a rebuild cannot
    /// cure: its own [`unsatisfiable_at`](MigrationTransaction::unsatisfiable_at) mark (its inputs
    /// are gone), or a dead dependency (the rebuild would re-anchor to inputs that never come).
    /// Either is replan territory ([`AdvanceStep::Replan`]), so such a transfer is never offered.
    ///
    /// `set_aside` carries the drive loop's call-local deferrals, exactly as for the prove and
    /// broadcast queues: a rebuild candidate's satisfiability is checked too, and a "not yet"
    /// answer (an unsynced wallet unable to vouch for the funding note) must take the candidate
    /// out of THIS queue as well — a loop that set a candidate aside only to be re-offered the
    /// identical `Rebuild` step would spin forever. [`Self::next_step`] supplies both exclusions.
    ///
    /// Among the expired candidates the earliest SCHEDULED one is returned, judged on the CURRENT
    /// schedule: a transfer already rebuilt once, and so rescheduled later, falls behind those
    /// still holding their original windows.
    ///
    /// Expiry is judged at [`targets.scanned()`](DuenessTargets::scanned): a rebuild discards a
    /// pre-signed artifact and demands a fresh signature, so it is offered only for a lapse the
    /// wallet's own chain data supports. A transfer merely BELIEVED lapsed by the estimate is
    /// withheld from the broadcast and prove queues (see [`Blocker::ExpiryImminent`]) but never
    /// rebuilt here: the withhold reverses itself as the scan catches up, a rebuild does not.
    fn next_rebuildable(
        &self,
        targets: DuenessTargets,
        dead: &BTreeSet<MigrationTransferId>,
        set_aside: &[MigrationTransferId],
    ) -> Option<MigrationTransferId> {
        self.transactions
            .iter()
            .filter(|t| matches!(t.kind, MigrationTxKind::Transfer { .. }))
            .filter(|t| {
                Self::is_expired(t, targets.scanned())
                    && t.unsatisfiable.is_none()
                    && !t.depends_on.iter().any(|d| dead.contains(d))
                    && !set_aside.contains(&t.id)
            })
            .min_by_key(|t| (t.scheduled_height, t.id))
            .map(|t| t.id)
    }

    /// Whether transaction `t` is ready to PROVE: its dependencies are mined and its Orchard anchor
    /// is resolvable from the wallet's commitment tree right now.
    ///
    /// A TRANSFER anchors to a drawn boundary ([`anchor_boundary`](MigrationTransaction::anchor_boundary)),
    /// which must have SETTLED: the boundary block must sit at least
    /// [`PROVABLE_ANCHOR_DEPTH`](crate::scheduling::PROVABLE_ANCHOR_DEPTH) blocks below the
    /// scanned chain tip, so its checkpoint exists in the tree AND is deep enough that a reorg
    /// can no longer plausibly displace it.
    /// Proving becomes available as soon as that holds, decoupled from the (later) broadcast
    /// schedule: the wallet durably retains the boundary checkpoint, so nothing forces the proof
    /// to happen promptly, but making it available early lets the sync-heavy proving work happen
    /// at a sync wake-up in a different waking session from the broadcast (see
    /// [`Self::next_step`]). A PREPARATION carries no drawn boundary and anchors to a fresh
    /// checkpoint at the tip when proved, so it is prove-ready once its dependencies are mined
    /// and its scheduled height has arrived.
    ///
    /// The two targets divide here exactly as [`DuenessTargets`] describes. Boundary settledness is
    /// judged at [`scanned`](DuenessTargets::scanned): the checkpoint either exists in the wallet's
    /// tree or it does not, and an estimate cannot conjure one — offering a proof against a
    /// checkpoint that has not been scanned would only fail in the prover. Schedule dueness (a
    /// preparation's) and the expiry SKIP are judged at [`effective`](DuenessTargets::effective):
    /// both are reversible, and proving a transfer whose expiry has probably passed is wasted work
    /// even before the wallet can confirm the lapse.
    fn prove_ready(&self, t: &MigrationTransaction, targets: DuenessTargets) -> bool {
        // An expired transaction can never be mined, so proving it is wasted work: it must be rebuilt
        // (with a fresh anchor and expiry) first. Judged at the ESTIMATE — this is a skip, not a
        // determination: nothing is recorded, no artifact is discarded, and a transfer whose lapse
        // the estimate overstated is proved as soon as the scan catches up. Guarding here keeps
        // `next_provable_tx` from ever offering a transaction believed expired.
        if Self::is_expired(t, targets.effective()) {
            return false;
        }
        if !self.deps_mined(&t.depends_on) {
            return false;
        }
        match t.anchor_boundary {
            // A transfer: the boundary must sit AT LEAST `PROVABLE_ANCHOR_DEPTH` blocks below
            // the SCANNED tip — deep enough that the checkpoint proved against is reorg-stable
            // (see the constant). The scanned target is `tip + 1`, so `tip - boundary >= DEPTH`
            // is `boundary + DEPTH < scanned`.
            Some(boundary) => {
                u32::from(boundary) + scheduling::PROVABLE_ANCHOR_DEPTH
                    < u32::from(targets.scanned())
            }
            // A preparation: prove-ready once its schedule is due, at the served target. It
            // anchors to a fresh checkpoint at the tip when proved, so no boundary depth applies.
            None => t.scheduled_height <= targets.effective(),
        }
    }

    /// EVERY pre-signed transaction ready to PROVE (move `Signed -> Proved`): each one's anchor
    /// is resolvable now. Proving is decoupled from broadcasting so a transfer can be proved at a
    /// sync wake-up well before its scheduled broadcast height, keeping the sync work and the
    /// broadcast in separate waking sessions — and the whole ready set is surfaced as ONE
    /// [`AdvanceStep::Prove`], because proving emits nothing a network observer can see, so
    /// nothing about it wants the one-at-a-time spacing the broadcast queue exists to provide.
    ///
    /// Ordered earliest-ready first: a transfer by its anchor boundary, a preparation by its
    /// scheduled height (it carries no boundary), ties broken by id — oldest-anchor first, so a
    /// consumer proving in order retires the checkpoints the wallet has been retaining longest.
    ///
    /// Transactions in `dead` — the ids judged unable to ever mine, at the SCANNED target — and in
    /// `set_aside` — the drive loop's call-local exclusions — are never offered;
    /// [`Self::next_step`] supplies both. Readiness itself splits the pair as
    /// [`Self::prove_ready`] describes.
    fn provable_targets(
        &self,
        targets: DuenessTargets,
        dead: &BTreeSet<MigrationTransferId>,
        set_aside: &[MigrationTransferId],
    ) -> Vec<ProveTarget> {
        let mut ready: Vec<&MigrationTransaction> = self
            .transactions
            .iter()
            .filter(|t| {
                matches!(t.state, MigrationTxState::Signed)
                    && !dead.contains(&t.id)
                    && !set_aside.contains(&t.id)
                    && self.prove_ready(t, targets)
            })
            .collect();
        // The height each became provable at: a transfer's drawn boundary, a preparation's
        // schedule.
        ready.sort_by_key(|t| (t.anchor_boundary.unwrap_or(t.scheduled_height), t.id));
        ready
            .into_iter()
            .map(|t| ProveTarget {
                id: t.id,
                kind: t.kind,
            })
            .collect()
    }

    /// The id of the next transaction ready to BROADCAST: already `Proved`, its dependencies mined,
    /// and scheduled at or before [`targets.effective()`](DuenessTargets::effective) — the served
    /// target, so a wallet woken by wall-clock estimate submits a due transfer without first
    /// synchronizing.
    ///
    /// Among the due candidates the earliest SCHEDULED one is returned — for this queue that is
    /// the same as longest-due, the schedule being what makes a transaction broadcastable — so a
    /// wallet waking with several windows open submits them in the order those windows opened.
    /// Everything due is broadcast before the loop moves on to proving.
    ///
    /// Transactions in `dead` — the ids judged unable to ever mine, at the SCANNED target — and in
    /// `set_aside` — the drive loop's call-local exclusions — are never offered;
    /// [`Self::next_step`] supplies both. Nor is a transaction carrying a broadcast-failure
    /// report ([`MigrationState::report_broadcast_failure`]): that exclusion is PERSISTED rather
    /// than call-local, because it is precisely the store's stale "satisfiable" that would
    /// otherwise re-offer the doomed broadcast.
    pub(crate) fn next_broadcastable(
        &self,
        targets: DuenessTargets,
        dead: &BTreeSet<MigrationTransferId>,
        set_aside: &[MigrationTransferId],
    ) -> Option<MigrationTransferId> {
        self.transactions
            .iter()
            .filter(|t| {
                matches!(t.state, MigrationTxState::Proved)
                    && t.scheduled_height <= targets.effective()
                    && !dead.contains(&t.id)
                    && !set_aside.contains(&t.id)
                    // A node already rejected this transaction, and nothing the wallet has
                    // scanned yet explains why: offering it again would repeat a submission
                    // known to fail.
                    && t.broadcast_failure_at.is_none()
                    && self.deps_mined(&t.depends_on)
                    // An expired proven transaction would be rejected by the node; it must be
                    // rebuilt, not broadcast. Judged at the ESTIMATE, which makes this guard do two
                    // jobs. For a lapse the wallet has scanned it is redundant with the dead set
                    // (every expired unmined transaction is a dead-set seed), but kept independent:
                    // this is what stops a wallet resumed after its broadcast windows lapsed from
                    // broadcasting a stale, no-longer-includable transaction, whatever `dead` the
                    // caller passed. For a lapse only the ESTIMATE believes in — the doomed window,
                    // `scanned <= expiry < effective` — it is the protective WITHHOLD: submitting
                    // would be refused by the node and, for a same-seed re-broadcast loop, refused
                    // repeatedly. It records nothing and reverses itself once the scan reaches the
                    // expiry, where the scanned path makes the actual determination;
                    // `transaction_statuses` renders the withheld transaction
                    // [`Blocker::ExpiryImminent`], so a status-driven consumer agrees with this
                    // queue exactly.
                    && !Self::is_expired(t, targets.effective())
            })
            .min_by_key(|t| (t.scheduled_height, t.id))
            .map(|t| t.id)
    }

    /// The minimal schedule of sync/proving wake-ups for the transfers that still need proofs, as
    /// of the observed chain tip `current_tip`: each entry is a height at which to wake, sync, and
    /// prove (see [`crate::scheduling::schedule_sync_wakeups`], which defines the windows, the
    /// minimality guarantee, the jitter, and the immediate wake-up that collects overdue
    /// transfers). This is the schedule a background-constrained wallet registers with its OS,
    /// alongside the (independent) broadcast heights the transfers themselves carry.
    ///
    /// Unlike the sibling query methods, which take a [`DuenessTargets`] pair, this method takes a
    /// single observed tip: wake-up heights are floored at the tip (a wake-up at exactly
    /// `current_tip` means "right now"), and a wake-up schedule is purely ADVISORY — it decides
    /// nothing, records nothing, and discards nothing, so nothing here needs the pair's separation
    /// between what the chain data supports and what the clock suggests. Expiry is judged at
    /// `current_tip + 1`, consistent with [`Self::expired_transactions`].
    ///
    /// Covered are transfers in the `Signed` or `AwaitingSignature` state — proving and signature
    /// application are independent operations, so a transfer whose signed PCZT has not yet been
    /// returned by the external signer still needs its proof on the same schedule — while `Proved`,
    /// `Broadcast`, and `Mined` transfers, dead transfers (the expired ones, whose rebuild
    /// reschedules them, and those marked unsatisfiable or dependent on a transaction that can
    /// never mine, whose remedy is the migration-level replan — see [`AdvanceStep::Replan`]), and
    /// preparations (which anchor at the tip when proved, driven by
    /// [`advance_migration`](crate::satisfiability::advance_migration) at their own broadcast
    /// wake-ups) are not. A transfer lacking a drawn anchor boundary (impossible for a state
    /// committed by this crate) likewise contributes no wake-up: like a preparation, it is driven
    /// by [`advance_migration`](crate::satisfiability::advance_migration) at its scheduled height.
    /// Nothing is persisted: the schedule is derived from the migration state, so recompute it —
    /// with fresh jitter — after any state change (a proof stored, a rebuild, a missed wake-up).
    pub fn sync_wakeup_schedule<R: RngCore + CryptoRng>(
        &self,
        current_tip: BlockHeight,
        params: &WakeupParams,
        rng: &mut R,
    ) -> Result<Vec<SyncWakeup<MigrationTransferId>>, WakeupScheduleError<MigrationTransferId>>
    {
        // Expiry semantics are defined against the next block a transaction could mine in. The
        // caller's tip is an observation, so the pair is degenerate: there is no estimate here to
        // separate from.
        let targets = DuenessTargets::at(current_tip + 1);
        // The dead set subsumes expiry (an expired unmined transfer is a dead-set seed), so this
        // one exclusion covers both a transfer past its own window and one whose inputs can never
        // exist: neither will ever need the proof a wake-up exists to produce.
        let dead = self.dead_set(targets);
        let transfers: Vec<(MigrationTransferId, BlockHeight, BlockHeight)> = self
            .transactions
            .iter()
            .filter(|t| {
                matches!(t.kind, MigrationTxKind::Transfer { .. })
                    && matches!(
                        t.state,
                        MigrationTxState::Signed | MigrationTxState::AwaitingSignature
                    )
                    && !dead.contains(&t.id)
            })
            .filter_map(|t| t.anchor_boundary.map(|a| (t.id, a, t.scheduled_height)))
            .collect();
        scheduling::schedule_sync_wakeups(params, current_tip, &transfers, rng)
    }

    /// Recomputes the overall [`MigrationStatus`]: `Complete` once every transaction is mined,
    /// `InProgress` once any has been broadcast or mined. Leaves the status unchanged otherwise (an
    /// uncommitted or freshly committed migration keeps its `Planning`/`Committed` status until work
    /// begins).
    pub fn recompute_status(&mut self) {
        // Recomputation never leaves a terminal status: once Complete, Failed, or Superseded,
        // further calls are no-ops. Failed and Superseded are POLICY determinations — nothing here
        // or elsewhere revisits them. Complete is CHAIN-DERIVED, so it is exactly as revocable as
        // the chain it was derived from; only a chain rewind that un-mines a transaction could
        // revoke it, and doing so is not this function's concern. Without this guard, a cancelled
        // migration whose transactions were already broadcast would be resurrected to InProgress
        // the next time the status is recomputed.
        if self.is_terminal() {
            return;
        }
        let all_mined = !self.transactions.is_empty()
            && self
                .transactions
                .iter()
                .all(|t| matches!(t.state, MigrationTxState::Mined { .. }));
        let any_started = self.transactions.iter().any(|t| {
            matches!(
                t.state,
                MigrationTxState::Broadcast { .. } | MigrationTxState::Mined { .. }
            )
        });
        if all_mined {
            self.status = MigrationStatus::Complete;
        } else if any_started {
            self.status = MigrationStatus::InProgress;
        }
    }

    /// Whether the unsatisfiable share of planned transfer value STRICTLY exceeds the
    /// [`ReplanThreshold`](crate::satisfiability::ReplanThreshold) stamped at commit — the
    /// condition under which the migration should be re-planned immediately rather than after
    /// satisfiable work drains. The share counts each unmined transfer marked
    /// [`unsatisfiable_at`](MigrationTransaction::unsatisfiable_at) at its crossing value, over the
    /// total planned crossing value; preparations enter only through the transfers they fund, and a
    /// mined transfer counts in the denominator only. Derived, never stored: a stored copy could
    /// not un-cross the threshold when a reorg clears marks.
    pub fn replan_required(&self) -> bool {
        let unsat: u64 = self
            .transactions
            .iter()
            .filter(|t| {
                t.unsatisfiable.is_some() && !matches!(t.state, MigrationTxState::Mined { .. })
            })
            .filter_map(|t| self.transfer_crossing_value(t))
            .map(u64::from)
            .sum();
        let total: u64 = self
            .denominations
            .crossing_values()
            .iter()
            .copied()
            .map(u64::from)
            .sum();
        // Widened to u128: `DenominationPlan::from_stored_parts` validates each crossing value but
        // not the list's sum, so a corrupt store could hand this a `total` large enough that the
        // `100 * unsat` or `percent * total` product overflows `u64` (a debug panic, or a silent
        // wraparound in release).
        100u128 * u128::from(unsat)
            > u128::from(self.replan_threshold.percent()) * u128::from(total)
    }

    /// Whether this migration has reached a terminal status, so a new migration may replace it. A
    /// non-terminal migration is still in progress and must not be overwritten.
    ///
    /// Delegates to [`MigrationStatus::is_terminal`], which is where terminality is decided; a
    /// second list here could disagree with the one a store queries on.
    pub fn is_terminal(&self) -> bool {
        self.status.is_terminal()
    }

    /// Moves a non-terminal migration to [`MigrationStatus::Superseded`], the consumer's response
    /// to a migration whose remaining value must be re-planned: after this, the commit guard
    /// accepts a replacement migration for the remaining balance. A no-op on an already-terminal
    /// migration — terminality is never overwritten by policy.
    pub fn mark_superseded(&mut self) {
        if !self.is_terminal() {
            self.status = MigrationStatus::Superseded;
        }
    }

    /// Moves a non-terminal migration to [`MigrationStatus::Cancelled`], the consumer's response to
    /// a user who has chosen to abandon the migration: after this, the commit guard accepts a
    /// replacement migration. A no-op on an already-terminal migration — terminality is never
    /// overwritten by policy, so whichever terminal status got there first remains the truthful
    /// history.
    ///
    /// Cancelling is a STATUS change and nothing more. It does not release any hold the migration's
    /// transactions have on the wallet's notes, so a consumer that has proved transactions is not
    /// done after calling this; see the pool-migration cancel flow for what else a wallet-backed
    /// store must do.
    pub fn mark_cancelled(&mut self) {
        if !self.is_terminal() {
            self.status = MigrationStatus::Cancelled;
        }
    }

    /// Records that the transaction `id` was broadcast, then recomputes the overall status. The
    /// consumer calls this after it broadcasts the transaction the engine handed it.
    ///
    /// Takes no txid. The transaction's id was derived when it was built
    /// ([`MigrationTransaction::txid`]) and cannot have changed since — signing and proving add
    /// only authorizing data — so a consumer broadcasting a stored transaction has nothing to tell
    /// the engine that the engine does not already know better.
    pub fn mark_broadcast(&mut self, id: MigrationTransferId) {
        if let Some(tx) = self.transactions.iter_mut().find(|t| t.id == id) {
            // The id is the one derived when the transaction was built, not one the caller
            // supplies: a consumer broadcasting a stored transaction cannot produce a different
            // one, and being able to pass a mismatched id was a way to lose track of a
            // transaction that is on chain.
            tx.state = MigrationTxState::Broadcast { txid: tx.txid };
        }
        self.recompute_status();
    }

    /// Shifts the scheduled height of every transaction that has not yet been broadcast forward
    /// by `delta` blocks, preserving the schedule's inter-broadcast gaps.
    ///
    /// This is the RE-SPREAD half of ZIP 318's missed-schedule policy — at most one overdue
    /// transfer is released immediately; the rest are re-spread — applied by
    /// [`advance_migration`](crate::satisfiability::advance_migration) when the step it would
    /// surface lags the served target by more than
    /// the schedule-scaled tolerance
    /// ([`overdue_shift_tolerance`](crate::satisfiability::overdue_shift_tolerance)). Shifting
    /// every pending transaction by the same delta moves the whole remaining schedule forward in
    /// block-time without redrawing it, so the gaps between broadcasts — the observable the drawn
    /// exponential delays exist to shape — survive the wallet's absence unchanged, instead of the
    /// missed steps piling up and broadcasting as a cluster.
    ///
    /// Only PENDING transactions shift ([`AwaitingSignature`](MigrationTxState::AwaitingSignature),
    /// [`Signed`](MigrationTxState::Signed), [`Proved`](MigrationTxState::Proved)): an in-flight
    /// or mined transaction's schedule has already been served, and moving it would only distort
    /// the record of when it was due. Expiry heights are untouched — a pre-signed transaction's
    /// expiry is effecting data under ZIP 203, fixed at signing — so a large enough shift can move
    /// a pending schedule past its own expiry; such a transaction self-heals through the ordinary
    /// expiry path (its rebuild redraws both schedule and expiry). Heights saturate rather than
    /// overflow.
    ///
    /// A shifted TRANSFER whose proof is still to come ([`AwaitingSignature`](MigrationTxState::AwaitingSignature)
    /// or [`Signed`](MigrationTxState::Signed)) also gets its anchor boundary REDRAWN against the
    /// shifted schedule ([`redraw_anchor_boundary`](crate::scheduling::redraw_anchor_boundary)):
    /// the stored boundary was drawn to be in-distribution relative to the ORIGINAL broadcast
    /// height, so keeping it would broadcast an anchor `delta` blocks older than any honest draw —
    /// and every deferred transfer of this wallet older by the SAME `delta`, a linkable
    /// fingerprint. The redraw is sound exactly as `prove_transfer`'s proving-time redraw is:
    /// ZIP 374 defers the anchor and witnesses to proving, so nothing in the stored artifact pins
    /// the old boundary. A [`Proved`](MigrationTxState::Proved) transfer's proof DOES pin its
    /// anchor, so its boundary is kept (re-anchoring it would mean discarding the proof), and a
    /// preparation carries no drawn boundary at all. In the rare case where no candidate exists at
    /// or above the prior boundary (see [`redraw_anchor_boundary`](crate::scheduling::redraw_anchor_boundary)),
    /// the prior — still provable — boundary is kept.
    pub(crate) fn shift_schedule<R: RngCore + CryptoRng>(&mut self, delta: u32, rng: &mut R) {
        let interval = self.anchor_bucket_interval;
        for tx in &mut self.transactions {
            match tx.state {
                MigrationTxState::Broadcast { .. } | MigrationTxState::Mined { .. } => continue,
                MigrationTxState::AwaitingSignature | MigrationTxState::Signed => {
                    tx.scheduled_height = tx.scheduled_height + delta;
                    if matches!(tx.kind, MigrationTxKind::Transfer { .. })
                        && let Some(prior) = tx.anchor_boundary
                        && let Some(fresh) = crate::scheduling::redraw_anchor_boundary(
                            interval,
                            prior,
                            tx.scheduled_height,
                            rng,
                        )
                    {
                        tx.anchor_boundary = Some(fresh);
                    }
                }
                MigrationTxState::Proved => {
                    tx.scheduled_height = tx.scheduled_height + delta;
                }
            }
        }
    }

    /// Records that the transaction `id` was mined under `txid` at `height`, then recomputes the
    /// overall status. This is what lets a later preparation layer or the transfers become
    /// actionable. Recording the txid on `Mined` (rather than dropping it once broadcast is
    /// superseded) is what lets reorg handling demote a rolled-back mined transaction back to
    /// `Broadcast` without losing the id it was mined under.
    ///
    /// A DRIVER DOES NOT CALL THIS.
    /// [`advance_migration`](crate::satisfiability::advance_migration) derives inclusion from the
    /// wallet's own scan, through [`PoolMigrationRead::mined_height`], for every in-flight
    /// transaction it sweeps — so a consumer that broadcasts and records THAT gets the promotion
    /// for free, and one that also polls for mining would only race the sweep to the same answer.
    /// This remains public for a consumer standing outside that loop: a test fixture building a
    /// state by hand, or a store reconstructing one. Mining is chain-derived (compare
    /// [`Self::mark_broadcast`], which records testimony no scan can supply), and deriving it in
    /// one place is what keeps the stored state from trailing the scan that already knows.
    ///
    /// [`PoolMigrationRead::mined_height`]: crate::engine::PoolMigrationRead::mined_height
    ///
    /// Mining also DISCHARGES both standing judgments about whether the transaction ever could
    /// mine — its [`unsatisfiable`](MigrationTransaction::unsatisfiable) mark and its
    /// broadcast-failure report ([`Self::report_broadcast_failure`]). Chain inclusion outranks
    /// either: a persisted "its inputs can never all exist unspent" beside a mined state is a
    /// contradiction a wallet would render, and a rejection is answered by the very inclusion
    /// that followed it. Both were derivable rather than fundamental — every other reader already
    /// exempts mined transactions (the dead set, the replan share, the blocker precedence) — so
    /// clearing them here costs no information, and a reorg that demotes the row leaves the
    /// oracle to re-derive against the new chain, exactly as
    /// [`Self::truncate_to_height`] leaves a cleared mark to be re-derived.
    pub fn mark_mined(&mut self, id: MigrationTransferId, height: BlockHeight) {
        if let Some(tx) = self.transactions.iter_mut().find(|t| t.id == id) {
            // Like `mark_broadcast`, the id comes from the row rather than the caller: the
            // transaction that mined is the one this row describes, and the two could only
            // disagree by mistake.
            tx.state = MigrationTxState::Mined {
                txid: tx.txid,
                height,
            };
            tx.unsatisfiable = None;
            tx.broadcast_failure_at = None;
        }
        self.recompute_status();
    }

    /// Records that a broadcast of transaction `id` was REJECTED by the node the application
    /// submitted it to, at `observed_tip`: the chain tip that node reported. The application has
    /// such a tip even when its wallet is far behind — it talked to the network in order to
    /// broadcast — and it is the height the rejection's explanation, if there is one, must lie at
    /// or below. Persist the state afterwards (`replace_migration`).
    ///
    /// A node's rejection is TESTIMONY FROM ANOTHER OBSERVER, not evidence in this wallet's view,
    /// so it records no [`unsatisfiable`](MigrationTransaction::unsatisfiable) mark and no cause:
    /// the engine never trusts a node's stated reason, and every mark rests on chain state this
    /// wallet has scanned, which is what makes reorg truncation exact. What the report does is
    /// WITHHOLD. The transaction leaves the broadcast queue and reports
    /// [`Blocker::AwaitingReevaluation`] until
    /// [`advance_migration`](crate::satisfiability::advance_migration) adjudicates it against the
    /// store's oracle — which it can do once the wallet has scanned to `observed_tip`, and until
    /// then surfaces [`AdvanceStep::Reevaluate`] instead of any other work. Adjudication either
    /// finds the spend behind the rejection (an ordinary evidence-backed mark) or does not (the
    /// rejection was transient, the report is discharged, and the broadcast is offered again).
    ///
    /// Recorded only for a [`Proved`](MigrationTxState::Proved) transaction: a broadcast that
    /// failed never reached [`Self::mark_broadcast`], so that is the state a rejected transaction
    /// is in. A no-op for an unknown id or a transaction in any other state — in particular a
    /// mined one, whose inclusion settles the question the report exists to raise. A second
    /// report OVERWRITES the first: the newest testimony supersedes, and its (later) tip is the
    /// one the wallet must reach.
    pub fn report_broadcast_failure(&mut self, id: MigrationTransferId, observed_tip: BlockHeight) {
        if let Some(tx) = self
            .transactions
            .iter_mut()
            .find(|t| t.id == id && matches!(t.state, MigrationTxState::Proved))
        {
            tx.broadcast_failure_at = Some(observed_tip);
        }
    }

    /// Discharges the broadcast-failure report on `id`, if it carries one: the drive API's
    /// adjudication, applied once an oracle answer resting at or above the reported tip has
    /// decided the question — by recording a mark, or by finding nothing to record. Internal,
    /// because a report is withdrawn only against evidence, or by
    /// [`Self::truncate_to_height`] when the chain state it named is gone.
    pub(crate) fn clear_broadcast_failure(&mut self, id: MigrationTransferId) {
        if let Some(tx) = self.transactions.iter_mut().find(|t| t.id == id) {
            tx.broadcast_failure_at = None;
        }
    }

    /// Records the outcomes of satisfiability checks as durable
    /// [`unsatisfiable`](MigrationTransaction::unsatisfiable) marks: the single door
    /// through which satisfiability observations enter the state. The engine's drive and prove
    /// paths record through this method after consulting
    /// [`check_step_satisfiability`](crate::engine::PoolMigrationRead::check_step_satisfiability);
    /// `determinations` pairs each checked transaction with its answer, and `targets` supplies the
    /// height at which expiry is judged for the dependency closure below. Persist the state
    /// afterwards (`replace_migration`).
    ///
    /// Marking is CAUSE-DEPENDENT:
    ///
    /// | Answer | Effect |
    /// |---|---|
    /// | [`Unsatisfiable`](StepSatisfiability::Unsatisfiable) via [`InputsSpent`](crate::satisfiability::UnsatisfiableCause::InputsSpent), [`InputsInvalidated`](crate::satisfiability::UnsatisfiableCause::InputsInvalidated), or [`AnchorInvalidated`](crate::satisfiability::UnsatisfiableCause::AnchorInvalidated) | marks the transaction at the answer's `as_of_height`, under the cause's [`UnsatisfiableKind`] |
    /// | [`Unsatisfiable`](StepSatisfiability::Unsatisfiable) via [`Expired`](crate::satisfiability::UnsatisfiableCause::Expired) | no mark |
    /// | [`Satisfiable`](StepSatisfiability::Satisfiable) / [`NotYetSatisfiable`](StepSatisfiability::NotYetSatisfiable) | no mark |
    ///
    /// The input-level and anchor-level causes record an observation about chain state that the
    /// state machine cannot re-derive on its own (the store saw the inputs spent, or an anchor
    /// permanently displaced), so it must be stored durably; the mark carries the answer's
    /// `as_of_height` — the chain height the observation RESTS ON, not the height it was recorded
    /// at — which is what gives reorg truncation exact semantics, and the cause's reduced
    /// [`UnsatisfiableKind`], so a wallet can say WHY without re-consulting the oracle. `Expired`
    /// instead confirms a derivation the kernel already makes from the same
    /// [`expiry_height`](MigrationTransaction::expiry_height), so a stored copy would add
    /// nothing and could only drift.
    ///
    /// The FIRST observation wins: a transaction already carrying a mark is never restamped,
    /// and a mined transaction is never marked (it is final; its inputs' disposition no longer
    /// matters). The only eraser is reorg truncation ([`Self::truncate_to_height`]) — a mark
    /// stands until the chain state backing it rolls back.
    ///
    /// After the direct marks, the DURABLE CLOSURE runs to a fixpoint over the dependency
    /// graph, so a stranded subtree is marked even when the oracle was never asked about it
    /// (or was asked about nothing at all): with the dead sources being the marked
    /// transactions and the expired-and-unmined ones (judged at
    /// [`targets.scanned()`](DuenessTargets::scanned) — this closure WRITES marks into the state,
    /// so its expired sources may only be the ones the wallet's own chain data supports; a wallet
    /// whose estimate ran ahead of its scan must never persist an
    /// [`Inherited`](UnsatisfiableKind::Inherited) verdict against a transaction that is still
    /// live, since only a reorg truncation below the stamp could withdraw it, and there is no
    /// reorg to truncate), every
    /// unmined, unmarked transaction with a dead direct dependency inherits a mark, of kind
    /// [`Inherited`](UnsatisfiableKind::Inherited) — nothing was observed about the transaction
    /// itself, so what killed it is read off that dependency's own mark. The
    /// inherited stamp is the MINIMUM applicable stamp over its dead direct dependencies — a
    /// marked dependency contributes its `unsatisfiable_at`, an expired-unmined one its
    /// `expiry_height` (both, when it is both) — which is the earliest height whose rollback
    /// would revive the dependent: reviving it means reviving EVERY dead dependency, so a
    /// truncation must reach strictly below all of their stamps (below the minimum), and
    /// [`Self::truncate_to_height`] clears marks strictly above its height, so the inherited
    /// mark clears exactly then. In particular, a dependent stranded behind an expired-unmined
    /// source is stamped at the source's `expiry_height`, so a rewind that un-expires the
    /// source clears the inheritance with it. The expired sources themselves stay unmarked:
    /// their deadness is derived afresh wherever it is needed (the kernel's dead set), and a
    /// stored copy could not un-expire.
    pub fn record_satisfiability(
        &mut self,
        targets: DuenessTargets,
        determinations: &[(MigrationTransferId, StepSatisfiability)],
    ) {
        // Direct marks: only the input-level and anchor-level causes record, and only onto an
        // unmarked, unmined transaction.
        for (id, answer) in determinations {
            let StepSatisfiability::Unsatisfiable {
                cause,
                as_of_height,
            } = answer
            else {
                continue;
            };
            // Whether a cause marks — and under which kind — is defined once, on the cause itself:
            // the drive API's loop decides what to record from the same predicate, and its
            // termination depends on the two agreeing (see `UnsatisfiableCause::kind` and its
            // derived `marks`).
            let Some(kind) = cause.kind() else {
                continue;
            };
            if let Some(t) = self.transactions.iter_mut().find(|t| {
                t.id == *id
                    && t.unsatisfiable.is_none()
                    && !matches!(t.state, MigrationTxState::Mined { .. })
            }) {
                t.unsatisfiable = Some((*as_of_height, kind));
            }
        }
        // The durable closure, to a fixpoint. Each pass is two-phase — collect the inherited
        // stamps over an immutable scan, then apply them — and a mark applied in one pass makes
        // its dependents' stamps derivable in the next. Marks only accumulate, so this
        // terminates within `transactions.len()` passes.
        loop {
            let inherited: Vec<(MigrationTransferId, BlockHeight)> = self
                .transactions
                .iter()
                .filter(|t| {
                    !matches!(t.state, MigrationTxState::Mined { .. }) && t.unsatisfiable.is_none()
                })
                .filter_map(|t| {
                    // The minimum applicable stamp over this transaction's dead direct
                    // dependencies (see the method docs for why the minimum); `None` when no
                    // direct dependency is dead.
                    t.depends_on
                        .iter()
                        .filter_map(|d| self.transactions.iter().find(|x| x.id == *d))
                        .filter(|d| !matches!(d.state, MigrationTxState::Mined { .. }))
                        .filter_map(|d| {
                            // The SCANNED target: an inherited mark is persisted and only a
                            // reorg truncation clears it, so an estimate must never contribute a
                            // dead source here.
                            let expired =
                                Self::is_expired(d, targets.scanned()).then_some(d.expiry_height);
                            match (d.unsatisfiable_at(), expired) {
                                (Some(m), Some(e)) => Some(m.min(e)),
                                (Some(m), None) => Some(m),
                                (None, Some(e)) => Some(e),
                                (None, None) => None,
                            }
                        })
                        .min()
                        .map(|stamp| (t.id, stamp))
                })
                .collect();
            if inherited.is_empty() {
                break;
            }
            for (id, stamp) in inherited {
                if let Some(t) = self.transactions.iter_mut().find(|t| t.id == id) {
                    // Nothing was observed about this transaction itself; what killed it is read
                    // off the dead dependency that contributed the stamp.
                    t.unsatisfiable = Some((stamp, UnsatisfiableKind::Inherited));
                }
            }
        }
    }

    /// Invalidates every CHAIN-DERIVED determination resting on chain state strictly above
    /// `height`: the reorg hook, which the consumer calls wherever it truncates its wallet,
    /// passing the height the wallet ACTUALLY truncated to — a wallet may truncate lower than
    /// requested and reports the achieved height, and passing the requested height instead
    /// would leave marks standing on state that no longer exists — and persisting the state
    /// afterwards (`replace_migration`). Four things roll back, and nothing else:
    ///
    /// - every [`unsatisfiable`](MigrationTransaction::unsatisfiable) mark whose stamp is strictly
    ///   above `height` is cleared, kind and all: the observation it recorded rested on state that
    ///   no longer exists;
    /// - every broadcast-failure report ([`Self::report_broadcast_failure`]) whose observed tip is
    ///   strictly above `height` is discharged: it named a chain the wallet no longer holds, and
    ///   waiting to sync to a vanished tip would withhold the transaction forever. A rejection
    ///   that is still real on the new chain simply re-reports at the next broadcast attempt,
    ///   which is the same coarse-and-re-derive discipline the marks follow;
    /// - every [`Mined`](MigrationTxState::Mined) transaction whose mined height is strictly
    ///   above `height` is demoted to [`Broadcast`](MigrationTxState::Broadcast), keeping the
    ///   txid it was mined under: the transaction is back in flight and may well re-mine, and
    ///   the consumer's chain view re-detects that and records it with [`Self::mark_mined`] as
    ///   usual;
    /// - a [`Complete`](MigrationStatus::Complete) status is reverted to
    ///   [`InProgress`](MigrationStatus::InProgress) when a demotion leaves a transaction
    ///   unmined: `Complete` is chain-derived, exactly as revocable as the chain it was derived
    ///   from (see [`MigrationStatus::Complete`]), and once every demoted transaction re-mines,
    ///   ordinary [`Self::recompute_status`] (via [`Self::mark_mined`]) restores it.
    ///
    /// The POLICY determinations are untouched: [`Failed`](MigrationStatus::Failed) and
    /// [`Superseded`](MigrationStatus::Superseded) record decisions, not chain state, and no
    /// chain event ever revisits them (the same framing as [`Self::recompute_status`]'s
    /// terminal guard) — though a Failed or Superseded migration's TRANSACTIONS still demote,
    /// keeping the per-transaction record truthful.
    ///
    /// Clearing is deliberately coarse. A cleared mark whose underlying fact is still true on
    /// the post-reorg chain (the inputs were also spent below the truncation, say) is simply
    /// re-derived by the next satisfiability checks once the wallet's answers reflect the new
    /// chain, re-entering through [`Self::record_satisfiability`]. And a mined row that was
    /// exempted from the nullifier backfill (an empty
    /// [`spend_nullifiers`](MigrationTransaction::spend_nullifiers) cache) cannot slip into
    /// vacuous satisfiability when demoted here: demotion makes it non-mined, and the store
    /// oracle treats an empty cache on a non-mined transaction as loud corruption at its next
    /// satisfiability check (see
    /// [`classify_input_observations`](crate::satisfiability::classify_input_observations)), never as
    /// an answer.
    pub fn truncate_to_height(&mut self, height: BlockHeight) {
        for t in &mut self.transactions {
            if t.unsatisfiable.is_some_and(|(h, _)| h > height) {
                t.unsatisfiable = None;
            }
            if t.broadcast_failure_at.is_some_and(|h| h > height) {
                t.broadcast_failure_at = None;
            }
            if let MigrationTxState::Mined {
                txid,
                height: mined_height,
            } = t.state
                && mined_height > height
            {
                t.state = MigrationTxState::Broadcast { txid };
            }
        }
        if self.status == MigrationStatus::Complete
            && self
                .transactions
                .iter()
                .any(|t| !matches!(t.state, MigrationTxState::Mined { .. }))
        {
            self.status = MigrationStatus::InProgress;
        }
    }

    /// Store an EXTERNALLY signed PCZT for transaction `id`, moving it from
    /// [`AwaitingSignature`](MigrationTxState::AwaitingSignature) to [`Signed`](MigrationTxState::Signed)
    /// so the normal state machine can prove and broadcast it. This is the second half of the
    /// external-signing seam: after
    /// [`build_preparation_unsigned`](crate::engine::build_preparation_unsigned) exports the unsigned PCZT,
    /// the caller has it signed out of band and returns the signed PCZT here, matched by `id`. Persist
    /// the state afterwards (`replace_migration`).
    ///
    /// Returns `true` if the signature was applied. Returns `false`, leaving the state unchanged, if no
    /// transaction has that `id` or it is not awaiting a signature (already signed, still an unbuilt
    /// placeholder, or already broadcast or mined), so a caller can detect a stale or misrouted signature.
    #[must_use]
    pub fn apply_signature(&mut self, id: MigrationTransferId, signed_pczt: Vec<u8>) -> bool {
        let Some(tx) = self
            .transactions
            .iter_mut()
            .find(|t| t.id == id && matches!(t.state, MigrationTxState::AwaitingSignature))
        else {
            return false;
        };
        tx.pczt = signed_pczt;
        tx.state = MigrationTxState::Signed;
        true
    }

    /// Decides the next step to advance the migration, purely from the persisted state: the single
    /// highest-priority action available at the caller's [`DuenessTargets`]. The decision is made
    /// once, here, so every consumer (a mobile wallet using these crates directly, or a server
    /// like Zallet) advances the same state the same way.
    ///
    /// This is the planning KERNEL, and it is internal to the crate: it DECIDES, but it does not
    /// VERIFY. The step it names has not been put to the store's satisfiability oracle, so it may
    /// name a transaction the wallet already knows can never execute.
    /// [`advance_migration`](crate::satisfiability::advance_migration) is what wraps this decision
    /// in that check, and it is the API a consumer drives a migration with; it also documents what
    /// each step asks of the consumer.
    ///
    /// `targets` carries the caller's scanned frontier and its estimate of the chain tip, and the
    /// two are read by CLASSIFICATION, never interchangeably: every judgment that persists a
    /// verdict or destroys work — the dead set, rebuild eligibility, the drain-time
    /// [`Replan`](AdvanceStep::Replan) gate, a transfer's anchor-boundary settledness — is made at
    /// [`scanned`](DuenessTargets::scanned), while the SCHEDULE is served at
    /// [`effective`](DuenessTargets::effective), together with the two reversible things the
    /// estimate is allowed to do: withhold a doomed broadcast and skip a doomed proof. See
    /// [`DuenessTargets`] for the full table and the ZIP 318 session separation behind it, and
    /// [`advance_migration`](crate::satisfiability::advance_migration) for the same contract on the
    /// API a consumer actually drives.
    ///
    /// `set_aside` is the drive loop's call-local list of candidates whose satisfiability check
    /// ([`PoolMigrationRead::check_step_satisfiability`](crate::engine::PoolMigrationRead::check_step_satisfiability))
    /// answered "not yet": every queue — prove, broadcast, and rebuild alike — skips them, so
    /// other actionable work still surfaces in the same pass instead of the loop being re-offered
    /// the identical deferred step forever. A non-empty list also holds back the late
    /// [`Replan`](AdvanceStep::Replan) slot: deferral means information is pending after sync, so
    /// the pass ends in [`Waiting`](AdvanceStep::Waiting) rather than a destructive supersede.
    /// Pass `&[]` to plan without an oracle.
    ///
    /// One call returns ONE step, and the call is pure: until the state records that step's
    /// completion, the same step is decided again.
    ///
    /// # Ordering, and what it implies for wallet construction
    ///
    /// When several actions are available at once the priority is BROADCAST, then REPLAN when
    /// the committed threshold is exceeded, then PROVE, then REBUILD, then REPLAN once dead
    /// value is all that remains.
    ///
    /// Within the broadcast and rebuild queues the longest-READY candidate is offered first,
    /// ties broken by id — never the first by position in
    /// [`transactions`](MigrationState::transactions) — and the whole queue is drained, one
    /// candidate per call, before the next queue is consulted. Readiness is what each queue
    /// itself waits on: the scheduled height for a broadcast or a rebuild, the anchor boundary
    /// (a preparation: its scheduled height) for a proof. The PROVE queue is instead served
    /// WHOLE: one [`Prove`](AdvanceStep::Prove) step carries every ready candidate,
    /// earliest-ready first, because proving emits nothing observable and so has no reason to be
    /// doled out call by call. Either way this orders work within a session, not across them.
    ///
    /// [`Reevaluate`](AdvanceStep::Reevaluate) is NOT among the steps decided here: adjudicating
    /// a broadcast-failure report needs the oracle, so the drive API owns that slot. What this
    /// kernel does with a report is WITHHOLD — a reported transaction is out of the broadcast
    /// queue for as long as the report stands (see
    /// [`MigrationState::report_broadcast_failure`]), so a store's stale "satisfiable" cannot
    /// re-offer a submission a node has already refused.
    ///
    /// Every queue is filtered through the DEAD SET, derived afresh at each call: the
    /// transactions marked [`unsatisfiable_at`](MigrationTransaction::unsatisfiable_at) and the
    /// expired-and-unmined ones, closed transitively over dependents (a dependent of a
    /// transaction that can never mine can never mine either). A dead transaction is never
    /// offered for proving or broadcast, and an expired transfer is offered for rebuild only
    /// while the rebuild could succeed: its own mark, or a dead dependency, disqualifies it,
    /// because a rebuild cannot cure missing inputs.
    ///
    /// [`AdvanceStep::Replan`] occupies two slots in the priority. The EARLY slot is
    /// evidence-based: it PREEMPTS proving as soon as [`Self::replan_required`] holds — proving
    /// more of a plan already being abandoned is wasted work — but never a due,
    /// still-satisfiable broadcast (each proven transaction that mines is migrated value the
    /// replan need not carry), and it fires whatever this call's `set_aside` list says. The
    /// LATE slot is the drain-time surfacing of stranded value: it fires only once EVERY
    /// unmined transaction is dead and nothing was set aside this call. A live transfer that is
    /// merely undue (the privacy schedule spreads broadcasts over weeks) or still in flight
    /// gets its chance first — each one that completes is value the replan need not carry, and
    /// the consumer's contracted response to `Replan` ([`Self::mark_superseded`]) is
    /// destructive — while a set-aside candidate answered "not yet satisfiable", a
    /// retry-after-sync answer that makes the honest report [`Waiting`](AdvanceStep::Waiting);
    /// that covers set-aside REBUILD candidates too, whose expiry makes them dead-set seeds (a
    /// wallet restored from seed must not be pushed into superseding its migration by transient
    /// scan lag). Dead-set membership excludes mined transactions, so when the late slot fires,
    /// dead value is all that remains — and a migration never ends silently holding some.
    ///
    /// Broadcast precedes prove because the two kinds of work want to be in DIFFERENT WAKING
    /// SESSIONS. ZIP 318 requires that a background wake window be used either to sync the wallet
    /// or to broadcast a due transfer, never both, so a network observer cannot correlate a
    /// wallet's sync traffic with the transactions it broadcasts. Broadcasting a stored proven
    /// transaction requires no sync at all; proving is inherently sync-bound (it resolves anchors
    /// and witnesses from the synced commitment tree). Surfacing every due broadcast before any
    /// proving work is what makes a broadcast-only session possible: a wallet that wakes to find
    /// transactions due submits them immediately, without first initiating sync operations (unless
    /// the user independently needs to sync, e.g. to spend funds manually). Note that neither this
    /// method nor the drive API above it has any notion of a session — once every due broadcast is
    /// dispatched, proving work is offered in the same loop, and enforcing the session separation
    /// is the CONSUMER's runtime policy (see the "Out of scope" notes in [`crate::scheduling`]).
    ///
    /// Proving is in turn DECOUPLED from the broadcast schedule: a transfer is provable as soon
    /// as its drawn anchor boundary settles (strictly below the chain tip), typically long before
    /// its scheduled broadcast height. There is no deadline pressure — the wallet durably retains
    /// the boundary checkpoints its committed transfers anchor to (see
    /// [`MigrationBackend::scheduling_params`](crate::engine::MigrationBackend::scheduling_params)),
    /// so a transfer remains provable until it is broadcast — but proving at an early sync
    /// wake-up is what leaves nothing but the bare submission for the broadcast session. A
    /// PREPARATION transaction instead becomes provable only when its schedule is due, and is
    /// expected to be proved and broadcast at the same wake-up: it anchors to a fresh checkpoint
    /// at the tip, like an ordinary transaction.
    ///
    /// Rebuild is surfaced only when no still-valid transaction can be proved or broadcast, so
    /// progress on live transactions is never delayed by remediation; reporting it in preference
    /// to `Waiting` is what stops the migration stalling forever on an expired transfer, which
    /// nothing else will ever make broadcastable again. Only a TRANSFER is offered (see
    /// [`AdvanceStep::Rebuild`]); an expired preparation is reported through [`Blocker::Expired`]
    /// and [`Self::expired_transactions`], and — being dead value like any other — drives the
    /// late `Replan` slot once no live work remains.
    ///
    /// A missed schedule degrades gracefully rather than requiring reconciliation: a wallet that
    /// slept through a transfer's proving wake-ups and its broadcast height is simply offered
    /// `Prove` and then `Broadcast` for it as soon as it wakes — or `Rebuild`, once the transfer
    /// has expired. The drive layer adds the RE-SPREAD on top:
    /// [`advance_migration`](crate::satisfiability::advance_migration) shifts the whole pending
    /// schedule forward ([`Self::shift_schedule`]) before serving a step overdue by more than
    /// [`overdue_shift_tolerance`](crate::satisfiability::overdue_shift_tolerance) allows, so this
    /// kernel judges the shifted schedule and at most one overdue step is ever released at once.
    pub(crate) fn next_step(
        &self,
        targets: DuenessTargets,
        set_aside: &[MigrationTransferId],
    ) -> AdvanceStep {
        // A terminal migration (complete, failed/cancelled, or superseded by a re-plan) has no next
        // action: never build or broadcast for it, so a cancelled migration cannot be driven
        // further.
        if self.is_terminal() {
            return AdvanceStep::Complete;
        }
        // Derived once per decision and threaded through every queue: a transaction that can
        // never mine must never be offered as a step, whether or not its death has been durably
        // marked yet.
        let dead = self.dead_set(targets);
        // If the wallet has a transaction available for broadcast, it should immediately
        // do that and *not* initiate any sync operations unless the user specifically needs
        // to sync (e.g. if they need to manually spend some of their funds).
        if let Some(id) = self.next_broadcastable(targets, &dead, set_aside) {
            return AdvanceStep::Broadcast { id };
        }
        // Above the committed threshold, the replan preempts proving — spending proof work on a
        // plan already being abandoned is waste — but not the due broadcasts above: each proven,
        // still-satisfiable transaction that mines is migrated value the replan need not carry.
        if self.replan_required() {
            return AdvanceStep::Replan;
        }
        // A wallet should not broadcast and sync in the same waking session unless necessary.
        // At this point we know we're not broadcasting, so we can sync and prove — and prove
        // EVERYTHING that is ready: proving emits nothing observable, so the whole provable set
        // is served as one step rather than being doled out call by call.
        let provable = self.provable_targets(targets, &dead, set_aside);
        if !provable.is_empty() {
            return AdvanceStep::Prove {
                transactions: provable,
            };
        }
        // If we have not been able to make progress on still-valid transactions, then surface any
        // expired transfer for rebuild. Reporting Rebuild in preference to Waiting is what stops
        // the migration stalling forever on a transfer whose broadcast window lapsed: nothing else
        // will ever make it broadcastable again.
        if let Some(id) = self.next_rebuildable(targets, &dead, set_aside) {
            return AdvanceStep::Rebuild { id };
        }
        // The LATE Replan slot: the drain-time surfacing of stranded value, firing only once
        // EVERY unmined transaction is dead and nothing was set aside this call. Live transfers
        // that are merely undue (the privacy schedule spreads broadcasts over weeks) or still in
        // flight get their chance first: each one that completes is value the replan need not
        // carry, and the consumer's contracted response to Replan (`mark_superseded`) is
        // destructive. A set-aside candidate answered "not yet satisfiable" — a retry-after-sync
        // answer — so its presence makes the honest report Waiting; that covers set-aside REBUILD
        // candidates too, whose expiry makes them dead-set seeds (a wallet restored from seed
        // must not be pushed into superseding its migration by transient scan lag). Dead-set
        // membership excludes mined transactions, so `!dead.is_empty()` is exactly "some unmined
        // transaction is dead", and the `all` is "no unmined transaction is live".
        if !dead.is_empty()
            && set_aside.is_empty()
            && self
                .transactions
                .iter()
                .all(|t| matches!(t.state, MigrationTxState::Mined { .. }) || dead.contains(&t.id))
        {
            return AdvanceStep::Replan;
        }
        if !self.transactions.is_empty()
            && self
                .transactions
                .iter()
                .all(|t| matches!(t.state, MigrationTxState::Mined { .. }))
        {
            return AdvanceStep::Complete;
        }
        AdvanceStep::Waiting
    }

    /// The KIND of the next step that will involve transaction `t`, with the earliest target
    /// height at which it could be served: the per-transaction FLOOR behind
    /// [`Self::upcoming_step`]. `dead` is the caller's [`Self::dead_set`].
    ///
    /// `None` means no future step involves the transaction: it is mined or in flight (mining is
    /// chain-derived, not a step), it can never mine — its own mark, or a dead dependency — so
    /// its value is [`Replan`](AdvanceStep::Replan) territory (a step that names no transaction),
    /// or it is an expired PREPARATION, whose remediation is a new signing ceremony over its
    /// dependent subtree rather than any single step.
    ///
    /// The height is a floor, not an appointment: each step's serviceability guard is
    /// upward-closed in the target height, so the least target satisfying it is well-defined —
    /// but chain-driven guards (dependencies mining, the doomed-window withhold resolving) are
    /// the caller's to judge. Per step, the floor is the least target at which the guard holds: a
    /// transfer's proof once its drawn boundary sits at least
    /// [`PROVABLE_ANCHOR_DEPTH`](crate::scheduling::PROVABLE_ANCHOR_DEPTH) blocks below the
    /// scanned tip (`boundary + PROVABLE_ANCHOR_DEPTH + 1`), a preparation's proof and any
    /// broadcast at the scheduled height, a
    /// rebuild at the lapse's first observability (`expiry_height + 1`), and a reported
    /// transaction's reevaluation at the first scanned target resting at its reported tip
    /// (`reported + 1`). Dispositions are judged in [`Self::transaction_statuses`]' blocker
    /// precedence (unsatisfiable, then a standing report, then expiry, then the lifecycle), so
    /// the floor, the status view, and the kernel's queues tell one story. An
    /// `AwaitingSignature` transaction's next STEP is its proof — signature application is the
    /// consumer's own flow, not an advance step — matching [`Self::sync_wakeup_schedule`].
    fn step_floor(
        &self,
        t: &MigrationTransaction,
        targets: DuenessTargets,
        dead: &BTreeSet<MigrationTransferId>,
    ) -> Option<(StepKind, BlockHeight)> {
        // Mined is final: nothing is ever asked of the transaction again.
        if matches!(t.state, MigrationTxState::Mined { .. }) {
            return None;
        }
        // The unsatisfiable determination, exactly as `transaction_statuses` renders
        // `Blocker::Unsatisfiable`. Expiry ALONE deliberately does not route here, though it
        // seeds the dead set: an expired but otherwise-live transfer's next step is its rebuild,
        // below.
        if t.unsatisfiable.is_some() || t.depends_on.iter().any(|d| dead.contains(d)) {
            return None;
        }
        // A standing report withholds the transaction until the drive API can adjudicate it,
        // which needs the wallet's answers resting at or above the reported tip. Ahead of
        // expiry, as in the status view: being actively withheld on another observer's testimony
        // is the more specific thing to report.
        if let Some(reported) = t.broadcast_failure_at {
            return Some((StepKind::Reevaluate, reported + 1));
        }
        // A lapse the wallet's own scan supports: a transfer's remedy is its rebuild; an expired
        // preparation has no single-transaction step (see `Blocker::Expired`).
        if Self::is_expired(t, targets.scanned()) {
            return match t.kind {
                MigrationTxKind::Transfer { .. } => Some((StepKind::Rebuild, t.expiry_height + 1)),
                MigrationTxKind::Preparation { .. } => None,
            };
        }
        match t.state {
            MigrationTxState::Signed | MigrationTxState::AwaitingSignature => Some((
                StepKind::Prove,
                match t.anchor_boundary {
                    Some(boundary) => boundary + (scheduling::PROVABLE_ANCHOR_DEPTH + 1),
                    None => t.scheduled_height,
                },
            )),
            MigrationTxState::Proved => Some((StepKind::Broadcast, t.scheduled_height)),
            MigrationTxState::Broadcast { .. } | MigrationTxState::Mined { .. } => None,
        }
    }

    /// The step that will next become serviceable, as the kind of work it is and the earliest
    /// target height at which the kernel could name it: the OUTLOOK the drive API returns
    /// alongside each step ([`Advance`](crate::satisfiability::Advance) documents the consumer
    /// contract). `set_aside` carries the drive loop's call-local deferrals, exactly as for
    /// [`Self::next_step`]: a candidate answered "not yet satisfiable" is chain-gated — retry
    /// after further sync — so it must not resurface as a schedulable outlook either.
    ///
    /// When the kernel already has actionable work at these targets, the outlook is that step's
    /// kind at its own floor ([`Self::step_floor`]; the migration-level
    /// [`Replan`](AdvanceStep::Replan), which no height gates, is served at the current target).
    /// When the kernel reports [`Waiting`](AdvanceStep::Waiting), the outlook looks PAST the
    /// current targets: the earliest per-transaction floor among the transactions whose
    /// serviceability is HEIGHT-gated — live, dependencies mined, and not withheld in the doomed
    /// window — with ties broken by the queue order the kernel would serve them in (broadcast,
    /// prove, rebuild) and then by id. A transaction gated on chain events (dependencies still
    /// mining, a doomed-window withhold the scan must resolve) contributes nothing: no height
    /// makes it serviceable, and the consumer's ordinary sync-and-drive loop is what discovers
    /// it. `None` therefore means nothing is height-schedulable: what follows is chain-driven or
    /// user-driven, or the migration is terminal.
    pub(crate) fn upcoming_step(
        &self,
        targets: DuenessTargets,
        set_aside: &[MigrationTransferId],
    ) -> Option<(BlockHeight, StepKind)> {
        match self.next_step(targets, set_aside) {
            AdvanceStep::Complete => None,
            // The kernel never returns `Reevaluate` (the drive API owns that slot), but it is a
            // step like any other here, and matching it explicitly keeps that fact from resting
            // on the absence of an arm.
            AdvanceStep::Reevaluate => None,
            // No height gates a replan: it is serviceable the moment it is decided.
            AdvanceStep::Replan => Some((targets.effective(), StepKind::Replan)),
            step @ (AdvanceStep::Prove { .. }
            | AdvanceStep::Broadcast { .. }
            | AdvanceStep::Rebuild { .. }) => {
                let id = match &step {
                    // The set orders earliest-ready first, and readiness order is floor order,
                    // so the first member carries the step's own floor.
                    AdvanceStep::Prove { transactions } => transactions.first()?.id,
                    AdvanceStep::Broadcast { id } | AdvanceStep::Rebuild { id } => *id,
                    _ => unreachable!("matched an actionable step"),
                };
                let dead = self.dead_set(targets);
                self.transactions
                    .iter()
                    .find(|t| t.id == id)
                    .and_then(|t| self.step_floor(t, targets, &dead))
                    .map(|(kind, height)| (height, kind))
            }
            AdvanceStep::Waiting => {
                let dead = self.dead_set(targets);
                self.transactions
                    .iter()
                    .filter(|t| !set_aside.contains(&t.id))
                    // Chain-gated, not height-gated: no wake-up height serves a transaction
                    // whose dependencies are still mining, and a doomed-window withhold
                    // (`scanned <= expiry < effective`) resolves by scan — into either a
                    // rebuild or a resumed broadcast — not by any target being reached.
                    .filter(|t| self.deps_mined(&t.depends_on))
                    .filter(|t| !Self::is_expired(t, targets.effective()))
                    .filter_map(|t| self.step_floor(t, targets, &dead).map(|f| (t.id, f)))
                    // The earliest floor; at equal heights, the queue order the kernel serves
                    // (broadcast, then prove, then rebuild), then id, so the outlook is
                    // deterministic and agrees with what the wake-up's own call will name.
                    .min_by_key(|(id, (kind, height))| {
                        let rank = match kind {
                            StepKind::Broadcast => 0u8,
                            StepKind::Prove => 1,
                            StepKind::Rebuild => 2,
                            _ => 3,
                        };
                        (*height, rank, *id)
                    })
                    .map(|(_, (kind, height))| (height, kind))
            }
        }
    }

    /// Builds the per-transaction status view at the caller's [`DuenessTargets`], so a wallet can
    /// render progress and decide, deterministically and from persisted state alone, the next
    /// transaction to sign or broadcast.
    ///
    /// A `Signed` transaction whose dependencies are mined and whose anchor is resolvable (a
    /// transfer's drawn boundary has settled; a preparation is due on its schedule) is ready to
    /// prove; a `Proved` one whose scheduled height has arrived is ready to broadcast. Otherwise a
    /// waiting transaction reports what it is blocked on: its dependencies (a preparation still to
    /// mine), an anchor boundary yet to settle, the broadcast schedule, or an external signature —
    /// or, dominating those, that its expiry has probably passed
    /// ([`Blocker::ExpiryImminent`]), that it has verifiably expired ([`Blocker::Expired`]), that
    /// a rejected broadcast is awaiting reevaluation ([`Blocker::AwaitingReevaluation`]), or,
    /// dominating everything, that it is unsatisfiable ([`Blocker::Unsatisfiable`]).
    ///
    /// This view AGREES WITH THE KERNEL by construction: a transaction is reported `ready` with
    /// [`NextAction::Broadcast`] exactly when
    /// [`advance_migration`](crate::satisfiability::advance_migration) would offer its broadcast,
    /// so the sync-gate predicate a consumer writes over these statuses (`ready() && action() ==
    /// Some(NextAction::Broadcast)`) never wakes a broadcast session the drive API would then
    /// refuse. In particular the two read the same fields for the same purposes: the
    /// [`Expired`](Blocker::Expired) determination and the dead set at
    /// [`scanned`](DuenessTargets::scanned), the schedule and the doomed-broadcast withhold at
    /// [`effective`](DuenessTargets::effective).
    pub fn transaction_statuses(&self, targets: DuenessTargets) -> Vec<TransactionStatus> {
        // The transitively-closed dead set, needed to recognize a transaction whose own inputs
        // are intact but whose dependency can never mine.
        let dead = self.dead_set(targets);
        self.transactions
            .iter()
            .map(|t| {
                let deps_ok = self.deps_mined(&t.depends_on);
                // A transaction determined UNSATISFIABLE — its own mark (`unsatisfiable`), or a
                // dependency that can never mine — dominates every
                // other disposition: ahead of Expired, because expiry's remedy (a rebuild)
                // cannot cure missing inputs, and ahead of the state match, because even an
                // in-flight `Broadcast` row with a dead dependency can never mine. Expiry ALONE
                // deliberately does NOT route here, though it seeds the dead set: an expired but
                // otherwise-live transaction keeps reporting `Expired`, whose rebuild remedy
                // still applies. A mined transaction is final and never dead, so the Mined arm
                // below is undisturbed.
                let unsatisfiable = !matches!(t.state, MigrationTxState::Mined { .. })
                    && (t.unsatisfiable.is_some() || t.depends_on.iter().any(|d| dead.contains(d)));
                // The rendering detail behind `Blocker::Unsatisfiable`, and populated only with
                // it. A transaction stranded behind a merely DERIVED-dead dependency (one expired
                // and unmined, whose deadness is never stored) carries no mark of its own, and
                // `Inherited` is exactly its situation: nothing was observed about it.
                let unsatisfiable_kind = unsatisfiable.then(|| {
                    t.unsatisfiable
                        .map(|(_, kind)| kind)
                        .unwrap_or(UnsatisfiableKind::Inherited)
                });
                // A transaction whose broadcast a node REJECTED, with the rejection not yet
                // adjudicated against the wallet's own view (`report_broadcast_failure`). It is
                // reported behind the unsatisfiable determination above — which may well be what
                // the adjudication just recorded about this very transaction — and ahead of
                // expiry and every state-derived blocker below, because being actively withheld
                // from the broadcast queue is more specific than any of the reasons a broadcast
                // is merely pending. Guarded on non-mined for the same reason the determination
                // above is: a mined transaction is final and never carries a blocker (its own
                // `mark_mined` discharges any report, so only a store handing back an
                // already-mined reported row could reach this).
                let awaiting_reevaluation = !matches!(t.state, MigrationTxState::Mined { .. })
                    && t.broadcast_failure_at.is_some();
                // An expired transaction (not yet mined, past its expiry height as the wallet's own
                // scan can see) can never be mined and must be rebuilt; report that ahead of any
                // other blocker, so a wallet shows it as needing attention rather than as waiting
                // on a dependency or the schedule. Behind it, the doomed window: an expiry the
                // ESTIMATE has passed but the scan has not (`scanned <= expiry < effective`). The
                // kernel withholds such a transaction from the broadcast and prove queues without
                // recording anything, so it is reported as neither `ready` nor actionable — which
                // is what keeps a status-driven consumer from waking a broadcast session
                // `advance_migration` would refuse — but under a blocker of its own, because
                // calling it `Expired` would render a determination nothing has made. The two are
                // disjoint by construction: `effective >= scanned`, so an expiry below `scanned`
                // takes the arm above.
                let (ready, action, blocked_on) = if unsatisfiable {
                    (false, None, Some(Blocker::Unsatisfiable))
                } else if awaiting_reevaluation {
                    (false, None, Some(Blocker::AwaitingReevaluation))
                } else if Self::is_expired(t, targets.scanned()) {
                    (false, None, Some(Blocker::Expired))
                } else if Self::is_expired(t, targets.effective()) {
                    (false, None, Some(Blocker::ExpiryImminent))
                } else {
                    // `Signed`/`Proved` transactions are actionable only once their dependencies (the
                    // preparation layers that mint their inputs) are mined and they are due.
                    match t.state {
                        // Built for an external signer and waiting for its signed PCZT; the wallet's
                        // automatic driver takes no action (the external-signing caller drives it via
                        // `apply_signature`), so it is neither ready nor blocked on the chain.
                        MigrationTxState::AwaitingSignature => {
                            (false, None, Some(Blocker::Signature))
                        }
                        // Pre-signed and awaiting proof: ready to PROVE once its anchor is resolvable (a
                        // transfer's boundary has settled, or a preparation is due). Not yet proved, so
                        // not yet broadcast.
                        MigrationTxState::Signed => {
                            if !deps_ok {
                                (false, None, Some(Blocker::Dependencies))
                            } else if self.prove_ready(t, targets) {
                                (true, Some(NextAction::Prove), None)
                            } else {
                                // Deps mined but not prove-ready: a transfer waiting for its anchor
                                // boundary to settle, or a preparation not yet due on its schedule.
                                let blocker = match t.anchor_boundary {
                                    Some(_) => Blocker::AnchorBoundary,
                                    None => Blocker::Schedule,
                                };
                                (false, None, Some(blocker))
                            }
                        }
                        // Proved and awaiting broadcast: ready to BROADCAST once its scheduled height has
                        // arrived, otherwise waiting on the broadcast schedule.
                        MigrationTxState::Proved => {
                            if !deps_ok {
                                (false, None, Some(Blocker::Dependencies))
                            } else if t.scheduled_height <= targets.effective() {
                                (true, Some(NextAction::Broadcast), None)
                            } else {
                                (false, None, Some(Blocker::Schedule))
                            }
                        }
                        MigrationTxState::Broadcast { .. } => (false, None, None),
                        MigrationTxState::Mined { .. } => (false, None, None),
                    }
                };
                let txid = match t.state {
                    MigrationTxState::Broadcast { txid } | MigrationTxState::Mined { txid, .. } => {
                        Some(txid)
                    }
                    _ => None,
                };
                let mined_height = match t.state {
                    MigrationTxState::Mined { height, .. } => Some(height),
                    _ => None,
                };
                TransactionStatus {
                    id: t.id,
                    kind: t.kind,
                    state: t.state,
                    depends_on: t.depends_on.clone(),
                    scheduled_height: t.scheduled_height,
                    expiry_height: t.expiry_height,
                    ready,
                    action,
                    blocked_on,
                    unsatisfiable_kind,
                    mined_height,
                    txid,
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::MigrationTransaction;
    use crate::satisfiability::UnsatisfiableCause;
    use zcash_protocol::value::Zatoshis;

    use crate::denomination::DenominationPlan;
    use crate::preparation::PreparationPlan;
    use alloc::vec;

    use crate::scheduling::WakeupParams;
    use rand_chacha::ChaCha8Rng;
    use rand_core::SeedableRng;

    // A DIRECT unsatisfiability mark resting on the chain state at `height`, in the shape
    // `record_satisfiability` writes for an observed spend. Wherever only the stamp is under test,
    // which observation it records is immaterial — but a mark always has one.
    fn marked(height: u32) -> Option<(BlockHeight, UnsatisfiableKind)> {
        Some((
            BlockHeight::from_u32(height),
            UnsatisfiableKind::InputsSpent,
        ))
    }

    // A migration transaction with the given id/kind/state, no dependencies, scheduled at height 0.
    fn tx(id: u32, kind: MigrationTxKind, state: MigrationTxState) -> MigrationTransaction {
        // The row's id, and the copy any lifecycle state carries, are one value by construction:
        // production derives both from the built PCZT, so a fixture that let them differ would be
        // describing a state the engine cannot produce.
        let txid = TxId::from_bytes([id as u8; 32]);
        let state = match state {
            MigrationTxState::Broadcast { .. } => MigrationTxState::Broadcast { txid },
            MigrationTxState::Mined { height, .. } => MigrationTxState::Mined { txid, height },
            other => other,
        };
        MigrationTransaction {
            id: MigrationTransferId(id),
            kind,
            pczt: Vec::new(),
            depends_on: Vec::new(),
            scheduled_height: BlockHeight::from_u32(0),
            expiry_height: BlockHeight::from_u32(0),
            anchor_boundary: None,
            txid,
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

    // One member of an expected `Prove` batch.
    fn pt(id: u32, kind: MigrationTxKind) -> ProveTarget {
        ProveTarget {
            id: MigrationTransferId(id),
            kind,
        }
    }

    // A state wrapping the given transactions; the plan pieces are empty (unused by state logic).
    fn state_with(transactions: Vec<MigrationTransaction>) -> MigrationState {
        MigrationState {
            status: MigrationStatus::Committed,
            denominations: DenominationPlan::from_stored_parts(
                Vec::new(),
                Zatoshis::ZERO,
                None,
                Zatoshis::ZERO,
                Zatoshis::ZERO,
                Zatoshis::ZERO,
            )
            .expect("an empty stored plan reconstructs"),
            preparation: PreparationPlan::from_parts(Vec::new(), Vec::new()),
            transactions,
            anchor_bucket_interval: crate::scheduling::AnchorBucketInterval::ZIP_318,
            replan_threshold: crate::satisfiability::ReplanThreshold::DEFAULT,
        }
    }

    fn mined(height: u32) -> MigrationTxState {
        MigrationTxState::Mined {
            txid: TxId::from_bytes([0; 32]),
            height: BlockHeight::from_u32(height),
        }
    }

    /// A state whose denomination plan carries the given crossing values and fee buffer, so the
    /// funding notes are each crossing plus the buffer.
    fn state_with_crossings(
        crossings: &[u64],
        buffer: u64,
        transactions: Vec<MigrationTransaction>,
    ) -> MigrationState {
        let zats = |v: u64| Zatoshis::from_u64(v).expect("test values are valid");
        let total = zats(crossings.iter().sum());
        MigrationState {
            status: MigrationStatus::Committed,
            denominations: DenominationPlan::from_stored_parts(
                crossings.iter().copied().map(zats).collect(),
                zats(buffer),
                None,
                Zatoshis::ZERO,
                total,
                total,
            )
            .expect("a consistent stored plan reconstructs"),
            preparation: PreparationPlan::from_parts(Vec::new(), Vec::new()),
            transactions,
            anchor_bucket_interval: crate::scheduling::AnchorBucketInterval::ZIP_318,
            replan_threshold: crate::satisfiability::ReplanThreshold::DEFAULT,
        }
    }

    /// A transfer reports what it MOVES (its crossing value), not what it spends: the funding note
    /// it spends is that value plus the fee buffer funding its own fee, and reporting the spend
    /// side overstates every transfer by a fee.
    #[test]
    fn transfer_crossing_value_is_the_funding_note_less_the_fee_buffer() {
        let buffer = 15_000;
        let crossings = [100_000_000u64, 200_000_000];
        let state = state_with_crossings(
            &crossings,
            buffer,
            vec![
                tx(0, prep(0, 0), mined(10)),
                tx(1, transfer(0), MigrationTxState::Signed),
                tx(2, transfer(1), MigrationTxState::Signed),
            ],
        );

        for (i, &crossing) in crossings.iter().enumerate() {
            let tx = &state.transactions[i + 1];
            assert_eq!(
                state.transfer_crossing_value(tx),
                Some(Zatoshis::from_u64(crossing).expect("valid")),
                "transfer {i} must report its crossing value"
            );
            assert_eq!(
                state.funding_notes()[i],
                Zatoshis::from_u64(crossing + buffer).expect("valid"),
                "the funding note it spends is that value plus the buffer"
            );
        }
    }

    /// A preparation transaction crosses nothing, so it has no crossing value to report.
    #[test]
    fn transfer_crossing_value_is_none_for_a_preparation() {
        let state = state_with_crossings(
            &[100_000_000],
            15_000,
            vec![tx(0, prep(0, 0), MigrationTxState::Signed)],
        );
        assert_eq!(
            state.transfer_crossing_value(&state.transactions[0]),
            None,
            "a preparation transaction crosses nothing"
        );
    }

    #[test]
    fn replan_required_crosses_the_stamped_threshold_strictly() {
        // Crossings 20 + 80: the 20-crossing alone is exactly 20% — NOT more than the threshold.
        let mut s = state_with_crossings(
            &[20_000_000, 80_000_000],
            15_000,
            vec![
                tx(0, prep(0, 0), mined(10)),
                tx(1, transfer(0), MigrationTxState::Signed),
                tx(2, transfer(1), MigrationTxState::Signed),
            ],
        );
        assert!(!s.replan_required());
        s.transactions[1].unsatisfiable = marked(50);
        assert!(
            !s.replan_required(),
            "exactly at threshold is not MORE than it"
        );
        s.transactions[2].unsatisfiable = marked(50);
        assert!(s.replan_required());
        // A mined transfer counts in the denominator only: un-mark the 80-crossing and mine it;
        // the marked 20-crossing is back to exactly 20%.
        s.transactions[2].unsatisfiable = None;
        s.transactions[2].state = mined(60);
        assert!(!s.replan_required());
    }

    /// The two [`ReplanThreshold`](crate::satisfiability::ReplanThreshold) endpoints have distinct
    /// meanings, and a marked preparation never contributes to the numerator (only its funded
    /// transfers can).
    #[test]
    fn replan_required_threshold_endpoints_and_preparation_exemption() {
        // Threshold 0: nothing marked yet, so nothing triggers.
        let mut zero = state_with_crossings(
            &[20_000_000, 80_000_000],
            15_000,
            vec![
                tx(0, prep(0, 0), MigrationTxState::Signed),
                tx(1, transfer(0), MigrationTxState::Signed),
                tx(2, transfer(1), MigrationTxState::Signed),
            ],
        );
        zero.replan_threshold = crate::satisfiability::ReplanThreshold::new(0).expect("0 is valid");
        assert!(!zero.replan_required(), "nothing marked yet");

        // Marking the UNMINED PREPARATION contributes nothing to the numerator: a preparation
        // crosses nothing (see `transfer_crossing_value_is_none_for_a_preparation`), so even at
        // the most sensitive threshold, marking one alone cannot trigger a replan.
        zero.transactions[0].unsatisfiable = marked(50);
        assert!(
            !zero.replan_required(),
            "a marked preparation contributes nothing to the numerator"
        );

        // Marking a transfer, however small its crossing value, DOES trigger at threshold 0: any
        // marked unmined transfer value is more than zero.
        zero.transactions[1].unsatisfiable = marked(50);
        assert!(zero.replan_required());

        // Threshold 100: even with EVERY transfer marked, `unsat == total`, and the comparison is
        // strict, so an immediate replan is never triggered — only draining to completion (or a
        // policy change) can resolve a fully-unsatisfiable migration under this threshold.
        let mut hundred = state_with_crossings(
            &[20_000_000, 80_000_000],
            15_000,
            vec![
                tx(0, prep(0, 0), MigrationTxState::Signed),
                tx(1, transfer(0), MigrationTxState::Signed),
                tx(2, transfer(1), MigrationTxState::Signed),
            ],
        );
        hundred.replan_threshold =
            crate::satisfiability::ReplanThreshold::new(100).expect("100 is valid");
        hundred.transactions[1].unsatisfiable = marked(50);
        hundred.transactions[2].unsatisfiable = marked(50);
        assert!(
            !hundred.replan_required(),
            "threshold 100 never triggers immediately, even when everything is marked"
        );
    }

    #[test]
    fn apply_signature_moves_awaiting_to_signed() {
        let mut state = state_with(vec![tx(0, prep(0, 0), MigrationTxState::AwaitingSignature)]);
        assert!(state.apply_signature(MigrationTransferId(0), vec![1u8, 2, 3]));
        assert_eq!(state.transactions[0].state, MigrationTxState::Signed);
        assert_eq!(state.transactions[0].pczt, vec![1u8, 2, 3]);
    }

    #[test]
    fn apply_signature_rejects_unknown_or_wrong_state() {
        let mut state = state_with(vec![
            tx(0, prep(0, 0), MigrationTxState::AwaitingSignature),
            tx(1, transfer(0), MigrationTxState::Signed),
        ]);
        // An unknown id, and a transaction not awaiting a signature (already signed), are both
        // rejected without changing any state.
        assert!(!state.apply_signature(MigrationTransferId(9), vec![1u8]));
        assert!(!state.apply_signature(MigrationTransferId(1), vec![1u8]));
        assert_eq!(
            state.transactions[0].state,
            MigrationTxState::AwaitingSignature
        );
        // The first signature applies; a second, after it is already Signed, is rejected (a stale or
        // misrouted signature cannot overwrite the stored one).
        assert!(state.apply_signature(MigrationTransferId(0), vec![1u8]));
        assert!(!state.apply_signature(MigrationTransferId(0), vec![2u8]));
        assert_eq!(state.transactions[0].pczt, vec![1u8]);
    }

    #[test]
    fn awaiting_signature_is_blocked_on_signature() {
        let state = state_with(vec![tx(0, prep(0, 0), MigrationTxState::AwaitingSignature)]);
        let views = state.transaction_statuses(DuenessTargets::at(BlockHeight::from_u32(100)));
        assert!(!views[0].ready);
        assert_eq!(views[0].action, None);
        assert_eq!(views[0].blocked_on, Some(Blocker::Signature));
    }

    #[test]
    fn deps_and_preparation_mining() {
        let s = state_with(vec![
            tx(0, prep(0, 0), mined(10)),
            tx(1, prep(0, 1), MigrationTxState::Signed),
        ]);
        assert!(s.deps_mined(&[MigrationTransferId(0)]));
        assert!(!s.deps_mined(&[MigrationTransferId(1)]));
        assert!(s.deps_mined(&[])); // empty deps are trivially satisfied
    }

    #[test]
    fn next_broadcastable_respects_state_deps_and_schedule() {
        // Only a PROVED transaction is broadcastable (proving is a separate earlier step).
        let mut proved = tx(1, transfer(0), MigrationTxState::Proved);
        proved.depends_on = vec![MigrationTransferId(0)];
        proved.scheduled_height = BlockHeight::from_u32(5);
        let mut s = state_with(vec![tx(0, prep(0, 0), mined(10)), proved]);

        // Not due yet (target below scheduled height).
        assert_eq!(
            s.next_broadcastable(
                DuenessTargets::at(BlockHeight::from_u32(4)),
                &BTreeSet::new(),
                &[]
            ),
            None
        );
        // Due and deps mined.
        assert_eq!(
            s.next_broadcastable(
                DuenessTargets::at(BlockHeight::from_u32(5)),
                &BTreeSet::new(),
                &[]
            ),
            Some(MigrationTransferId(1))
        );

        // A Signed (not yet proved) transaction is NOT broadcastable: it must be proved first.
        s.transactions[1].state = MigrationTxState::Signed;
        assert_eq!(
            s.next_broadcastable(
                DuenessTargets::at(BlockHeight::from_u32(5)),
                &BTreeSet::new(),
                &[]
            ),
            None
        );

        // Dependency not mined: not broadcastable even when Proved.
        s.transactions[1].state = MigrationTxState::Proved;
        s.transactions[0].state = MigrationTxState::Broadcast {
            txid: TxId::from_bytes([0; 32]),
        };
        assert_eq!(
            s.next_broadcastable(
                DuenessTargets::at(BlockHeight::from_u32(5)),
                &BTreeSet::new(),
                &[]
            ),
            None
        );
    }

    /// Each queue offers the candidate that has been READY longest, not the first one stored: the
    /// vector is in dependency order, which a rebuild breaks by rescheduling a transfer in place.
    /// Readiness differs per queue, so the two transfers here are deliberately ordered one way by
    /// anchor boundary and the other way by schedule.
    #[test]
    fn queues_offer_the_longest_ready_candidate() {
        let mut s = state_with(vec![
            scheduled_transfer(0, 0, 100, 500, MigrationTxState::Proved),
            scheduled_transfer(1, 1, 150, 200, MigrationTxState::Proved),
        ]);
        let due = DuenessTargets::at(BlockHeight::from_u32(600));

        // Broadcast: due longest, so by schedule (transfer 1), though it is stored second.
        assert_eq!(
            s.next_broadcastable(due, &BTreeSet::new(), &[]),
            Some(MigrationTransferId(1))
        );
        // Setting it aside falls through by schedule, not by position.
        assert_eq!(
            s.next_broadcastable(due, &BTreeSet::new(), &[MigrationTransferId(1)]),
            Some(MigrationTransferId(0))
        );

        // Prove: the whole ready set at once, ordered by ANCHOR BOUNDARY (transfer 0 first) —
        // the opposite order.
        s.transactions[0].state = MigrationTxState::Signed;
        s.transactions[1].state = MigrationTxState::Signed;
        assert_eq!(
            s.provable_targets(due, &BTreeSet::new(), &[]),
            vec![pt(0, transfer(0)), pt(1, transfer(1))]
        );
        assert_eq!(
            s.provable_targets(due, &BTreeSet::new(), &[MigrationTransferId(0)]),
            vec![pt(1, transfer(1))]
        );

        // Rebuild: expired longest, so by schedule again. Give both an expiry the target passed.
        s.transactions[0].expiry_height = BlockHeight::from_u32(550);
        s.transactions[1].expiry_height = BlockHeight::from_u32(250);
        assert_eq!(
            s.next_rebuildable(due, &BTreeSet::new(), &[]),
            Some(MigrationTransferId(1))
        );
        // Rebuilding transfer 1 reschedules it past transfer 0 while keeping its slot, so the
        // stored-order candidate and the schedule-order candidate now differ.
        s.transactions[1].scheduled_height = BlockHeight::from_u32(900);
        s.transactions[1].expiry_height = BlockHeight::from_u32(950);
        assert_eq!(
            s.next_rebuildable(due, &BTreeSet::new(), &[]),
            Some(MigrationTransferId(0))
        );
    }

    /// Equal scheduled heights tie-break on id, so the decision does not depend on the order a
    /// store read the transactions back in.
    #[test]
    fn equal_schedules_tie_break_on_id() {
        let s = state_with(vec![
            scheduled_transfer(7, 0, 10, 200, MigrationTxState::Proved),
            scheduled_transfer(3, 1, 10, 200, MigrationTxState::Proved),
        ]);
        assert_eq!(
            s.next_broadcastable(
                DuenessTargets::at(BlockHeight::from_u32(600)),
                &BTreeSet::new(),
                &[]
            ),
            Some(MigrationTransferId(3))
        );
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

    /// Only transfers still needing a proof are scheduled: preparations and already-proved,
    /// broadcast, or mined transfers contribute no wake-ups; a not-yet-signed transfer still needs
    /// its wake-up once its signature arrives.
    #[test]
    fn sync_wakeup_schedule_filters_lifecycle_states() {
        let state = state_with(vec![
            tx(0, prep(0, 0), MigrationTxState::Signed),
            scheduled_transfer(1, 0, 1440, 1700, MigrationTxState::Signed),
            scheduled_transfer(2, 1, 1584, 1800, MigrationTxState::AwaitingSignature),
            scheduled_transfer(3, 2, 2880, 3100, MigrationTxState::Proved),
            scheduled_transfer(
                4,
                3,
                2880,
                3100,
                MigrationTxState::Broadcast {
                    txid: TxId::from_bytes([9; 32]),
                },
            ),
            scheduled_transfer(5, 4, 2880, 3100, mined(3000)),
        ]);
        let mut r = ChaCha8Rng::seed_from_u64(1);
        let wakeups = state
            .sync_wakeup_schedule(
                BlockHeight::from_u32(100),
                &WakeupParams::new(10, 0),
                &mut r,
            )
            .expect("feasible");
        // Windows [1450, 1699] and [1594, 1799] overlap: one wake-up covers both pending
        // transfers; everything else is filtered out.
        assert_eq!(wakeups.len(), 1);
        assert_eq!(u32::from(wakeups[0].height()), 1594);
        assert_eq!(
            wakeups[0].covers(),
            &[MigrationTransferId(1), MigrationTransferId(2)]
        );
    }

    /// An expired transfer is excluded (its rebuild reschedules it and the schedule is recomputed);
    /// an overdue-but-unexpired transfer collapses into an immediate wake-up at the current tip.
    #[test]
    fn sync_wakeup_schedule_overdue_and_expired() {
        let mut expired = scheduled_transfer(0, 0, 144, 400, MigrationTxState::Signed);
        expired.expiry_height = BlockHeight::from_u32(999);
        let state = state_with(vec![
            expired, // expired at tip 2000 (expiry 999 < 2001): excluded entirely
            scheduled_transfer(1, 1, 144, 400, MigrationTxState::Signed), // never expires: overdue
            scheduled_transfer(2, 2, 4320, 4700, MigrationTxState::Signed),
        ]);
        let mut r = ChaCha8Rng::seed_from_u64(1);
        let wakeups = state
            .sync_wakeup_schedule(
                BlockHeight::from_u32(2000),
                &WakeupParams::new(10, 0),
                &mut r,
            )
            .expect("feasible");
        assert_eq!(wakeups.len(), 2);
        assert_eq!(u32::from(wakeups[0].height()), 2000);
        assert_eq!(wakeups[0].covers(), &[MigrationTransferId(1)]);
        assert_eq!(u32::from(wakeups[1].height()), 4330);
        assert_eq!(wakeups[1].covers(), &[MigrationTransferId(2)]);
    }

    #[test]
    fn next_step_walks_the_lifecycle() {
        // Every transaction is pre-signed at commit; the state machine orders proving then
        // broadcasting, respecting the anchor-bucket dependency order: prove-then-broadcast layer 0,
        // then layer 1 once layer 0 mines, then the transfer once the whole preparation mines. Each
        // transaction is PROVED (`Signed -> Proved`) before it is broadcast.
        let mut l1 = tx(1, prep(1, 0), MigrationTxState::Signed);
        l1.depends_on = vec![MigrationTransferId(0)];
        let mut xfer = tx(2, transfer(0), MigrationTxState::Signed);
        xfer.depends_on = vec![MigrationTransferId(1)];
        let mut s = state_with(vec![tx(0, prep(0, 0), MigrationTxState::Signed), l1, xfer]);

        // 1) Layer 0 is signed and due -> prove it first, then broadcast it once proved.
        assert_eq!(
            s.next_step(DuenessTargets::at(BlockHeight::from_u32(100)), &[]),
            AdvanceStep::Prove {
                transactions: vec![pt(0, prep(0, 0))],
            }
        );
        s.transactions[0].state = MigrationTxState::Proved;
        assert_eq!(
            s.next_step(DuenessTargets::at(BlockHeight::from_u32(100)), &[]),
            AdvanceStep::Broadcast {
                id: MigrationTransferId(0)
            }
        );

        // 2) Layer 0 broadcast, not yet mined -> its dependents stay blocked, waiting.
        s.transactions[0].state = MigrationTxState::Broadcast {
            txid: TxId::from_bytes([1; 32]),
        };
        assert_eq!(
            s.next_step(DuenessTargets::at(BlockHeight::from_u32(100)), &[]),
            AdvanceStep::Waiting
        );

        // 3) Layer 0 mined -> layer 1 becomes provable, then broadcastable.
        s.transactions[0].state = mined(10);
        assert_eq!(
            s.next_step(DuenessTargets::at(BlockHeight::from_u32(100)), &[]),
            AdvanceStep::Prove {
                transactions: vec![pt(1, prep(1, 0))],
            }
        );
        s.transactions[1].state = MigrationTxState::Proved;
        assert_eq!(
            s.next_step(DuenessTargets::at(BlockHeight::from_u32(100)), &[]),
            AdvanceStep::Broadcast {
                id: MigrationTransferId(1)
            }
        );

        // 4) Layer 1 mined -> the transfer becomes provable, then broadcastable.
        s.transactions[1].state = mined(11);
        assert_eq!(
            s.next_step(DuenessTargets::at(BlockHeight::from_u32(100)), &[]),
            AdvanceStep::Prove {
                transactions: vec![pt(2, transfer(0))],
            }
        );
        s.transactions[2].state = MigrationTxState::Proved;
        assert_eq!(
            s.next_step(DuenessTargets::at(BlockHeight::from_u32(100)), &[]),
            AdvanceStep::Broadcast {
                id: MigrationTransferId(2)
            }
        );

        // 5) Everything mined -> complete.
        s.transactions[2].state = mined(12);
        assert_eq!(
            s.next_step(DuenessTargets::at(BlockHeight::from_u32(100)), &[]),
            AdvanceStep::Complete
        );
    }

    #[test]
    fn next_step_waiting_when_schedule_not_reached() {
        let mut xfer = tx(1, transfer(0), MigrationTxState::Signed);
        xfer.scheduled_height = BlockHeight::from_u32(50);
        let s = state_with(vec![tx(0, prep(0, 0), mined(10)), xfer]);
        // The transfer is signed with deps mined but not due yet -> nothing else to do, waiting.
        assert_eq!(
            s.next_step(DuenessTargets::at(BlockHeight::from_u32(20)), &[]),
            AdvanceStep::Waiting
        );
        // Once due, the first step on a still-`Signed` transaction is to PROVE it (broadcasting is a
        // separate later step, once proved).
        assert_eq!(
            s.next_step(DuenessTargets::at(BlockHeight::from_u32(50)), &[]),
            AdvanceStep::Prove {
                transactions: vec![pt(1, transfer(0))],
            }
        );
    }

    /// `shift_schedule` moves every PENDING schedule forward by the same delta — preserving the
    /// inter-broadcast gaps — and leaves served schedules (in-flight and mined rows) and every
    /// expiry height untouched. A deferred transfer whose proof is still to come has its anchor
    /// boundary REDRAWN in-distribution against its shifted schedule; a proved transfer's proof
    /// pins its anchor, and a preparation carries none.
    #[test]
    fn shift_schedule_moves_only_pending_schedules() {
        let mut s = state_with(vec![
            tx(0, prep(0, 0), MigrationTxState::AwaitingSignature),
            tx(1, prep(0, 1), MigrationTxState::Signed),
            tx(2, transfer(0), MigrationTxState::Proved),
            tx(
                3,
                transfer(1),
                MigrationTxState::Broadcast {
                    txid: TxId::from_bytes([3; 32]),
                },
            ),
            tx(4, transfer(2), mined(500)),
            tx(5, transfer(3), MigrationTxState::Signed),
            tx(6, transfer(4), MigrationTxState::AwaitingSignature),
        ]);
        for (i, h) in [
            (0usize, 100u32),
            (1, 200),
            (2, 300),
            (3, 400),
            (4, 500),
            (5, 600),
            (6, 700),
        ] {
            s.transactions[i].scheduled_height = BlockHeight::from_u32(h);
            s.transactions[i].expiry_height = BlockHeight::from_u32(h + 140_000);
        }
        // The transfers carry drawn boundaries on the ZIP 318 grid (the state's interval);
        // 144 = 1 * 144.
        for i in [2usize, 5, 6] {
            s.transactions[i].anchor_boundary = Some(BlockHeight::from_u32(144));
        }

        s.shift_schedule(100_000, &mut ChaCha8Rng::seed_from_u64(7));

        let scheduled: Vec<u32> = s
            .transactions
            .iter()
            .map(|t| u32::from(t.scheduled_height))
            .collect();
        assert_eq!(
            scheduled,
            vec![100_100, 100_200, 100_300, 400, 500, 100_600, 100_700],
            "pending schedules shift; served ones stay put"
        );
        // Expiry is effecting data, fixed at signing: no shift may touch it.
        let expiries: Vec<u32> = s
            .transactions
            .iter()
            .map(|t| u32::from(t.expiry_height))
            .collect();
        assert_eq!(
            expiries,
            vec![
                140_100, 140_200, 140_300, 140_400, 140_500, 140_600, 140_700
            ]
        );

        // The proved transfer's proof pins its anchor: the boundary is untouched.
        assert_eq!(
            s.transactions[2].anchor_boundary,
            Some(BlockHeight::from_u32(144)),
            "a proved transfer keeps the boundary its proof was built against"
        );
        // The unproved transfers' boundaries are redrawn in-distribution against the SHIFTED
        // schedule: within `ANCHOR_AGE_CAP` (4) buckets strictly below the most recent grid
        // boundary at the new scheduled height. The old boundary sits far outside that window,
        // so the redraw is guaranteed to have replaced it.
        for i in [5usize, 6] {
            let new_schedule = u32::from(s.transactions[i].scheduled_height);
            let most_recent = new_schedule - (new_schedule % 144);
            let boundary = u32::from(s.transactions[i].anchor_boundary.expect("still a transfer"));
            assert_eq!(boundary % 144, 0, "the redrawn boundary is on the grid");
            assert!(
                boundary >= most_recent - 4 * 144 && boundary < most_recent,
                "boundary {boundary} is in-distribution for schedule {new_schedule}"
            );
        }
        // The preparations never carry a boundary, before or after.
        assert_eq!(s.transactions[0].anchor_boundary, None);
        assert_eq!(s.transactions[1].anchor_boundary, None);
    }

    #[test]
    fn mark_transitions_and_status() {
        let mut s = state_with(vec![
            tx(0, prep(0, 0), MigrationTxState::Signed),
            tx(1, transfer(0), MigrationTxState::Signed),
        ]);
        assert_eq!(s.status, MigrationStatus::Committed);

        s.mark_broadcast(MigrationTransferId(0));
        assert!(matches!(
            s.transactions[0].state,
            MigrationTxState::Broadcast { txid } if txid == TxId::from_bytes([0; 32])
        ));
        assert_eq!(s.status, MigrationStatus::InProgress);
        assert!(!s.is_terminal());

        s.mark_mined(MigrationTransferId(0), BlockHeight::from_u32(10));
        s.mark_mined(MigrationTransferId(1), BlockHeight::from_u32(11));
        assert_eq!(s.status, MigrationStatus::Complete);
        assert!(s.is_terminal());
    }

    #[test]
    fn terminal_status_is_not_resurrected() {
        // A cancelled migration (Failed) whose transactions were already broadcast must stay
        // terminal: neither recomputing the status nor asking for the next step may revive it.
        let mut s = state_with(vec![
            tx(
                0,
                prep(0, 0),
                MigrationTxState::Broadcast {
                    txid: TxId::from_bytes([1; 32]),
                },
            ),
            tx(1, transfer(0), MigrationTxState::Signed),
        ]);
        s.status = MigrationStatus::Failed;

        s.recompute_status();
        assert_eq!(
            s.status,
            MigrationStatus::Failed,
            "a Failed (cancelled) migration must not be revived to InProgress"
        );
        assert!(s.is_terminal());

        // The next step for a terminal migration is Complete (no action), so a driver never
        // broadcasts or builds for it; a Signed transaction is NOT offered for broadcast.
        assert_eq!(
            s.next_step(DuenessTargets::at(BlockHeight::from_u32(100)), &[]),
            AdvanceStep::Complete
        );

        // Detecting a mined transaction still does not resurrect it.
        s.mark_mined(MigrationTransferId(0), BlockHeight::from_u32(10));
        assert_eq!(s.status, MigrationStatus::Failed);
    }

    #[test]
    fn mark_superseded_is_terminal_and_policy_stable() {
        let mut s = state_with(vec![tx(0, transfer(0), MigrationTxState::Signed)]);
        s.mark_superseded();
        assert_eq!(s.status, MigrationStatus::Superseded);
        assert!(s.is_terminal());
        // Terminality is never overwritten by policy: a second call and a recompute are no-ops.
        s.mark_superseded();
        s.recompute_status();
        assert_eq!(s.status, MigrationStatus::Superseded);
        // An already-terminal migration is not superseded over.
        let mut done = state_with(vec![tx(0, transfer(0), mined(10))]);
        done.recompute_status();
        assert_eq!(done.status, MigrationStatus::Complete);
        done.mark_superseded();
        assert_eq!(done.status, MigrationStatus::Complete);
        // Nor is a Failed migration: whichever terminal status got there first is the truthful
        // history, and mark_superseded must not overwrite it.
        let mut failed = state_with(vec![tx(0, transfer(0), MigrationTxState::Signed)]);
        failed.status = MigrationStatus::Failed;
        failed.mark_superseded();
        assert_eq!(failed.status, MigrationStatus::Failed);
    }

    /// `mark_cancelled` is a closure operator on the status order: idempotent, landing in the
    /// terminal set, and fixing every status already in it. The three assertions below are those
    /// three laws in order.
    #[test]
    fn mark_cancelled_is_terminal_and_policy_stable() {
        // LANDS IN THE TERMINAL SET.
        let mut s = state_with(vec![tx(0, transfer(0), MigrationTxState::Signed)]);
        s.mark_cancelled();
        assert_eq!(s.status, MigrationStatus::Cancelled);
        assert!(s.is_terminal());

        // IDEMPOTENT, and a recompute does not resurrect it either.
        s.mark_cancelled();
        s.recompute_status();
        assert_eq!(s.status, MigrationStatus::Cancelled);

        // TERMINALITY-PRESERVING: a completed migration is not cancelled over. Its transfers are
        // mined, so saying otherwise would deny work the chain has already accepted.
        let mut done = state_with(vec![tx(0, transfer(0), mined(10))]);
        done.recompute_status();
        assert_eq!(done.status, MigrationStatus::Complete);
        done.mark_cancelled();
        assert_eq!(done.status, MigrationStatus::Complete);

        // Nor a failed one: the post-mortem is the truthful history, and rewriting it to look like
        // a deliberate user action would lose exactly the distinction `Cancelled` exists to draw.
        let mut failed = state_with(vec![tx(0, transfer(0), MigrationTxState::Signed)]);
        failed.status = MigrationStatus::Failed;
        failed.mark_cancelled();
        assert_eq!(failed.status, MigrationStatus::Failed);

        // Nor a superseded one, symmetrically; and cancelling is not superseded over in turn.
        let mut superseded = state_with(vec![tx(0, transfer(0), MigrationTxState::Signed)]);
        superseded.mark_superseded();
        superseded.mark_cancelled();
        assert_eq!(superseded.status, MigrationStatus::Superseded);
        let mut cancelled = state_with(vec![tx(0, transfer(0), MigrationTxState::Signed)]);
        cancelled.mark_cancelled();
        cancelled.mark_superseded();
        assert_eq!(cancelled.status, MigrationStatus::Cancelled);
    }

    /// A cancelled migration whose transactions were already broadcast is not resurrected to
    /// `InProgress` by a status recompute, and detecting one of them mined does not resurrect it
    /// either. This is the case `recompute_status`'s terminal guard exists for, and it is
    /// reachable for `Cancelled` in a way it is not for `Superseded`: the user cancels precisely
    /// when transactions are already in flight.
    #[test]
    fn cancelled_survives_broadcast_and_mining() {
        let mut s = state_with(vec![tx(0, transfer(0), MigrationTxState::Signed)]);
        s.mark_cancelled();
        s.mark_broadcast(MigrationTransferId(0));
        assert_eq!(s.status, MigrationStatus::Cancelled);
        s.mark_mined(MigrationTransferId(0), BlockHeight::from_u32(10));
        assert_eq!(s.status, MigrationStatus::Cancelled);
    }

    #[test]
    fn transaction_statuses_report_ready_and_blockers() {
        let mut l1 = tx(1, prep(1, 0), MigrationTxState::Signed);
        l1.depends_on = vec![MigrationTransferId(0)];
        let mut xfer = tx(2, transfer(0), MigrationTxState::Signed);
        xfer.depends_on = vec![MigrationTransferId(1)];
        xfer.scheduled_height = BlockHeight::from_u32(30);
        let s = state_with(vec![tx(0, prep(0, 0), mined(10)), l1, xfer]);

        let views = s.transaction_statuses(DuenessTargets::at(BlockHeight::from_u32(100)));
        assert_eq!(views.len(), 3);

        // tx 0: mined -> done, not ready, no blocker.
        assert!(!views[0].ready);
        assert_eq!(views[0].blocked_on, None);
        assert_eq!(views[0].mined_height, Some(BlockHeight::from_u32(10)));

        // tx 1: signed with its dependency (tx 0) mined and due -> ready to prove.
        assert!(views[1].ready);
        assert_eq!(views[1].action, Some(NextAction::Prove));
        assert_eq!(views[1].blocked_on, None);

        // tx 2: signed but its dependency (tx 1) is not mined -> blocked on dependencies.
        assert!(!views[2].ready);
        assert_eq!(views[2].blocked_on, Some(Blocker::Dependencies));
    }

    #[test]
    fn transaction_statuses_block_on_schedule() {
        let mut xfer = tx(1, transfer(0), MigrationTxState::Signed);
        xfer.scheduled_height = BlockHeight::from_u32(30);
        let s = state_with(vec![tx(0, prep(0, 0), mined(10)), xfer]);
        // Deps mined but not due at target 20 -> blocked on schedule; ready at target 30.
        let blocked = s.transaction_statuses(DuenessTargets::at(BlockHeight::from_u32(20)));
        assert!(!blocked[1].ready);
        assert_eq!(blocked[1].blocked_on, Some(Blocker::Schedule));
        let ready = s.transaction_statuses(DuenessTargets::at(BlockHeight::from_u32(30)));
        assert!(ready[1].ready);
        assert_eq!(ready[1].action, Some(NextAction::Prove));
    }

    #[test]
    fn transfer_prove_ready_waits_for_its_anchor_boundary() {
        // A transfer anchors to a drawn boundary; it is not provable until the boundary block
        // sits at least `PROVABLE_ANCHOR_DEPTH` blocks below the tip (its checkpoint has
        // settled to reorg stability), decoupled from the broadcast schedule.
        let mut xfer = tx(1, transfer(0), MigrationTxState::Signed);
        xfer.depends_on = vec![MigrationTransferId(0)];
        xfer.anchor_boundary = Some(BlockHeight::from_u32(40));
        xfer.scheduled_height = BlockHeight::from_u32(60);
        let mut s = state_with(vec![tx(0, prep(0, 0), mined(10)), xfer]);

        // `target_height` is `tip + 1`. At tip 49 (target 50) the boundary is only 9 blocks
        // below the tip -> not yet provable, blocked on the anchor boundary.
        assert_eq!(
            s.next_step(DuenessTargets::at(BlockHeight::from_u32(50)), &[]),
            AdvanceStep::Waiting
        );
        let v = s.transaction_statuses(DuenessTargets::at(BlockHeight::from_u32(50)));
        assert!(!v[1].ready);
        assert_eq!(v[1].blocked_on, Some(Blocker::AnchorBoundary));

        // At tip 50 (target 51) boundary 40 sits exactly `PROVABLE_ANCHOR_DEPTH` blocks below
        // the tip -> provable now, even though the broadcast schedule (60) has not arrived.
        assert_eq!(
            u32::from(BlockHeight::from_u32(40)) + crate::scheduling::PROVABLE_ANCHOR_DEPTH,
            50,
            "the settling target below tracks the constant"
        );
        assert_eq!(
            s.next_step(DuenessTargets::at(BlockHeight::from_u32(51)), &[]),
            AdvanceStep::Prove {
                transactions: vec![pt(1, transfer(0))],
            }
        );

        // Once proved, it is NOT broadcast until its scheduled height arrives.
        s.transactions[1].state = MigrationTxState::Proved;
        assert_eq!(
            s.next_step(DuenessTargets::at(BlockHeight::from_u32(42)), &[]),
            AdvanceStep::Waiting
        );
        let v = s.transaction_statuses(DuenessTargets::at(BlockHeight::from_u32(42)));
        assert!(!v[1].ready);
        assert_eq!(v[1].blocked_on, Some(Blocker::Schedule));

        // At the scheduled height it becomes broadcastable.
        assert_eq!(
            s.next_step(DuenessTargets::at(BlockHeight::from_u32(60)), &[]),
            AdvanceStep::Broadcast {
                id: MigrationTransferId(1)
            }
        );
    }

    // A transaction with the given id/kind/state, no dependencies, scheduled at 0, expiring after
    // `expiry`. An `expiry` of 0 means the transaction never expires.
    fn tx_expiring(
        id: u32,
        kind: MigrationTxKind,
        state: MigrationTxState,
        expiry: u32,
    ) -> MigrationTransaction {
        let mut t = tx(id, kind, state);
        t.expiry_height = BlockHeight::from_u32(expiry);
        t
    }

    #[test]
    fn zero_expiry_height_never_expires() {
        // The default `tx` helper uses expiry_height 0; at any target the transaction is not expired,
        // preserving the pre-expiry behaviour of every other test in this module.
        let s = state_with(vec![tx(0, transfer(0), MigrationTxState::Proved)]);
        assert!(
            s.expired_transactions(DuenessTargets::at(BlockHeight::from_u32(1_000_000)))
                .is_empty()
        );
    }

    #[test]
    fn expired_transaction_is_not_broadcast_or_proved() {
        // A proved transfer valid only up to height 50. `target_height` is `tip + 1`, i.e. the height
        // of the next block it could be mined into.
        let mut xfer = tx_expiring(1, transfer(0), MigrationTxState::Proved, 50);
        xfer.scheduled_height = BlockHeight::from_u32(40);
        let mut s = state_with(vec![tx(0, prep(0, 0), mined(10)), xfer]);

        // At target 50 (tip 49) it can still be mined -> broadcastable.
        assert_eq!(
            s.next_broadcastable(
                DuenessTargets::at(BlockHeight::from_u32(50)),
                &BTreeSet::new(),
                &[]
            ),
            Some(MigrationTransferId(1))
        );
        // At target 51 (tip 50) expiry has passed (51 > 50) -> not broadcastable, must be rebuilt.
        assert_eq!(
            s.next_broadcastable(
                DuenessTargets::at(BlockHeight::from_u32(51)),
                &BTreeSet::new(),
                &[]
            ),
            None
        );
        assert_eq!(
            s.next_step(DuenessTargets::at(BlockHeight::from_u32(51)), &[]),
            AdvanceStep::Rebuild {
                id: MigrationTransferId(1)
            }
        );

        // The same holds for a still-`Signed` (unproved) expired transfer: it is not provable either.
        s.transactions[1].state = MigrationTxState::Signed;
        assert_eq!(
            s.provable_targets(
                DuenessTargets::at(BlockHeight::from_u32(51)),
                &BTreeSet::new(),
                &[],
            ),
            Vec::new()
        );
        assert_eq!(
            s.next_step(DuenessTargets::at(BlockHeight::from_u32(51)), &[]),
            AdvanceStep::Rebuild {
                id: MigrationTransferId(1)
            }
        );
    }

    #[test]
    fn expired_transaction_reports_blocker_and_expiry_height() {
        let xfer = tx_expiring(1, transfer(0), MigrationTxState::Proved, 50);
        let s = state_with(vec![tx(0, prep(0, 0), mined(10)), xfer]);

        let v = s.transaction_statuses(DuenessTargets::at(BlockHeight::from_u32(51)));
        assert!(!v[1].ready);
        assert_eq!(v[1].action, None);
        assert_eq!(v[1].blocked_on, Some(Blocker::Expired));
        assert_eq!(v[1].expiry_height, BlockHeight::from_u32(50));
        assert_eq!(
            s.expired_transactions(DuenessTargets::at(BlockHeight::from_u32(51))),
            vec![MigrationTransferId(1)]
        );
    }

    #[test]
    fn mined_transaction_past_expiry_is_not_expired() {
        // A transaction that already mined is final even once the chain passes its expiry height: it
        // was included in time and must never be reported as expired or offered for rebuild.
        let s = state_with(vec![tx_expiring(0, transfer(0), mined(40), 50)]);
        assert!(
            s.expired_transactions(DuenessTargets::at(BlockHeight::from_u32(1_000)))
                .is_empty()
        );
        let v = s.transaction_statuses(DuenessTargets::at(BlockHeight::from_u32(1_000)));
        assert_eq!(v[0].blocked_on, None);
    }

    #[test]
    fn valid_work_precedes_rebuild() {
        // One transfer is provable now; an independent, already-proved transfer has expired. The
        // migration makes progress on the valid transfer first, and only surfaces the rebuild once no
        // valid prove/broadcast work remains.
        let prep0 = tx(0, prep(0, 0), mined(10));
        let provable = tx(1, transfer(0), MigrationTxState::Signed);
        let expired = tx_expiring(2, transfer(1), MigrationTxState::Proved, 50);
        let mut s = state_with(vec![prep0, provable, expired]);

        // Target 51: transfer 1 is provable (no boundary, deps mined, due), transfer 2 is expired.
        assert_eq!(
            s.next_step(DuenessTargets::at(BlockHeight::from_u32(51)), &[]),
            AdvanceStep::Prove {
                transactions: vec![pt(1, transfer(0))],
            }
        );
        // Once the valid transfer is proved and broadcast, the expired one is surfaced for rebuild.
        s.transactions[1].state = MigrationTxState::Broadcast {
            txid: TxId::from_bytes([3; 32]),
        };
        assert_eq!(
            s.next_step(DuenessTargets::at(BlockHeight::from_u32(51)), &[]),
            AdvanceStep::Rebuild {
                id: MigrationTransferId(2)
            }
        );
    }

    #[test]
    fn expired_preparation_is_not_offered_for_rebuild() {
        // An expired preparation cannot be rebuilt in isolation: its dependents' pre-signatures
        // commit to the notes it would have minted, so its remediation (rebuilding and re-signing
        // the whole dependent subtree) is a new signing ceremony, not a single advance step.
        // `next_step` reports Replan rather than an unactionable Rebuild — the preparation and its
        // dependents are dead value, and with no live work left the migration must be re-planned —
        // while the expiry stays visible through `Blocker::Expired` and `expired_transactions`.
        let expired_prep = tx_expiring(
            0,
            prep(0, 0),
            MigrationTxState::Broadcast {
                txid: TxId::from_bytes([7; 32]),
            },
            50,
        );
        let mut dependent = tx(1, transfer(0), MigrationTxState::Signed);
        dependent.depends_on = vec![MigrationTransferId(0)];
        let s = state_with(vec![expired_prep, dependent]);

        assert_eq!(
            s.next_step(DuenessTargets::at(BlockHeight::from_u32(51)), &[]),
            AdvanceStep::Replan
        );
        let v = s.transaction_statuses(DuenessTargets::at(BlockHeight::from_u32(51)));
        assert_eq!(v[0].blocked_on, Some(Blocker::Expired));
        assert_eq!(
            s.expired_transactions(DuenessTargets::at(BlockHeight::from_u32(51))),
            vec![MigrationTransferId(0)]
        );
    }

    #[test]
    fn rebuild_surfaces_an_expired_transfer_past_an_expired_preparation() {
        // When both a preparation and a transfer have expired, the rebuild decision surfaces the
        // TRANSFER (the engine can rebuild it), not the preparation listed before it.
        let expired_prep = tx_expiring(
            0,
            prep(0, 0),
            MigrationTxState::Broadcast {
                txid: TxId::from_bytes([7; 32]),
            },
            50,
        );
        let expired_xfer = tx_expiring(1, transfer(0), MigrationTxState::Proved, 50);
        let s = state_with(vec![expired_prep, expired_xfer]);

        assert_eq!(
            s.next_step(DuenessTargets::at(BlockHeight::from_u32(51)), &[]),
            AdvanceStep::Rebuild {
                id: MigrationTransferId(1)
            }
        );
    }

    #[test]
    fn terminal_migration_is_not_offered_for_rebuild() {
        // A cancelled (Failed) migration with an expired transaction must stay terminal: next_step
        // reports Complete, never Rebuild, so a cancelled migration is never driven further.
        let mut s = state_with(vec![tx_expiring(
            0,
            transfer(0),
            MigrationTxState::Proved,
            50,
        )]);
        s.status = MigrationStatus::Failed;
        assert_eq!(
            s.next_step(DuenessTargets::at(BlockHeight::from_u32(1_000)), &[]),
            AdvanceStep::Complete
        );
    }

    #[test]
    fn dead_set_closes_over_marked_and_expired_unmined_sources() {
        // An expired-unmined broadcast preparation is a dead source; its pending dependent dies
        // by closure. A marked in-flight transfer is dead directly; its broadcast dependent dies
        // too (a broadcast dependent of a transaction that can never mine can never mine either).
        let prep0 = tx_expiring(
            0,
            prep(0, 0),
            MigrationTxState::Broadcast {
                txid: TxId::from_bytes([1; 32]),
            },
            50,
        );
        let mut xfer = tx(1, transfer(0), MigrationTxState::Signed);
        xfer.depends_on = vec![MigrationTransferId(0)];
        let mut inflight = tx(
            2,
            transfer(1),
            MigrationTxState::Broadcast {
                txid: TxId::from_bytes([2; 32]),
            },
        );
        inflight.unsatisfiable = marked(40);
        let mut bdep = tx(
            3,
            prep(1, 0),
            MigrationTxState::Broadcast {
                txid: TxId::from_bytes([3; 32]),
            },
        );
        bdep.depends_on = vec![MigrationTransferId(2)];
        let s = state_with(vec![prep0, xfer, inflight, bdep]);

        // At target 51 the preparation is expired: all four are dead.
        let dead: alloc::vec::Vec<_> = s
            .dead_set(DuenessTargets::at(BlockHeight::from_u32(51)))
            .into_iter()
            .collect();
        assert_eq!(
            dead,
            vec![
                MigrationTransferId(0),
                MigrationTransferId(1),
                MigrationTransferId(2),
                MigrationTransferId(3),
            ]
        );
        // At target 50 the preparation is still live: only the marked transfer and its dependent.
        let dead: alloc::vec::Vec<_> = s
            .dead_set(DuenessTargets::at(BlockHeight::from_u32(50)))
            .into_iter()
            .collect();
        assert_eq!(dead, vec![MigrationTransferId(2), MigrationTransferId(3)]);
    }

    #[test]
    fn replan_surfaces_immediately_above_threshold_but_after_broadcast() {
        // Crossings 90 + 10 (threshold 20%): marking the 90-crossing exceeds the threshold, so
        // Replan preempts proving — but a due, already-proven, still-satisfiable broadcast goes
        // out first (each one that mines is migrated value the replan need not carry).
        let mut s = state_with_crossings(
            &[90_000_000, 10_000_000],
            15_000,
            vec![
                tx(0, prep(0, 0), mined(10)),
                tx(1, transfer(0), MigrationTxState::Signed),
                tx(2, transfer(1), MigrationTxState::Proved),
            ],
        );
        s.transactions[1].unsatisfiable = marked(40);
        assert!(s.replan_required());
        assert_eq!(
            s.next_step(DuenessTargets::at(BlockHeight::from_u32(100)), &[]),
            AdvanceStep::Broadcast {
                id: MigrationTransferId(2)
            }
        );
        s.transactions[2].state = MigrationTxState::Broadcast {
            txid: TxId::from_bytes([9; 32]),
        };
        assert_eq!(
            s.next_step(DuenessTargets::at(BlockHeight::from_u32(100)), &[]),
            AdvanceStep::Replan
        );
    }

    #[test]
    fn replan_surfaces_at_drain_below_threshold() {
        // Crossings 90 + 10: marking the 10-crossing is 10% — below the threshold. Live work
        // proceeds; only once nothing else is actionable does the stranded dead value surface
        // Replan instead of Waiting (or a doomed Rebuild), and the migration can never end
        // silently with dead value stranded.
        let mut s = state_with_crossings(
            &[90_000_000, 10_000_000],
            15_000,
            vec![
                tx(0, prep(0, 0), mined(10)),
                tx(1, transfer(0), MigrationTxState::Proved),
                tx(2, transfer(1), MigrationTxState::Signed),
            ],
        );
        s.transactions[2].unsatisfiable = marked(40);
        assert!(!s.replan_required());
        assert_eq!(
            s.next_step(DuenessTargets::at(BlockHeight::from_u32(100)), &[]),
            AdvanceStep::Broadcast {
                id: MigrationTransferId(1)
            }
        );
        s.transactions[1].state = mined(60);
        assert_eq!(
            s.next_step(DuenessTargets::at(BlockHeight::from_u32(100)), &[]),
            AdvanceStep::Replan
        );
    }

    #[test]
    fn a_dead_expired_transfer_is_not_offered_for_rebuild() {
        // Expired alone -> Rebuild (rebuildable; inputs intact). Expired AND marked -> the rebuild
        // could only fail (its input is gone); the remedy is the replan.
        let mut s = state_with(vec![
            tx(0, prep(0, 0), mined(10)),
            tx_expiring(1, transfer(0), MigrationTxState::Proved, 50),
        ]);
        assert_eq!(
            s.next_step(DuenessTargets::at(BlockHeight::from_u32(51)), &[]),
            AdvanceStep::Rebuild {
                id: MigrationTransferId(1)
            }
        );
        s.transactions[1].unsatisfiable = marked(45);
        assert_eq!(
            s.next_step(DuenessTargets::at(BlockHeight::from_u32(51)), &[]),
            AdvanceStep::Replan
        );
    }

    #[test]
    fn replan_above_threshold_preempts_proving() {
        // Crossings 90 + 10 (threshold 20%): the marked 90-crossing is PROVED — dead, so never
        // broadcastable — while the live 10-crossing is Signed, satisfiable, deps mined, and due,
        // i.e. prove-ready. This is what discriminates the EARLY Replan slot from the late one:
        // provable work remains, so the Prove queue would answer before the late slot is ever
        // reached, and without the threshold preemption the kernel would offer Prove for the live
        // sibling instead of the replan.
        let mut s = state_with_crossings(
            &[90_000_000, 10_000_000],
            15_000,
            vec![
                tx(0, prep(0, 0), mined(10)),
                tx(1, transfer(0), MigrationTxState::Proved),
                tx(2, transfer(1), MigrationTxState::Signed),
            ],
        );
        s.transactions[1].unsatisfiable = marked(40);
        assert!(s.replan_required());
        assert_eq!(
            s.next_step(DuenessTargets::at(BlockHeight::from_u32(100)), &[]),
            AdvanceStep::Replan
        );
    }

    #[test]
    fn rebuild_set_aside_skips_only_the_listed_candidates() {
        // The set-aside list reaches the rebuild queue too: a deferred expired-unmarked transfer
        // is never re-offered as the identical Rebuild (the drive loop would spin on it forever),
        // while its rebuildable sibling still surfaces. With every candidate deferred, the honest
        // answer is Waiting, never Replan: "not yet satisfiable" means retry after sync, and a
        // wallet restored from seed must not be pushed into superseding its migration by
        // transient scan lag — the late Replan slot requires an empty set-aside list.
        let s = state_with(vec![
            tx(0, prep(0, 0), mined(10)),
            tx_expiring(1, transfer(0), MigrationTxState::Proved, 50),
            tx_expiring(2, transfer(1), MigrationTxState::Proved, 50),
        ]);
        assert_eq!(
            s.next_step(DuenessTargets::at(BlockHeight::from_u32(51)), &[]),
            AdvanceStep::Rebuild {
                id: MigrationTransferId(1)
            }
        );
        assert_eq!(
            s.next_step(
                DuenessTargets::at(BlockHeight::from_u32(51)),
                &[MigrationTransferId(1)]
            ),
            AdvanceStep::Rebuild {
                id: MigrationTransferId(2)
            }
        );
        assert_eq!(
            s.next_step(
                DuenessTargets::at(BlockHeight::from_u32(51)),
                &[MigrationTransferId(1), MigrationTransferId(2)]
            ),
            AdvanceStep::Waiting
        );
    }

    #[test]
    fn late_replan_waits_for_an_undue_proved_transfer() {
        // Crossings 90 + 10, the 10-crossing marked (10% — below the threshold): the live
        // 90-crossing is PROVED but scheduled far in the future. The late Replan slot must not
        // fire while it waits out the privacy schedule: mark_superseded is destructive, and the
        // undue transfer, once mined, is value the replan need not carry. Only when it mines is
        // dead value all that remains.
        let mut live = tx(1, transfer(0), MigrationTxState::Proved);
        live.scheduled_height = BlockHeight::from_u32(10_000);
        let mut s = state_with_crossings(
            &[90_000_000, 10_000_000],
            15_000,
            vec![
                tx(0, prep(0, 0), mined(10)),
                live,
                tx(2, transfer(1), MigrationTxState::Signed),
            ],
        );
        s.transactions[2].unsatisfiable = marked(40);
        assert!(!s.replan_required());
        assert_eq!(
            s.next_step(DuenessTargets::at(BlockHeight::from_u32(100)), &[]),
            AdvanceStep::Waiting
        );
        s.transactions[1].state = mined(60);
        assert_eq!(
            s.next_step(DuenessTargets::at(BlockHeight::from_u32(100)), &[]),
            AdvanceStep::Replan
        );
    }

    #[test]
    fn late_replan_waits_for_an_inflight_broadcast() {
        // Crossings 90 + 10, the 10-crossing marked: the live 90-crossing is BROADCAST and
        // unmined. In flight is not dead — it gets its chance to mine before the migration is
        // superseded; once it mines, the stranded sibling is all that remains and Replan
        // surfaces.
        let mut s = state_with_crossings(
            &[90_000_000, 10_000_000],
            15_000,
            vec![
                tx(0, prep(0, 0), mined(10)),
                tx(
                    1,
                    transfer(0),
                    MigrationTxState::Broadcast {
                        txid: TxId::from_bytes([5; 32]),
                    },
                ),
                tx(2, transfer(1), MigrationTxState::Signed),
            ],
        );
        s.transactions[2].unsatisfiable = marked(40);
        assert!(!s.replan_required());
        assert_eq!(
            s.next_step(DuenessTargets::at(BlockHeight::from_u32(100)), &[]),
            AdvanceStep::Waiting
        );
        s.transactions[1].state = mined(60);
        assert_eq!(
            s.next_step(DuenessTargets::at(BlockHeight::from_u32(100)), &[]),
            AdvanceStep::Replan
        );
    }

    #[test]
    fn an_expired_transfer_with_a_dead_dependency_is_not_offered_for_rebuild() {
        // Both the preparation and its dependent transfer expired unmined. Rebuilding the
        // transfer would re-anchor it to a funding note whose producer can never mine, so it is
        // never offered (contrast `rebuild_surfaces_an_expired_transfer_past_an_expired_preparation`,
        // whose transfer does not depend on the dead preparation); with nothing live left, the
        // remedy is the replan.
        let expired_prep = tx_expiring(
            0,
            prep(0, 0),
            MigrationTxState::Broadcast {
                txid: TxId::from_bytes([7; 32]),
            },
            50,
        );
        let mut expired_xfer = tx_expiring(1, transfer(0), MigrationTxState::Proved, 50);
        expired_xfer.depends_on = vec![MigrationTransferId(0)];
        let s = state_with(vec![expired_prep, expired_xfer]);

        assert_eq!(
            s.next_step(DuenessTargets::at(BlockHeight::from_u32(51)), &[]),
            AdvanceStep::Replan
        );
    }

    #[test]
    fn a_marked_unexpired_transfer_gets_no_wakeup() {
        // Discriminates the dead-set wake-up filter from the expiry-only filter it replaced:
        // this transfer never expires, so only its unsatisfiable mark can exclude it from the
        // schedule.
        let mut xfer = scheduled_transfer(1, 0, 1440, 1700, MigrationTxState::Signed);
        xfer.unsatisfiable = marked(40);
        let s = state_with(vec![tx(0, prep(0, 0), mined(10)), xfer]);
        let mut r = ChaCha8Rng::seed_from_u64(1);
        let wakeups = s
            .sync_wakeup_schedule(
                BlockHeight::from_u32(100),
                &WakeupParams::new(10, 0),
                &mut r,
            )
            .expect("feasible");
        assert!(
            wakeups.is_empty(),
            "a marked transfer never needs its proof"
        );
    }

    #[test]
    fn early_replan_fires_despite_a_set_aside_broadcast() {
        // The threshold slot is evidence-based: the marked share exceeds the committed threshold
        // whatever this call's set-aside list says, so deferring the due broadcast (its oracle
        // answered "not yet") must not push the pass to a silent Waiting.
        let mut s = state_with_crossings(
            &[90_000_000, 10_000_000],
            15_000,
            vec![
                tx(0, prep(0, 0), mined(10)),
                tx(1, transfer(0), MigrationTxState::Signed),
                tx(2, transfer(1), MigrationTxState::Proved),
            ],
        );
        s.transactions[1].unsatisfiable = marked(40);
        assert!(s.replan_required());
        assert_eq!(
            s.next_step(
                DuenessTargets::at(BlockHeight::from_u32(100)),
                &[MigrationTransferId(2)]
            ),
            AdvanceStep::Replan
        );
    }

    #[test]
    fn statuses_unsatisfiable_beats_signature_and_inflight_broadcast() {
        // The unsatisfiable determination precedes the state match: an AwaitingSignature row
        // with a dead dependency reports Unsatisfiable (not Signature — no signature will ever
        // help it), and a marked in-flight Broadcast row reports Unsatisfiable (not the
        // blocker-free in-flight rendering — it can never mine).
        let mut marked_inflight = tx(
            1,
            transfer(0),
            MigrationTxState::Broadcast {
                txid: TxId::from_bytes([4; 32]),
            },
        );
        marked_inflight.unsatisfiable = marked(40);
        let mut awaiting = tx(2, prep(1, 0), MigrationTxState::AwaitingSignature);
        awaiting.depends_on = vec![MigrationTransferId(1)];
        let s = state_with(vec![
            tx(0, prep(0, 0), mined(10)),
            marked_inflight,
            awaiting,
        ]);

        let v = s.transaction_statuses(DuenessTargets::at(BlockHeight::from_u32(100)));
        assert_eq!(v[1].blocked_on, Some(Blocker::Unsatisfiable));
        assert!(!v[1].ready);
        assert_eq!(v[2].blocked_on, Some(Blocker::Unsatisfiable));
        assert!(!v[2].ready);
    }

    #[test]
    fn next_step_set_aside_skips_only_the_listed_candidates() {
        let s = state_with(vec![
            tx(0, prep(0, 0), MigrationTxState::Signed),
            tx(1, prep(0, 1), MigrationTxState::Signed),
        ]);
        assert_eq!(
            s.next_step(DuenessTargets::at(BlockHeight::from_u32(100)), &[]),
            AdvanceStep::Prove {
                transactions: vec![pt(0, prep(0, 0)), pt(1, prep(0, 1))],
            }
        );
        assert_eq!(
            s.next_step(
                DuenessTargets::at(BlockHeight::from_u32(100)),
                &[MigrationTransferId(0)]
            ),
            AdvanceStep::Prove {
                transactions: vec![pt(1, prep(0, 1))],
            }
        );
        assert_eq!(
            s.next_step(
                DuenessTargets::at(BlockHeight::from_u32(100)),
                &[MigrationTransferId(0), MigrationTransferId(1)]
            ),
            AdvanceStep::Waiting
        );
    }

    #[test]
    fn dead_transactions_render_unsatisfiable_and_get_no_wakeups() {
        // A marked transfer renders Blocker::Unsatisfiable (ahead of Expired) and is excluded
        // from the sync wake-up schedule; a closure-dead dependent renders the same.
        let mut xfer = scheduled_transfer(1, 0, 1440, 1700, MigrationTxState::Signed);
        xfer.unsatisfiable = marked(40);
        xfer.expiry_height = BlockHeight::from_u32(45); // ALSO expired: Unsatisfiable wins
        let mut dep = tx(2, prep(1, 0), MigrationTxState::Signed);
        dep.depends_on = vec![MigrationTransferId(1)];
        let s = state_with(vec![tx(0, prep(0, 0), mined(10)), xfer, dep]);

        let v = s.transaction_statuses(DuenessTargets::at(BlockHeight::from_u32(100)));
        assert_eq!(v[1].blocked_on, Some(Blocker::Unsatisfiable));
        assert_eq!(v[2].blocked_on, Some(Blocker::Unsatisfiable));

        let mut r = ChaCha8Rng::seed_from_u64(1);
        let wakeups = s
            .sync_wakeup_schedule(
                BlockHeight::from_u32(100),
                &WakeupParams::new(10, 0),
                &mut r,
            )
            .expect("feasible");
        assert!(wakeups.is_empty(), "no proof wake-ups for dead transfers");
    }

    #[test]
    fn record_satisfiability_marks_by_cause_and_closes_durably() {
        let mut l1 = tx(3, prep(1, 0), MigrationTxState::Signed);
        l1.depends_on = vec![MigrationTransferId(1)];
        let mut s = state_with(vec![
            tx(0, prep(0, 0), mined(10)),
            tx(1, transfer(0), MigrationTxState::Signed),
            tx(2, transfer(1), MigrationTxState::Proved),
            l1,
        ]);
        let h = BlockHeight::from_u32(500);
        s.record_satisfiability(
            DuenessTargets::at(BlockHeight::from_u32(600)),
            &[
                (
                    MigrationTransferId(1),
                    StepSatisfiability::Unsatisfiable {
                        cause: UnsatisfiableCause::InputsSpent {
                            nullifiers: vec![[9; 32]],
                        },
                        as_of_height: h,
                    },
                ),
                // Non-marking answers are no-ops:
                (
                    MigrationTransferId(2),
                    StepSatisfiability::NotYetSatisfiable { as_of_height: h },
                ),
            ],
        );
        assert_eq!(s.transactions[1].unsatisfiable_at(), Some(h));
        assert_eq!(s.transactions[2].unsatisfiable_at(), None);
        // Durable closure: the dependent inherits the SOURCE's stamp.
        assert_eq!(s.transactions[3].unsatisfiable_at(), Some(h));
    }

    #[test]
    fn record_satisfiability_cause_dependence() {
        // Expired confirms a derivation the kernel already makes: no mark. AnchorInvalidated and
        // InputsInvalidated mark. An existing mark is never restamped, and a mined transaction is
        // never marked.
        let mut s = state_with(vec![
            tx(0, transfer(0), MigrationTxState::Proved),
            tx(
                1,
                transfer(1),
                MigrationTxState::Broadcast {
                    txid: TxId::from_bytes([1; 32]),
                },
            ),
            tx(2, transfer(2), MigrationTxState::Signed),
            tx(3, transfer(3), mined(10)),
        ]);
        let h = BlockHeight::from_u32(500);
        s.record_satisfiability(
            DuenessTargets::at(BlockHeight::from_u32(600)),
            &[(
                MigrationTransferId(0),
                StepSatisfiability::Unsatisfiable {
                    cause: UnsatisfiableCause::Expired,
                    as_of_height: h,
                },
            )],
        );
        assert_eq!(
            s.transactions[0].unsatisfiable_at(),
            None,
            "Expired never marks"
        );
        s.record_satisfiability(
            DuenessTargets::at(BlockHeight::from_u32(600)),
            &[
                (
                    MigrationTransferId(1),
                    StepSatisfiability::Unsatisfiable {
                        cause: UnsatisfiableCause::AnchorInvalidated,
                        as_of_height: h,
                    },
                ),
                (
                    MigrationTransferId(2),
                    StepSatisfiability::Unsatisfiable {
                        cause: UnsatisfiableCause::InputsInvalidated { anchor: [7; 32] },
                        as_of_height: h,
                    },
                ),
                (
                    MigrationTransferId(3),
                    StepSatisfiability::Unsatisfiable {
                        cause: UnsatisfiableCause::InputsSpent {
                            nullifiers: vec![[8; 32]],
                        },
                        as_of_height: h,
                    },
                ),
            ],
        );
        assert_eq!(s.transactions[1].unsatisfiable_at(), Some(h));
        assert_eq!(s.transactions[2].unsatisfiable_at(), Some(h));
        assert_eq!(
            s.transactions[3].unsatisfiable_at(),
            None,
            "a mined transaction is final and is never marked"
        );
        // Re-recording at a different height leaves the original stamp (first observation wins;
        // clearing is truncation's job alone).
        s.record_satisfiability(
            DuenessTargets::at(BlockHeight::from_u32(700)),
            &[(
                MigrationTransferId(1),
                StepSatisfiability::Unsatisfiable {
                    cause: UnsatisfiableCause::AnchorInvalidated,
                    as_of_height: BlockHeight::from_u32(650),
                },
            )],
        );
        assert_eq!(s.transactions[1].unsatisfiable_at(), Some(h));
    }

    #[test]
    fn record_satisfiability_expired_source_stamps_expiry_height() {
        // With NO determinations at all, the durable closure alone marks a subtree stranded
        // behind an expired-unmined preparation, stamped at the SOURCE's expiry height — chosen
        // so reorg truncation clears the mark exactly when a rewind un-expires the source. The
        // expired source itself stays UNMARKED: its deadness is derived, not stored.
        let prep0 = tx_expiring(
            0,
            prep(0, 0),
            MigrationTxState::Broadcast {
                txid: TxId::from_bytes([1; 32]),
            },
            50,
        );
        let mut dep = tx(1, transfer(0), MigrationTxState::Signed);
        dep.depends_on = vec![MigrationTransferId(0)];
        let mut grandchild = tx(2, prep(2, 0), MigrationTxState::Signed);
        grandchild.depends_on = vec![MigrationTransferId(1)];
        let mut s = state_with(vec![prep0, dep, grandchild]);
        s.record_satisfiability(DuenessTargets::at(BlockHeight::from_u32(60)), &[]);
        assert_eq!(s.transactions[0].unsatisfiable_at(), None);
        assert_eq!(
            s.transactions[1].unsatisfiable_at(),
            Some(BlockHeight::from_u32(50))
        );
        // The grandchild inherits through the chain (its parent's stamp, itself inherited).
        assert_eq!(
            s.transactions[2].unsatisfiable_at(),
            Some(BlockHeight::from_u32(50))
        );
        // At a target where the source is NOT yet expired, the closure marks nothing.
        let mut s2 = state_with(vec![tx_expiring(
            0,
            prep(0, 0),
            MigrationTxState::Broadcast {
                txid: TxId::from_bytes([1; 32]),
            },
            50,
        )]);
        s2.record_satisfiability(DuenessTargets::at(BlockHeight::from_u32(50)), &[]);
        assert!(s2.transactions.iter().all(|t| t.unsatisfiable.is_none()));
    }

    #[test]
    fn record_satisfiability_inherits_the_minimum_stamp() {
        // A dependent of TWO dead sources inherits the MINIMUM applicable stamp — the earliest
        // height whose rollback would revive it. Source A is marked at 500. Source B is BOTH
        // marked (at 400) and expired (at 50), so its applicable stamp is the min of the two:
        // only a truncation below 50 both clears its mark and un-expires it. The dependent
        // therefore inherits 50, and a truncation to 100 — which clears both sources' own marks —
        // leaves the inherited mark standing: B is still expired, so the dependent is still dead,
        // and its stamp says so.
        let mut a = tx(0, transfer(0), MigrationTxState::Signed);
        a.unsatisfiable = marked(500);
        let mut b = tx_expiring(1, transfer(1), MigrationTxState::Signed, 50);
        b.unsatisfiable = marked(400);
        let mut dep = tx(2, prep(1, 0), MigrationTxState::Signed);
        dep.depends_on = vec![MigrationTransferId(0), MigrationTransferId(1)];
        let mut s = state_with(vec![a, b, dep]);
        s.record_satisfiability(DuenessTargets::at(BlockHeight::from_u32(600)), &[]);
        assert_eq!(
            s.transactions[2].unsatisfiable_at(),
            Some(BlockHeight::from_u32(50))
        );
        s.truncate_to_height(BlockHeight::from_u32(100));
        assert_eq!(
            s.transactions[2].unsatisfiable_at(),
            Some(BlockHeight::from_u32(50)),
            "truncation to 100 leaves the minimum stamp standing"
        );
    }

    // A demoted (formerly mined) transaction with an empty `spend_nullifiers` cache surfaces as
    // loud store corruption at its next oracle check, never vacuous satisfiability: demotion
    // makes the row non-Mined, and the store-side satisfiability oracle refuses an empty cache
    // on any non-mined row (see `classify_input_observations` in the engine, and the sqlite
    // oracle's composition test of exactly this truncate-then-check sequence). No test here can
    // reach an oracle — this crate holds only the state — so the guarantee is exercised on the
    // sqlite side.
    #[test]
    fn truncate_to_height_invalidates_chain_derived_determinations_only() {
        let mut s = state_with(vec![
            tx(
                0,
                prep(0, 0),
                MigrationTxState::Mined {
                    txid: TxId::from_bytes([1; 32]),
                    height: BlockHeight::from_u32(100),
                },
            ),
            tx(
                1,
                transfer(0),
                MigrationTxState::Mined {
                    txid: TxId::from_bytes([2; 32]),
                    height: BlockHeight::from_u32(110),
                },
            ),
        ]);
        s.transactions[0].unsatisfiable = marked(100);
        s.recompute_status();
        assert_eq!(s.status, MigrationStatus::Complete);
        s.truncate_to_height(BlockHeight::from_u32(100));
        // A mark at exactly the truncation height rests on surviving state: kept. A mined height
        // above it: demoted to Broadcast, txid preserved. Complete: reverted (chain-derived).
        assert_eq!(
            s.transactions[0].unsatisfiable_at(),
            Some(BlockHeight::from_u32(100))
        );
        assert!(
            matches!(s.transactions[0].state, MigrationTxState::Mined { .. }),
            "mined at exactly the truncation height rests on surviving state"
        );
        assert!(matches!(
            s.transactions[1].state,
            MigrationTxState::Broadcast { txid } if txid == TxId::from_bytes([1; 32])
        ));
        assert_eq!(s.status, MigrationStatus::InProgress);
        // Marks strictly above the height clear.
        s.transactions[0].unsatisfiable = marked(101);
        s.truncate_to_height(BlockHeight::from_u32(100));
        assert_eq!(s.transactions[0].unsatisfiable_at(), None);
        // Policy-terminal statuses are never revived.
        s.status = MigrationStatus::Superseded;
        s.truncate_to_height(BlockHeight::from_u32(5));
        assert_eq!(s.status, MigrationStatus::Superseded);
        let mut f = state_with(vec![tx(
            0,
            transfer(0),
            MigrationTxState::Mined {
                txid: TxId::from_bytes([3; 32]),
                height: BlockHeight::from_u32(80),
            },
        )]);
        f.status = MigrationStatus::Failed;
        f.truncate_to_height(BlockHeight::from_u32(50));
        assert!(matches!(
            f.transactions[0].state,
            MigrationTxState::Broadcast { .. }
        ));
        assert_eq!(
            f.status,
            MigrationStatus::Failed,
            "policy-terminal never revived"
        );
    }

    /// Recording an observation stores WHY alongside the stamp: a direct determination records its
    /// cause's kind, a mark the dependency closure applies records `Inherited` (nothing was
    /// observed about the transaction itself), and a non-marking answer records neither.
    #[test]
    fn record_satisfiability_records_the_cause_kind_and_inherits() {
        // 0 -> spent inputs, 1 -> a dead anchor, 2 -> invalidated inputs, 3 -> a dependent of 0
        // reached only through the closure, 4 -> untouched.
        let mut dependent = tx(3, prep(1, 0), MigrationTxState::Signed);
        dependent.depends_on = vec![MigrationTransferId(0)];
        let mut s = state_with(vec![
            tx(0, transfer(0), MigrationTxState::Signed),
            tx(
                1,
                transfer(1),
                MigrationTxState::Broadcast {
                    txid: TxId::from_bytes([1; 32]),
                },
            ),
            tx(2, transfer(2), MigrationTxState::Signed),
            dependent,
            tx(4, transfer(3), MigrationTxState::Signed),
        ]);
        let h = BlockHeight::from_u32(500);
        s.record_satisfiability(
            DuenessTargets::at(BlockHeight::from_u32(600)),
            &[
                (
                    MigrationTransferId(0),
                    StepSatisfiability::Unsatisfiable {
                        cause: UnsatisfiableCause::InputsSpent {
                            nullifiers: vec![[9; 32]],
                        },
                        as_of_height: h,
                    },
                ),
                (
                    MigrationTransferId(1),
                    StepSatisfiability::Unsatisfiable {
                        cause: UnsatisfiableCause::AnchorInvalidated,
                        as_of_height: h,
                    },
                ),
                (
                    MigrationTransferId(2),
                    StepSatisfiability::Unsatisfiable {
                        cause: UnsatisfiableCause::InputsInvalidated { anchor: [7; 32] },
                        as_of_height: h,
                    },
                ),
                (
                    MigrationTransferId(4),
                    StepSatisfiability::Satisfiable { as_of_height: h },
                ),
            ],
        );
        assert_eq!(
            s.transactions[0].unsatisfiable,
            Some((h, UnsatisfiableKind::InputsSpent))
        );
        assert_eq!(
            s.transactions[1].unsatisfiable,
            Some((h, UnsatisfiableKind::AnchorInvalidated))
        );
        assert_eq!(
            s.transactions[2].unsatisfiable,
            Some((h, UnsatisfiableKind::InputsInvalidated))
        );
        assert_eq!(
            s.transactions[3].unsatisfiable,
            Some((h, UnsatisfiableKind::Inherited)),
            "a mark the closure applied says only that it was inherited"
        );
        assert_eq!(s.transactions[4].unsatisfiable, None);

        // Truncating below the marks clears them whole: the kind says why THAT observation stood,
        // and the observation is gone.
        s.truncate_to_height(BlockHeight::from_u32(400));
        assert!(
            s.transactions.iter().all(|t| t.unsatisfiable.is_none()),
            "a cleared mark leaves nothing behind"
        );
    }

    /// The status view surfaces the kind exactly alongside `Blocker::Unsatisfiable` — and for a
    /// transaction stranded behind a merely DERIVED-dead dependency (expired and unmined, a
    /// deadness the kernel re-derives and never stores) it reports `Inherited`, which is precisely
    /// its situation: nothing was observed about the transaction itself.
    #[test]
    fn transaction_statuses_surface_the_unsatisfiability_kind() {
        // 0 -> marked directly; 1 -> depends on 0 and is itself marked by the closure; 2 -> an
        // expired-unmined preparation, dead by derivation and never marked; 3 -> depends on 2 and
        // carries no mark at all; 4 -> live.
        let mut inherited = tx(1, prep(1, 0), MigrationTxState::Signed);
        inherited.depends_on = vec![MigrationTransferId(0)];
        let mut stranded = tx(3, transfer(2), MigrationTxState::Signed);
        stranded.depends_on = vec![MigrationTransferId(2)];
        let mut s = state_with(vec![
            tx(0, transfer(0), MigrationTxState::Signed),
            inherited,
            tx_expiring(
                2,
                prep(0, 0),
                MigrationTxState::Broadcast {
                    txid: TxId::from_bytes([2; 32]),
                },
                50,
            ),
            stranded,
            tx(4, transfer(3), MigrationTxState::Signed),
        ]);
        s.transactions[0].unsatisfiable =
            Some((BlockHeight::from_u32(500), UnsatisfiableKind::InputsSpent));
        s.transactions[1].unsatisfiable =
            Some((BlockHeight::from_u32(500), UnsatisfiableKind::Inherited));

        let v = s.transaction_statuses(DuenessTargets::at(BlockHeight::from_u32(600)));
        assert_eq!(v[0].blocked_on, Some(Blocker::Unsatisfiable));
        assert_eq!(
            v[0].unsatisfiable_kind,
            Some(UnsatisfiableKind::InputsSpent)
        );
        assert_eq!(v[1].blocked_on, Some(Blocker::Unsatisfiable));
        assert_eq!(v[1].unsatisfiable_kind, Some(UnsatisfiableKind::Inherited));
        // The expired source itself is not unsatisfiable: expiry's remedy still applies, and no
        // kind is reported with `Expired`.
        assert_eq!(v[2].blocked_on, Some(Blocker::Expired));
        assert_eq!(v[2].unsatisfiable_kind, None);
        // Stranded behind it, with NO stored mark of its own: `Inherited` is the honest answer.
        assert_eq!(
            s.transactions[3].unsatisfiable, None,
            "the stranded transaction carries no stored mark; the kind is derived here"
        );
        assert_eq!(v[3].blocked_on, Some(Blocker::Unsatisfiable));
        assert_eq!(v[3].unsatisfiable_kind, Some(UnsatisfiableKind::Inherited));
        // A live transaction reports neither.
        assert_ne!(v[4].blocked_on, Some(Blocker::Unsatisfiable));
        assert_eq!(v[4].unsatisfiable_kind, None);
    }

    #[test]
    fn truncation_then_rederivation_restores_true_marks() {
        // The mark-clear + demotion + kernel-closure pipeline composes: truncating below a mark
        // frees the transaction, and a subsequent record_satisfiability with a fresh observation
        // re-marks it — first-observation-wins applies only to LIVE marks.
        let mut s = state_with(vec![tx(0, transfer(0), MigrationTxState::Signed)]);
        s.record_satisfiability(
            DuenessTargets::at(BlockHeight::from_u32(600)),
            &[(
                MigrationTransferId(0),
                StepSatisfiability::Unsatisfiable {
                    cause: UnsatisfiableCause::InputsSpent {
                        nullifiers: vec![[9; 32]],
                    },
                    as_of_height: BlockHeight::from_u32(500),
                },
            )],
        );
        s.truncate_to_height(BlockHeight::from_u32(400));
        assert_eq!(s.transactions[0].unsatisfiable_at(), None);
        s.record_satisfiability(
            DuenessTargets::at(BlockHeight::from_u32(600)),
            &[(
                MigrationTransferId(0),
                StepSatisfiability::Unsatisfiable {
                    cause: UnsatisfiableCause::InputsSpent {
                        nullifiers: vec![[9; 32]],
                    },
                    as_of_height: BlockHeight::from_u32(420),
                },
            )],
        );
        assert_eq!(
            s.transactions[0].unsatisfiable_at(),
            Some(BlockHeight::from_u32(420))
        );
    }

    /// The report is recorded for a `Proved` transaction and nothing else: a failed broadcast
    /// never reached `mark_broadcast`, so that is the state a rejected transaction is in. An
    /// unknown id, a transaction not yet proved, one already in flight, and a mined one are all
    /// no-ops — the last most pointedly, since chain inclusion settles the question the report
    /// exists to raise.
    #[test]
    fn report_broadcast_failure_applies_only_to_proved_transactions() {
        let tip = BlockHeight::from_u32(900);
        let mut s = state_with(vec![
            tx(0, transfer(0), MigrationTxState::Proved),
            tx(1, transfer(1), MigrationTxState::Signed),
            tx(
                2,
                transfer(2),
                MigrationTxState::Broadcast {
                    txid: TxId::from_bytes([1; 32]),
                },
            ),
            tx(3, transfer(3), mined(100)),
        ]);
        for id in 0..4 {
            s.report_broadcast_failure(MigrationTransferId(id), tip);
        }
        s.report_broadcast_failure(MigrationTransferId(99), tip);

        assert_eq!(s.transactions[0].broadcast_failure_at, Some(tip));
        for i in 1..4 {
            assert_eq!(
                s.transactions[i].broadcast_failure_at, None,
                "only a Proved transaction records a rejection",
            );
        }

        // The newest testimony supersedes: a second rejection at a later tip replaces the first,
        // so the adjudication must reach the later chain state.
        let later = BlockHeight::from_u32(950);
        s.report_broadcast_failure(MigrationTransferId(0), later);
        assert_eq!(s.transactions[0].broadcast_failure_at, Some(later));
        // Including a rejection at an EARLIER tip: whichever report stands is the one to answer,
        // and the verb keeps no history to reconcile.
        let earlier = BlockHeight::from_u32(800);
        s.report_broadcast_failure(MigrationTransferId(0), earlier);
        assert_eq!(s.transactions[0].broadcast_failure_at, Some(earlier));
    }

    /// A reported transaction leaves the broadcast queue, and the kernel offers the migration's
    /// other work instead; discharging the report puts it back.
    #[test]
    fn a_reported_transaction_is_withheld_from_the_broadcast_queue() {
        let mut s = state_with(vec![
            tx(0, transfer(0), MigrationTxState::Proved),
            tx(1, transfer(1), MigrationTxState::Proved),
        ]);
        let target = BlockHeight::from_u32(50);
        assert_eq!(
            s.next_step(DuenessTargets::at(target), &[]),
            AdvanceStep::Broadcast {
                id: MigrationTransferId(0)
            }
        );

        s.report_broadcast_failure(MigrationTransferId(0), BlockHeight::from_u32(49));
        assert_eq!(
            s.next_step(DuenessTargets::at(target), &[]),
            AdvanceStep::Broadcast {
                id: MigrationTransferId(1)
            },
            "the migration's other due broadcast still surfaces",
        );
        s.report_broadcast_failure(MigrationTransferId(1), BlockHeight::from_u32(49));
        assert_eq!(
            s.next_step(DuenessTargets::at(target), &[]),
            AdvanceStep::Waiting,
            "with every due broadcast withheld there is nothing else to do",
        );
        assert_ne!(
            s.next_step(DuenessTargets::at(target), &[]),
            AdvanceStep::Reevaluate,
            "the kernel has no oracle to adjudicate with, so it never names that step",
        );

        s.clear_broadcast_failure(MigrationTransferId(0));
        assert_eq!(
            s.next_step(DuenessTargets::at(target), &[]),
            AdvanceStep::Broadcast {
                id: MigrationTransferId(0)
            },
            "a discharged report returns the transaction to the queue",
        );
    }

    /// The blocker precedence around the report: an unsatisfiability determination outranks it
    /// (including one recorded about the very transaction whose rejection was adjudicated), and it
    /// outranks expiry and the state-derived blockers.
    #[test]
    fn statuses_rank_awaiting_reevaluation_below_unsatisfiable_and_above_expired() {
        let target = BlockHeight::from_u32(100);
        let mut s = state_with(vec![
            tx(0, transfer(0), MigrationTxState::Proved),
            tx(1, transfer(1), MigrationTxState::Proved),
            tx(2, transfer(2), MigrationTxState::Proved),
        ]);
        // 0: reported only. 1: reported AND marked. 2: reported AND expired.
        s.transactions[1].unsatisfiable = marked(90);
        s.transactions[2].expiry_height = BlockHeight::from_u32(80);
        for id in 0..3 {
            s.report_broadcast_failure(MigrationTransferId(id), BlockHeight::from_u32(99));
        }

        let v = s.transaction_statuses(DuenessTargets::at(target));
        assert_eq!(v[0].blocked_on, Some(Blocker::AwaitingReevaluation));
        assert!(!v[0].ready && v[0].action.is_none());
        assert_eq!(
            v[0].unsatisfiable_kind, None,
            "a pending question is not a determination",
        );
        assert_eq!(
            v[1].blocked_on,
            Some(Blocker::Unsatisfiable),
            "an answered question outranks an open one",
        );
        assert_eq!(
            v[1].unsatisfiable_kind,
            Some(UnsatisfiableKind::InputsSpent)
        );
        assert_eq!(
            v[2].blocked_on,
            Some(Blocker::AwaitingReevaluation),
            "being actively withheld is more specific than an expiry whose rebuild is pending",
        );

        // Discharge the reports and the ordinary dispositions return.
        for id in 0..3 {
            s.clear_broadcast_failure(MigrationTransferId(id));
        }
        let v = s.transaction_statuses(DuenessTargets::at(target));
        assert!(v[0].ready && v[0].action == Some(NextAction::Broadcast));
        assert_eq!(v[1].blocked_on, Some(Blocker::Unsatisfiable));
        assert_eq!(v[2].blocked_on, Some(Blocker::Expired));
    }

    /// A report names a chain tip, so truncation judges it exactly as it judges a mark: a report
    /// at the truncation height still refers to surviving state, one above it does not.
    #[test]
    fn truncation_clears_reports_above_the_height_only() {
        let mut s = state_with(vec![
            tx(0, transfer(0), MigrationTxState::Proved),
            tx(1, transfer(1), MigrationTxState::Proved),
        ]);
        s.report_broadcast_failure(MigrationTransferId(0), BlockHeight::from_u32(100));
        s.report_broadcast_failure(MigrationTransferId(1), BlockHeight::from_u32(101));

        s.truncate_to_height(BlockHeight::from_u32(100));
        assert_eq!(
            s.transactions[0].broadcast_failure_at,
            Some(BlockHeight::from_u32(100)),
            "a report at exactly the truncation height rests on surviving state",
        );
        assert_eq!(
            s.transactions[1].broadcast_failure_at, None,
            "a report above it named a chain the wallet no longer holds",
        );
        assert_eq!(
            s.next_step(DuenessTargets::at(BlockHeight::from_u32(50)), &[]),
            AdvanceStep::Broadcast {
                id: MigrationTransferId(1)
            },
            "and the transaction it withheld is offered again",
        );
    }

    /// The wake-up schedule is about PROVING, which a rejected broadcast says nothing about: a
    /// reported transfer is already proved, so it contributed no wake-up before the report either,
    /// and an unproved sibling keeps the one it had.
    #[test]
    fn a_report_does_not_disturb_the_wakeup_schedule() {
        let mut s = state_with(vec![
            scheduled_transfer(0, 0, 1440, 1700, MigrationTxState::Proved),
            scheduled_transfer(1, 1, 1584, 1800, MigrationTxState::Signed),
        ]);
        let params = WakeupParams::new(10, 0);
        let tip = BlockHeight::from_u32(1600);
        let mut rng = ChaCha8Rng::seed_from_u64(7);
        let before = s
            .sync_wakeup_schedule(tip, &params, &mut rng)
            .expect("a schedule exists");

        s.report_broadcast_failure(MigrationTransferId(0), BlockHeight::from_u32(1600));
        let mut rng = ChaCha8Rng::seed_from_u64(7);
        let after = s
            .sync_wakeup_schedule(tip, &params, &mut rng)
            .expect("a schedule exists");
        assert_eq!(
            before.len(),
            after.len(),
            "reports concern broadcast, not proving",
        );
    }

    /// Chain inclusion outranks every judgment about whether the transaction could ever mine: a
    /// mark and a broadcast-failure report are both discharged when the row mines, so neither can
    /// stand on a mined transaction contradicting it.
    #[test]
    fn mining_discharges_the_mark_and_the_report() {
        let mut s = state_with_crossings(
            &[50_000_000, 50_000_000],
            15_000,
            vec![
                tx(
                    0,
                    transfer(0),
                    MigrationTxState::Broadcast {
                        txid: TxId::from_bytes([1; 32]),
                    },
                ),
                tx(1, transfer(1), MigrationTxState::Proved),
            ],
        );
        // 0 was marked in flight (a settled reorg displaced its anchor, say) and then mined
        // anyway; 1 was rejected at broadcast and then mined under a later attempt.
        s.transactions[0].unsatisfiable = marked(90);
        s.report_broadcast_failure(MigrationTransferId(1), BlockHeight::from_u32(95));
        assert!(
            s.replan_required(),
            "half the planned crossing value is marked and unmined, past the 20% threshold",
        );

        s.mark_mined(MigrationTransferId(0), BlockHeight::from_u32(100));
        s.mark_mined(MigrationTransferId(1), BlockHeight::from_u32(101));

        assert_eq!(s.transactions[0].unsatisfiable, None);
        assert_eq!(s.transactions[1].broadcast_failure_at, None);
        let v = s.transaction_statuses(DuenessTargets::at(BlockHeight::from_u32(102)));
        assert_eq!(v[0].blocked_on, None, "a mined row carries no blocker");
        assert_eq!(v[0].unsatisfiable_kind, None);
        assert_eq!(v[1].blocked_on, None);
        assert!(
            !s.replan_required(),
            "the share was already computed over unmined transfers, so clearing changes nothing",
        );
    }

    /// The reverse order of the same interaction: a mined transaction is never marked in the first
    /// place, so the replan share is what it was either way.
    #[test]
    fn a_mined_transaction_is_neither_marked_nor_reported() {
        let mut s = state_with(vec![tx(0, transfer(0), MigrationTxState::Proved)]);
        s.mark_mined(MigrationTransferId(0), BlockHeight::from_u32(100));
        s.record_satisfiability(
            DuenessTargets::at(BlockHeight::from_u32(120)),
            &[(
                MigrationTransferId(0),
                StepSatisfiability::Unsatisfiable {
                    cause: UnsatisfiableCause::InputsSpent {
                        nullifiers: vec![[9; 32]],
                    },
                    as_of_height: BlockHeight::from_u32(110),
                },
            )],
        );
        s.report_broadcast_failure(MigrationTransferId(0), BlockHeight::from_u32(110));
        assert_eq!(s.transactions[0].unsatisfiable, None);
        assert_eq!(s.transactions[0].broadcast_failure_at, None);
        assert!(!s.replan_required());
    }
    // ---------------------------------------------------------------------------------------
    // Dual-target dueness. Every test below fixes one migration and reads it at two target
    // pairs: `at(scanned)` (the degenerate pair, which is what every other test in this module
    // uses) and `new(scanned, estimated)` with an estimate that runs AHEAD of the scan. The
    // invariant under test is that the overshoot changes only what is SERVED or WITHHELD, never
    // what is determined, recorded, or discarded.
    // ---------------------------------------------------------------------------------------

    /// The clamp is the whole reason `DuenessTargets` is a type and not a pair of arguments: an
    /// estimate that lags the wallet's own observations is simply less informed than they are,
    /// and a transposed pair (estimate first) must not be able to lower the served target.
    #[test]
    fn dueness_targets_clamps_an_estimate_below_the_scanned_frontier() {
        let behind = DuenessTargets::new(BlockHeight::from_u32(100), BlockHeight::from_u32(60));
        assert_eq!(behind.scanned(), BlockHeight::from_u32(100));
        assert_eq!(
            behind.effective(),
            BlockHeight::from_u32(100),
            "an estimate behind the scan is clamped up to it"
        );
        let ahead = DuenessTargets::new(BlockHeight::from_u32(100), BlockHeight::from_u32(160));
        assert_eq!(ahead.scanned(), BlockHeight::from_u32(100));
        assert_eq!(ahead.effective(), BlockHeight::from_u32(160));
        let degenerate = DuenessTargets::at(BlockHeight::from_u32(100));
        assert_eq!(degenerate.scanned(), degenerate.effective());
        assert_eq!(
            degenerate,
            DuenessTargets::new(BlockHeight::from_u32(100), BlockHeight::from_u32(100)),
            "`at` is the equal pair `new` builds from two equal heights"
        );
    }

    /// What the estimate is FOR: a wallet whose scan is a week behind still submits a transfer
    /// whose scheduled height the clock says has arrived. ZIP 318 forbids contacting
    /// lightwalletd before the decision, so without this the broadcast would never be offered.
    #[test]
    fn a_broadcast_due_only_by_the_estimate_is_served() {
        let s = state_with(vec![
            tx(0, prep(0, 0), mined(10)),
            scheduled_transfer(1, 0, 40, 1_500, MigrationTxState::Proved),
        ]);

        assert_eq!(
            s.next_step(DuenessTargets::at(BlockHeight::from_u32(500)), &[]),
            AdvanceStep::Waiting,
            "the scanned frontier alone considers nothing due"
        );
        assert_eq!(
            s.next_step(
                DuenessTargets::new(BlockHeight::from_u32(500), BlockHeight::from_u32(1_501)),
                &[],
            ),
            AdvanceStep::Broadcast {
                id: MigrationTransferId(1)
            },
            "the estimate serves the schedule"
        );
        let v = s.transaction_statuses(DuenessTargets::new(
            BlockHeight::from_u32(500),
            BlockHeight::from_u32(1_501),
        ));
        assert!(v[1].ready);
        assert_eq!(v[1].action, Some(NextAction::Broadcast));
        assert_eq!(v[1].blocked_on, None);
    }

    /// The DOOMED WINDOW (`scanned <= expiry < effective`), and the agreement the SDK's sync gate
    /// rests on: the kernel withholds the broadcast, and the status view reports the transfer as
    /// neither ready nor actionable — under `ExpiryImminent`, because nothing has DETERMINED the
    /// lapse. A live sibling due by the same estimate is still served in the same pass, so the
    /// withhold is one transaction's, not the migration's.
    #[test]
    fn the_doomed_window_withholds_the_broadcast_and_reports_expiry_imminent() {
        let mut doomed = scheduled_transfer(1, 0, 40, 1_500, MigrationTxState::Proved);
        doomed.expiry_height = BlockHeight::from_u32(1_600);
        let s = state_with(vec![
            tx(0, prep(0, 0), mined(10)),
            doomed,
            scheduled_transfer(2, 1, 40, 1_500, MigrationTxState::Proved),
        ]);
        // Scanned 1_501 (the wallet cannot see the expiry at 1_600 either way), estimate 1_700.
        let targets =
            DuenessTargets::new(BlockHeight::from_u32(1_501), BlockHeight::from_u32(1_700));

        assert_eq!(
            s.next_step(targets, &[]),
            AdvanceStep::Broadcast {
                id: MigrationTransferId(2)
            },
            "the doomed transfer is skipped and the live sibling served"
        );
        assert_eq!(
            s.next_broadcastable(targets, &BTreeSet::new(), &[]),
            Some(MigrationTransferId(2)),
            "the broadcast queue itself withholds the doomed transfer"
        );

        let v = s.transaction_statuses(targets);
        assert_eq!(v[1].blocked_on, Some(Blocker::ExpiryImminent));
        assert!(!v[1].ready, "a withheld broadcast is never reported ready");
        assert_eq!(
            v[1].action, None,
            "the sync gate is `ready && action == Broadcast`, so the withheld row carries neither"
        );
        assert_eq!(
            v[1].unsatisfiable_kind, None,
            "nothing was determined about it"
        );
        assert!(v[2].ready, "the live sibling is served");
        assert_eq!(v[2].action, Some(NextAction::Broadcast));

        // And the withhold is exactly the estimate's doing: read at the scanned frontier alone,
        // the doomed transfer is the first one offered.
        assert_eq!(
            s.next_step(DuenessTargets::at(BlockHeight::from_u32(1_501)), &[]),
            AdvanceStep::Broadcast {
                id: MigrationTransferId(1)
            }
        );
    }

    /// NEGATIVE: an expiry the estimate has passed but the scan has not is not a DEATH. It seeds
    /// neither the dead set nor its transitive closure, so nothing behind it is stranded, and
    /// `expired_transactions` — the launch-time reconciliation a wallet tells the user about —
    /// does not name it.
    #[test]
    fn an_estimated_expiry_does_not_seed_the_dead_set() {
        let mut source = tx_expiring(
            0,
            prep(0, 0),
            MigrationTxState::Broadcast {
                txid: TxId::from_bytes([7; 32]),
            },
            1_600,
        );
        source.scheduled_height = BlockHeight::from_u32(1_000);
        let mut dependent = scheduled_transfer(1, 0, 40, 1_500, MigrationTxState::Signed);
        dependent.depends_on = vec![MigrationTransferId(0)];
        let s = state_with(vec![source, dependent]);

        let overshooting =
            DuenessTargets::new(BlockHeight::from_u32(1_501), BlockHeight::from_u32(1_700));
        assert!(
            s.dead_set(overshooting).is_empty(),
            "an estimated expiry is not a dead-set seed"
        );
        assert!(
            s.expired_transactions(overshooting).is_empty(),
            "nor a rendered expiry determination"
        );
        let v = s.transaction_statuses(overshooting);
        assert_eq!(v[0].blocked_on, Some(Blocker::ExpiryImminent));
        assert_eq!(
            v[1].blocked_on,
            Some(Blocker::Dependencies),
            "the dependent is merely waiting on its source, not stranded behind a dead one"
        );
        assert_eq!(v[1].unsatisfiable_kind, None);

        // Once the wallet has actually scanned past the expiry, every one of those becomes the
        // determination it always would have been.
        let scanned = DuenessTargets::at(BlockHeight::from_u32(1_700));
        assert_eq!(s.dead_set(scanned).len(), 2, "source and dependent alike");
        assert_eq!(
            s.expired_transactions(scanned),
            vec![MigrationTransferId(0)]
        );
        let v = s.transaction_statuses(scanned);
        assert_eq!(v[0].blocked_on, Some(Blocker::Expired));
        assert_eq!(v[1].blocked_on, Some(Blocker::Unsatisfiable));
    }

    /// NEGATIVE: a rebuild throws away a pre-signed artifact and demands a fresh signing, so an
    /// estimated expiry must never surface `Rebuild`. The kernel reports `Waiting` — there is
    /// nothing to do until the scan catches up — and offers the rebuild the moment it does.
    #[test]
    fn an_estimated_expiry_does_not_surface_rebuild() {
        let mut doomed = scheduled_transfer(1, 0, 40, 1_500, MigrationTxState::Proved);
        doomed.expiry_height = BlockHeight::from_u32(1_600);
        let s = state_with(vec![tx(0, prep(0, 0), mined(10)), doomed]);

        assert_eq!(
            s.next_step(
                DuenessTargets::new(BlockHeight::from_u32(1_501), BlockHeight::from_u32(1_700)),
                &[],
            ),
            AdvanceStep::Waiting,
            "the transfer is withheld, not condemned to a re-signing"
        );
        assert_eq!(
            s.next_step(DuenessTargets::at(BlockHeight::from_u32(1_700)), &[]),
            AdvanceStep::Rebuild {
                id: MigrationTransferId(1)
            },
            "the same expiry, once scanned, is the rebuild it always was"
        );
    }

    /// NEGATIVE: the late `Replan` slot fires when every unmined transaction is dead, and the
    /// consumer's contracted response to it (`mark_superseded`) is terminal. An estimate that
    /// overshoots every remaining expiry must not be able to reach it.
    #[test]
    fn an_estimated_expiry_does_not_flip_the_late_replan_gate() {
        let mut a = scheduled_transfer(1, 0, 40, 1_500, MigrationTxState::Proved);
        a.expiry_height = BlockHeight::from_u32(1_600);
        let mut b = scheduled_transfer(2, 1, 40, 1_500, MigrationTxState::Proved);
        b.expiry_height = BlockHeight::from_u32(1_610);
        let s = state_with(vec![tx(0, prep(0, 0), mined(10)), a, b]);

        assert_eq!(
            s.next_step(
                DuenessTargets::new(BlockHeight::from_u32(1_501), BlockHeight::from_u32(1_700)),
                &[],
            ),
            AdvanceStep::Waiting,
            "no live work, but no determination either: the honest answer is to wait"
        );
        assert_eq!(
            s.next_step(DuenessTargets::at(BlockHeight::from_u32(1_700)), &[]),
            AdvanceStep::Rebuild {
                id: MigrationTransferId(1)
            },
            "scanned, both transfers are rebuildable rather than stranded"
        );
    }

    /// NEGATIVE, and the worst of them: the durable closure WRITES `Inherited` marks into the
    /// store, and only a reorg truncation below the stamp clears one — but an estimate names no
    /// chain state to truncate, so a mark stamped off it would stand against a live transaction
    /// forever.
    #[test]
    fn record_satisfiability_does_not_inherit_from_an_estimated_expiry() {
        let build = || {
            let source = tx_expiring(
                0,
                prep(0, 0),
                MigrationTxState::Broadcast {
                    txid: TxId::from_bytes([7; 32]),
                },
                1_600,
            );
            let mut dependent = tx(1, transfer(0), MigrationTxState::Signed);
            dependent.depends_on = vec![MigrationTransferId(0)];
            state_with(vec![source, dependent])
        };

        let mut overshot = build();
        overshot.record_satisfiability(
            DuenessTargets::new(BlockHeight::from_u32(1_501), BlockHeight::from_u32(1_700)),
            &[],
        );
        assert_eq!(
            overshot.transactions[1].unsatisfiable, None,
            "no Inherited mark is persisted off an expiry only the estimate believes in"
        );

        let mut scanned = build();
        scanned.record_satisfiability(DuenessTargets::at(BlockHeight::from_u32(1_700)), &[]);
        assert_eq!(
            scanned.transactions[1].unsatisfiable,
            Some((BlockHeight::from_u32(1_600), UnsatisfiableKind::Inherited)),
            "the same closure, run at the scanned frontier, stamps at the source's expiry"
        );
    }

    /// The prove side of the estimate's licence: SKIPPING a proof is reversible (nothing is
    /// recorded, no artifact discarded), so a transfer the estimate believes lapsed is not proved
    /// — and is reported under the same `ExpiryImminent` blocker the broadcast withhold uses.
    #[test]
    fn proving_is_skipped_for_a_transfer_doomed_by_the_estimate() {
        let mut doomed = scheduled_transfer(1, 0, 40, 1_500, MigrationTxState::Signed);
        doomed.expiry_height = BlockHeight::from_u32(1_600);
        let s = state_with(vec![tx(0, prep(0, 0), mined(10)), doomed]);
        let targets =
            DuenessTargets::new(BlockHeight::from_u32(1_501), BlockHeight::from_u32(1_700));

        assert!(!s.prove_ready(&s.transactions[1], targets));
        assert_eq!(s.next_step(targets, &[]), AdvanceStep::Waiting);
        assert_eq!(
            s.transaction_statuses(targets)[1].blocked_on,
            Some(Blocker::ExpiryImminent)
        );
        // Un-doomed by the same pair once its expiry is out of the window: proved as usual.
        let mut live = s;
        live.transactions[1].expiry_height = BlockHeight::from_u32(1_800);
        assert_eq!(
            live.next_step(targets, &[]),
            AdvanceStep::Prove {
                transactions: vec![pt(1, transfer(0))],
            }
        );
    }

    /// NEGATIVE: an estimate cannot conjure a commitment-tree checkpoint. A transfer whose drawn
    /// anchor boundary has settled by the ESTIMATE but not by the scan is not prove-ready — the
    /// wallet does not hold the checkpoint, so the proof would only fail in the prover — and is
    /// still reported as waiting on its boundary.
    #[test]
    fn an_estimate_does_not_conjure_a_settled_anchor_boundary() {
        // Boundary 1_500 settles at target 1_511 (`boundary + PROVABLE_ANCHOR_DEPTH < target`),
        // so a scan at 1_510 has not reached it while an estimate at 1_700 has.
        let s = state_with(vec![
            tx(0, prep(0, 0), mined(10)),
            scheduled_transfer(1, 0, 1_500, 1_400, MigrationTxState::Signed),
        ]);
        let targets =
            DuenessTargets::new(BlockHeight::from_u32(1_510), BlockHeight::from_u32(1_700));

        assert!(
            !s.prove_ready(&s.transactions[1], targets),
            "the boundary has not settled to the provability depth in the wallet's own scan"
        );
        assert_eq!(s.next_step(targets, &[]), AdvanceStep::Waiting);
        assert_eq!(
            s.transaction_statuses(targets)[1].blocked_on,
            Some(Blocker::AnchorBoundary)
        );
        // One more scanned block and the boundary is deep enough, whatever the estimate says.
        assert_eq!(
            s.next_step(
                DuenessTargets::new(BlockHeight::from_u32(1_511), BlockHeight::from_u32(1_700)),
                &[],
            ),
            AdvanceStep::Prove {
                transactions: vec![pt(1, transfer(0))],
            }
        );
    }
}
