//! Migration state logic: the pure, backend-agnostic methods a consuming application uses to drive a
//! committed migration and render its progress.
//!
//! These are methods on [`MigrationState`] that operate only on the persisted state and never touch a
//! wallet, a prover, or the network, so every consumer (a mobile wallet using these crates directly,
//! or a server like Zallet) makes the SAME decisions from the SAME state. The consumer supplies the
//! I/O: it detects that a broadcast transaction has mined (via its own chain view) and calls
//! [`MigrationState::mark_mined`], it broadcasts a transaction and calls
//! [`MigrationState::mark_broadcast`], it reports evidence that a transaction can never mine (a
//! funding note spent outside the migration, a node rejection) with
//! [`MigrationState::mark_invalid`], and it performs the build/prove/broadcast work that
//! [`MigrationState::next_step`] tells it to do. The decision of WHAT to do next, and the transaction
//! status a wallet shows the user, live here.
//!
//! Every transaction is built and pre-signed when the migration is committed (one signing phase;
//! anchors and witnesses are deferred to proving time per ZIP 374), so the state machine's only
//! job is to ORDER the remaining work: a transaction is proved — installing its anchor and
//! witnesses — once its anchor is resolvable (for a transfer, once its drawn boundary settles),
//! and becomes broadcastable once it is proved, its dependencies (the preparation layers that
//! mint its inputs) have mined, and its scheduled height has arrived. See
//! [`MigrationState::next_step`] for how the two are ordered and the sync/broadcast session
//! separation that ordering is designed around.

use alloc::vec::Vec;

use getset::{CopyGetters, Getters};
use rand_core::{CryptoRng, RngCore};
use zcash_protocol::TxId;
use zcash_protocol::consensus::BlockHeight;

use crate::engine::{
    InvalidReason, MigrationState, MigrationStatus, MigrationTransaction, MigrationTransferId,
    MigrationTxKind, MigrationTxState,
};
use crate::scheduling::{self, SyncWakeup, WakeupParams, WakeupScheduleError};

/// The next thing to do to advance a committed migration, decided purely from its state. The consumer
/// performs the corresponding I/O and updates the state (via the commit functions and
/// [`MigrationState::mark_broadcast`] / [`MigrationState::mark_mined`]), then calls
/// [`MigrationState::next_step`] again.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdvanceStep {
    /// No automatic step can advance this migration: transaction `id` is marked
    /// [`Invalid`](MigrationTxState::Invalid) (see its status for the reason), and the consumer
    /// resolves it out-of-band — typically by cancelling the migration and re-planning the
    /// remaining balance.
    ///
    /// Surfaced ahead of all actionable work: every broadcast of an invalid transaction is a
    /// guaranteed rejection (and everything depending on it waits forever), so a consumer needs
    /// the attention signal before it continues to drive the run. Only a terminal migration
    /// ([`Complete`](Self::Complete)) takes precedence.
    Attend {
        /// The invalid transaction needing attention.
        id: MigrationTransferId,
    },
    /// Prove this pre-signed transaction (install its deferred Orchard anchor and spend witnesses and
    /// store the proven PCZT), WITHOUT broadcasting: its dependencies are mined and, for a transfer,
    /// its drawn anchor boundary has settled (the boundary block is strictly below the chain tip, so
    /// its checkpoint exists in the wallet's commitment tree). Broadcast is a separate later step;
    /// whether it belongs in the same waking session depends on the transaction's `kind` (see that
    /// field, and [`MigrationState::next_step`]).
    ///
    /// Proving is not time-critical: the wallet durably retains the boundary checkpoints its
    /// committed transfers anchor to (they are exempt from ordinary checkpoint pruning; see
    /// [`MigrationBackend::scheduling_params`](crate::engine::MigrationBackend::scheduling_params)),
    /// so a transfer remains provable from the moment its boundary settles until it is broadcast.
    /// Proving EARLY — at a sync wake-up well before the broadcast height — is what keeps the
    /// sync-heavy work out of the broadcast session.
    Prove {
        /// The transaction to prove.
        id: MigrationTransferId,
        /// What the transaction is, surfaced because the two kinds want different session
        /// handling. A PREPARATION becomes provable only once its broadcast schedule is due, so
        /// when it is surfaced here it is by construction ready to broadcast the moment it is
        /// proved: prove it against a fresh checkpoint at the tip and broadcast it at the same
        /// wake-up, like an ordinary transaction. A TRANSFER is surfaced as soon as its drawn
        /// anchor boundary settles, typically well before its scheduled broadcast height: prove it
        /// now and leave the broadcast to its own (later) session.
        kind: MigrationTxKind,
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
    /// Nothing to do now: waiting for one or more transactions to mine, for an anchor boundary to
    /// settle, or for a scheduled height to arrive.
    Waiting,
    /// Nothing will ever be actionable again: every transaction is mined, or the migration has
    /// reached a terminal status (complete, or failed/cancelled — see
    /// [`MigrationState::is_terminal`]), so a driver can stop polling it.
    Complete,
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
    /// Its [`expiry_height`](MigrationTransaction::expiry_height) has passed without it mining, so it
    /// can no longer be included in a block (ZIP 203): the pre-signed artifact is dead, and an
    /// entirely new transaction must be constructed and signed anew (with a fresh anchor and
    /// expiry, its denomination unchanged) before this part can advance. For a TRANSFER the
    /// consumer performs that rebuild when [`next_step`](MigrationState::next_step) returns
    /// [`AdvanceStep::Rebuild`]. For a PREPARATION no single-transaction rebuild exists (its
    /// dependents' pre-signatures commit to the notes it would have minted), so this blocker is the
    /// signal that the migration needs a new signing ceremony over the affected subtree. Reported
    /// so a wallet can show the transaction as needing attention rather than as merely waiting.
    Expired,
    /// Marked [`Invalid`](MigrationTxState::Invalid): the consumer observed evidence that this
    /// transaction can never mine (its [`state`](TransactionStatus::state) carries the
    /// [`InvalidReason`]), so no chain condition will ever make it actionable again. Its
    /// resolution is out-of-band, surfaced to the driver as [`AdvanceStep::Attend`]. Reported as a
    /// blocker — like [`Signature`](Self::Signature) and [`Expired`](Self::Expired), whose facts
    /// the state and heights also already imply — so a wallet keyed on blockers shows it as
    /// needing attention rather than as done.
    Invalid,
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
    /// Why it is not yet actionable, when it is waiting (and not already broadcast or mined).
    #[getset(get_copy = "pub")]
    pub(crate) blocked_on: Option<Blocker>,
    /// The height it was mined at, once mined.
    #[getset(get_copy = "pub")]
    pub(crate) mined_height: Option<BlockHeight>,
    /// The transaction id (raw internal bytes), once broadcast.
    #[getset(get_copy = "pub")]
    pub(crate) txid: Option<TxId>,
}

/// The pair of target heights the estimate-aware delivery queries
/// ([`MigrationState::next_provable_at`], [`MigrationState::next_broadcastable_at`]) evaluate
/// due-ness against, for a consumer whose SCANNED chain view lags the real chain between syncs (a
/// mobile wallet waking from the background).
///
/// `scanned` is the trustworthy target: `scanned_tip + 1`, the height of the next block a
/// transaction could mine in as witnessed by the data the wallet has actually scanned. `effective`
/// is the serving target: a wall-clock ESTIMATE of where the real chain's target has reached,
/// clamped to never fall below `scanned`, consulted only to decide that a scheduled height has
/// ARRIVED.
///
/// The rule the pair encodes: **the estimate may only ACCELERATE schedule due-ness; expiry,
/// rebuild eligibility, and every other destructive decision evaluate on the scanned target
/// only.** An estimate can be wrong in either direction, and the two kinds of decision fail
/// differently. Serving a broadcast a few blocks before its scheduled height is harmless — the
/// schedule's jitter dwarfs the estimate's error. Treating a transfer as EXPIRED on an estimate
/// would trigger its rebuild — an entirely new, freshly signed transaction — while the original
/// may in fact still mine, making the rebuild a double-spend of it. A transfer's anchor-boundary
/// settledness is likewise a statement about scanned data (the boundary checkpoint either exists
/// in the wallet's commitment tree or it does not — an estimate cannot conjure it), so it too is
/// judged on `scanned` alone.
#[derive(Clone, Copy, Debug, PartialEq, Eq, CopyGetters)]
pub struct DuenessTargets {
    /// The scanned target height (`scanned_tip + 1`): expiry, anchor-boundary settledness, and
    /// every destructive decision evaluate here.
    #[getset(get_copy = "pub")]
    scanned: BlockHeight,
    /// The serving target: schedule due-ness evaluates here. Never below
    /// [`scanned`](Self::scanned), by construction.
    #[getset(get_copy = "pub")]
    effective: BlockHeight,
}

impl DuenessTargets {
    /// The targets for a scanned target height plus an optional wall-clock estimate of the real
    /// chain's target: `effective` is the larger of the two, or `scanned_target` alone when there
    /// is no estimate. The clamp is what maintains `effective >= scanned`: an estimate BEHIND the
    /// scanned tip is simply stale (the scanned data has overtaken it), and must not drag serving
    /// backwards below what the scanned view already proves due.
    pub fn new(scanned_target: BlockHeight, estimated_target: Option<BlockHeight>) -> Self {
        let effective = estimated_target.map_or(scanned_target, |estimated| {
            core::cmp::max(scanned_target, estimated)
        });
        Self {
            scanned: scanned_target,
            effective,
        }
    }

    /// The degenerate targets of a consumer with no estimate: both heights are `target`. The
    /// single-target queries delegate through this, making them the `effective == scanned` special
    /// case of the `_at` variants by construction.
    pub const fn at(target: BlockHeight) -> Self {
        Self {
            scanned: target,
            effective: target,
        }
    }
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
    /// expiry and is final. An [`Invalid`](MigrationTxState::Invalid) transaction is never expired
    /// either — its death is already recorded, and its remediation (out-of-band, via
    /// [`AdvanceStep::Attend`]) is not the expiry path's rebuild — so a dead transaction is never
    /// reported through both channels at once.
    fn is_expired(t: &MigrationTransaction, target_height: BlockHeight) -> bool {
        if matches!(
            t.state,
            MigrationTxState::Mined { .. } | MigrationTxState::Invalid { .. }
        ) {
            return false;
        }
        let expiry = u32::from(t.expiry_height);
        expiry != 0 && expiry < u32::from(target_height)
    }

    /// The ids of every transaction that has expired at `target_height` (`chain_tip + 1`) without
    /// mining. This is the detection a wallet runs on launch to reconcile a schedule whose
    /// broadcast windows were missed: each id it returns is a pre-signed transaction the node would
    /// now reject, whose part must be carried by an entirely new transaction, constructed and
    /// signed anew with a fresh anchor and expiry while keeping its denomination. A TRANSFER here
    /// is also surfaced as [`AdvanceStep::Rebuild`]; a PREPARATION is not (rebuilding it means
    /// re-signing its whole dependent subtree, a remediation beyond a single advance step), so a
    /// wallet uses this list to tell the user the migration needs a new signing ceremony. A
    /// transaction marked [`Invalid`](MigrationTxState::Invalid) is never listed: its death is
    /// already recorded, surfaced as [`AdvanceStep::Attend`] and resolved out-of-band rather than
    /// through the expiry path.
    pub fn expired_transactions(&self, target_height: BlockHeight) -> Vec<MigrationTransferId> {
        self.transactions
            .iter()
            .filter(|t| Self::is_expired(t, target_height))
            .map(|t| t.id)
            .collect()
    }

    /// The id of the next TRANSFER that must be rebuilt because it has expired (see
    /// [`Self::is_expired`]). Only a transfer is surfaced: it is a leaf of the dependency graph, so
    /// it can be reconstructed and signed anew on its own. An expired PREPARATION has no
    /// single-transaction remediation — its dependents' pre-signatures commit to the notes it would
    /// have minted, so rebuilding it means re-signing the whole dependent subtree (a follow-on
    /// slice); it stays visible through [`Blocker::Expired`] and [`Self::expired_transactions`].
    fn next_rebuildable(&self, target_height: BlockHeight) -> Option<MigrationTransferId> {
        self.transactions
            .iter()
            .filter(|t| matches!(t.kind, MigrationTxKind::Transfer { .. }))
            .find(|t| Self::is_expired(t, target_height))
            .map(|t| t.id)
    }

    /// The id of the first transaction marked [`Invalid`](MigrationTxState::Invalid), the one
    /// [`Self::next_step`] surfaces as [`AdvanceStep::Attend`]. Purely state-matched: invalidity
    /// is recorded evidence, not a height computation, so no target height is involved.
    fn next_attention(&self) -> Option<MigrationTransferId> {
        self.transactions
            .iter()
            .find(|t| matches!(t.state, MigrationTxState::Invalid { .. }))
            .map(|t| t.id)
    }

    /// Whether transaction `t` is ready to PROVE at `targets`: its dependencies are mined and its
    /// Orchard anchor is resolvable from the wallet's commitment tree right now.
    ///
    /// A TRANSFER anchors to a drawn boundary ([`anchor_boundary`](MigrationTransaction::anchor_boundary)),
    /// which must have SETTLED: the boundary block must be strictly below the chain tip so its
    /// checkpoint exists in the tree. Proving becomes available as soon as that holds, decoupled
    /// from the (later) broadcast schedule: the wallet durably retains the boundary checkpoint, so
    /// nothing forces the proof to happen promptly, but making it available early lets the
    /// sync-heavy proving work happen at a sync wake-up in a different waking session from the
    /// broadcast (see [`Self::next_step`]). A PREPARATION carries no drawn boundary and anchors to
    /// a fresh checkpoint at the tip when proved, so it is prove-ready once its dependencies are
    /// mined and its scheduled height has arrived.
    ///
    /// Under the dual-target rule (see [`DuenessTargets`]) only the preparation's schedule
    /// comparison consults the EFFECTIVE serving target; expiry and a transfer's boundary
    /// settledness are statements about scanned chain data, judged on the SCANNED target alone.
    fn prove_ready_at(&self, t: &MigrationTransaction, targets: DuenessTargets) -> bool {
        // An expired transaction can never be mined, so proving it is wasted work: it must be rebuilt
        // (with a fresh anchor and expiry) first. Guarding here keeps `next_provable` from ever
        // offering an expired transaction. Judged on the SCANNED target: an estimate never decides
        // an expiry.
        if Self::is_expired(t, targets.scanned()) {
            return false;
        }
        if !self.deps_mined(&t.depends_on) {
            return false;
        }
        match t.anchor_boundary {
            // A transfer: the boundary must be strictly below the SCANNED tip — its checkpoint
            // exists in the wallet's tree only once the scanned data proves the boundary settled;
            // an estimate cannot conjure it. The scanned target is `tip + 1`, so `boundary < tip`
            // is `boundary + 1 < target`.
            Some(boundary) => u32::from(boundary) + 1 < u32::from(targets.scanned()),
            // A preparation: prove-ready once its schedule is due on the SERVING target (the one
            // comparison the estimate may accelerate).
            None => t.scheduled_height <= targets.effective(),
        }
    }

    /// The next pre-signed transaction ready to PROVE, as [`Self::next_provable_at`] selects it,
    /// with the whole transaction visible so [`Self::next_step`] can also surface its kind.
    fn next_provable_tx_at(&self, targets: DuenessTargets) -> Option<&MigrationTransaction> {
        self.transactions.iter().find(|t| {
            matches!(t.state, MigrationTxState::Signed) && self.prove_ready_at(t, targets)
        })
    }

    /// The id of the next pre-signed transaction ready to PROVE (move `Signed -> Proved`): its anchor
    /// is resolvable now. Proving is decoupled from broadcasting so a transfer can be proved at a
    /// sync wake-up well before its scheduled broadcast height, keeping the sync work and the
    /// broadcast in separate waking sessions.
    ///
    /// Equivalent to [`Self::next_provable_at`] with both targets at `target_height` (the
    /// no-estimate case).
    pub fn next_provable(&self, target_height: BlockHeight) -> Option<MigrationTransferId> {
        self.next_provable_at(DuenessTargets::at(target_height))
    }

    /// The estimate-aware variant of [`Self::next_provable`], for a consumer whose scanned chain
    /// view lags the real chain (see [`DuenessTargets`]): a preparation transaction's schedule
    /// due-ness is judged on the EFFECTIVE serving target, so a wall-clock estimate can surface it
    /// at the wake-up its schedule aimed at rather than one sync later; expiry and a transfer's
    /// anchor-boundary settledness are judged on the SCANNED target alone.
    pub fn next_provable_at(&self, targets: DuenessTargets) -> Option<MigrationTransferId> {
        self.next_provable_tx_at(targets).map(|t| t.id)
    }

    /// The id of the next transaction ready to BROADCAST: already `Proved`, its dependencies mined,
    /// and scheduled at or before `target_height` (`chain_tip + 1`).
    ///
    /// Equivalent to [`Self::next_broadcastable_at`] with both targets at `target_height` (the
    /// no-estimate case).
    pub fn next_broadcastable(&self, target_height: BlockHeight) -> Option<MigrationTransferId> {
        self.next_broadcastable_at(DuenessTargets::at(target_height))
    }

    /// The estimate-aware variant of [`Self::next_broadcastable`], for a consumer whose scanned
    /// chain view lags the real chain (see [`DuenessTargets`]): the schedule comparison is judged
    /// on the EFFECTIVE serving target, so a wall-clock estimate can surface a due broadcast at
    /// the wake-up its schedule aimed at rather than one sync later.
    ///
    /// The expiry handling is deliberately ASYMMETRIC between the two targets. A transaction the
    /// SCANNED target proves expired is excluded exactly as everywhere else, and the ordinary
    /// expired -> [`AdvanceStep::Rebuild`] path owns it. A transaction whose
    /// [`expiry_height`](MigrationTransaction::expiry_height) only the EFFECTIVE target has passed
    /// is ALSO not served, yet is treated as expired NOWHERE: if the estimate is right, the node's
    /// tip is past its expiry and broadcasting it is a guaranteed network rejection, so the
    /// protective refusal wastes nothing; if the estimate is wrong, one broadcast waits until the
    /// scanned tip either reaches the scheduled height (still unexpired: it is served) or confirms
    /// the expiry (the rebuild path takes over). The estimate may WITHHOLD a doomed submission
    /// (protective, reversible) but never trigger a rebuild (destructive — a new signing —
    /// requiring the scanned tip's proof).
    pub fn next_broadcastable_at(&self, targets: DuenessTargets) -> Option<MigrationTransferId> {
        self.transactions
            .iter()
            .find(|t| {
                matches!(t.state, MigrationTxState::Proved)
                    && t.scheduled_height <= targets.effective()
                    && self.deps_mined(&t.depends_on)
                    // An expired proven transaction would be rejected by the node; it must be rebuilt,
                    // not broadcast. This is what stops a wallet resumed after its broadcast windows
                    // lapsed from broadcasting a stale, no-longer-includable transaction. Judged on
                    // the EFFECTIVE target: since `effective >= scanned`, the one comparison both
                    // excludes a scanned-confirmed expiry (like every other query) and refuses the
                    // merely-estimated one — the doomed-broadcast guard; see the method docs for
                    // the asymmetry.
                    && !Self::is_expired(t, targets.effective())
            })
            .map(|t| t.id)
    }

    /// The minimal schedule of sync/proving wake-ups for the transfers that still need proofs, as
    /// of the observed chain tip `current_tip`: each entry is a height at which to wake, sync, and
    /// prove (see [`crate::scheduling::schedule_sync_wakeups`], which defines the windows, the
    /// minimality guarantee, the jitter, and the immediate wake-up that collects overdue
    /// transfers). This is the schedule a background-constrained wallet registers with its OS,
    /// alongside the (independent) broadcast heights the transfers themselves carry.
    ///
    /// Unlike the sibling query methods, which take a `target_height` (`chain_tip + 1`, the next
    /// block a transaction could mine in), this method takes the tip itself: wake-up heights are
    /// floored at the tip (a wake-up at exactly `current_tip` means "right now"). Expiry is still
    /// judged at `current_tip + 1`, consistent with [`Self::expired_transactions`].
    ///
    /// Covered are transfers in the `Signed` or `AwaitingSignature` state — proving and signature
    /// application are independent operations, so a transfer whose signed PCZT has not yet been
    /// returned by the external signer still needs its proof on the same schedule — while
    /// `Proved`, `Broadcast`, `Mined`, and `Invalid` transfers, expired transfers (their rebuild
    /// reschedules them), and preparations (which anchor at the tip when proved, driven by
    /// [`Self::next_step`] at their own broadcast wake-ups) are not. A transfer lacking a drawn
    /// anchor boundary (impossible for a state committed by this crate) likewise contributes no
    /// wake-up: like a preparation, it is driven by [`Self::next_step`] at its scheduled height.
    /// Nothing is persisted: the schedule is derived from the migration state, so recompute it —
    /// with fresh jitter — after any state change (a proof stored, a rebuild, a missed wake-up).
    pub fn sync_wakeup_schedule<R: RngCore + CryptoRng>(
        &self,
        current_tip: BlockHeight,
        params: &WakeupParams,
        rng: &mut R,
    ) -> Result<Vec<SyncWakeup<MigrationTransferId>>, WakeupScheduleError<MigrationTransferId>>
    {
        // Expiry semantics are defined against the next block a transaction could mine in.
        let target_height = current_tip + 1;
        let transfers: Vec<(MigrationTransferId, BlockHeight, BlockHeight)> = self
            .transactions
            .iter()
            .filter(|t| {
                matches!(t.kind, MigrationTxKind::Transfer { .. })
                    && matches!(
                        t.state,
                        MigrationTxState::Signed | MigrationTxState::AwaitingSignature
                    )
                    && !Self::is_expired(t, target_height)
            })
            .filter_map(|t| t.anchor_boundary.map(|a| (t.id, a, t.scheduled_height)))
            .collect();
        scheduling::schedule_sync_wakeups(params, current_tip, &transfers, rng)
    }

    /// Recomputes the overall [`MigrationStatus`]: `Complete` once every transaction is mined,
    /// `InProgress` once any has been broadcast or mined. Leaves the status unchanged otherwise (an
    /// uncommitted or freshly committed migration keeps its `Planning`/`Committed` status until work
    /// begins). A run containing an [`Invalid`](MigrationTxState::Invalid) transaction is by the
    /// same all-mined test never `Complete`: it stays non-terminal, with [`Self::next_step`]
    /// reporting [`AdvanceStep::Attend`], until the consumer resolves it (typically by cancelling,
    /// which IS terminal, and re-planning).
    pub fn recompute_status(&mut self) {
        // A terminal status (Complete or Failed, the latter also used for a cancelled migration) is
        // final: never move out of it. Otherwise a cancelled migration whose transactions were
        // already broadcast would be resurrected to InProgress the next time the status is recomputed.
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

    /// Whether this migration has reached a terminal status (`Complete` or `Failed`), so a new
    /// migration may replace it. A non-terminal migration is still in progress and must not be
    /// overwritten.
    pub fn is_terminal(&self) -> bool {
        matches!(
            self.status,
            MigrationStatus::Complete | MigrationStatus::Failed
        )
    }

    /// Records that the transaction `id` was broadcast with the given `txid`, then recomputes the
    /// overall status. The consumer calls this after it broadcasts the transaction the engine handed
    /// it. An unknown `id` is a no-op.
    ///
    /// An [`Invalid`](MigrationTxState::Invalid) transaction is left unchanged: a submission is
    /// not evidence of validity (a node accepting a transaction into its mempool does not make it
    /// minable), so it must not erase a recorded death — if the transaction does mine after all,
    /// [`Self::mark_mined`] supersedes the verdict then.
    pub fn mark_broadcast(&mut self, id: MigrationTransferId, txid: TxId) {
        if let Some(tx) = self
            .transactions
            .iter_mut()
            .find(|t| t.id == id && !matches!(t.state, MigrationTxState::Invalid { .. }))
        {
            tx.state = MigrationTxState::Broadcast { txid };
        }
        self.recompute_status();
    }

    /// Records that the transaction `id` was mined at `height`, then recomputes the overall status. The
    /// consumer detects mining through its own chain view (matching a broadcast transaction's txid) and
    /// calls this, which is what lets a later preparation layer or the transfers become actionable.
    /// An unknown `id` is a no-op.
    ///
    /// Mining DOES overwrite an [`Invalid`](MigrationTxState::Invalid) transaction: inclusion in a
    /// block is the one piece of evidence that outranks an invalidity verdict (which rests on a
    /// single node's rejection or the consumer's own scan inference), so a stale or mistaken
    /// [`Self::mark_invalid`] is self-healing — the chain's verdict wins whichever report arrives
    /// last.
    pub fn mark_mined(&mut self, id: MigrationTransferId, height: BlockHeight) {
        if let Some(tx) = self.transactions.iter_mut().find(|t| t.id == id) {
            tx.state = MigrationTxState::Mined { height };
        }
        self.recompute_status();
    }

    /// Records the consumer's observed EVIDENCE that transaction `id` can never mine — a funding
    /// note spent outside the migration, or a node rejecting the submission — moving it to
    /// [`Invalid`](MigrationTxState::Invalid) with the given `reason`, then recomputes the overall
    /// status. The consumer reports this from its own I/O (its wallet scan, its broadcast error
    /// handling): the engine deliberately performs neither, so an event-based death exists for the
    /// state machine only once it is recorded here. [`Self::next_step`] thereafter surfaces the
    /// transaction as [`AdvanceStep::Attend`], and every actionable query excludes it.
    ///
    /// An already-[`Mined`](MigrationTxState::Mined) transaction is left unchanged: it was
    /// included in a block, so it SUCCEEDED, and whatever prompted the call is stale — refusing it
    /// here is what makes a race between a mining detection and an invalidity report converge on
    /// the chain's verdict in either arrival order. An unknown `id` is a no-op, matching
    /// [`Self::mark_broadcast`] / [`Self::mark_mined`]. Every other state is overwritten,
    /// including an earlier `Invalid` (the newest evidence carries the reason shown to the user).
    pub fn mark_invalid(&mut self, id: MigrationTransferId, reason: InvalidReason) {
        if let Some(tx) = self
            .transactions
            .iter_mut()
            .find(|t| t.id == id && !matches!(t.state, MigrationTxState::Mined { .. }))
        {
            tx.state = MigrationTxState::Invalid { reason };
        }
        self.recompute_status();
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
    /// highest-priority action available at `target_height` (`chain_tip + 1`, the height of the
    /// next block a transaction could be mined in). The decision is made once, here, so every
    /// consumer (a mobile wallet using these crates directly, or a server like Zallet) advances
    /// the same state the same way.
    ///
    /// # The drive loop
    ///
    /// One call returns ONE step. The consumer performs that step's I/O, records the outcome in
    /// the state, persists it, and calls this again; a call is pure, so until the state records
    /// the step's completion, the same step is returned. The steps map onto the crate's
    /// operations as follows:
    ///
    /// - [`AdvanceStep::Attend`]: the transaction is marked [`Invalid`](MigrationTxState::Invalid)
    ///   (its entry in [`Self::transaction_statuses`] carries the reason) and nothing this crate
    ///   automates can advance it: resolve it out-of-band, typically by cancelling the migration
    ///   and re-planning the remaining balance. The one step no engine operation discharges.
    /// - [`AdvanceStep::Prove`]: install the transaction's deferred anchor and witnesses and store
    ///   the proven PCZT — [`prove_transfer`](crate::engine::prove_transfer) /
    ///   [`prove_preparation`](crate::engine::prove_preparation), which also record the
    ///   `Signed -> Proved` transition. Proving needs a SYNCED wallet and mutable access to its
    ///   commitment trees, but only the account's viewing key. The step carries the transaction's
    ///   kind so the consumer can tell, without a lookup, whether the broadcast follows in the
    ///   same session (a preparation) or in its own later one (a transfer); see below.
    /// - [`AdvanceStep::Broadcast`]: submit the stored proven transaction to the network, then
    ///   record it with [`Self::mark_broadcast`]. Its mining is later detected through the
    ///   consumer's own chain view and recorded with [`Self::mark_mined`], which is what unblocks
    ///   the transactions depending on it.
    /// - [`AdvanceStep::Rebuild`]: construct and sign a replacement for an expired transfer —
    ///   [`rebuild_expired_transfer`](crate::engine::rebuild_expired_transfer) or its unsigned
    ///   (external-signer) variant. The only step that needs the account's SPEND AUTHORITY.
    /// - [`AdvanceStep::Waiting`]: nothing is actionable at this height. Consult
    ///   [`Self::transaction_statuses`] for what each transaction is blocked on, and register the
    ///   heights at which to wake and re-check: [`Self::sync_wakeup_schedule`] for the proving
    ///   wake-ups, plus each transaction's own scheduled broadcast height.
    /// - [`AdvanceStep::Complete`]: the migration is terminal (every transaction mined, or the
    ///   migration failed/cancelled); nothing will ever be actionable again, so stop polling.
    ///
    /// # Ordering, and what it implies for wallet construction
    ///
    /// When several actions are available at once the priority is ATTEND, then BROADCAST, then
    /// PROVE, then REBUILD.
    ///
    /// Attend outranks everything but a terminal run: an invalid transaction means part of the
    /// migration is dead in a way no automatic step remedies — every broadcast of it is a
    /// guaranteed rejection, and everything depending on it waits forever — so a consumer must
    /// receive the attention signal before it continues to drive, rather than after it has spent
    /// its waking sessions working a run whose outcome is already decided. (The signal hides no
    /// work: the still-valid transactions stay visible through [`Self::transaction_statuses`] and
    /// served by [`Self::next_provable`] / [`Self::next_broadcastable`], so a consumer that
    /// deliberately continues past it can.)
    ///
    /// Broadcast precedes prove because the two kinds of work want to be in DIFFERENT WAKING
    /// SESSIONS. ZIP 318 requires that a background wake window be used either to sync the wallet
    /// or to broadcast a due transfer, never both, so a network observer cannot correlate a
    /// wallet's sync traffic with the transactions it broadcasts. Broadcasting a stored proven
    /// transaction requires no sync at all; proving is inherently sync-bound (it resolves anchors
    /// and witnesses from the synced commitment tree). Surfacing every due broadcast before any
    /// proving work is what makes a broadcast-only session possible: a wallet that wakes to find
    /// transactions due submits them immediately, without first initiating sync operations (unless
    /// the user independently needs to sync, e.g. to spend funds manually). Note that this method
    /// has no notion of a session — once every due broadcast is dispatched it will offer proving
    /// work in the same loop, and enforcing the session separation is the CONSUMER's runtime
    /// policy (see the "Out of scope" notes in [`crate::scheduling`]): a wallet honoring it stops
    /// driving the migration after broadcasting and leaves the offered proving work to its next
    /// sync wake-up.
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
    /// and [`Self::expired_transactions`] instead.
    ///
    /// A missed schedule degrades gracefully rather than requiring reconciliation: a wallet that
    /// slept through a transfer's proving wake-ups and its broadcast height is simply offered
    /// `Prove` and then `Broadcast` for it as soon as it wakes — or `Rebuild`, once the transfer
    /// has expired.
    ///
    /// This method is deliberately SINGLE-TARGET: the drive loop is evaluated on the consumer's
    /// scanned chain view (`target_height` = `scanned_tip + 1`), since everything it decides —
    /// expiry, boundary settledness, what to rebuild — must rest on data the wallet has actually
    /// seen. A consumer whose scanned tip lags the real chain between syncs and that keeps a
    /// wall-clock estimate of the real target serves its delivery lanes through
    /// [`Self::next_provable_at`] / [`Self::next_broadcastable_at`] instead, where the estimate
    /// may accelerate schedule due-ness (and only that; see [`DuenessTargets`]).
    pub fn next_step(&self, target_height: BlockHeight) -> AdvanceStep {
        // A terminal migration (complete, or failed/cancelled) has no next action: never build or
        // broadcast for it, so a cancelled migration cannot be driven further.
        if self.is_terminal() {
            return AdvanceStep::Complete;
        }
        // An invalid transaction outranks all actionable work: part of the run is dead in a way no
        // automatic step remedies, and the consumer must see that before it keeps driving (see the
        // ordering rationale above). The migration itself is NOT terminal — the consumer resolves
        // the death out-of-band, typically by cancelling and re-planning — which is why this is a
        // step, not a status.
        if let Some(id) = self.next_attention() {
            return AdvanceStep::Attend { id };
        }
        // If the wallet has a transaction available for broadcast, it should immediately
        // do that and *not* initiate any sync operations unless the user specifically needs
        // to sync (e.g. if they need to manually spend some of their funds).
        if let Some(id) = self.next_broadcastable(target_height) {
            return AdvanceStep::Broadcast { id };
        }
        // A wallet should not broadcast and sync in the same waking session unless necessary.
        // At this point we know we're not broadcasting, so we can sync and prove. The kind rides
        // along because it decides the session handling: a preparation is broadcast as soon as it
        // is proved, a transfer's broadcast waits for its own (later) session.
        if let Some(t) = self.next_provable_tx_at(DuenessTargets::at(target_height)) {
            return AdvanceStep::Prove {
                id: t.id,
                kind: t.kind,
            };
        }
        // If we have not been able to make progress on still-valid transactions, then surface any
        // expired transfer for rebuild. Reporting Rebuild in preference to Waiting is what stops
        // the migration stalling forever on a transfer whose broadcast window lapsed: nothing else
        // will ever make it broadcastable again.
        if let Some(id) = self.next_rebuildable(target_height) {
            return AdvanceStep::Rebuild { id };
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

    /// Builds the per-transaction status view at `target_height` (`chain_tip + 1`), so a wallet can
    /// render progress and decide, deterministically and from persisted state alone, the next
    /// transaction to sign or broadcast.
    ///
    /// A `Signed` transaction whose dependencies are mined and whose anchor is resolvable (a
    /// transfer's drawn boundary has settled; a preparation is due on its schedule) is ready to
    /// prove; a `Proved` one whose scheduled height has arrived is ready to broadcast. Otherwise a
    /// waiting transaction reports what it is blocked on: its dependencies (a preparation still to
    /// mine), an anchor boundary yet to settle, the broadcast schedule, an external signature, or
    /// its own death (expired, or marked invalid — the latter with its reason in
    /// [`state`](TransactionStatus::state)).
    pub fn transaction_statuses(&self, target_height: BlockHeight) -> Vec<TransactionStatus> {
        self.transactions
            .iter()
            .map(|t| {
                let deps_ok = self.deps_mined(&t.depends_on);
                // An expired transaction (not yet mined, past its expiry height) can never be mined and
                // must be rebuilt; report that ahead of any other blocker, so a wallet shows it as
                // needing attention rather than as waiting on a dependency or the schedule. (An
                // `Invalid` transaction is never `is_expired`, so its more specific verdict — which
                // carries a reason — is what gets reported below.)
                let (ready, action, blocked_on) = if Self::is_expired(t, target_height) {
                    (false, None, Some(Blocker::Expired))
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
                            } else if self.prove_ready_at(t, DuenessTargets::at(target_height)) {
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
                            } else if t.scheduled_height <= target_height {
                                (true, Some(NextAction::Broadcast), None)
                            } else {
                                (false, None, Some(Blocker::Schedule))
                            }
                        }
                        MigrationTxState::Broadcast { .. } => (false, None, None),
                        MigrationTxState::Mined { .. } => (false, None, None),
                        // Dead by observed event: not actionable, and no chain condition will
                        // change that (`next_step` surfaces the run-level attention signal as
                        // `Attend`). The reason rides in `state`, which this view carries.
                        MigrationTxState::Invalid { .. } => (false, None, Some(Blocker::Invalid)),
                    }
                };
                let txid = match t.state {
                    MigrationTxState::Broadcast { txid } => Some(txid),
                    _ => None,
                };
                let mined_height = match t.state {
                    MigrationTxState::Mined { height } => Some(height),
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
    use zcash_protocol::value::Zatoshis;

    use crate::denomination::DenominationPlan;
    use crate::preparation::PreparationPlan;
    use alloc::vec;

    use crate::scheduling::WakeupParams;
    use rand_chacha::ChaCha8Rng;
    use rand_core::SeedableRng;

    // A migration transaction with the given id/kind/state, no dependencies, scheduled at height 0.
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
        }
    }

    fn prep(layer: usize, index: usize) -> MigrationTxKind {
        MigrationTxKind::Preparation { layer, index }
    }

    fn transfer(crossing: usize) -> MigrationTxKind {
        MigrationTxKind::Transfer { crossing }
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
        }
    }

    fn mined(height: u32) -> MigrationTxState {
        MigrationTxState::Mined {
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
        let views = state.transaction_statuses(BlockHeight::from_u32(100));
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
        assert_eq!(s.next_broadcastable(BlockHeight::from_u32(4)), None);
        // Due and deps mined.
        assert_eq!(
            s.next_broadcastable(BlockHeight::from_u32(5)),
            Some(MigrationTransferId(1))
        );

        // A Signed (not yet proved) transaction is NOT broadcastable: it must be proved first.
        s.transactions[1].state = MigrationTxState::Signed;
        assert_eq!(s.next_broadcastable(BlockHeight::from_u32(5)), None);

        // Dependency not mined: not broadcastable even when Proved.
        s.transactions[1].state = MigrationTxState::Proved;
        s.transactions[0].state = MigrationTxState::Broadcast {
            txid: TxId::from_bytes([0; 32]),
        };
        assert_eq!(s.next_broadcastable(BlockHeight::from_u32(5)), None);
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
            s.next_step(BlockHeight::from_u32(100)),
            AdvanceStep::Prove {
                id: MigrationTransferId(0),
                kind: prep(0, 0),
            }
        );
        s.transactions[0].state = MigrationTxState::Proved;
        assert_eq!(
            s.next_step(BlockHeight::from_u32(100)),
            AdvanceStep::Broadcast {
                id: MigrationTransferId(0)
            }
        );

        // 2) Layer 0 broadcast, not yet mined -> its dependents stay blocked, waiting.
        s.transactions[0].state = MigrationTxState::Broadcast {
            txid: TxId::from_bytes([1; 32]),
        };
        assert_eq!(
            s.next_step(BlockHeight::from_u32(100)),
            AdvanceStep::Waiting
        );

        // 3) Layer 0 mined -> layer 1 becomes provable, then broadcastable.
        s.transactions[0].state = mined(10);
        assert_eq!(
            s.next_step(BlockHeight::from_u32(100)),
            AdvanceStep::Prove {
                id: MigrationTransferId(1),
                kind: prep(1, 0),
            }
        );
        s.transactions[1].state = MigrationTxState::Proved;
        assert_eq!(
            s.next_step(BlockHeight::from_u32(100)),
            AdvanceStep::Broadcast {
                id: MigrationTransferId(1)
            }
        );

        // 4) Layer 1 mined -> the transfer becomes provable, then broadcastable.
        s.transactions[1].state = mined(11);
        assert_eq!(
            s.next_step(BlockHeight::from_u32(100)),
            AdvanceStep::Prove {
                id: MigrationTransferId(2),
                kind: transfer(0),
            }
        );
        s.transactions[2].state = MigrationTxState::Proved;
        assert_eq!(
            s.next_step(BlockHeight::from_u32(100)),
            AdvanceStep::Broadcast {
                id: MigrationTransferId(2)
            }
        );

        // 5) Everything mined -> complete.
        s.transactions[2].state = mined(12);
        assert_eq!(
            s.next_step(BlockHeight::from_u32(100)),
            AdvanceStep::Complete
        );
    }

    #[test]
    fn next_step_waiting_when_schedule_not_reached() {
        let mut xfer = tx(1, transfer(0), MigrationTxState::Signed);
        xfer.scheduled_height = BlockHeight::from_u32(50);
        let s = state_with(vec![tx(0, prep(0, 0), mined(10)), xfer]);
        // The transfer is signed with deps mined but not due yet -> nothing else to do, waiting.
        assert_eq!(s.next_step(BlockHeight::from_u32(20)), AdvanceStep::Waiting);
        // Once due, the first step on a still-`Signed` transaction is to PROVE it (broadcasting is a
        // separate later step, once proved).
        assert_eq!(
            s.next_step(BlockHeight::from_u32(50)),
            AdvanceStep::Prove {
                id: MigrationTransferId(1),
                kind: transfer(0),
            }
        );
    }

    #[test]
    fn mark_transitions_and_status() {
        let mut s = state_with(vec![
            tx(0, prep(0, 0), MigrationTxState::Signed),
            tx(1, transfer(0), MigrationTxState::Signed),
        ]);
        assert_eq!(s.status, MigrationStatus::Committed);

        s.mark_broadcast(MigrationTransferId(0), TxId::from_bytes([7; 32]));
        assert!(matches!(
            s.transactions[0].state,
            MigrationTxState::Broadcast { txid } if txid == TxId::from_bytes([7; 32])
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
            s.next_step(BlockHeight::from_u32(100)),
            AdvanceStep::Complete
        );

        // Detecting a mined transaction still does not resurrect it.
        s.mark_mined(MigrationTransferId(0), BlockHeight::from_u32(10));
        assert_eq!(s.status, MigrationStatus::Failed);
    }

    #[test]
    fn transaction_statuses_report_ready_and_blockers() {
        let mut l1 = tx(1, prep(1, 0), MigrationTxState::Signed);
        l1.depends_on = vec![MigrationTransferId(0)];
        let mut xfer = tx(2, transfer(0), MigrationTxState::Signed);
        xfer.depends_on = vec![MigrationTransferId(1)];
        xfer.scheduled_height = BlockHeight::from_u32(30);
        let s = state_with(vec![tx(0, prep(0, 0), mined(10)), l1, xfer]);

        let views = s.transaction_statuses(BlockHeight::from_u32(100));
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
        let blocked = s.transaction_statuses(BlockHeight::from_u32(20));
        assert!(!blocked[1].ready);
        assert_eq!(blocked[1].blocked_on, Some(Blocker::Schedule));
        let ready = s.transaction_statuses(BlockHeight::from_u32(30));
        assert!(ready[1].ready);
        assert_eq!(ready[1].action, Some(NextAction::Prove));
    }

    #[test]
    fn transfer_prove_ready_waits_for_its_anchor_boundary() {
        // A transfer anchors to a drawn boundary; it is not provable until the boundary block is
        // strictly below the tip (its checkpoint has settled), decoupled from the broadcast schedule.
        let mut xfer = tx(1, transfer(0), MigrationTxState::Signed);
        xfer.depends_on = vec![MigrationTransferId(0)];
        xfer.anchor_boundary = Some(BlockHeight::from_u32(40));
        xfer.scheduled_height = BlockHeight::from_u32(60);
        let mut s = state_with(vec![tx(0, prep(0, 0), mined(10)), xfer]);

        // `target_height` is `tip + 1`. At tip 40 (target 41) the boundary is not yet strictly below
        // the tip -> not provable, blocked on the anchor boundary.
        assert_eq!(s.next_step(BlockHeight::from_u32(41)), AdvanceStep::Waiting);
        let v = s.transaction_statuses(BlockHeight::from_u32(41));
        assert!(!v[1].ready);
        assert_eq!(v[1].blocked_on, Some(Blocker::AnchorBoundary));

        // At tip 41 (target 42) boundary 40 is strictly below the tip -> provable now, even though
        // the broadcast schedule (60) has not arrived.
        assert_eq!(
            s.next_step(BlockHeight::from_u32(42)),
            AdvanceStep::Prove {
                id: MigrationTransferId(1),
                kind: transfer(0),
            }
        );

        // Once proved, it is NOT broadcast until its scheduled height arrives.
        s.transactions[1].state = MigrationTxState::Proved;
        assert_eq!(s.next_step(BlockHeight::from_u32(42)), AdvanceStep::Waiting);
        let v = s.transaction_statuses(BlockHeight::from_u32(42));
        assert!(!v[1].ready);
        assert_eq!(v[1].blocked_on, Some(Blocker::Schedule));

        // At the scheduled height it becomes broadcastable.
        assert_eq!(
            s.next_step(BlockHeight::from_u32(60)),
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
            s.expired_transactions(BlockHeight::from_u32(1_000_000))
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
            s.next_broadcastable(BlockHeight::from_u32(50)),
            Some(MigrationTransferId(1))
        );
        // At target 51 (tip 50) expiry has passed (51 > 50) -> not broadcastable, must be rebuilt.
        assert_eq!(s.next_broadcastable(BlockHeight::from_u32(51)), None);
        assert_eq!(
            s.next_step(BlockHeight::from_u32(51)),
            AdvanceStep::Rebuild {
                id: MigrationTransferId(1)
            }
        );

        // The same holds for a still-`Signed` (unproved) expired transfer: it is not provable either.
        s.transactions[1].state = MigrationTxState::Signed;
        assert_eq!(s.next_provable(BlockHeight::from_u32(51)), None);
        assert_eq!(
            s.next_step(BlockHeight::from_u32(51)),
            AdvanceStep::Rebuild {
                id: MigrationTransferId(1)
            }
        );
    }

    #[test]
    fn expired_transaction_reports_blocker_and_expiry_height() {
        let xfer = tx_expiring(1, transfer(0), MigrationTxState::Proved, 50);
        let s = state_with(vec![tx(0, prep(0, 0), mined(10)), xfer]);

        let v = s.transaction_statuses(BlockHeight::from_u32(51));
        assert!(!v[1].ready);
        assert_eq!(v[1].action, None);
        assert_eq!(v[1].blocked_on, Some(Blocker::Expired));
        assert_eq!(v[1].expiry_height, BlockHeight::from_u32(50));
        assert_eq!(
            s.expired_transactions(BlockHeight::from_u32(51)),
            vec![MigrationTransferId(1)]
        );
    }

    #[test]
    fn mined_transaction_past_expiry_is_not_expired() {
        // A transaction that already mined is final even once the chain passes its expiry height: it
        // was included in time and must never be reported as expired or offered for rebuild.
        let s = state_with(vec![tx_expiring(0, transfer(0), mined(40), 50)]);
        assert!(
            s.expired_transactions(BlockHeight::from_u32(1_000))
                .is_empty()
        );
        let v = s.transaction_statuses(BlockHeight::from_u32(1_000));
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
            s.next_step(BlockHeight::from_u32(51)),
            AdvanceStep::Prove {
                id: MigrationTransferId(1),
                kind: transfer(0),
            }
        );
        // Once the valid transfer is proved and broadcast, the expired one is surfaced for rebuild.
        s.transactions[1].state = MigrationTxState::Broadcast {
            txid: TxId::from_bytes([3; 32]),
        };
        assert_eq!(
            s.next_step(BlockHeight::from_u32(51)),
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
        // `next_step` reports Waiting rather than an unactionable Rebuild, while the expiry stays
        // visible through `Blocker::Expired` and `expired_transactions`.
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

        assert_eq!(s.next_step(BlockHeight::from_u32(51)), AdvanceStep::Waiting);
        let v = s.transaction_statuses(BlockHeight::from_u32(51));
        assert_eq!(v[0].blocked_on, Some(Blocker::Expired));
        assert_eq!(
            s.expired_transactions(BlockHeight::from_u32(51)),
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
            s.next_step(BlockHeight::from_u32(51)),
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
            s.next_step(BlockHeight::from_u32(1_000)),
            AdvanceStep::Complete
        );
    }

    /// A transaction in the given invalid state, for the failure-state tests.
    fn invalid(reason: InvalidReason) -> MigrationTxState {
        MigrationTxState::Invalid { reason }
    }

    /// The precedence pin for evidence-based death: with an invalid transaction present, `Attend`
    /// is surfaced ahead of a broadcast that is due right now (and hence ahead of prove and
    /// rebuild, which rank below broadcast).
    #[test]
    fn attend_precedes_broadcast_and_all_other_work() {
        let due = tx(0, transfer(0), MigrationTxState::Proved); // scheduled at 0: due immediately
        let dead = tx(1, transfer(1), invalid(InvalidReason::FundingSpent));
        let s = state_with(vec![due, dead]);

        assert_eq!(
            s.next_broadcastable(BlockHeight::from_u32(100)),
            Some(MigrationTransferId(0)),
            "the broadcast IS due; the precedence, not the query, holds it back"
        );
        assert_eq!(
            s.next_step(BlockHeight::from_u32(100)),
            AdvanceStep::Attend {
                id: MigrationTransferId(1)
            }
        );
    }

    /// An invalid transaction is excluded from every actionable query — never provable,
    /// broadcastable, or wake-up-scheduled — and its death is reported through the invalidity
    /// channel alone: even past its expiry height it is neither listed as expired nor offered for
    /// rebuild.
    #[test]
    fn invalid_transaction_is_excluded_from_every_query() {
        let target = BlockHeight::from_u32(100);
        // A transfer that would be provable (boundary settled, no dependencies, never expires) —
        // and broadcastable were it proved (scheduled height passed) — except for its state.
        let s = state_with(vec![scheduled_transfer(
            0,
            0,
            40,
            60,
            invalid(InvalidReason::RejectedInvalid),
        )]);
        assert_eq!(s.next_provable(target), None);
        assert_eq!(s.next_broadcastable(target), None);
        let mut r = ChaCha8Rng::seed_from_u64(1);
        let wakeups = s
            .sync_wakeup_schedule(BlockHeight::from_u32(50), &WakeupParams::new(10, 0), &mut r)
            .expect("feasible");
        assert!(
            wakeups.is_empty(),
            "a dead transfer needs no proving wake-up"
        );

        // The counterfactual, proving the exclusions are the state's doing and not the fixture's:
        // merely `Signed`, the same transfer is provable and wake-up-scheduled.
        let mut alive = s.clone();
        alive.transactions[0].state = MigrationTxState::Signed;
        assert_eq!(alive.next_provable(target), Some(MigrationTransferId(0)));
        let mut r = ChaCha8Rng::seed_from_u64(1);
        assert!(
            !alive
                .sync_wakeup_schedule(BlockHeight::from_u32(50), &WakeupParams::new(10, 0), &mut r)
                .expect("feasible")
                .is_empty()
        );

        // Past its expiry as well: still reported through the invalidity channel alone.
        let mut dead_and_expired = s;
        dead_and_expired.transactions[0].expiry_height = BlockHeight::from_u32(80);
        assert!(
            dead_and_expired.expired_transactions(target).is_empty(),
            "an invalid transaction is not reported as expired (its death is already recorded)"
        );
        assert_eq!(
            dead_and_expired.next_step(target),
            AdvanceStep::Attend {
                id: MigrationTransferId(0)
            },
            "and never offered for rebuild"
        );
    }

    /// `mark_invalid` records the death (with its reason) for a not-yet-mined transaction and an
    /// unknown id is a no-op, matching `mark_broadcast`/`mark_mined`; on an already-invalid row
    /// the newest evidence wins.
    #[test]
    fn mark_invalid_records_the_reason_and_ignores_unknown_ids() {
        let mut s = state_with(vec![
            tx(0, prep(0, 0), MigrationTxState::Signed),
            tx(1, transfer(0), MigrationTxState::Proved),
        ]);

        s.mark_invalid(MigrationTransferId(9), InvalidReason::FundingSpent);
        assert!(
            s.transactions
                .iter()
                .all(|t| t.state.invalid_reason().is_none()),
            "an unknown id changes nothing"
        );

        s.mark_invalid(MigrationTransferId(1), InvalidReason::FundingSpent);
        assert_eq!(
            s.transactions[1].state,
            invalid(InvalidReason::FundingSpent)
        );
        assert_eq!(
            s.status,
            MigrationStatus::Committed,
            "nothing broadcast or mined: recomputing the status changes nothing"
        );

        s.mark_invalid(MigrationTransferId(1), InvalidReason::RejectedInvalid);
        assert_eq!(
            s.transactions[1].state.invalid_reason(),
            Some(InvalidReason::RejectedInvalid),
            "the newest evidence carries the reason"
        );
    }

    /// Chain inclusion is the one piece of evidence that outranks an invalidity verdict: a mined
    /// row is never marked invalid, `mark_mined` supersedes an earlier verdict, and a broadcast (a
    /// mere submission, not evidence of validity) leaves the verdict standing — so a race between
    /// the mining detection and the invalidity report converges on the chain's answer in either
    /// arrival order.
    #[test]
    fn chain_inclusion_outranks_invalidity_evidence() {
        // Evidence arriving after the mining detection is stale: rejected.
        let mut s = state_with(vec![tx(0, transfer(0), mined(10))]);
        s.mark_invalid(MigrationTransferId(0), InvalidReason::FundingSpent);
        assert_eq!(s.transactions[0].state, mined(10));

        // The other arrival order: the verdict lands first, then the transaction is seen mined.
        let mut s = state_with(vec![tx(
            0,
            transfer(0),
            invalid(InvalidReason::RejectedExpired),
        )]);
        s.mark_mined(MigrationTransferId(0), BlockHeight::from_u32(20));
        assert_eq!(s.transactions[0].state, mined(20));
        assert_eq!(s.status, MigrationStatus::Complete);

        // A broadcast is not inclusion: it must not erase the verdict.
        let mut s = state_with(vec![tx(
            0,
            transfer(0),
            invalid(InvalidReason::FundingSpent),
        )]);
        s.mark_broadcast(MigrationTransferId(0), TxId::from_bytes([7; 32]));
        assert_eq!(
            s.transactions[0].state.invalid_reason(),
            Some(InvalidReason::FundingSpent)
        );
    }

    /// A run containing an invalid transaction never reaches `Complete`: the all-mined test fails,
    /// so the migration stays non-terminal — surfacing `Attend` — even when every OTHER
    /// transaction has mined.
    #[test]
    fn a_run_with_an_invalid_transaction_is_not_complete() {
        let mut s = state_with(vec![
            tx(0, prep(0, 0), mined(10)),
            tx(1, transfer(0), MigrationTxState::Proved),
        ]);
        s.mark_invalid(MigrationTransferId(1), InvalidReason::FundingSpent);
        assert_eq!(
            s.status,
            MigrationStatus::InProgress,
            "started (a transaction mined), but never complete"
        );
        assert!(!s.is_terminal());
        assert_eq!(
            s.next_step(BlockHeight::from_u32(100)),
            AdvanceStep::Attend {
                id: MigrationTransferId(1)
            }
        );
    }

    /// An invalid transaction reports not-ready with no action and the `Invalid` blocker, its
    /// reason riding in `state` — and that verdict wins over `Expired` when both hold, the
    /// recorded event (which carries a reason) being the more specific fact.
    #[test]
    fn transaction_statuses_report_invalid_with_its_reason() {
        let reason = InvalidReason::RejectedExpired;
        let dead = tx_expiring(1, transfer(0), invalid(reason), 50);
        let s = state_with(vec![tx(0, prep(0, 0), mined(10)), dead]);

        // Target 100 is past the expiry height 50 too: Invalid still wins.
        let v = s.transaction_statuses(BlockHeight::from_u32(100));
        assert!(!v[1].ready);
        assert_eq!(v[1].action, None);
        assert_eq!(v[1].blocked_on, Some(Blocker::Invalid));
        assert_eq!(
            v[1].state.invalid_reason(),
            Some(reason),
            "the reason is readable off the status's state"
        );
    }

    /// A terminal (cancelled) migration is never asked to attend: `Complete` still wins, so a
    /// consumer that already cancelled a run with a dead transaction is not re-alerted forever.
    #[test]
    fn terminal_migration_is_not_offered_for_attention() {
        let mut s = state_with(vec![tx(
            0,
            transfer(0),
            invalid(InvalidReason::FundingSpent),
        )]);
        s.status = MigrationStatus::Failed;
        assert_eq!(
            s.next_step(BlockHeight::from_u32(100)),
            AdvanceStep::Complete
        );
    }

    /// `DuenessTargets::new` clamps: a stale estimate below the scanned target never drags the
    /// serving target backwards, and no estimate leaves both targets coincident (the
    /// [`DuenessTargets::at`] case).
    #[test]
    fn dueness_targets_clamp_a_stale_estimate() {
        let scanned = BlockHeight::from_u32(200);

        let stale = DuenessTargets::new(scanned, Some(BlockHeight::from_u32(150)));
        assert_eq!(stale.scanned(), scanned);
        assert_eq!(stale.effective(), scanned);

        assert_eq!(
            DuenessTargets::new(scanned, None),
            DuenessTargets::at(scanned)
        );

        let ahead = DuenessTargets::new(scanned, Some(BlockHeight::from_u32(250)));
        assert_eq!(ahead.scanned(), scanned);
        assert_eq!(ahead.effective(), BlockHeight::from_u32(250));
    }

    /// The estimate accelerates SCHEDULE due-ness: work due only under the effective target is
    /// served by the `_at` lanes — a proved transfer for broadcast, a pre-signed preparation for
    /// proving (its prove-readiness IS schedule due-ness) — while the single-target queries at the
    /// scanned tip alone still serve nothing.
    #[test]
    fn estimated_target_accelerates_schedule_dueness() {
        let scanned = BlockHeight::from_u32(100);
        let targets = DuenessTargets::new(scanned, Some(BlockHeight::from_u32(130)));

        // A proved transfer scheduled between the scanned and effective targets.
        let mut xfer = tx(0, transfer(0), MigrationTxState::Proved);
        xfer.scheduled_height = BlockHeight::from_u32(120);
        let s = state_with(vec![xfer]);
        assert_eq!(s.next_broadcastable(scanned), None);
        assert_eq!(
            s.next_broadcastable_at(targets),
            Some(MigrationTransferId(0))
        );

        // A pre-signed preparation scheduled likewise.
        let mut prep0 = tx(0, prep(0, 0), MigrationTxState::Signed);
        prep0.scheduled_height = BlockHeight::from_u32(120);
        let s = state_with(vec![prep0]);
        assert_eq!(s.next_provable(scanned), None);
        assert_eq!(s.next_provable_at(targets), Some(MigrationTransferId(0)));
    }

    /// The estimate never DECIDES an expiry — but it does WITHHOLD a doomed broadcast. A proved,
    /// due transfer whose expiry only the effective target has passed is refused by the
    /// estimate-aware lane (if the estimate is right, the node would reject the submission), yet
    /// treated as expired NOWHERE: not listed, not offered for rebuild. The two outcomes are
    /// distinct decisions, and only the protective refusal may ride on the estimate; once the
    /// SCANNED tip confirms the expiry, the ordinary rebuild path takes over.
    #[test]
    fn estimated_target_withholds_a_doomed_broadcast_but_never_decides_expiry() {
        let scanned = BlockHeight::from_u32(100);
        let targets = DuenessTargets::new(scanned, Some(BlockHeight::from_u32(130)));
        // Due below the scanned target; expires between the scanned and effective targets.
        let mut xfer = tx_expiring(0, transfer(0), MigrationTxState::Proved, 110);
        xfer.scheduled_height = BlockHeight::from_u32(90);
        let s = state_with(vec![xfer]);

        // The scanned view serves it (still includable as far as scanned data proves)...
        assert_eq!(s.next_broadcastable(scanned), Some(MigrationTransferId(0)));
        // ...the estimate-aware lane refuses it...
        assert_eq!(s.next_broadcastable_at(targets), None);
        // ...and nothing treats it as expired on the estimate: that verdict needs the scanned tip.
        assert!(s.expired_transactions(scanned).is_empty());
        assert_eq!(
            s.next_step(scanned),
            AdvanceStep::Broadcast {
                id: MigrationTransferId(0)
            }
        );

        // Once the SCANNED target itself passes the expiry, the ordinary expired path owns it.
        let confirmed = BlockHeight::from_u32(111);
        assert_eq!(
            s.expired_transactions(confirmed),
            vec![MigrationTransferId(0)]
        );
        assert_eq!(
            s.next_step(confirmed),
            AdvanceStep::Rebuild {
                id: MigrationTransferId(0)
            }
        );
        assert_eq!(s.next_broadcastable_at(DuenessTargets::at(confirmed)), None);
    }

    /// A transfer's anchor-boundary settledness is a statement about SCANNED data — the boundary
    /// checkpoint either exists in the wallet's tree or it does not, and an estimate cannot
    /// conjure it — so the effective target never accelerates it.
    #[test]
    fn boundary_settledness_is_not_accelerated() {
        // Boundary at 100, schedule long since due: provable once the boundary settles.
        let mut xfer = tx(0, transfer(0), MigrationTxState::Signed);
        xfer.anchor_boundary = Some(BlockHeight::from_u32(100));
        xfer.scheduled_height = BlockHeight::from_u32(90);
        let s = state_with(vec![xfer]);

        // Scanned tip 100 (target 101): the boundary is not yet strictly below the tip, and no
        // estimate — however far ahead — changes that.
        let unsettled = DuenessTargets::new(
            BlockHeight::from_u32(101),
            Some(BlockHeight::from_u32(1_000)),
        );
        assert_eq!(s.next_provable_at(unsettled), None);

        // One scanned block later the boundary has genuinely settled.
        let settled = DuenessTargets::new(
            BlockHeight::from_u32(102),
            Some(BlockHeight::from_u32(1_000)),
        );
        assert_eq!(s.next_provable_at(settled), Some(MigrationTransferId(0)));
    }

    /// With no estimate the `_at` lanes and the single-target queries agree everywhere: the
    /// single-target queries delegate through [`DuenessTargets::at`], pinned here over a mixed
    /// fixture across a sweep of targets that crosses schedules, a boundary settlement, and an
    /// expiry.
    #[test]
    fn single_target_queries_equal_the_at_variants_with_no_estimate() {
        let mut expiring = tx_expiring(2, transfer(1), MigrationTxState::Proved, 60);
        expiring.scheduled_height = BlockHeight::from_u32(40);
        let mut late_prep = tx(3, prep(1, 0), MigrationTxState::Signed);
        late_prep.scheduled_height = BlockHeight::from_u32(80);
        let s = state_with(vec![
            tx(0, prep(0, 0), mined(10)),
            scheduled_transfer(1, 0, 44, 70, MigrationTxState::Signed),
            expiring,
            late_prep,
        ]);

        for target in 0..120u32 {
            let target = BlockHeight::from_u32(target);
            assert_eq!(
                s.next_provable(target),
                s.next_provable_at(DuenessTargets::at(target))
            );
            assert_eq!(
                s.next_broadcastable(target),
                s.next_broadcastable_at(DuenessTargets::at(target))
            );
        }
    }
}
