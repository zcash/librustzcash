//! Migration state logic: the pure, backend-agnostic methods a consuming application uses to drive a
//! committed migration and render its progress.
//!
//! These are methods on [`MigrationState`] that operate only on the persisted state and never touch a
//! wallet, a prover, or the network, so every consumer (a mobile wallet using these crates directly,
//! or a server like Zallet) makes the SAME decisions from the SAME state. The consumer supplies the
//! I/O: it detects that a broadcast transaction has mined (via its own chain view) and calls
//! [`MigrationState::mark_mined`], it broadcasts a transaction and calls
//! [`MigrationState::mark_broadcast`], and it performs the build/prove/broadcast work that
//! [`MigrationState::next_step`] tells it to do. The decision of WHAT to do next, and the transaction
//! status a wallet shows the user, live here.
//!
//! Every transaction is built and pre-signed when the migration is committed (one signing phase;
//! anchors and witnesses are deferred to proving time per ZIP 374), so the state machine's only
//! job is to ORDER the broadcasts: a transaction becomes broadcastable once its dependencies (the
//! preparation layers that mint its inputs) have mined and its scheduled height has arrived, and
//! the consumer proves it — installing its anchor and witnesses — just before broadcasting.

use alloc::vec::Vec;

use getset::{CopyGetters, Getters};
use zcash_protocol::TxId;
use zcash_protocol::consensus::BlockHeight;

use crate::engine::{
    MigrationState, MigrationStatus, MigrationTransaction, MigrationTxId, MigrationTxKind,
    MigrationTxState,
};

/// The next thing to do to advance a committed migration, decided purely from its state. The consumer
/// performs the corresponding I/O and updates the state (via the commit functions and
/// [`MigrationState::mark_broadcast`] / [`MigrationState::mark_mined`]), then calls
/// [`MigrationState::next_step`] again.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdvanceStep {
    /// Prove this pre-signed transaction (install its deferred Orchard anchor and spend witnesses and
    /// store the proven PCZT), WITHOUT broadcasting: its dependencies are mined and, for a transfer,
    /// its drawn anchor boundary has settled (the boundary block is below the tip, so its checkpoint
    /// exists and is still within the wallet's checkpoint-pruning window). Broadcast is a separate
    /// later step once the privacy broadcast schedule is due. Proving is time-critical: the boundary
    /// checkpoint is pruned once the tip advances past it by the wallet's pruning depth, so a transfer
    /// must be proved while its boundary is fresh, not deferred to its (later) broadcast height.
    Prove {
        /// The transaction to prove.
        id: MigrationTxId,
    },
    /// Broadcast this already-proven transaction: it is `Proved`, its dependencies are mined, and its
    /// scheduled broadcast height has arrived.
    Broadcast {
        /// The transaction to broadcast.
        id: MigrationTxId,
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
        id: MigrationTxId,
    },
    /// Nothing to do now: waiting for one or more transactions to mine, for an anchor boundary to
    /// settle, or for a scheduled height to arrive.
    Waiting,
    /// Every transaction is mined; the migration is complete.
    Complete,
}

/// The action a wallet takes next on a ready migration transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NextAction {
    /// Prove this pre-signed transaction now (install its deferred anchor and witnesses and store the
    /// proven PCZT): its dependencies are mined and, for a transfer, its anchor boundary has settled
    /// within the wallet's checkpoint-pruning window. It is not broadcast yet.
    Prove,
    /// Broadcast this already-proven transaction now: it is `Proved` and its scheduled broadcast
    /// height has arrived.
    Broadcast,
}

/// Why a migration transaction is not yet actionable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Blocker {
    /// Waiting for its dependency transactions (an earlier preparation layer, or the whole
    /// preparation) to mine, so its input notes become witnessable in a new anchor bucket. A
    /// multi-layer preparation signs and broadcasts each layer in a separate anchor bucket, so a later
    /// layer cannot be built until its predecessor has mined.
    Dependencies,
    /// Built and due only at a later height (the privacy broadcast schedule): waiting for the chain tip
    /// to reach its scheduled height.
    Schedule,
    /// A transfer whose drawn anchor boundary has not yet settled: waiting for the chain tip to move
    /// strictly past the boundary block, so the boundary checkpoint exists and the transfer can be
    /// proved against it (while it is still within the wallet's checkpoint-pruning window).
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
}

/// The status of one migration transaction, as a wallet renders it and decides the next step. This is
/// the machine-readable view a mobile wallet needs: it cannot pre-sign a multi-layer migration up
/// front (later layers become witnessable only as earlier layers mine) and may be restarted between
/// layers, so it decides which transaction to sign or broadcast next, and what the rest are waiting on,
/// from this view of the persisted state alone.
#[derive(Clone, Debug, Getters, CopyGetters)]
pub struct TransactionStatus {
    /// This transaction's stable id.
    #[getset(get_copy = "pub")]
    pub(crate) id: MigrationTxId,
    /// What it does (a preparation transaction, carrying its layer / anchor bucket, or a transfer).
    #[getset(get_copy = "pub")]
    pub(crate) kind: MigrationTxKind,
    /// Its current lifecycle state.
    #[getset(get_copy = "pub")]
    pub(crate) state: MigrationTxState,
    /// The transactions that must be mined before this one can be built or broadcast.
    #[getset(get = "pub")]
    pub(crate) depends_on: Vec<MigrationTxId>,
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

impl MigrationState {
    /// Whether every transaction in `depends_on` is mined.
    pub fn deps_mined(&self, depends_on: &[MigrationTxId]) -> bool {
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
    fn is_expired(t: &MigrationTransaction, target_height: BlockHeight) -> bool {
        if matches!(t.state, MigrationTxState::Mined { .. }) {
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
    /// wallet uses this list to tell the user the migration needs a new signing ceremony.
    pub fn expired_transactions(&self, target_height: BlockHeight) -> Vec<MigrationTxId> {
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
    fn next_rebuildable(&self, target_height: BlockHeight) -> Option<MigrationTxId> {
        self.transactions
            .iter()
            .filter(|t| matches!(t.kind, MigrationTxKind::Transfer { .. }))
            .find(|t| Self::is_expired(t, target_height))
            .map(|t| t.id)
    }

    /// Whether transaction `t` is ready to PROVE at `target_height` (`chain_tip + 1`): its
    /// dependencies are mined and its Orchard anchor is resolvable from the wallet's commitment tree
    /// right now.
    ///
    /// A TRANSFER anchors to a drawn boundary ([`anchor_boundary`](MigrationTransaction::anchor_boundary)),
    /// which must have SETTLED: the boundary block must be strictly below the chain tip so its
    /// checkpoint exists in the tree. Proving is due as soon as that holds, decoupled from the (later)
    /// broadcast schedule, because the boundary checkpoint is pruned once the tip advances past it by
    /// the wallet's pruning depth; a transfer must therefore be proved while its boundary is still
    /// fresh, not deferred to its broadcast height. A PREPARATION carries no drawn boundary and
    /// anchors to a fresh checkpoint at the tip when proved, so it is prove-ready once its
    /// dependencies are mined and its scheduled height has arrived.
    fn prove_ready(&self, t: &MigrationTransaction, target_height: BlockHeight) -> bool {
        // An expired transaction can never be mined, so proving it is wasted work: it must be rebuilt
        // (with a fresh anchor and expiry) first. Guarding here keeps `next_provable` from ever
        // offering an expired transaction.
        if Self::is_expired(t, target_height) {
            return false;
        }
        if !self.deps_mined(&t.depends_on) {
            return false;
        }
        match t.anchor_boundary {
            // A transfer: the boundary must be strictly below the tip. `target_height` is `tip + 1`,
            // so `boundary < tip` is `boundary + 1 < target_height`.
            Some(boundary) => u32::from(boundary) + 1 < u32::from(target_height),
            // A preparation: prove-ready once its schedule is due.
            None => t.scheduled_height <= target_height,
        }
    }

    /// The id of the next pre-signed transaction ready to PROVE (move `Signed -> Proved`): its anchor
    /// is resolvable now (see [`Self::prove_ready`]). Proving is decoupled from broadcasting so a
    /// transfer is proved while its anchor boundary checkpoint is still within the wallet's pruning
    /// window, then broadcast later at its scheduled height.
    pub fn next_provable(&self, target_height: BlockHeight) -> Option<MigrationTxId> {
        self.transactions
            .iter()
            .find(|t| {
                matches!(t.state, MigrationTxState::Signed) && self.prove_ready(t, target_height)
            })
            .map(|t| t.id)
    }

    /// The id of the next transaction ready to BROADCAST: already `Proved`, its dependencies mined,
    /// and scheduled at or before `target_height` (`chain_tip + 1`).
    pub fn next_broadcastable(&self, target_height: BlockHeight) -> Option<MigrationTxId> {
        self.transactions
            .iter()
            .find(|t| {
                matches!(t.state, MigrationTxState::Proved)
                    && t.scheduled_height <= target_height
                    && self.deps_mined(&t.depends_on)
                    // An expired proven transaction would be rejected by the node; it must be rebuilt,
                    // not broadcast. This is what stops a wallet resumed after its broadcast windows
                    // lapsed from broadcasting a stale, no-longer-includable transaction.
                    && !Self::is_expired(t, target_height)
            })
            .map(|t| t.id)
    }

    /// Recomputes the overall [`MigrationStatus`]: `Complete` once every transaction is mined,
    /// `InProgress` once any has been broadcast or mined. Leaves the status unchanged otherwise (an
    /// uncommitted or freshly committed migration keeps its `Planning`/`Committed` status until work
    /// begins).
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
    /// it.
    pub fn mark_broadcast(&mut self, id: MigrationTxId, txid: TxId) {
        if let Some(tx) = self.transactions.iter_mut().find(|t| t.id == id) {
            tx.state = MigrationTxState::Broadcast { txid };
        }
        self.recompute_status();
    }

    /// Records that the transaction `id` was mined at `height`, then recomputes the overall status. The
    /// consumer detects mining through its own chain view (matching a broadcast transaction's txid) and
    /// calls this, which is what lets a later preparation layer or the transfers become actionable.
    pub fn mark_mined(&mut self, id: MigrationTxId, height: BlockHeight) {
        if let Some(tx) = self.transactions.iter_mut().find(|t| t.id == id) {
            tx.state = MigrationTxState::Mined { height };
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
    pub fn apply_signature(&mut self, id: MigrationTxId, signed_pczt: Vec<u8>) -> bool {
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

    /// Decides the next step to advance the migration, from state alone: prove and broadcast the
    /// next due, dependency-satisfied transaction; else report `Complete` when everything is
    /// mined, or `Waiting` otherwise. This is made once, here, so it is never duplicated per
    /// consumer.
    pub fn next_step(&self, target_height: BlockHeight) -> AdvanceStep {
        // A terminal migration (complete, or failed/cancelled) has no next action: never build or
        // broadcast for it, so a cancelled migration cannot be driven further.
        if self.is_terminal() {
            return AdvanceStep::Complete;
        }
        // Prove before broadcasting: a transfer's anchor boundary checkpoint is only briefly within
        // the wallet's pruning window, so proving is time-critical, whereas broadcasting a proven
        // transaction can wait for its (later) schedule.
        if let Some(id) = self.next_provable(target_height) {
            return AdvanceStep::Prove { id };
        }
        if let Some(id) = self.next_broadcastable(target_height) {
            return AdvanceStep::Broadcast { id };
        }
        // Make progress on still-valid transactions first (above), then surface any expired
        // transfer for rebuild. Reporting Rebuild in preference to Waiting is what stops the
        // migration stalling forever on a transfer whose broadcast window lapsed: nothing else
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
    /// A `Signed` (or `Proved`) transaction whose dependencies are mined and whose scheduled
    /// height has arrived is ready to prove and broadcast. Otherwise a waiting transaction reports
    /// what it is blocked on: its dependencies (a preparation still to mine), the broadcast
    /// schedule, or an external signature.
    pub fn transaction_statuses(&self, target_height: BlockHeight) -> Vec<TransactionStatus> {
        self.transactions
            .iter()
            .map(|t| {
                let deps_ok = self.deps_mined(&t.depends_on);
                // An expired transaction (not yet mined, past its expiry height) can never be mined and
                // must be rebuilt; report that ahead of any other blocker, so a wallet shows it as
                // needing attention rather than as waiting on a dependency or the schedule.
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
                            } else if self.prove_ready(t, target_height) {
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

    use crate::note_splitting::NoteSplitPlan;
    use crate::preparation::PreparationPlan;
    use alloc::vec;

    // A migration transaction with the given id/kind/state, no dependencies, scheduled at height 0.
    fn tx(id: u32, kind: MigrationTxKind, state: MigrationTxState) -> MigrationTransaction {
        MigrationTransaction {
            id: MigrationTxId(id),
            kind,
            pczt: Vec::new(),
            depends_on: Vec::new(),
            scheduled_height: BlockHeight::from_u32(0),
            expiry_height: BlockHeight::from_u32(0),
            anchor_boundary: None,
            state,
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
            note_split: NoteSplitPlan::from_stored_parts(
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
        }
    }

    fn mined(height: u32) -> MigrationTxState {
        MigrationTxState::Mined {
            height: BlockHeight::from_u32(height),
        }
    }

    #[test]
    fn apply_signature_moves_awaiting_to_signed() {
        let mut state = state_with(vec![tx(0, prep(0, 0), MigrationTxState::AwaitingSignature)]);
        assert!(state.apply_signature(MigrationTxId(0), vec![1u8, 2, 3]));
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
        assert!(!state.apply_signature(MigrationTxId(9), vec![1u8]));
        assert!(!state.apply_signature(MigrationTxId(1), vec![1u8]));
        assert_eq!(
            state.transactions[0].state,
            MigrationTxState::AwaitingSignature
        );
        // The first signature applies; a second, after it is already Signed, is rejected (a stale or
        // misrouted signature cannot overwrite the stored one).
        assert!(state.apply_signature(MigrationTxId(0), vec![1u8]));
        assert!(!state.apply_signature(MigrationTxId(0), vec![2u8]));
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
        assert!(s.deps_mined(&[MigrationTxId(0)]));
        assert!(!s.deps_mined(&[MigrationTxId(1)]));
        assert!(s.deps_mined(&[])); // empty deps are trivially satisfied
    }

    #[test]
    fn next_broadcastable_respects_state_deps_and_schedule() {
        // Only a PROVED transaction is broadcastable (proving is a separate earlier step).
        let mut proved = tx(1, transfer(0), MigrationTxState::Proved);
        proved.depends_on = vec![MigrationTxId(0)];
        proved.scheduled_height = BlockHeight::from_u32(5);
        let mut s = state_with(vec![tx(0, prep(0, 0), mined(10)), proved]);

        // Not due yet (target below scheduled height).
        assert_eq!(s.next_broadcastable(BlockHeight::from_u32(4)), None);
        // Due and deps mined.
        assert_eq!(
            s.next_broadcastable(BlockHeight::from_u32(5)),
            Some(MigrationTxId(1))
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

    #[test]
    fn next_step_walks_the_lifecycle() {
        // Every transaction is pre-signed at commit; the state machine orders proving then
        // broadcasting, respecting the anchor-bucket dependency order: prove-then-broadcast layer 0,
        // then layer 1 once layer 0 mines, then the transfer once the whole preparation mines. Each
        // transaction is PROVED (`Signed -> Proved`) before it is broadcast.
        let mut l1 = tx(1, prep(1, 0), MigrationTxState::Signed);
        l1.depends_on = vec![MigrationTxId(0)];
        let mut xfer = tx(2, transfer(0), MigrationTxState::Signed);
        xfer.depends_on = vec![MigrationTxId(1)];
        let mut s = state_with(vec![tx(0, prep(0, 0), MigrationTxState::Signed), l1, xfer]);

        // 1) Layer 0 is signed and due -> prove it first, then broadcast it once proved.
        assert_eq!(
            s.next_step(BlockHeight::from_u32(100)),
            AdvanceStep::Prove {
                id: MigrationTxId(0)
            }
        );
        s.transactions[0].state = MigrationTxState::Proved;
        assert_eq!(
            s.next_step(BlockHeight::from_u32(100)),
            AdvanceStep::Broadcast {
                id: MigrationTxId(0)
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
                id: MigrationTxId(1)
            }
        );
        s.transactions[1].state = MigrationTxState::Proved;
        assert_eq!(
            s.next_step(BlockHeight::from_u32(100)),
            AdvanceStep::Broadcast {
                id: MigrationTxId(1)
            }
        );

        // 4) Layer 1 mined -> the transfer becomes provable, then broadcastable.
        s.transactions[1].state = mined(11);
        assert_eq!(
            s.next_step(BlockHeight::from_u32(100)),
            AdvanceStep::Prove {
                id: MigrationTxId(2)
            }
        );
        s.transactions[2].state = MigrationTxState::Proved;
        assert_eq!(
            s.next_step(BlockHeight::from_u32(100)),
            AdvanceStep::Broadcast {
                id: MigrationTxId(2)
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
                id: MigrationTxId(1)
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

        s.mark_broadcast(MigrationTxId(0), TxId::from_bytes([7; 32]));
        assert!(matches!(
            s.transactions[0].state,
            MigrationTxState::Broadcast { txid } if txid == TxId::from_bytes([7; 32])
        ));
        assert_eq!(s.status, MigrationStatus::InProgress);
        assert!(!s.is_terminal());

        s.mark_mined(MigrationTxId(0), BlockHeight::from_u32(10));
        s.mark_mined(MigrationTxId(1), BlockHeight::from_u32(11));
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
        s.mark_mined(MigrationTxId(0), BlockHeight::from_u32(10));
        assert_eq!(s.status, MigrationStatus::Failed);
    }

    #[test]
    fn transaction_statuses_report_ready_and_blockers() {
        let mut l1 = tx(1, prep(1, 0), MigrationTxState::Signed);
        l1.depends_on = vec![MigrationTxId(0)];
        let mut xfer = tx(2, transfer(0), MigrationTxState::Signed);
        xfer.depends_on = vec![MigrationTxId(1)];
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
        xfer.depends_on = vec![MigrationTxId(0)];
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
                id: MigrationTxId(1)
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
                id: MigrationTxId(1)
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
            Some(MigrationTxId(1))
        );
        // At target 51 (tip 50) expiry has passed (51 > 50) -> not broadcastable, must be rebuilt.
        assert_eq!(s.next_broadcastable(BlockHeight::from_u32(51)), None);
        assert_eq!(
            s.next_step(BlockHeight::from_u32(51)),
            AdvanceStep::Rebuild {
                id: MigrationTxId(1)
            }
        );

        // The same holds for a still-`Signed` (unproved) expired transfer: it is not provable either.
        s.transactions[1].state = MigrationTxState::Signed;
        assert_eq!(s.next_provable(BlockHeight::from_u32(51)), None);
        assert_eq!(
            s.next_step(BlockHeight::from_u32(51)),
            AdvanceStep::Rebuild {
                id: MigrationTxId(1)
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
            vec![MigrationTxId(1)]
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
                id: MigrationTxId(1)
            }
        );
        // Once the valid transfer is proved and broadcast, the expired one is surfaced for rebuild.
        s.transactions[1].state = MigrationTxState::Broadcast {
            txid: TxId::from_bytes([3; 32]),
        };
        assert_eq!(
            s.next_step(BlockHeight::from_u32(51)),
            AdvanceStep::Rebuild {
                id: MigrationTxId(2)
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
        dependent.depends_on = vec![MigrationTxId(0)];
        let s = state_with(vec![expired_prep, dependent]);

        assert_eq!(s.next_step(BlockHeight::from_u32(51)), AdvanceStep::Waiting);
        let v = s.transaction_statuses(BlockHeight::from_u32(51));
        assert_eq!(v[0].blocked_on, Some(Blocker::Expired));
        assert_eq!(
            s.expired_transactions(BlockHeight::from_u32(51)),
            vec![MigrationTxId(0)]
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
                id: MigrationTxId(1)
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
}
