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
//! The central invariant is the multi-layer anchor bucketing: a later preparation layer spends the
//! feeder notes an earlier layer minted, which become witnessable only once that earlier layer is
//! mined, so each layer is built, signed, and broadcast against a distinct anchor and a later layer is
//! never actionable until its dependencies (its whole prior layer) have mined.

use alloc::vec::Vec;

use zcash_protocol::TxId;
use zcash_protocol::consensus::BlockHeight;

use crate::engine::{
    MigrationState, MigrationStatus, MigrationTxId, MigrationTxKind, MigrationTxState,
};

/// The next thing to do to advance a committed migration, decided purely from its state. The consumer
/// performs the corresponding I/O and updates the state (via the commit functions and
/// [`MigrationState::mark_broadcast`] / [`MigrationState::mark_mined`]), then calls
/// [`MigrationState::next_step`] again.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdvanceStep {
    /// Build and pre-sign the next ready preparation layer (its predecessor has mined). The consumer
    /// calls [`commit_pending_preparation`](crate::engine::commit_pending_preparation).
    BuildPreparationLayer {
        /// The layer to build.
        layer: usize,
    },
    /// Build and pre-sign the transfers; the whole preparation is mined. The consumer calls
    /// [`commit_transfers`](crate::engine::commit_transfers).
    BuildTransfers,
    /// Prove and broadcast this pre-signed transaction: its dependencies are mined and it is due.
    Broadcast {
        /// The transaction to prove and broadcast.
        id: MigrationTxId,
    },
    /// Nothing to do now: waiting for one or more transactions to mine, or for a scheduled height to
    /// arrive.
    Waiting,
    /// Every transaction is mined; the migration is complete.
    Complete,
}

/// The action a wallet takes next on a ready migration transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NextAction {
    /// Build and pre-sign this placeholder now that its dependencies are mined (a later preparation
    /// layer, or the transfers once the whole preparation is mined).
    BuildAndSign,
    /// Prove and broadcast this pre-signed transaction now that its dependencies are mined and it is
    /// due.
    ProveAndBroadcast,
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
    /// Built but awaiting an EXTERNAL signature: its unsigned PCZT was exported to a hardware or offline
    /// signer, and this transaction cannot advance until
    /// [`MigrationState::apply_signature`](MigrationState::apply_signature) stores the signed PCZT
    /// returned by the device.
    Signature,
}

/// The status of one migration transaction, as a wallet renders it and decides the next step. This is
/// the machine-readable view a mobile wallet needs: it cannot pre-sign a multi-layer migration up
/// front (later layers become witnessable only as earlier layers mine) and may be restarted between
/// layers, so it decides which transaction to sign or broadcast next, and what the rest are waiting on,
/// from this view of the persisted state alone.
#[derive(Clone, Debug)]
pub struct TransactionStatus {
    /// This transaction's stable id.
    pub id: MigrationTxId,
    /// What it does (a preparation transaction, carrying its layer / anchor bucket, or a transfer).
    pub kind: MigrationTxKind,
    /// Its current lifecycle state.
    pub state: MigrationTxState,
    /// The transactions that must be mined before this one can be built or broadcast.
    pub depends_on: Vec<MigrationTxId>,
    /// The height at or after which it is due to broadcast.
    pub scheduled_height: BlockHeight,
    /// Whether the wallet can act on it right now.
    pub ready: bool,
    /// The action available now, when `ready` is true.
    pub action: Option<NextAction>,
    /// Why it is not yet actionable, when it is waiting (and not already broadcast or mined).
    pub blocked_on: Option<Blocker>,
    /// The height it was mined at, once mined.
    pub mined_height: Option<BlockHeight>,
    /// The transaction id (raw internal bytes), once broadcast.
    pub txid: Option<TxId>,
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

    /// Whether all preparation transactions are mined (so the funding notes exist and the transfers can
    /// be built).
    pub fn all_preparations_mined(&self) -> bool {
        self.transactions
            .iter()
            .filter(|t| matches!(t.kind, MigrationTxKind::Preparation { .. }))
            .all(|t| matches!(t.state, MigrationTxState::Mined { .. }))
    }

    /// The earliest deferred preparation layer that is ready to build: a multi-layer preparation records
    /// its later layers (`layer > 0`) as unbuilt placeholders, and one becomes buildable once its whole
    /// prior layer (its `depends_on`) is mined and its feeder notes are witnessable. Returns the layer
    /// number, or `None` if no later layer is ready.
    pub fn ready_prep_layer(&self) -> Option<usize> {
        self.transactions
            .iter()
            .filter_map(|t| match t.kind {
                MigrationTxKind::Preparation { layer, .. }
                    if layer > 0
                        && matches!(t.state, MigrationTxState::Planned)
                        && self.deps_mined(&t.depends_on) =>
                {
                    Some(layer)
                }
                _ => None,
            })
            .min()
    }

    /// Whether a deferred preparation layer is ready to build (see
    /// [`ready_prep_layer`](MigrationState::ready_prep_layer)).
    pub fn has_ready_prep_layer(&self) -> bool {
        self.ready_prep_layer().is_some()
    }

    /// The id of the next transaction ready to prove and broadcast: pre-signed (`Signed`) or already
    /// `Proved`, its dependencies mined, and scheduled at or before `target_height` (`chain_tip + 1`).
    pub fn next_broadcastable(&self, target_height: BlockHeight) -> Option<MigrationTxId> {
        self.transactions
            .iter()
            .find(|t| {
                matches!(t.state, MigrationTxState::Signed | MigrationTxState::Proved)
                    && t.scheduled_height <= target_height
                    && self.deps_mined(&t.depends_on)
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
    /// [`build_preparation_unsigned`](crate::engine::build_preparation_unsigned) or
    /// [`build_transfers_unsigned`](crate::engine::build_transfers_unsigned) exports the unsigned PCZT,
    /// the caller has it signed out of band and returns the signed PCZT here, matched by `id`. Persist
    /// the state afterwards (`put_migration`).
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
        tx.pczt = Some(signed_pczt);
        tx.state = MigrationTxState::Signed;
        true
    }

    /// Decides the next step to advance the migration, from state alone. The priority is: prove and
    /// broadcast the next due, dependency-satisfied transaction; else build the next ready preparation
    /// layer; else, once the whole preparation is mined, build the transfers; else report `Complete`
    /// when everything is mined, or `Waiting` otherwise. This is made once, here, so it is never
    /// duplicated per consumer.
    pub fn next_step(&self, target_height: BlockHeight) -> AdvanceStep {
        // A terminal migration (complete, or failed/cancelled) has no next action: never build or
        // broadcast for it, so a cancelled migration cannot be driven further.
        if self.is_terminal() {
            return AdvanceStep::Complete;
        }
        if let Some(id) = self.next_broadcastable(target_height) {
            return AdvanceStep::Broadcast { id };
        }
        if let Some(layer) = self.ready_prep_layer() {
            return AdvanceStep::BuildPreparationLayer { layer };
        }
        let has_unbuilt_transfer = self.transactions.iter().any(|t| {
            matches!(t.kind, MigrationTxKind::Transfer { .. })
                && matches!(t.state, MigrationTxState::Planned)
        });
        if self.all_preparations_mined() && has_unbuilt_transfer {
            return AdvanceStep::BuildTransfers;
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
    /// A `Planned` (or `Expired`) placeholder whose dependencies are all mined is ready to build and
    /// sign; a `Signed` (or `Proved`) transaction whose dependencies are mined and whose scheduled
    /// height has arrived is ready to prove and broadcast. Otherwise a waiting transaction reports what
    /// it is blocked on: its dependencies (a prior anchor bucket still to mine) or the broadcast
    /// schedule.
    pub fn transaction_statuses(&self, target_height: BlockHeight) -> Vec<TransactionStatus> {
        self.transactions
            .iter()
            .map(|t| {
                let deps_ok = self.deps_mined(&t.depends_on);
                // `Planned`/`Expired` need building; `Signed`/`Proved` need broadcasting. In both cases
                // a transaction is actionable only once its dependencies (the prior anchor bucket) are
                // mined, and a broadcastable one only once it is also due.
                let (ready, action, blocked_on) = match t.state {
                    MigrationTxState::Planned | MigrationTxState::Expired => {
                        if deps_ok {
                            (true, Some(NextAction::BuildAndSign), None)
                        } else {
                            (false, None, Some(Blocker::Dependencies))
                        }
                    }
                    // Built for an external signer and waiting for its signed PCZT; the wallet's
                    // automatic driver takes no action (the external-signing caller drives it via
                    // `apply_signature`), so it is neither ready nor blocked on the chain.
                    MigrationTxState::AwaitingSignature => (false, None, Some(Blocker::Signature)),
                    MigrationTxState::Signed | MigrationTxState::Proved => {
                        if !deps_ok {
                            (false, None, Some(Blocker::Dependencies))
                        } else if t.scheduled_height <= target_height {
                            (true, Some(NextAction::ProveAndBroadcast), None)
                        } else {
                            (false, None, Some(Blocker::Schedule))
                        }
                    }
                    MigrationTxState::Broadcast { .. } => (false, None, None),
                    MigrationTxState::Mined { .. } => (false, None, None),
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
    use crate::note_splitting::NoteSplitPlan;
    use crate::preparation::PreparationPlan;
    use alloc::vec;

    // A migration transaction with the given id/kind/state, no dependencies, scheduled at height 0.
    fn tx(id: u32, kind: MigrationTxKind, state: MigrationTxState) -> MigrationTransaction {
        MigrationTransaction {
            id: MigrationTxId(id),
            kind,
            pczt: None,
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
            note_split: NoteSplitPlan::from_stored_parts(Vec::new(), 0, None, 0, 0, 0),
            funding_notes: Vec::new(),
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
        assert_eq!(
            state.transactions[0].pczt.as_deref(),
            Some(&[1u8, 2, 3][..])
        );
    }

    #[test]
    fn apply_signature_rejects_unknown_or_wrong_state() {
        let mut state = state_with(vec![
            tx(0, prep(0, 0), MigrationTxState::AwaitingSignature),
            tx(1, transfer(0), MigrationTxState::Planned),
        ]);
        // An unknown id, and a transaction not awaiting a signature (a Planned placeholder), are both
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
        assert_eq!(state.transactions[0].pczt.as_deref(), Some(&[1u8][..]));
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
        assert!(!s.all_preparations_mined()); // tx 1 is not mined
    }

    #[test]
    fn ready_prep_layer_needs_prior_layer_mined() {
        // Layer 0 half-mined: layer 1 (depending on both layer-0 txs) is not ready.
        let mut l1 = tx(2, prep(1, 0), MigrationTxState::Planned);
        l1.depends_on = vec![MigrationTxId(0), MigrationTxId(1)];
        let mut s = state_with(vec![
            tx(0, prep(0, 0), mined(10)),
            tx(
                1,
                prep(0, 1),
                MigrationTxState::Broadcast {
                    txid: TxId::from_bytes([0; 32]),
                },
            ),
            l1.clone(),
        ]);
        assert_eq!(s.ready_prep_layer(), None);
        assert!(!s.has_ready_prep_layer());

        // Mine the rest of layer 0: layer 1 becomes ready.
        s.transactions[1].state = mined(11);
        assert_eq!(s.ready_prep_layer(), Some(1));
        assert!(s.has_ready_prep_layer());
    }

    #[test]
    fn ready_prep_layer_picks_earliest() {
        let mut l1 = tx(1, prep(1, 0), MigrationTxState::Planned);
        l1.depends_on = vec![MigrationTxId(0)];
        let mut l2 = tx(2, prep(2, 0), MigrationTxState::Planned);
        l2.depends_on = vec![MigrationTxId(1)];
        // Only layer 0 is mined, so only layer 1 is ready.
        let s = state_with(vec![tx(0, prep(0, 0), mined(10)), l1, l2]);
        assert_eq!(s.ready_prep_layer(), Some(1));
    }

    #[test]
    fn next_broadcastable_respects_state_deps_and_schedule() {
        let mut signed = tx(1, transfer(0), MigrationTxState::Signed);
        signed.depends_on = vec![MigrationTxId(0)];
        signed.scheduled_height = BlockHeight::from_u32(5);
        let mut s = state_with(vec![tx(0, prep(0, 0), mined(10)), signed]);

        // Not due yet (target below scheduled height).
        assert_eq!(s.next_broadcastable(BlockHeight::from_u32(4)), None);
        // Due and deps mined.
        assert_eq!(
            s.next_broadcastable(BlockHeight::from_u32(5)),
            Some(MigrationTxId(1))
        );

        // A Proved transaction is also broadcastable.
        s.transactions[1].state = MigrationTxState::Proved;
        assert_eq!(
            s.next_broadcastable(BlockHeight::from_u32(5)),
            Some(MigrationTxId(1))
        );

        // Dependency not mined: not broadcastable.
        s.transactions[0].state = MigrationTxState::Broadcast {
            txid: TxId::from_bytes([0; 32]),
        };
        assert_eq!(s.next_broadcastable(BlockHeight::from_u32(5)), None);
    }

    #[test]
    fn next_step_walks_the_lifecycle() {
        // Layer 0 signed, layer 1 planned depending on it, one transfer planned depending on layer 1.
        let mut l1 = tx(1, prep(1, 0), MigrationTxState::Planned);
        l1.depends_on = vec![MigrationTxId(0)];
        let mut xfer = tx(2, transfer(0), MigrationTxState::Planned);
        xfer.depends_on = vec![MigrationTxId(1)];
        let mut s = state_with(vec![tx(0, prep(0, 0), MigrationTxState::Signed), l1, xfer]);

        // 1) Layer 0 is signed and due -> broadcast it.
        assert_eq!(
            s.next_step(BlockHeight::from_u32(100)),
            AdvanceStep::Broadcast {
                id: MigrationTxId(0)
            }
        );

        // 2) Layer 0 broadcast, not yet mined -> nothing ready, waiting.
        s.transactions[0].state = MigrationTxState::Broadcast {
            txid: TxId::from_bytes([1; 32]),
        };
        assert_eq!(
            s.next_step(BlockHeight::from_u32(100)),
            AdvanceStep::Waiting
        );

        // 3) Layer 0 mined -> layer 1 ready to build.
        s.transactions[0].state = mined(10);
        assert_eq!(
            s.next_step(BlockHeight::from_u32(100)),
            AdvanceStep::BuildPreparationLayer { layer: 1 }
        );

        // 4) Layer 1 signed and due -> broadcast it.
        s.transactions[1].state = MigrationTxState::Signed;
        assert_eq!(
            s.next_step(BlockHeight::from_u32(100)),
            AdvanceStep::Broadcast {
                id: MigrationTxId(1)
            }
        );

        // 5) Layer 1 mined, all preparation mined -> build transfers.
        s.transactions[1].state = mined(11);
        assert_eq!(
            s.next_step(BlockHeight::from_u32(100)),
            AdvanceStep::BuildTransfers
        );

        // 6) Transfer signed and due -> broadcast it.
        s.transactions[2].state = MigrationTxState::Signed;
        assert_eq!(
            s.next_step(BlockHeight::from_u32(100)),
            AdvanceStep::Broadcast {
                id: MigrationTxId(2)
            }
        );

        // 7) Everything mined -> complete.
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
        assert_eq!(
            s.next_step(BlockHeight::from_u32(50)),
            AdvanceStep::Broadcast {
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
        let mut l1 = tx(1, prep(1, 0), MigrationTxState::Planned);
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

        // tx 1: planned with its dependency (tx 0) mined -> ready to build.
        assert!(views[1].ready);
        assert_eq!(views[1].action, Some(NextAction::BuildAndSign));
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
        assert_eq!(ready[1].action, Some(NextAction::ProveAndBroadcast));
    }
}
