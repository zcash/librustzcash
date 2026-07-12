//! Public data types for the migration engine.
//!
//! Amounts use [`Zatoshis`] and heights use [`BlockHeight`] — the canonical `zcash_protocol`
//! types, which enforce their own invariants — and transaction identifiers use [`TxId`]. Unlike
//! the `zodl_ironwood_migration` prototype this crate ports from, none of these types derive
//! `serde`: every type here has private fields with `from_parts`-style constructors and accessor
//! methods instead, and the platform's FFI/JNI layer is expected to define its own wire-format
//! DTOs over those accessors.

use std::fmt;

use zcash_protocol::{TxId, consensus::BlockHeight, value::Zatoshis};

/// A run-scoped identifier for a single migration transfer, or for the one-off note-split
/// ("prep") transaction that precedes them.
///
/// Backed by a string of the form `"<run_id>:<index>"` (built by `TransferId::for_transfer`) or
/// `"prep:<run_id>"` (built by `TransferId::for_prep`), rather than a bare run id, so a single
/// value round-trips through storage and identifies both the run it belongs to and, for ordinary
/// transfers, its position within that run's schedule.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TransferId(String);

impl TransferId {
    /// Run-scoped transfer id: `"<run_id>:<index>"`. Constructed by the engine.
    pub(crate) fn for_transfer(run_id: &str, index: u32) -> Self {
        TransferId(format!("{run_id}:{index}"))
    }

    /// The note-split prep transaction id: `"prep:<run_id>"`.
    pub(crate) fn for_prep(run_id: &str) -> Self {
        TransferId(format!("prep:{run_id}"))
    }

    /// Wraps an already-formatted id string, e.g. one read back from the store.
    pub(crate) fn from_raw(raw: String) -> Self {
        TransferId(raw)
    }

    /// The underlying id string.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns `true` if this is the note-split "prep" transaction's id (i.e. it was built by
    /// `TransferId::for_prep`), as opposed to an ordinary per-transfer id.
    pub(crate) fn is_prep(&self) -> bool {
        self.0.starts_with("prep:")
    }
}

impl fmt::Display for TransferId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A planned note split: the self-funding denomination notes to mint, and the split fee.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoteSplitProposal {
    output_values: Vec<Zatoshis>,
    fee: Zatoshis,
}

impl NoteSplitProposal {
    /// Constructs a proposal from its parts: the per-note output values (each a power-of-ten
    /// crossing value plus the transfer fee buffer) and the fee paid by the split transaction
    /// itself.
    pub fn from_parts(output_values: Vec<Zatoshis>, fee: Zatoshis) -> Self {
        NoteSplitProposal { output_values, fee }
    }

    /// The value of each output note the split transaction will create.
    pub fn output_values(&self) -> &[Zatoshis] {
        &self.output_values
    }

    /// The fee paid by the note-split transaction.
    pub fn fee(&self) -> Zatoshis {
        self.fee
    }
}

/// A single scheduled Orchard→Ironwood transfer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferProposal {
    id: TransferId,
    amount: Zatoshis,
    anchor_height: BlockHeight,
    next_executable_after_height: BlockHeight,
    expiry_height: BlockHeight,
}

impl TransferProposal {
    /// Constructs a transfer proposal from its parts.
    pub fn from_parts(
        id: TransferId,
        amount: Zatoshis,
        anchor_height: BlockHeight,
        next_executable_after_height: BlockHeight,
        expiry_height: BlockHeight,
    ) -> Self {
        TransferProposal {
            id,
            amount,
            anchor_height,
            next_executable_after_height,
            expiry_height,
        }
    }

    /// The run-scoped identifier for this transfer.
    pub fn id(&self) -> &TransferId {
        &self.id
    }

    /// The value that crosses the turnstile from Orchard to Ironwood — a power-of-ten ZEC
    /// amount.
    ///
    /// This is **not** the value of the note actually spent to fund the transfer: the spent note
    /// carries `amount()` plus a fee buffer that pays for the transfer's own ZIP-317 fee, and
    /// only `amount()` itself is delivered across the pool boundary.
    pub fn amount(&self) -> Zatoshis {
        self.amount
    }

    /// The anchor height this transfer's PCZT is built against.
    ///
    /// This is the wallet's real, witnessable note-commitment-tree anchor (from
    /// `get_target_and_anchor_heights`), shared by every transfer in the same
    /// [`MigrationSchedule`]. It is deliberately *not* rounded to a network-wide bucket: the
    /// wallet only checkpoints at its own scan-batch boundaries, so an arbitrary bucketed height
    /// is essentially never witnessable (see the note in [`crate::scheduling`]).
    pub fn anchor_height(&self) -> BlockHeight {
        self.anchor_height
    }

    /// The height after which the platform may broadcast this transfer.
    pub fn next_executable_after_height(&self) -> BlockHeight {
        self.next_executable_after_height
    }

    /// The height after which this transfer is no longer valid and its step must be restarted.
    pub fn expiry_height(&self) -> BlockHeight {
        self.expiry_height
    }
}

/// The full migration schedule presented to the user for one-time confirmation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationSchedule {
    transfers: Vec<TransferProposal>,
    estimated_duration_hours: u32,
}

impl MigrationSchedule {
    /// Constructs a schedule from its parts.
    ///
    /// An empty `transfers` list is valid: it means there is nothing left to migrate.
    pub fn from_parts(transfers: Vec<TransferProposal>, estimated_duration_hours: u32) -> Self {
        MigrationSchedule {
            transfers,
            estimated_duration_hours,
        }
    }

    /// The scheduled transfers, in execution order.
    pub fn transfers(&self) -> &[TransferProposal] {
        &self.transfers
    }

    /// A rough estimate of how long the schedule will take to fully execute, in hours.
    pub fn estimated_duration_hours(&self) -> u32 {
        self.estimated_duration_hours
    }

    /// Returns `true` if the schedule has no transfers, i.e. there is nothing left to migrate.
    pub fn is_empty(&self) -> bool {
        self.transfers.is_empty()
    }
}

/// Live migration progress for the progress UI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationProgress {
    completed_transfers: u32,
    total_transfers: u32,
    remaining_orchard_value: Zatoshis,
    next_transfer_ready_at_height: Option<BlockHeight>,
}

impl MigrationProgress {
    /// Constructs a progress snapshot from its parts.
    pub fn from_parts(
        completed_transfers: u32,
        total_transfers: u32,
        remaining_orchard_value: Zatoshis,
        next_transfer_ready_at_height: Option<BlockHeight>,
    ) -> Self {
        MigrationProgress {
            completed_transfers,
            total_transfers,
            remaining_orchard_value,
            next_transfer_ready_at_height,
        }
    }

    /// The number of scheduled transfers confirmed on-chain so far.
    pub fn completed_transfers(&self) -> u32 {
        self.completed_transfers
    }

    /// The total number of transfers in the current schedule.
    pub fn total_transfers(&self) -> u32 {
        self.total_transfers
    }

    /// The Orchard-pool value not yet migrated to Ironwood.
    pub fn remaining_orchard_value(&self) -> Zatoshis {
        self.remaining_orchard_value
    }

    /// The height at which the next transfer becomes eligible for broadcast, if one is
    /// scheduled.
    pub fn next_transfer_ready_at_height(&self) -> Option<BlockHeight> {
        self.next_transfer_ready_at_height
    }
}

/// A fully proven and signed transaction, persisted as a PCZT, ready for the platform to
/// broadcast.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedTransfer {
    id: TransferId,
    txid: TxId,
    pczt_bytes: Vec<u8>,
}

impl PreparedTransfer {
    /// Constructs a prepared transfer from its parts. Used internally once a transfer's PCZT has
    /// been built, proven, signed, and finalized.
    pub(crate) fn from_parts(id: TransferId, txid: TxId, pczt_bytes: Vec<u8>) -> Self {
        PreparedTransfer {
            id,
            txid,
            pczt_bytes,
        }
    }

    /// The transfer this prepared transaction answers.
    pub fn id(&self) -> &TransferId {
        &self.id
    }

    /// The (pre-computed) transaction id of the finalized transaction carried by this PCZT.
    pub fn txid(&self) -> TxId {
        self.txid
    }

    /// The serialized, proven, and signed `pczt::Pczt`.
    ///
    /// The platform extracts the consensus transaction from this PCZT and broadcasts it.
    pub fn pczt_bytes(&self) -> &[u8] {
        &self.pczt_bytes
    }

    /// Consumes this prepared transfer, returning the owned serialized PCZT bytes.
    pub fn into_pczt_bytes(self) -> Vec<u8> {
        self.pczt_bytes
    }
}

/// An unsigned-but-proven PCZT awaiting an external signer (Keystone-style hardware wallet
/// flow).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsignedTransferPczt {
    id: TransferId,
    pczt_bytes: Vec<u8>,
}

impl UnsignedTransferPczt {
    /// Constructs an unsigned transfer PCZT from its parts. Used internally when staging a
    /// proven, unsigned PCZT for export to an external signer
    /// (`MigrationContext::create_unsigned_transfer_pczts`).
    pub(crate) fn from_parts(id: TransferId, pczt_bytes: Vec<u8>) -> Self {
        UnsignedTransferPczt { id, pczt_bytes }
    }

    /// The transfer this PCZT corresponds to.
    pub fn id(&self) -> &TransferId {
        &self.id
    }

    /// The serialized, proven, but not-yet-signed `pczt::Pczt`, for the platform to hand to the
    /// external signer.
    pub fn pczt_bytes(&self) -> &[u8] {
        &self.pczt_bytes
    }
}

/// A signed PCZT returned from an external signer, paired with the transfer it answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedTransferPczt {
    id: TransferId,
    pczt_bytes: Vec<u8>,
}

impl SignedTransferPczt {
    /// Constructs a signed transfer PCZT from the external signer's output.
    ///
    /// Unlike `UnsignedTransferPczt::from_parts`, this constructor is public: the platform
    /// builds these directly from the bytes an external signer (e.g. a hardware wallet) returns,
    /// and hands them back to the engine to combine with the staged unsigned PCZT.
    pub fn from_parts(id: TransferId, pczt_bytes: Vec<u8>) -> Self {
        SignedTransferPczt { id, pczt_bytes }
    }

    /// The transfer this PCZT corresponds to.
    pub fn id(&self) -> &TransferId {
        &self.id
    }

    /// The serialized, proven, and signed `pczt::Pczt` returned by the external signer.
    pub fn pczt_bytes(&self) -> &[u8] {
        &self.pczt_bytes
    }
}

/// Top-level migration state machine surfaced to the app.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MigrationState {
    /// No migration has been initiated.
    NotStarted,
    /// The note-split transaction has been submitted and is awaiting on-chain confirmation.
    SplitPendingConfirmation,
    /// The split is confirmed (or was not needed); the engine is ready to propose transfers.
    ReadyToPropose,
    /// The schedule has been committed and transfers are executing.
    InProgress(MigrationProgress),
    /// A transfer cannot proceed automatically; the app must act.
    RequiresAttention(AttentionReason),
    /// All transfers are confirmed; the Orchard balance is fully migrated.
    Complete,
}

/// Why a migration requires user attention.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttentionReason {
    /// The input note funding this transfer was spent externally before the transfer was
    /// broadcast.
    InvalidTransfer(TransferId),
    /// A transaction's anchor/expiry elapsed before it could be broadcast.
    TransferExpired,
    /// A transfer produced change back to Orchard that must be synced before the next spend.
    SyncRequiredBeforeNext,
}

/// The outcome of a broadcast attempt, reported back to the engine by the platform.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransferResult {
    /// The transaction broadcast successfully; carries the resulting transaction id.
    Success(TxId),
    /// A transient network failure.
    NetworkError {
        /// Whether the platform should retry this transfer in a later window.
        retryable: bool,
    },
    /// The input note had already been spent.
    InvalidNote,
    /// The transaction's anchor/expiry height had already passed.
    Expired,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transfer_id_formats() {
        let t = TransferId::for_transfer("run-1", 3);
        assert_eq!(t.as_str(), "run-1:3");
        assert!(!t.is_prep());
        let p = TransferId::for_prep("run-1");
        assert_eq!(p.as_str(), "prep:run-1");
        assert!(p.is_prep());
        assert_eq!(TransferId::from_raw("prep:run-1".into()), p);
    }

    #[test]
    fn note_split_proposal_round_trips_parts() {
        let vals = vec![Zatoshis::const_from_u64(100_020_000)];
        let p = NoteSplitProposal::from_parts(vals.clone(), Zatoshis::const_from_u64(15_000));
        assert_eq!(p.output_values(), &vals[..]);
        assert_eq!(p.fee(), Zatoshis::const_from_u64(15_000));
    }

    #[test]
    fn transfer_proposal_round_trips_parts() {
        let id = TransferId::for_transfer("run-1", 0);
        let t = TransferProposal::from_parts(
            id.clone(),
            Zatoshis::const_from_u64(1_000_000_000),
            BlockHeight::from_u32(2_880_000),
            BlockHeight::from_u32(2_880_288),
            BlockHeight::from_u32(2_880_576),
        );
        assert_eq!(t.id(), &id);
        assert_eq!(t.amount(), Zatoshis::const_from_u64(1_000_000_000));
        assert_eq!(t.anchor_height(), BlockHeight::from_u32(2_880_000));
        assert_eq!(
            t.next_executable_after_height(),
            BlockHeight::from_u32(2_880_288)
        );
        assert_eq!(t.expiry_height(), BlockHeight::from_u32(2_880_576));
    }

    #[test]
    fn migration_schedule_round_trips_parts_and_reports_emptiness() {
        let transfer = TransferProposal::from_parts(
            TransferId::for_transfer("run-1", 0),
            Zatoshis::const_from_u64(5),
            BlockHeight::from_u32(1),
            BlockHeight::from_u32(2),
            BlockHeight::from_u32(3),
        );
        let transfers = vec![transfer];
        let schedule = MigrationSchedule::from_parts(transfers.clone(), 6);
        assert_eq!(schedule.transfers(), &transfers[..]);
        assert_eq!(schedule.estimated_duration_hours(), 6);
        assert!(!schedule.is_empty());

        let empty = MigrationSchedule::from_parts(vec![], 0);
        assert!(empty.is_empty());
        assert_eq!(empty.estimated_duration_hours(), 0);
    }

    #[test]
    fn migration_progress_round_trips_parts() {
        let p = MigrationProgress::from_parts(
            2,
            5,
            Zatoshis::const_from_u64(600_000_000),
            Some(BlockHeight::from_u32(2_880_864)),
        );
        assert_eq!(p.completed_transfers(), 2);
        assert_eq!(p.total_transfers(), 5);
        assert_eq!(
            p.remaining_orchard_value(),
            Zatoshis::const_from_u64(600_000_000)
        );
        assert_eq!(
            p.next_transfer_ready_at_height(),
            Some(BlockHeight::from_u32(2_880_864))
        );

        let none = MigrationProgress::from_parts(2, 5, Zatoshis::const_from_u64(600_000_000), None);
        assert_eq!(none.next_transfer_ready_at_height(), None);
    }

    #[test]
    fn prepared_transfer_round_trips_parts_and_converts_into_bytes() {
        let id = TransferId::for_transfer("run-1", 0);
        let txid = TxId::from_bytes([7u8; 32]);
        let bytes = vec![0x50, 0x00, 0xff];
        let prepared = PreparedTransfer::from_parts(id.clone(), txid, bytes.clone());
        assert_eq!(prepared.id(), &id);
        assert_eq!(prepared.txid(), txid);
        assert_eq!(prepared.pczt_bytes(), &bytes[..]);
        assert_eq!(prepared.into_pczt_bytes(), bytes);
    }

    #[test]
    fn unsigned_transfer_pczt_round_trips_parts() {
        let id = TransferId::for_transfer("run-1", 0);
        let bytes = vec![0x50, 0x43, 0x5a, 0x54];
        let pczt = UnsignedTransferPczt::from_parts(id.clone(), bytes.clone());
        assert_eq!(pczt.id(), &id);
        assert_eq!(pczt.pczt_bytes(), &bytes[..]);
    }

    #[test]
    fn signed_transfer_pczt_round_trips_parts() {
        let id = TransferId::for_prep("run-1");
        let bytes = vec![0x01, 0x02];
        let pczt = SignedTransferPczt::from_parts(id.clone(), bytes.clone());
        assert_eq!(pczt.id(), &id);
        assert_eq!(pczt.pczt_bytes(), &bytes[..]);
    }

    #[test]
    fn migration_state_constructs_each_variant() {
        let progress = MigrationProgress::from_parts(1, 3, Zatoshis::const_from_u64(1), None);
        assert_eq!(MigrationState::NotStarted, MigrationState::NotStarted);
        assert_eq!(
            MigrationState::SplitPendingConfirmation,
            MigrationState::SplitPendingConfirmation
        );
        assert_eq!(
            MigrationState::ReadyToPropose,
            MigrationState::ReadyToPropose
        );
        assert_eq!(
            MigrationState::InProgress(progress.clone()),
            MigrationState::InProgress(progress)
        );
        assert_eq!(
            MigrationState::RequiresAttention(AttentionReason::TransferExpired),
            MigrationState::RequiresAttention(AttentionReason::TransferExpired)
        );
        assert_eq!(
            MigrationState::RequiresAttention(AttentionReason::InvalidTransfer(
                TransferId::for_transfer("run-1", 0)
            )),
            MigrationState::RequiresAttention(AttentionReason::InvalidTransfer(
                TransferId::for_transfer("run-1", 0)
            ))
        );
        assert_eq!(MigrationState::Complete, MigrationState::Complete);
        assert_ne!(MigrationState::NotStarted, MigrationState::Complete);
    }

    #[test]
    fn attention_reason_constructs_each_variant() {
        let id = TransferId::for_transfer("run-1", 2);
        assert_eq!(
            AttentionReason::InvalidTransfer(id.clone()),
            AttentionReason::InvalidTransfer(id)
        );
        assert_eq!(
            AttentionReason::TransferExpired,
            AttentionReason::TransferExpired
        );
        assert_eq!(
            AttentionReason::SyncRequiredBeforeNext,
            AttentionReason::SyncRequiredBeforeNext
        );
        assert_ne!(
            AttentionReason::TransferExpired,
            AttentionReason::SyncRequiredBeforeNext
        );
    }

    #[test]
    fn transfer_result_constructs_each_variant() {
        let txid = TxId::from_bytes([1u8; 32]);
        assert_eq!(TransferResult::Success(txid), TransferResult::Success(txid));
        assert_eq!(
            TransferResult::NetworkError { retryable: true },
            TransferResult::NetworkError { retryable: true }
        );
        assert_ne!(
            TransferResult::NetworkError { retryable: true },
            TransferResult::NetworkError { retryable: false }
        );
        assert_eq!(TransferResult::InvalidNote, TransferResult::InvalidNote);
        assert_eq!(TransferResult::Expired, TransferResult::Expired);
        assert_ne!(TransferResult::InvalidNote, TransferResult::Expired);
    }
}
