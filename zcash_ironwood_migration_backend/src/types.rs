//! Public data types for the migration engine.
//!
//! Amounts use [`Zatoshis`] and heights use [`BlockHeight`] (the canonical `zcash_protocol`
//! types, which enforce their own invariants), and transaction identifiers use [`TxId`].
//!
//! Where a value has a signing lifecycle, that lifecycle is encoded in the type system rather than
//! carried as a runtime flag: a transfer PCZT is a [`TransferPczt<State>`](TransferPczt) whose
//! `State` is [`Unsigned`] or [`Signed`], and the only way to reach the signed state is the
//! [`TransferPczt::into_signed`] transition.

use core::fmt;
use core::marker::PhantomData;

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

    /// Wraps a raw stored id string verbatim (round-tripping a persisted transfer id).
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
    /// Constructs a proposal from its parts: the per-note output values (each a `{1, 2, 5} * 10^k`
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

/// A single scheduled Orchard -> Ironwood transfer.
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

    /// The value that crosses the turnstile from Orchard to Ironwood: a `{1, 2, 5} * 10^k` ZEC
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
    /// is essentially never witnessable.
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

/// Typestate marker for a transfer PCZT that has been proven but not yet signed.
///
/// Uninhabited: it exists only as the `State` type parameter of [`TransferPczt`], never as a
/// value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unsigned {}

/// Typestate marker for a transfer PCZT that has been signed by an external signer.
///
/// Uninhabited: it exists only as the `State` type parameter of [`TransferPczt`], never as a
/// value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Signed {}

/// A transfer PCZT together with its signing state, tracked at the type level.
///
/// The `State` parameter is either [`Unsigned`] (a proven PCZT awaiting an external signer, the
/// Keystone-style hardware wallet flow) or [`Signed`] (the bytes an external signer returned). Both
/// states carry the same data (the [`TransferId`] they answer and the serialized `pczt::Pczt`
/// bytes) but are distinct types, so the compiler enforces the lifecycle: an unsigned value can
/// only become signed through the [`TransferPczt::into_signed`] transition, and an API that
/// requires a signed PCZT cannot be handed an unsigned one by mistake.
///
/// The two states are also exposed as the aliases [`UnsignedTransferPczt`] and
/// [`SignedTransferPczt`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferPczt<State> {
    id: TransferId,
    pczt_bytes: Vec<u8>,
    _state: PhantomData<State>,
}

/// A proven-but-unsigned transfer PCZT awaiting an external signer (Keystone-style hardware wallet
/// flow). Alias for [`TransferPczt<Unsigned>`](TransferPczt).
pub type UnsignedTransferPczt = TransferPczt<Unsigned>;

/// A signed transfer PCZT returned from an external signer, paired with the transfer it answers.
/// Alias for [`TransferPczt<Signed>`](TransferPczt).
pub type SignedTransferPczt = TransferPczt<Signed>;

impl<State> TransferPczt<State> {
    /// The transfer this PCZT corresponds to.
    pub fn id(&self) -> &TransferId {
        &self.id
    }

    /// The serialized `pczt::Pczt` bytes, in whichever signing state this value holds.
    pub fn pczt_bytes(&self) -> &[u8] {
        &self.pczt_bytes
    }
}

impl TransferPczt<Unsigned> {
    /// Constructs an unsigned transfer PCZT from its parts. Used internally when staging a proven,
    /// unsigned PCZT for export to an external signer
    /// (`MigrationContext::create_unsigned_transfer_pczts`).
    pub(crate) fn from_parts(id: TransferId, pczt_bytes: Vec<u8>) -> Self {
        TransferPczt {
            id,
            pczt_bytes,
            _state: PhantomData,
        }
    }

    /// Transitions this proven-but-unsigned PCZT into the [`Signed`] state, replacing its bytes
    /// with the signed PCZT bytes an external signer returned while carrying the [`TransferId`]
    /// across unchanged.
    ///
    /// This is the only way to obtain a [`SignedTransferPczt`] from an [`UnsignedTransferPczt`],
    /// so the signing step cannot be skipped or the two states confused at a call site.
    pub fn into_signed(self, signed_pczt_bytes: Vec<u8>) -> SignedTransferPczt {
        TransferPczt {
            id: self.id,
            pczt_bytes: signed_pczt_bytes,
            _state: PhantomData,
        }
    }
}

impl TransferPczt<Signed> {
    /// Constructs a signed transfer PCZT from an external signer's output and the id of the
    /// transfer it answers.
    ///
    /// Prefer [`TransferPczt::into_signed`] when the originating [`UnsignedTransferPczt`] is still
    /// in hand, since it carries the [`TransferId`] across for you. This constructor is public for
    /// platforms that reconstruct the signed PCZT from a stored [`TransferId`] and the signer's
    /// bytes instead.
    pub fn from_parts(id: TransferId, pczt_bytes: Vec<u8>) -> Self {
        TransferPczt {
            id,
            pczt_bytes,
            _state: PhantomData,
        }
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

/// Proptest strategies for the public types.
#[cfg(feature = "test-dependencies")]
pub mod testing {
    use proptest::collection::vec;
    use proptest::prelude::*;
    use zcash_protocol::value::testing::arb_zatoshis;

    use super::{
        AttentionReason, BlockHeight, MigrationProgress, MigrationSchedule, MigrationState,
        NoteSplitProposal, PreparedTransfer, SignedTransferPczt, TransferId, TransferProposal,
        TransferResult, TxId, UnsignedTransferPczt,
    };

    /// A short run-id fragment (`[a-z0-9]{1,12}`) used to build [`TransferId`]s.
    fn arb_run_id() -> impl Strategy<Value = String> {
        "[a-z0-9]{1,12}"
    }

    /// An arbitrary [`BlockHeight`] within a wide, realistic range.
    pub fn arb_block_height() -> impl Strategy<Value = BlockHeight> {
        (0u32..3_000_000u32).prop_map(BlockHeight::from_u32)
    }

    /// An arbitrary [`TxId`].
    pub fn arb_txid() -> impl Strategy<Value = TxId> {
        proptest::array::uniform32(any::<u8>()).prop_map(TxId::from_bytes)
    }

    /// An arbitrary [`TransferId`]: either an ordinary per-transfer id or a note-split "prep" id.
    pub fn arb_transfer_id() -> impl Strategy<Value = TransferId> {
        prop_oneof![
            (arb_run_id(), any::<u32>())
                .prop_map(|(run_id, index)| TransferId::for_transfer(&run_id, index)),
            arb_run_id().prop_map(|run_id| TransferId::for_prep(&run_id)),
        ]
    }

    /// An arbitrary [`NoteSplitProposal`].
    pub fn arb_note_split_proposal() -> impl Strategy<Value = NoteSplitProposal> {
        (vec(arb_zatoshis(), 0..8), arb_zatoshis())
            .prop_map(|(output_values, fee)| NoteSplitProposal::from_parts(output_values, fee))
    }

    /// An arbitrary [`TransferProposal`].
    pub fn arb_transfer_proposal() -> impl Strategy<Value = TransferProposal> {
        (
            arb_transfer_id(),
            arb_zatoshis(),
            arb_block_height(),
            arb_block_height(),
            arb_block_height(),
        )
            .prop_map(|(id, amount, anchor, next_executable, expiry)| {
                TransferProposal::from_parts(id, amount, anchor, next_executable, expiry)
            })
    }

    /// An arbitrary [`MigrationSchedule`], possibly empty.
    pub fn arb_migration_schedule() -> impl Strategy<Value = MigrationSchedule> {
        (vec(arb_transfer_proposal(), 0..6), any::<u32>())
            .prop_map(|(transfers, hours)| MigrationSchedule::from_parts(transfers, hours))
    }

    /// An arbitrary [`MigrationProgress`].
    pub fn arb_migration_progress() -> impl Strategy<Value = MigrationProgress> {
        (
            any::<u32>(),
            any::<u32>(),
            arb_zatoshis(),
            proptest::option::of(arb_block_height()),
        )
            .prop_map(|(completed, total, remaining, next_ready)| {
                MigrationProgress::from_parts(completed, total, remaining, next_ready)
            })
    }

    /// An arbitrary [`PreparedTransfer`].
    pub fn arb_prepared_transfer() -> impl Strategy<Value = PreparedTransfer> {
        (arb_transfer_id(), arb_txid(), vec(any::<u8>(), 0..64))
            .prop_map(|(id, txid, bytes)| PreparedTransfer::from_parts(id, txid, bytes))
    }

    /// An arbitrary [`UnsignedTransferPczt`].
    pub fn arb_unsigned_transfer_pczt() -> impl Strategy<Value = UnsignedTransferPczt> {
        (arb_transfer_id(), vec(any::<u8>(), 0..64))
            .prop_map(|(id, bytes)| UnsignedTransferPczt::from_parts(id, bytes))
    }

    /// An arbitrary [`SignedTransferPczt`].
    pub fn arb_signed_transfer_pczt() -> impl Strategy<Value = SignedTransferPczt> {
        (arb_transfer_id(), vec(any::<u8>(), 0..64))
            .prop_map(|(id, bytes)| SignedTransferPczt::from_parts(id, bytes))
    }

    /// An arbitrary [`AttentionReason`].
    pub fn arb_attention_reason() -> impl Strategy<Value = AttentionReason> {
        prop_oneof![
            arb_transfer_id().prop_map(AttentionReason::InvalidTransfer),
            Just(AttentionReason::TransferExpired),
            Just(AttentionReason::SyncRequiredBeforeNext),
        ]
    }

    /// An arbitrary [`MigrationState`], covering every variant.
    pub fn arb_migration_state() -> impl Strategy<Value = MigrationState> {
        prop_oneof![
            Just(MigrationState::NotStarted),
            Just(MigrationState::SplitPendingConfirmation),
            Just(MigrationState::ReadyToPropose),
            arb_migration_progress().prop_map(MigrationState::InProgress),
            arb_attention_reason().prop_map(MigrationState::RequiresAttention),
            Just(MigrationState::Complete),
        ]
    }

    /// An arbitrary [`TransferResult`], covering every variant.
    pub fn arb_transfer_result() -> impl Strategy<Value = TransferResult> {
        prop_oneof![
            arb_txid().prop_map(TransferResult::Success),
            any::<bool>().prop_map(|retryable| TransferResult::NetworkError { retryable }),
            Just(TransferResult::InvalidNote),
            Just(TransferResult::Expired),
        ]
    }
}
