//! The [`MigrationStore`] trait: the persistence the migration engine needs, and the plain-data
//! row types that cross that boundary.
//!
//! The engine is generic over an implementation of this trait, so the same migration logic drives
//! any storage backend (SQLite today, an in-memory backend for tests later). A backend persists
//! and reads the engine's run/transaction/note state; the engine owns every decision about what to
//! store and when.
//!
//! Multi-write operations that must be durable all-or-nothing are exposed as single "commit"
//! methods (see the trait's atomic-commit section), so an implementation makes each one atomic in
//! whatever way suits it, and the engine never manages transactions itself.

use crate::state::Phase;

/// Which kind of staged external-signer PCZTs an operation concerns.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StagedKind {
    /// The note-split PCZT.
    Split,
    /// The scheduled-transfer PCZTs.
    Transfer,
}

impl StagedKind {
    /// The persisted string form of this kind.
    pub fn as_str(&self) -> &'static str {
        match self {
            StagedKind::Split => "split",
            StagedKind::Transfer => "transfer",
        }
    }
}

/// The parameters to insert a new migration run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NewRun {
    run_id: String,
    account_uuid: String,
    network: String,
    db_fingerprint: String,
    phase: Phase,
    prep_txid: Option<String>,
    target_values: Vec<u64>,
}

impl NewRun {
    /// Constructs the new-run parameters from their parts.
    pub fn from_parts(
        run_id: String,
        account_uuid: String,
        network: String,
        db_fingerprint: String,
        phase: Phase,
        prep_txid: Option<String>,
        target_values: Vec<u64>,
    ) -> Self {
        NewRun {
            run_id,
            account_uuid,
            network,
            db_fingerprint,
            phase,
            prep_txid,
            target_values,
        }
    }

    /// The run's unique id.
    pub fn run_id(&self) -> &str {
        &self.run_id
    }

    /// The account this run belongs to.
    pub fn account_uuid(&self) -> &str {
        &self.account_uuid
    }

    /// The network this run runs against.
    pub fn network(&self) -> &str {
        &self.network
    }

    /// A fingerprint of the wallet database the run was created against.
    pub fn db_fingerprint(&self) -> &str {
        &self.db_fingerprint
    }

    /// The run's initial phase.
    pub fn phase(&self) -> Phase {
        self.phase
    }

    /// The note-split transaction id, once one exists.
    pub fn prep_txid(&self) -> Option<&str> {
        self.prep_txid.as_deref()
    }

    /// The self-funding crossing values this run will migrate.
    pub fn target_values(&self) -> &[u64] {
        &self.target_values
    }
}

/// A persisted migration run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunRow {
    run_id: String,
    account_uuid: String,
    network: String,
    phase: String,
    prep_txid: Option<String>,
    target_values: Vec<u64>,
    last_error: Option<String>,
}

impl RunRow {
    /// Constructs a run row from its parts.
    pub fn from_parts(
        run_id: String,
        account_uuid: String,
        network: String,
        phase: String,
        prep_txid: Option<String>,
        target_values: Vec<u64>,
        last_error: Option<String>,
    ) -> Self {
        RunRow {
            run_id,
            account_uuid,
            network,
            phase,
            prep_txid,
            target_values,
            last_error,
        }
    }

    /// The run's unique id.
    pub fn run_id(&self) -> &str {
        &self.run_id
    }

    /// The account this run belongs to.
    pub fn account_uuid(&self) -> &str {
        &self.account_uuid
    }

    /// The network this run runs against.
    pub fn network(&self) -> &str {
        &self.network
    }

    /// The run's persisted phase string (parse with [`Phase::parse`]).
    pub fn phase(&self) -> &str {
        &self.phase
    }

    /// The note-split transaction id, if one exists.
    pub fn prep_txid(&self) -> Option<&str> {
        self.prep_txid.as_deref()
    }

    /// The self-funding crossing values this run migrates.
    pub fn target_values(&self) -> &[u64] {
        &self.target_values
    }

    /// The last recorded error for this run, if any.
    pub fn last_error(&self) -> Option<&str> {
        self.last_error.as_deref()
    }
}

/// A prepared self-funding note produced by the note split, held under a migration lock.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedNote {
    txid_hex: String,
    output_index: u32,
    value_zatoshi: u64,
    note_version: i64,
    nullifier_hex: Option<String>,
    lock_state: String,
}

impl PreparedNote {
    /// Constructs a prepared-note record from its parts.
    pub fn from_parts(
        txid_hex: String,
        output_index: u32,
        value_zatoshi: u64,
        note_version: i64,
        nullifier_hex: Option<String>,
        lock_state: String,
    ) -> Self {
        PreparedNote {
            txid_hex,
            output_index,
            value_zatoshi,
            note_version,
            nullifier_hex,
            lock_state,
        }
    }

    /// The hex transaction id that created the note.
    pub fn txid_hex(&self) -> &str {
        &self.txid_hex
    }

    /// The note's output index within that transaction.
    pub fn output_index(&self) -> u32 {
        self.output_index
    }

    /// The note's value in zatoshi.
    pub fn value_zatoshi(&self) -> u64 {
        self.value_zatoshi
    }

    /// The note's bundle version (Orchard vs Ironwood).
    pub fn note_version(&self) -> i64 {
        self.note_version
    }

    /// The note's nullifier, hex-encoded, if known.
    pub fn nullifier_hex(&self) -> Option<&str> {
        self.nullifier_hex.as_deref()
    }

    /// The note's migration lock state.
    pub fn lock_state(&self) -> &str {
        &self.lock_state
    }
}

/// The one note-split ("prep") transaction that precedes a run's transfers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NoteSplitTxRow {
    run_id: String,
    txid_hex: String,
    raw_pczt: Vec<u8>,
    status: String,
}

impl NoteSplitTxRow {
    /// Constructs a note-split transaction row from its parts.
    pub fn from_parts(run_id: String, txid_hex: String, raw_pczt: Vec<u8>, status: String) -> Self {
        NoteSplitTxRow {
            run_id,
            txid_hex,
            raw_pczt,
            status,
        }
    }

    /// The run this note-split transaction belongs to.
    pub fn run_id(&self) -> &str {
        &self.run_id
    }

    /// The transaction's hex id.
    pub fn txid_hex(&self) -> &str {
        &self.txid_hex
    }

    /// The serialized, proven, and signed PCZT.
    pub fn raw_pczt(&self) -> &[u8] {
        &self.raw_pczt
    }

    /// The transaction's status.
    pub fn status(&self) -> &str {
        &self.status
    }
}

/// A single scheduled Orchard-to-Ironwood transfer awaiting its send window, broadcast, or
/// confirmation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScheduledTransferRow {
    txid_hex: String,
    raw_pczt: Vec<u8>,
    anchor_height: u32,
    target_height: u32,
    next_executable_after_height: u32,
    expiry_height: u32,
    value_zatoshi: u64,
    fee_zatoshi: u64,
    selected_note_txid: String,
    selected_note_output_index: u32,
    selected_note_value: u64,
    status: String,
    metadata_json: String,
}

impl ScheduledTransferRow {
    /// Constructs a scheduled-transfer row from its parts.
    #[allow(clippy::too_many_arguments)]
    pub fn from_parts(
        txid_hex: String,
        raw_pczt: Vec<u8>,
        anchor_height: u32,
        target_height: u32,
        next_executable_after_height: u32,
        expiry_height: u32,
        value_zatoshi: u64,
        fee_zatoshi: u64,
        selected_note_txid: String,
        selected_note_output_index: u32,
        selected_note_value: u64,
        status: String,
        metadata_json: String,
    ) -> Self {
        ScheduledTransferRow {
            txid_hex,
            raw_pczt,
            anchor_height,
            target_height,
            next_executable_after_height,
            expiry_height,
            value_zatoshi,
            fee_zatoshi,
            selected_note_txid,
            selected_note_output_index,
            selected_note_value,
            status,
            metadata_json,
        }
    }

    /// The transfer transaction's hex id.
    pub fn txid_hex(&self) -> &str {
        &self.txid_hex
    }

    /// The serialized, proven, and signed PCZT.
    pub fn raw_pczt(&self) -> &[u8] {
        &self.raw_pczt
    }

    /// The note-commitment-tree anchor height the PCZT is built against.
    pub fn anchor_height(&self) -> u32 {
        self.anchor_height
    }

    /// The target height the PCZT is built for.
    pub fn target_height(&self) -> u32 {
        self.target_height
    }

    /// The height after which the platform may broadcast this transfer.
    pub fn next_executable_after_height(&self) -> u32 {
        self.next_executable_after_height
    }

    /// The height after which this transfer is no longer valid.
    pub fn expiry_height(&self) -> u32 {
        self.expiry_height
    }

    /// The value (zatoshi) that crosses the turnstile.
    pub fn value_zatoshi(&self) -> u64 {
        self.value_zatoshi
    }

    /// The transfer's ZIP-317 fee in zatoshi.
    pub fn fee_zatoshi(&self) -> u64 {
        self.fee_zatoshi
    }

    /// The hex transaction id of the note this transfer spends.
    pub fn selected_note_txid(&self) -> &str {
        &self.selected_note_txid
    }

    /// The output index of the note this transfer spends.
    pub fn selected_note_output_index(&self) -> u32 {
        self.selected_note_output_index
    }

    /// The value (zatoshi) of the note this transfer spends.
    pub fn selected_note_value(&self) -> u64 {
        self.selected_note_value
    }

    /// The transfer's status.
    pub fn status(&self) -> &str {
        &self.status
    }

    /// Opaque platform metadata carried with the transfer.
    pub fn metadata_json(&self) -> &str {
        &self.metadata_json
    }
}

/// A proven-but-unsigned PCZT staged for an external signer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StagedPczt {
    staging_id: String,
    raw_pczt: Vec<u8>,
    metadata_json: String,
}

impl StagedPczt {
    /// Constructs a staged-PCZT record from its parts.
    pub fn from_parts(staging_id: String, raw_pczt: Vec<u8>, metadata_json: String) -> Self {
        StagedPczt {
            staging_id,
            raw_pczt,
            metadata_json,
        }
    }

    /// The staging id that identifies this PCZT within its kind.
    pub fn staging_id(&self) -> &str {
        &self.staging_id
    }

    /// The serialized, proven, unsigned PCZT.
    pub fn raw_pczt(&self) -> &[u8] {
        &self.raw_pczt
    }

    /// Opaque platform metadata carried with the staged PCZT.
    pub fn metadata_json(&self) -> &str {
        &self.metadata_json
    }
}

/// Counts of a run's scheduled transfers by status.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransferTotals {
    scheduled: u32,
    broadcasted: u32,
    confirmed: u32,
    total: u32,
}

impl TransferTotals {
    /// Constructs transfer totals from their parts.
    pub fn from_parts(scheduled: u32, broadcasted: u32, confirmed: u32, total: u32) -> Self {
        TransferTotals {
            scheduled,
            broadcasted,
            confirmed,
            total,
        }
    }

    /// The number of transfers still scheduled (not yet broadcast).
    pub fn scheduled(&self) -> u32 {
        self.scheduled
    }

    /// The number of transfers broadcast but not yet confirmed.
    pub fn broadcasted(&self) -> u32 {
        self.broadcasted
    }

    /// The number of transfers confirmed on-chain.
    pub fn confirmed(&self) -> u32 {
        self.confirmed
    }

    /// The total number of transfers in the run.
    pub fn total(&self) -> u32 {
        self.total
    }
}

/// The persistence the migration engine requires from a storage backend.
///
/// The engine is generic over an implementation, which owns its own storage handle. Reads return
/// owned row types; single writes mutate one row group; the atomic-commit methods each persist a
/// multi-row operation all-or-nothing. No storage-backend-specific type (a connection, a SQL error)
/// appears in this interface.
pub trait MigrationStore {
    /// The storage backend's error type.
    type Error: core::error::Error;

    /// Ensures the engine's own storage exists (idempotent).
    fn init(&mut self) -> Result<(), Self::Error>;

    // ----- reads -----

    /// The newest non-terminal run for the account and network, if any.
    fn active_run(&self, account_uuid: &str, network: &str) -> Result<Option<RunRow>, Self::Error>;

    /// The run with the given id, if any.
    fn run_by_id(&self, run_id: &str) -> Result<Option<RunRow>, Self::Error>;

    /// The run's note-split transaction, if one exists.
    fn note_split_tx(&self, run_id: &str) -> Result<Option<NoteSplitTxRow>, Self::Error>;

    /// The earliest scheduled transfer due at or below `tip_height`, if any.
    fn next_due_transfer(
        &self,
        run_id: &str,
        tip_height: u32,
    ) -> Result<Option<ScheduledTransferRow>, Self::Error>;

    /// The minimum send height among the run's still-scheduled transfers, if any.
    fn next_scheduled_send_height(&self, run_id: &str) -> Result<Option<u32>, Self::Error>;

    /// The hex transaction ids of the run's broadcast-but-not-confirmed transfers.
    fn broadcasted_txids(&self, run_id: &str) -> Result<Vec<String>, Self::Error>;

    /// Counts of the run's scheduled transfers by status.
    fn transfer_totals(&self, run_id: &str) -> Result<TransferTotals, Self::Error>;

    /// Whether the run has a transfer due at or below `tip_height` (a cheap existence check).
    fn has_due_transfer(&self, run_id: &str, tip_height: u32) -> Result<bool, Self::Error>;

    /// The `(txid_hex, output_index)` notes locked by the account's live runs, optionally excluding
    /// one run.
    fn locked_note_refs(
        &self,
        account_uuid: &str,
        exclude_run_id: Option<&str>,
    ) -> Result<Vec<(String, u32)>, Self::Error>;

    /// The account's staged external-signer PCZTs of a given kind, in insertion order.
    fn staged_pczts(
        &self,
        account_uuid: &str,
        network: &str,
        kind: StagedKind,
    ) -> Result<Vec<StagedPczt>, Self::Error>;

    // ----- single writes -----

    /// Sets a run's phase and its last error.
    fn set_phase(
        &mut self,
        run_id: &str,
        phase: Phase,
        last_error: Option<&str>,
    ) -> Result<(), Self::Error>;

    /// Sets the run's note-split transaction status.
    fn set_note_split_tx_status(&mut self, run_id: &str, status: &str) -> Result<(), Self::Error>;

    /// Sets a transfer's status by its hex transaction id, returning the number of rows updated.
    fn mark_transfer_status(&mut self, txid_hex: &str, status: &str) -> Result<usize, Self::Error>;

    /// Deletes the run's still-scheduled transfers (those not yet broadcast), returning the number
    /// deleted.
    fn clear_scheduled_transfers(&mut self, run_id: &str) -> Result<usize, Self::Error>;

    /// Inserts or replaces a staged external-signer PCZT of a given kind.
    fn upsert_staged_pczt(
        &mut self,
        account_uuid: &str,
        network: &str,
        kind: StagedKind,
        staged: &StagedPczt,
    ) -> Result<(), Self::Error>;

    /// Deletes all of the account's staged PCZTs of a given kind, returning the number deleted.
    fn clear_staged_pczts(
        &mut self,
        account_uuid: &str,
        network: &str,
        kind: StagedKind,
    ) -> Result<usize, Self::Error>;

    // ----- atomic commits -----

    /// Persists a signed note split all-or-nothing: the run, its note-split transaction, and its
    /// locked prepared notes; and, when `clear_staged` is set, clears that kind of staged PCZT
    /// (the external-signer path).
    fn commit_note_split(
        &mut self,
        run: &NewRun,
        note_split_tx: &NoteSplitTxRow,
        prepared_notes: &[PreparedNote],
        clear_staged: Option<StagedKind>,
    ) -> Result<(), Self::Error>;

    /// Persists a signed transfer schedule all-or-nothing: the run, its scheduled transfers, and
    /// its new phase; and, when `clear_staged` is set, clears that kind of staged PCZT.
    fn commit_transfer_schedule(
        &mut self,
        run: &NewRun,
        transfers: &[ScheduledTransferRow],
        phase: Phase,
        clear_staged: Option<StagedKind>,
    ) -> Result<(), Self::Error>;

    /// Persists a run and its phase all-or-nothing (the sign-and-store path, which re-anchors an
    /// existing run without changing its transfers).
    fn commit_run_phase(&mut self, run: &NewRun, phase: Phase) -> Result<(), Self::Error>;
}
