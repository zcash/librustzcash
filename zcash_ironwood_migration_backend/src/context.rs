//! The [`MigrationContext`] engine: the public, synchronous API the platform wraps, generic over a
//! [`WalletMigrationBackend`] and a [`MigrationStore`].
//!
//! The engine ties the pure core (note splitting, scheduling, state, the PCZT pipeline) to two
//! backend traits: a wallet backend reads balances/heights and builds unproven PCZTs, and a store
//! persists the engine's run/transaction/note state. All migration logic lives here; the backends
//! supply only data and I/O. It covers the software-signing path, where the platform supplies a
//! [`UnifiedSpendingKey`] directly, and the external-signer (hardware wallet) path, which stages
//! proven-but-unsigned PCZTs and accepts the device's signatures back.

use std::collections::{BTreeMap, BTreeSet};

use rand::rngs::OsRng;
use uuid::Uuid;
use zcash_keys::keys::UnifiedSpendingKey;
use zcash_protocol::TxId;
use zcash_protocol::consensus::BlockHeight;
use zcash_protocol::value::Zatoshis;

use crate::error::{InvalidStateError, MigrationError};
use crate::note_splitting::{
    CanonicalPowerOfTen, DenominationStrategy, FeePolicy, MIGRATION_MAX_PREPARED_NOTES_PER_RUN,
    NoteSplitPlan, RESIDUAL_MIGRATION_MIN_ZATOSHI, Zip317FeePolicy, plan_note_split,
};
use crate::pipeline::{self, SignedPcztOutcome};
use crate::scheduling;
use crate::state::{self, Phase};
use crate::store::{
    MigrationStore, NewRun, NoteSplitTxRow, PreparedNote, RunRow, ScheduledTransferRow, StagedKind,
    StagedPczt,
};
use crate::types::{
    AttentionReason, MigrationProgress, MigrationSchedule, MigrationState, NoteSplitProposal,
    PreparedTransfer, SignedTransferPczt, TransferId, TransferProposal, TransferResult,
    UnsignedTransferPczt,
};
use crate::wallet::{NoteRef, SpentNote, WalletMigrationBackend};

/// ZIP-317 single-action fee estimate (zatoshi) used to seed note-split planning; the actual fee is
/// determined by the wallet backend when it builds the split.
const FEE_ESTIMATE_ZATOSHI: u64 = 10_000;
/// The ZIP-317 marginal fee per logical action, in zatoshi.
const MARGINAL_FEE_ZATOSHI: u64 = 5_000;
/// The ZIP-317 grace: the fee never drops below this many actions.
const GRACE_ACTIONS: u64 = 2;
/// The single staging id used for the note-split PCZT: one staged split per account/network.
const SPLIT_STAGING_ID: &str = "split";

// ----- external-signer staging metadata (versioned text, no serde) -----
//
// The external-signer flow stages a proven-but-unsigned PCZT and must remember, alongside it,
// whatever the store step needs to persist the run once the device returns signatures. Each is
// hand-rolled into a compact, versioned text encoding written to the staging row's metadata column.
// Both encodings carry a `v1;` prefix. Decoding is strict: this column is engine-internal, never
// user input, so a malformed value is a pipeline error rather than a silent default.

/// What [`MigrationContext::create_unsigned_note_split_pczt`] records alongside the staged split
/// PCZT so [`MigrationContext::store_signed_note_split_pczt`] can persist the run like the
/// software-signing path: the planned per-note output values and the `(output_index, value)` of
/// each prepared migration note.
struct SplitStagingMetadata {
    output_notes: Vec<u64>,
    placed_outputs: Vec<(u32, u64)>,
}

/// Encodes [`SplitStagingMetadata`] as `v1;notes=<u64 csv>;placed=<u32:u64 csv>`. Parsed by
/// [`parse_split_staging`].
fn encode_split_staging(meta: &SplitStagingMetadata) -> String {
    let notes = meta
        .output_notes
        .iter()
        .map(u64::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let placed = meta
        .placed_outputs
        .iter()
        .map(|(i, v)| format!("{i}:{v}"))
        .collect::<Vec<_>>()
        .join(",");
    format!("v1;notes={notes};placed={placed}")
}

/// Parses the format [`encode_split_staging`] writes, returning [`MigrationError::Pipeline`] on any
/// malformed input.
fn parse_split_staging(text: &str) -> Result<SplitStagingMetadata, MigrationError> {
    let err = || MigrationError::Pipeline(format!("decode split staging metadata: {text:?}"));
    let mut fields = text.split(';');
    if fields.next() != Some("v1") {
        return Err(err());
    }
    let notes = fields
        .next()
        .and_then(|s| s.strip_prefix("notes="))
        .ok_or_else(err)?;
    let placed = fields
        .next()
        .and_then(|s| s.strip_prefix("placed="))
        .ok_or_else(err)?;
    if fields.next().is_some() {
        return Err(err());
    }
    Ok(SplitStagingMetadata {
        output_notes: parse_u64_csv(notes).ok_or_else(err)?,
        placed_outputs: parse_placed_csv(placed).ok_or_else(err)?,
    })
}

/// Parses a comma-separated list of `u64` (an empty string is the empty list).
fn parse_u64_csv(s: &str) -> Option<Vec<u64>> {
    if s.is_empty() {
        return Some(Vec::new());
    }
    s.split(',').map(|p| p.parse::<u64>().ok()).collect()
}

/// Parses a comma-separated list of `output_index:value` (`u32:u64`) pairs (empty is empty list).
fn parse_placed_csv(s: &str) -> Option<Vec<(u32, u64)>> {
    if s.is_empty() {
        return Some(Vec::new());
    }
    s.split(',')
        .map(|pair| {
            let (i, v) = pair.split_once(':')?;
            Some((i.parse::<u32>().ok()?, v.parse::<u64>().ok()?))
        })
        .collect()
}

/// What [`MigrationContext::create_unsigned_transfer_pczts`] records alongside each staged transfer
/// PCZT so [`MigrationContext::store_signed_schedule_pczts`] can rebuild the transfer row without
/// re-running note selection: the schedule transfer's heights and crossing value. The fee and
/// selected-note triple are not carried (the external-signer store step no longer holds the input
/// data they come from); those informational columns are recorded as zero/empty.
struct TransferStagingMetadata {
    anchor_height: u32,
    next_executable_after_height: u32,
    expiry_height: u32,
    value_zatoshi: u64,
}

/// Encodes [`TransferStagingMetadata`] as `v1;anchor=<u32>;send=<u32>;expiry=<u32>;value=<u64>`.
/// Parsed by [`parse_transfer_staging`].
fn encode_transfer_staging(meta: &TransferStagingMetadata) -> String {
    format!(
        "v1;anchor={};send={};expiry={};value={}",
        meta.anchor_height,
        meta.next_executable_after_height,
        meta.expiry_height,
        meta.value_zatoshi,
    )
}

/// Parses the format [`encode_transfer_staging`] writes, returning [`MigrationError::Pipeline`] on
/// any malformed input.
fn parse_transfer_staging(text: &str) -> Result<TransferStagingMetadata, MigrationError> {
    let err = || MigrationError::Pipeline(format!("decode transfer staging metadata: {text:?}"));
    let mut fields = text.split(';');
    if fields.next() != Some("v1") {
        return Err(err());
    }
    let anchor = parse_kv(fields.next(), "anchor=").ok_or_else(err)?;
    let send = parse_kv(fields.next(), "send=").ok_or_else(err)?;
    let expiry = parse_kv(fields.next(), "expiry=").ok_or_else(err)?;
    let value = parse_kv(fields.next(), "value=").ok_or_else(err)?;
    if fields.next().is_some() {
        return Err(err());
    }
    Ok(TransferStagingMetadata {
        anchor_height: anchor,
        next_executable_after_height: send,
        expiry_height: expiry,
        value_zatoshi: value,
    })
}

/// Strips `key` from `field` and parses the remainder as `T` (both must succeed).
fn parse_kv<T: std::str::FromStr>(field: Option<&str>, key: &str) -> Option<T> {
    field?.strip_prefix(key)?.parse::<T>().ok()
}

/// Builds the [`ScheduledTransferRow`] for a software-signed transfer from its proposal, spent note,
/// and finalized outcome. The fee is `spent_note.value - crossing_value` (for a self-funding note
/// this is exactly the fee buffer); the selected-note triple records the note the transfer spends.
fn scheduled_transfer_row(
    t: &TransferProposal,
    spent_note: &SpentNote,
    signed: &SignedPcztOutcome,
) -> ScheduledTransferRow {
    let crossing_value = u64::from(t.amount());
    ScheduledTransferRow::from_parts(
        signed.txid().to_string(),
        signed.pczt_bytes().to_vec(),
        u32::from(t.anchor_height()),
        u32::from(t.next_executable_after_height()),
        u32::from(t.next_executable_after_height()),
        u32::from(t.expiry_height()),
        crossing_value,
        spent_note.value().saturating_sub(crossing_value),
        spent_note.txid().to_string(),
        spent_note.output_index(),
        spent_note.value(),
        "scheduled".to_string(),
        "{}".to_string(),
    )
}

/// Rebuilds the [`ScheduledTransferRow`] for an externally signed transfer from its staged metadata
/// and the combined (device-signed) outcome. The fee and selected-note triple are recorded as
/// zero/empty (see [`TransferStagingMetadata`]).
fn staged_transfer_row(
    meta: &TransferStagingMetadata,
    combined: &SignedPcztOutcome,
) -> ScheduledTransferRow {
    ScheduledTransferRow::from_parts(
        combined.txid().to_string(),
        combined.pczt_bytes().to_vec(),
        meta.anchor_height,
        meta.next_executable_after_height,
        meta.next_executable_after_height,
        meta.expiry_height,
        meta.value_zatoshi,
        0,
        String::new(),
        0,
        0,
        "scheduled".to_string(),
        "{}".to_string(),
    )
}

/// The public, synchronous migration engine, generic over a wallet backend and a store backend.
///
/// The engine holds the two backend implementations plus the account and network they operate on.
/// A wallet backend reads balances/heights and builds unproven PCZTs; a store persists the engine's
/// run/transaction/note state. The engine performs all planning, scheduling, and the pure PCZT
/// prove/sign/finalize steps itself.
pub struct MigrationContext<W, S> {
    wallet: W,
    store: S,
    account_uuid: String,
    network: String,
}

impl<W: WalletMigrationBackend, S: MigrationStore> MigrationContext<W, S> {
    /// Creates an engine bound to a wallet backend, a store backend, an account, and a network,
    /// ensuring the store's own state exists.
    ///
    /// # Errors
    ///
    /// Returns [`MigrationError::Store`] if the store cannot be initialised.
    pub fn new(
        wallet: W,
        store: S,
        account_uuid: String,
        network: String,
    ) -> Result<Self, MigrationError> {
        let mut ctx = Self {
            wallet,
            store,
            account_uuid,
            network,
        };
        ctx.store.init().map_err(store_err)?;
        Ok(ctx)
    }

    // ----- internal helpers -----

    /// A string recorded alongside each run; no query reads it back today. The engine has no wallet
    /// database path (that is a backend detail), so this is left empty.
    fn db_fingerprint(&self) -> String {
        String::new()
    }

    fn orchard_spendable(&self) -> Result<u64, MigrationError> {
        Ok(self
            .wallet
            .pool_balances()
            .map_err(backend_err)?
            .orchard_spendable())
    }

    fn active_run(&self) -> Result<Option<RunRow>, MigrationError> {
        self.store
            .active_run(&self.account_uuid, &self.network)
            .map_err(store_err)
    }

    /// The account's cross-run locked notes as [`NoteRef`]s, optionally excluding one run's own
    /// notes (the run whose transfers exist to spend them).
    fn reserved_note_refs(
        &self,
        exclude_run_id: Option<&str>,
    ) -> Result<Vec<NoteRef>, MigrationError> {
        self.store
            .locked_note_refs(&self.account_uuid, exclude_run_id)
            .map_err(store_err)?
            .into_iter()
            .map(|(txid_hex, output_index)| {
                Ok(NoteRef::from_parts(
                    parse_txid_hex(&txid_hex)?,
                    output_index,
                ))
            })
            .collect()
    }

    /// Reconstructs the insert parameters for an already-persisted run, preserving its phase,
    /// prep-txid, and target values.
    fn new_run_from_row(&self, row: &RunRow) -> NewRun {
        NewRun::from_parts(
            row.run_id().to_string(),
            row.account_uuid().to_string(),
            row.network().to_string(),
            self.db_fingerprint(),
            Phase::parse(row.phase()).unwrap_or(Phase::ReadyToMigrate),
            row.prep_txid().map(str::to_string),
            row.target_values().to_vec(),
        )
    }

    fn progress_for_run(&self, run_id: &str) -> Result<MigrationProgress, MigrationError> {
        let totals = self.store.transfer_totals(run_id).map_err(store_err)?;
        let remaining_orchard = Zatoshis::const_from_u64(self.orchard_spendable()?);
        let next_transfer_ready_at_height = self
            .store
            .next_scheduled_send_height(run_id)
            .map_err(store_err)?
            .map(BlockHeight::from_u32);
        Ok(MigrationProgress::from_parts(
            totals.confirmed(),
            totals.total(),
            remaining_orchard,
            next_transfer_ready_at_height,
        ))
    }

    // ----- state -----

    /// The current migration state. The app calls this on launch and after every operation.
    ///
    /// This is the reconciliation hub: it (1) marks broadcasted transfers confirmed once the wallet
    /// has scanned them as mined, (2) advances a note split to [`MigrationState::ReadyToPropose`]
    /// once its prep transaction has mined and produced spendable notes, and (3) persists overall
    /// completion once every scheduled transfer is confirmed and the Orchard balance has fully
    /// drained into Ironwood.
    ///
    /// # Errors
    ///
    /// Returns [`MigrationError::InvalidState`] if the run's phase is unrecognised, and
    /// [`MigrationError::Backend`]/[`MigrationError::Store`] on backend access errors.
    pub fn migration_state(&mut self) -> Result<MigrationState, MigrationError> {
        let Some(run) = self.active_run()? else {
            return Ok(MigrationState::NotStarted);
        };
        let run_id = run.run_id().to_string();
        let phase = Phase::parse(run.phase()).ok_or_else(|| {
            MigrationError::InvalidState(InvalidStateError::UnknownPhase(run.phase().to_string()))
        })?;
        let last_error = run.last_error().map(str::to_string);
        drop(run);

        if matches!(
            phase,
            Phase::BroadcastScheduled | Phase::Broadcasting | Phase::WaitingMigrationConfirmations
        ) {
            let broadcasted = self.store.broadcasted_txids(&run_id).map_err(store_err)?;
            for txid_hex in broadcasted {
                let txid = parse_txid_hex(&txid_hex)?;
                if self.wallet.is_tx_mined(txid).map_err(backend_err)? {
                    self.store
                        .mark_transfer_status(&txid_hex, "confirmed")
                        .map_err(store_err)?;
                }
            }
        }
        let progress = self.progress_for_run(&run_id)?;
        let attention = last_error
            .as_deref()
            .map(attention_from_error)
            .filter(|_| matches!(phase, Phase::FailedRecoverable | Phase::FailedTerminal));
        let mapped = state::to_state(phase, progress, attention);

        if matches!(
            phase,
            Phase::PreparingDenominations | Phase::WaitingDenomConfirmations
        ) {
            if let Some(prep) = self.store.note_split_tx(&run_id).map_err(store_err)? {
                let txid = parse_txid_hex(prep.txid_hex())?;
                if self.wallet.is_tx_mined(txid).map_err(backend_err)? {
                    let spendable = self
                        .wallet
                        .pool_balances()
                        .map_err(backend_err)?
                        .orchard_spendable();
                    if spendable > 0 {
                        self.store
                            .set_phase(&run_id, Phase::ReadyToMigrate, None)
                            .map_err(store_err)?;
                        return Ok(MigrationState::ReadyToPropose);
                    }
                }
            }
        }

        if let MigrationState::InProgress(p) = &mapped {
            if p.total_transfers() > 0 && p.completed_transfers() == p.total_transfers() {
                let balances = self.wallet.pool_balances().map_err(backend_err)?;
                if balances.orchard_spendable() == 0 && balances.ironwood_total() > 0 {
                    self.store
                        .set_phase(&run_id, Phase::Complete, None)
                        .map_err(store_err)?;
                    return Ok(MigrationState::Complete);
                }
            }
        }
        Ok(mapped)
    }

    /// Progress details, present only while a migration is in progress.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::migration_state`], which this delegates to.
    pub fn migration_progress(&mut self) -> Result<Option<MigrationProgress>, MigrationError> {
        match self.migration_state()? {
            MigrationState::InProgress(p) => Ok(Some(p)),
            _ => Ok(None),
        }
    }

    // ----- note splitting -----

    /// Whether the Orchard notes must be split before migration: there is spendable Orchard balance
    /// and no split has yet been prepared.
    ///
    /// # Errors
    ///
    /// Returns [`MigrationError::Backend`] if the balance cannot be read, and
    /// [`MigrationError::Store`] on a store access error.
    pub fn is_note_split_needed(&self) -> Result<bool, MigrationError> {
        let already_prepared = self
            .active_run()?
            .and_then(|r| Phase::parse(r.phase()))
            .map(|p| {
                !matches!(
                    p,
                    Phase::NoOrchardFunds
                        | Phase::WaitingForSpendableOrchard
                        | Phase::ReadyToPrepare
                )
            })
            .unwrap_or(false);
        if already_prepared {
            return Ok(false);
        }
        Ok(self.orchard_spendable()? > 0)
    }

    /// Computes the note split for the spendable Orchard balance: the self-funding output notes and
    /// the estimated split fee.
    ///
    /// The wallet backend exposes no spendable-note count, so the fee estimate here assumes a single
    /// spend; the actual fee is charged when the wallet builds the split at signing time.
    ///
    /// # Errors
    ///
    /// Returns [`MigrationError::Backend`] if the balance cannot be read, and
    /// [`MigrationError::Pipeline`] if the plan would exceed the per-run prepared-note limit.
    pub fn prepare_note_split(&self) -> Result<NoteSplitProposal, MigrationError> {
        let total = self
            .wallet
            .pool_balances()
            .map_err(backend_err)?
            .orchard_spendable();
        let (plan, fee_estimate) = converge_denomination_plan(total, 1);
        let output_values = plan
            .migration_outputs()
            .iter()
            .map(|&v| Zatoshis::const_from_u64(v))
            .collect();
        Ok(NoteSplitProposal::from_parts(
            output_values,
            Zatoshis::const_from_u64(fee_estimate),
        ))
    }

    /// Builds, signs (as a PCZT), and persists the note-split transaction, returning the serialized
    /// PCZT for the platform to broadcast.
    ///
    /// The transaction is built and signed before any run is persisted, then the run, its note-split
    /// transaction, and its locked prepared notes are committed together. A signing failure leaves
    /// the store untouched.
    ///
    /// # Errors
    ///
    /// Returns [`MigrationError::InvalidState`] if `proposal` has no outputs,
    /// [`MigrationError::Backend`]/[`MigrationError::Pipeline`] if the split cannot be built or
    /// signed, and [`MigrationError::Store`] if the run cannot be persisted.
    pub fn sign_note_split(
        &mut self,
        proposal: &NoteSplitProposal,
        usk: &UnifiedSpendingKey,
    ) -> Result<PreparedTransfer, MigrationError> {
        if proposal.output_values().is_empty() {
            return Err(MigrationError::InvalidState(
                InvalidStateError::NotApplicable("note split proposal has no outputs"),
            ));
        }
        let run_id = new_run_id();
        let target_values: Vec<u64> = proposal
            .output_values()
            .iter()
            .map(|&v| u64::from(v))
            .collect();
        let reserved = self.reserved_note_refs(None)?;
        let (pczt, split_outputs) = self
            .wallet
            .build_note_split_pczt(&target_values, &reserved)
            .map_err(backend_err)?;
        let signed = pipeline::prove_sign_finalize(pczt, usk)?;
        let txid = signed.txid();
        let txid_hex = txid.to_string();
        let prepared = prepared_notes(&txid_hex, split_outputs.migration_notes());
        let pczt_bytes = signed.into_pczt_bytes();
        let new_run = NewRun::from_parts(
            run_id.clone(),
            self.account_uuid.clone(),
            self.network.clone(),
            self.db_fingerprint(),
            Phase::PreparingDenominations,
            None,
            target_values,
        );
        let note_split_tx = NoteSplitTxRow::from_parts(
            run_id.clone(),
            txid_hex,
            pczt_bytes.clone(),
            "pending".to_string(),
        );
        self.store
            .commit_note_split(&new_run, &note_split_tx, &prepared, None)
            .map_err(store_err)?;
        Ok(PreparedTransfer::from_parts(
            TransferId::for_prep(&run_id),
            txid,
            pczt_bytes,
        ))
    }

    // ----- external signer (hardware wallet) -----

    /// Builds the note-split transaction as an unsigned PCZT for an external signer: plans the split
    /// for the current spendable Orchard balance, builds and proves it, stages the proven original,
    /// and returns the unsigned PCZT to route to the signing device. No run is created until the
    /// signed split is stored.
    ///
    /// # Errors
    ///
    /// Returns [`MigrationError::Backend`]/[`MigrationError::Pipeline`] if the split cannot be
    /// planned, built, or proven, and [`MigrationError::Store`] if the proven original cannot be
    /// staged.
    pub fn create_unsigned_note_split_pczt(&mut self) -> Result<Vec<u8>, MigrationError> {
        let proposal = self.prepare_note_split()?;
        let output_notes: Vec<u64> = proposal
            .output_values()
            .iter()
            .map(|&v| u64::from(v))
            .collect();
        let reserved = self.reserved_note_refs(None)?;
        let (pczt, split_outputs) = self
            .wallet
            .build_note_split_pczt(&output_notes, &reserved)
            .map_err(backend_err)?;
        let placed_outputs = split_outputs.migration_notes().to_vec();
        let unsigned = pczt.clone().serialize().map_err(|e| {
            MigrationError::Pipeline(format!("serialize unsigned split pczt: {e:?}"))
        })?;
        let proven = pipeline::prove_pczt(pczt)?;
        let proven_bytes = proven
            .serialize()
            .map_err(|e| MigrationError::Pipeline(format!("serialize proven split pczt: {e:?}")))?;
        let metadata = SplitStagingMetadata {
            output_notes,
            placed_outputs,
        };
        let staged = StagedPczt::from_parts(
            SPLIT_STAGING_ID.to_string(),
            proven_bytes,
            encode_split_staging(&metadata),
        );
        self.store
            .upsert_staged_pczt(
                &self.account_uuid,
                &self.network,
                StagedKind::Split,
                &staged,
            )
            .map_err(store_err)?;
        Ok(unsigned)
    }

    /// Accepts the externally signed note-split PCZT: merges the device's signatures into the staged
    /// proven original, verifies and finalizes it, and persists the run like [`Self::sign_note_split`].
    ///
    /// # Errors
    ///
    /// Returns [`MigrationError::InvalidState`] if there is no staged note-split PCZT,
    /// [`MigrationError::Pipeline`] if the staged metadata or PCZTs cannot be decoded/combined, and
    /// [`MigrationError::Store`] if the run cannot be persisted.
    pub fn store_signed_note_split_pczt(
        &mut self,
        signed_pczt: &[u8],
    ) -> Result<PreparedTransfer, MigrationError> {
        let staged = self
            .store
            .staged_pczts(&self.account_uuid, &self.network, StagedKind::Split)
            .map_err(store_err)?;
        let Some(staged) = staged.into_iter().next() else {
            return Err(MigrationError::InvalidState(
                InvalidStateError::NotApplicable("no staged note-split PCZT to store"),
            ));
        };
        let metadata = parse_split_staging(staged.metadata_json())?;
        let signed = pipeline::combine_signed_pczt(staged.raw_pczt(), signed_pczt)?;
        let txid = signed.txid();
        let txid_hex = txid.to_string();
        let prepared = prepared_notes(&txid_hex, &metadata.placed_outputs);
        let run_id = new_run_id();
        let pczt_bytes = signed.into_pczt_bytes();
        let new_run = NewRun::from_parts(
            run_id.clone(),
            self.account_uuid.clone(),
            self.network.clone(),
            self.db_fingerprint(),
            Phase::PreparingDenominations,
            None,
            metadata.output_notes,
        );
        let note_split_tx = NoteSplitTxRow::from_parts(
            run_id.clone(),
            txid_hex,
            pczt_bytes.clone(),
            "pending".to_string(),
        );
        self.store
            .commit_note_split(&new_run, &note_split_tx, &prepared, Some(StagedKind::Split))
            .map_err(store_err)?;
        Ok(PreparedTransfer::from_parts(
            TransferId::for_prep(&run_id),
            txid,
            pczt_bytes,
        ))
    }

    /// Builds one unsigned PCZT per transfer of `schedule` for an external signer, each proved and
    /// staged. Returns the `(transfer id, unsigned PCZT)` pairs to route to the device; the pairing
    /// must survive to [`Self::store_signed_schedule_pczts`], which matches by id.
    ///
    /// # Errors
    ///
    /// Returns [`MigrationError::InvalidState`] if `schedule` is empty or has duplicate ids, and
    /// [`MigrationError::Backend`]/[`MigrationError::Pipeline`]/[`MigrationError::Store`] if a
    /// transfer cannot be built, proven, or staged.
    pub fn create_unsigned_transfer_pczts(
        &mut self,
        schedule: &MigrationSchedule,
    ) -> Result<Vec<UnsignedTransferPczt>, MigrationError> {
        if schedule.is_empty() {
            return Err(MigrationError::InvalidState(
                InvalidStateError::NotApplicable("cannot build PCZTs for an empty schedule"),
            ));
        }
        let mut seen = BTreeSet::new();
        if !schedule.transfers().iter().all(|t| seen.insert(t.id())) {
            return Err(MigrationError::InvalidState(
                InvalidStateError::NotApplicable("schedule contains duplicate transfer ids"),
            ));
        }
        let (target, _anchor) = self
            .wallet
            .target_and_anchor_heights()
            .map_err(backend_err)?;
        let own_run_id = self.active_run()?.map(|r| r.run_id().to_string());
        let mut reserved = self.reserved_note_refs(own_run_id.as_deref())?;
        self.store
            .clear_staged_pczts(&self.account_uuid, &self.network, StagedKind::Transfer)
            .map_err(store_err)?;
        let mut pairs = Vec::with_capacity(schedule.transfers().len());
        for t in schedule.transfers() {
            let build = self
                .wallet
                .build_transfer_pczt(
                    u64::from(t.amount()),
                    &reserved,
                    target,
                    u32::from(t.expiry_height()),
                )
                .map_err(backend_err)?
                .ok_or_else(|| {
                    MigrationError::Pipeline(format!("no spendable note for transfer {}", t.id()))
                })?;
            let (pczt, spent_note) = build.into_parts();
            reserved.push(NoteRef::from_parts(
                spent_note.txid(),
                spent_note.output_index(),
            ));
            let unsigned = pczt.clone().serialize().map_err(|e| {
                MigrationError::Pipeline(format!("serialize unsigned transfer pczt: {e:?}"))
            })?;
            let proven = pipeline::prove_pczt(pczt)?;
            let proven_bytes = proven.serialize().map_err(|e| {
                MigrationError::Pipeline(format!("serialize proven transfer pczt: {e:?}"))
            })?;
            let metadata = TransferStagingMetadata {
                anchor_height: u32::from(t.anchor_height()),
                next_executable_after_height: u32::from(t.next_executable_after_height()),
                expiry_height: u32::from(t.expiry_height()),
                value_zatoshi: u64::from(t.amount()),
            };
            let staged = StagedPczt::from_parts(
                t.id().as_str().to_string(),
                proven_bytes,
                encode_transfer_staging(&metadata),
            );
            self.store
                .upsert_staged_pczt(
                    &self.account_uuid,
                    &self.network,
                    StagedKind::Transfer,
                    &staged,
                )
                .map_err(store_err)?;
            pairs.push(UnsignedTransferPczt::from_parts(t.id().clone(), unsigned));
        }
        Ok(pairs)
    }

    /// Accepts the full set of externally signed transfer PCZTs, all-or-nothing. Every staged
    /// transfer must be matched by exactly one signed PCZT (by id); each pair is merged and verified;
    /// only if every transfer succeeds is the schedule persisted.
    ///
    /// # Errors
    ///
    /// Returns [`MigrationError::InvalidState`] if the set is empty, has no staged counterpart, has
    /// duplicate ids, or does not match the staged set; [`MigrationError::Pipeline`] if a PCZT cannot
    /// be decoded/combined; and [`MigrationError::Store`] if the schedule cannot be persisted.
    pub fn store_signed_schedule_pczts(
        &mut self,
        signed: &[SignedTransferPczt],
    ) -> Result<(), MigrationError> {
        if signed.is_empty() {
            return Err(MigrationError::InvalidState(
                InvalidStateError::NotApplicable("no signed transfer PCZTs provided"),
            ));
        }
        let staged = self
            .store
            .staged_pczts(&self.account_uuid, &self.network, StagedKind::Transfer)
            .map_err(store_err)?;
        if staged.is_empty() {
            return Err(MigrationError::InvalidState(
                InvalidStateError::NotApplicable("no staged transfer PCZTs to store"),
            ));
        }
        let mut by_id = BTreeMap::new();
        for pair in signed {
            if by_id
                .insert(pair.id().as_str(), pair.pczt_bytes())
                .is_some()
            {
                return Err(MigrationError::InvalidState(
                    InvalidStateError::NotApplicable("duplicate transfer id in signed PCZT set"),
                ));
            }
        }
        if by_id.len() != staged.len() {
            return Err(MigrationError::InvalidState(
                InvalidStateError::NotApplicable(
                    "signed transfer PCZTs do not match the staged set",
                ),
            ));
        }
        let mut rows = Vec::with_capacity(staged.len());
        for st in &staged {
            let Some(signed_bytes) = by_id.get(st.staging_id()) else {
                return Err(MigrationError::InvalidState(
                    InvalidStateError::NotApplicable(
                        "signed transfer PCZTs do not match the staged set",
                    ),
                ));
            };
            let metadata = parse_transfer_staging(st.metadata_json())?;
            let combined = pipeline::combine_signed_pczt(st.raw_pczt(), signed_bytes)?;
            rows.push(staged_transfer_row(&metadata, &combined));
        }
        let existing = self.active_run()?;
        let new_run = match &existing {
            Some(r) => self.new_run_from_row(r),
            None => NewRun::from_parts(
                new_run_id(),
                self.account_uuid.clone(),
                self.network.clone(),
                self.db_fingerprint(),
                Phase::ReadyToMigrate,
                None,
                Vec::new(),
            ),
        };
        self.store
            .commit_transfer_schedule(
                &new_run,
                &rows,
                Phase::BroadcastScheduled,
                Some(StagedKind::Transfer),
            )
            .map_err(store_err)?;
        Ok(())
    }

    // ----- migration proposal -----

    /// The leftover Orchard balance that a migration schedule would not cross, reported only when it
    /// is large enough to be worth offering the user a choice about (at or above
    /// `RESIDUAL_MIGRATION_MIN_ZATOSHI`). Smaller leftovers are dust and are never reported.
    ///
    /// # Errors
    ///
    /// Returns [`MigrationError::Backend`] if the balance cannot be read, and
    /// [`MigrationError::Pipeline`] if the plan would exceed the per-run prepared-note limit.
    pub fn residual_after_migration(&self) -> Result<Option<Zatoshis>, MigrationError> {
        let total = self
            .wallet
            .pool_balances()
            .map_err(backend_err)?
            .orchard_spendable();
        // Deterministic estimate: the canonical strategy keeps the reported residual stable across
        // calls (the randomized split strategy would vary it).
        let plan = CanonicalPowerOfTen::zip_draft().plan(total, 0, &mut OsRng);
        Ok(plan
            .change()
            .filter(|&v| v >= RESIDUAL_MIGRATION_MIN_ZATOSHI)
            .map(Zatoshis::const_from_u64))
    }

    /// Generates the full migration schedule for the spendable Orchard balance. Each transfer's
    /// `amount` is the value that crosses the turnstile (the pre-split note pays its own fee).
    ///
    /// When `include_residual` is `true` and the balance leaves a residual worth offering (see
    /// [`Self::residual_after_migration`]), one further transfer for that amount is appended.
    ///
    /// # Errors
    ///
    /// Returns [`MigrationError::Backend`] if the heights or balance cannot be read, and
    /// [`MigrationError::Pipeline`] if the plan would exceed the per-run prepared-note limit.
    pub fn propose_migration_transfers(
        &self,
        include_residual: bool,
    ) -> Result<MigrationSchedule, MigrationError> {
        let (target, anchor) = self
            .wallet
            .target_and_anchor_heights()
            .map_err(backend_err)?;
        let buffer = Zip317FeePolicy.transfer_fee_buffer_zatoshi();
        // Read the crossing values from the split's actual, persisted prepared notes rather than
        // re-planning: the randomized split strategy would not reproduce the same notes. Each stored
        // `target_value` is a self-funding note (crossing value plus its transfer-fee buffer), so the
        // crossing value is `target_value - buffer`. Before any run exists (rare pre-split path), fall
        // back to planning the current spendable balance.
        let mut crossing_values = match self.active_run()? {
            Some(run) => run
                .target_values()
                .iter()
                .map(|&v| v.saturating_sub(buffer))
                .collect::<Vec<u64>>(),
            None => {
                let total = self
                    .wallet
                    .pool_balances()
                    .map_err(backend_err)?
                    .orchard_spendable();
                plan_note_split(total, 0, &mut OsRng)
                    .crossing_values()
                    .to_vec()
            }
        };
        if include_residual {
            if let Some(residual) = self.residual_after_migration()? {
                // Net out the fee buffer so the scheduled crossing value is what lands in the
                // destination pool; this matches the residual self-funding note the split minted.
                crossing_values.push(u64::from(residual).saturating_sub(buffer));
            }
        }
        let run_id = new_run_id();
        Ok(scheduling::build_schedule(
            &mut OsRng,
            &run_id,
            &crossing_values,
            target,
            anchor,
            0,
        ))
    }

    /// Proposes the immediate (single-transaction) migration: sweep the entire spendable Orchard
    /// balance into one Ironwood output. Returns an empty schedule when nothing is migratable.
    ///
    /// # Errors
    ///
    /// Returns [`MigrationError::Backend`] if the heights or sweep amount cannot be read.
    pub fn propose_immediate_migration_transfers(
        &self,
    ) -> Result<MigrationSchedule, MigrationError> {
        let (target, anchor) = self
            .wallet
            .target_and_anchor_heights()
            .map_err(backend_err)?;
        let crossing = self.wallet.sweep_crossing_value().map_err(backend_err)?;
        let run_id = new_run_id();
        let amounts = crossing.map(|value| vec![value]).unwrap_or_default();
        Ok(scheduling::build_schedule(
            &mut OsRng, &run_id, &amounts, target, anchor, 0,
        ))
    }

    /// Pre-signs and persists every transfer in the schedule at the schedule's shared natural anchor,
    /// which is pinned for the duration of signing. Reuses the account's active run if one exists,
    /// otherwise starts a new one. Persists all-or-nothing: a signing failure leaves the store
    /// untouched.
    ///
    /// # Errors
    ///
    /// Returns [`MigrationError::InvalidState`] if `schedule` is empty, and
    /// [`MigrationError::Backend`]/[`MigrationError::Pipeline`]/[`MigrationError::Store`] if a
    /// transfer cannot be built, signed, or persisted.
    pub fn sign_and_store_migration_schedule(
        &mut self,
        schedule: &MigrationSchedule,
        usk: &UnifiedSpendingKey,
    ) -> Result<(), MigrationError> {
        if schedule.is_empty() {
            return Err(MigrationError::InvalidState(
                InvalidStateError::NotApplicable("cannot sign an empty schedule"),
            ));
        }
        let existing = self.active_run()?;
        let pinned_anchor = schedule
            .transfers()
            .first()
            .map(|t| u32::from(t.anchor_height()));
        if let Some(anchor) = pinned_anchor {
            self.wallet.retain_anchor(anchor).map_err(backend_err)?;
        }
        let result = self.sign_all_transfers(schedule, usk, existing.as_ref());
        if let Some(anchor) = pinned_anchor {
            let _ = self.wallet.release_retained_anchors_below(anchor + 1);
        }
        let rows = result?;
        let new_run = match &existing {
            Some(r) => self.new_run_from_row(r),
            None => NewRun::from_parts(
                new_run_id(),
                self.account_uuid.clone(),
                self.network.clone(),
                self.db_fingerprint(),
                Phase::ReadyToMigrate,
                None,
                Vec::new(),
            ),
        };
        self.store
            .commit_transfer_schedule(&new_run, &rows, Phase::BroadcastScheduled, None)
            .map_err(store_err)?;
        Ok(())
    }

    /// Builds and signs every transfer, returning the rows to persist. The anchor is pinned by the
    /// caller.
    fn sign_all_transfers(
        &mut self,
        schedule: &MigrationSchedule,
        usk: &UnifiedSpendingKey,
        existing: Option<&RunRow>,
    ) -> Result<Vec<ScheduledTransferRow>, MigrationError> {
        let (target, _anchor) = self
            .wallet
            .target_and_anchor_heights()
            .map_err(backend_err)?;
        let own_run_id = existing.map(|r| r.run_id().to_string());
        let mut reserved = self.reserved_note_refs(own_run_id.as_deref())?;
        let mut rows = Vec::with_capacity(schedule.transfers().len());
        for t in schedule.transfers() {
            let build = self
                .wallet
                .build_transfer_pczt(
                    u64::from(t.amount()),
                    &reserved,
                    target,
                    u32::from(t.expiry_height()),
                )
                .map_err(backend_err)?
                .ok_or_else(|| {
                    MigrationError::Pipeline(format!("no spendable note for transfer {}", t.id()))
                })?;
            let (pczt, spent_note) = build.into_parts();
            reserved.push(NoteRef::from_parts(
                spent_note.txid(),
                spent_note.output_index(),
            ));
            let signed = pipeline::prove_sign_finalize(pczt, usk)?;
            rows.push(scheduled_transfer_row(t, &spent_note, &signed));
        }
        Ok(rows)
    }

    // ----- background execution -----

    /// Whether a sync is required before the next transfer. Each transfer spends a whole pre-split
    /// note and produces no Orchard change, so this is always `false` today.
    ///
    /// # Errors
    ///
    /// Never returns an error.
    pub fn is_sync_required_before_next_transfer(&self) -> Result<bool, MigrationError> {
        Ok(false)
    }

    /// The next height-due pre-signed transfer, or `None`. The platform extracts the transaction
    /// from [`PreparedTransfer::pczt_bytes`], broadcasts it, then calls
    /// [`Self::record_transfer_result`].
    ///
    /// # Errors
    ///
    /// Returns [`MigrationError::Backend`] if the target height cannot be read, and
    /// [`MigrationError::Store`]/[`MigrationError::Pipeline`] on store or decode errors.
    pub fn next_due_transfer(&self) -> Result<Option<PreparedTransfer>, MigrationError> {
        let Some(run) = self.active_run()? else {
            return Ok(None);
        };
        if let Some(prep) = self.store.note_split_tx(run.run_id()).map_err(store_err)? {
            if prep.status() == "pending" {
                let txid = parse_txid_hex(prep.txid_hex())?;
                return Ok(Some(PreparedTransfer::from_parts(
                    TransferId::for_prep(run.run_id()),
                    txid,
                    prep.raw_pczt().to_vec(),
                )));
            }
        }
        let (target, _anchor) = self
            .wallet
            .target_and_anchor_heights()
            .map_err(backend_err)?;
        let Some(tx) = self
            .store
            .next_due_transfer(run.run_id(), target)
            .map_err(store_err)?
        else {
            return Ok(None);
        };
        let txid = parse_txid_hex(tx.txid_hex())?;
        Ok(Some(PreparedTransfer::from_parts(
            TransferId::from_raw(tx.txid_hex().to_string()),
            txid,
            tx.raw_pczt().to_vec(),
        )))
    }

    /// Extracts the broadcast-ready consensus transaction bytes from a serialized signed PCZT.
    ///
    /// # Errors
    ///
    /// Returns [`MigrationError::Pipeline`] if the PCZT cannot be parsed, extracted, or encoded.
    pub fn extract_broadcast_tx(&self, pczt_bytes: &[u8]) -> Result<Vec<u8>, MigrationError> {
        pipeline::extract_broadcast_tx(pczt_bytes)
    }

    /// Re-proposes at a fresh anchor and re-signs the active run's scheduled transfers, replacing
    /// PCZTs whose anchor may have gone stale. Returns the number of transfers refreshed.
    ///
    /// # Errors
    ///
    /// Returns whatever [`Self::restart_current_migration_step`] and
    /// [`Self::sign_and_store_migration_schedule`] can return.
    pub fn refresh_stale_transfers(
        &mut self,
        usk: &UnifiedSpendingKey,
        include_residual: bool,
    ) -> Result<u32, MigrationError> {
        let schedule = self.restart_current_migration_step(include_residual)?;
        let count = schedule.transfers().len() as u32;
        self.sign_and_store_migration_schedule(&schedule, usk)?;
        Ok(count)
    }

    /// Records the platform's broadcast outcome, advancing the engine's state.
    ///
    /// A result for the note-split ("prep") transaction advances the split phase on success; other
    /// outcomes for it are no-ops. For an ordinary transfer, success marks its row broadcasted, a
    /// retryable network error leaves it scheduled, and `InvalidNote`/`Expired` park the run in a
    /// recoverable failure state.
    ///
    /// # Errors
    ///
    /// Returns [`MigrationError::InvalidState`] if there is no active run,
    /// [`MigrationError::Pipeline`] if a success references an unknown transfer, and
    /// [`MigrationError::Store`] on a store update error.
    pub fn record_transfer_result(
        &mut self,
        id: &TransferId,
        result: TransferResult,
    ) -> Result<(), MigrationError> {
        let Some(run) = self.active_run()? else {
            return Err(MigrationError::InvalidState(InvalidStateError::NoActiveRun));
        };
        let run_id = run.run_id().to_string();
        if id.is_prep() {
            if let TransferResult::Success(_) = result {
                self.store
                    .set_note_split_tx_status(&run_id, "broadcasted")
                    .map_err(store_err)?;
                self.store
                    .set_phase(&run_id, Phase::WaitingDenomConfirmations, None)
                    .map_err(store_err)?;
            }
            return Ok(());
        }
        match result {
            TransferResult::Success(txid) => {
                let updated = self
                    .store
                    .mark_transfer_status(&txid.to_string().to_lowercase(), "broadcasted")
                    .map_err(store_err)?;
                if updated == 0 {
                    return Err(MigrationError::Pipeline(format!(
                        "transfer result references unknown txid {txid}"
                    )));
                }
            }
            TransferResult::NetworkError { .. } => {}
            TransferResult::InvalidNote => {
                self.store
                    .set_phase(
                        &run_id,
                        Phase::FailedRecoverable,
                        Some(&format!("invalid note for transfer {id}")),
                    )
                    .map_err(store_err)?;
            }
            TransferResult::Expired => {
                self.store
                    .set_phase(
                        &run_id,
                        Phase::FailedRecoverable,
                        Some(&format!("transfer {id} expired")),
                    )
                    .map_err(store_err)?;
            }
        }
        Ok(())
    }

    // ----- on-launch reconciliation -----

    /// Whether any scheduled transfer is past its send height but not yet broadcast.
    ///
    /// # Errors
    ///
    /// Returns [`MigrationError::Backend`] if the target height cannot be read, and
    /// [`MigrationError::Store`] on a store access error.
    pub fn has_overdue_transfers(&self) -> Result<bool, MigrationError> {
        let Some(run) = self.active_run()? else {
            return Ok(false);
        };
        let (target, _anchor) = self
            .wallet
            .target_and_anchor_heights()
            .map_err(backend_err)?;
        self.store
            .has_due_transfer(run.run_id(), target)
            .map_err(store_err)
    }

    /// Whether the migration is in an invalid state: spendable Orchard remains but no scheduled
    /// transfer covers it. Only meaningful once a schedule should exist (from `BroadcastScheduled`
    /// onward).
    ///
    /// # Errors
    ///
    /// Returns [`MigrationError::Backend`] if the balance must be checked and cannot be read, and
    /// [`MigrationError::Store`] on a store access error.
    pub fn has_invalid_transfers(&self) -> Result<bool, MigrationError> {
        let Some(run) = self.active_run()? else {
            return Ok(false);
        };
        let pre_schedule = Phase::parse(run.phase()).is_some_and(|p| {
            matches!(
                p,
                Phase::NoOrchardFunds
                    | Phase::WaitingForSpendableOrchard
                    | Phase::ReadyToPrepare
                    | Phase::PreparingDenominations
                    | Phase::WaitingDenomConfirmations
                    | Phase::ReadyToMigrate
            )
        });
        if pre_schedule {
            return Ok(false);
        }
        let totals = self
            .store
            .transfer_totals(run.run_id())
            .map_err(store_err)?;
        let nothing_queued = totals.scheduled() == 0 && totals.broadcasted() == 0;
        Ok(nothing_queued && self.orchard_spendable()? > 0)
    }

    // ----- recovery / lifecycle -----

    /// Re-evaluates the remaining spendable Orchard balance and returns a fresh schedule for it,
    /// clearing the active run's stale scheduled transfers.
    ///
    /// # Errors
    ///
    /// Returns [`MigrationError::Store`] if the stale transfers cannot be cleared, and whatever
    /// [`Self::propose_migration_transfers`] can return.
    pub fn restart_current_migration_step(
        &mut self,
        include_residual: bool,
    ) -> Result<MigrationSchedule, MigrationError> {
        if let Some(run) = self.active_run()? {
            let run_id = run.run_id().to_string();
            self.store
                .clear_scheduled_transfers(&run_id)
                .map_err(store_err)?;
        }
        self.propose_migration_transfers(include_residual)
    }
}

/// Maps `(output_index, value)` pairs to locked [`PreparedNote`]s for `txid_hex` (Orchard, version 2).
fn prepared_notes(txid_hex: &str, placed: &[(u32, u64)]) -> Vec<PreparedNote> {
    placed
        .iter()
        .map(|&(output_index, value)| {
            PreparedNote::from_parts(
                txid_hex.to_string(),
                output_index,
                value,
                2,
                None,
                "locked".to_string(),
            )
        })
        .collect()
}

/// Wraps a wallet-backend error as an opaque [`MigrationError::Backend`].
fn backend_err<E: core::fmt::Display>(e: E) -> MigrationError {
    MigrationError::Backend(e.to_string())
}

/// Wraps a store-backend error as an opaque [`MigrationError::Store`].
fn store_err<E: core::fmt::Display>(e: E) -> MigrationError {
    MigrationError::Store(e.to_string())
}

fn new_run_id() -> String {
    Uuid::new_v4().to_string()
}

/// The ZIP-317 fee for a transaction with `n_spends` spends and `n_changes` change outputs.
fn split_fee(n_spends: usize, n_changes: usize) -> u64 {
    let actions = (n_spends as u64).saturating_add(n_changes as u64);
    MARGINAL_FEE_ZATOSHI * actions.max(GRACE_ACTIONS)
}

/// Decomposes `total` into self-funding notes, converging the reserved fee estimate against the
/// resulting output count so the split reserves enough headroom.
///
/// The prep fee reserved while decomposing must cover the real split fee, which itself depends on
/// the output count. Rather than requiring an exact fixed point (which the randomized decomposition
/// does not admit), this stops as soon as the reserved fee is sufficient (`real_fee <=
/// fee_estimate`); each non-terminating round strictly increases the estimate, bounded by the
/// note-count cap, so it always terminates. Returns the plan and the converged fee estimate.
fn converge_denomination_plan(total: u64, n_spends: usize) -> (NoteSplitPlan, u64) {
    let mut fee_estimate = FEE_ESTIMATE_ZATOSHI;
    let mut rng = OsRng;
    let mut plan = plan_note_split(total, fee_estimate, &mut rng);
    for _ in 0..=MIGRATION_MAX_PREPARED_NOTES_PER_RUN {
        let real_fee = split_fee(n_spends, plan.migration_outputs().len().max(1));
        if real_fee <= fee_estimate {
            break;
        }
        fee_estimate = real_fee;
        plan = plan_note_split(total, fee_estimate, &mut rng);
    }
    (plan, fee_estimate)
}

/// Classifies a recoverable failure's error message into an [`AttentionReason`].
fn attention_from_error(message: &str) -> AttentionReason {
    let lower = message.to_ascii_lowercase();
    if lower.contains("invalid note") {
        let transfer_id = message
            .split("transfer ")
            .nth(1)
            .unwrap_or("")
            .trim()
            .to_string();
        AttentionReason::InvalidTransfer(TransferId::from_raw(transfer_id))
    } else {
        AttentionReason::TransferExpired
    }
}

/// Parses the 64-character byte-reversed hex string produced by `TxId`'s `Display` impl (and stored
/// verbatim as `txid_hex` by the store) back into a [`TxId`]. `zcash_protocol::TxId` has no public
/// hex parser, so this hand-rolls the inverse of its `Display` (reversing the byte order, matching
/// the block-explorer txid convention).
fn parse_txid_hex(hex_str: &str) -> Result<TxId, MigrationError> {
    if hex_str.len() != 64 || !hex_str.is_ascii() {
        return Err(MigrationError::Pipeline(format!(
            "invalid txid hex: {hex_str:?}"
        )));
    }
    let mut bytes = [0u8; 32];
    for (i, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex_str[2 * i..2 * i + 2], 16)
            .map_err(|_| MigrationError::Pipeline(format!("invalid txid hex: {hex_str:?}")))?;
    }
    bytes.reverse();
    Ok(TxId::from_bytes(bytes))
}
