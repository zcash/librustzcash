//! The [`MigrationContext`] facade: the public, synchronous API the platform SDKs wrap. It ties
//! the pure core (denominations, scheduling, state, store) to the [`crate::backend`] wallet
//! integration.
//!
//! This module covers the software-signing path, where the platform supplies a
//! [`UnifiedSpendingKey`] directly; the external-signer (hardware wallet) variants described in
//! the crate's design spec are layered on top separately, reusing the same run/phase machinery.
//!
//! Methods that only touch the engine's own SQLite tables (`record_transfer_result`, the no-run
//! state) are exercised by unit tests with a temporary database. Methods that read balances/
//! heights or build/sign PCZTs are compile-verified against the real upstream APIs; exercising
//! them end-to-end needs a seeded, synced wallet database (a documented integration gap, spec
//! D10).

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use rand::rngs::OsRng;
use rusqlite::Connection;
use uuid::Uuid;
use zcash_client_sqlite::{AccountUuid, ReceivedNoteId};
use zcash_keys::keys::UnifiedSpendingKey;
use zcash_protocol::TxId;
use zcash_protocol::consensus::{BlockHeight, NetworkType, Parameters};
use zcash_protocol::value::Zatoshis;

use crate::backend;
use crate::denominations::plan_denominations;
use crate::error::{InvalidStateError, MigrationError};
use crate::scheduling;
use crate::split::Db;
use crate::state::{self, Phase};
use crate::store;
use crate::types::{
    AttentionReason, MigrationProgress, MigrationSchedule, MigrationState, NoteSplitProposal,
    PreparedTransfer, SignedTransferPczt, TransferId, TransferProposal, TransferResult,
    UnsignedTransferPczt,
};

/// ZIP-317 single-action fee estimate (zatoshi) used by note-split / migration planning; this is
/// only a planning-time estimate, the actual fee charged by a proposal at signing time is what
/// ends up persisted.
const FEE_ESTIMATE_ZATOSHI: u64 = 10_000;

/// The single staging id used for the note-split PCZT: one staged split per account/network, so
/// re-proposing an unsigned split replaces the previous one.
const SPLIT_STAGING_ID: &str = "split";

// ----- external-signer staging metadata (versioned, no serde) -----
//
// The external-signer flow stages a proven-but-unsigned PCZT and must remember, alongside it,
// whatever `store_signed_*` needs to persist the run once the device returns signatures. The
// prototype serialized these companion structs with `serde_json`; this crate takes no `serde`
// dependency (spec D3), so each is hand-rolled into a compact, VERSIONED text encoding written to
// the staging row's `metadata_json` column. Both encodings carry a `v1;` prefix (they hold
// evolvable app-level structs, so a format change bumps the version — unlike the store's
// unversioned `target_values` codec, whose shape is fixed). Decoding is strict: this column is
// engine-internal, never user input, so a malformed value is a pipeline error rather than a
// silent default.

/// What [`MigrationContext::create_unsigned_note_split_pczt`] records alongside the staged split
/// PCZT so [`MigrationContext::store_signed_note_split_pczt`] can persist the run exactly like the
/// software-signing path ([`MigrationContext::sign_note_split`]): the planned per-note output
/// values (the run row's `target_values`) and the residual-adjusted `(action_index, value)` of
/// every change output within the built transaction (the prepared-note refs, which only the
/// builder's shuffle metadata knows).
struct SplitStagingMetadata {
    output_notes: Vec<u64>,
    placed_outputs: Vec<(u32, u64)>,
}

/// Encodes [`SplitStagingMetadata`] as versioned text:
///
/// ```text
/// v1;notes=<u64 csv>;placed=<u32:u64 csv>
/// ```
///
/// `notes` is the comma-separated planned output values; `placed` the comma-separated
/// `action_index:value` pairs. Either list may be empty (`v1;notes=;placed=`). Parsed by
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
/// malformed input (wrong version, missing/extra field, non-numeric value).
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

/// Parses a comma-separated list of `action_index:value` (`u32:u64`) pairs (empty → empty list).
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
/// PCZT so [`MigrationContext::store_signed_schedule_pczts`] can rebuild the transfer's
/// [`store::PendingTxRow`] without re-running input selection: the schedule transfer's heights and
/// crossing value. The fee and selected-note triple are not carried — the external-signer store
/// step no longer holds the input-selection proposal they come from, so (as in the prototype) it
/// records them as zero/empty; no scheduling decision reads those informational columns back.
struct TransferStagingMetadata {
    anchor_height: u32,
    next_executable_after_height: u32,
    expiry_height: u32,
    value_zatoshi: u64,
}

/// Encodes [`TransferStagingMetadata`] as versioned text:
///
/// ```text
/// v1;anchor=<u32>;send=<u32>;expiry=<u32>;value=<u64>
/// ```
///
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
/// any malformed input (wrong version, missing/extra field, non-numeric value).
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

/// Rebuilds the [`store::PendingTxRow`] for an externally signed transfer from its staged metadata
/// and the combined (device-signed) outcome — the external-signer counterpart of
/// `backend::pending_row`. The fee and selected-note triple are recorded as zero/empty (see
/// [`TransferStagingMetadata`]).
fn transfer_pending_row(
    meta: &TransferStagingMetadata,
    combined: &backend::SignedPcztOutcome,
) -> store::PendingTxRow {
    store::PendingTxRow {
        txid_hex: combined.txid.to_string(),
        raw_pczt: combined.pczt_bytes.clone(),
        anchor_height: meta.anchor_height,
        target_height: meta.next_executable_after_height,
        next_executable_after_height: meta.next_executable_after_height,
        expiry_height: meta.expiry_height,
        value_zatoshi: meta.value_zatoshi,
        fee_zatoshi: 0,
        selected_note_txid: String::new(),
        selected_note_output_index: 0,
        selected_note_value: 0,
        status: "scheduled".to_string(),
        metadata_json: "{}".to_string(),
    }
}

/// Holds wallet context for migration operations (mirrors how the platform SDKs pass a db path,
/// network, and account uuid). Cheap to construct: [`Self::new`] only ensures the engine's own
/// tables exist, and every operation opens its own database connection(s) — SQLite handles
/// cross-connection locking with the platform's own connections — so there is no shared mutable
/// state to manage across calls.
pub struct MigrationContext<P> {
    db_path: PathBuf,
    network: P,
    account: AccountUuid,
}

impl<P: Parameters + Clone> MigrationContext<P> {
    /// Creates a context bound to a wallet database, network, and account, ensuring the engine's
    /// own `ext_ironwood_migration_*` tables exist in that database.
    ///
    /// This does not open or validate the wallet's own schema: every operation that needs the
    /// wallet database opens it lazily, so `new` succeeds even against a database that has not
    /// yet been initialized as a `zcash_client_sqlite` wallet.
    ///
    /// # Errors
    ///
    /// Returns [`MigrationError::Db`] if the engine's own tables cannot be created.
    pub fn new(db_path: &Path, network: P, account: AccountUuid) -> Result<Self, MigrationError> {
        let ctx = Self {
            db_path: db_path.to_path_buf(),
            network,
            account,
        };
        // Ensure the ext_ironwood_migration_* tables exist.
        let _ = ctx.store_conn()?;
        Ok(ctx)
    }

    // ----- internal helpers -----

    fn store_conn(&self) -> Result<Connection, MigrationError> {
        let conn = Connection::open(&self.db_path)?;
        store::init(&conn)?;
        Ok(conn)
    }

    fn open_wallet(&self) -> Result<Db<P>, MigrationError> {
        backend::open_wallet(&self.db_path, self.network.clone())
    }

    fn account_str(&self) -> String {
        self.account.expose_uuid().to_string()
    }

    fn network_str(&self) -> &'static str {
        match self.network.network_type() {
            NetworkType::Main => "main",
            NetworkType::Test => "test",
            NetworkType::Regtest => "regtest",
        }
    }

    /// A string recorded alongside each run for future integrity checks; no query reads it back
    /// today (`store::RunRow` has no `db_fingerprint` field).
    fn db_fingerprint(&self) -> String {
        self.db_path.to_string_lossy().into_owned()
    }

    fn orchard_spendable(&self) -> Result<u64, MigrationError> {
        let db = self.open_wallet()?;
        Ok(backend::pool_balances(&db, self.account)?.orchard_spendable)
    }

    fn active_run(&self, conn: &Connection) -> Result<Option<store::RunRow>, MigrationError> {
        Ok(store::active_run(
            conn,
            &self.account_str(),
            self.network_str(),
        )?)
    }

    // ----- state -----

    /// Current migration state. The app calls this on launch and after every operation.
    ///
    /// This is the reconciliation hub: on each call it (1) marks any of the active run's
    /// broadcasted transactions confirmed once the wallet has scanned them as mined, (2) advances
    /// a note split from "pending confirmation" to [`MigrationState::ReadyToPropose`] once its
    /// prep transaction has mined and produced spendable notes, and (3) detects overall
    /// completion once every scheduled transfer is confirmed and the Orchard balance has fully
    /// drained into Ironwood. Completion is **persisted** — the run's phase is set to
    /// `Phase::Complete`, a terminal phase — so the run becomes inactive: its note locks are
    /// released and a later deposit of Orchard funds can start a fresh migration run.
    ///
    /// # Errors
    ///
    /// Returns [`MigrationError::InvalidState`] (carrying [`InvalidStateError::UnknownPhase`]) if
    /// the active run's persisted phase is not recognised, and
    /// [`MigrationError::NotSynced`]/[`MigrationError::Backend`] if a balance or mined-transaction
    /// check requires wallet data that is not yet available.
    pub fn migration_state(&self) -> Result<MigrationState, MigrationError> {
        let conn = self.store_conn()?;
        let Some(run) = self.active_run(&conn)? else {
            return Ok(MigrationState::NotStarted);
        };
        let phase = Phase::parse(&run.phase).ok_or_else(|| {
            MigrationError::InvalidState(InvalidStateError::UnknownPhase(run.phase.clone()))
        })?;
        // Transfer-confirmation reconciliation: the platform only reports the broadcast; mining is
        // observed via the wallet's scan (mirroring the split's prep-tx detection below). Without
        // this, `confirmed` never advances and the progress UI shows every sent transfer as still
        // active.
        if matches!(
            phase,
            Phase::BroadcastScheduled | Phase::Broadcasting | Phase::WaitingMigrationConfirmations
        ) {
            let broadcasted = store::broadcasted_txids(&conn, &run.run_id)?;
            if !broadcasted.is_empty() {
                let db = self.open_wallet()?;
                for txid_hex in broadcasted {
                    let txid = parse_txid_hex(&txid_hex)?;
                    if backend::is_tx_mined(&db, txid)? {
                        store::mark_pending_status(&conn, &txid_hex, "confirmed")?;
                    }
                }
            }
        }
        let progress = self.progress_for_run(&conn, &run.run_id)?;
        let attention = run
            .last_error
            .as_deref()
            .map(attention_from_error)
            .filter(|_| matches!(phase, Phase::FailedRecoverable | Phase::FailedTerminal));
        let mapped = state::to_state(phase, progress, attention);
        // Denomination-split confirmation: the split has no explicit confirmation callback, so
        // advance to ReadyToPropose once its (prep) transaction is mined — the resulting notes are
        // then spendable by the subsequent propose. Covers `PreparingDenominations` (so a broadcast
        // whose result wasn't recorded still advances) and `WaitingDenomConfirmations`. A prep tx
        // that isn't mined yet (signed-only or still in the mempool) is `is_tx_mined == false`, so a
        // not-yet-broadcast split never advances prematurely. Mirrors the `Complete` override below.
        if matches!(
            phase,
            Phase::PreparingDenominations | Phase::WaitingDenomConfirmations
        ) {
            if let Some(prep) = store::prep_tx(&conn, &run.run_id)? {
                let db = self.open_wallet()?;
                let txid = parse_txid_hex(&prep.txid_hex)?;
                // Mined alone is not enough: the split's change notes must also be SPENDABLE
                // (enough confirmations for the balance policy). Advancing on mined-only let the
                // subsequent propose run against a still-zero balance and produce an empty
                // schedule.
                if backend::is_tx_mined(&db, txid)? {
                    let spendable = backend::pool_balances(&db, self.account)?.orchard_spendable;
                    if spendable > 0 {
                        store::set_phase(&conn, &run.run_id, Phase::ReadyToMigrate, None)?;
                        return Ok(MigrationState::ReadyToPropose);
                    }
                }
            }
        }
        // Completion: an in-progress run whose transfers are all confirmed, with the Orchard
        // balance fully migrated into Ironwood. Persist the terminal phase before returning, so the
        // run drops out of `active_run` — releasing its note locks and freeing a future deposit to
        // start a new run. Without this the run row stays non-terminal forever and blocks any
        // subsequent migration.
        if let MigrationState::InProgress(p) = &mapped {
            if p.total_transfers() > 0 && p.completed_transfers() == p.total_transfers() {
                let db = self.open_wallet()?;
                let balances = backend::pool_balances(&db, self.account)?;
                if balances.orchard_spendable == 0 && balances.ironwood_total > 0 {
                    store::set_phase(&conn, &run.run_id, Phase::Complete, None)?;
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
    pub fn migration_progress(&self) -> Result<Option<MigrationProgress>, MigrationError> {
        match self.migration_state()? {
            MigrationState::InProgress(p) => Ok(Some(p)),
            _ => Ok(None),
        }
    }

    fn progress_for_run(
        &self,
        conn: &Connection,
        run_id: &str,
    ) -> Result<MigrationProgress, MigrationError> {
        let totals = store::pending_totals(conn, run_id)?;
        // `unwrap_or(0)`: remaining value reads zero when the wallet cannot provide a summary (e.g.
        // still unsyncing) rather than failing the whole progress read — prototype-parity behavior.
        let remaining_orchard = Zatoshis::const_from_u64(self.orchard_spendable().unwrap_or(0));
        let next_transfer_ready_at_height =
            store::next_scheduled_send_height(conn, run_id)?.map(BlockHeight::from_u32);
        Ok(MigrationProgress::from_parts(
            totals.confirmed,
            totals.total,
            remaining_orchard,
            next_transfer_ready_at_height,
        ))
    }

    // ----- note splitting -----

    /// Whether the Orchard notes must be split before migration. Splitting is mandatory whenever
    /// there is spendable Orchard balance and no split has yet been confirmed.
    ///
    /// # Errors
    ///
    /// Returns [`MigrationError::NotSynced`]/[`MigrationError::Backend`] if the spendable Orchard
    /// balance cannot be read, and [`MigrationError::Db`] on an engine-table access error.
    pub fn is_note_split_needed(&self) -> Result<bool, MigrationError> {
        let conn = self.store_conn()?;
        let already_prepared = self
            .active_run(&conn)?
            .and_then(|r| Phase::parse(&r.phase))
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

    /// Compute the optimal note split for the spendable Orchard balance. Each output note is
    /// self-funding (`power_of_ten + buffer`) and always keeps that exact value — any leftover
    /// (fee-estimate drift, or a balance that doesn't decompose evenly) is left as ordinary,
    /// unlocked Orchard change at signing time instead of being folded into a migration note (see
    /// [`crate::split::finalize_split_outputs`]). The reported fee is the exact ZIP-317 fee for the
    /// split transaction (`5000 × (spends + outputs)`, floored at 2 actions), converged against the
    /// resulting output count so the real signing step reserves enough headroom.
    ///
    /// # Errors
    ///
    /// Returns [`MigrationError::NotSynced`]/[`MigrationError::Backend`] if the spendable Orchard
    /// balance or its notes cannot be read, and [`MigrationError::Pipeline`] if the plan would
    /// exceed the per-run prepared-note limit.
    pub fn prepare_note_split(&self) -> Result<NoteSplitProposal, MigrationError> {
        let db = self.open_wallet()?;
        let total = backend::pool_balances(&db, self.account)?.orchard_spendable;
        // Pre-split there are no migration locks yet, so no exclusions apply.
        let locks = BTreeSet::new();
        let reserved = BTreeSet::new();
        let n_spends =
            crate::split::select_spendable_orchard_notes(&db, self.account, &reserved, &locks)?
                .len()
                .max(1);
        let (plan, fee_estimate) = converge_denomination_plan(total, n_spends)?;
        let output_values = plan
            .migration_outputs
            .iter()
            .map(|&v| Zatoshis::const_from_u64(v))
            .collect();
        Ok(NoteSplitProposal::from_parts(
            output_values,
            Zatoshis::const_from_u64(fee_estimate),
        ))
    }

    /// Build, sign (as a PCZT), and persist the note-split transaction; returns the serialized
    /// PCZT for the platform to extract and broadcast. The split is a wallet-internal
    /// multi-output send to the account's own address.
    ///
    /// The transaction is built and signed *before* any engine rows are written, then the run, its
    /// prep transaction, and its locked prepared notes are persisted in a single database
    /// transaction. A signing failure therefore leaves the store untouched, rather than stranding a
    /// phantom run in the non-terminal `PreparingDenominations` phase — which `active_run` would
    /// keep returning, blocking every future migration for the account.
    ///
    /// # Errors
    ///
    /// Returns [`MigrationError::InvalidState`] (carrying [`InvalidStateError::NotApplicable`]) if
    /// `proposal` has no outputs, [`MigrationError::Db`] if the run cannot be recorded, and
    /// [`MigrationError::NotSynced`]/[`MigrationError::Backend`]/[`MigrationError::Pipeline`] if
    /// the split transaction cannot be built, proven, or signed.
    pub fn sign_note_split(
        &self,
        proposal: &NoteSplitProposal,
        usk: &UnifiedSpendingKey,
    ) -> Result<PreparedTransfer, MigrationError> {
        // Reject an output-less proposal up front — before any run is created or the wallet is
        // opened — mirroring the empty-schedule guard in `sign_and_store_migration_schedule`.
        // Signing a split with nothing to fan into would produce a degenerate transaction and, but
        // for this guard, could strand a non-terminal run.
        if proposal.output_values().is_empty() {
            return Err(MigrationError::InvalidState(
                InvalidStateError::NotApplicable("note split proposal has no outputs"),
            ));
        }
        let conn = self.store_conn()?;
        let run_id = new_run_id();
        let target_values: Vec<u64> = proposal
            .output_values()
            .iter()
            .map(|&v| u64::from(v))
            .collect();
        // Sign FIRST: build, prove, and sign the split without touching the engine's tables.
        let mut db = self.open_wallet()?;
        let (signed, split_outputs) = backend::sign_split(
            &mut db,
            &self.network,
            self.account,
            &conn,
            &run_id,
            proposal,
            usk,
        )?;
        let txid_hex = signed.txid.to_string();
        // Only the self-funding migration notes are locked for the schedule. Any plain change
        // output (`split_outputs.change`) is deliberately left untracked here: it is ordinary,
        // unlocked Orchard balance for the wallet's regular scanner to pick up once the split
        // mines, not a note this engine reserves for a scheduled transfer.
        let prepared: Vec<store::PreparedNote> = split_outputs
            .migration_notes
            .iter()
            .map(|&(action_index, value_zatoshi)| store::PreparedNote {
                txid_hex: txid_hex.clone(),
                output_index: action_index,
                value_zatoshi,
                note_version: 2,
                nullifier_hex: None,
                lock_state: "locked".to_string(),
            })
            .collect();
        // Persist AFTER, atomically: the run, its prep transaction, and its locked prepared notes
        // appear together in the `PreparingDenominations` phase, or nothing does. Mirrors the
        // external-signer `store_signed_note_split_pczt` storage shape.
        let tx = conn.unchecked_transaction()?;
        store::insert_run(
            &tx,
            &store::NewRun {
                run_id: &run_id,
                account_uuid: &self.account_str(),
                network: self.network_str(),
                db_fingerprint: &self.db_fingerprint(),
                phase: Phase::PreparingDenominations,
                prep_txid: None,
                target_values: &target_values,
            },
        )?;
        store::insert_prep_tx(&tx, &run_id, &txid_hex, &signed.pczt_bytes, "pending")?;
        store::insert_prepared_notes(&tx, &run_id, &prepared)?;
        tx.commit()?;
        Ok(PreparedTransfer::from_parts(
            TransferId::for_prep(&run_id),
            signed.txid,
            signed.pczt_bytes,
        ))
    }

    // ----- external signer (hardware wallet) -----
    //
    // The external-signer path splits `sign_note_split` / `sign_and_store_migration_schedule` at
    // the signature: `create_unsigned_*` builds and **proves** each PCZT (proofs are not covered
    // by the sighash, so proving early is free and keeps the store step cheap and atomic), stages
    // the proven original in the wallet database, and returns the *unproven* unsigned PCZT for the
    // device channel — the platform redacts it for the QR exactly like its regular hardware-wallet
    // send. `store_signed_*` then merges the device's signatures into the staged original
    // (Combiner), verifies proofs + signatures via transaction extraction, and persists the same
    // rows the software-signing path writes. The staged PCZTs inherit that path's anchor/expiry
    // semantics: a transfer signed too slowly can pass its expiry before broadcast, which the
    // existing recovery machinery handles.

    /// Build the note-split transaction as an unsigned PCZT for an external signer. Plans the split
    /// for the current spendable Orchard balance (the [`Self::prepare_note_split`] plan), builds
    /// and proves the transaction, stages the proven original, and returns the unsigned PCZT to
    /// route to the signing device. No run is created yet — like the software-signing path,
    /// migration state only advances when the signed split is stored.
    ///
    /// The split pairs every change output with a fabricated zero-value wallet-owned spend, so the
    /// device must sign all wallet-owned actions, not only the value-carrying spends.
    ///
    /// # Errors
    ///
    /// Returns [`MigrationError::NotSynced`]/[`MigrationError::Backend`]/[`MigrationError::Pipeline`]
    /// if the split cannot be planned, built, proven, or serialized, and [`MigrationError::Db`] if
    /// the proven original cannot be staged.
    pub fn create_unsigned_note_split_pczt(&self) -> Result<Vec<u8>, MigrationError> {
        let proposal = self.prepare_note_split()?;
        let conn = self.store_conn()?;
        let mut db = self.open_wallet()?;
        let orchard_fvk = backend::account_orchard_fvk(&db, self.account)?;
        // No run exists yet for this split (it is created when the signed split is stored), so
        // there is no own-run exclusion; other live runs' locks still apply.
        let locks = store::locked_note_refs(&conn, &self.account_str(), None)?;
        let output_notes: Vec<u64> = proposal
            .output_values()
            .iter()
            .map(|&v| u64::from(v))
            .collect();
        let (pczt, split_outputs) = crate::split::build_split_pczt(
            &mut db,
            &self.network,
            self.account,
            &orchard_fvk,
            &locks,
            &output_notes,
        )?;
        // Only the migration notes are staged for locking; any plain change output
        // (`split_outputs.change`) is deliberately dropped here — it is ordinary, unlocked Orchard
        // balance, not a note this engine reserves for a scheduled transfer.
        let placed_outputs = split_outputs.migration_notes;
        // The device-facing copy is serialized before proving: the proof is not signed over, and
        // the platform redacts the PCZT for the QR channel anyway.
        let unsigned = pczt.clone().serialize().map_err(|e| {
            MigrationError::Pipeline(format!("serialize unsigned split pczt: {e:?}"))
        })?;
        let proven = backend::prove_pczt(pczt)?;
        let proven_bytes = proven
            .serialize()
            .map_err(|e| MigrationError::Pipeline(format!("serialize proven split pczt: {e:?}")))?;
        let metadata = SplitStagingMetadata {
            output_notes,
            placed_outputs,
        };
        store::upsert_staged_pczt(
            &conn,
            &self.account_str(),
            self.network_str(),
            store::STAGED_KIND_SPLIT,
            &store::StagedPczt {
                staging_id: SPLIT_STAGING_ID.to_string(),
                raw_pczt: proven_bytes,
                metadata_json: encode_split_staging(&metadata),
            },
        )?;
        Ok(unsigned)
    }

    /// Accept the externally signed note-split PCZT: merge the device's signatures into the staged
    /// proven original, verify and finalize it, and persist the run exactly like
    /// [`Self::sign_note_split`] does after its internal signing. Returns the broadcastable
    /// [`PreparedTransfer`] (carrying the `prep:<run_id>` id); broadcasting then flows through the
    /// platform's existing submit path and [`Self::record_transfer_result`].
    ///
    /// The run, its prep transaction, and its locked prepared notes are inserted and the staged
    /// original consumed in a single database transaction: either all of it persists, or nothing
    /// does and the staged original is retained for a retry.
    ///
    /// # Errors
    ///
    /// Returns [`MigrationError::InvalidState`] (carrying [`InvalidStateError::NotApplicable`]) if
    /// there is no staged note-split PCZT, [`MigrationError::Pipeline`] if the staged metadata or
    /// either PCZT cannot be decoded or the signed PCZT cannot be combined/finalized/extracted, and
    /// [`MigrationError::Db`] if the run cannot be persisted.
    pub fn store_signed_note_split_pczt(
        &self,
        signed_pczt: &[u8],
    ) -> Result<PreparedTransfer, MigrationError> {
        let conn = self.store_conn()?;
        let staged = store::staged_pczts(
            &conn,
            &self.account_str(),
            self.network_str(),
            store::STAGED_KIND_SPLIT,
        )?;
        let Some(staged) = staged.into_iter().next() else {
            return Err(MigrationError::InvalidState(
                InvalidStateError::NotApplicable("no staged note-split PCZT to store"),
            ));
        };
        let metadata = parse_split_staging(&staged.metadata_json)?;
        let signed = backend::combine_signed_pczt(&staged.raw_pczt, signed_pczt)?;
        let txid_hex = signed.txid.to_string();
        let prepared: Vec<store::PreparedNote> = metadata
            .placed_outputs
            .iter()
            .map(|&(action_index, value_zatoshi)| store::PreparedNote {
                txid_hex: txid_hex.clone(),
                output_index: action_index,
                value_zatoshi,
                note_version: 2,
                nullifier_hex: None,
                lock_state: "locked".to_string(),
            })
            .collect();
        let run_id = new_run_id();
        // Persist atomically: the run, its prep tx, and its locked notes appear together and the
        // staged original is consumed, or nothing changes.
        let tx = conn.unchecked_transaction()?;
        store::insert_run(
            &tx,
            &store::NewRun {
                run_id: &run_id,
                account_uuid: &self.account_str(),
                network: self.network_str(),
                db_fingerprint: &self.db_fingerprint(),
                phase: Phase::PreparingDenominations,
                prep_txid: None,
                target_values: &metadata.output_notes,
            },
        )?;
        store::insert_prep_tx(&tx, &run_id, &txid_hex, &signed.pczt_bytes, "pending")?;
        store::insert_prepared_notes(&tx, &run_id, &prepared)?;
        store::clear_staged_pczts(
            &tx,
            &self.account_str(),
            self.network_str(),
            store::STAGED_KIND_SPLIT,
        )?;
        tx.commit()?;
        Ok(PreparedTransfer::from_parts(
            TransferId::for_prep(&run_id),
            signed.txid,
            signed.pczt_bytes,
        ))
    }

    /// Build one unsigned PCZT per transfer of `schedule` for an external signer, each proved and
    /// staged like [`Self::create_unsigned_note_split_pczt`]. Returns the `(transfer id, unsigned
    /// PCZT)` pairs to route to the signing device; the pairing must survive to
    /// [`Self::store_signed_schedule_pczts`], which matches the signed PCZTs back to the staged
    /// originals by id. Any previously staged (unconsumed) transfer PCZTs for the account are
    /// replaced.
    ///
    /// # Errors
    ///
    /// Returns [`MigrationError::InvalidState`] (carrying [`InvalidStateError::NotApplicable`]) if
    /// `schedule` is empty or contains duplicate transfer ids, and
    /// [`MigrationError::NotSynced`]/[`MigrationError::Backend`]/[`MigrationError::Pipeline`]/
    /// [`MigrationError::Db`] if a transfer cannot be proposed, built, proven, or staged.
    pub fn create_unsigned_transfer_pczts(
        &self,
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
        let conn = self.store_conn()?;
        let mut db = self.open_wallet()?;
        let (target, _anchor) = backend::target_and_anchor(&db)?;
        // Mirror the software-signing schedule: exclude the active run's own prepared notes from
        // the lock set — the transfers exist to spend them.
        let own_run_id = self.active_run(&conn)?.map(|r| r.run_id);
        let locks = store::locked_note_refs(&conn, &self.account_str(), own_run_id.as_deref())?;
        store::clear_staged_pczts(
            &conn,
            &self.account_str(),
            self.network_str(),
            store::STAGED_KIND_TRANSFER,
        )?;
        let orchard_fvk = backend::account_orchard_fvk(&db, self.account)?;
        let mut reserved: BTreeSet<ReceivedNoteId> = BTreeSet::new();
        let mut pairs = Vec::with_capacity(schedule.transfers().len());
        for t in schedule.transfers() {
            // Direct-builder path first (matches `sign_and_store_migration_schedule`): a
            // self-funding note pays its own fee, no wallet fee/change logic needed. Falls back to
            // the ordinary input-selection pipeline when no such note exists (the immediate/sweep
            // migration path).
            let pczt = if let Some(outcome) = backend::build_self_funding_transfer_pczt(
                &mut db,
                &self.network,
                self.account,
                &orchard_fvk,
                u64::from(t.amount()),
                &reserved,
                &locks,
                target,
                u32::from(t.expiry_height()),
            )? {
                reserved.insert(outcome.spent_note_id);
                outcome.pczt
            } else {
                let request =
                    backend::self_payment_request(&db, &self.network, self.account, t.amount())?;
                let proposal = backend::propose_migration_transfer(
                    &db,
                    &self.network,
                    self.account,
                    target,
                    u32::from(t.anchor_height()),
                    &reserved,
                    &locks,
                    request,
                )?;
                reserved.extend(backend::proposal_note_refs(&proposal));
                backend::create_transfer_pczt(
                    &mut db,
                    &self.network,
                    self.account,
                    &proposal,
                    u32::from(t.expiry_height()),
                )?
            };
            let unsigned = pczt.clone().serialize().map_err(|e| {
                MigrationError::Pipeline(format!("serialize unsigned transfer pczt: {e:?}"))
            })?;
            let proven = backend::prove_pczt(pczt)?;
            let proven_bytes = proven.serialize().map_err(|e| {
                MigrationError::Pipeline(format!("serialize proven transfer pczt: {e:?}"))
            })?;
            let metadata = TransferStagingMetadata {
                anchor_height: u32::from(t.anchor_height()),
                next_executable_after_height: u32::from(t.next_executable_after_height()),
                expiry_height: u32::from(t.expiry_height()),
                value_zatoshi: u64::from(t.amount()),
            };
            store::upsert_staged_pczt(
                &conn,
                &self.account_str(),
                self.network_str(),
                store::STAGED_KIND_TRANSFER,
                &store::StagedPczt {
                    staging_id: t.id().as_str().to_string(),
                    raw_pczt: proven_bytes,
                    metadata_json: encode_transfer_staging(&metadata),
                },
            )?;
            pairs.push(UnsignedTransferPczt::from_parts(t.id().clone(), unsigned));
        }
        Ok(pairs)
    }

    /// Accept the full set of externally signed transfer PCZTs — **all-or-nothing**. Every staged
    /// transfer must be matched by exactly one signed PCZT (by id); each pair is merged, verified,
    /// and finalized; and only if every transfer succeeds is the committed schedule persisted, in
    /// one database transaction, exactly like [`Self::sign_and_store_migration_schedule`] does
    /// after its internal signing. A partial, mismatched, or invalid set stores nothing.
    ///
    /// # Errors
    ///
    /// Returns [`MigrationError::InvalidState`] (carrying [`InvalidStateError::NotApplicable`]) if
    /// the set is empty, has no staged counterpart, contains duplicate ids, or does not match the
    /// staged set exactly; [`MigrationError::Pipeline`] if any staged metadata or PCZT cannot be
    /// decoded/combined/finalized/extracted; and [`MigrationError::Db`] if the schedule cannot be
    /// persisted.
    pub fn store_signed_schedule_pczts(
        &self,
        signed: &[SignedTransferPczt],
    ) -> Result<(), MigrationError> {
        if signed.is_empty() {
            return Err(MigrationError::InvalidState(
                InvalidStateError::NotApplicable("no signed transfer PCZTs provided"),
            ));
        }
        let conn = self.store_conn()?;
        let staged = store::staged_pczts(
            &conn,
            &self.account_str(),
            self.network_str(),
            store::STAGED_KIND_TRANSFER,
        )?;
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
        // Validate the id sets fully before any PCZT work: equal counts plus every staged id
        // resolving ⇒ the sets are identical, so a partial or mismatched hand-back is reported as
        // such (not as a downstream combine failure).
        if by_id.len() != staged.len() {
            return Err(MigrationError::InvalidState(
                InvalidStateError::NotApplicable(
                    "signed transfer PCZTs do not match the staged set",
                ),
            ));
        }
        let mut paired = Vec::with_capacity(staged.len());
        for st in &staged {
            let Some(signed_bytes) = by_id.get(st.staging_id.as_str()) else {
                return Err(MigrationError::InvalidState(
                    InvalidStateError::NotApplicable(
                        "signed transfer PCZTs do not match the staged set",
                    ),
                ));
            };
            paired.push((st, *signed_bytes));
        }
        // Combine (and thereby verify) every pair before touching the database: a single failure
        // aborts with nothing persisted and the staged originals retained.
        let mut rows = Vec::with_capacity(paired.len());
        for (st, signed_bytes) in paired {
            let metadata = parse_transfer_staging(&st.metadata_json)?;
            let combined = backend::combine_signed_pczt(&st.raw_pczt, signed_bytes)?;
            rows.push(transfer_pending_row(&metadata, &combined));
        }
        // Atomic store — mirrors `sign_and_store_migration_schedule`'s persistence tail.
        let tx = conn.unchecked_transaction()?;
        let run_id = match self.active_run(&tx)? {
            Some(r) => r.run_id,
            None => {
                let id = new_run_id();
                store::insert_run(
                    &tx,
                    &store::NewRun {
                        run_id: &id,
                        account_uuid: &self.account_str(),
                        network: self.network_str(),
                        db_fingerprint: &self.db_fingerprint(),
                        phase: Phase::ReadyToMigrate,
                        prep_txid: None,
                        target_values: &[],
                    },
                )?;
                id
            }
        };
        store::insert_pending_txs(&tx, &run_id, &rows)?;
        store::set_phase(&tx, &run_id, Phase::BroadcastScheduled, None)?;
        store::clear_staged_pczts(
            &tx,
            &self.account_str(),
            self.network_str(),
            store::STAGED_KIND_TRANSFER,
        )?;
        tx.commit()?;
        Ok(())
    }

    // ----- migration proposal -----

    /// The leftover Orchard balance that a migration schedule would *not* cross, reported only
    /// when it is large enough to be worth offering the user a choice about (see
    /// [`crate::denominations::MIGRATION_THRESHOLD_ZATOSHI`]). Values below that threshold are
    /// true dust — moving them would cost more in fees than they're worth — and are never
    /// reported; the caller should just leave them in the wallet.
    ///
    /// Intended for the "also migrate the rest?" opt-in: whales who prize the round-number
    /// crossing-value privacy property may decline (the residual is not a power of ten, so
    /// migrating it is comparatively more identifiable); everyday users who would rather have
    /// nothing left behind can opt in, which [`Self::propose_migration_transfers`]'s
    /// `include_residual` flag then adds to the schedule as one extra transfer.
    ///
    /// # Errors
    ///
    /// Returns [`MigrationError::NotSynced`]/[`MigrationError::Backend`] if the spendable Orchard
    /// balance cannot be read, and [`MigrationError::Pipeline`] if the plan would exceed the
    /// per-run prepared-note limit.
    pub fn residual_after_migration(&self) -> Result<Option<Zatoshis>, MigrationError> {
        let db = self.open_wallet()?;
        let total = backend::pool_balances(&db, self.account)?.orchard_spendable;
        let plan = plan_denominations(total, 0).map_err(MigrationError::Pipeline)?;
        Ok(plan
            .orchard_change
            .filter(|&v| v >= crate::denominations::MIGRATION_THRESHOLD_ZATOSHI)
            .map(Zatoshis::const_from_u64))
    }

    /// Generate the full migration schedule for the spendable Orchard balance. Each staggered
    /// transfer's `amount` is the value that crosses the turnstile (the pre-split note pays its own
    /// fee).
    ///
    /// When `include_residual` is `true` and the balance leaves a residual worth offering (see
    /// [`Self::residual_after_migration`]), one further transfer for exactly that (non-round)
    /// amount is appended to the schedule — it will not match any self-funding note, so it signs
    /// via the ordinary input-selection pipeline rather than the direct-builder path the staggered
    /// transfers use (see `backend::build_self_funding_transfer_pczt`).
    ///
    /// # Errors
    ///
    /// Returns [`MigrationError::NotSynced`]/[`MigrationError::Backend`] if the target/anchor
    /// heights or spendable Orchard balance cannot be read, and [`MigrationError::Pipeline`] if
    /// the resulting plan would exceed the per-run prepared-note limit.
    pub fn propose_migration_transfers(
        &self,
        include_residual: bool,
    ) -> Result<MigrationSchedule, MigrationError> {
        let db = self.open_wallet()?;
        let (target, anchor) = backend::target_and_anchor(&db)?;
        let total = backend::pool_balances(&db, self.account)?.orchard_spendable;
        // No fee reservation here (unlike `prepare_note_split`): by the time this runs, the
        // spendable balance is expected to already consist of the split's self-funding notes
        // (each already carrying its own transfer-fee buffer) — there is no further transaction
        // fee to pay to "unlock" them, so decomposing with a zero prep-fee is what reproduces
        // those exact notes back as crossing values. A balance that is not (yet, or no longer)
        // purely self-funding notes — including leftover Orchard change — decomposes on a
        // best-effort basis; `MigrationContext::sign_and_store_migration_schedule` falls back to
        // the ordinary input-selection pipeline for any crossing value with no matching note (see
        // `backend::build_self_funding_transfer_pczt`).
        let plan = plan_denominations(total, 0).map_err(MigrationError::Pipeline)?;
        let mut crossing_values = plan.crossing_values;
        if include_residual {
            if let Some(residual) = plan
                .orchard_change
                .filter(|&v| v >= crate::denominations::MIGRATION_THRESHOLD_ZATOSHI)
            {
                // Unlike a planned self-funding note, the residual has no fee pre-reserved by a
                // denomination plan — net out TRANSFER_FEE_BUFFER_ZATOSHI here so the scheduled
                // crossing value is what actually lands in Ironwood. This is exactly the value
                // `build_self_funding_transfer_pczt` will look for later
                // (`crossing_value + TRANSFER_FEE_BUFFER_ZATOSHI == residual`): the residual note
                // `finalize_split_outputs` (split.rs) minted is worth exactly `residual`, so this
                // transfer *does* match it and signs via the same direct-builder path as the
                // round-number crossings — not the ordinary input-selection fallback, despite the
                // residual's non-round crossing amount. Only a residual that didn't originate from
                // a real split's exact accounting (or was already partially spent) would miss and
                // fall back to `propose_migration_transfer`/`create_transfer_pczt` instead.
                crossing_values.push(
                    residual.saturating_sub(crate::denominations::TRANSFER_FEE_BUFFER_ZATOSHI),
                );
            }
        }
        let run_id = new_run_id();
        Ok(scheduling::build_schedule(
            &mut OsRng,
            &run_id,
            &crossing_values,
            target,
            anchor,
            // First transfer executable immediately; de-correlation from user activity is the
            // send-time machinery's job (background delivery; future: no send earlier than ~10
            // minutes after the last sync).
            0,
        ))
    }

    /// Propose the immediate (single-transaction) migration: sweep the entire spendable Orchard
    /// balance into one Ironwood output, executable now. Unlike the staggered path there is no
    /// denomination and no note split — the whole balance (minus the transaction fee) crosses in
    /// a single transfer. Returns an empty schedule when nothing is migratable.
    ///
    /// # Errors
    ///
    /// Returns [`MigrationError::NotSynced`]/[`MigrationError::Backend`] if the target/anchor
    /// heights or spendable Orchard balance cannot be read, and [`MigrationError::Pipeline`] if
    /// probing the sweep transaction's fee fails.
    pub fn propose_immediate_migration_transfers(
        &self,
    ) -> Result<MigrationSchedule, MigrationError> {
        let db = self.open_wallet()?;
        let (target, anchor) = backend::target_and_anchor(&db)?;
        let crossing = backend::sweep_crossing_value(&db, &self.network, self.account)?;
        let run_id = new_run_id();
        let amounts = crossing.map(|value| vec![value]).unwrap_or_default();
        Ok(scheduling::build_schedule(
            &mut OsRng, &run_id, &amounts, target, anchor,
            // immediate: executable now, no first-transfer privacy delay
            0,
        ))
    }

    /// Pre-sign and persist every transfer in the schedule, each at the schedule's shared natural
    /// anchor.
    ///
    /// Reuses the account's active run if one already exists (e.g. a note split already in
    /// progress); otherwise starts a new one.
    ///
    /// # Errors
    ///
    /// Returns [`MigrationError::InvalidState`] (carrying [`InvalidStateError::NotApplicable`]) if
    /// `schedule` is empty, and
    /// [`MigrationError::Db`]/[`MigrationError::NotSynced`]/[`MigrationError::Backend`]/
    /// [`MigrationError::Pipeline`] if a transfer cannot be proposed, built, signed, or persisted.
    pub fn sign_and_store_migration_schedule(
        &self,
        schedule: &MigrationSchedule,
        usk: &UnifiedSpendingKey,
    ) -> Result<(), MigrationError> {
        // Refuse an empty schedule outright: signing it would advance the run into the
        // post-schedule phases with nothing queued, which reads as an invalid migration.
        if schedule.is_empty() {
            return Err(MigrationError::InvalidState(
                InvalidStateError::NotApplicable("cannot sign an empty schedule"),
            ));
        }
        let conn = self.store_conn()?;
        let run_id = match self.active_run(&conn)? {
            Some(r) => r.run_id,
            None => {
                let id = new_run_id();
                store::insert_run(
                    &conn,
                    &store::NewRun {
                        run_id: &id,
                        account_uuid: &self.account_str(),
                        network: self.network_str(),
                        db_fingerprint: &self.db_fingerprint(),
                        phase: Phase::ReadyToMigrate,
                        prep_txid: None,
                        target_values: &[],
                    },
                )?;
                id
            }
        };
        let mut db = self.open_wallet()?;
        backend::sign_schedule(
            &mut db,
            &self.network,
            self.account,
            &conn,
            &run_id,
            schedule,
            usk,
        )?;
        store::set_phase(&conn, &run_id, Phase::BroadcastScheduled, None)?;
        Ok(())
    }

    // ----- background execution -----

    /// Whether a sync is required before the next transfer (change returned to Orchard). With the
    /// clean self-funding denominations each transfer spends a whole pre-split note and produces
    /// no Orchard change, so this is false; richer change detection is a future refinement.
    ///
    /// # Errors
    ///
    /// Never returns an error.
    pub fn is_sync_required_before_next_transfer(&self) -> Result<bool, MigrationError> {
        Ok(false)
    }

    /// The next height-due pre-signed transfer, or `None`. The platform extracts the transaction
    /// from [`PreparedTransfer::pczt_bytes`] (see [`Self::extract_broadcast_tx`]), broadcasts it,
    /// then calls [`Self::record_transfer_result`].
    ///
    /// # Errors
    ///
    /// Returns [`MigrationError::NotSynced`]/[`MigrationError::Backend`] if the current target
    /// height cannot be read (only reached when there is no pending note-split transaction), and
    /// [`MigrationError::Db`] on an engine-table access error.
    pub fn next_due_transfer(&self) -> Result<Option<PreparedTransfer>, MigrationError> {
        let conn = self.store_conn()?;
        let Some(run) = self.active_run(&conn)? else {
            return Ok(None);
        };
        // The note-split (prep) transaction must broadcast and confirm before any transfer.
        if let Some(prep) = store::prep_tx(&conn, &run.run_id)? {
            if prep.status == "pending" {
                let txid = parse_txid_hex(&prep.txid_hex)?;
                return Ok(Some(PreparedTransfer::from_parts(
                    TransferId::for_prep(&run.run_id),
                    txid,
                    prep.raw_pczt,
                )));
            }
        }
        let db = self.open_wallet()?;
        let (target, _anchor) = backend::target_and_anchor(&db)?;
        let Some(tx) = store::next_due_transfer(&conn, &run.run_id, target)? else {
            return Ok(None);
        };
        let txid = parse_txid_hex(&tx.txid_hex)?;
        Ok(Some(PreparedTransfer::from_parts(
            TransferId::from_raw(tx.txid_hex),
            txid,
            tx.raw_pczt,
        )))
    }

    /// The next height-due scheduled transfer's full proposal (amount, anchor, timing), or `None`
    /// if nothing is due, or the active run has no scheduled transfer yet (e.g. only the
    /// note-split prep transaction is pending — the prep has no `TransferProposal` of its own).
    ///
    /// Unlike [`Self::next_due_transfer`]'s [`PreparedTransfer`] (an opaque, already-signed PCZT),
    /// this exposes the same fields [`Self::propose_migration_transfers`] originally returned for
    /// this transfer — e.g. so a platform can validate a proposed reschedule target against
    /// [`TransferProposal::expiry_height`] without parsing the PCZT to recover it.
    ///
    /// # Errors
    ///
    /// Returns [`MigrationError::NotSynced`]/[`MigrationError::Backend`] if the current target
    /// height cannot be read, [`MigrationError::Db`] on an engine-table access error, and
    /// [`MigrationError::Pipeline`] if the stored value is not a valid [`Zatoshis`] amount.
    pub fn pending_transfer_proposal(&self) -> Result<Option<TransferProposal>, MigrationError> {
        let conn = self.store_conn()?;
        let Some(run) = self.active_run(&conn)? else {
            return Ok(None);
        };
        if let Some(prep) = store::prep_tx(&conn, &run.run_id)? {
            if prep.status == "pending" {
                return Ok(None);
            }
        }
        let db = self.open_wallet()?;
        let (target, _anchor) = backend::target_and_anchor(&db)?;
        let Some(tx) = store::next_due_transfer(&conn, &run.run_id, target)? else {
            return Ok(None);
        };
        let amount = Zatoshis::from_u64(tx.value_zatoshi)
            .map_err(|e| MigrationError::Pipeline(format!("Invalid transfer value: {e}")))?;
        Ok(Some(TransferProposal::from_parts(
            TransferId::from_raw(tx.txid_hex),
            amount,
            BlockHeight::from(tx.anchor_height),
            BlockHeight::from(tx.next_executable_after_height),
            BlockHeight::from(tx.expiry_height),
        )))
    }

    /// Extract the broadcast-ready consensus transaction bytes from a serialized signed PCZT (as
    /// carried in [`PreparedTransfer::pczt_bytes`]). A convenience for callers not already linking
    /// librustzcash directly.
    ///
    /// # Errors
    ///
    /// Returns [`MigrationError::Pipeline`] if the PCZT cannot be parsed or extracted, or the
    /// transaction cannot be encoded.
    pub fn extract_broadcast_tx(&self, pczt_bytes: &[u8]) -> Result<Vec<u8>, MigrationError> {
        backend::extract_broadcast_tx(pczt_bytes)
    }

    /// Re-propose at a fresh anchor and re-sign the active run's scheduled transfers, replacing
    /// PCZTs whose anchor may have gone stale. Returns the number of transfers refreshed. A future
    /// refinement re-anchors the persisted PCZTs in place via the updater role rather than
    /// regenerating them.
    ///
    /// `include_residual` should match whatever choice the user made when the schedule being
    /// refreshed was first proposed (see [`Self::propose_migration_transfers`]).
    ///
    /// # Errors
    ///
    /// Returns whatever [`Self::restart_current_migration_step`] and
    /// [`Self::sign_and_store_migration_schedule`] can return.
    pub fn refresh_stale_transfers(
        &self,
        usk: &UnifiedSpendingKey,
        include_residual: bool,
    ) -> Result<u32, MigrationError> {
        let schedule = self.restart_current_migration_step(include_residual)?;
        let count = schedule.transfers().len() as u32;
        self.sign_and_store_migration_schedule(&schedule, usk)?;
        Ok(count)
    }

    /// Record the platform's broadcast outcome, advancing the engine's state.
    ///
    /// A result for the note-split ("prep") transaction (`id.is_prep()`) advances the split phase
    /// to `Phase::WaitingDenomConfirmations` on success; there is at most one active run (and
    /// one prep transaction) per account/network, so the active run's own id is used directly
    /// rather than extracting a run id out of `id`. A network error on the prep transaction is
    /// simply left for the platform to retry; a prep transaction is never itself reported as
    /// invalid or expired. For an ordinary transfer: success marks its row `broadcasted` (keyed by
    /// the reported transaction id, which the platform obtained by broadcasting exactly the bytes
    /// [`Self::next_due_transfer`] returned); a retryable network error leaves it scheduled for a
    /// later attempt; `InvalidNote`/`Expired` park the whole run in
    /// `Phase::FailedRecoverable` for [`Self::restart_current_migration_step`] /
    /// [`Self::refresh_stale_transfers`] to resolve.
    ///
    /// # Errors
    ///
    /// Returns [`MigrationError::InvalidState`] (carrying [`InvalidStateError::NoActiveRun`]) if
    /// there is no active migration run, and [`MigrationError::Db`] if the engine's tables cannot
    /// be updated.
    pub fn record_transfer_result(
        &self,
        id: &TransferId,
        result: TransferResult,
    ) -> Result<(), MigrationError> {
        let conn = self.store_conn()?;
        let Some(run) = self.active_run(&conn)? else {
            return Err(MigrationError::InvalidState(InvalidStateError::NoActiveRun));
        };
        // A result for the note-split (prep) transaction advances the split phase.
        if id.is_prep() {
            if let TransferResult::Success(_) = result {
                store::set_prep_tx_status(&conn, &run.run_id, "broadcasted")?;
                store::set_phase(&conn, &run.run_id, Phase::WaitingDenomConfirmations, None)?;
            }
            return Ok(());
        }
        match result {
            TransferResult::Success(txid) => {
                // A success must key an actual pending row; if it updates none, the platform
                // reported a txid the engine never scheduled. Surface it rather than silently
                // succeeding (which would drop the broadcast on the floor).
                let updated = store::mark_pending_status(
                    &conn,
                    &txid.to_string().to_lowercase(),
                    "broadcasted",
                )?;
                if updated == 0 {
                    return Err(MigrationError::Pipeline(format!(
                        "transfer result references unknown txid {txid}"
                    )));
                }
            }
            TransferResult::NetworkError { .. } => { /* leave scheduled for retry */ }
            TransferResult::InvalidNote => {
                store::set_phase(
                    &conn,
                    &run.run_id,
                    Phase::FailedRecoverable,
                    Some(&format!("invalid note for transfer {id}")),
                )?;
            }
            TransferResult::Expired => {
                store::set_phase(
                    &conn,
                    &run.run_id,
                    Phase::FailedRecoverable,
                    Some(&format!("transfer {id} expired")),
                )?;
            }
        }
        Ok(())
    }

    // ----- on-launch reconciliation -----

    /// Whether any scheduled transfer is past its send height but not yet broadcast.
    ///
    /// Uses a blob-free `EXISTS` check (`store::has_due_transfer`) rather than loading the next
    /// due transfer's PCZT, since only the boolean is needed for on-launch reconciliation.
    ///
    /// # Errors
    ///
    /// Returns [`MigrationError::NotSynced`]/[`MigrationError::Backend`] if the current target
    /// height cannot be read, and [`MigrationError::Db`] on an engine-table access error.
    pub fn has_overdue_transfers(&self) -> Result<bool, MigrationError> {
        let conn = self.store_conn()?;
        let Some(run) = self.active_run(&conn)? else {
            return Ok(false);
        };
        let db = self.open_wallet()?;
        let (target, _anchor) = backend::target_and_anchor(&db)?;
        Ok(store::has_due_transfer(&conn, &run.run_id, target)?)
    }

    /// Whether the migration is in an invalid state: spendable Orchard remains but no scheduled
    /// transfer covers it.
    ///
    /// Only meaningful once a schedule should exist (from `Phase::BroadcastScheduled` onward).
    /// In the pre-schedule phases — the note split underway or confirmed, the transfer plan not
    /// yet user-approved — having no queued transfers while the balance still sits in Orchard is
    /// the expected state, not an invalid one; without this gate a relaunch in those phases would
    /// be misrouted to a "transfer no longer valid" recovery screen.
    ///
    /// # Errors
    ///
    /// Returns [`MigrationError::NotSynced`]/[`MigrationError::Backend`] if the spendable Orchard
    /// balance must be checked and cannot be read (the pre-schedule phases return `false` before
    /// any wallet access), and [`MigrationError::Db`] on an engine-table access error.
    pub fn has_invalid_transfers(&self) -> Result<bool, MigrationError> {
        let conn = self.store_conn()?;
        let Some(run) = self.active_run(&conn)? else {
            return Ok(false);
        };
        let pre_schedule = Phase::parse(&run.phase).is_some_and(|p| {
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
        let totals = store::pending_totals(&conn, &run.run_id)?;
        let nothing_queued = totals.scheduled == 0 && totals.broadcasted == 0;
        Ok(nothing_queued && self.orchard_spendable()? > 0)
    }

    // ----- recovery / lifecycle -----

    /// Re-evaluate the remaining spendable Orchard balance and return a fresh schedule for it. The
    /// returned schedule goes through the normal confirm → sign flow.
    ///
    /// # Errors
    ///
    /// Returns [`MigrationError::Db`] if the run's stale scheduled transfers cannot be cleared,
    /// and whatever [`Self::propose_migration_transfers`] can return.
    pub fn restart_current_migration_step(
        &self,
        include_residual: bool,
    ) -> Result<MigrationSchedule, MigrationError> {
        let conn = self.store_conn()?;
        if let Some(run) = self.active_run(&conn)? {
            store::clear_scheduled_pending(&conn, &run.run_id)?;
        }
        self.propose_migration_transfers(include_residual)
    }
}

fn new_run_id() -> String {
    Uuid::new_v4().to_string()
}

/// Decompose `total` into self-funding power-of-ten notes ([`plan_denominations`]), converging the
/// reserved fee estimate against the resulting output count. Used by
/// [`MigrationContext::prepare_note_split`], which is about to pay a real split-transaction fee
/// and so needs that fee reserved accurately up front (unlike
/// [`MigrationContext::propose_migration_transfers`], which re-derives a schedule from an
/// *already* self-funded balance and so needs no fee reservation at all — see its own doc
/// comment).
///
/// The prep-fee reserved while decomposing must cover the real split fee
/// (`split::split_fee(n_spends, n_outputs)`), which itself depends on the resulting output count.
/// Naively re-planning with the fee implied by the previous round's output count can **oscillate**
/// forever between two fee/output-count pairs that imply each other (e.g. fee A decomposes to k
/// outputs, whose real fee is B; fee B decomposes to k−1 outputs, whose real fee is A again) — the
/// discrete jumps in `plan_denominations`'s greedy decomposition mean an *exact* fixed point
/// (`real_fee == fee_estimate`) does not always exist. So instead of requiring exact equality,
/// this stops as soon as the reserved fee is *sufficient* (`real_fee <= fee_estimate`) — which
/// happens well before any cycle would repeat, since each non-terminating round strictly
/// increases `fee_estimate` (bounded above by the note-count cap, so this always terminates) — and
/// is provably safe: `plan_denominations` never lets a plan's outputs exceed its `total -
/// fee_estimate` budget, so `sum(outputs) <= total - fee_estimate <= total - real_fee`, which is
/// exactly the non-error condition [`crate::split::finalize_split_outputs`] checks at signing
/// time. A stricter fixed point (spending exactly the reserved fee, not more than needed) is not
/// required for correctness, only for optimality — the loop bound below is a defensive cap, not
/// load-bearing.
///
/// Returns the plan together with the converged (sufficient, not necessarily exact) fee estimate.
fn converge_denomination_plan(
    total: u64,
    n_spends: usize,
) -> Result<(crate::denominations::DenominationPlan, u64), MigrationError> {
    let mut fee_estimate = FEE_ESTIMATE_ZATOSHI;
    let mut plan = plan_denominations(total, fee_estimate).map_err(MigrationError::Pipeline)?;
    for _ in 0..=crate::denominations::MIGRATION_MAX_PREPARED_NOTES_PER_RUN {
        let real_fee = crate::split::split_fee(n_spends, plan.migration_outputs.len().max(1));
        if real_fee <= fee_estimate {
            break;
        }
        fee_estimate = real_fee;
        plan = plan_denominations(total, fee_estimate).map_err(MigrationError::Pipeline)?;
    }
    Ok((plan, fee_estimate))
}

/// Classify a recoverable failure's error message into an [`AttentionReason`].
fn attention_from_error(message: &str) -> AttentionReason {
    let lower = message.to_ascii_lowercase();
    if lower.contains("invalid note") {
        // The transfer id is embedded in the message after "transfer ".
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

/// Parses the 64-character byte-reversed hex string produced by `TxId`'s `Display` impl — and
/// stored verbatim as `txid_hex` by [`store`] — back into a [`TxId`]. `zcash_protocol::TxId` has
/// no public hex parser of its own (only `Display`/`from_bytes`/`read`/`write`), and adding
/// `zcash_encoding::ReverseHex` as a new direct dependency for this one decode is not worth it
/// (this crate takes on no new dependencies), so this hand-rolls the inverse of `TxId`'s `Display`
/// (reversing the byte order, matching the Bitcoin/Zcash block-explorer txid convention).
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

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;
    use zcash_protocol::consensus::Network;

    fn ctx() -> (NamedTempFile, MigrationContext<Network>) {
        let file = NamedTempFile::new().unwrap();
        let account = AccountUuid::from_uuid(Uuid::from_bytes([7u8; 16]));
        let ctx = MigrationContext::new(file.path(), Network::MainNetwork, account).unwrap();
        (file, ctx)
    }

    #[test]
    fn new_creates_tables_and_state_is_not_started() {
        let (_file, ctx) = ctx();
        assert_eq!(ctx.migration_state().unwrap(), MigrationState::NotStarted);
        assert!(ctx.migration_progress().unwrap().is_none());
    }

    #[test]
    fn converge_denomination_plan_terminates_on_an_oscillating_total() {
        // 2.0005 ZEC, 1 spendable note: fee=10_000 decomposes to two 1-ZEC notes (real fee for 2
        // outputs is 15_000); fee=15_000 decomposes to only one 1-ZEC note (real fee for 1 output
        // is back down to 10_000, the 2-action grace floor) — an exact fixed point does not exist,
        // it cycles between these two states forever. The loop must still terminate and return a
        // plan whose reserved fee is *sufficient* for its own real fee, not necessarily equal to
        // it (see the function's doc comment for why that's the correct, safe termination rule).
        let (plan, fee_estimate) = converge_denomination_plan(200_050_000, 1).unwrap();
        let real_fee = crate::split::split_fee(1, plan.migration_outputs.len().max(1));
        assert!(
            real_fee <= fee_estimate,
            "the reserved fee ({fee_estimate}) must cover the real fee ({real_fee}) for the \
             plan's own output count, or finalize_split_outputs will reject it at signing time"
        );
        // Confirm the plan is actually signable: finalize_split_outputs must not error given the
        // exact total and outputs converge_denomination_plan settled on.
        crate::split::finalize_split_outputs(1, 200_050_000, &plan.migration_outputs)
            .expect("a converged plan must always be signable");
    }

    #[test]
    fn attention_from_error_classifies() {
        assert!(matches!(
            attention_from_error("invalid note for transfer run-2"),
            AttentionReason::InvalidTransfer(_)
        ));
        assert_eq!(
            attention_from_error("transfer run-1 expired"),
            AttentionReason::TransferExpired
        );
    }

    /// Inserts an active run at `phase` for the fixture's account and returns the context.
    fn ctx_with_run_at(phase: Phase) -> (NamedTempFile, MigrationContext<Network>) {
        let (file, ctx) = ctx();
        let conn = ctx.store_conn().unwrap();
        store::insert_run(
            &conn,
            &store::NewRun {
                run_id: "run-phase-test",
                account_uuid: &ctx.account_str(),
                network: ctx.network_str(),
                db_fingerprint: &ctx.db_fingerprint(),
                phase,
                prep_txid: None,
                target_values: &[],
            },
        )
        .unwrap();
        (file, ctx)
    }

    // Regression: a run resumed in a pre-schedule phase (split underway, awaiting confirmation, or
    // ready to propose) has NO queued transfers and a spendable Orchard balance by design — it must
    // not classify as "invalid" (which would route relaunches into a "transfer no longer valid"
    // screen). The fixture's wallet path is not a real wallet DB, so these also prove the
    // pre-schedule gate returns before any wallet access.
    #[test]
    fn has_invalid_transfers_is_false_while_awaiting_denom_confirmations() {
        let (_file, ctx) = ctx_with_run_at(Phase::WaitingDenomConfirmations);
        assert!(!ctx.has_invalid_transfers().unwrap());
    }

    #[test]
    fn has_invalid_transfers_is_false_when_ready_to_migrate() {
        let (_file, ctx) = ctx_with_run_at(Phase::ReadyToMigrate);
        assert!(!ctx.has_invalid_transfers().unwrap());
    }

    /// A throwaway spending key for tests that reject their input before ever using the key. Only
    /// its existence is needed; it is never used to sign.
    fn test_usk() -> UnifiedSpendingKey {
        UnifiedSpendingKey::from_seed(&Network::MainNetwork, &[0u8; 32], zip32::AccountId::ZERO)
            .expect("USK derives from the fixed test seed")
    }

    // An output-less note-split proposal is rejected up front, before any run is created or the
    // wallet (which the fixture's path is not) is opened — so this runs without a real wallet.
    #[test]
    fn sign_note_split_rejects_a_proposal_with_no_outputs() {
        let (_file, ctx) = ctx();
        let empty = NoteSplitProposal::from_parts(vec![], Zatoshis::const_from_u64(10_000));
        assert_not_applicable(ctx.sign_note_split(&empty, &test_usk()).unwrap_err());
        // The guard returns before touching the store: no phantom run is left behind.
        let conn = ctx.store_conn().unwrap();
        assert_eq!(count(&conn, "ext_ironwood_migration_runs"), 0);
    }

    /// A scheduled `PendingTxRow` with an arbitrary txid, for seeding the pending-transfer table.
    fn scheduled_pending(txid_hex: &str) -> store::PendingTxRow {
        store::PendingTxRow {
            txid_hex: txid_hex.to_string(),
            raw_pczt: vec![1, 2, 3],
            anchor_height: 100,
            target_height: 1000,
            next_executable_after_height: 1000,
            expiry_height: 1288,
            value_zatoshi: 100,
            fee_zatoshi: 10,
            selected_note_txid: "note".to_string(),
            selected_note_output_index: 0,
            selected_note_value: 110,
            status: "scheduled".to_string(),
            metadata_json: "{}".to_string(),
        }
    }

    // Regression: a `Success` result whose txid matches no scheduled pending row means the platform
    // broadcast a transaction the engine never handed out. Surface it as a pipeline error instead of
    // silently succeeding and dropping the outcome on the floor.
    #[test]
    fn record_transfer_result_errors_on_success_for_unknown_txid() {
        let (_file, ctx) = ctx_with_run_at(Phase::BroadcastScheduled);
        let conn = ctx.store_conn().unwrap();
        store::insert_pending_txs(&conn, "run-phase-test", &[scheduled_pending("seeded-txid")])
            .unwrap();
        let unknown = TxId::from_bytes([9u8; 32]);
        let id = TransferId::from_raw("run-phase-test:0".to_string());
        let err = ctx
            .record_transfer_result(&id, TransferResult::Success(unknown))
            .unwrap_err();
        assert!(matches!(err, MigrationError::Pipeline(_)), "got {err:?}");
    }

    // ===== external-signer (hardware wallet) path =====

    use crate::types::{SignedTransferPczt, TransferProposal};

    fn count(conn: &Connection, table: &str) -> i64 {
        conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))
            .unwrap()
    }

    fn transfer_proposal(id: &str, amount: u64, send_height: u32) -> TransferProposal {
        TransferProposal::from_parts(
            TransferId::from_raw(id.to_string()),
            Zatoshis::const_from_u64(amount),
            BlockHeight::from_u32(9_999_999),
            BlockHeight::from_u32(send_height),
            BlockHeight::from_u32(send_height + 288),
        )
    }

    fn stage_transfer(
        ctx: &MigrationContext<Network>,
        proposal: &TransferProposal,
        raw_pczt: Vec<u8>,
    ) {
        let metadata = TransferStagingMetadata {
            anchor_height: u32::from(proposal.anchor_height()),
            next_executable_after_height: u32::from(proposal.next_executable_after_height()),
            expiry_height: u32::from(proposal.expiry_height()),
            value_zatoshi: u64::from(proposal.amount()),
        };
        let conn = ctx.store_conn().unwrap();
        store::upsert_staged_pczt(
            &conn,
            &ctx.account_str(),
            ctx.network_str(),
            store::STAGED_KIND_TRANSFER,
            &store::StagedPczt {
                staging_id: proposal.id().as_str().to_string(),
                raw_pczt,
                metadata_json: encode_transfer_staging(&metadata),
            },
        )
        .unwrap();
    }

    fn signed_pczt(id: &str, raw_pczt: Vec<u8>) -> SignedTransferPczt {
        SignedTransferPczt::from_parts(TransferId::from_raw(id.to_string()), raw_pczt)
    }

    fn assert_not_applicable(err: MigrationError) {
        assert!(
            matches!(
                err,
                MigrationError::InvalidState(InvalidStateError::NotApplicable(_))
            ),
            "expected InvalidState(NotApplicable), got {err:?}"
        );
    }

    // ----- versioned staging-metadata codec -----

    #[test]
    fn staging_metadata_round_trips() {
        // Split metadata, non-empty (including a u64::MAX value and a shuffled action index).
        let split = SplitStagingMetadata {
            output_notes: vec![500_000, 490_000, u64::MAX],
            placed_outputs: vec![(1, 500_000), (0, 490_000), (7, u64::MAX)],
        };
        let decoded = parse_split_staging(&encode_split_staging(&split)).unwrap();
        assert_eq!(decoded.output_notes, split.output_notes);
        assert_eq!(decoded.placed_outputs, split.placed_outputs);

        // Split metadata, empty lists.
        let empty = SplitStagingMetadata {
            output_notes: vec![],
            placed_outputs: vec![],
        };
        assert_eq!(encode_split_staging(&empty), "v1;notes=;placed=");
        let decoded = parse_split_staging("v1;notes=;placed=").unwrap();
        assert!(decoded.output_notes.is_empty() && decoded.placed_outputs.is_empty());

        // Transfer metadata.
        let xfer = TransferStagingMetadata {
            anchor_height: 9_999_999,
            next_executable_after_height: 1000,
            expiry_height: 1288,
            value_zatoshi: 990_000,
        };
        let decoded = parse_transfer_staging(&encode_transfer_staging(&xfer)).unwrap();
        assert_eq!(decoded.anchor_height, xfer.anchor_height);
        assert_eq!(
            decoded.next_executable_after_height,
            xfer.next_executable_after_height
        );
        assert_eq!(decoded.expiry_height, xfer.expiry_height);
        assert_eq!(decoded.value_zatoshi, xfer.value_zatoshi);

        // Malformed input is rejected, not silently defaulted.
        assert!(parse_split_staging("v2;notes=;placed=").is_err()); // wrong version
        assert!(parse_split_staging("notes=;placed=").is_err()); // missing version
        assert!(parse_split_staging("v1;notes=1,x;placed=").is_err()); // non-numeric note
        assert!(parse_split_staging("v1;notes=;placed=0:bad").is_err()); // non-numeric value
        assert!(parse_split_staging("v1;notes=;placed=5").is_err()); // missing `:value`
        assert!(parse_split_staging("v1;notes=;placed=;extra=1").is_err()); // trailing field
        assert!(parse_transfer_staging("v1;anchor=1;send=2;expiry=3").is_err()); // missing value
        assert!(parse_transfer_staging("v1;anchor=x;send=2;expiry=3;value=4").is_err()); // non-numeric
    }

    // ----- validation / all-or-nothing (no real PCZTs needed) -----

    #[test]
    fn store_signed_note_split_pczt_without_staged_split_is_invalid_state() {
        let (_file, ctx) = ctx();
        assert_not_applicable(ctx.store_signed_note_split_pczt(&[1, 2, 3]).unwrap_err());
        let conn = ctx.store_conn().unwrap();
        assert_eq!(count(&conn, "ext_ironwood_migration_runs"), 0);
    }

    #[test]
    fn store_signed_note_split_pczt_with_undecodable_pczt_stores_nothing() {
        let (_file, ctx) = ctx();
        let conn = ctx.store_conn().unwrap();
        let metadata = SplitStagingMetadata {
            output_notes: vec![500_000],
            placed_outputs: vec![(0, 500_000)],
        };
        store::upsert_staged_pczt(
            &conn,
            &ctx.account_str(),
            ctx.network_str(),
            store::STAGED_KIND_SPLIT,
            &store::StagedPczt {
                staging_id: SPLIT_STAGING_ID.to_string(),
                raw_pczt: vec![1, 2, 3],
                metadata_json: encode_split_staging(&metadata),
            },
        )
        .unwrap();
        let err = ctx.store_signed_note_split_pczt(&[9, 9, 9]).unwrap_err();
        assert!(matches!(err, MigrationError::Pipeline(_)), "got {err:?}");
        // Nothing persisted; the staged original is retained so the flow can be retried.
        assert_eq!(count(&conn, "ext_ironwood_migration_runs"), 0);
        assert_eq!(count(&conn, "ext_ironwood_migration_prep_tx"), 0);
        assert_eq!(count(&conn, "ext_ironwood_migration_staged_pczts"), 1);
    }

    #[test]
    fn store_signed_schedule_pczts_rejects_empty_input() {
        let (_file, ctx) = ctx();
        assert_not_applicable(ctx.store_signed_schedule_pczts(&[]).unwrap_err());
    }

    #[test]
    fn store_signed_schedule_pczts_without_staged_rows_is_invalid_state() {
        let (_file, ctx) = ctx();
        let signed = vec![signed_pczt("run-0", vec![1])];
        assert_not_applicable(ctx.store_signed_schedule_pczts(&signed).unwrap_err());
    }

    #[test]
    fn store_signed_schedule_pczts_rejects_a_partial_set() {
        let (_file, ctx) = ctx();
        stage_transfer(&ctx, &transfer_proposal("run-0", 100, 1000), vec![1]);
        stage_transfer(&ctx, &transfer_proposal("run-1", 200, 1288), vec![2]);
        let signed = vec![signed_pczt("run-0", vec![1])];
        assert_not_applicable(ctx.store_signed_schedule_pczts(&signed).unwrap_err());
        let conn = ctx.store_conn().unwrap();
        assert_eq!(count(&conn, "ext_ironwood_migration_pending_txs"), 0);
        assert_eq!(count(&conn, "ext_ironwood_migration_staged_pczts"), 2);
    }

    #[test]
    fn store_signed_schedule_pczts_rejects_duplicate_ids() {
        let (_file, ctx) = ctx();
        stage_transfer(&ctx, &transfer_proposal("run-0", 100, 1000), vec![1]);
        stage_transfer(&ctx, &transfer_proposal("run-1", 200, 1288), vec![2]);
        let signed = vec![signed_pczt("run-0", vec![1]), signed_pczt("run-0", vec![2])];
        assert_not_applicable(ctx.store_signed_schedule_pczts(&signed).unwrap_err());
    }

    #[test]
    fn store_signed_schedule_pczts_rejects_an_unknown_id() {
        let (_file, ctx) = ctx();
        stage_transfer(&ctx, &transfer_proposal("run-0", 100, 1000), vec![1]);
        stage_transfer(&ctx, &transfer_proposal("run-1", 200, 1288), vec![2]);
        let signed = vec![signed_pczt("run-0", vec![1]), signed_pczt("run-9", vec![2])];
        assert_not_applicable(ctx.store_signed_schedule_pczts(&signed).unwrap_err());
        let conn = ctx.store_conn().unwrap();
        assert_eq!(count(&conn, "ext_ironwood_migration_pending_txs"), 0);
    }

    #[test]
    fn store_signed_schedule_pczts_is_all_or_nothing_on_undecodable_pczts() {
        let (_file, ctx) = ctx();
        stage_transfer(&ctx, &transfer_proposal("run-0", 100, 1000), vec![1]);
        stage_transfer(&ctx, &transfer_proposal("run-1", 200, 1288), vec![2]);
        let signed = vec![signed_pczt("run-0", vec![9]), signed_pczt("run-1", vec![9])];
        let err = ctx.store_signed_schedule_pczts(&signed).unwrap_err();
        assert!(matches!(err, MigrationError::Pipeline(_)), "got {err:?}");
        let conn = ctx.store_conn().unwrap();
        assert_eq!(count(&conn, "ext_ironwood_migration_pending_txs"), 0);
        assert_eq!(count(&conn, "ext_ironwood_migration_runs"), 0);
        assert_eq!(count(&conn, "ext_ironwood_migration_staged_pczts"), 2);
    }

    #[test]
    fn create_unsigned_transfer_pczts_rejects_an_empty_schedule() {
        let (_file, ctx) = ctx();
        let schedule = MigrationSchedule::from_parts(vec![], 0);
        assert_not_applicable(ctx.create_unsigned_transfer_pczts(&schedule).unwrap_err());
    }

    #[test]
    fn create_unsigned_transfer_pczts_rejects_duplicate_transfer_ids() {
        let (_file, ctx) = ctx();
        let schedule = MigrationSchedule::from_parts(
            vec![
                transfer_proposal("run-0", 100, 1000),
                transfer_proposal("run-0", 200, 1288),
            ],
            6,
        );
        assert_not_applicable(ctx.create_unsigned_transfer_pczts(&schedule).unwrap_err());
    }

    // ----- real-PCZT round trips (device emulation) -----
    //
    // The propose step (`create_unsigned_*`) needs a seeded, synced wallet database — the crate's
    // documented backend-tier integration gap, shared with the software-signing path. These tests
    // therefore fabricate the PCZT exactly the way `build_split_pczt` does (public transaction
    // builder -> Creator -> IoFinalizer -> prove), stage it through the real staging store, emulate
    // the signing device (redact, then sign with a locally derived key, what Keystone does), and
    // drive the REAL `store_signed_*` calls end to end: combine, verify, finalize, extract, persist.
    // The resulting table state is asserted to match what the software-signing storage writes, and
    // the stored PCZT round-trips through `extract_broadcast_tx`.
    //
    // The bundle is a post-NU6.3 Orchard bundle (built at a testnet height above the NU6.3
    // activation — MainNetwork has not activated NU6.3) — the same regime the pipeline proves in —
    // so it proves with the exact `backend::shielded_proving_key()` (`PostNu6_3`) the crate uses.

    /// A fabricated single-spend Orchard PCZT: the proven unsigned original (what the crate stages),
    /// the device-signed counterpart (what the platform hands back), the requested change-output
    /// values, and their `(action_index, value)` placements.
    struct TestPczt {
        proven: Vec<u8>,
        signed: Vec<u8>,
        outputs: Vec<u64>,
        placed: Vec<(u32, u64)>,
    }

    fn build_test_pczt(seed: u8, outputs: &[u64]) -> TestPczt {
        use zcash_primitives::transaction::builder::{BuildConfig, Builder};
        use zcash_primitives::transaction::fees::zip317::FeeRule as Zip317FeeRule;
        use zcash_protocol::memo::MemoBytes;

        let sk = orchard::keys::SpendingKey::from_bytes([seed; 32]).unwrap();
        let ask = orchard::keys::SpendAuthorizingKey::from(&sk);
        let fvk = orchard::keys::FullViewingKey::from(&sk);
        let recipient = fvk.address_at(0u32, orchard::keys::Scope::External);
        let change_address = fvk.address_at(0u32, orchard::keys::Scope::Internal);
        let internal_ovk = fvk.to_ovk(orchard::keys::Scope::Internal);

        // The split disables cross-address transfers, so each spend and each change output is its
        // own action: fabricate one input note self-funding `Sum(outputs) + split_fee(1, n)`.
        let fee = crate::split::split_fee(1, outputs.len());
        let total: u64 = outputs.iter().sum::<u64>() + fee;
        let rho = orchard::note::Rho::from_bytes(&[0u8; 32]).unwrap();
        let rseed =
            orchard::note::RandomSeed::from_bytes([seed.wrapping_add(1); 32], &rho).unwrap();
        let note = orchard::note::Note::from_parts(
            recipient,
            orchard::value::NoteValue::from_raw(total),
            rho,
            rseed,
            orchard::note::NoteVersion::V2,
        )
        .unwrap();

        // A single-leaf tree provides a self-consistent witness + anchor for the fabricated note.
        let cmx: orchard::note::ExtractedNoteCommitment = note.commitment().into();
        let leaf = orchard::tree::MerkleHashOrchard::from_cmx(&cmx);
        let (anchor, merkle_path) = {
            let mut tree =
                shardtree::ShardTree::<_, 32, 16>::new(
                    shardtree::store::memory::MemoryShardStore::<
                        orchard::tree::MerkleHashOrchard,
                        u32,
                    >::empty(),
                    100,
                );
            tree.append(leaf, incrementalmerkletree::Retention::Marked)
                .unwrap();
            tree.checkpoint(9_999_999).unwrap();
            let witness = tree
                .witness_at_checkpoint_depth(0u64.into(), 0)
                .unwrap()
                .unwrap();
            let anchor: orchard::Anchor = witness.root(leaf).into();
            let merkle_path: orchard::tree::MerklePath = witness.into();
            (anchor, merkle_path)
        };

        // TestNetwork activates NU6.3 (at height 4_134_000); MainNetwork has not yet, so only a
        // testnet height above that activation yields the post-NU6.3 orchard_v3 bundle (cross-
        // address disabled, `PostNu6_3` circuit) the pipeline proves against.
        let mut builder = Builder::new(
            Network::TestNetwork,
            BlockHeight::from_u32(10_000_000),
            BuildConfig::Standard {
                sapling_anchor: None,
                orchard_anchor: Some(anchor),
                ironwood_anchor: None,
                orchard_bundle_type: orchard::builder::BundleType::DEFAULT,
                ironwood_bundle_type: orchard::builder::BundleType::DEFAULT,
            },
        );
        builder
            .add_orchard_spend::<std::convert::Infallible>(fvk.clone(), note, merkle_path)
            .unwrap();
        for &value in outputs {
            builder
                .add_orchard_change_output::<std::convert::Infallible>(
                    fvk.clone(),
                    Some(internal_ovk.clone()),
                    change_address,
                    Zatoshis::const_from_u64(value),
                    MemoBytes::empty(),
                )
                .unwrap();
        }
        let build_result = builder
            .build_for_pczt(rand::rngs::OsRng, &Zip317FeeRule::standard())
            .unwrap();
        let placed: Vec<(u32, u64)> = outputs
            .iter()
            .enumerate()
            .map(|(i, &value)| {
                (
                    build_result.orchard_meta.output_action_index(i).unwrap() as u32,
                    value,
                )
            })
            .collect();

        let created =
            pczt::roles::creator::Creator::build_from_parts(build_result.pczt_parts).unwrap();
        let finalized = pczt::roles::io_finalizer::IoFinalizer::new(created)
            .finalize_io()
            .unwrap();
        // The device-facing unsigned copy is serialized before proving, exactly like
        // `create_unsigned_note_split_pczt`.
        let unsigned = finalized.clone().serialize().unwrap();
        let proven = {
            let mut prover = pczt::roles::prover::Prover::new(finalized);
            if prover.requires_orchard_proof() {
                prover = prover
                    .create_orchard_proof(crate::backend::shielded_proving_key())
                    .unwrap();
            }
            prover.finish().serialize().unwrap()
        };

        // Device emulation: redact the unsigned PCZT the way the platform does for the QR channel,
        // then sign every wallet-owned Orchard action with the locally derived key.
        let signed = {
            let pczt = pczt::Pczt::parse(&unsigned).unwrap();
            let redacted = pczt::roles::redactor::Redactor::new(pczt)
                .redact_orchard_with(|mut r| {
                    r.redact_actions(|mut ar| {
                        ar.clear_spend_witness();
                    })
                })
                .finish();
            let mut signer = pczt::roles::signer::Signer::new(redacted).unwrap();
            for index in 0.. {
                match signer.sign_orchard(index, &ask) {
                    Err(pczt::roles::signer::Error::InvalidIndex) => break,
                    Ok(())
                    | Err(pczt::roles::signer::Error::OrchardSign(
                        orchard::pczt::SignerError::WrongSpendAuthorizingKey,
                    )) => {}
                    Err(e) => panic!("device sign: {e:?}"),
                }
            }
            signer.finish().serialize().unwrap()
        };

        TestPczt {
            proven,
            signed,
            outputs: outputs.to_vec(),
            placed,
        }
    }

    /// Shared across the round-trip tests so the proving key is built (and each PCZT proved) once.
    fn fixtures() -> &'static Vec<TestPczt> {
        static FIXTURES: std::sync::OnceLock<Vec<TestPczt>> = std::sync::OnceLock::new();
        FIXTURES.get_or_init(|| {
            vec![
                build_test_pczt(7, &[500_000, 490_000]), // split-shaped: two outputs
                build_test_pczt(11, &[990_000]),         // transfer "run-0"
                build_test_pczt(13, &[880_000, 110_000]), // transfer "run-1"
            ]
        })
    }

    #[test]
    fn store_signed_note_split_pczt_round_trips_an_externally_signed_split() {
        let (_file, ctx) = ctx();
        let conn = ctx.store_conn().unwrap();
        let fixture = &fixtures()[0];
        let metadata = SplitStagingMetadata {
            output_notes: fixture.outputs.clone(),
            placed_outputs: fixture.placed.clone(),
        };
        store::upsert_staged_pczt(
            &conn,
            &ctx.account_str(),
            ctx.network_str(),
            store::STAGED_KIND_SPLIT,
            &store::StagedPczt {
                staging_id: SPLIT_STAGING_ID.to_string(),
                raw_pczt: fixture.proven.clone(),
                metadata_json: encode_split_staging(&metadata),
            },
        )
        .unwrap();

        let prepared = ctx.store_signed_note_split_pczt(&fixture.signed).unwrap();

        // The prepared tx carries the `prep:<run_id>` id contract and a display-order txid.
        assert!(prepared.id().as_str().starts_with("prep:"));
        assert_eq!(prepared.txid().to_string().len(), 64);
        // The run is persisted exactly like `sign_note_split` persists it.
        let run = ctx.active_run(&conn).unwrap().unwrap();
        assert_eq!(run.phase, "preparing_denominations");
        assert_eq!(run.target_values, fixture.outputs);
        let prep = store::prep_tx(&conn, &run.run_id).unwrap().unwrap();
        assert_eq!(prep.txid_hex, prepared.txid().to_string());
        assert_eq!(prep.status, "pending");
        assert_eq!(prep.raw_pczt.as_slice(), prepared.pczt_bytes());
        // The prepared notes are locked at the builder's real (shuffled) action indices.
        let refs = store::locked_note_refs(&conn, &ctx.account_str(), None).unwrap();
        for (action_index, _) in &fixture.placed {
            assert!(refs.contains(&(prepared.txid().to_string().to_lowercase(), *action_index)));
        }
        // The staged original is consumed.
        assert_eq!(count(&conn, "ext_ironwood_migration_staged_pczts"), 0);
        // The stored PCZT is broadcastable through the normal submit path.
        let tx_bytes = ctx.extract_broadcast_tx(prepared.pczt_bytes()).unwrap();
        assert!(!tx_bytes.is_empty());
    }

    #[test]
    fn store_signed_schedule_pczts_round_trips_externally_signed_transfers() {
        let (_file, ctx) = ctx();
        let conn = ctx.store_conn().unwrap();
        let t0 = transfer_proposal("run-0", 990_000, 1000);
        let t1 = transfer_proposal("run-1", 880_000, 1288);
        stage_transfer(&ctx, &t0, fixtures()[1].proven.clone());
        stage_transfer(&ctx, &t1, fixtures()[2].proven.clone());

        // Hand the signed PCZTs back in a different order than they were staged; the pairing is by
        // id, not by position.
        ctx.store_signed_schedule_pczts(&[
            signed_pczt("run-1", fixtures()[2].signed.clone()),
            signed_pczt("run-0", fixtures()[1].signed.clone()),
        ])
        .unwrap();

        // The committed schedule matches what `sign_and_store_migration_schedule` persists.
        let run = ctx.active_run(&conn).unwrap().unwrap();
        assert_eq!(run.phase, "broadcast_scheduled");
        let totals = store::pending_totals(&conn, &run.run_id).unwrap();
        assert_eq!(totals.scheduled, 2);
        assert_eq!(totals.total, 2);
        // The earliest transfer is due first and carries the schedule's row fields.
        let due = store::next_due_transfer(&conn, &run.run_id, u32::MAX)
            .unwrap()
            .unwrap();
        assert_eq!(due.value_zatoshi, 990_000);
        assert_eq!(due.anchor_height, u32::from(t0.anchor_height()));
        assert_eq!(due.next_executable_after_height, 1000);
        assert_eq!(due.expiry_height, 1288);
        assert_eq!(due.status, "scheduled");
        assert_eq!(due.txid_hex.len(), 64);
        // Broadcastable via the existing extract path; staging fully consumed.
        assert!(!ctx.extract_broadcast_tx(&due.raw_pczt).unwrap().is_empty());
        assert_eq!(count(&conn, "ext_ironwood_migration_staged_pczts"), 0);
    }

    #[test]
    fn store_signed_schedule_pczts_rejects_swapped_pairings() {
        let (_file, ctx) = ctx();
        let conn = ctx.store_conn().unwrap();
        stage_transfer(
            &ctx,
            &transfer_proposal("run-0", 990_000, 1000),
            fixtures()[1].proven.clone(),
        );
        stage_transfer(
            &ctx,
            &transfer_proposal("run-1", 880_000, 1288),
            fixtures()[2].proven.clone(),
        );

        // Each signed PCZT is valid on its own, but paired with the wrong id: the combine step must
        // reject the effecting-data mismatch and store nothing.
        let err = ctx
            .store_signed_schedule_pczts(&[
                signed_pczt("run-0", fixtures()[2].signed.clone()),
                signed_pczt("run-1", fixtures()[1].signed.clone()),
            ])
            .unwrap_err();

        assert!(matches!(err, MigrationError::Pipeline(_)), "got {err:?}");
        assert!(ctx.active_run(&conn).unwrap().is_none());
        assert_eq!(count(&conn, "ext_ironwood_migration_pending_txs"), 0);
        assert_eq!(count(&conn, "ext_ironwood_migration_staged_pczts"), 2);
    }
}
