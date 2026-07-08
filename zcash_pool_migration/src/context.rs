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

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use rusqlite::Connection;
use uuid::Uuid;
use zcash_client_sqlite::AccountUuid;
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
    PreparedTransfer, TransferId, TransferResult,
};

/// ZIP-317 single-action fee estimate (zatoshi) used by note-split / migration planning; this is
/// only a planning-time estimate, the actual fee charged by a proposal at signing time is what
/// ends up persisted.
const FEE_ESTIMATE_ZATOSHI: u64 = 10_000;

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
    /// drained into Ironwood.
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
        // balance fully migrated into Ironwood.
        if let MigrationState::InProgress(p) = &mapped {
            if p.total_transfers() > 0 && p.completed_transfers() == p.total_transfers() {
                let db = self.open_wallet()?;
                let balances = backend::pool_balances(&db, self.account)?;
                if balances.orchard_spendable == 0 && balances.ironwood_total > 0 {
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
    /// self-funding (`power_of_ten + buffer`); any residual stays in Orchard. The reported fee is
    /// the exact ZIP-317 fee for the split transaction (`5000 × (spends + outputs)`, floored at 2
    /// actions); at signing time the last output absorbs any drift between this plan and the
    /// then-current balance.
    ///
    /// # Errors
    ///
    /// Returns [`MigrationError::NotSynced`]/[`MigrationError::Backend`] if the spendable Orchard
    /// balance or its notes cannot be read, and [`MigrationError::Pipeline`] if the plan would
    /// exceed the per-run prepared-note limit.
    pub fn prepare_note_split(&self) -> Result<NoteSplitProposal, MigrationError> {
        let db = self.open_wallet()?;
        let total = backend::pool_balances(&db, self.account)?.orchard_spendable;
        let plan =
            plan_denominations(total, FEE_ESTIMATE_ZATOSHI).map_err(MigrationError::Pipeline)?;
        // Pre-split there are no migration locks yet, so no exclusions apply.
        let locks = BTreeSet::new();
        let n_spends = crate::split::select_spendable_orchard_notes(&db, self.account, &locks)?
            .len()
            .max(1);
        let n_outputs = plan.migration_outputs.len();
        let output_values = plan
            .migration_outputs
            .iter()
            .map(|&v| Zatoshis::const_from_u64(v))
            .collect();
        Ok(NoteSplitProposal::from_parts(
            output_values,
            Zatoshis::const_from_u64(crate::split::split_fee(n_spends, n_outputs)),
        ))
    }

    /// Build, sign (as a PCZT), and persist the note-split transaction; returns the serialized
    /// PCZT for the platform to extract and broadcast. The split is a wallet-internal
    /// multi-output send to the account's own address.
    ///
    /// # Errors
    ///
    /// Returns [`MigrationError::Db`] if the new run cannot be recorded, and
    /// [`MigrationError::NotSynced`]/[`MigrationError::Backend`]/[`MigrationError::Pipeline`] if
    /// the split transaction cannot be built, proven, or signed.
    pub fn sign_note_split(
        &self,
        proposal: &NoteSplitProposal,
        usk: &UnifiedSpendingKey,
    ) -> Result<PreparedTransfer, MigrationError> {
        let conn = self.store_conn()?;
        let run_id = new_run_id();
        let target_values: Vec<u64> = proposal
            .output_values()
            .iter()
            .map(|&v| u64::from(v))
            .collect();
        store::insert_run(
            &conn,
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
        let mut db = self.open_wallet()?;
        let signed = backend::sign_split(
            &mut db,
            &self.network,
            self.account,
            &conn,
            &run_id,
            proposal,
            usk,
        )?;
        Ok(PreparedTransfer::from_parts(
            TransferId::for_prep(&run_id),
            signed.txid,
            signed.pczt_bytes,
        ))
    }

    // ----- migration proposal -----

    /// Generate the full migration schedule for the spendable Orchard balance. Each transfer's
    /// `amount` is the value that crosses the turnstile (the pre-split note pays its own fee).
    ///
    /// # Errors
    ///
    /// Returns [`MigrationError::NotSynced`]/[`MigrationError::Backend`] if the target/anchor
    /// heights or spendable Orchard balance cannot be read, and [`MigrationError::Pipeline`] if
    /// the resulting plan would exceed the per-run prepared-note limit.
    pub fn propose_migration_transfers(&self) -> Result<MigrationSchedule, MigrationError> {
        let db = self.open_wallet()?;
        let (target, anchor) = backend::target_and_anchor(&db)?;
        let total = backend::pool_balances(&db, self.account)?.orchard_spendable;
        let plan =
            plan_denominations(total, FEE_ESTIMATE_ZATOSHI).map_err(MigrationError::Pipeline)?;
        let run_id = new_run_id();
        Ok(scheduling::build_schedule(
            &run_id,
            &plan.crossing_values,
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
            &run_id, &amounts, target, anchor,
            // immediate: executable now, no first-transfer privacy delay
            0,
        ))
    }

    /// Pre-sign and persist every transfer in the schedule, each at its bucketed anchor.
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
    /// # Errors
    ///
    /// Returns whatever [`Self::restart_current_migration_step`] and
    /// [`Self::sign_and_store_migration_schedule`] can return.
    pub fn refresh_stale_transfers(&self, usk: &UnifiedSpendingKey) -> Result<u32, MigrationError> {
        let schedule = self.restart_current_migration_step()?;
        let count = schedule.transfers().len() as u32;
        self.sign_and_store_migration_schedule(&schedule, usk)?;
        Ok(count)
    }

    /// Record the platform's broadcast outcome, advancing the engine's state.
    ///
    /// A result for the note-split ("prep") transaction (`id.is_prep()`) advances the split phase
    /// to [`Phase::WaitingDenomConfirmations`] on success; there is at most one active run (and
    /// one prep transaction) per account/network, so the active run's own id is used directly
    /// rather than extracting a run id out of `id`. A network error on the prep transaction is
    /// simply left for the platform to retry; a prep transaction is never itself reported as
    /// invalid or expired. For an ordinary transfer: success marks its row `broadcasted` (keyed by
    /// the reported transaction id, which the platform obtained by broadcasting exactly the bytes
    /// [`Self::next_due_transfer`] returned); a retryable network error leaves it scheduled for a
    /// later attempt; `InvalidNote`/`Expired` park the whole run in
    /// [`Phase::FailedRecoverable`] for [`Self::restart_current_migration_step`] /
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
                store::mark_pending_status(&conn, &txid.to_string().to_lowercase(), "broadcasted")?;
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
    /// Uses a blob-free `EXISTS` check ([`store::has_due_transfer`]) rather than loading the next
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
    /// Only meaningful once a schedule should exist (from [`Phase::BroadcastScheduled`] onward).
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
    pub fn restart_current_migration_step(&self) -> Result<MigrationSchedule, MigrationError> {
        let conn = self.store_conn()?;
        if let Some(run) = self.active_run(&conn)? {
            store::clear_scheduled_pending(&conn, &run.run_id)?;
        }
        self.propose_migration_transfers()
    }
}

fn new_run_id() -> String {
    Uuid::new_v4().to_string()
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
}
