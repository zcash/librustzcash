//! An engine for migrating Zcash wallet funds from the Orchard value pool to the Ironwood value
//! pool.
//!
//! The crate's single public entry point is [`MigrationContext`]; [`MigrationContext::new`] is
//! also its only setup step — it just ensures the engine's own tables exist in the wallet
//! database and does not otherwise open or validate the wallet's own schema. The engine is
//! **synchronous and does no networking**: it plans the note split, builds, proves, and signs
//! migration transactions as PCZTs, schedules them by block height, and persists all of this
//! state in five additive `ext_ironwood_migration_*` tables in the shared wallet SQLite database
//! — but broadcasting a transaction onto the network, and custody of the spending key, both stay
//! with the platform. See [`types`] for the full public type catalogue (private fields,
//! `from_parts` constructors, and accessor methods throughout — no `serde` anywhere in this
//! crate) and [`error`] for the error types.
//!
//! # Migration flow
//!
//! A migration proceeds through four stages, each available in a software-signing and an
//! external-signer form (see "Software vs external-signer paths" below):
//!
//! 1. **Split.** [`MigrationContext::is_note_split_needed`] reports whether the account's
//!    spendable Orchard balance still needs decomposing into self-funding notes (see "Security
//!    and design notes" below); if so, [`MigrationContext::prepare_note_split`] computes the
//!    [`NoteSplitProposal`], and [`MigrationContext::sign_note_split`] builds, proves, signs, and
//!    persists it as a single "prep" transaction.
//! 2. **Confirm.** The prep transaction is broadcast through the same trio described in
//!    "Broadcast contract" below. Once the wallet scans it as mined and the resulting notes
//!    become spendable, [`MigrationContext::migration_state`] advances the run on its own, from
//!    [`MigrationState::SplitPendingConfirmation`] to [`MigrationState::ReadyToPropose`].
//! 3. **Schedule.** [`MigrationContext::propose_migration_transfers`] turns the (now
//!    self-funding) spendable Orchard notes into a [`MigrationSchedule`] of individually-timed
//!    transfers — or [`MigrationContext::propose_immediate_migration_transfers`] proposes
//!    sweeping the whole balance in a single transaction right away, skipping the split
//!    entirely. The platform presents the schedule to the user for one-time confirmation, and
//!    [`MigrationContext::sign_and_store_migration_schedule`] then builds, proves, signs, and
//!    persists every transfer in it.
//! 4. **Broadcast, then completion.** The platform's background delivery loop drives the
//!    scheduled transfers one at a time through the same broadcast trio.
//!    [`MigrationContext::migration_state`] is the reconciliation hub: on every call it marks
//!    broadcasted transfers confirmed once the wallet scans them as mined, and once every
//!    scheduled transfer is confirmed and the account's spendable Orchard balance has fully
//!    drained into Ironwood, it persists the run in its terminal `complete` phase — so a later
//!    Orchard deposit is free to start a fresh run — and reports [`MigrationState::Complete`].
//!
//! ## Broadcast contract
//!
//! The engine never touches the network itself; the platform drives delivery through three
//! calls:
//!
//! 1. [`MigrationContext::next_due_transfer`] returns the next [`PreparedTransfer`] the platform
//!    should act on, or `None` if nothing is due. While a run has a prep transaction (from the
//!    split step) that has not yet been reported broadcast, it is always returned here first,
//!    with no height gating; only once it has been reported broadcast does this method start
//!    returning the run's ordinary scheduled transfers, gated by their own due height.
//! 2. [`MigrationContext::extract_broadcast_tx`] turns [`PreparedTransfer::pczt_bytes`] into the
//!    consensus transaction bytes, which the platform submits to the network by whatever means
//!    it has (lightwalletd, Tor, ...).
//! 3. [`MigrationContext::record_transfer_result`] reports the outcome. For the prep
//!    transaction, only [`TransferResult::Success`] has any effect (it advances the split
//!    phase); every other outcome is a no-op, since a prep transaction is never itself reported
//!    invalid or expired. For an ordinary transfer, [`TransferResult::Success`] marks it
//!    broadcasted, a retryable [`TransferResult::NetworkError`] leaves it scheduled for a later
//!    attempt, and [`TransferResult::InvalidNote`] / [`TransferResult::Expired`] park the whole
//!    run in a recoverable failure state for [`MigrationContext::restart_current_migration_step`]
//!    or [`MigrationContext::refresh_stale_transfers`] to resolve.
//!
//! [`MigrationContext::has_overdue_transfers`] and [`MigrationContext::has_invalid_transfers`]
//! support on-launch reconciliation: the former is a cheap existence check for a transfer that
//! has passed its due height without being broadcast; the latter detects a run whose schedule no
//! longer covers its remaining Orchard balance (checked only from the point a schedule should
//! exist onward, so the pre-schedule phases are never misreported as invalid).
//!
//! # State machine
//!
//! Internally the engine tracks one of 14 phase strings per migration run — kept identical to
//! the `vizor-wallet` reference implementation's `PHASE_*` values for traceability, and persisted
//! verbatim in the wallet database. [`MigrationContext::migration_state`] collapses them to the
//! 6-value public [`MigrationState`] the application is expected to branch on:
//!
//! | Persisted phase(s) | [`MigrationState`] |
//! |---|---|
//! | `no_orchard_funds`, `waiting_for_spendable_orchard`, `ready_to_prepare`, `abandoned` | [`MigrationState::NotStarted`] |
//! | `preparing_denominations`, `waiting_denom_confirmations` | [`MigrationState::SplitPendingConfirmation`] |
//! | `ready_to_migrate` | [`MigrationState::ReadyToPropose`] |
//! | `broadcast_scheduled`, `broadcasting`, `waiting_migration_confirmations`, `paused` | [`MigrationState::InProgress`] |
//! | `complete` | [`MigrationState::Complete`] |
//! | `failed_recoverable`, `failed_terminal` | [`MigrationState::RequiresAttention`] |
//!
//! `NotStarted` covers both "nothing to migrate yet" and an abandoned run; there is no separate
//! signal for the two today. [`MigrationState::InProgress`] carries a [`MigrationProgress`]
//! snapshot (completed/total transfer counts, remaining Orchard value, and the next transfer's
//! ready height); [`MigrationState::RequiresAttention`] carries an [`AttentionReason`]: which
//! transfer's funding note was spent elsewhere ([`AttentionReason::InvalidTransfer`]), that a
//! PCZT's anchor/expiry elapsed before it could be broadcast
//! ([`AttentionReason::TransferExpired`], the default when a recorded failure's reason cannot be
//! classified), or that a sync is needed before the next spend
//! ([`AttentionReason::SyncRequiredBeforeNext`] — reserved for future use; today's self-funding
//! denominations never produce Orchard change, so
//! [`MigrationContext::is_sync_required_before_next_transfer`] always returns `false` and the
//! engine never reports this variant).
//!
//! # Software vs external-signer paths
//!
//! Every signing step above has two forms:
//!
//! * **Software signing** — the platform supplies a `UnifiedSpendingKey` directly, and
//!   [`MigrationContext::sign_note_split`] /
//!   [`MigrationContext::sign_and_store_migration_schedule`] build, prove, sign, and persist in
//!   one call.
//! * **External signing** (Keystone-style hardware wallet) — split at the signature, since
//!   proofs (unlike signatures) are not covered by the sighash and so can be computed before the
//!   device round trip. [`MigrationContext::create_unsigned_note_split_pczt`] builds and proves
//!   the split PCZT, stages the proven original in the wallet database, and returns the raw
//!   unsigned PCZT bytes for the platform to route to the signing device (typically redacted and
//!   shown as a QR code, mirroring the platform's regular hardware-wallet send flow); there is
//!   only ever one split staged at a time, so no id pairing is needed.
//!   [`MigrationContext::store_signed_note_split_pczt`] then merges the device's signed bytes
//!   into the staged original, verifies it (PCZT combining plus transaction extraction), and
//!   persists the same rows the software-signing path writes.
//!   [`MigrationContext::create_unsigned_transfer_pczts`] does the same per scheduled transfer,
//!   returning one [`UnsignedTransferPczt`] per transfer — each carrying the [`TransferId`] it
//!   corresponds to, since a whole schedule is staged and signed together.
//!   [`MigrationContext::store_signed_schedule_pczts`] takes the matching [`SignedTransferPczt`]
//!   slice back and is **all-or-nothing**: every staged transfer must be matched by exactly one
//!   signed PCZT by id, or nothing is persisted and the staged originals are retained for a
//!   retry.
//!
//! # Security and design notes
//!
//! * **Self-funding denominations.** The note split decomposes the spendable Orchard balance
//!   into power-of-ten ZEC notes (1, 10, 100, ... ZEC), each holding its power-of-ten crossing
//!   value plus a fee buffer (4× the ZIP-317 marginal fee, covering the 2 Orchard + 2 Ironwood
//!   actions a migration transfer spends). When such a note is later spent, it pays its own
//!   transfer fee and exactly the power-of-ten value crosses the Orchard→Ironwood turnstile.
//! * **Dust stays in Orchard.** Any residual that cannot form a whole self-funding note —
//!   including dust — is left behind as Orchard change, never folded into a transaction fee:
//!   folding an identifiable dust amount into a fee would deanonymize a dust-attacked wallet.
//! * **Natural anchor, pinned during signing.** Every transfer in a schedule shares the wallet's
//!   real, witnessable note-commitment-tree anchor height, not a bucketed or rounded one — the
//!   wallet only checkpoints at its own scan-batch boundaries, so an arbitrary rounded height is
//!   essentially never witnessable. While a schedule's transfers are being proposed and signed,
//!   that shared anchor's checkpoint is pinned (`ensure_retained`) on both the Orchard and
//!   Ironwood commitment trees, so ordinary checkpoint pruning cannot invalidate it mid-signing;
//!   the pin is released again once signing finishes, whether it succeeded or failed partway
//!   through.
//! * **Network-free engine.** The crate never opens a network connection, and holds no signing
//!   key beyond the scope of a single call; broadcasting transactions and custody of keys both
//!   stay with the platform.

#![deny(rustdoc::broken_intra_doc_links)]

mod backend;
mod context;
mod denominations;
mod reserved_source;
mod scheduling;
mod split;
mod state;
mod store;

pub mod error;
pub mod types;

pub use context::MigrationContext;
pub use error::{InvalidStateError, MigrationError};
pub use types::{
    AttentionReason, MigrationProgress, MigrationSchedule, MigrationState, NoteSplitProposal,
    PreparedTransfer, SignedTransferPczt, TransferId, TransferProposal, TransferResult,
    UnsignedTransferPczt,
};
