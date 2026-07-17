# `zcash_pool_migration` Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Port the Orchard→Ironwood migration engine into a new `zcash_pool_migration` workspace crate in librustzcash, per the approved spec.

**Architecture:** Eleven-module crate (`types`, `error`, `denominations`, `scheduling`, `state`, `store`, `reserved_source`, `split`, `backend`, `context` + `lib`) mirroring the proven prototype crate, adapted to upstream APIs. Pure modules port nearly verbatim with TDD; the transaction pipelines adapt: transfers move to the upstream high-level `propose → create_pczt_from_proposal → prove → sign` path, the note split keeps the direct-`Builder` path.

**Tech Stack:** Rust (edition 2024, MSRV 1.85.1), rusqlite, zcash_client_backend/zcash_client_sqlite (feature `orchard`), pczt roles, orchard 0.15.

## Global Constraints

- **Spec:** `docs/superpowers/specs/2026-07-08-zcash-pool-migration-crate-design.md` — read it first; it is the contract. Section references (D1–D10, §4, §5, §10) below point there.
- **Prototype (behavioral source of truth):** `/Users/chlup/Developing/zec/work/real-ironwood/ZODLIronwoodMigrationRust/src/` — referenced per task as `PROTO/<file>`. Port semantics exactly unless a task says otherwise.
- **No new external dependencies** (cargo-vet). Everything needed is already a workspace dependency.
- **No serde anywhere in this crate** (spec D3). **No `zcash_unstable` cfg** (spec D2).
- Public types: **private fields, accessor methods, `from_parts`-style constructors** (spec D8). All public items get rustdoc with error cases documented.
- Commit per task, message style `zcash_pool_migration: <Imperative summary>`, body with motivation, ending with `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`.
- Every task must end green on: `cargo test -p zcash_pool_migration --all-features` (plus the task's named checks). `cargo fmt --all` before every commit.
- Test compile is slow (`[profile.test] opt-level = 3`); use `cargo test --profile=dev` ONLY to iterate on compile errors, never for final verification (AGENTS.md).
- Amount/height/id types in public API: `Zatoshis`, `BlockHeight`, `TxId`, `AccountUuid`, `TransferId` — never bare `u64`/`u32`/`String` (internal/store code may keep bare ints).

---

### Task 1: Crate scaffold + workspace wiring

**Files:**
- Modify: `Cargo.toml` (workspace root — `members` list)
- Create: `zcash_pool_migration/Cargo.toml`
- Create: `zcash_pool_migration/README.md`
- Create: `zcash_pool_migration/CHANGELOG.md`
- Create: `zcash_pool_migration/LICENSE-APACHE`, `zcash_pool_migration/LICENSE-MIT` (copy from repo root if sibling crates have them — check `ls zcash_client_sqlite/LICENSE*`; if siblings don't carry per-crate license files, skip)
- Create: `zcash_pool_migration/src/lib.rs`

**Interfaces:**
- Produces: an empty-but-building crate other tasks add modules to.

- [ ] **Step 1: Inspect conventions.** Read `zcash_client_sqlite/Cargo.toml` (how it declares workspace deps/features/lints), `zcash_client_sqlite/README.md`, `zcash_client_sqlite/CHANGELOG.md` (first ~30 lines, for format), and root `Cargo.toml` `[workspace.dependencies]` (confirm `rusqlite`, `uuid`, `rand`, `orchard`, `pczt`, `shardtree`, `zip321`, `zcash_address` entries exist and their exact keys).

- [ ] **Step 2: Add the workspace member.** In root `Cargo.toml`, add `"zcash_pool_migration"` to `members` (alphabetical position: after `"zcash_keys"`, before `"zcash_primitives"` — match the existing ordering scheme, which lists `zcash_client_*` before `zcash_history`; place it to keep the list sorted).

- [ ] **Step 3: Write `zcash_pool_migration/Cargo.toml`.**

```toml
[package]
name = "zcash_pool_migration"
description = "Orchard to Ironwood value-pool migration engine for Zcash wallets"
version = "0.1.0"
authors = ["Michal Fousek <michal.fousek@chlup.info>"]
homepage = "https://github.com/zcash/librustzcash"
repository.workspace = true
readme = "README.md"
license.workspace = true
edition.workspace = true
rust-version.workspace = true
categories.workspace = true

[package.metadata.docs.rs]
all-features = true

[dependencies]
zcash_address.workspace = true
zcash_client_backend = { workspace = true, features = ["orchard", "pczt"] }
zcash_client_sqlite = { workspace = true, features = ["orchard"] }
zcash_keys = { workspace = true, features = ["orchard"] }
zcash_primitives.workspace = true
zcash_protocol.workspace = true
zip321.workspace = true

orchard.workspace = true
pczt = { workspace = true, features = ["orchard", "io-finalizer", "prover", "signer", "spend-finalizer", "tx-extractor", "combiner"] }
shardtree.workspace = true

rand.workspace = true
rusqlite.workspace = true
uuid = { workspace = true, features = ["v4"] }

[dev-dependencies]
incrementalmerkletree.workspace = true
tempfile = "3"
zcash_client_backend = { workspace = true, features = ["orchard", "pczt", "test-dependencies"] }
zcash_client_sqlite = { workspace = true, features = ["orchard", "test-dependencies"] }

[features]
## Exposes APIs that are useful for testing, such as `proptest` strategies.
test-dependencies = []
expensive-tests = []

[lints]
workspace = true
```

Adjust to reality: (a) if root `[workspace.dependencies]` lacks any of these keys (e.g. `zcash_client_sqlite` may not be there since nothing depends on it yet — check), add the missing entry to the ROOT `Cargo.toml` `[workspace.dependencies]` as a path+version dep matching how other in-workspace crates are declared (e.g. `zcash_client_sqlite = { version = "0.21.1", path = "zcash_client_sqlite" }`); (b) `pczt` feature names — verify against `pczt/Cargo.toml` `[features]` and keep only the ones that exist; (c) if `uuid` is not a workspace dep, check how `zcash_client_sqlite` declares it and mirror; (d) drop the `zcash_client_sqlite` dev-dependency line if the normal dependency already carries what tests need (dev-deps section only adds `test-dependencies` features). (e) `tempfile` is used by `zcash_client_sqlite` dev-deps already — mirror its version key (workspace or "3").

- [ ] **Step 4: Write `src/lib.rs`** (crate docs skeleton; modules land in later tasks):

```rust
//! An engine for migrating Zcash wallet funds from the Orchard value pool to the
//! Ironwood value pool.
//!
//! [Full crate docs are completed in Task 14; keep this header + the module wiring.]

#![deny(rustdoc::broken_intra_doc_links)]

mod denominations;
mod scheduling;
mod state;
mod store;

mod backend;
mod context;
mod reserved_source;
mod split;

pub mod error;
pub mod types;

pub use context::MigrationContext;
pub use error::{InvalidStateError, MigrationError};
pub use types::{
    AttentionReason, MigrationProgress, MigrationSchedule, MigrationState, NoteSplitProposal,
    PreparedTransfer, SignedTransferPczt, TransferId, TransferProposal, TransferResult,
    UnsignedTransferPczt,
};
```

For THIS task only, create each `mod` as an empty placeholder file (`src/denominations.rs` etc. containing only `//! <one-line module doc>`) and comment out the `pub use` lines that reference not-yet-existing items — Task 2+ uncomment them as items appear. Alternative (preferred if simpler): declare only `pub mod error; pub mod types;` now with empty files, and add each `mod` line in the task that creates the module. Choose one; the build must be green at the end of every task.

- [ ] **Step 5: Write README.md** (mirror `zcash_client_sqlite/README.md` structure: title, one-paragraph description, license section). Description: "An engine for migrating Zcash wallet funds from the Orchard value pool to the Ironwood value pool. The engine plans a note split into self-funding power-of-ten denominations, builds and signs migration transactions as PCZTs, schedules them by block height, and persists its state in the wallet database; the consuming application broadcasts the transactions and reports results back."

- [ ] **Step 6: Write CHANGELOG.md** (mirror sibling format/keepachangelog):

```markdown
# Changelog
All notable changes to this library will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this library adheres to Rust's notion of
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
Initial release of the Orchard → Ironwood value-pool migration engine.
```

- [ ] **Step 7: Verify.** Run: `cargo check -p zcash_pool_migration --all-features` → success. Run `cargo check --workspace --all-features` → success (proves workspace wiring didn't break siblings). Run `cargo fmt --all`.

- [ ] **Step 8: Commit.** `git add -A && git commit` — message: `zcash_pool_migration: Add crate scaffold` + body explaining the new workspace member and its purpose + Co-Authored-By trailer.

---

### Task 2: `error.rs`

**Files:**
- Create: `zcash_pool_migration/src/error.rs` (port of `PROTO/error.rs`, 186 lines)
- Modify: `zcash_pool_migration/src/lib.rs` (enable `pub mod error;` + re-exports)

**Interfaces:**
- Produces: `pub enum InvalidStateError { NoActiveRun, UnknownPhase(String), WrongPhase { expected: &'static str, found: String }, AlreadyComplete, NotApplicable(&'static str) }`;
  `#[non_exhaustive] pub enum MigrationError { NotSynced, NotInitialized, InvalidState(InvalidStateError), Db(rusqlite::Error), Backend(SqliteClientError), Pipeline(String) }`;
  `MigrationError::error_code(&self) -> u32` (NotSynced=1, NotInitialized=2, InvalidState=3, Db=4, Backend=5, Pipeline=6);
  `impl Display + std::error::Error (source() for Db/Backend)`;
  `From<rusqlite::Error>`, `From<SqliteClientError>`, `From<shardtree::error::ShardTreeError<E: fmt::Display>>` (→ `Pipeline`).

- [ ] **Step 1: Port the tests first.** Read `PROTO/error.rs`; copy its 4 `#[cfg(test)]` tests (`error_codes_are_stable_and_display_readable`, `usable_as_std_error_with_source`, `not_synced_and_not_initialized_display`, `invalid_state_display_variants`) into the new file under a stub enum so the file compiles but tests fail (or simply write tests + full port together and rely on Step 3's run — for a verbatim port, write tests first, confirm they fail to compile, then port the impl).
- [ ] **Step 2: Port the implementation.** Changes vs prototype: remove ALL `#[cfg(feature = "librustzcash-backend")]` gates (no feature tiers here — `Backend`/`Pipeline` variants and the `From` impls are unconditional); `SqliteClientError` imports from `zcash_client_sqlite::error::SqliteClientError`; add `#[non_exhaustive]` to `MigrationError` (repo rule: error enums are non-exhaustive); keep everything else byte-equivalent including error-code values and Display strings.
- [ ] **Step 3: Run.** `cargo test -p zcash_pool_migration --all-features error::` → 4 passed.
- [ ] **Step 4: Rustdoc.** Every public item documented (the prototype's docs are good starting points; document each error variant's meaning + when `error_code` values may be relied on by FFI).
- [ ] **Step 5: Commit** (`zcash_pool_migration: Add the migration error types`).

---

### Task 3: `types.rs`

**Files:**
- Create: `zcash_pool_migration/src/types.rs` (idiomatic reshape of `PROTO/types.rs` per spec §4.1/D8)
- Modify: `zcash_pool_migration/src/lib.rs` (enable re-exports)

**Interfaces (produces — later tasks call exactly these):**

```rust
pub struct TransferId(/* private String */);
impl TransferId {
    /// Run-scoped transfer id: "<run_id>:<index>". Constructed by the engine.
    pub(crate) fn for_transfer(run_id: &str, index: u32) -> Self;
    /// The note-split prep transaction id: "prep:<run_id>".
    pub(crate) fn for_prep(run_id: &str) -> Self;
    pub(crate) fn from_raw(raw: String) -> Self;      // for store round-trips
    pub fn as_str(&self) -> &str;
    pub(crate) fn is_prep(&self) -> bool;             // starts_with "prep:"
}
// + Display, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord

pub struct NoteSplitProposal { /* output_values: Vec<Zatoshis>, fee: Zatoshis */ }
impl NoteSplitProposal {
    pub fn from_parts(output_values: Vec<Zatoshis>, fee: Zatoshis) -> Self;
    pub fn output_values(&self) -> &[Zatoshis];
    pub fn fee(&self) -> Zatoshis;
}

pub struct TransferProposal { /* id, amount, anchor_height, next_executable_after_height, expiry_height */ }
impl TransferProposal {
    pub fn from_parts(id: TransferId, amount: Zatoshis, anchor_height: BlockHeight,
        next_executable_after_height: BlockHeight, expiry_height: BlockHeight) -> Self;
    pub fn id(&self) -> &TransferId;
    pub fn amount(&self) -> Zatoshis;                  // the turnstile crossing value
    pub fn anchor_height(&self) -> BlockHeight;
    pub fn next_executable_after_height(&self) -> BlockHeight;
    pub fn expiry_height(&self) -> BlockHeight;
}

pub struct MigrationSchedule { /* transfers, estimated_duration_hours */ }
impl MigrationSchedule {
    pub fn from_parts(transfers: Vec<TransferProposal>, estimated_duration_hours: u32) -> Self;
    pub fn transfers(&self) -> &[TransferProposal];
    pub fn estimated_duration_hours(&self) -> u32;
    pub fn is_empty(&self) -> bool;
}

pub struct MigrationProgress { /* completed, total, remaining_orchard_value, next_transfer_ready_at_height */ }
impl MigrationProgress {
    pub fn from_parts(completed_transfers: u32, total_transfers: u32,
        remaining_orchard_value: Zatoshis, next_transfer_ready_at_height: Option<BlockHeight>) -> Self;
    pub fn completed_transfers(&self) -> u32;
    pub fn total_transfers(&self) -> u32;
    pub fn remaining_orchard_value(&self) -> Zatoshis;
    pub fn next_transfer_ready_at_height(&self) -> Option<BlockHeight>;
}

pub struct PreparedTransfer { /* id, txid: TxId, pczt_bytes: Vec<u8> */ }
impl PreparedTransfer {
    pub(crate) fn from_parts(id: TransferId, txid: TxId, pczt_bytes: Vec<u8>) -> Self;
    pub fn id(&self) -> &TransferId;
    pub fn txid(&self) -> TxId;
    pub fn pczt_bytes(&self) -> &[u8];
    pub fn into_pczt_bytes(self) -> Vec<u8>;
}

pub struct UnsignedTransferPczt { /* id, pczt_bytes */ }
impl UnsignedTransferPczt {
    pub(crate) fn from_parts(id: TransferId, pczt_bytes: Vec<u8>) -> Self;
    pub fn id(&self) -> &TransferId;
    pub fn pczt_bytes(&self) -> &[u8];
}

pub struct SignedTransferPczt { /* id, pczt_bytes */ }
impl SignedTransferPczt {
    /// PUBLIC constructor — the platform builds these from the external signer's output.
    pub fn from_parts(id: TransferId, pczt_bytes: Vec<u8>) -> Self;
    pub fn id(&self) -> &TransferId;
    pub fn pczt_bytes(&self) -> &[u8];
}

pub enum MigrationState {
    NotStarted, SplitPendingConfirmation, ReadyToPropose,
    InProgress(MigrationProgress), RequiresAttention(AttentionReason), Complete,
}
pub enum AttentionReason { InvalidTransfer(TransferId), TransferExpired, SyncRequiredBeforeNext }
pub enum TransferResult { Success(TxId), NetworkError { retryable: bool }, InvalidNote, Expired }
```

All types: `Debug + Clone + PartialEq` (+ `Eq` where all members allow). `TxId` from `zcash_protocol::TxId` (single import path crate-wide — do NOT also import it via `zcash_primitives`).

- [ ] **Step 1: Write tests** — constructor/accessor round-trips replace the prototype's serde tests. Real test code to include:

```rust
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
```

…plus analogous round-trip tests for `TransferProposal`, `MigrationSchedule` (incl. `is_empty`), `MigrationProgress`, `PreparedTransfer` (txid + `into_pczt_bytes`), `UnsignedTransferPczt`/`SignedTransferPczt`, and simple variant-construction tests for the three enums.
- [ ] **Step 2: Run to fail** (`cargo test -p zcash_pool_migration --all-features types::` — compile errors count as red).
- [ ] **Step 3: Implement** the types exactly as the Interfaces block. Rustdoc every public item (crib semantics from `PROTO/types.rs` doc comments — e.g. `TransferProposal::amount` documents the crossing-vs-note-value distinction).
- [ ] **Step 4: Run to pass.**
- [ ] **Step 5: Commit** (`zcash_pool_migration: Add the public migration data types`).

---

### Task 4: `denominations.rs`

**Files:**
- Create: `zcash_pool_migration/src/denominations.rs` — port of `PROTO/denominations.rs` (165 lines), near-verbatim.

**Interfaces:**
- Produces (all `pub(crate)`): `const ZATOSHIS_PER_ZEC: u64 = 100_000_000;`, `const MIGRATION_MAX_PREPARED_NOTES_PER_RUN: usize = 64;`, `const TRANSFER_FEE_BUFFER_ZATOSHI: u64 = 20_000;`,
  `struct DenominationPlan { migration_outputs: Vec<u64>, crossing_values: Vec<u64>, orchard_change: Option<u64>, prep_fee_zatoshi: u64, total_input_zatoshi: u64, total_migratable_zatoshi: u64 }` (fields `pub(crate)`),
  `fn plan_denominations(total_input_zatoshi: u64, prep_fee_zatoshi: u64) -> Result<DenominationPlan, String>`.

- [ ] **Step 1: Port the 7 tests verbatim** from `PROTO/denominations.rs` (`each_output_is_power_of_ten_plus_self_funding_buffer`, `dust_is_left_in_orchard_never_folded_into_fee`, `exact_funding_leaves_no_change`, `sub_one_zec_input_migrates_nothing_keeps_all_in_orchard`, `noops_when_prep_fee_consumes_balance`, `reserves_prep_fee_before_decomposition`, `rejects_more_than_max_prepared_outputs`). Keep names and assertion values identical.
- [ ] **Step 2: Run to fail.**
- [ ] **Step 3: Port the implementation verbatim** (pure u64 arithmetic; no upstream types involved; keep the checked-arithmetic style and the Apache-provenance module doc comment, updating the "ported from" note to cite vizor + the prototype crate).
- [ ] **Step 4: Run to pass** (7 tests).
- [ ] **Step 5: Commit** (`zcash_pool_migration: Add self-funding power-of-ten denomination planning`).

---

### Task 5: `scheduling.rs`

**Files:**
- Create: `zcash_pool_migration/src/scheduling.rs` — port of `PROTO/scheduling.rs` (178 lines).

**Interfaces:**
- Consumes: `TransferId::for_transfer`, `TransferProposal::from_parts`, `MigrationSchedule::from_parts` (Task 3).
- Produces (`pub(crate)`): `const TRANSFER_CADENCE_BLOCKS: u32 = 288;`, `const TRANSFER_EXPIRY_WINDOW_BLOCKS: u32 = 288;`, `const BLOCKS_PER_HOUR: u32 = 48;`,
  `fn build_schedule(run_id: &str, crossing_values: &[u64], target_height: u32, natural_anchor: u32, first_delay_blocks: u32) -> MigrationSchedule`.

- [ ] **Step 1: Port the 7 tests** from `PROTO/scheduling.rs`, adapting assertions to the Task-3 accessors (e.g. `t.anchor_height()` returns `BlockHeight` — compare against `BlockHeight::from_u32(...)`; `t.amount()` returns `Zatoshis`). Keep test names + numeric expectations identical (`schedule_is_empty_for_no_amounts`, `schedule_shares_one_natural_anchor_across_transfers`, `schedule_staggers_send_and_expiry_heights`, `schedule_maps_amounts_in_order`, `schedule_transfer_ids_are_unique_and_carry_run_id`, `estimated_duration_spans_to_the_last_window`, `immediate_schedule_has_no_first_delay`).
- [ ] **Step 2: Run to fail.**
- [ ] **Step 3: Port the implementation** — inside, convert to the Task-3 constructors: `TransferProposal::from_parts(TransferId::for_transfer(run_id, i as u32), Zatoshis::const_from_u64(*v), BlockHeight::from_u32(natural_anchor), BlockHeight::from_u32(target_height + first_delay_blocks + i as u32 * TRANSFER_CADENCE_BLOCKS), BlockHeight::from_u32(<send> + TRANSFER_EXPIRY_WINDOW_BLOCKS))`. `Zatoshis::const_from_u64` panics only on > MAX_MONEY — crossing values come from `plan_denominations`, always ≤ MAX_MONEY; if the prototype used fallible conversion, mirror it. Keep the module-doc NOTE about why bucketed anchors were abandoned (it documents spec D5 rationale).
- [ ] **Step 4: Run to pass.**
- [ ] **Step 5: Commit** (`zcash_pool_migration: Add height-based transfer scheduling`).

---

### Task 6: `state.rs`

**Files:**
- Create: `zcash_pool_migration/src/state.rs` — port of `PROTO/state.rs` (234 lines), verbatim except types.

**Interfaces:**
- Consumes: `MigrationState`, `MigrationProgress`, `AttentionReason` (Task 3).
- Produces (`pub(crate)`): `enum Phase` (14 variants: NoOrchardFunds, WaitingForSpendableOrchard, ReadyToPrepare, PreparingDenominations, WaitingDenomConfirmations, ReadyToMigrate, BroadcastScheduled, Broadcasting, WaitingMigrationConfirmations, Complete, Paused, FailedRecoverable, FailedTerminal, Abandoned) with `as_str() -> &'static str` / `parse(&str) -> Option<Phase>` (vizor-compatible strings, e.g. `"waiting_denom_confirmations"`),
  `fn to_state(phase: Phase, progress: MigrationProgress, attention: Option<AttentionReason>) -> MigrationState`.

- [ ] **Step 1: Port the 10 tests** (names/assertions identical; adapt constructor calls to Task-3 `from_parts`).
- [ ] **Step 2: Run to fail.**
- [ ] **Step 3: Port the implementation** (pure; phase strings must stay byte-identical to the prototype — they are persisted).
- [ ] **Step 4: Run to pass.**
- [ ] **Step 5: Commit** (`zcash_pool_migration: Add the migration phase state machine`).

---

### Task 7: `store.rs`

**Files:**
- Create: `zcash_pool_migration/src/store.rs` — port of `PROTO/store.rs` (922 lines).

**Interfaces:**
- Produces (`pub(crate)`, signatures as in the prototype unless noted): `fn init(conn: &rusqlite::Connection) -> Result<(), rusqlite::Error>` (creates the 5 `ext_ironwood_migration_*` tables + 2 indexes, `IF NOT EXISTS`);
  structs `NewRun`, `RunRow`, `PreparedNote`, `PendingTxRow`, `PrepTxRow`, `StagedPczt`, `PendingTotals`;
  consts `STAGED_KIND_SPLIT`, `STAGED_KIND_TRANSFER`, `TERMINAL_PHASES`;
  fns `insert_run`, `run_by_id`, `active_run`, `set_phase`, `insert_prepared_notes`, `locked_note_refs`, `insert_pending_txs`, `next_due_transfer`, `next_scheduled_send_height`, `broadcasted_txids`, `mark_pending_status`, `pending_totals`, `clear_scheduled_pending`, `insert_prep_tx`, `prep_tx`, `set_prep_tx_status`, `upsert_staged_pczt`, `staged_pczts`, `clear_staged_pczts`;
  **NEW:** `fn has_due_transfer(conn: &Connection, run_id: &str, tip_height: u32) -> Result<bool, rusqlite::Error>` — `SELECT EXISTS(SELECT 1 FROM ext_ironwood_migration_pending_txs WHERE run_id = ?1 AND status = 'scheduled' AND next_executable_after_height <= ?2)`; does not load PCZT blobs (spec §4.3 `has_overdue_transfers`).

- [ ] **Step 1: Port all 21 store tests verbatim** (tempfile-backed sqlite; names in the spec §6.1 list, starting `schema_uses_ext_prefix` asserting **5** tables) and ADD:

```rust
#[test]
fn has_due_transfer_matches_next_due_without_loading_blobs() {
    let (_dir, conn) = test_conn();               // reuse the ported test helper
    // seed one run + one pending tx scheduled at height 100 via insert_run/insert_pending_txs
    // (copy the seeding pattern from the ported next_due_returns_earliest_scheduled_at_or_below_tip test)
    assert!(!has_due_transfer(&conn, run_id, 99).unwrap());
    assert!(has_due_transfer(&conn, run_id, 100).unwrap());
}
```

- [ ] **Step 2: Run to fail.**
- [ ] **Step 3: Port the implementation.** Changes vs prototype: none semantic. Keep `run_by_id`'s `#[allow(dead_code)]` + comment if the facade still doesn't use it at the end of Task 11 — re-check then. Timestamps: the prototype used wall-clock ms (`created_at_ms`) via `SystemTime` — keep identical.
- [ ] **Step 4: Run to pass** (22 tests).
- [ ] **Step 5: Commit** (`zcash_pool_migration: Add the ext_ironwood_migration_* persistence layer`).

---

### Task 8: `reserved_source.rs`

**Files:**
- Create: `zcash_pool_migration/src/reserved_source.rs` — port of `PROTO/reserved_source.rs` (192 lines) onto the CURRENT upstream `InputSource` shape.

**Interfaces:**
- Produces (`pub(crate)`):

```rust
pub(crate) struct ReservedInputSource<'a, DbT: InputSource> {
    inner: &'a DbT,
    reserved: &'a BTreeSet<DbT::NoteRef>,
    migration_locks: &'a BTreeSet<(String, u32)>,   // (lowercase txid hex, output index)
}
impl<'a, DbT: InputSource> ReservedInputSource<'a, DbT> {
    pub(crate) fn new(inner: &'a DbT, reserved: &'a BTreeSet<DbT::NoteRef>,
        migration_locks: &'a BTreeSet<(String, u32)>) -> Self;
}
impl<'a, DbT: InputSource> InputSource for ReservedInputSource<'a, DbT> { /* delegating; filters below */ }
```

- Upstream trait: `zcash_client_backend::data_api::InputSource` (`zcash_client_backend/src/data_api.rs:1578`). Methods to implement (copy exact current signatures from that file — they changed from the fork):
  - `get_spendable_note(&self, txid: &TxId, protocol: ShieldedPool, index: u32, target_height: TargetHeight) -> Result<Option<ReceivedNote<Self::NoteRef, Note>>, Self::Error>` — delegate, then `.filter(|n| !self.reserved.contains(n.internal_note_id()) && !self.note_is_locked(n))`.
  - `select_spendable_notes(&self, account, target_value: TargetValue, sources: &[ShieldedPool], target_height: TargetHeight, confirmations_policy: ConfirmationsPolicy, exclude: &[Self::NoteRef]) -> Result<ReceivedNotes<Self::NoteRef>, Self::Error>` — delegate with `merged_excludes(exclude)`, then post-filter the **orchard** vec by `!note_is_locked` (sapling/ironwood pass through). Rebuild `ReceivedNotes` — check how it's constructed upstream (`ReceivedNotes::new(...)` or per-pool setters; read `zcash_client_backend/src/data_api.rs:967` and mirror whatever constructor exists; if fields are only readable, collect + reconstruct via its `from_parts`-style API — find it with `rg "impl.*ReceivedNotes" zcash_client_backend/src/data_api.rs`).
  - `select_unspent_notes(...)` (same delegation+filter pattern; signature at `data_api.rs:1623`).
  - `get_account_metadata(&self, account, selector: &NoteFilter, target_height, exclude) -> Result<AccountMeta, _>` — delegate with merged excludes.
  - `#[cfg(feature = "transparent-inputs")]` methods: this crate does NOT enable `transparent-inputs`; upstream's defaults (`unimplemented!()`/default impls) apply — do not implement them. If the compiler demands them anyway (feature unification from `zcash_client_sqlite`), delegate 1:1 to `inner` with zero filtering, matching the prototype.
- Keep helpers `merge_excludes`, `is_locked`, `merged_excludes`, `note_is_locked` and their 3 unit tests verbatim (`merge_excludes_unions_sorts_dedups`, `merge_excludes_with_empty_reserved_is_sorted_dedup_excludes`, `is_locked_matches_lowercased_txid_and_index`).

- [ ] **Step 1: Port the 3 helper tests** (pure; no DB) → run to fail.
- [ ] **Step 2: Implement helpers** → tests pass.
- [ ] **Step 3: Implement the `InputSource` impl** against the real trait (compile-verified; e2e coverage arrives in Task 13). `cargo check -p zcash_pool_migration --all-features` must pass.
- [ ] **Step 4: Run all crate tests; fmt; commit** (`zcash_pool_migration: Add the reserving InputSource adapter`).

---

### Task 9: `split.rs`

**Files:**
- Create: `zcash_pool_migration/src/split.rs` — port of `PROTO/split.rs` (437 lines) MINUS the transfer builder (transfers move to the high-level path in Task 10; `build_transfer_pczt` is NOT ported).

**Interfaces:**
- Consumes: `ReservedInputSource` (Task 8), `store::locked_note_refs` output shape (Task 7).
- Produces (`pub(crate)`):
  - `const MARGINAL_FEE_ZATOSHI: u64 = 5_000;` `const GRACE_ACTIONS: u64 = 2;`
  - `fn split_fee(n_spends: usize, n_changes: usize) -> u64` — `5000 * max(spends + changes, 2)` (ZIP-317, Orchard-only tx).
  - `fn adjust_outputs_for_exact_balance(selected_total: u64, fee: u64, outputs: &[u64]) -> Result<Vec<u64>, MigrationError>` — last output absorbs residual; errors on non-positive last output / fee > total / empty outputs.
  - `fn select_spendable_orchard_notes<P: Parameters>(db: &Db<P>, account: AccountUuid, migration_locks: &BTreeSet<(String, u32)>) -> Result<Vec<ReceivedNote<ReceivedNoteId, orchard::note::Note>>, MigrationError>` — select ALL unspent Orchard-pool notes via `ReservedInputSource` + `InputSource::select_unspent_notes(account, &[ShieldedPool::Orchard], target_height, &[])`, take the orchard vec. (Upstream tracks Ironwood as a separate pool, so Orchard-pool selection already excludes V3 notes; keep the prototype's explicit `note.version() == NoteVersion::V2`-style filter only if `orchard::note::Note` still exposes `version()` — otherwise drop it and note why in a comment.)
  - `fn build_split_pczt<P: Parameters + Clone>(db: &mut Db<P>, network: &P, account: AccountUuid, orchard_fvk: &orchard::keys::FullViewingKey, migration_locks: &BTreeSet<(String, u32)>, outputs: &[u64]) -> Result<(pczt::Pczt, Vec<(u32, u64)>), MigrationError>` — returns the unsigned PCZT + `(shuffled_action_index, value)` per denomination output.
- `Db<P>` type alias comes from Task 10's `backend.rs`; to keep this task self-contained, define it HERE and have `backend.rs` re-use it: `pub(crate) type Db<P> = zcash_client_sqlite::WalletDb<rusqlite::Connection, P, zcash_client_sqlite::util::SystemClock, rand::rngs::OsRng>;`

**Port adaptations for `build_split_pczt`** (follow `PROTO/split.rs:136-257` structure):
1. Anchor/witnesses: unchanged pattern — `db.with_orchard_tree_mut(|tree| { let anchor = tree.root_at_checkpoint_id(&anchor_height)?...; per-note tree.witness_at_checkpoint_id_caching(position, &anchor_height) })`. Confirm method names against `zcash_client_backend/src/data_api.rs` `WalletCommitmentTrees` (`with_orchard_tree_mut` at ~`:3740`; exact closure error plumbing — mirror an existing call site, e.g. in `zcash_client_backend/src/data_api/wallet.rs:1379-1418`).
2. Builder: `Builder::new(network.clone(), target_height_as_blockheight, BuildConfig::Standard { sapling_anchor: None, orchard_anchor: Some(anchor), ironwood_anchor: None })` (`zcash_primitives/src/transaction/builder.rs:258`). The prototype passed no expiry override for the split (default ~40-block expiry is CORRECT here — the split broadcasts immediately); keep that.
3. Spends: `builder.add_orchard_spend::<Infallible>(&sk_or_fvk_source, note, merkle_path)` — copy the prototype call shape, updating to the current upstream signature (check `builder.rs:~740` for `add_orchard_spend`; it may take `FullViewingKey` + note + `MerklePath`).
4. Denomination outputs: `builder.add_orchard_change_output::<Infallible>(orchard_fvk, /* internal scope value+empty memo per current signature */)` per output (`builder.rs:763`) — same-account internal outputs keep value in the Orchard V2 pool.
5. Tx version: the builder derives the version from `network` + `target_height`; post-NU6.3 that is V6 and the orchard bundle uses `BundleVersion::orchard_v3()` automatically (`builder.rs:321-322`). No version parameter exists — do not try to force one.
6. `let build_result = builder.build_for_pczt(OsRng, &Zip317FeeRule::standard())?;` then map output indices: `build_result.orchard_meta.output_action_index(i)` for each denomination output `i` → `(index as u32, value)` pairs.
7. PCZT assembly: `pczt::roles::creator::Creator::build_from_parts(build_result.pczt_parts).ok_or(...)` → `pczt::roles::io_finalizer::IoFinalizer::new(pczt).finalize_io()?`.
8. Map every heterogeneous error into `MigrationError::Pipeline(format!(...))` exactly as the prototype does.

- [ ] **Step 1: Port the 6 pure-fn tests** (`split_fee_is_marginal_fee_times_actions`, `split_fee_applies_the_two_action_grace_floor`, `adjust_keeps_outputs_when_balance_is_exact`, `adjust_absorbs_the_residual_in_the_last_output`, `adjust_rejects_a_nonpositive_last_output`, `adjust_rejects_fee_exceeding_total_and_empty_outputs`) → fail → implement `split_fee` + `adjust_outputs_for_exact_balance` → pass.
- [ ] **Step 2: Implement `select_spendable_orchard_notes` + `build_split_pczt`** per the adaptation list (compile-verified here; exercised e2e in Task 13). `cargo check -p zcash_pool_migration --all-features` green.
- [ ] **Step 3: Full crate tests; fmt; commit** (`zcash_pool_migration: Add note-split PCZT construction`).

---

### Task 10: `backend.rs`

**Files:**
- Create: `zcash_pool_migration/src/backend.rs` — port of `PROTO/backend.rs` (583 lines) with the transfer pipeline moved to upstream high-level APIs (spec D4/D5).

**Interfaces:**
- Consumes: `Db<P>` (Task 9), `ReservedInputSource` (Task 8), store row types (Task 7), `split::build_split_pczt` (Task 9).
- Produces (`pub(crate)`):
  - `struct PoolBalances { orchard_spendable: u64, ironwood_total: u64 }` + `fn pool_balances<P: Parameters>(db: &Db<P>) -> Result<PoolBalances, MigrationError>` — from `db.get_wallet_summary(...)` → `summary.account_balances()[&account]`, `orchard_balance().spendable_value()`, `ironwood_balance().total()`. (Check the current `get_wallet_summary` signature — it takes a `ConfirmationsPolicy` or min-confirmations; mirror an existing caller found via `rg "get_wallet_summary\(" zcash_client_sqlite/src`.)
  - `fn open_wallet<P: Parameters + Clone>(db_path: &Path, network: P) -> Result<Db<P>, MigrationError>` — `WalletDb::for_path(path, network, SystemClock, OsRng)`.
  - `fn account_orchard_fvk<P: Parameters>(db: &Db<P>, account: AccountUuid) -> Result<orchard::keys::FullViewingKey, MigrationError>` — via `WalletRead::get_account` → `.ufvk()` → `.orchard()`.
  - `fn target_and_anchor<P: Parameters>(db: &Db<P>) -> Result<(u32, u32), MigrationError>` — `get_target_and_anchor_heights(ConfirmationsPolicy::default().trusted())`-equivalent (verify the exact current API with `rg "get_target_and_anchor_heights" zcash_client_backend/src/data_api.rs`); `Err(MigrationError::NotSynced)` when `None`.
  - `fn is_tx_mined<P: Parameters>(db: &Db<P>, txid: TxId) -> Result<bool, MigrationError>` — `WalletRead::get_tx_height`.
  - `fn self_payment_request<P: Parameters>(db: &Db<P>, network: &P, account: AccountUuid, value: Zatoshis) -> Result<zip321::TransactionRequest, MigrationError>` — `WalletRead::get_last_generated_address_matching(account, UnifiedAddressRequest::AllAvailableKeys)` (signature at `zcash_client_backend/src/data_api.rs:1924`; adapt the request-enum variant to whatever the current `UnifiedAddressRequest` offers for "orchard-capable") → `addr.to_zcash_address(network.network_type())` → `Payment::without_memo(zaddr, value)` → `TransactionRequest::new(vec![payment])`.
  - `fn propose_migration_transfer<'a, P: Parameters + Clone>(db: &Db<P>, network: &P, account: AccountUuid, target_height: u32, anchor_height: u32, reserved: &BTreeSet<ReceivedNoteId>, locks: &BTreeSet<(String, u32)>, request: TransactionRequest) -> Result<Proposal<Zip317FeeRule, ReceivedNoteId>, MigrationError>` — build `ReservedInputSource::new(db, reserved, locks)`; change strategy `MultiOutputChangeStrategy::new(Zip317FeeRule::standard(), None, <change-pool>, DustOutputPolicy::default(), SplitPolicy::single_output())` — read the CURRENT constructor at `zcash_client_backend/src/fees/zip317.rs:163-201` and pass the shielded change-pool argument it expects (start with `ShieldedProtocol::Orchard` as the prototype did; if e2e Task 13 shows change must route to Ironwood explicitly, switch — record which); selector `GreedyInputSelector::new()`; call `InputSelector::propose_transaction(network, &reserved_source, TargetHeight-wrapped target, BlockHeight::from_u32(anchor_height), ConfirmationsPolicy::default(), account, request, &change_strategy, &spend_policy, Some(TxVersion::V6))` (full current signature at `zcash_client_backend/src/data_api/wallet/input_selection.rs:203` — includes `spend_policy: &SpendPolicy`; use `SpendPolicy::shielded_pools([ShieldedPool::Orchard])` if such a constructor exists — check `input_selection.rs:492-508` — so transfers only ever spend Orchard-pool notes).
  - `fn sweep_crossing_value<P: Parameters + Clone>(...) -> Result<Option<u64>, MigrationError>` — port from `PROTO/backend.rs:238` (probes `InputSelectorError::InsufficientFunds { available, required }` to derive the max sweepable value; verify the variant fields compile, else adapt the match).
  - Proving keys: `fn orchard_proving_key() -> &'static orchard::circuit::ProvingKey` and `fn ironwood_proving_key() -> &'static orchard::circuit::ProvingKey` as `OnceLock` statics. The orchard 0.15 construction API differs from the fork's `BundleProtocol` — find the exact calls with `rg "ProvingKey::build" pczt/ zcash_client_backend/ zcash_primitives/` (the pczt end-to-end tests and wallet code construct both keys); mirror those call sites (spec §10.2).
  - `struct SignedPcztOutcome { txid: TxId, pczt_bytes: Vec<u8> }` (rename of prototype `SignedPczt`).
  - `fn prove_pczt(pczt: pczt::Pczt) -> Result<pczt::Pczt, MigrationError>` — `Prover::new(pczt)`; if `requires_orchard_proof()` → `create_orchard_proof(orchard_proving_key())?`; if `requires_ironwood_proof()` → `create_ironwood_proof(ironwood_proving_key())?`; `finish()`.
  - `fn sign_all_orchard_spends(pczt: pczt::Pczt, usk: &UnifiedSpendingKey) -> Result<pczt::Pczt, MigrationError>` — port the prototype probe loop (`PROTO/backend.rs:302-341`): `Signer::new(pczt)`, `ask = orchard::keys::SpendAuthorizingKey::from(usk.orchard())`, loop `signer.sign_orchard(index, &ask)` from 0 upward, `break` on `Error::InvalidIndex`, ignore `Error::OrchardSign(WrongSpendAuthorizingKey)` (decoy/padding positions); verify the current error-variant paths in `pczt/src/roles/signer/mod.rs`.
  - `fn prove_sign_finalize(pczt: pczt::Pczt, usk: &UnifiedSpendingKey) -> Result<SignedPcztOutcome, MigrationError>` — prove → sign → `SpendFinalizer::new(p).finalize_spends()?` → `bytes = p.serialize()` → txid via `TransactionExtractor::new(p).extract()?.txid()`. NOTE: check whether `TransactionExtractor` consumes the PCZT (it does — extract AFTER serializing, exactly like the prototype).
  - `fn combine_signed_pczt(proven: &[u8], signed: &[u8]) -> Result<SignedPcztOutcome, MigrationError>` — `Pczt::parse` both → `Combiner::new(vec![proven, signed]).combine()` → SpendFinalizer → serialize + extract (port `PROTO/backend.rs:367-405`).
  - `fn extract_broadcast_tx(pczt_bytes: &[u8]) -> Result<Vec<u8>, MigrationError>` — parse → extract → `tx.write(&mut buf)`.
  - `fn create_transfer_pczt<P: Parameters + Clone>(db: &mut Db<P>, network: &P, account: AccountUuid, proposal: &Proposal<Zip317FeeRule, ReceivedNoteId>, expiry_height: u32) -> Result<pczt::Pczt, MigrationError>` — **the new high-level piece replacing `PROTO/split.rs::build_transfer_pczt`:** `create_pczt_from_proposal(db, network, account, OvkPolicy::Sender, proposal, Some(BlockHeight::from_u32(expiry_height)))` (`zcash_client_backend/src/data_api/wallet.rs:2272`; map its error into `Pipeline`).
  - Anchor pinning (spec D5): `fn retain_anchor<P: Parameters>(db: &mut Db<P>, anchor_height: u32) -> Result<(), MigrationError>` — `db.with_orchard_tree_mut(|t| t.ensure_retained(BlockHeight::from_u32(anchor_height)))` and the same on `with_ironwood_tree_mut`; `fn release_retained_anchors<P: Parameters>(db: &mut Db<P>, below: u32)` — `WalletCommitmentTrees::remove_retained_checkpoints_below(BlockHeight::from_u32(below))` (`zcash_client_backend/src/data_api.rs:3810`). Verify exact shardtree method name via `rg "ensure_retained" zcash_client_sqlite/src zcash_client_backend/src` and mirror a call site. If `ensure_retained` turns out to require the checkpoint to already exist and errors otherwise, treat failure as non-fatal (log-and-continue semantics: wrap in `let _ = …;` with a comment) — pinning is hardening, not correctness (witnesses bake at sign time).
  - Orchestrators, ported from `PROTO/backend.rs:477-583` with the new pipeline:
    - `fn sign_schedule<P>(db: &mut Db<P>, network: &P, account: AccountUuid, conn: &Connection, run_id: &str, schedule: &MigrationSchedule, usk: &UnifiedSpendingKey) -> Result<(), MigrationError>` — resolve `(target, anchor)`; `retain_anchor(db, anchor)`; per transfer: `self_payment_request(crossing value)` → `propose_migration_transfer` (reserving each proposal's input notes into `reserved` so later transfers exclude them — port `proposal_note_refs` from `PROTO/backend.rs:439`) → `create_transfer_pczt(..., transfer.expiry_height())` → `prove_sign_finalize` → build `PendingTxRow` (port `pending_row` from `PROTO/backend.rs:453`: values, fee from `proposal.steps().head.balance().fee_required()`, selected-note triple from the reserved note, heights from the `TransferProposal`) → `store::insert_pending_txs`; after the loop `release_retained_anchors(db, anchor)`.
    - `fn sign_split<P>(db: &mut Db<P>, network: &P, account: AccountUuid, conn: &Connection, run_id: &str, proposal: &NoteSplitProposal, usk: &UnifiedSpendingKey) -> Result<SignedPcztOutcome, MigrationError>` — `split::build_split_pczt` → `prove_sign_finalize` → `store::insert_prep_tx` + `store::insert_prepared_notes` (note_version = 2, values at shuffled action indices).

- [ ] **Step 1: Port the 1 pure test** (`build_self_payment_creates_single_payment_for_amount`, adapting to `self_payment_request`'s pure inner helper — keep the prototype's split into a testable `build_self_payment(addr, value)` helper) → fail → implement helper → pass.
- [ ] **Step 2: Implement everything else** per the interface list (compile-verified; e2e in Task 13). Iterate with `cargo check -p zcash_pool_migration --all-features` until green; resolve each "verify current signature" note by reading the referenced upstream file — never by guessing.
- [ ] **Step 3: Crate tests green; clippy for this crate:** `cargo clippy -p zcash_pool_migration --all-features --all-targets -- -D warnings`. Fix everything (expect `too_many_arguments` allows like the prototype — keep them targeted).
- [ ] **Step 4: fmt; commit** (`zcash_pool_migration: Add the wallet backend and PCZT signing pipeline`).

---

### Task 11: `context.rs` — facade, software-signing path

**Files:**
- Create: `zcash_pool_migration/src/context.rs` — port of `PROTO/context.rs` lines 1–320 + 616–883 (everything EXCEPT the external-signer methods, which are Task 12).
- Modify: `zcash_pool_migration/src/lib.rs` (enable `pub use context::MigrationContext;`)

**Interfaces:**
- Consumes: everything above.
- Produces (public — spec §4.3): `MigrationContext<P: Parameters + Clone>` with `new(db_path: &Path, network: P, account: AccountUuid) -> Result<Self, MigrationError>` and methods `migration_state`, `migration_progress`, `is_note_split_needed`, `prepare_note_split`, `sign_note_split(&NoteSplitProposal, &UnifiedSpendingKey)`, `propose_migration_transfers`, `propose_immediate_migration_transfers`, `sign_and_store_migration_schedule(&MigrationSchedule, &UnifiedSpendingKey)`, `is_sync_required_before_next_transfer`, `next_due_transfer`, `extract_broadcast_tx(&[u8])`, `record_transfer_result(&TransferId, TransferResult)`, `has_overdue_transfers`, `has_invalid_transfers`, `refresh_stale_transfers(&UnifiedSpendingKey)`, `restart_current_migration_step` — semantics exactly per `PROTO/context.rs` (the per-method step-by-step behavior is catalogued in the spec §4.3/§5.3 and readable in the prototype).

**Port adaptations:**
1. `new` stores `db_path: PathBuf`, `network: P`, `account: AccountUuid`; calls the store-init connection helper (port `store_conn` from `PROTO/context.rs:72`). NO `initialize_post_upgrade` method (spec D7).
2. USK: methods take `&UnifiedSpendingKey` — delete the prototype's `parse_usk` byte-parsing (FFI's job now).
3. `has_overdue_transfers` uses `store::has_due_transfer` (Task 7) at the current target height — no blob loading.
4. `record_transfer_result(id, result)`: match on `id.is_prep()` for the split path (replaces the prototype's string-prefix check); `TransferResult::Success(txid)` carries `TxId` — convert to the store's hex representation with the SAME lowercase-display-hex convention the store tests use (`txid.to_string().to_lowercase()`; verify against how `PROTO/context.rs:762-806` normalized).
5. `migration_state()` reconciliation hub ports 1:1 (`PROTO/context.rs:113-185`), including: marking mined broadcasted txs confirmed (`backend::is_tx_mined`), split-phase advancement (prep tx mined AND `orchard_spendable > 0` → set `ReadyToMigrate`), completion detection (all confirmed AND orchard == 0 AND ironwood > 0 → `Complete`).
6. `attention_from_error` classifier and `new_run_id()` (uuid v4) port verbatim.
7. `FEE_ESTIMATE_ZATOSHI = 10_000` const stays (planning-time estimate; actual fee from proposal at sign time).

- [ ] **Step 1: Port the non-external-signer context tests** from `PROTO/context.rs` (`new_creates_tables_and_state_is_not_started`, `attention_from_error_classifies`, `has_invalid_transfers_is_false_while_awaiting_denom_confirmations`, `has_invalid_transfers_is_false_when_ready_to_migrate`) — these use tempfile DBs + direct store writes, no wallet needed. CAREFUL: `new_creates_tables_...` requires `MigrationContext::new` on a path with no wallet DB — the prototype only touched the migration tables in `new`; preserve that (wallet DB opens lazily per operation).
- [ ] **Step 2: Run to fail; implement; run to pass.**
- [ ] **Step 3: Whole-crate check + clippy + fmt.** Re-check `store::run_by_id` dead-code status; if still unused, keep the prototype's `#[allow(dead_code)]` + comment.
- [ ] **Step 4: Commit** (`zcash_pool_migration: Add the MigrationContext facade`).

---

### Task 12: `context.rs` — external-signer (Keystone) flow

**Files:**
- Modify: `zcash_pool_migration/src/context.rs` — port `PROTO/context.rs:324-615` (+ its tests at `:1156-1460`).

**Interfaces:**
- Produces (public): `create_unsigned_note_split_pczt(&self) -> Result<Vec<u8>, MigrationError>`, `store_signed_note_split_pczt(&self, signed_pczt: &[u8]) -> Result<PreparedTransfer, MigrationError>`, `create_unsigned_transfer_pczts(&self, schedule: &MigrationSchedule) -> Result<Vec<UnsignedTransferPczt>, MigrationError>`, `store_signed_schedule_pczts(&self, signed: &[SignedTransferPczt]) -> Result<(), MigrationError>`.

**Port notes:** semantics 1:1 with the prototype (staging in `ext_ironwood_migration_staged_pczts` under kinds `split`/`transfer`; proven-unsigned out, `Combiner`-merge on the way back; all-or-nothing validation: reject empty/duplicate/partial/unknown-id sets; atomic run+rows insert + staged clear). The split staging metadata struct (`SplitStagingMetadata { output_notes, placed_outputs }`) was serde-serialized to the `metadata_json` column in the prototype — REPLACE serde with a tiny hand-rolled encoding (the store column is a private implementation detail): encode as the existing JSON shape manually via `format!` + parse with minimal string parsing, OR simpler: store the two vecs in a compact `"v1;notes=a,b,c;placed=i:v,i:v"` string with a version prefix (serialized data must be versioned — repo rule). Choose ONE, document it on the column's rustdoc, and cover with a round-trip unit test. Do NOT add a serde/serde_json dependency (D3).

- [ ] **Step 1: Port the validation tests** (the 10 no-wallet tests: `store_signed_note_split_pczt_without_staged_split_is_invalid_state`, `..._with_undecodable_pczt_stores_nothing`, `store_signed_schedule_pczts_rejects_empty_input`, `..._without_staged_rows_is_invalid_state`, `..._rejects_a_partial_set`, `..._rejects_duplicate_ids`, `..._rejects_an_unknown_id`, `..._is_all_or_nothing_on_undecodable_pczts`, `create_unsigned_transfer_pczts_rejects_an_empty_schedule`, `..._rejects_duplicate_transfer_ids`) + a new `staging_metadata_round_trips` test for the hand-rolled encoding → fail → implement → pass.
- [ ] **Step 2: Port the real-PCZT round-trip tests** (`store_signed_note_split_pczt_round_trips_an_externally_signed_split`, `store_signed_schedule_pczts_round_trips_externally_signed_transfers`, `store_signed_schedule_pczts_rejects_swapped_pairings` from `PROTO/context.rs:1166-1460`): they fabricate an in-memory Orchard note + single-leaf shardtree, build a PCZT, prove with the ORCHARD proving key, emulate device signing, and hand the signed PCZT back. Adaptations: orchard 0.15 API for note fabrication (check `Rho`/`RandomSeed`/`ExtractedNoteCommitment` paths compile; mirror `pczt/tests/end_to_end.rs` where the prototype's fork idioms fail); proving-key call from Task 10. These tests PROVE — if they are slower than ~60s each under the default test profile, move them behind `#[cfg(feature = "expensive-tests")]` and note it in the task commit message.
- [ ] **Step 3: Whole-crate green + clippy + fmt; commit** (`zcash_pool_migration: Add the external-signer PCZT flow`).

---

### Task 13: End-to-end integration tests (seeded wallet)

**Files:**
- Create: `zcash_pool_migration/tests/migration_e2e.rs`

**Interfaces:**
- Consumes: the full public facade + `zcash_client_backend::data_api::testing` / `zcash_client_sqlite` `test-dependencies`.

**Approach.** This closes the prototype's "backend compile-verified only" gap (spec D10). Study before writing: (a) `zcash_client_backend/src/data_api/testing.rs` (TestState/TestBuilder core), (b) `zcash_client_backend/src/data_api/testing/pool.rs` (Ironwood-aware pool tests — find how they activate NU6.3, fund an account with Orchard notes, scan generated blocks, and how `create_pczt_from_proposal` tests drive proving/signing — `rg -n "ironwood" zcash_client_backend/src/data_api/testing/pool.rs | head -50` and `rg -rn "create_pczt_from_proposal" zcash_client_sqlite/src` for concrete test call sites), (c) how `zcash_client_sqlite` binds the framework (`rg -n "TestBuilder|TestState" zcash_client_sqlite/src/testing*`). The `MigrationContext` needs a real DB FILE path (it re-opens per call) — check whether the sqlite test harness exposes the db path/file (`rg -n "db_path|data_file" zcash_client_sqlite/src/testing*`); if the harness is memory-only, build the fixture manually: `WalletDb::for_path` on a tempfile, `init_wallet_db`, create account from a seed, then reuse the framework's block-generation + scanning helpers against that DB.

**Target tests (write as many as the harness supports; each is independently valuable):**

1. `note_split_plans_and_signs_against_a_seeded_wallet` — seed wallet with ~12.5 spendable ZEC of Orchard V2 notes post-NU6.3-activation; `prepare_note_split()` → assert `NoteSplitProposal.output_values()` matches `plan_denominations` for the seeded balance; `sign_note_split(...)` → returns `PreparedTransfer`; `extract_broadcast_tx` yields parseable tx bytes (`zcash_primitives::transaction::Transaction::read`) whose Orchard bundle has the expected output count and whose expiry is ~default; migration DB rows exist (run row phase `preparing_denominations`→ set to waiting after record).
2. `transfer_pipeline_produces_a_v6_ironwood_crossing_tx` — seed a wallet holding one confirmed Orchard note of `D + 20_000`; drive `propose_migration_transfers()` (or directly `backend::propose_migration_transfer` + `create_transfer_pczt` for a tighter unit) → `sign_and_store_migration_schedule` → `next_due_transfer()` → extract tx → assert: tx version is V6, exactly one Ironwood-bundle output ≥ crossing value classification (crossing output + possibly ironwood change), Orchard bundle spends the note, expiry == `next_executable_after_height + 288`. **This test verifies spec §10.1 (change routing) — record the observed change pool in a comment.**
3. `record_transfer_result_advances_to_complete` — after test 2's schedule is stored, mine/scan the extracted tx via the harness (if the harness can inject a raw tx into a generated block — check `rg -n "put_tx|fake.*block|add_tx" zcash_client_backend/src/data_api/testing.rs`; if it cannot, simulate: `record_transfer_result(id, Success(txid))` then assert broadcasted status + `migration_state()` reports `InProgress`, and separately unit-drive the confirmed path by marking the store row confirmed) → eventually `MigrationState::Complete` once orchard drains and ironwood balance appears.
4. `next_due_transfer_is_height_gated` — schedule with 2 transfers; assert only the first is due at target height, the second becomes due after advancing the chain tip by 288 blocks (harness block generation).

**Fallback policy (spec §8/D10):** if a specific assertion cannot be driven through the harness (e.g. injecting the migration tx into a scanned block), implement the closest observable assertion, and add a `// GAP:` comment + list it for the final report. Do NOT delete the test — keep what it CAN verify.

- [ ] **Step 1: Study the harness** (the rg commands above; read the 2–3 most similar existing tests end to end).
- [ ] **Step 2: Write test 2 first** (the most valuable single test), red→green (expect iteration on change-strategy/spend-policy details from Task 10 — fixing `backend.rs` here is in-scope; keep fixes minimal and re-run Task 10's clippy).
- [ ] **Step 3: Add tests 1, 3, 4.**
- [ ] **Step 4: Runtime check** — if the e2e file exceeds ~5 minutes total under the default profile, gate the slowest cases behind `expensive-tests` (`#[cfg(feature = "expensive-tests")]`) keeping at least one prove+sign test in the default set.
- [ ] **Step 5: Full crate green + fmt; commit** (`zcash_pool_migration: Add seeded-wallet end-to-end migration tests`).

---

### Task 14: Polish, workspace CI parity, docs

**Files:**
- Modify: `zcash_pool_migration/src/lib.rs` (full crate-level docs), `CHANGELOG.md`, `README.md` (final), any file clippy/doc flags.

- [ ] **Step 1: Crate docs.** Write the full `//!` lib.rs docs: the migration flow (split → confirm → schedule → broadcast via platform → record results → complete), the state machine table (14 phases → 6 states), the software vs external-signer paths, the broadcast contract (`next_due_transfer` → `extract_broadcast_tx` → platform submit → `record_transfer_result`), and the security notes (self-funding denominations, dust-stays-in-Orchard, natural anchor + retention). Source material: spec §1/§5 + `PROTO/lib.rs` docs.
- [ ] **Step 2: Rustdoc completeness pass.** `cargo doc --no-deps -p zcash_pool_migration --all-features --document-private-items` → zero warnings; every public item has docs + error sections.
- [ ] **Step 3: Full CI parity locally.**
  - `cargo fmt --all -- --check`
  - `cargo clippy --all-features --all-targets -- -D warnings` (WORKSPACE-wide — proves no sibling regressions)
  - `cargo test -p zcash_pool_migration --all-features`
  - `cargo test -p zcash_pool_migration --no-default-features` (must compile+pass or be a no-op — fix feature gates if not)
  - `cargo check --workspace --all-features`
  - If time allows: `cargo test --workspace --all-features` (long; acceptable to run once here)
- [ ] **Step 4: CHANGELOG final** — describe the initial API surface under `## [Unreleased]` following sibling format.
- [ ] **Step 5: History review.** `git log --oneline main..HEAD` — verify each commit is a discrete semantic change with the Co-Authored-By trailer; no fixup noise (if any, use `git revise`/interactive-free rebase alternatives — `git revise` is the repo-sanctioned tool).
- [ ] **Step 6: Commit** any remaining changes (`zcash_pool_migration: Complete crate documentation and changelog`).

---

## Self-review checklist (run after drafting; issues found were fixed inline)

- Spec coverage: D1(Task 1), D2(Cargo/no cfg anywhere), D3(no serde; Task 12 metadata encoding), D4(Tasks 9/10), D5(Task 10 retain/release), D6(Task 7), D7(Tasks 11/12 method set), D8(Task 3), D9(Task 2), D10(Task 13); spec §10 verification items land in Tasks 10/12/13 + final report.
- Type consistency: `Db<P>` defined once (Task 9), consumed by Tasks 10–13; `TransferId` constructors used by scheduling (Task 5) and context (Task 11); `SignedPcztOutcome` produced in Task 10, consumed in Tasks 11/12.
- Every task ends with runnable verification + commit.
