# Design Spec — `zcash_pool_migration` crate

**Date:** 2026-07-08
**Repo:** `zcash/librustzcash`, branch `michal/ironwood-migration` (currently at `origin/main`, HEAD `bb0cdbd7b9`)
**Goal destination:** PR to `zcash/librustzcash` `main`, full upstream discipline
**Behavioral source of truth:** `zodl_ironwood_migration` crate at
`/Users/chlup/Developing/zec/work/real-ironwood/ZODLIronwoodMigrationRust` (itself ported from
vizor-wallet `origin/adam/qleak-pr73-orchard-librustzcash`, Apache-2.0)
**Consumers:** iOS / Android SDK FFI layers (rewritten from scratch against this crate; the existing
`michal/MOB-1455-*` SDK branches are throwaway prototypes and impose **no** compatibility constraints)

---

## 1. Goal

Add the Orchard→Ironwood migration engine to upstream librustzcash as a new workspace crate,
**`zcash_pool_migration`**: a synchronous, network-free library that

- plans the **note split** (decompose spendable Orchard balance into self-funding power-of-ten notes),
- builds, proves, and signs the split and the migration transfers as **PCZTs**,
- persists runs / prepared notes / pending transactions in the shared wallet SQLite DB,
- schedules transfers by **block height** (288-block cadence) and hands the platform pre-signed
  transactions to broadcast, consuming broadcast results back to advance its state machine,
- supports both **software signing** (USK provided by the platform) and **external signing**
  (Keystone-style: export unsigned PCZTs, accept signed ones back).

The platform (SDK) owns: OS scheduling, UI, network/broadcast, and key custody. The crate owns every
migration decision.

This is a **port + adaptation** of the proven `zodl_ironwood_migration` crate (85 unit tests,
compile-verified backend) onto upstream APIs — not a redesign. Upstream `main` now provides the full
Ironwood wallet layer the fork used to provide (verified 2026-07-08; the 2026-06-30
`UPSTREAM-GAP-ANALYSIS.md` is obsolete).

## 2. Key decisions (locked)

| # | Decision | Rationale |
|---|----------|-----------|
| D1 | **New workspace crate `zcash_pool_migration`** | User-selected. Depends on `zcash_client_backend` + `zcash_client_sqlite`; cleanest port, self-contained review, no churn in the big crates. Name chosen over `zcash_client_migration`. |
| D2 | **No cfg gating** | Ironwood/NU6.3 is stabilized on upstream main (`NetworkUpgrade::Nu6_3`, `TxVersion::V6`, wallet layer all un-gated; only NU7/ZIP-233 remains behind `zcash_unstable="nu7"`). The engine needs the `orchard` cargo feature on its deps, nothing more. SDKs no longer need `RUSTFLAGS` cfg. |
| D3 | **No serde in the crate's own types or wire formats** | Upstream policy forbids derived serde outside marked cases; the only argument for it (prototype FFI wire-format compat) is void because the SDK FFI is being rewritten. The FFI defines its own DTOs via this crate's accessors/constructors. Adding a `serde` feature later would be non-breaking if ever needed. *Amended during implementation:* the crate derives no serde and hand-rolls its one persisted text encoding, but it MAY enable a dependency's serde feature where an upstream API unconditionally requires it — concretely, `create_pczt_from_proposal` bounds `AccountId: serde::Serialize`, satisfiable only via `zcash_client_sqlite/serde` (D4 mandates that pipeline, so the letter of the original wording was unsatisfiable). |
| D4 | **Transfers via the upstream high-level path; note split via the direct builder** | Transfers: `InputSelector::propose_transaction` (explicit anchor, `TxVersion::V6`) → `create_pczt_from_proposal(…, target_expiry_height)` → PCZT prove/sign/finalize. Upstream now supports expiry override and Ironwood-routed Orchard-receiver payments, so the prototype's hand-built transfer path is retired; PCZTs gain proper ZIP-32/updater metadata (needed for real Keystone signing). The split cannot use that path (post-activation it routes all Orchard-destined outputs to Ironwood; the split must mint Orchard V2 notes), so it keeps the direct `Builder` path on public upstream APIs (`add_orchard_spend`, `add_orchard_change_output`, `build_for_pczt`, pczt `Creator::build_from_parts` + `IoFinalizer`). |
| D5 | **Natural anchor; pin with `ensure_retained` during signing** | The abandoned "bucketed anchor" stays out (needs scanner cooperation; documented as future privacy work). New hardening upstream enables: pin the anchor checkpoint via shardtree `ensure_retained` for the duration of the multi-transfer proving/signing loop, releasing afterwards, so checkpoint pruning (PRUNING_DEPTH=100) cannot race a long signing session. |
| D6 | **Persistence = five `ext_ironwood_migration_*` tables, unchanged** | Additive `CREATE TABLE IF NOT EXISTS` in the shared wallet DB. The `ext_` prefix is `zcash_client_sqlite`'s documented contract for externally-owned tables; a sibling workspace crate is still external to its schema-migration system. Schema ports verbatim from the prototype (runs, prepared_notes, prep_tx, pending_txs, staged_pczts). |
| D7 | **Software + external signing both in scope** | 16 of the 17 platform-facing methods the prototype proved (`initialize_post_upgrade` is dropped — no-op; `new()` ensures tables), plus the 4 external-signer (Keystone) methods. `NetworkPrivacyOptions` is dropped (platform-side broadcast concern; engine never read it). |
| D8 | **Fully idiomatic public types** | Private fields + accessors, `from_parts`-style constructors that validate, `TxId` / `Zatoshis` / `BlockHeight` / `AccountUuid` upstream types throughout (no hex-`String` txids, no bare `u64`/`u32` in public signatures). No wire-format constraints exist anymore. |
| D9 | **Hand-rolled error enums** | Matches the wallet crates this extends (`zcash_client_backend`/`sqlite` style): `Display` + `std::error::Error` + `From` conversions + stable `error_code() -> u32` for FFI. (AGENTS.md mentions a snafu preference; the wallet-layer siblings don't use it and this keeps conversions to `SqliteClientError` simple. Cosmetic to change if maintainers ask.) |
| D10 | **End-to-end tests against the upstream wallet-testing framework** | `zcash_client_backend::data_api::testing` + the sqlite test backend already support Ironwood. Seeded-wallet tests exercise split and transfer pipelines for real (propose → PCZT → prove → sign → extract), closing the prototype's "backend compile-verified only" gap. Heavy proving tests go behind `expensive-tests` if runtime demands. |

## 3. Crate layout

```
zcash_pool_migration/
  Cargo.toml            # workspace member; license.workspace; no new external deps
  CHANGELOG.md          # repo changelog format, starts Unreleased
  README.md             # short crate readme, matches sibling style
  src/
    lib.rs              # crate docs (flow + state machine), module wiring, re-exports
    types.rs            # public data types (idiomatic, D8)
    error.rs            # MigrationError / InvalidStateError (D9)
    denominations.rs    # plan_denominations: power-of-ten + fee buffer   [pure]
    scheduling.rs       # 288-block cadence schedule builder              [pure]
    state.rs            # 14-phase → 6-state machine                      [pure]
    store.rs            # ext_ironwood_migration_* tables (rusqlite)      [pure: unit-testable]
    reserved_source.rs  # ReservedInputSource: InputSource wrapper
    split.rs            # note-split PCZT building (direct Builder path, D4)
    backend.rs          # wallet reads, propose, prove/sign/finalize pipeline
    context.rs          # MigrationContext facade
  tests/                # end-to-end tests via data_api::testing (D10), if not inline
```

No feature split between "core" and "backend" tiers (the prototype's `librustzcash-backend` feature
existed to dodge the fork's build cost; in-workspace it's pointless). Crate features: none beyond
what dependency wiring requires (e.g. passing through `multicore` if needed). `unstable` is **not**
required.

Dependencies (all already in the workspace / lockfile — no cargo-vet additions):
`zcash_client_backend` (features `orchard`, `pczt`), `zcash_client_sqlite` (feature `orchard`),
`zcash_primitives`, `zcash_keys` (feature `orchard`), `zcash_protocol`, `zcash_address`, `zip321`,
`pczt` (roles: creator, io-finalizer, prover, signer, spend-finalizer, tx-extractor, combiner),
`orchard`, `shardtree`, `rusqlite`, `uuid`, `rand`. Dev: `tempfile`, `incrementalmerkletree`,
`zcash_client_backend`/`zcash_client_sqlite` with `test-dependencies`.

## 4. Public API

All public items get full rustdoc with documented error cases. Types below show accessors, not
fields (fields are private, D8).

### 4.1 Data types (`types.rs`)

```rust
/// A planned note split: the self-funding denomination notes to mint, and the split fee.
pub struct NoteSplitProposal { … }
impl NoteSplitProposal {
    pub fn output_values(&self) -> &[Zatoshis];   // each = power-of-ten + fee buffer
    pub fn fee(&self) -> Zatoshis;
}

/// One scheduled Orchard→Ironwood transfer.
pub struct TransferProposal { … }
impl TransferProposal {
    pub fn id(&self) -> &TransferId;              // newtype over the run-scoped UUID string
    pub fn amount(&self) -> Zatoshis;             // the turnstile "crossing" value (power of ten)
    pub fn anchor_height(&self) -> BlockHeight;
    pub fn next_executable_after_height(&self) -> BlockHeight;
    pub fn expiry_height(&self) -> BlockHeight;
}

pub struct MigrationSchedule { … }                // transfers() + estimated_duration_hours()

pub struct MigrationProgress { … }
impl MigrationProgress {
    pub fn completed_transfers(&self) -> u32;
    pub fn total_transfers(&self) -> u32;
    pub fn remaining_orchard_value(&self) -> Zatoshis;
    pub fn next_transfer_ready_at_height(&self) -> Option<BlockHeight>;
}

/// A fully proven + signed transaction, persisted as a PCZT, ready for platform broadcast.
pub struct PreparedTransfer { … }                 // id() + txid() -> TxId + pczt_bytes()

/// An unsigned-but-proven PCZT awaiting an external signer (Keystone flow).
pub struct UnsignedTransferPczt { … }             // id() + pczt_bytes()

/// A signed PCZT returned from an external signer, paired with the transfer it answers.
pub struct SignedTransferPczt { … }               // constructor from_parts(id, pczt_bytes); id() + pczt_bytes()

pub enum MigrationState {
    NotStarted,
    SplitPendingConfirmation,
    ReadyToPropose,
    InProgress(MigrationProgress),
    RequiresAttention(AttentionReason),
    Complete,
}
pub enum AttentionReason { InvalidTransfer { transfer_id: TransferId }, TransferExpired, SyncRequiredBeforeNext }

/// Broadcast outcome reported back by the platform.
pub enum TransferResult { Success { txid: TxId }, NetworkError { retryable: bool }, InvalidNote, Expired }
```

`TransferId` is a small newtype (string-backed UUID + `"prep:"` prefix convention for the split tx)
so ids are not bare `String`s in signatures. Exact accessor names may be polished during
implementation; semantics are fixed.

### 4.2 Errors (`error.rs`)

```rust
pub enum InvalidStateError { NoActiveRun, UnknownPhase(String), WrongPhase { expected, found }, AlreadyComplete, NotApplicable(&'static str) }

#[non_exhaustive]
pub enum MigrationError {
    NotSynced,
    NotInitialized,
    InvalidState(InvalidStateError),
    Db(rusqlite::Error),
    Backend(SqliteClientError),
    Pipeline(String),          // heterogeneous propose/build/prove/sign pipeline errors
}
impl MigrationError { pub fn error_code(&self) -> u32; }   // stable codes 1..=6 for FFI
```

`Display` + `Error::source()` + `From<rusqlite::Error>` / `From<SqliteClientError>` /
`From<ShardTreeError<_>>` as in the prototype.

### 4.3 `MigrationContext` facade (`context.rs`)

```rust
pub struct MigrationContext<P: Parameters + Clone> { /* db_path, network params, account uuid */ }

impl<P: Parameters + Clone> MigrationContext<P> {
    pub fn new(db_path: &Path, network: P, account: AccountUuid) -> Result<Self, MigrationError>;

    // state (platform polls)
    pub fn migration_state(&self) -> Result<MigrationState, MigrationError>;
    pub fn migration_progress(&self) -> Result<Option<MigrationProgress>, MigrationError>;

    // note split (software signing)
    pub fn is_note_split_needed(&self) -> Result<bool, MigrationError>;
    pub fn prepare_note_split(&self) -> Result<NoteSplitProposal, MigrationError>;
    pub fn sign_note_split(&self, proposal: &NoteSplitProposal, usk: &UnifiedSpendingKey)
        -> Result<PreparedTransfer, MigrationError>;

    // schedule (software signing)
    pub fn propose_migration_transfers(&self) -> Result<MigrationSchedule, MigrationError>;
    pub fn propose_immediate_migration_transfers(&self) -> Result<MigrationSchedule, MigrationError>;
    pub fn sign_and_store_migration_schedule(&self, schedule: &MigrationSchedule, usk: &UnifiedSpendingKey)
        -> Result<(), MigrationError>;

    // external-signer (Keystone) variants
    pub fn create_unsigned_note_split_pczt(&self) -> Result<Vec<u8>, MigrationError>;
    pub fn store_signed_note_split_pczt(&self, signed_pczt: &[u8]) -> Result<PreparedTransfer, MigrationError>;
    pub fn create_unsigned_transfer_pczts(&self, schedule: &MigrationSchedule)
        -> Result<Vec<UnsignedTransferPczt>, MigrationError>;
    pub fn store_signed_schedule_pczts(&self, signed: &[SignedTransferPczt]) -> Result<(), MigrationError>;

    // background execution (platform broadcasts)
    pub fn is_sync_required_before_next_transfer(&self) -> Result<bool, MigrationError>;
    pub fn next_due_transfer(&self) -> Result<Option<PreparedTransfer>, MigrationError>;
    pub fn extract_broadcast_tx(&self, pczt_bytes: &[u8]) -> Result<Vec<u8>, MigrationError>;
    pub fn record_transfer_result(&self, id: &TransferId, result: TransferResult) -> Result<(), MigrationError>;

    // on-launch reconciliation / recovery
    pub fn has_overdue_transfers(&self) -> Result<bool, MigrationError>;      // EXISTS query, no blob load
    pub fn has_invalid_transfers(&self) -> Result<bool, MigrationError>;
    pub fn refresh_stale_transfers(&self, usk: &UnifiedSpendingKey) -> Result<u32, MigrationError>;
    pub fn restart_current_migration_step(&self) -> Result<MigrationSchedule, MigrationError>;
}
```

Changes vs the prototype facade: `initialize_post_upgrade` removed (D7); `usk: &[u8]` becomes
`&UnifiedSpendingKey` (the FFI parses bytes → key; upstream code shouldn't take opaque key bytes);
`account_uuid: [u8; 16]` becomes `AccountUuid`; `db_path: &str` becomes `&Path`;
`TransferPczt` renamed to `UnsignedTransferPczt`/`SignedTransferPczt` (input vs output roles);
`PreparedTx` renamed `PreparedTransfer`. Everything else is semantics-identical to the prototype.

The context is cheap to construct and opens DB connections per operation (SQLite handles
cross-connection locking with the SDK's own connections; matches the prototype's proven model).

## 5. Engine semantics (ported unchanged)

These are the behaviors the prototype + vizor proved; the port must preserve them exactly.

### 5.1 Denomination planning (`denominations.rs`)

Self-funding power-of-ten decomposition (issue-1 D7 semantics):
`plan_denominations(total_input, prep_fee)`; reserve `prep_fee`; greedily take the largest
power-of-ten ZEC value `D` with `D + TRANSFER_FEE_BUFFER ≤ remaining`; each output note =
`D + TRANSFER_FEE_BUFFER` (buffer = 20_000 zatoshi = 4 × ZIP-317 marginal fee, funding the
transfer's 2 Orchard + 2 Ironwood actions); the crossing value is `D`. Any residual —
including dust — stays as Orchard change, never folded into fees (dust-attack de-anonymization
guard). Cap: 64 outputs per run (error beyond). Constants: `ZATOSHIS_PER_ZEC = 100_000_000`,
`MIGRATION_MAX_PREPARED_NOTES_PER_RUN = 64`, `TRANSFER_FEE_BUFFER_ZATOSHI = 20_000`.

### 5.2 Height-based scheduling (`scheduling.rs`)

All transfers in a schedule share the wallet's **natural anchor** (D5). Transfer `i`:
`next_executable_after_height = target + first_delay + i × 288`;
`expiry_height = next_executable_after_height + 288`;
`estimated_duration_hours` from 48 blocks/hour. "Immediate migration" = single-transfer schedule
with `first_delay = 0`. Time-based scheduling (vizor's exponential offsets) stays dead.

### 5.3 State machine (`state.rs`)

The 14 vizor-compatible phase strings persist in the DB; public collapse to 6 `MigrationState`
values as in the prototype (`state::to_state`). `migration_state()` remains the reconciliation
hub: it marks mined txs confirmed, advances split→ready when the prep tx mines and spendable
notes appear, and detects completion (all transfers confirmed, Orchard drained, Ironwood > 0).

### 5.4 Persistence (`store.rs`)

Five tables, verbatim schema from the prototype (columns/keys/indexes unchanged):
`ext_ironwood_migration_runs`, `…_prepared_notes`, `…_prep_tx`, `…_pending_txs`,
`…_staged_pczts`, plus the two indexes. `raw_pczt` BLOBs are plaintext (the wallet DB is the
platform's secure store). All store functions port 1:1 (`insert_run`, `active_run`, `set_phase`,
`locked_note_refs`, `insert_pending_txs`, `next_due_transfer`, `mark_pending_status`,
`pending_totals`, `clear_scheduled_pending`, prep-tx + staged-PCZT CRUD, terminal-phase guards).

### 5.5 Note reservation (`reserved_source.rs`)

`ReservedInputSource` wraps `&WalletDb`, implementing upstream's **current** `InputSource` shape
(pool-slice `sources: &[ShieldedPool]`, `ReceivedNotes` return, `TargetHeight`,
`ConfirmationsPolicy`; transparent methods delegate unfiltered). Filters: merged exclude-set of
already-reserved `ReceivedNoteId`s + migration-locked `(txid, output_index)` pairs from live runs.

### 5.6 Transaction pipelines (`split.rs`, `backend.rs`) — D4

**Note split** (direct builder): select all spendable Orchard **V2** notes (via
`ReservedInputSource`, filtered to `NoteVersion::V2`); fee = ZIP-317 marginal × actions with the
2-action grace floor; last output absorbs the exact-balance residual; build with
`Builder::new(…, BuildConfig::Standard { orchard_anchor, ironwood_anchor: None, sapling_anchor: None })`,
`add_orchard_spend` per note, `add_orchard_change_output` per denomination (internal same-account
outputs keep value in the Orchard V2 pool); `build_for_pczt` → map output action indices through
`orchard_meta` (builder shuffles actions) → pczt `Creator::build_from_parts` → `IoFinalizer` →
prove → sign → `SpendFinalizer` → serialize; persist prep tx + prepared notes (values at their
shuffled action indices).

**Transfers** (upstream high-level): per transfer, build a ZIP-321 `TransactionRequest` paying the
account's own unified address (`WalletRead::get_last_generated_address_matching`); propose via
`InputSelector::propose_transaction` on the `GreedyInputSelector` over `ReservedInputSource`
(explicit target/anchor, `proposed_version = Some(TxVersion::V6)`, spend policy permitting
Orchard+Ironwood, ZIP-317 change strategy) — post-activation upstream classifies the
Orchard-receiver payment as the **Ironwood crossing output** and routes change to Ironwood; then
`create_pczt_from_proposal(…, target_expiry_height: Some(expiry_height))` → prove (Orchard +
Ironwood proofs as required) → sign → finalize → serialize. Each transfer spends exactly one
prepared note (reservation makes the N transfers independent — no chained change).

**Prove/sign details:** two process-global `OnceLock` proving keys (Orchard-bundle and
Ironwood-bundle circuit versions per upstream orchard 0.15 API). Software signing derives
`SpendAuthorizingKey` from the USK and signs each Orchard spend (recorded indices where available,
else the prototype's index-probe loop tolerant of `WrongSpendAuthorizingKey` on decoys);
`sign_ironwood` is unnecessary today (Ironwood bundle is output-only) — assert/document this.
External-signer flow: stage proven-unsigned PCZTs (`…_staged_pczts`), accept signed PCZTs back,
`Combiner` merge (rejects mismatched pairs), finalize, persist — all-or-nothing per schedule.

**Anchor retention (D5):** before the per-schedule signing loop, `ensure_retained` the chosen
anchor checkpoint on the Orchard (and Ironwood, if applicable) trees via
`WalletCommitmentTrees`; release retained checkpoints below the tip afterwards.

**Broadcast contract:** platform calls `next_due_transfer()` → `extract_broadcast_tx(pczt)` →
submits via its own lightwalletd/Tor → `record_transfer_result(id, result)`. Success advances
scheduled→broadcasted (and split phases); retryable network errors leave state untouched;
`InvalidNote`/`Expired` park the run in `failed_recoverable` for `restart_current_migration_step`
/ `refresh_stale_transfers`.

## 6. Testing plan (D10)

1. **Unit tests (port all ~85, adapted):** denominations (7), scheduling (7), state (10),
   store (21, tempfile DBs), reserved-source merge/lock logic, split fee/balance arithmetic,
   error codes/Display, type constructor validation, context state-machine + external-signer
   validation tests (including the real-PCZT fabricated-note round trips).
2. **New end-to-end tests** via `zcash_client_backend::data_api::testing` + the
   `zcash_client_sqlite` test backend (Ironwood-aware): seed a wallet with Orchard notes across
   NU6.3 activation, then exercise: split plan→build→prove→sign→extract (outputs land as V2
   Orchard notes); transfer propose→PCZT→prove→sign→extract (one Orchard spend in, Ironwood
   crossing output + Ironwood change out, correct expiry); schedule persistence + `next_due` by
   height; `record_transfer_result` transitions; completion detection. If proving runtime is
   excessive for default CI, gate the heavy cases behind `expensive-tests` (repo convention).
3. **CI matrix compliance:** `cargo test --workspace --all-features`, clippy `-D warnings`,
   `fmt --check`, doc-link validation, and the repo's feature-combination builds.

TDD ordering for implementation: pure modules first (red→green per module), then store, then
backend/split against the testing framework, context last.

## 7. Upstream discipline

- Discrete semantic commits (no WIP), each public-API commit updates rustdoc + CHANGELOG.
- `Co-Authored-By: Claude <noreply@anthropic.com>` on AI-assisted commits (AGENTS.md AI disclosure).
- New crate versioned `0.1.0` with `CHANGELOG.md` in repo format; workspace `members` updated;
  README.md matching sibling crates.
- No new external dependencies → no cargo-vet/deny churn.
- PR body notes provenance (vizor → zodl crate → this port) and links this spec.

## 8. Out of scope (documented, not implemented)

- SDK/FFI repos (fresh integration is a separate effort; §9 notes what it needs).
- In-place PCZT re-anchoring via the updater role (`refresh_stale_transfers` keeps the proven
  regenerate strategy; noted as future optimization).
- Richer `is_sync_required_before_next_transfer` (stays `false` by design: self-funding notes
  produce no Orchard change requiring re-sync).
- Bucketed/shared anchors and scanner-side checkpoint alignment (future privacy hardening; needs
  sync-path cooperation).
- Voting, multi-device/stateless recovery, time-based scheduling (dead vizor features).
- `NetworkPrivacyOptions` (platform-side), `initialize_post_upgrade` (obsolete no-op).

## 9. SDK integration notes (FYI for the fresh FFI)

- Construct `MigrationContext` per call from `(db_path, network, AccountUuid)`; parse USK bytes to
  `UnifiedSpendingKey` at the FFI edge.
- Marshalling is the FFI's job now (crate has no serde): define DTOs over the accessors; likely
  JSON as before, but any format works.
- The broadcast loop contract is unchanged: `next_due_transfer` → `extract_broadcast_tx` → submit
  → `record_transfer_result`. Do not infer `InvalidNote`/`Expired` from submit errors; the engine
  detects deep invalidity itself (`has_invalid_transfers` / `RequiresAttention`).
- No `RUSTFLAGS`/cfg needed anymore; enable the `orchard` feature on the client crates.

## 10. Risks & verification items (resolve during implementation; report in final report)

1. **Transfer change-routing** — verify `create_pczt_from_proposal` + chosen change strategy
   yields exactly: 1 Orchard V2 spend (+ padding), Ironwood crossing output, Ironwood change,
   ZIP-317 fee = 20k for the standard shape. Covered by the new end-to-end tests.
2. **Proving-key/bundle-version pairing** — upstream orchard 0.15 `BundleVersion` API replaces the
   fork's `BundleProtocol`; confirm the Orchard-bundle vs Ironwood-bundle circuit versions at
   first proving test.
3. **Split PCZT assembly** — `Creator::build_from_parts` + `IoFinalizer` on upstream pczt 0.7 for
   an all-change Orchard transaction; verify no updater metadata is mandatory for software signing
   (external-signer split may want ZIP-32 metadata added — check what Keystone requires and add
   via the updater if cheap).
4. **`ensure_retained` semantics** — pin/release behavior across the signing loop; confirm the
   retained-checkpoint tables exist for both Orchard and Ironwood trees.
5. **qleak / dummy-ciphertext privacy property** — confirm whether crates.io `orchard 0.15.0-pre.2`
   randomizes the spend-paired dummy output's `enc_ciphertext` (the fork carried this fix; a
   migration is a self-send, so an ivk-holder detecting spends is a real privacy regression).
   Lives in the orchard crate, not this code — flag to the team if absent.
6. **Licensing/provenance** — vizor is Apache-2.0 (repo-level, no file headers); this workspace is
   MIT OR Apache-2.0. Code was rewritten twice since vizor, but confirm the team is comfortable
   with the dual license at PR time.
7. **Witness-not-ready transients** — vizor treated missing-witness errors as transient
   (re-park in waiting phase). Ensure the port maps upstream's `ShardTreeError`/`CheckpointPruned`
   variants to a recoverable state rather than `failed_terminal`.
