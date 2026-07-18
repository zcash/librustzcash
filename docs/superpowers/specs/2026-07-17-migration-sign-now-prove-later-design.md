# Design Spec — Sign-now/Prove-later for `zcash_pool_migration`

**Date:** 2026-07-17
**Repo:** `zcash/librustzcash`, local branch `feature/orchard_migration` (testbed, superseded
upstream by Danny Willems' PR stack starting at `zcash/librustzcash#2606` — see §7)
**Extends:** `docs/superpowers/specs/2026-07-08-zcash-pool-migration-crate-design.md` (Michal
Fousek's original crate design). This document does not repeal that spec; it corrects one pipeline
detail (§5.6 there) that live testnet testing found does not match the intended architecture, and
records app-flow decisions the original spec left as SDK-integration notes (§9 there).

## 1. Background

Live testnet testing of the migration flow surfaced a reproducible
`InsufficientFunds { available: Zatoshis(0), required: ... }` failure whenever
`signAndStoreMigrationSchedule` proposed more than one transfer from a wallet that had not run
note-split. Root-causing this (session of 2026-07-17) surfaced two separate, real problems and one
architectural gap:

1. **Real bug, fixed:** `select_spendable_notes`'s eligibility gate (`witness_stabilized=1 OR
   freshly-`Scanned` shard priority`) can never pass for a note in a wallet's currently-open
   (not-yet-complete) commitment-tree shard on a live, continuously-polling wallet, because
   `update_chain_tip` re-marks that shard's scanned range `ScanPriority::ChainTip` on every sync
   tick once an earlier shard has completed. Fixed via `InputSource::select_spendable_notes_deferred_witness`
   (commit history on this branch). This fix is real and independently confirmed — Kris Nuttycombe
   diagnosed the identical root cause on 2026-04-30 in `#core-wallet`, and it is what the stalled,
   unmerged `origin/spendability_conditions` branch (7 commits, Apr–May) addresses more thoroughly
   upstream (introduces a height-based `witness_anchor_stable` field and `ScanPriority::Anchor`,
   replacing the boolean gate). Worth flagging to Danny Willems' rewrite in case it isn't already
   drawing on that branch.
2. **Not a bug — expected behavior, previously undocumented:** a schedule with multiple
   denominations proposed against *raw, unsplit* notes exhausts the wallet's balance on the first
   transfer (`GreedyInputSelector`'s oldest-first running-sum crossing consumes every note it scans
   until crossing the target, not the smallest sufficient subset), leaving `InsufficientFunds` for
   every subsequent transfer in the same schedule. This is exactly the scenario note-split (ZIP 318
   Phase 1) exists to prevent. **The real gap is that no consumer of this crate (app or otherwise)
   currently calls `is_note_split_needed`/`prepare_note_split`/`sign_note_split` at all** — see §3.
3. **Architectural gap in this crate (the subject of this document):** the current pipeline
   (`context.rs`, spec §5.6) proves *and* signs eagerly, in the same call
   (`sign_and_store_migration_schedule` → `backend::sign_schedule` →
   `build_self_funding_transfer_pczt`/`propose_migration_transfer`, both of which call
   `witness_at_checkpoint_id_caching`/rely on `select_spendable_notes` before signing). This
   requires the funding note to already be mined, scanned, and witnessed at *signing* time. ZIP 318
   requires only that it be mined and witnessed at *proving/broadcast* time — signing may happen
   earlier, in the same session as note-split, using a witness that doesn't exist yet. §4 below
   specifies the fix.

## 2. Sign-now/prove-later: what ZIP 318 actually requires

Source: [ZIP 318](https://github.com/zcash/zips/pull/1317), "Phase 1, Note preparation" and
"Rationale for anchor selection".

> "Because Orchard nullifiers are position-independent, all layers MAY be constructed and signed in
> a single session; however, each layer can be proved and broadcast only after the previous layer's
> outputs have been mined and a subsequent boundary observed..."

> "Under the version 6 transaction format, the anchor is committed as authorizing data rather than
> by the signature hash [ZIP 244]... the wallet can attach or update a pre-signed transaction's
> anchor and proof after signing without re-signing."

> "The wallet MUST wait until the boundary that closes the anchor-height bucket in which a
> note-preparation transaction was mined has passed before treating its output notes as available
> for migration."

Implications, precisely:

- **Signing an Orchard spend never needs a real Merkle witness.** The spend's nullifier, `rk`,
  `cv_net`, and the spend authorization signature are all derivable from the note's own secrets
  (value, `rho`, `rseed`, `psi`) plus the spend authorizing key and a randomizer `alpha` — none of
  these depend on the note's tree position or any anchor. Only the **proof** (the zk-SNARK
  attesting membership at a specific anchor) needs the real witness.
- A whole batch — note-split *and* every migration transfer that spends one of its outputs — can
  therefore be **constructed and signed in one session**, before note-split has even broadcast, let
  alone mined.
- **Proving and broadcasting cannot happen until the funding note is mined *and* a subsequent
  anchor-height boundary has been observed** (this is a hard MUST, not an optimization — spending
  sooner would let a lightwalletd-compromising adversary correlate sync timing with the anchor
  drawn).
- Verified independently in `#wallet-team` (2026-07-13): dominik asked Adam Tucker (Valar) whether
  note-split + migration transfer presigning is safe given the witness isn't known yet; Adam
  confirmed: *"note split + migration transactions presign should not be a problem as creation of
  ZKP can be postponed before real send as anchor needs to be replaced anyway."*

## 3. Note-split is not subject to the same sync/broadcast decoupling as migration transfers

ZIP 318's "Decoupling synchronization from broadcast" section (a single background window MUST
either sync or broadcast, never both) applies to **Phase 2 migration (pool-crossing) transfers**,
because those transfers are the ones an observer can link to the wallet's sync activity via the
anchor they carry. Confirmed directly by Kris Nuttycombe (`#core-wallet`, 2026-07-something,
responding to dominik's question about whether the split transaction needs the same treatment):

> "The split transaction doesn't have the same limitations, because it doesn't leak any information
> — it's a fully shielded transaction."
>
> "I don't think it's a big deal that someone who is watching wallets sync can see 'oh this person
> is starting a migration' because basically every wallet user has to do this."

**Consequence for the app flow:** note-split can execute immediately and sync immediately
afterward, in the same session, with no artificial delay. Only the migration transfers themselves
need the scheduled, sync-decoupled treatment ZIP 318 describes for Phase 2.

## 4. Revised pipeline (supersedes spec §5.6's eager prove-then-sign)

### 4.1 New states

A transfer's prepared PCZT now has two persisted sub-states where the original spec had one
(`staged`/`ready`):

- **`SignedAwaitingProof`** — the PCZT has a placeholder witness (see §4.2), is fully constructed
  and signed, but has no proof yet. Not eligible for `next_due_transfer()`.
- **`ReadyToBroadcast`** — the placeholder witness has been replaced with the note's real witness
  (via `pczt::roles::updater::set_orchard_spend_witnesses`/`set_anchor`) and the Prover role has
  run. Eligible for `next_due_transfer()` once its scheduled height also arrives.

### 4.2 Signing with a placeholder witness

**Verified empirically 2026-07-17/18** (see `zcash_pool_migration/tests/migration_e2e.rs`,
`transaction_level_builder_rejects_orchard_anchor_none` and
`placeholder_witness_synthetic_anchor_then_redacted_signs_successfully`, commit `ff54a227e7` on
this branch). The naive approach this section originally specified —
`BuildConfig::Standard { orchard_anchor: None, .. }` — does **not** work: it is not "defer the
anchor", it means "build no Orchard bundle at all".
`zcash_primitives::transaction::builder::BuildConfig::orchard_builder` only constructs the
underlying `orchard::builder::Builder` when the anchor is `Some`; `Builder::add_orchard_spend` then
fails immediately with `Error::OrchardBuilderNotAvailable`. This is not just a wrapper limitation:
`orchard::builder::Builder::new` itself requires a non-optional `anchor: Anchor`, and
`Builder::add_spend` performs a live consistency check (`SpendInfo::has_matching_anchor`) rejecting
any `merkle_path` whose own root doesn't equal the builder's anchor. There is no "anchor-less
spend" mode anywhere in the orchard crate's builder API — do not attempt `orchard_anchor: None`.

**The working approach — build self-consistent, then redact:**

1. Construct a placeholder `orchard::tree::MerklePath` for the self-funding note whose split output
   is not yet mined, via the public
   `MerklePath::from_parts(position: u32, auth_path: [MerkleHashOrchard; MERKLE_DEPTH_ORCHARD])`
   (unlike the crate-private `MerklePath::dummy()`, which is for padding actions with no real spend
   at all — not what we want here). Any position/auth_path values work (e.g. all-zero) — they are
   discarded in step 3.
2. Compute a **synthetic anchor that matches this placeholder path's own root** —
   `placeholder_path.root(note.commitment().into())` — and pass `Some(that synthetic anchor)` as
   `orchard_anchor` in `BuildConfig::Standard`. This satisfies the builder's internal
   `has_matching_anchor` check (the anchor and the witness are mutually consistent, just not real).
   Build and sign exactly as today: `add_orchard_spend` → `add_ironwood_output` → `build_for_pczt`
   → `Creator::build_from_parts` → `IoFinalizer::finalize_io()` → the crate's existing software
   `Signer` step. All of this succeeds unmodified — signing genuinely does not depend on whether the
   anchor/witness are real, only on the note's own secrets and the spend authorizing key.
3. **Redact** the synthetic anchor and witness back to absent, *after* signing, via
   `pczt::roles::redactor::Redactor::redact_orchard_with(...).finish()`. `Redactor` is not used
   elsewhere in this crate and needs no new Cargo feature (`pczt/src/roles.rs` does not gate it
   behind a feature, unlike prover/signer). Verified directly via `Pczt`'s public accessors:
   `orchard().anchor()` is `None` after redaction (and survives a serialize/parse round trip), while
   `spend_auth_sig` remains `Some` — the signature is genuinely untouched by clearing the anchor,
   confirming the ZIP 244 premise (anchor is authorizing data, not under the v6 sighash) holds in
   practice, not just in principle.

   **Correction found during implementation (not caught by the spike, since the spike never ran
   the Prover role on the redacted PCZT): redact only the real spend's own action, not every action
   via `redact_actions` (all actions).** The Orchard bundle is padded to two actions
   (`BundleType::DEFAULT`); the second, padded/dummy action also carries a witness. Clearing *that*
   action's witness too makes the later `Prover` role fail with `Prover(MissingWitness)` once real
   data is attached to the real spend and proving is attempted — the padded action's own witness
   must survive untouched. Redact by action index (`clear_spend_witness()` on the specific action
   that holds the real, not-yet-mined spend), not blanket over the whole bundle.

The resulting PCZT — validly signed, with the real spend's `anchor: None` and no witness on that
one action — is persisted in the `SignedAwaitingProof` sub-state. §4.3's later
`set_orchard_anchor`/`set_orchard_spend_witnesses` calls are unaffected by this correction: they
still require the slot to be `None` first, which the
redaction step now provides (instead of the originally-planned "never set it in the first place").

### 4.3 Finalizing once the funding note is witnessed

Once `migration_state()`'s reconciliation (existing mechanism, spec §5.3) detects that a
note-preparation output is mined and a boundary has passed, for each `SignedAwaitingProof` PCZT
whose funding note is now witnessed:

1. Fetch the note's real `MerklePath` (existing `witness_at_checkpoint_id_caching` call, unchanged).
2. Fetch/select the anchor per the reuse rule in §5.
3. `pczt::roles::updater::Updater::set_orchard_spend_witnesses([(action_index, real_merkle_path)])`
   then `.set_orchard_anchor(real_anchor)` (both confirmed present in
   `pczt/src/roles/updater/mod.rs`). The witness setter is guarded by
   `ensure_no_orchard_proof_for_witness`; the anchor setter by `ensure_no_orchard_proof_for_anchor`
   plus `set_anchor`'s `None → Some` transition rule (see §4.2 — this is exactly why the anchor
   slot must have been left `None`, not pre-filled with a placeholder). Both are safe to call here
   since no proof exists yet at this stage.
4. Run the `pczt::roles::prover::Prover` role (unchanged from today's eager path, just moved later).
5. Transition the transfer's persisted state from `SignedAwaitingProof` to `ReadyToBroadcast`.

### 4.4 Public API changes to `MigrationContext` (additive to spec §4.3)

```rust
// Existing, behavior changes as described in §4.2 (placeholder witness instead of real):
pub fn sign_and_store_migration_schedule(&self, schedule: &MigrationSchedule, usk: &UnifiedSpendingKey)
    -> Result<(), MigrationError>;

// New: called by the reconciliation hub once a funding note is witnessed. Idempotent — a no-op if
// there is nothing in SignedAwaitingProof yet, or if the specific transfer's note isn't witnessed
// yet (returns 0, does not error — this is an ordinary, expected transient state, not
// MigrationError::Pipeline; see §6).
pub fn finalize_ready_transfers(&self) -> Result<u32, MigrationError>; // returns count finalized
```

### 4.5 Implementation status (2026-07-18)

§4 is implemented on this branch, commits `9c17301758`/`28af46c8da`/`769fc35dde`. Two real
deviations from the letter of this section, both correctness-motivated, not shortcuts:

- **`build_self_funding_transfer_pczt` (real-witness) was kept, unmodified, alongside a new
  `sign_self_funding_transfer_awaiting_proof` (placeholder path).** The external-signer flow
  (`create_unsigned_transfer_pczts`, Keystone/hardware-wallet staging) still proves *eagerly*
  before staging a PCZT for an external signer — feeding it a synthetic anchor would silently bake
  a permanently-invalid proof into what gets handed to the external signer. Only the
  software-signing path (`sign_and_store_migration_schedule` → `sign_schedule`) moved to the
  placeholder-then-redact approach. If the external-signer flow is ever changed to also defer
  proving, it should reuse `sign_self_funding_transfer_awaiting_proof`'s pattern rather than
  duplicating it a third time.
- **Anchor reuse (§5) is scoped to one `finalize_ready_transfers()` call, not persisted across
  calls.** One anchor is fetched per call and reused for every transfer finalized within it; a
  later call fetches a fresh one. There is no "last anchor used" persistence spanning multiple
  calls/background windows. This is intentionally narrower than §5's full framing (which describes
  cross-session reuse tied to sync activity) because the boundary/cohort/`ANCHOR_AGE_CAP` bookkeeping
  that would make cross-call reuse meaningful is Phase 2 background-scheduling machinery, explicitly
  out of scope per §7's closing note. Revisit when that scheduling subsystem is built.

**Independently reviewed 2026-07-18 (no code changes needed) — one real gap flagged, not fixed
here:** a `SignedAwaitingProof` transfer whose funding note becomes *permanently* invalid (spent
elsewhere; its note-split parent never confirms) is indistinguishable, in
`finalize_self_funding_transfer`, from one that is simply *not witnessed yet* — both currently
return `Ok(None)`/a transient no-op per §6. Because such a row never reaches `proof_status =
'ready'`, none of the crate's existing recovery surfaces see it: `has_invalid_transfers` only
counts `status = 'scheduled'` rows with zero pending (an awaiting-proof row still counts as
`scheduled`, masking it), and `expiry_height` is persisted but never compared against the current
height for awaiting-proof rows anywhere. Net effect: a permanently stuck row retries as a silent
no-op forever, with no path to `RequiresAttention`. Whoever builds the Phase 2
background-scheduling subsystem (§7) should treat `expiry_height` as a hard cutoff for
awaiting-proof rows too, surfaced via a new `AttentionReason` variant — do not assume this is
already handled.

**Fixed 2026-07-18 (was flagged Minor in review, hit live within hours):** the review also flagged
that `init()`'s `CREATE TABLE IF NOT EXISTS` is a no-op against a `pending_txs` table that already
existed from before this pipeline landed, leaving it without `proof_status`/`spend_action_index`
entirely. This was reproduced live on a testnet device on the very next real test run — the wallet
DB predated today's schema change, and every query referencing the new columns
(`hasOverdueTransfers` in this case) crashed with "no such column" immediately after a successful
note-split broadcast. Fixed (commit `4b5db3f697`) with an idempotent `ALTER TABLE` fallback in
`init()`, guarded by `PRAGMA table_info`, plus a regression test
(`init_adds_proof_columns_to_a_pre_existing_pending_txs_table`) that recreates the pre-existing-table
scenario directly rather than relying on live device state to catch a regression.

## 5. Anchor reuse across a schedule (multiplicity / cohorts)

ZIP 318's "Anchor-height bucketing and cohorts": multiple transfers from the *same* wallet MAY
share the same boundary anchor (this is the expected, designed-for case, not an edge case) — up to
a soft `K_MAX` per cohort (exact value an open point for the core team; not yet fixed upstream).
Anchor age is measured relative to *the most recent boundary the wallet has observed at proving
time* — if no new sync has happened since transfer N was proved, transfer N+1 MAY reuse transfer
N's exact anchor; nothing about the wallet's observation state has changed, so the anchor is not
"more stale" from the wallet's own point of view. Do not draw a fresh anchor speculatively when no
sync has occurred since the last draw — reuse the last one.

## 6. Witness-not-ready is a transient, recoverable state, never a hard failure

The original crate spec already anticipated this class of problem (§10, risk 7): *"vizor treated
missing-witness errors as transient (re-park in waiting phase)... map upstream's
`ShardTreeError`/`CheckpointPruned` variants to a recoverable state rather than `failed_terminal`."*
The final report confirmed this was tested and verified safe *for shard-tree witness-construction
failures* (`ShardTreeError` → `MigrationError::Pipeline`, propagates without wedging state).

**What was missing:** the specific case this session hit — `InputSelectorError::InsufficientFunds`
surfacing all the way to the app as a raw exception — was never mapped to a recoverable
`MigrationState`/`AttentionReason` variant at all; it is not the same code path the original
"transient witness errors" testing exercised (that was about proving a note whose position IS known
failing due to pruning timing, not about zero candidate notes because a schedule's raw-note
fallback burned through the balance on transfer 1, or because a funding note isn't witnessed yet
under the new §4 pipeline). With §4's `SignedAwaitingProof` sub-state, "not witnessed yet" stops
being an error at all — it's simply not `ReadyToBroadcast` yet, and `finalize_ready_transfers`
being a no-op is the correct, non-error steady state. No error-mapping change should be needed once
§4 lands; flag this row as resolved by construction rather than requiring separate handling.

## 7. App-side flow (Kotlin, `zashi-android`) — the actual gap found live

`MigrationReviewVM.init` calls `proposeMigrationTransfers()`/`proposeImmediateMigration()`
directly; `onConfirm`/`confirmAutomatic` call `signAndStoreMigrationSchedule` directly. **No call
site in the real app anywhere calls `isNoteSplitNeeded`/`prepareNoteSplit`/`submitNoteSplit`** —
those exist only in `OrchardMigrationSdkMock.kt` and a stale comment. Per user
(dominik) 2026-07-17: note-split is the first step of "Confirm Transfer Plan" (the Review screen's
confirm action), not a separate screen.

Required flow inside `MigrationReviewVM`'s confirm action (AUTOMATIC mode; IMMEDIATE mode does not
need note-split per §5.6 of the original spec — single-transfer fallback spends a raw note
directly):

1. `isNoteSplitNeeded()`.
2. If needed: `prepareNoteSplit()` → `sign_note_split()` (or the external-signer/Keystone
   equivalent) → submit/broadcast the split transaction. Per §3, this MAY sync immediately after,
   no artificial delay.
3. `proposeMigrationTransfers()` / `signAndStoreMigrationSchedule()` — under the §4 pipeline, this
   now signs immediately (placeholder witnesses for any not-yet-mined self-funding notes), so step
   3 does **not** need to wait for step 2 to confirm on-chain.
4. Background execution (existing `MigrationScheduler`/WorkManager machinery, out of scope for this
   document) is responsible for calling `finalize_ready_transfers()` once reconciliation detects a
   funding note is witnessed, and for the scheduled, sync-decoupled broadcast of each transfer per
   ZIP 318 Phase 2 (unchanged by this document).

This document does not specify the Phase 2 background-scheduling subsystem itself (anchor-bucket
timing, WorkManager scheduling, fallback-on-open) — that is real, separate, substantial work
tracked against ZIP 318 §"Transfer scheduling"/"Background scheduling"/"Fallback on application
open" directly, out of scope for the local testbed fix this document describes.

### 7.1 Implementation status (2026-07-18)

Steps 1–4 above are implemented, across both repos (branch `feature/orchard_migration` in each):

- **`zcash-android-wallet-sdk`** (commit `57b25204`) — `finalize_ready_transfers` exposed end to end:
  `migration.rs` (`finalizeReadyTransfersNative`, modeled on `isSyncRequiredBeforeNextTransferNative`)
  → `MigrationRustBackend.kt` → `TypesafeMigrationBackend(Impl).kt` → `MigrationSdk.kt`
  (`suspend fun finalizeReadyTransfers(): Int`) → `OrchardMigrationSdkImpl.kt` (via the existing
  `logged("finalizeReadyTransfers") { ... }` wrapper).
- **`zashi-android`** — `MigrationReviewVM.kt`'s `confirmAutomatic` (commit `804e7a012`) now calls
  `isNoteSplitNeeded()` → `prepareNoteSplit()` → `submitNoteSplit(proposal, usk)` before
  `signAndStoreMigrationSchedule`, per steps 1–3 above; `submitNoteSplit` was confirmed to already
  compose sign → extract → broadcast → `recordTransferResult` into one call (no additional
  composition was needed on the app side). `MigrationWorker.kt` (commit `61966f3c8`) calls
  `sdk.finalizeReadyTransfers()` in `doWork()`, immediately after resolving `sdk` and *before* the
  `isSyncRequiredBeforeNextTransfer()` gate, so a funding note witnessed since the last run is
  finalized in time to be picked up by `executeNextPendingTransfer()` later in the same run —
  concretely satisfying step 4's "background execution... calling `finalize_ready_transfers()`",
  as a narrow stopgap rather than the full Phase 2 scheduling subsystem (unchanged from this
  section's framing above).

**Known deviation:** the Keystone (external-signer) branch of `confirmAutomatic` was deliberately
left unchanged — it returns early into the QR sign/scan detour before reaching the new note-split
call. Per §4.5's first documented deviation, the external-signer PCZT path
(`create_unsigned_transfer_pczts`) still proves eagerly on the Rust side and was never moved to the
placeholder-witness scheme, so wiring note-split into that branch would need its own composition
against a deferred-proof path that doesn't exist for external signing yet. Keystone migration
therefore still requires the wallet's existing notes to already fund the schedule exactly, same as
before this document.

**Known gap:** `MigrationReviewVM` (and `MigrationWorker`) have no pre-existing test coverage to
extend — this repo's test suite does not currently cover this VM/Worker at all, independent of this
change.

## 8. Fallback on application open (reference, not re-specified here)

ZIP 318 §"Fallback on application open" already specifies the missed-window behavior precisely:
reconcile on every launch, disclose the privacy cost, send at most one overdue transfer per open,
reschedule the remainder. `dominik`'s recollection of the app's existing "transfer now (sync
delayed) vs. sync now (transfer later)" choice screen is consistent with this ZIP section and
should be implemented against it directly rather than against this document.

## 9. Scope note

This document, and the local `librustzcash` branch `feature/orchard_migration` it describes changes
against, is a **disposable testbed** (confirmed 2026-07-16, before this session began: Danny
Willems is redoing `zcash_pool_migration` from scratch upstream, PR #2606 already supersedes
#2572). The value of implementing §4 here is to unblock **local dev/testing of background
execution** now, not to produce something intended for upstream submission. Flag §1 item 1 (the
`spendability_conditions` branch) and this document's §4 (sign-now/prove-later) to Danny/Kris in
case the upstream rewrite doesn't already account for either.
