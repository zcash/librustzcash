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

`orchard::tree::MerklePath::from_parts(position: u32, auth_path: [MerkleHashOrchard; MERKLE_DEPTH_ORCHARD])`
is public (unlike the crate-private `MerklePath::dummy()`, which is for padding actions with no
real spend at all — not what we want here). Construct a placeholder
(`position = 0`, `auth_path = [MerkleHashOrchard::default(); MERKLE_DEPTH_ORCHARD]` or similar) for
each self-funding note whose split output is not yet mined.

**The bundle-level anchor MUST be left `None` at this stage, not a placeholder value.**
`pczt::roles::updater`'s `set_anchor` helper (`pczt/src/roles/updater/mod.rs`) rejects overwriting
an anchor slot that already holds a *different* value (`ConflictingAnchor`) — it only accepts a
transition from `None` to `Some`. Passing `orchard_anchor: Some(Anchor::empty_tree())` (the pattern
`build_self_funding_transfer_pczt` already uses for the analogous *Ironwood*-bundle-has-no-spend
case) at initial construction would bake in a real value that `set_orchard_anchor(real_anchor)`
could then never legally replace. `zcash_primitives::transaction::builder::BuildConfig::Standard.orchard_anchor`
is `Option<orchard::Anchor>` and is exercised with `None` elsewhere in this workspace's own test
suite (`zcash_primitives/src/transaction/builder.rs`, multiple cases) — pass `None` here for any
spend whose funding note is not yet mined.

**Open verification item (do first, before building out the rest of §4):** confirm empirically that
the *orchard* crate's own builder (not just the `zcash_primitives` wrapper) accepts `add_spend`
being called with a real note + placeholder `MerklePath` while the enclosing `BuildConfig`'s
`orchard_anchor` is `None` — i.e., that it does not itself require `merkle_path.root(note.commitment())`
to equal a `Some` anchor at spend-construction time. Write this as the crate's first new test
(`zcash_pool_migration/tests/`), independent of the rest of the pipeline change: construct a spend
with a placeholder `MerklePath` and `orchard_anchor: None`, run it through `Creator`/`IoFinalizer`/
`Signer`, and assert the resulting PCZT is well-formed with `witness: None`-or-placeholder and
`anchor: None`. If this does not work as expected, this whole approach needs re-evaluation before
any further code is written against it.

Build and sign the PCZT with these placeholders instead of a real
`witness_at_checkpoint_id_caching` call and a real anchor. The resulting PCZT is fully, validly
signed — signing does not depend on the (wrong) witness content — and is persisted in the
`SignedAwaitingProof` sub-state.

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
