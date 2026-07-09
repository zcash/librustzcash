# Final Report — `zcash_pool_migration`

**Date:** 2026-07-09
**Branch:** `michal/ironwood-migration` (29 commits over `origin/main` @ `bb0cdbd7b9`)
**Spec:** [2026-07-08-zcash-pool-migration-crate-design.md](../specs/2026-07-08-zcash-pool-migration-crate-design.md) ·
**Plan:** [2026-07-08-zcash-pool-migration.md](../plans/2026-07-08-zcash-pool-migration.md)

## Status: complete and verified

- **99 tests green**: 95 unit (incl. real-PCZT prove/sign round trips, ~3–5 s each) + **4 seeded-wallet
  end-to-end tests** (~16 s total) exercising the real pipelines against scanned chains.
- Full CI parity locally: `cargo fmt --check`, workspace-wide `clippy --all-features --all-targets -D warnings`,
  `cargo doc` (zero warnings, private items included), `cargo check --workspace --all-features`,
  and a full `cargo test --workspace --all-features` run — all green.
- Every commit is a discrete semantic change with the AI-disclosure trailer; nothing under
  `.superpowers/` (session scratch) was committed.
- Reviews: every task passed an independent spec + quality review (two required fix loops, both
  re-verified); a final whole-branch review (most capable model) found **no fund-safety defects**,
  and its fix wave (4 commits) was re-verified item by item: *fixed and clean*.

## What was built

`zcash_pool_migration` (~6,500 LOC incl. tests): the Orchard→Ironwood migration engine as a new
workspace crate, per spec D1–D10. Modules: `types`, `error`, `denominations`, `scheduling`,
`state`, `store`, `reserved_source`, `split`, `backend`, `context` (facade). Public surface:
`MigrationContext<P>` (20 methods) + 11 data types, private fields + accessors throughout, full
rustdoc with error sections, CHANGELOG/README in sibling format.

Key architecture (all per spec):
- **Transfers** ride upstream's high-level path: `InputSelector::propose_transaction` (explicit
  anchor, `TxVersion::V6`, Orchard-only spend policy, over the ported `ReservedInputSource`) →
  `create_pczt_from_proposal(…, target_expiry_height)` → PCZT prove → sign → finalize.
- **Note split** keeps the direct-builder path (`add_orchard_spend` + `add_orchard_change_output`
  × denominations → `build_for_pczt` → pczt `Creator`/`IoFinalizer`), since the high-level path
  deliberately routes Orchard-destined outputs to Ironwood post-activation.
- **Both signing models**: software (USK) and external-signer/Keystone (proven-unsigned staging →
  `Combiner` merge → all-or-nothing atomic persistence).
- **No cfg flags** (Ironwood is stabilized upstream), **no serde derives or wire formats** in the
  crate, five `ext_ironwood_migration_*` tables byte-identical to the prototype schema.

## Spec §10 verification outcomes

1. **§10.1 change routing — VERIFIED e2e.** A V6 transfer crosses exactly `D` into the Ironwood
   bundle; fee is exactly the 20 000-zatoshi self-funding buffer; residual change falls back to
   **Orchard** (zero in the standard shape). Asserted on the parsed consensus transaction.
2. **§10.2 proving-key pairing — VERIFIED at runtime.** orchard 0.15 collapsed the fork's
   `BundleProtocol` into a single `PostNu6_3` proving key serving both bundles; the first real
   **Ironwood proof** succeeds in ~2–3 s; Orchard proofs likewise.
3. **§10.3 split PCZT assembly — verified** (build_from_parts + IoFinalizer; software signing
   needs no updater metadata; external-signer round trips prove it end to end).
4. **§10.4 `ensure_retained` — works**; anchors are pinned across signing loops on both trees and
   released on both success and error paths (release is bulk-below-height; documented).
5. **§10.5 qleak / dummy-ciphertext privacy property — UNRESOLVED, flag to the team.** The
   workspace pins crates.io `orchard 0.15.0-pre.2`; whether it randomizes the spend-paired dummy
   output's `enc_ciphertext` (the valargroup fork carried this; a migration is a self-send) was
   not verifiable from librustzcash sources. **Ask the orchard maintainers before release.**
6. **§10.6 licensing** — crate is `MIT OR Apache-2.0` (workspace); lineage (vizor, Apache-2.0 →
   zodl prototype → this rewrite) noted here; confirm team comfort at PR time.
7. **§10.7 transient witness errors — VERIFIED SAFE.** `FailedTerminal` is never written by any
   code path; `ShardTreeError` → `Pipeline` errors propagate without wedging state; the two
   failure-path wedges the final review found (phantom split run, partial schedule) were fixed
   (`a8ac1d6dc0`) and re-verified.

## Deliberate deviations from the prototype (adjudicated during the port)

- `TransferId` uses `run:index` (colon) ids — opaque by contract; only the `prep:` prefix is ever
  parsed; `from_raw` is public for FFI reconstruction.
- serde: none in the crate; the `zcash_client_sqlite/serde` *feature* is enabled because
  `create_pczt_from_proposal` bounds `AccountId: serde::Serialize` (spec D3 amended in-commit).
- Dropped: `initialize_post_upgrade` (no-op), `NetworkPrivacyOptions` (platform concern),
  time-based scheduling, vizor's dummy-anchor pre-signing.
- **Restored vizor behavior beyond the prototype:** `migration_state()` now persists
  `Phase::Complete` (prototype left runs stuck non-terminal, blocking future runs).
- `has_overdue_transfers` is a blob-free EXISTS query (narrower than the prototype: a pending
  split tx no longer counts as "overdue"; may return `NotSynced`).
- Hand-rolled text codecs replace prototype serde_json: lenient for the legacy-shaped
  `target_values_json` column, **strict + versioned** for external-signer staging metadata.
- `record_transfer_result(Success)` on an unknown txid is now an error (prototype: silent no-op).
- Unknown-index probe-loop signing kept; `sign_ironwood` deliberately never called (Ironwood
  bundle is output-only) — documented in code.
- Error surface: codes 1, 3, 4, 5, 6 (code 2 retired with the removed `NotInitialized`; doc says
  never reassign).

## Non-blocking findings / follow-up candidates (none block the PR)

1. **Expired note-split liveness gap** (inherited): if the platform never broadcasts the split
   within its ~40-block expiry, the run shows `SplitPendingConfirmation` indefinitely; recovery
   requires `restart_current_migration_step`. Candidate: expiry detection in `migration_state()`.
2. **Recovery-loop e2e test** (InvalidNote/Expired → RequiresAttention → restart/refresh against
   a seeded wallet) and an e2e for the external-signer *propose* half.
3. **Phase gate in `next_due_transfer`** as belt-and-braces (partial-schedule clearing already
   fixed the underlying wedge).
4. External-signer pending rows keep `fee`/`selected_note_*` zero/empty (prototype-faithful;
   verified inert; staging codec is versioned for later widening).
5. `restart_current_migration_step` while a `broadcasted` transfer is unmined can propose a
   conflicting self-send (recoverable via the invalid-note loop; inherited).
6. `refresh_stale_transfers` regenerates rather than re-anchoring persisted PCZTs in place
   (spec §8 future optimization); `is_sync_required_before_next_transfer` hardcoded `false`
   (documented design).
7. `MigrationContext<P: Parameters>` monomorphizes per network in the FFI — standard practice,
   worth one line in the FFI layer.

## PR assembly checklist (decisions for the branch owner)

1. **Drop the `docs/superpowers` commits** before opening the PR (`f97f8862a2`, `825e361f06`,
   `42ef21ee36`, and this report's commit) — session process docs with local paths; the spec's
   content belongs in the PR description (repo allows `git revise` history editing within a PR).
2. **The three dependency-crate lint commits** (`d643243c4e` zcash_client_backend targeted allow;
   `a849cca052` + `d62c0dd2f0` zcash_client_sqlite, final form = precise cfg gating) are isolated
   and defensible in-series (the new crate's feature unification surfaces them), but maintainers
   may ask for a separate preliminary PR — be ready to split.
3. **AGENTS.md contribution process**: no team-acknowledged issue exists yet for this work; as a
   maintainer you can open the PR directly, but flagging it to the team first per house process
   is recommended (also settles §10.5 and the licensing note).
4. A duplicate of the `d643243c4e` wallet.rs lint fix may exist in the separate session spawned
   from the suggestion chip — keep only one.

## SDK integration notes (fresh FFI)

Construct `MigrationContext::new(db_path, network, AccountUuid)` per call; parse USK bytes to
`UnifiedSpendingKey` at the FFI edge; reconstruct ids with `TransferId::from_raw`. Marshalling is
the FFI's job (no serde; accessors/constructors cover everything). Broadcast contract unchanged:
`next_due_transfer` → `extract_broadcast_tx` → submit → `record_transfer_result` (don't infer
`InvalidNote`/`Expired` from submit errors). Errors: `Display` + stable `error_code()` (1, 3–6).
No `RUSTFLAGS`/cfg needed; the crate's Cargo features pull everything required.
