# Handoff: Arbitrary t→t Transactions (COR-199)

**From:** Schell &nbsp;·&nbsp; **To:** John (@nullcopy) &nbsp;·&nbsp; **Date:** 2026-05-19
**Branch:** `feat/COR-199-arbitrary-t-2-t` &nbsp;·&nbsp; **Base:** `origin/main` @ `eb70164b0e`
**Worktree:** `librustzcash/arbitrary_t_2_t`

> **Status: WIP, does not currently compile.** See [§ Build status](#build-status) for
> the specific errors and likely cause. The design and most of the threading work is
> complete; what remains is fixing the test-module imports broken by the in-flight
> `sapling-crypto 0.6` / `orchard 0.12` upgrade, plus a few open design questions.

---

## TL;DR

This branch adds support for **arbitrary transparent-to-transparent (t→t)
transactions with transparent change** to the `zcash_client_backend` /
`zcash_client_sqlite` wallet stack, behind the `zcashd-compat` feature flag
(which now implies `transparent-inputs`). The intended consumer is Zallet as a
zcashd wallet-replacement.

The public-API surface is in place:

- `TransparentUtxoFilter<'a>` — composable address/coinbase filter on UTXO selection.
- `propose_transparent_transfer` — fully-transparent equivalent of `propose_transfer`,
  behind `zcashd-compat`.
- `ChangeStrategy::with_transparent_change()` — opt-in toggle that lets ZIP 317
  change strategies emit a P2PKH transparent change output instead of shielding.
- `WalletWrite::reserve_next_n_internal_addresses` — BIP 44 internal-scope
  (change) transparent-address reservation, parallel to the existing ephemeral
  reservation API.

What's *not* in: a working build. Test-helper modules in `zcash_client_backend`
reference `sapling::{note_encryption,util,zip32}`, `transparent::address`, and
`orchard::tree` paths that no longer exist after the dep bump.

---

## Problem statement

> The librustzcash wallet stack was originally designed for shielded-only
> wallets, and the only transparent spending currently supported is
> *shielding* transfers within the wallet. Zallet needs to be a drop-in
> zcashd-wallet replacement, which requires full t→t transaction
> functionality including transparent change generation.
>
> — Original spec (session `ses_29b46bca0…`)

The original spec proposed an `Option<TransparentInputFilter>` argument on
`InputSelector::propose_transaction`. During design we evolved this into the
more general **`TransparentUtxoFilter`** (single composable filter that also
handles the coinbase-only case zcashd's `z_sendmany` needs), and we pushed the
high-level entry point out as a new function (`propose_transparent_transfer`)
rather than modifying the existing `propose_transfer` signature, to keep
existing shielded-only callers untouched.

`zcashd-compat` now implies `transparent-inputs`, as suggested in the spec.

---

## Design decisions (where they came from, where they landed)

| # | Decision | Origin | Landed in |
|---|---|---|---|
| 1 | New filter type: `TransparentUtxoFilter` (struct, not enum) carrying `addresses: Option<&[TransparentAddress]>` *and* `coinbase_only: bool` — supersedes the original `TransparentInputFilter` enum from the spec. | `ses_29b46bca0…` design discussion | `zcash_client_backend/src/data_api.rs` (~lines 1471-1573) |
| 2 | Constants `TransparentUtxoFilter::ALL` and `::COINBASE_ONLY`, plus `none()`, `from_addresses()`, `coinbase_from_addresses()` constructors. | Same | Same |
| 3 | New top-level function `propose_transparent_transfer` rather than modifying `propose_transfer`. Behind `#[cfg(feature = "zcashd-compat")]`. Rejects shielded recipients up-front with `ProposalError::ShieldedRecipientInTransparentTransfer`. | Spec | `zcash_client_backend/src/data_api/wallet.rs` (~line 850+) |
| 4 | `zcashd-compat` implies `transparent-inputs` in `zcash_client_backend/Cargo.toml`. | Spec | `zcash_client_backend/Cargo.toml` |
| 5 | `InputSelector::propose_transaction` gains an optional `TransparentUtxoFilter<'_>` arg behind `#[cfg(feature = "transparent-inputs")]`. Existing callers pass `None` to preserve behavior. | Spec + research session `ses_29b46a45e…` | `zcash_client_backend/src/data_api/wallet/input_selection.rs` |
| 6 | `InputSource::get_spendable_transparent_outputs` takes `TransparentUtxoFilter<'_>` instead of `&TransparentAddress`, unifying address-list and coinbase-only queries into one trait method. | Research session `ses_29b46a45e…` | `data_api.rs` trait + `zcash_client_sqlite/src/lib.rs` + `zcash_client_memory/src/input_source.rs` |
| 7 | `ShieldingSelector::propose_shielding` and `wallet::propose_shielding` also gain a `utxo_filter` parameter so the existing shielding API benefits from coinbase filtering too. | Side-effect of (6) | `wallet.rs`, `input_selection.rs` |
| 8 | Transparent change is opt-in via builder method `with_transparent_change()` on the ZIP 317 change strategies (`SingleOutputChangeStrategy`, `MultiOutputChangeStrategy`). Default remains `false`. | Research session `ses_29ad2c544…` (zcashd `z_sendmany` parity) | `zcash_client_backend/src/fees/zip317.rs`, `fees/common.rs` |
| 9 | In `fees/common.rs`, `wants_transparent_change = fully_transparent && cfg.allow_transparent_change`. New `Ordering::Equal if fully_transparent && !wants_transparent_change` branch preserves the existing exact-match (no-change) case; new `_ if wants_transparent_change` branch emits a `ChangeValue::transparent(…)`. | Research session `ses_29ad2c544…` | `zcash_client_backend/src/fees/common.rs` |
| 10 | New `ChangeValue::transparent(zatoshis)` constructor (non-ephemeral) + `is_transparent_change()` accessor. Distinct from the existing ephemeral-output `ChangeValue`. | Research session `ses_29b2681df…` (transparent change derivation) | `zcash_client_backend/src/fees.rs` |
| 11 | New `WalletWrite::reserve_next_n_internal_addresses` trait method, parallel to `reserve_next_n_ephemeral_addresses`, using `TransparentKeyScope::INTERNAL` (BIP 44 scope 1). Default impl `unimplemented!()` — backends must override. | Research session `ses_29b2681df…` | `zcash_client_backend/src/data_api.rs` trait; SQLite impl in `zcash_client_sqlite/src/wallet/transparent.rs` |
| 12 | `propose_transparent_transfer` validates recipients up-front and rejects shielded addresses with `ProposalError::ShieldedRecipientInTransparentTransfer`. | Session `ses_29b46bca0…` | `wallet.rs` |

### Decisions surfaced in sessions but **NOT yet** reflected in code

- **zcashd's coinbase-spend-forbids-change rule.** Research session
  `ses_29ad2c544…` found that zcashd's `AddChangePayment(...)` rejects any
  nonzero change when coinbase UTXOs are being spent. Our current code
  permits transparent change unconditionally when the strategy is configured
  for it. **Open question for John:** do we want to reproduce that constraint
  here, and if so should it be enforced at the change-strategy layer or
  earlier? (See [§ Open questions](#open-questions).)
- **`LegacyCompat` privacy-policy mapping.** zcashd resolves
  `LegacyCompat → FullPrivacy | AllowFullyTransparent` based on UA
  involvement. We don't have a privacy-policy enum in librustzcash and
  research concluded we shouldn't add one (the structural enforcement via
  `ChangeStrategy::with_transparent_change()` is the librustzcash analogue).
  Worth confirming Zallet is OK with that translation.

---

## File-by-file change summary (67 files, +982 / −409)

### `zcash_client_backend` — core API surface

| File | Purpose |
|---|---|
| `Cargo.toml` | `zcashd-compat` now implies `transparent-inputs`. |
| `CHANGELOG.md` | Already documents the public-API changes (this file is the source of truth — read it first). |
| `src/data_api.rs` | New `TransparentUtxoFilter` type. `InputSource::get_spendable_transparent_outputs` now takes the filter. New `WalletWrite::reserve_next_n_internal_addresses` trait method. |
| `src/data_api/wallet.rs` | New `propose_transparent_transfer` (zcashd-compat-gated). `propose_shielding` gains `utxo_filter` arg. Existing `propose_transfer` now passes `None` for the new transparent-inputs arg internally. |
| `src/data_api/wallet/input_selection.rs` | `InputSelector::propose_transaction` gains optional `TransparentUtxoFilter<'_>`. `ShieldingSelector::propose_shielding` gains the same. Threading + preferential-selection logic. |
| `src/fees.rs` | New `ChangeValue::transparent(zatoshis)` + `is_transparent_change()`. |
| `src/fees/common.rs` | `SinglePoolBalanceConfig` gains `allow_transparent_change`. New `wants_transparent_change` decision and the `Ordering::Equal` branch is split to preserve the existing exact-match no-change case. |
| `src/fees/zip317.rs`, `src/fees/fixed.rs` | `with_transparent_change()` builder methods. Plumbing the flag down to `SinglePoolBalanceConfig::new`. |
| `src/proposal.rs` | New `ProposalError::ShieldedRecipientInTransparentTransfer` variant. |
| `src/data_api/testing*.rs` | Test-helper updates — partially done; **these are the files with build errors** (see [§ Build status](#build-status)). |

### `zcash_client_sqlite` — SQLite backend impl

| File | Purpose |
|---|---|
| `CHANGELOG.md` | Notes the trait-signature change. |
| `src/lib.rs` | Updated `get_spendable_transparent_outputs` impl to consume `TransparentUtxoFilter`. |
| `src/wallet/transparent.rs` | New SQL paths for multi-address + coinbase-only filtering. Implementation of `reserve_next_n_internal_addresses`. |
| `src/wallet/init/migrations/*.rs` | Bulk import-style edits (mostly `use` reordering — see below). |
| `src/wallet.rs`, `src/wallet/{commitment_tree,common,encoding,init,init/migrations,orchard,sapling,scanning,transparent,transparent/ephemeral}.rs`, `src/{chain,error,testing,testing/db,testing/pool}.rs` | Predominantly import-style churn from a `rustfmt`-driven `use` reformat (see [§ Heads-up](#heads-up)). |

### `zcash_client_memory` — in-memory backend impl

| File | Purpose |
|---|---|
| `src/input_source.rs` | Updated `get_spendable_transparent_outputs` impl for the new filter. |
| `src/types/transaction.rs` | Minor adjustments. |

---

## What's done ✓

1. **Public API design.** `TransparentUtxoFilter`, `propose_transparent_transfer`,
   `with_transparent_change`, `reserve_next_n_internal_addresses` — all
   signatures land where we want them and are documented.
2. **Trait-signature changes.** `InputSource::get_spendable_transparent_outputs`
   and `ShieldingSelector::propose_shielding` updated. SQLite + memory backends
   implement the new signatures.
3. **Fee/change accounting.** `fees/common.rs` correctly distinguishes the
   "fully transparent, no change requested" case from "wants transparent
   change" and the existing shielded-change paths.
4. **CHANGELOGs.** Both `zcash_client_backend` and `zcash_client_sqlite`
   CHANGELOGs are updated and accurately reflect the public-API delta.
5. **`zcashd-compat ⇒ transparent-inputs`** dependency added in
   `zcash_client_backend/Cargo.toml`.

## What's in progress ⚙

1. **Test-helper migration after the sapling/orchard dep bump.**
   `data_api/testing.rs` still imports from old module paths
   (`sapling::note_encryption`, `sapling::util`, `sapling::zip32`,
   `transparent::address`, `orchard::tree`). These need to be relocated to
   their new homes under `sapling-crypto 0.6` / `orchard 0.12`. See
   [§ Build status](#build-status) for the full list.
2. **`DiversifiableFullViewingKey: TestFvk` trait impl.** Ten errors fall
   out of (1) — the `TestFvk` impl for sapling's `DiversifiableFullViewingKey`
   is missing (likely because the import broke). Should resolve as a knock-on
   once (1) is fixed.

## What's left ☐ (open work)

1. **Make it compile.** Fix the test-module imports — small and mechanical
   once you've done one of them.
2. **Run the test suite.** `cargo test --workspace --all-features` has not
   been run on this branch. Per the call sites enumerated in research
   session `ses_29b11517e…`, the following test files reference the changed
   API and may need updating:
   - `zcash_client_backend/src/data_api/testing/transparent.rs` (lines ~76, 131, 156, 171, 755, 1080)
   - `zcash_client_backend/src/data_api/testing/pool.rs` (lines ~5376, 5398)
3. **Add tests for transparent change.** None of the new behavior has direct
   test coverage:
   - `propose_transparent_transfer` — happy path, mixed shielded recipient
     rejection, insufficient funds, change-required and exact-match cases.
   - `with_transparent_change()` — coverage of all three branches in
     `fees/common.rs`: shielded change (default), exact match (no change), and
     transparent change.
   - `TransparentUtxoFilter::coinbase_from_addresses` SQL path in
     `zcash_client_sqlite::wallet::transparent::get_spendable_transparent_outputs`.
   - `reserve_next_n_internal_addresses` gap-limit behavior; parallel coverage
     to the existing ephemeral-address reservation tests.
4. **Decide on coinbase-change parity with zcashd.** See [§ Open questions](#open-questions).
5. **Propagate up to Zallet.** Out of scope for this PR but worth tracking.

---

## Open questions

1. **Should we reject transparent change when spending coinbase UTXOs?** zcashd
   does (`AddChangePayment` rejects nonzero change with coinbase inputs). Our
   code currently doesn't enforce this. Most natural location for enforcement
   would be `fees/common.rs` inside the `wants_transparent_change` branch,
   but the `ChangeStrategy` doesn't currently know which inputs are coinbase.
   That info is in the `transparent_inputs: &[TransparentInputInfo]` slice
   passed to `compute_balance` — would need a coinbase bit there, or a
   `has_coinbase_inputs: bool` field on `SinglePoolBalanceConfig`.
2. **`PrivacyPolicy::LegacyCompat` translation for Zallet.** Research session
   `ses_29ad2c544…` mapped zcashd's `LegacyCompat → FullPrivacy |
   AllowFullyTransparent` based on UA involvement. In librustzcash that
   becomes "caller chooses between `propose_transfer` and
   `propose_transparent_transfer`". Confirm with the Zallet side that this
   call-site dichotomy is acceptable, or whether we need an upper-layer
   helper that switches on a `PrivacyPolicy` value.
3. **Default for `allow_transparent_change`.** Currently `false`, requiring an
   explicit `.with_transparent_change()` call. Keep that as the safe default,
   or make `propose_transparent_transfer` flip it implicitly (currently it
   already does — verify that's the intended ergonomic).
4. **Should `propose_shielding` get a `TransparentUtxoFilter::COINBASE_ONLY`
   shortcut?** The signature now accepts the filter; check whether
   Zallet's coinbase-shielding use case wants a typed shortcut.

---

## Build status

`cargo check --workspace --all-features` in this worktree as of `HEAD`:

```
error[E0432]: unresolved imports `sapling::note_encryption`, `sapling::util`, `sapling::zip32`
  --> zcash_client_backend/src/data_api/testing.rs:22
error[E0432]: unresolved import `transparent::address`
  --> zcash_client_backend/src/data_api/testing.rs:85
error[E0432]: unresolved import `orchard::tree`
  --> zcash_client_backend/src/data_api/testing.rs:92
error[E0277]: the trait bound `DiversifiableFullViewingKey: TestFvk` is not satisfied
  (×10, all in zcash_client_backend test helpers)
error: could not compile `zcash_client_backend` (lib) due to 13 previous errors
```

These are dependency-version skew, not design defects. `zcash_client_backend`'s
CHANGELOG already records the migration to `sapling-crypto 0.6` / `orchard 0.12`,
so the new module paths are known; the test helpers just haven't been updated.

Test files referencing the changed API (need touching once builds pass) were
enumerated in session `ses_29b11517e…` — see [§ What's left](#whats-left--open-work).

`cargo fmt --check` and `cargo clippy` were **not** run.

---

## Heads-up / gotchas

1. **Huge import-reorder diff.** Many of the 67 modified files contain only
   `use`-statement reordering (e.g. `sapling::{note_encryption::{…}, prover::{…}}`
   moved to a different group). My editor's `rustfmt` defaults differ from
   the repo's — the AGENTS.md "Imports" convention groups stdlib / external /
   crate-internal, and a few files in this diff lost the blank-line
   separation between groups. **Suggest running `cargo fmt --all` before
   review and squashing the formatting hunk into a separate cleanup commit
   on top.**
2. **`#[cfg]` density.** The new transparent-inputs threading multiplies
   `#[cfg(feature = "transparent-inputs")]` annotations on signatures —
   especially in `wallet.rs` and `input_selection.rs`. We may want a follow-up
   to consolidate via a sealed helper trait if it gets worse.
3. **Conservative coinbase exclusion.** Per the docstring on
   `TransparentUtxoFilter::coinbase_only`, "outputs for which the transaction
   index is unknown are conservatively treated as non-coinbase and will be
   excluded when this filter is active." Worth confirming this matches Zallet
   expectations — alternative is to fail loudly on unknown tx_index.
4. **No PR yet.** Per AGENTS.md, the PR-compliance gate requires team
   acknowledgment on an issue before a PR is opened. COR-199 was scoped
   internally; please confirm there's a corresponding GitHub issue before
   opening a PR.

---

## Suggested next steps for John

In approximate order of dependency:

1. **`cargo fmt --all`** on the worktree as a separate commit to drop the
   import-reorder noise out of the meaningful diff.
2. **Fix the test-module imports** (see [§ Build status](#build-status)) —
   should be ~30 minutes of mechanical work.
3. **`cargo test --workspace --all-features`** and address the call-site
   churn enumerated in session `ses_29b11517e…`.
4. **Add tests** per [§ What's left](#whats-left--open-work).
5. **Decide the open questions** in [§ Open questions](#open-questions),
   especially the coinbase-change parity question, before opening a PR.
6. **Open a GitHub issue** referencing COR-199 (if not already extant) and
   wait for team ack before opening the PR. See AGENTS.md "MUST READ FIRST —
   CONTRIBUTION GATE".

---

## Session archive

OpenCode sessions that drove this work (oldest first). All under
`project_id = 081937162ce7cea128d7fd6adea30d35ef14b584` (librustzcash).

| Session ID | When | Topic |
|---|---|---|
| `ses_29b469bfcffedsZdnRVjRGzUgY` | 2026-04-06 14:37 | Explore wallet API and `propose_transfer` (@explore) |
| `ses_29b46a45effebqgzlskX0kO1GZ` | 2026-04-06 14:37 | Explore input selection code (@explore) |
| `ses_29b4695bfffeyzVZDHpK82R2ZP` | 2026-04-06 14:37 | Explore `TransparentAddress` type (@explore) |
| `ses_29b2681dfffeKFmGmZmuyreKEu` | 2026-04-06 15:14 | Research transparent change addresses (@explore) |
| `ses_29b11517effdPP4HqWwJZZt27C` | 2026-04-06 15:35 | Find all test call sites to update (@explore) |
| `ses_29ad2c544ffe6cEHB1sMogyoZ6` | 2026-04-06 16:44 | Research zcashd `z_sendmany` change policy (@explore) |
| `ses_29b46bca0ffeRB9esfSwdPDfnF` | 2026-04-07 13:09 | **Primary session — Transparent input selection in librustzcash** (design + implementation) |

---

*This handoff document was prepared with AI assistance (Claude / OpenCode).
The original commits and this document are co-authored — see the commit
trailers and AGENTS.md "AI Disclosure".*
