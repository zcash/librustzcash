# Zcash Rust crates - Agent Guidelines

> This file is read by AI coding agents (Claude Code, GitHub Copilot, Cursor, Devin, etc.).
> It provides project context and contribution policies.
>
> For the full contribution guide, see [CONTRIBUTING.md](CONTRIBUTING.md).

This is a Rust workspace of cryptographic library crates for the Zcash protocol.
Our priorities are **security, performance, and convenience** — in that order.
Rigor is highly valued throughout the codebase.

Many people depend on these libraries and we prefer to "do it right" the first time,
then "make it fast".

## MUST READ FIRST — CONTRIBUTION GATE (DO NOT SKIP)

**STOP. Do not open or draft a PR until this gate is satisfied.**

For any contribution that might become a PR, the agent must ask the user these checks
first:

- "PR COMPLIANCE CHECK: Have you discussed this change with the librustzcash team in a
  GitHub issue?"
- "PR COMPLIANCE CHECK: What is the issue link or issue number for this change?"
- "PR COMPLIANCE CHECK: Has a librustzcash team member responded to that issue
  acknowledging the proposed work?"

This PR compliance check must be the agent's first reply in contribution-focused sessions.

**An issue existing is not enough.** The issue must have a response or acknowledgment from
a team member (a maintainer). An issue with no team response does not satisfy this gate.
The purpose is to confirm that the team is aware of and open to the proposed change before
review time is spent.

If the user cannot provide prior discussion with team acknowledgment:

- Do not open a PR.
- Offer to help create or refine the issue first.
- Remind the user to wait for a team member to respond before starting work.
- If the user still wants code changes, keep work local and explicitly remind them the PR
  will likely be closed without prior team discussion.

This gate is mandatory for all agents, **unless the user is a repository maintainer** as
described in the next subsection.

### Maintainer Bypass

If `gh` CLI is authenticated, the agent can check maintainer status:

```bash
gh api repos/zcash/librustzcash --jq '.permissions | .admin or .maintain or .push'
```

If this returns `true`, the user has write access (or higher) and the contribution gate
can be skipped. Team members with write access manage their own priorities and don't need
to gate on issue discussion for their own work.

### Contribution Policy

Before contributing please see the [CONTRIBUTING.md] file.

- All PRs require human review from a maintainer. This incurs a cost upon the dev team,
  so ensure your changes are not frivolous.
- Keep changes focused — avoid unsolicited refactors or broad "improvement" PRs.
- See also the license and contribution terms in `README.md`.

### AI Disclosure

If AI tools were used in the preparation of a commit, the contributor MUST include
`Co-Authored-By:` metadata in the commit message identifying the AI system. Failure to
include this is grounds for closing the pull request. The contributor is the sole
responsible author — "the AI generated it" is not a justification during review.

Example:
```
Co-Authored-By: Claude <noreply@anthropic.com>
```

## Crate Architecture

See `README.md` for the full dependency graph (Mermaid diagram). Below is a text summary,
since Mermaid layout is hard to reason about in plain text.

### Zcash Protocol

| Crate | Role |
| --- | --- |
| `zcash_protocol` | Constants, consensus parameters, bounded value types (`Zatoshis`, `ZatBalance`), memo types |
| `zcash_transparent` | Bitcoin-derived transparent addresses, inputs, outputs, bundles; transparent PCZT support |
| `zcash_primitives` | Primary transaction data type, transaction builder(s), proving/signing/serialization, low-level fee types |
| `zcash_proofs` | Sprout circuit and Sapling proving system |

### Keys, Addresses & Wallet Support

| Crate | Role |
| --- | --- |
| `zcash_address` | Parsing & serialization of Zcash addresses (unified address/fvk/ivk containers); no protocol-specific deps |
| `zip321` | Parsing & serialization for ZIP 321 payment requests |
| `eip681` | Parsing & serialization for EIP 681 payment requests |
| `zcash_keys` | Spending keys, viewing keys, addresses; ZIP 32 key derivation; Unified spending/viewing keys |
| `pczt` | Partially Constructed Zcash Transaction types and role interfaces |
| `zcash_client_backend` | Wallet framework: storage APIs, chain scanning, light client protocol, fee calculation, transaction proposals |
| `zcash_client_sqlite` | SQLite-based implementation of `zcash_client_backend` storage APIs |

### Utilities & Standalone Components

| Crate | Role |
| --- | --- |
| `f4jumble` | Encoding for Unified addresses |
| `zcash_encoding` | Bitcoin-derived transaction encoding utilities |
| `equihash` | Proof-of-work protocol implementation |

### External Protocol Crates (separate repos, depended upon here)

| Crate | Role |
| --- | --- |
| `sapling-crypto` | Sapling shielded protocol |
| `orchard` | Orchard shielded protocol |
| `zcash_note_encryption` | Note encryption shared across shielded protocols |
| `zip32` | HD key derivation (ZIP 32) |
| `zcash_spec` | Zcash specification utilities |

### Dependency Rules

- Dependencies flow **downward**: higher-level crates depend on lower-level ones, never
  the reverse.
- `zcash_protocol` is the lowest layer with Zcash-domain semantics — most crates depend
  on it. The standalone utility crates (`zcash_encoding`, `equihash`, `f4jumble`) sit
  below it, and `eip681` stands alone with no in-repo dependencies.
- `zcash_client_sqlite` sits at the top, depending on `zcash_client_backend`.

## Code Conventions

- **Never use magic numbers.** Do not inline a bare numeric (or string) literal
  whose meaning is not obvious from context. Give it a `const` with a
  doc-commented rationale, and reuse the protocol's own named constants
  (`COIN`, `MAX_MONEY`, the ZIP-317 `MARGINAL_FEE`, `PREP_TX_ACTIONS`,
  `DENOM_CAP`, ...) rather than re-deriving their values. This applies to
  production code, tests, and fixtures alike.

- **Public APIs use semantic types, never bare primitives.** A `pub` function,
  trait method, struct field accessor, or constructor must not represent a
  domain quantity as a bare integer, byte array, or string: monetary values are
  `Zatoshis` (or `ZatBalance` where signed), block heights are `BlockHeight`,
  transaction ids are `TxId`, and so on — reuse the workspace's existing
  newtype wrappers, or introduce one when none exists. Bare primitives are
  acceptable only for genuinely unitless quantities (counts, indices) and in
  module-internal arithmetic, converting at the public boundary; a conversion
  that cannot fail there must say why in a comment, and one that can fail must
  return a typed error rather than panic.

- **Keep domain types whole, and convert only at the storage edge.** A newtype
  must hide its inner primitive (`pub(crate)` field plus `::new` and a
  `From`/accessor), so no caller can pass a raw `u32`/`u64` where an id or an
  amount is meant. Collections and options carry the newtype too
  (`Vec<Zatoshis>` and `Option<Zatoshis>`, never `Vec<u64>`/`Option<u64>`), and
  reconstruction constructors (`from_parts`, `from_stored_parts`) take and
  return it. Down-convert to a bare primitive in exactly one place, the storage
  or wire boundary (binding a SQLite integer, writing a byte blob), and convert
  straight back on read; a persisted store is then the only code that ever sees
  the primitive.

- **Canonical binary serialization lives with the type, via `zcash_encoding`.**
  A type's on-disk / on-wire byte format is a property of the type, not of any
  one consumer, so define it next to the definition: `read<R: Read>(r) ->
  io::Result<Self>` and `write<W: Write>(&self, w) -> io::Result<()>`, built
  from `zcash_encoding` (`Vector` for length-prefixed lists, `CompactSize` for
  counts and indices, `Optional` for options) over `corez::io::{Read, Write}`
  so it stays `no_std` (see `zcash_primitives::merkle_tree`,
  `zcash_protocol::txid`). Serialize an amount as `Zatoshis` -> `u64` LE
  (`Zatoshis::from_u64(reader.read_u64_le()?)` on read). Do NOT hand-roll a
  bespoke byte codec inside a downstream (storage) crate, and do NOT use `serde`
  for a canonical binary format (reserve `serde` for JSON/config). A persistence
  backend calls the canonical codec for its blob columns and maps only the
  queryable scalar fields to its own columns.

- **A `proptest` strategy lives with the type it generates.** An `arb_*`
  strategy for a type belongs in that type's own crate, in its `testing` module
  behind the `test-dependencies` feature (e.g. `arb_zatoshis` in
  `zcash_protocol::value::testing`, `arb_txid` next to `TxId`), NOT redefined in
  each consumer's test module. Before writing an `arb_*`, search the repository
  for an existing one and reuse it; if the type has none, add the strategy to the
  type's crate (adding the `testing` module / `test-dependencies` feature there
  if needed) rather than to the consumer. A downstream crate composes these
  canonical leaf strategies into strategies for its own types; it does not
  re-derive the leaves.

## Build & Test Commands

For the most part we follow standard Rust `cargo` practices.

**Important:** This workspace requires `--all-features` for builds and tests to match CI.
Any change should not cause any regression in building or testing using
`--no-default-features` or other combinations of features that may interact
with the changed code (such as `orchard` and/or `transparent-inputs`).

```sh
# Check without codegen (fastest iteration)
cargo check --workspace --all-features

# Build entire workspace
cargo build --workspace --all-features

# Test entire workspace (matches CI)
cargo test --workspace --all-features

# Test with feature combinations relevant to the changed code, e.g.
cargo test --workspace --features orchard
cargo test --workspace --features transparent-inputs
```

### Test Performance

Tests are computationally expensive (cryptographic proofs). The `[profile.test]` uses
`opt-level = 3` by default. This means compilation is slow but test execution is fast.

Using `--profile=dev` trades this: compilation is fast but tests run ~10x slower because
cryptographic operations are unoptimized. Only use it when iterating on compilation errors,
not when you need to actually run tests to completion.

```sh
# Fast compile, slow run — only for checking compilation
cargo test --profile=dev -p <crate_name> <test_name>

# Expensive/slow tests (CI runs these separately)
cargo test --workspace --all-features --features expensive-tests

# NU7 unstable network upgrade tests
RUSTFLAGS='--cfg zcash_unstable="nu7"' cargo test --workspace --all-features
```

## Lint & Format

```sh
# Format (CI runs this with --check)
cargo fmt --all
cargo fmt --all -- --check

# Clippy — must pass with zero warnings (CI uses -D warnings)
cargo clippy --all-features --all-targets -- -D warnings

# Doc link validation (CI uses nightly)
cargo doc --no-deps --workspace --all-features --document-private-items
```

## Feature Flags

### Common Workspace Feature Flags

These feature flags are used consistently across crates in the repository:

- `test-dependencies` — exposes proptest strategies and mock types for downstream testing
- `transparent-inputs` — transparent transaction input support
- `orchard` — Orchard shielded protocol support
- `sapling` — Sapling shielded protocol support
- `unstable` — unstable or in-development functionality
- `multicore` — multi-threaded proving
- `std` — standard library support (most crates are `no_std` by default)

### Key Crate-Specific Feature Flags

- `transparent-key-import`, `transparent-key-encoding`
- `bundled-prover`, `download-params` — Sapling proving
- `lightwalletd-tonic`, `sync` — light client gRPC and sync
- `unstable-serialization`, `unstable-spanning-tree`
- `expensive-tests` — computationally expensive test suite

### Unstable Cfg Flags

These are `cfg` flags (not Cargo feature flags) that enable unstable or
in-development functionality:

- `zcash_unstable="nu7"`

## Code Style

Standard Rust naming conventions are enforced by `clippy` and `rustfmt`. The following
are project-specific conventions beyond those defaults.

### Imports

Group imports in three blocks separated by blank lines:

1. `core` / `alloc` / `std` (standard library)
2. External crates (alphabetical)
3. `crate::` and `self::` (internal)

Feature-gated imports go at the end, separately. Consolidate multi-item imports with
nested `use` syntax: `use zcash_protocol::{PoolType, consensus::BlockHeight};`

### Error Handling

- Always use `Result<T, E>` with custom error `enum`s.
  * In the past we've used `thiserror`, but have had good results with `snafu` and prefer to
    continue with `snafu`.
- Provide `From` implementations for error conversion between layers.
- Generic error type parameters are used in wallet crates to stay storage-agnostic.

### Type Safety

Type safety is paramount. This is a security-critical codebase.

- Struct fields must be private (or `pub(crate)`). Expose constructors returning
  `Result` or `Option` that enforce invariants, plus accessor methods.
- Make invalid states unrepresentable.
- Error enum types (and ONLY error enum types) should be non-exhaustive.
- Use newtypes over bare integers, strings, and byte arrays. Avoid `usize` except for
  Rust collection indexing.
- Use `enum`s liberally. Prefer custom `enum` variants with semantic meaning over
  boolean arguments/return values.
- Prefer immutability. Only use `mut` when strictly needed for performance.
- When structured enum variants are needed, wrap an immutable type rather than using
  inline fields, to ensure safe construction. This can be relaxed for error enum types.
- No magic numbers: give every literal a named `const` with a documented meaning. Prefer an
  existing protocol constant (e.g. `zcash_protocol::value::COIN` / `MAX_MONEY`,
  `zip317::MARGINAL_FEE`) over redefining one.
- Make a library `no_std` (with `extern crate alloc`) whenever its dependencies allow it, keeping
  `std` to `#[cfg(test)]` and dev-dependencies.

### Naming — Project-Specific Conventions

- Feature flags: `kebab-case` — `transparent-inputs`, `test-dependencies`
- Acronyms as words in types: `TxId`, `Pczt`, `Ufvk` (not `TXID`, `PCZT`)
- Proptest generators: `arb_` prefix — `arb_bundle`, `arb_transparent_addr`
  * If possible use `proptest` for rigorous testing, especially when parsing

### Visibility

- `pub` items MUST be intentionally part of the public API. No public types in private
  modules (exception: sealed trait pattern).
- Use `pub(crate)` for internal sharing between modules.
- Test-only constructors/utilities go behind `#[cfg(any(test, feature = "test-dependencies"))]`.

### Documentation

- All public API items MUST have complete `rustdoc` doc comments (`///`).
  * Document all error cases
- Crate-level docs use `//!` at the top of `lib.rs`.
- Reference ZIP/BIP specs with markdown links: `/// [ZIP 316]: https://zips.z.cash/zip-0316`
- Use backtick links for cross-references to other items.
- All crates must have `#![deny(rustdoc::broken_intra_doc_links)]`.

### Serialization

- All serialized data MUST be versioned at the top level.
- Do NOT use derived `serde` serialization except in explicitly marked cases (e.g. `pczt`).
- Serialization-critical types must not be modified after public release.

### Side Effects & Capability-Oriented Programming

- Write referentially transparent functions where possible.
- Use `for` loops (not `map`/iterator chains) when the body produces side effects.
- Provide side-effect capabilities as explicit trait arguments (e.g., `clock: impl Clock`).
- Define capability traits in terms of domain types, not implementation details.

## Architecture Patterns

- **Authorization typestate**: Bundles are parameterized by `Authorization` associated
  types to enforce compile-time correctness of transaction construction stages.
- **`no_std` by default**: Most crates use `#![no_std]` with `extern crate alloc`.
  The `std` feature is optional.
- **`MapAuth` trait**: Transforms authorization types during transaction construction.
- **`from_parts` constructors**: Preferred over public struct fields.
- **`testing` submodules**: Exposed via `test-dependencies` feature for cross-crate
  test utilities (proptest strategies, mock implementations).
- **Instance-parameterized store modules**: a persistence module keeps its generic
  machinery private (DDL builders parameterized by table names, the
  connection wrapper) and exposes ONE public submodule per concrete
  instantiation that binds the table names, so nothing generic leaks and the
  table names reflect the instance (e.g. `zcash_client_sqlite`'s
  `pool_migration::orchard_ironwood` over `orchard_ironwood_migrations`). A
  second instance is a sibling submodule, not a fork. The blob (de)serialization is not defined here: it is the canonical
  codec on the types (see the serialization convention above), which the store
  calls.

## Database Write Atomicity (`zcash_client_sqlite`)

`rusqlite` autocommits every statement executed outside an explicit transaction. A
sequence of writes that must land together will therefore commit one at a time unless
it is wrapped, and a failure partway through (an I/O error, a full disk, a crash, or an
error returned by a later step) leaves a subset committed. Downstream wallets have
shipped real bugs of this shape against this crate's API, so it is checked on every
change that writes to the wallet database.

**Before writing or reviewing any code that writes to the wallet database, answer these
four questions in order.** Answer them in the PR description when the answer to the
first is "more than one".

1. **How many writes does this operation issue?** Count every `INSERT`, `UPDATE`, and
   `DELETE`, including those inside loops and inside the functions it calls. If the
   answer is one, stop here. Otherwise continue.
2. **Must they land together?** Is there any subset of these rows that, if committed
   alone, the rest of the wallet would treat as valid state? If so, they must share one
   transaction.
3. **What happens on retry?** Assume the operation failed after committing a subset and
   the caller runs it again. Does the retry repair the state, or does it refuse,
   diverge, or duplicate? This is the question that decides whether a partial write is
   a transient annoyance or a permanent one, and it is the one most often skipped.
4. **Does any read path see only one side?** If one store is reachable through an API
   that never consults the other, a partial write surfaces to the caller as valid data.

Two patterns turn a partial write into an unrecoverable one. Either of them present in
a multi-write operation is a hard requirement for a transaction, not a judgement call:

- **One-shot guards.** A check of the form "if this table is non-empty, refuse" turns a
  partial commit into a permanent refusal to ever finish the operation. The guard MUST
  also run inside the transaction, against the same connection. Reading it on a
  separate connection is both outside the rollback and a check-then-act race.
- **Asymmetric read paths.** When one API reads a table that another write path owns, a
  half-committed write is visible through one and absent through the other.

### Which primitive to use

- Several `WalletRead` or `WalletWrite` operations that must be atomic with each other:
  `WalletDb::transactionally`.
- A wallet write that must be paired with a write to an application's own
  `ext_`-prefixed tables: `WalletDb::transactionally_with_extension`. Do not expose the
  connection to let a caller hand-roll this; the private connection is what enforces
  the crate's invariants.
- Within the crate, a write helper that may be called from inside an existing
  transaction MUST take a `&rusqlite::Transaction` (or the transaction-scoped handle)
  rather than opening its own, so callers can compose it. A helper that opens its own
  transaction cannot be made atomic with anything else.

A `rusqlite` transaction cannot be held across an `.await`. Callers must hoist async
work outside it, so an API that forces async work into the middle of a write sequence
is an API that cannot be used atomically. Prefer signatures that let the caller
pre-compute async inputs and pass them in.

### Never discard an error inside a transaction closure

The `WalletDb<SqlTransaction<'_>>` implementations take no savepoint per method, so a
`WalletWrite` call that fails partway leaves its partial writes sitting in the
enclosing transaction. Nothing undoes them on its own: the rollback happens only
because the error propagates out of the closure and the `Transaction` is dropped
uncommitted. Discarding an error inside the closure (`let _ = ...`, `.ok()`, or a
`match` arm that logs and continues) therefore commits that partial state, and the
enclosing `transactionally` still returns `Ok`. Inside a `transactionally` or
`transactionally_with_extension` closure, every fallible call MUST propagate with `?`.
This is the load-bearing assumption of the whole design; do not weaken it locally.

Note also that atomicity does not compose across calls. `WalletDb<C: BorrowMut<Connection>>`
implements both `WalletWrite` and `WalletCommitmentTrees`, and each method there opens
its own transaction, so two sequential calls are two commits with an inconsistent
window between them. Nothing in the signatures says so. Sequences that must be atomic
have to be moved inside one `transactionally` closure.

### Documenting atomicity on `WalletWrite`

`WalletWrite` is implemented by storage backends this crate does not control, and its
callers cannot see whether a given method is atomic. Every trait method in
`zcash_client_backend::data_api` that mutates more than one piece of state MUST state
its atomicity requirement in its rustdoc, in the terms the `apply_tree_changes` doc
comment uses: whether an implementation is required to apply the whole update or none
of it, and what the caller may assume after an error. A method with a multi-part update and no
such sentence is an incomplete specification; add it when you touch the method.

### Test evidence

A change that adds or modifies a multi-statement write MUST come with a test that
returns an error from inside the transaction and asserts that none of the writes
persisted. See `transactionally_with_extension_rolls_back_on_error` in
`zcash_client_sqlite/src/lib.rs` for the shape. Asserting that the success path commits
is not sufficient; the bug being guarded against is on the failure path.

## Branching & Merging

This repository uses a **merge-based workflow**. Squash merges are not permitted.

### SemVer Policy

We enforce strict **Rust-Flavored SemVer** compliance. MSRV (Minimum Supported Rust
Version) bumps are considered **SemVer-breaking changes**.

### Branching for Bug Fixes

Maintenance branches exist for released crate versions (e.g. `maint/zcash_client_sqlite-0.18.x`,
`maint/zcash_primitives-0.26.x`). When fixing a bug in released code:

1. Branch from the **earliest existing `maint/` branch** for the crate in question, so
   that the fix can be included in a semver-compatible release.
2. If no `maint/` branch exists for the crate, branch from the latest release tag at the
   Rust-flavored semver "breaking" version (i.e. `x.y.z` for `0.x` crates, or `x.0.0`
   for `1.x+` crates) depended upon by the earliest `maint/zcash_client_sqlite` branch
   available.
3. The fix is then forward-merged into newer `maint/` branches and eventually `main`.

### Feature Work

New features and non-fix changes should branch from `main`.

## Changelog & Commit Discipline

- Update the crate's `CHANGELOG.md` for any public API change, bug fix, or
  semantic change. CHANGELOG updates must **only** reflect completed changes.
  since the last release, and never interstitial changes in APIs that have been
  changed multiple times since the last release. The CHANGELOG entry **MUST** be
  part of the commit that makes the API change. For newly added crates, the CHANGELOG
  should include **ONLY** a line indicating the initial release; as there is no prior
  release, there are no API changes for a user to adapt to. CHANGELOG entries should
  provide **only** the information needed for end users to adapt to API changes, and
  **never** describe implementation details or contracts that are not visible to
  a user of the public API.
- Commits must be discrete semantic changes — no WIP commits in final PR history.
- Each commit that alters public API must also update docs and changelog in the same commit.
- Use `git revise` to maintain clean history within a PR.
- Commit messages: short title (<120 chars), body with motivation for the change.

## CI Checks (all must pass)

- `cargo test --workspace` across 6 feature-flag configurations
- `cargo clippy --all-features --all-targets -- -D warnings`
- `cargo fmt --all -- --check`
- Intra-doc link validation (nightly)
- Protobuf generated code consistency
- UUID validity for SQLite migrations
- `cargo-deny` license checking, `cargo-vet` supply chain audits — adding or
  bumping dependencies requires new audit entries, so dependency changes have
  a real review cost; avoid unnecessary dependency churn
