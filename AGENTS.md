# AGENTS.md

This is a Rust workspace of cryptographic library crates for the Zcash protocol.
Our priorities are **security, performance, and convenience** — in that order.
Rigor is highly valued throughout the codebase.

Many people depend on these libraries and we prefer to "do it right" the first time,
then "make it fast".

## Contribution Policy

Before contributing please see the [CONTRIBUTING.md] file.

Before opening a PR, ensure there is a related GitHub issue with discussion justifying
the work. PRs without a prior issue and maintainer acknowledgment _may_ be closed without
review. If no issue exists, open one first and wait for feedback before starting work.

- All PRs require human review from a maintainer. This incurs a cost upon the dev team,
  so ensure your changes are not frivolous.
- Keep changes focused — avoid unsolicited refactors or broad "improvement" PRs.
- If AI tools were used, disclose the tool and scope in the PR description.
- See also the license and contribution terms in `README.md`.

## Crate Architecture

See `README.md` for the full dependency graph (Mermaid diagram). Below is a text summary
since LLMs cannot render diagrams.

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
- `zcash_protocol` is the lowest layer in this repo — most crates depend on it.
- `zcash_client_sqlite` sits at the top, depending on `zcash_client_backend`.

## Build & Test Commands

For the most part we follow standard Rust `cargo` practices.

**Important:** This workspace requires `--all-features` for builds and tests to match CI.

```sh
# Check without codegen (fastest iteration)
cargo check --workspace --all-features

# Build entire workspace
cargo build --workspace --all-features

# Test entire workspace (matches CI)
cargo test --workspace --all-features
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

## Key Feature Flags

- `test-dependencies` — exposes proptest strategies and mock types for downstream testing
- `transparent-inputs`, `transparent-key-import`, `transparent-key-encoding`
- `orchard` — Orchard shielded protocol support
- `bundled-prover`, `download-params` — Sapling proving
- `lightwalletd-tonic`, `sync` — light client gRPC and sync
- `unstable`, `unstable-serialization`, `unstable-spanning-tree`
- `expensive-tests` — computationally expensive test suite
- Unstable cfg flags: `zcash_unstable="zfuture"`, `zcash_unstable="nu7"`

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
- Enums should be non-exhaustive.
- Use newtypes over bare integers, strings, and byte arrays. Avoid `usize` except for
  Rust collection indexing.
- Use `enum`s liberally. Prefer custom `enum` variants with semantic meaning over
  boolean arguments/return values.
- Prefer immutability. Only use `mut` when strictly needed for performance.
- When structured enum variants are needed, wrap an immutable type rather than using
  inline fields, to ensure safe construction.

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

- Update the crate's `CHANGELOG.md` for any public API change, bug fix, or semantic change.
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
