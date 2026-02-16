# AGENTS.md

This is a Rust workspace of cryptographic library crates for the Zcash protocol.
Our priorities are **security, performance, and convenience** — in that order.
Rigor is highly valued throughout the codebase.

Many people depend on these libraries and we prefer to "do it right" the first time,
then "make it fast".

## Build Commands

```sh
# Build entire workspace (all features)
cargo build --workspace --all-features

# Build a single crate
cargo build -p zcash_client_backend

# Check without codegen (faster)
cargo check --workspace --all-features
```

## Test Commands

Tests are computationally expensive (cryptographic proofs). The `[profile.test]` uses
`opt-level = 3` by default. Use `--profile=dev` for faster compilation during iteration.

```sh
# Test entire workspace (all features — matches CI)
cargo test --workspace --all-features

# Test a single crate
cargo test -p zcash_client_sqlite

# Test a single test by name
cargo test -p zcash_client_sqlite <test_name>
cargo test <test_name> -- --exact

# Test with stdout visible
cargo test <test_name> -- --nocapture

# Fast unoptimized build (skip opt-level=3 test profile)
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

### Naming Conventions

- Types/Structs/Enums: `CamelCase` — `UnifiedFullViewingKey`, `TransparentAddress`
- Functions/Methods: `snake_case` — `from_seed`, `value_balance`
- Constants: `UPPER_SNAKE_CASE` — `MAGIC_BYTES`, `SAPLING_SHARD_HEIGHT`
- Modules: `snake_case` — `data_api`, `compact_formats`
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
