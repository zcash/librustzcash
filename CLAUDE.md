# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

This repository contains `librustzcash`, a workspace of Rust crates for working with Zcash. These are production-grade cryptographic libraries used by Zcash wallets and light clients. The codebase is under active development with frequent SemVer major releases.

## Common Development Commands

### Building
```bash
# Build all crates in workspace
cargo build --workspace

# Build with specific feature combinations (important for testing different pool configurations)
cargo build --workspace --features transparent-inputs,orchard

# Build for release (with LTO and other optimizations)
cargo build --workspace --release

# Check compilation without building
cargo check --workspace
```

### Testing
```bash
# Run all tests in workspace
cargo test --workspace

# Run tests for a specific crate
cargo test -p zcash_client_backend
cargo test -p zcash_primitives

# Run tests with specific features
cargo test --workspace --features transparent-inputs,orchard

# Run expensive/slow tests (marked with expensive-tests feature)
cargo test --workspace --features expensive-tests

# Run tests in release mode (recommended for computationally expensive tests)
cargo test --workspace --release

# Run a single test by name
cargo test -p zcash_client_backend test_name

# Run tests with unstable features (NU7, ZFuture)
RUSTFLAGS='--cfg zcash_unstable="nu7"' cargo test --workspace --all-features
```

### Linting and Formatting
```bash
# Check code formatting
cargo fmt --all -- --check

# Format all code
cargo fmt --all

# Run clippy lints (treats warnings as errors in CI)
cargo clippy --all-features --all-targets -- -D warnings

# Run clippy on specific crate
cargo clippy -p zcash_primitives -- -D warnings
```

### Documentation
```bash
# Build documentation for all crates
cargo doc --workspace --no-deps

# Build documentation with all features enabled
cargo doc --workspace --all-features --no-deps

# Open documentation in browser
cargo doc --workspace --all-features --no-deps --open

# Check documentation links (requires nightly)
cargo +nightly doc --no-deps --workspace --all-features --document-private-items
```

### Other Verification
```bash
# Run security audits with cargo-vet (used in release process)
cargo vet

# Check for outdated dependencies
cargo outdated

# Build benchmarks to prevent bitrot
cargo build --all --benches
```

## Architecture

### Workspace Structure

The workspace is organized into three logical layers:

1. **Protocol Components** (in `components/`): Low-level, standalone utilities
   - `zcash_protocol`: Constants, consensus parameters, bounded types (Zatoshis, ZatBalance), memo types
   - `zcash_address`: Address parsing/serialization (unified addresses, no protocol dependencies)
   - `zcash_encoding`: Bitcoin-derived encoding utilities
   - `f4jumble`: Unified address encoding
   - `equihash`: Proof-of-work implementation

2. **Core Transaction & Key Crates**: Main protocol implementation
   - `zcash_transparent`: Bitcoin-derived transparent components (addresses, inputs, outputs, bundles)
   - `zcash_primitives`: Core transaction types, builders, proving, signing, serialization
   - `zcash_proofs`: Sprout circuit and proving system
   - `zcash_keys`: Keys, addresses, ZIP 32 derivation (spending keys, viewing keys, unified keys)
   - `zip321`: Payment request URI parsing/serialization
   - `pczt`: Partially Constructed Zcash Transactions (for hardware wallets, multisig)

3. **Wallet Framework Crates**: High-level wallet functionality
   - `zcash_client_backend`: Wallet framework with storage APIs, scanning, fee calculation, transaction construction
   - `zcash_client_sqlite`: SQLite implementation of wallet storage APIs
   - `zcash_client_memory`: In-memory implementation (for testing)

### Key Architectural Patterns

#### Data Storage Traits (in `zcash_client_backend::data_api`)

The wallet framework is built around four core traits that define data storage requirements:

- **`WalletRead`**: Read-only access to wallet data (accounts, transactions, notes)
- **`WalletWrite`**: Write operations (storing blocks, transactions, updating account data)
- **`InputSource`**: Query spendable notes for transaction construction
- **`WalletCommitmentTrees`**: Manage note commitment trees for witness computation

These traits are implemented by `zcash_client_sqlite` for production use.

#### Account Model

Wallets manage one or more accounts, each with:
- A unique `AccountId`
- A corresponding `UnifiedFullViewingKey` (for scanning/receiving)
- Optional `UnifiedSpendingKey` (provided externally for spending)
- Both external and internal addresses (per ZIP 316)

The wallet framework does NOT store spending keys; they must be provided by callers or delegated to external devices via PCZT.

#### Shielded Pool Support

Crates expose different shielded pools via cargo features:
- `transparent-inputs`: Enable transparent address support
- `orchard`: Enable Orchard pool support
- Default: Sapling support is always included

#### Transaction Construction Flow

1. **Proposal Generation** (`propose_transfer`, `propose_shielding`):
   - Takes `TransactionRequest`
   - Performs input selection automatically
   - Calculates fees
   - Returns `Proposal` object

2. **Transaction Creation** (`create_proposed_transactions`):
   - Takes `Proposal`
   - Constructs `Transaction`(s)
   - Stores to wallet database
   - Returns `TxId`(s)
   - Caller must retrieve, serialize, and broadcast

#### Migration System (SQLite)

`zcash_client_sqlite` uses a UUID-based migration system:
- Each migration has a unique UUID (must be type 4 random UUID)
- Migrations defined with `const MIGRATION_ID: Uuid = Uuid::from_u128(0x...)`
- The `schemerz` crate manages migration state
- Migrations must maintain backwards compatibility within SemVer guarantees

## Development Practices

### Type Safety Requirements

- Invalid states must be unrepresentable at the type level
- Use newtype wrappers instead of bare primitives in public APIs
- Prefer `enum`s over boolean flags
- Avoid `usize` except for collection indexing
- Provide safe constructors returning `Result<T>` or `Option<T>`
- Keep struct members private with validated constructors

### Public API Guidelines

- All `pub` items MUST be part of the public API (no public items in private modules)
- Testing-only APIs must be behind `test-dependencies` feature
- Breaking API changes require CHANGELOG updates
- All public APIs require complete rustdoc documentation

### Error Handling

- Use custom error `enum`s with `Result<T, E>`
- Implement `std::error::Error` for public error types
- Avoid `panic!` in library code

### Serialization Rules

- All serialized data must be versioned at the top level
- Do NOT use derived serialization (`serde`) except in specific cases (like `pczt`)
- Types using derived serialization are immutable after public release
- Ephemeral wire formats may relax these rules

### Functional Programming Style

- Write referentially transparent functions when possible
- Avoid mutation outside narrow scopes
- Use imperative style when side effects are involved (use `for` loops, not `.map()`)
- Pass capabilities explicitly (e.g., `clock: impl Clock` for time access)

### Git Workflow

- **"Unstable main" workflow**: `main` branch is preview of next release, not stable
- **Merge-based workflow**: PRs merged with merge commits (no squash or rebase-merge)
- **Clean commit history**: Use `git revise` to maintain clean history within PRs
- **Semantic commits**: Each commit represents discrete semantic change
- **CHANGELOG updates**: Required for all API changes, bug fixes, semantic changes
- **No WIP commits**: Exception for documented partial API changes or failing test commits
- **Draft PRs**: Open as Draft until CI passes

Branch from release tags:
- For breaking changes: branch from `main`
- For compatible changes: branch from most recent tag of previous major version

### Pull Request Review Process

- Reviewers add `S-please-do-not-rebase` label to prevent rebasing during active review
- Authors mark resolved review comments using GitHub UI
- Authors provide diff links between branch states for reviewer convenience
- Separate target branch rebases from review comment addressing
- Use GitHub suggestions for co-author attribution

### Code Quality Standards

- High standard of quality; violations will require changes
- Upgrade existing code to modern style when modifying it
- Separate functional changes from style refactoring in commit history
- Do NOT submit trivial PRs (spelling, links, minor style) without prior discussion

## Important Configuration

### Rust Toolchain
- Version: 1.85.1 (specified in `rust-toolchain.toml`)
- Edition: 2024
- Required components: clippy, rustfmt

### Feature Flags

Common feature combinations tested in CI:
- `transparent-inputs transparent-key-encoding`: Transparent pool only
- `orchard`: Orchard pool only (Sapling is default)
- `orchard transparent-inputs transparent-key-encoding`: All pools
- `--all-features`: Everything including optional features (sync, tor, pczt, etc.)

### Unstable Features

Controlled via `--cfg zcash_unstable`:
- `zfuture`: Future network upgrade features
- `nu7`: NU7 network upgrade features

### CI Test Profile

The test profile compiles with optimizations by default (`opt-level = 3`) due to expensive cryptographic operations, but keeps debug info. Use `--profile=dev` to speed up compilation during development.

## Crate-Specific Notes

### `zcash_client_backend`

Primary wallet framework. Key modules:
- `data_api`: Core traits and wallet operations
- `data_api::wallet`: Transaction construction (`propose_transfer`, `create_proposed_transactions`)
- `data_api::chain`: Blockchain scanning (`scan_cached_blocks`)
- `data_api::scanning`: Scan queue management
- `fees`: Fee calculation and change strategies

### `zcash_client_sqlite`

SQLite storage implementation. Key modules:
- `wallet`: Implements `WalletRead`, `WalletWrite`, `InputSource`
- `chain`: Block and tree storage, implements `WalletCommitmentTrees`
- `chain::migrations`: Database migration system with UUID tracking

### `zcash_primitives`

Core transaction primitives. Key modules:
- `transaction`: Main transaction types
- `transaction::builder`: Transaction builder
- `transaction::components`: Transparent, Sapling bundle types

### `pczt`

Partially Constructed Zcash Transactions:
- Role-based interfaces for constructing multi-party transactions
- Uses derived serialization (types are immutable after release)
- Supports hardware wallets and multisig scenarios

## Security Considerations

- These libraries are under development and not fully reviewed
- Security issues must be reported via https://z.cash/support/security/ (NOT public GitHub issues)
- Do not commit sensitive information (keys, tokens) to the repository
- Transparent address usage must be explicit to prevent privacy violations
