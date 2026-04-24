# Changelog
All notable changes to this library will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this library adheres to Rust's notion of
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Future releases are
indicated by the `PLANNED` status in order to make it possible to correctly
represent the transitive `semver` implications of changes within the enclosing
workspace.

## [Unreleased]

### Added
- `pczt::ExtractError`
- `pczt::EffectsOnly`
- `pczt::orchard::Spend::spend_auth_sig` getter (via `getset`).
- `pczt::roles::signer`:
  - `Signer::sighash`
  - `Signer::append_transparent_signature`
  - `Signer::apply_sapling_signature`
  - `Signer::apply_orchard_signature`

### Changed
- Migrated to `orchard 0.13`, `sapling-crypto 0.7`, `zcash_protocol 0.8`, 
  `zcash_transparent 0.7`, `zcash_primitives 0.27`.
- `Pczt::into_effects` now returns `Result<TransactionData<EffectsOnly>, ExtractError>`
  instead of `Option<TransactionData<EffectsOnly>>`.
- `pczt::roles::io_finalizer::Error` now wraps parse and extract errors
  via `Extract(ExtractError)` instead of individual variants.
- `pczt::roles::signer::Error` now wraps parse and extract errors
  via `Extract(ExtractError)` instead of individual variants.
- `pczt::roles::tx_extractor::Error` now wraps parse and extract errors
  via `Extract(ExtractError)` instead of `Global(GlobalError)`,
  `IncompatibleLockTimes`, and protocol-specific `Parse` variants.

### Removed
- `pczt::roles::tx_extractor::GlobalError` (replaced by `pczt::ExtractError`).
- `pczt::roles::tx_extractor::TransparentError::Parse` (parse errors now
  flow through `pczt::ExtractError`).
- `pczt::roles::tx_extractor::SaplingError::Parse` (parse errors now
  flow through `pczt::ExtractError`).
- `pczt::roles::tx_extractor::OrchardError::Parse` (parse errors now
  flow through `pczt::ExtractError`).
- `pczt::roles::signer::EffectsOnly` (use `pczt::EffectsOnly` instead).

## [0.4.1, 0.5.1] - 2026-02-26

### Fixed
- Several missing feature flags dependencies have been fixed. The following
  missing feature flag dependencies have been added:
  - `signer` for the `io-finalizer` feature due to cross-role code reuse
  - `rand_core/getrandom` required by the `io-finalizer`, `prover`,
    `signer`, and `tx-extractor` features for `OsRng` access
  - `orchard/circuit` and `sapling/circuit` for the `prover`
    and `tx-extractor` features.

## [0.5.0] - 2025-11-05

### Changed
- MSRV is now 1.85.1.
- Migrated to `zcash_protocol 0.7`, `zcash_transparent 0.6`, `zcash_primitives 0.26`,
  `zcash_proofs 0.26`

## [0.4.0] - 2025-09-25

### Changed
- Migrated to `zcash_protocol 0.6`, `zcash_transparent 0.5`, `zcash_primitives 0.25`,
  `zcash_proofs 0.25`

## [0.3.0] - 2025-05-30

### Changed
- Migrated to `zcash_transparent 0.3`, `zcash_primitives 0.23`, `zcash_proofs 0.23`

## [0.2.1] - 2025-03-04

Documentation improvements and rendering fix; no code changes.

## [0.2.0] - 2025-02-21

### Added
- `pczt::common`:
  - `Global::{tx_version, version_group_id, consensus_branch_id, expiry_height}`
  - `determine_lock_time`
  - `LockTimeInput` trait
- `pczt::orchard`:
  - `Bundle::{flags, value_sum, anchor}`
  - `Action::cv_net`
  - `Spend::rk`
  - `Output::{cmx, ephemeral_key, enc_ciphertext, out_ciphertext}`
- `pczt::roles`:
  - `low_level_signer` module
  - `prover::Prover::{requires_sapling_proofs, requires_orchard_proof}`
  - `redactor` module
- `pczt::sapling`:
  - `Bundle::{value_sum, anchor}`
  - `Spend::{cv, nullifier, rk}`
  - `Output::{cv, cmu, ephemeral_key, enc_ciphertext, out_ciphertext}`
- `pczt::transparent`:
  - `Input::{sequence, script_pubkey}`
  - `Output::{value, script_pubkey}`

### Changed
- MSRV is now 1.81.0.
- Migrated to `nonempty 0.11`, `secp256k1 0.29`, `redjubjub 0.8`, `orchard 0.11`,
  `sapling-crypto 0.5`, `zcash_protocol 0.5`, `zcash_transparent 0.2`,
  `zcash_primitives 0.22`.


## [0.1.0] - 2024-12-16
Initial release supporting the PCZT v1 format.
