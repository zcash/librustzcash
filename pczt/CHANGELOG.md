# Changelog
All notable changes to this library will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this library adheres to Rust's notion of
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Future releases are
indicated by the `PLANNED` status in order to make it possible to correctly
represent the transitive `semver` implications of changes within the enclosing
workspace.

## [0.8.0] - PLANNED

### Changed
- `pczt::roles::creator::Creator::new` is now fallible, returning
  `Result<Self, pczt::roles::creator::Error>`; it rejects unrecognized consensus
  branch IDs and upgrades that predate the v5 transaction format.
- `pczt::roles::creator::Creator::with_orchard_flags` is now fallible, returning
  `Result<Self, pczt::roles::creator::Error>`. The Orchard bundle version (and
  hence the note-plaintext version and flag-byte encoding) is now derived from the
  consensus branch ID passed to `Creator::new` rather than supplied by the caller,
  and the flags are validated against it.
- PCZT version 1 is now treated as a serialization format for the logical
  `pczt::Pczt` type.
- The Orchard PCZT logical model now tracks the Orchard bundle's note plaintext
  version separately from the version 1 serialization format.
- PCZT version 2 serialization now omits empty Transparent, Sapling, and
  Orchard bundles.
- Direct `serde` serialization implementations have been removed from the
  logical `pczt::orchard::{Bundle, Action, Spend, Output}` types.
- `pczt::Pczt::serialize` now consumes `self` and returns
  `Result<Vec<u8>, pczt::EncodingError>` rather than borrowing `self` and
  returning `Vec<u8>`.

### Added
- `pczt::roles::creator::Error`, the error type returned by the now-fallible
  `Creator` methods.
- `pczt::parse`, a free function for parsing PCZT encodings.
- `pczt::EncodingError`, for errors that can occur during PCZT encoding.
- `pczt::EncodingError::UnsupportedOrchardNoteVersion`, returned when an
  Orchard note plaintext version cannot be represented in the version 1 PCZT
  encoding.
- `pczt::v1`, a module providing the version 1 PCZT serialization format via
  `pczt::v1::Pczt`.
- PCZT version 2 serialization, which encodes the Orchard note plaintext
  version at the Orchard bundle level.
- `PartialEq` is now derived for the logical `pczt::transparent::{Bundle, Input,
  Output}`, `pczt::sapling::{Bundle, Spend, Output}`, and
  `pczt::orchard::{Bundle, Action, Spend, Output}` types (used to detect empty
  bundles for v2 serialization).
- The logical `pczt::Pczt` type now includes an Ironwood bundle behind
  `zcash_unstable = "nu6.3"` and `zcash_unstable = "nu7"`.
- Ironwood PCZT role support behind `zcash_unstable = "nu6.3"` and
  `zcash_unstable = "nu7"`.

## [0.7.0] - 2026-06-02

### Changed
- Migrated to `zcash_protocol 0.9.0`, `zcash_transparent 0.8.0`, `zcash_primitives 0.28.0`,
  `zcash_proofs 0.28.0`.

### Fixed
- Updated to crate versions that fix an Orchard soundness vulnerability
  (GHSA-ww9q-8r59-xv46) and Orchard non-canonical proof size issue
  (GHSA-2x4w-pxqw-58v9).

## [0.6.0] - 2026-04-27

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
  `zcash_transparent 0.7`, `zcash_primitives 0.27`, `zcash_proofs 0.27`.
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
