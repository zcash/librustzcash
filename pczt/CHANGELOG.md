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
- Migrated to `zcash_protocol 0.10.0-pre.0`, `zcash_transparent 0.9.0-pre.0`,
  `zcash_primitives 0.29.0-pre.0`, `zcash_proofs 0.29.0-pre.0`.
- The empty states of the transparent, Sapling, Orchard, and Ironwood bundles
  now have a single canonical representation, produced consistently by the
  Creator, `Creator::build_from_parts`, the serialization formats, and the IO
  Finalizer, so that copies of a PCZT that take different serialization paths
  continue to merge successfully:
  - `Creator::build_from_parts` now uses an all-zeroes anchor (rather than the
    empty-tree root) for absent Sapling and Orchard bundles.
  - The Creator now initializes empty bundle value sums as non-negative zero.
  - The IO Finalizer no longer sets `bsk` on an empty Orchard-protocol bundle.
  - An Orchard-protocol bundle whose fields differ from the canonical empty
    representation is no longer omitted from (and then lossily restored by)
    the v2 serialization format, and the v1 serialization format refuses to
    encode a PCZT whose Ironwood bundle is not canonically empty, rather than
    silently dropping its non-default fields.
- Every PCZT role that parses the Orchard-pool bundle derives its bundle
  version from the PCZT's consensus branch ID, and returns an
  `UnsupportedConsensusBranchId` error when that branch ID is unrecognized or
  predates NU5.
- `pczt::roles::creator::Creator::new` now selects the v6 transaction format
  (and its version group ID) for consensus branch IDs at NU6.3 or later;
  previously the v5 format was always used.
- Transaction extraction now rejects v6 PCZTs whose consensus branch ID
  predates NU6.3, and non-v6 PCZTs that carry non-canonical Ironwood bundle
  data.
- The v1 serialization format refuses to encode v6 PCZTs, which a v1 parser
  could decode but never extract a transaction from.
- `pczt::roles::low_level_signer::Signer::sign_orchard_with` now bounds its
  error parameter by `From<pczt::roles::low_level_signer::OrchardParseError>`
  instead of `From<orchard::pczt::ParseError>` (as does the new
  `sign_ironwood_with`).
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
- The low-level Signer's `sign_orchard_with` and `sign_ironwood_with` now parse
  the bundle with a preverified signing parse that skips deriving each spend's
  full viewing key, driven by a bounded loop that keeps parsing stack usage flat
  on constrained devices. These methods no longer validate the wire `fvk` bytes
  (callers must first run the full Verifier checks over the identical PCZT bytes)
  but preserve them unchanged in the returned PCZT. The signing closure must not
  add, remove, or reorder actions; doing so now returns the new
  `pczt::roles::low_level_signer::OrchardParseError::SigningClosureModifiedActions`
  error and leaves the PCZT unmodified.
- The derived fields of the logical Orchard-shaped bundles are now optional, so
  a producer can elide them from the serialized encoding and let the receiver
  recompute them (byte-identically) from the note component fields it already
  holds:
  - `pczt::orchard::Action::cv_net`, `pczt::orchard::Spend::{nullifier, rk}`,
    and `pczt::orchard::Output::{cmx, ephemeral_key, enc_ciphertext}` (and their
    getters) are now `Option`al. `Output::out_ciphertext` remains required, as
    it is RNG-derived and can never be recomputed.
  - `pczt::orchard::Bundle::anchor` (and its getter) is now `Option`al. An
    elided anchor is refilled with the fixed `Anchor::empty_tree()` placeholder
    rather than recomputed, which is only sound on transports where the anchor
    is not part of the signed data (the v6 transaction format excludes it from
    the txid/sighash digest); the extracting wallet must install the real
    anchor.
  - The Combiner merges these fields like other optional fields, so a
    fully-populated copy fills a peer's omissions.
  - Parsing an Orchard-shaped bundle (in any role) recomputes elided fields
    before constructing the protocol types, so every parsing consumer continues
    to see fully-populated actions. In particular the low-level Signer accepts
    an elided PCZT and returns it filled.
  - The version 2 encoding carries these fields as optional (and each output's
    memo-kind tag), so an elided PCZT serializes without them. The released
    version 1 encoding is unchanged on the wire; it cannot represent the
    omissions and rejects such PCZTs with the new
    `pczt::EncodingError::RequiresV2`.

### Added
- `pczt::orchard::MemoKind`, a one-byte tag naming the memo (all-zero, or the
  ZIP 302 empty memo) under which an elided `enc_ciphertext` is reconstructed.
- `pczt::orchard::Output::memo_kind`, the elision metadata set by the Redactor
  and consumed by the fill.
- `pczt::Pczt::fill_derived_fields` and
  `pczt::orchard::Bundle::fill_derived_fields`, which recompute and fill every
  elided derived field in place (the inverse of the redactor's `clear_*`
  methods), for consumers that read the wire-format fields directly.
- `pczt::orchard::FillError`, the error type of the fill.
- `pczt::roles::low_level_signer::OrchardParseError::Fill`.
- Redactor methods for eliding the recomputable fields:
  `pczt::roles::redactor::orchard::ActionRedactor::{clear_cv_net,
  clear_nullifier, clear_rk, clear_cmx, clear_ephemeral_key,
  clear_enc_ciphertext}` and
  `pczt::roles::redactor::orchard::OrchardRedactor::clear_anchor`.
- `pczt::roles::creator::Error`, the error type returned by the now-fallible
  `Creator` methods.
- `pczt::parse`, a free function for parsing PCZT encodings.
- `pczt::EncodingError`, for errors that can occur during PCZT encoding.
- `pczt::EncodingError::UnsupportedOrchardNoteVersion`, returned when an
  Orchard note plaintext version cannot be represented in the version 1 PCZT
  encoding.
- `pczt::EncodingError::RequiresV2`, returned when a PCZT that elides derived
  fields or an anchor (or carries a memo-kind tag) is encoded to the version 1
  PCZT encoding, which cannot represent the omissions.
- `pczt::v1`, a module providing the version 1 PCZT serialization format via
  `pczt::v1::Pczt`.
- PCZT version 2 serialization, which encodes the Orchard note plaintext
  version at the Orchard bundle level, and in which the six derived
  Orchard-shaped fields and the bundle anchor may be omitted and each output
  carries an optional memo-kind tag.
- `PartialEq` is now derived for the logical `pczt::transparent::{Bundle, Input,
  Output}`, `pczt::sapling::{Bundle, Spend, Output}`, and
  `pczt::orchard::{Bundle, Action, Spend, Output}` types (used to detect empty
  bundles for v2 serialization).
- The logical `pczt::Pczt` type now includes an Ironwood bundle.
- Ironwood PCZT role support.
- `pczt::ExtractError::UnsupportedConsensusBranchId`
- `pczt::ExtractError::IronwoodNotSupported`
- `pczt::roles::creator::Creator::{with_ironwood_anchor, with_ironwood_flags}`
- `pczt::roles::signer::Signer::{sign_ironwood, apply_ironwood_signature}`
- `pczt::roles::signer::Error::{IronwoodSign, IronwoodVerify}`
- `pczt::roles::verifier::Verifier::with_ironwood`
- `pczt::roles::updater::Updater::update_ironwood_with`
- `pczt::roles::creator::Error::IronwoodNotSupported`
- `pczt::roles::low_level_signer::OrchardParseError`
- `UnsupportedConsensusBranchId` variants of `pczt::roles::updater::OrchardError`,
  `pczt::roles::verifier::OrchardError`, and `pczt::roles::prover::OrchardError`.
- `pczt::compact_migration`, a compact transport encoding for migration child
  PCZTs and batches, plus `Pczt::fill_missing_spend_fvks_for_zip32_path` and
  `pczt::orchard::Bundle::fill_missing_spend_fvks_for_zip32_path` for restoring
  omitted spend FVKs from wallet-known ZIP 32 account keys before signing.

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
