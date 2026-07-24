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
- `pczt::Pczt`'s Orchard/Ironwood bundle spends now expose their `witness` field
  via a getter.
- `pczt::roles::redactor::orchard::OrchardRedactor::compact_resolvable_fields`,
  behind the `orchard` feature, which compacts the Orchard-protocol (Orchard and
  Ironwood) action fields that `pczt::orchard::Bundle::resolve_fields` can restore.
- `pczt::orchard::AnchorConsistencyError` and `pczt::sapling::AnchorConsistencyError`,
  behind the `prover` feature combined with the `orchard` / `sapling` feature
  respectively: the witness-to-anchor consistency errors the `Prover` role
  reports via its `InconsistentWitness` error variants.

### Changed
- Migrated to `zcash_transparent 0.10.0`.
- Serializing an Orchard-protocol bundle built with its anchor deferred to
  proving time (`orchard`'s `Builder::new_with_anchor_deferred`, ZIP 374) now
  emits the bundle's anchor as ABSENT (its real spends' witnesses are already
  absent), for the `Updater` role to install at proving time.

## [0.8.0-rc.1] - 2026-07-12

### Changed
- MSRV is now 1.88
- Migrated to `zcash_protocol 0.10.0`, `zcash_transparent 0.9.0`,
  `zcash_primitives 0.29.0`, `zcash_proofs 0.29.0`,
  `orchard 0.15`, `shardtree 0.7`.
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
- `pczt::roles::creator::Creator::new` now takes optional Sapling and Orchard
  anchors. These may be [`None`] for v6 transactions, but v5 transactions still
  require an anchor for each corresponding non-empty shielded bundle when the
  PCZT is built.
- `pczt::roles::creator::Creator::build` is now fallible, returning
  `Result<Pczt, pczt::roles::creator::Error>`.
- `pczt::roles::creator::Creator::with_orchard_flags` is now fallible, returning
  `Result<Self, pczt::roles::creator::Error>`. The Orchard bundle version (and
  hence the note-plaintext version and flag-byte encoding) is now derived from the
  consensus branch ID passed to `Creator::new` rather than supplied by the caller,
  and the flags are validated against it.
- PCZT version 1 is now treated as a serialization format for the logical
  `pczt::Pczt` type.
- The Orchard PCZT logical model now represents the bundle anchor and per-action
  `cv_net` as optional fields, matching the version 2 encoding. The logical
  Orchard output model now similarly represents `cmx` as optional. Parsing
  resolves absent `cv_net` values from the note values and `rcv`, and absent
  `cmx` values from the output note fields and action spend nullifier; absent
  anchors remain absent until another PCZT copy or caller restores them.
- The logical Orchard output model now represents its encrypted note plaintext
  as `pczt::orchard::EncCiphertext`, allowing v2 serialization to carry either
  encrypted ciphertext or a trailing-zero-stripped
  `pczt::orchard::MemoPlaintext`.
- Direct `serde` serialization implementations have been removed from the
  logical `pczt::orchard::{Bundle, Action, Spend, Output}` types.
- `pczt::Pczt::serialize` now consumes `self` and returns
  `Result<Vec<u8>, pczt::EncodingError>` rather than borrowing `self` and
  returning `Vec<u8>`.
- The low-level Signer's `sign_orchard_with` and `sign_ironwood_with` now parse
  the bundle with a preverified signing parse that skips deriving each spend's
  full viewing key. These methods no longer validate the wire `fvk` bytes
  (callers must first run the full Verifier checks over the identical PCZT bytes)
  but preserve them unchanged in the returned PCZT. The signing closure must not
  add, remove, or reorder actions; doing so now returns the new
  `pczt::roles::low_level_signer::OrchardParseError::SigningClosureModifiedActions`
  error and leaves the PCZT unmodified.
- PCZT roles that do not consume shielded anchors now preserve absent Sapling,
  Orchard, and Ironwood anchors while parsing v6 transactions. Proving and
  transaction extraction still require anchors for non-empty Sapling, Orchard,
  and Ironwood bundles.
- The Sapling, Orchard, and Ironwood Provers now reject non-zero-valued spends
  whose witnesses do not root to the bundle anchor before creating proofs.
- PCZT parse errors surfaced by Sapling and Orchard role APIs now use
  `pczt::sapling::ParseError` and `pczt::orchard::ParseError`, so callers can
  distinguish missing anchors from other malformed bundle data.

### Added
- `pczt::roles::creator::Error`, the error type returned by the now-fallible
  `Creator` methods.
- `pczt::roles::creator::Error::AnchorRequiredForV5`, returned when building a
  v5 PCZT with a non-empty shielded bundle whose anchor is missing.
- `pczt::parse`, a free function for parsing PCZT encodings.
- `pczt::EncodingError`, for errors that can occur during PCZT encoding.
- `pczt::EncodingError::UnsupportedOrchardNoteVersion`, returned when an
  Orchard note plaintext version cannot be represented in the version 1 PCZT
  encoding.
- `pczt::EncodingError::RequiresV2`, returned when v1 serialization cannot
  represent v2-only logical PCZT data.
- `pczt::ParseError::MissingRequiredField`, returned when the PCZT encoding
  omits a field that the logical PCZT type still requires.
- `pczt::orchard::{EncCiphertext, MemoPlaintext}` for representing encrypted note
  plaintext data in the logical Orchard output model.
- `pczt::Pczt::resolve_fields`,
  `pczt::orchard::Bundle::{resolve_fields, resolve_memo_plaintexts}`, and
  `pczt::roles::redactor::orchard::ActionRedactor::{replace_enc_ciphertext_with_memo_plaintext, replace_enc_ciphertext_with_decrypted_memo_plaintext}`.
- `pczt::roles::redactor::orchard::OrchardRedactor::clear_anchor`,
  `pczt::roles::redactor::sapling::SaplingRedactor::clear_anchor`, and
  `pczt::roles::redactor::orchard::ActionRedactor::clear_cv_net`.
- `pczt::roles::redactor::orchard::ActionRedactor::clear_cmx`.
- `pczt::v1`, a module providing the version 1 PCZT serialization format via
  `pczt::v1::Pczt`.
- `pczt::v2`, a module providing the version 2 PCZT serialization format via
  `pczt::v2::Pczt`, which encodes the Orchard note plaintext version at the
  Orchard bundle level and omits empty Transparent, Sapling, and Orchard bundles.
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
- `pczt::roles::signer::SpendAuthSignature`,
  `pczt::roles::signer::extract_orchard_spend_auth_signatures`, and
  `pczt::roles::signer::Signer::apply_orchard_spend_auth_signature` for transporting
  Orchard and Ironwood spend authorization signatures separately from a PCZT.
- `pczt::roles::signer::batch` request and response types for transporting batches
  of PCZTs to an external signer and returning their Orchard and Ironwood spend
  authorization signatures. Sapling spend authorization signatures are not represented.
  Requests expose logical `Pczt` values, and both directions preserve request order in a
  magic-prefixed, versioned Postcard wire format. A request carries one shared PCZT wire
  version followed by headerless PCZT payloads. Request and response correlation is left
  to the application transport.
- `pczt::roles::verifier::Verifier::with_ironwood`
- `pczt::roles::updater::Updater::update_ironwood_with`
- `pczt::roles::updater::AnchorUpdateError` and
  `pczt::roles::updater::Updater::{set_sapling_anchor, set_orchard_anchor,
  set_ironwood_anchor}` for wallets that need to restore shielded anchors after
  signing.
- `pczt::roles::updater::Updater::{set_sapling_spend_witnesses,
  set_orchard_spend_witnesses, set_ironwood_spend_witnesses}` for restoring
  shielded spend witnesses before proof creation.
- `pczt::roles::updater::SpendWitnessUpdateError`
- `pczt::roles::creator::Error::IronwoodNotSupported`
- `pczt::roles::low_level_signer::OrchardParseError`
- `UnsupportedConsensusBranchId` variants of `pczt::roles::updater::OrchardError`,
  `pczt::roles::verifier::OrchardError`, and `pczt::roles::prover::OrchardError`.
- `pczt::sapling::ParseError`, `pczt::sapling::AnchorConsistencyError`
- `pczt::orchard::ParseError`, `pczt::orchard::AnchorConsistencyError`
- `pczt::roles::prover::SaplingError::InconsistentWitness`
- `pczt::roles::prover::OrchardError::InconsistentWitness`
- `pczt::roles::prover::IronwoodError::InconsistentWitness`

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
