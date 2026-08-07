# Changelog
All notable changes to this library will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this library adheres to Rust's notion of
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Future releases are
indicated by the `PLANNED` status in order to make it possible to correctly
represent the transitive `semver` implications of changes within the enclosing
workspace.

## [Unreleased]

## [0.9.3] - 2026-08-07

### Added
- `impl {core::fmt::Display, core::error::Error} for pczt::ParseError`
- `impl {core::fmt::Display, core::error::Error} for pczt::ExtractError`

### Changed
- The `orchard` and `sapling` features are now enabled by default. Consumers
  that require a smaller feature set (such as `no_std` signers) should disable
  default features and enable only the features they need.

## [0.9.2] - 2026-08-03

### Added
- `pczt::Pczt::has_data_in_pool`, which reports whether the always-present
  bundle for a given pool actually holds anything.
- `pczt::orchard::Bundle::{sole_action, value_carrying_outputs_all_pay}`. The
  latter returns `None` when a field it judges has been redacted from the PCZT.

### Fixed
- The `zcp-builder` feature now also enables the `orchard`, `sapling`, and
  `transparent` features that its code requires; enabling it alone no longer
  fails to compile.

## [0.9.1] - 2026-07-26

### Fixed
- Parsing a v1-encoded PCZT with an empty Orchard bundle no longer
  materializes the placeholder anchor substituted for it on encode. The
  logical bundle now round-trips to its canonical empty form (with no
  anchor), matching the invariant that the v1 decoder produces exactly the
  same empty bundle as the Creator and the v2 decoder.

## [0.9.0] - 2026-07-26

### Added
- `pczt::orchard::Bundle::zkproof`
- `pczt::orchard::Spend::dummy_sk`
- `pczt::sapling::Spend::witness`

### Changed
- `pczt::Pczt::serialize` now emits the minimal encoding version capable of
  representing the PCZT's content: the v1 encoding whenever the content is
  representable in it (a pre-v6 transaction with a canonical-empty Ironwood
  bundle and no compact-only field state), and the v2 encoding otherwise.
  Previously it always emitted the v2 encoding. This maximizes compatibility
  with receivers that predate the v2 encoding, such as deployed hardware
  signers. Callers that require a specific encoding version should use
  `pczt::v1::Pczt` or `pczt::v2::Pczt` directly.

### Fixed
- `pczt::v1::Pczt::try_from` (and thus `pczt::Pczt::serialize`'s v1 encoding
  selection) incorrectly required an Orchard anchor even for a PCZT with an
  empty Orchard bundle, returning `EncodingError::RequiresV2` for such PCZTs
  even though they carry no Orchard-protocol data. An empty Orchard bundle
  now falls back to a placeholder anchor for the v1 encoding, matching the
  existing behavior for an empty Sapling bundle.

## [0.8.0] - 2026-07-23

### Added
- The logical `pczt::Pczt` now carries an Ironwood (NU6.3) shielded bundle,
  exposed via `pczt::Pczt::ironwood`, and every PCZT role gained Ironwood
  support. Ironwood reuses the Orchard bundle types, so its role entry points
  take and return Orchard-typed bundles; the per-role additions are listed under
  each role below.
- `pczt::parse`, a free function equivalent to `pczt::Pczt::parse`.
- `pczt::v1` and `pczt::v2`, modules exposing the version 1 and version 2 PCZT
  serialization formats as `pczt::v1::Pczt` and `pczt::v2::Pczt`. Each provides
  `serialize` and `TryFrom<pczt::Pczt>`; `v1` additionally provides
  `From<pczt::v1::Pczt> for pczt::Pczt`. The version 2 format encodes the Orchard
  note-plaintext version at the bundle level and omits empty Transparent,
  Sapling, and Orchard bundles.
- `pczt::EncodingError` (`non_exhaustive`), returned by the now-fallible
  serialization paths, with variants `EncodingError::{UnsupportedTxVersion,
  UnsupportedOrchardNoteVersion, RequiresV2}`.
- `pczt::ParseError::MissingRequiredField`.
- `pczt::ExtractError::{IronwoodExtract, IronwoodParse, IronwoodNotSupported,
  UnsupportedConsensusBranchId}`.
- `pczt::Pczt::resolve_fields` and `pczt::orchard::Bundle::resolve_fields` (both
  require the `orchard` feature), which restore an Orchard-protocol bundle's
  compacted `cv_net`, `cmx`, and encrypted-note-plaintext fields.
- `pczt::orchard::{EncCiphertext, MemoPlaintext}`, the new representation of an
  Orchard output's encrypted note plaintext (either encrypted ciphertext or a
  trailing-zero-stripped memo plaintext).
- `pczt::orchard::Spend::witness` getter (also covering Ironwood spends).
- `pczt::orchard::ParseError` and `pczt::sapling::ParseError` (`non_exhaustive`),
  which distinguish a missing anchor from other malformed bundle data.
- `pczt::orchard::AnchorConsistencyError` and
  `pczt::sapling::AnchorConsistencyError` (require the `prover` feature combined
  with the `orchard` / `sapling` feature), the witness-to-anchor consistency
  errors the `Prover` reports.
- `PartialEq` is now derived for the logical `pczt::transparent::{Bundle, Input,
  Output}`, `pczt::sapling::{Bundle, Spend, Output}`, and
  `pczt::orchard::{Bundle, Action, Spend, Output}` types.
- `pczt::roles::creator`:
  - `Creator::{with_ironwood_anchor, with_ironwood_flags}`.
  - `Error`, the error type returned by the now-fallible `Creator` methods, with
    variants `Error::{AnchorRequiredForV5, IronwoodNotSupported,
    UnknownConsensusBranchId, UnsupportedConsensusBranchId,
    UnrepresentableOrchardFlags}`.
- `pczt::roles::updater`:
  - `Updater::update_ironwood_with`.
  - `Updater::{set_sapling_anchor, set_orchard_anchor, set_ironwood_anchor}`, for
    restoring shielded anchors after signing, and the `AnchorUpdateError` they
    return.
  - `Updater::{set_sapling_spend_witnesses, set_orchard_spend_witnesses,
    set_ironwood_spend_witnesses}`, for restoring shielded spend witnesses before
    proof creation, and the `SpendWitnessUpdateError` they return.
  - `OrchardError::UnsupportedConsensusBranchId`.
- `pczt::roles::signer`:
  - `Signer::{sign_ironwood, apply_ironwood_signature,
    apply_orchard_spend_auth_signature}`.
  - `Error::{IronwoodSign, IronwoodVerify}`.
  - `SpendAuthSignature` and `extract_orchard_spend_auth_signatures`, for
    transporting Orchard and Ironwood (but not Sapling) spend authorization
    signatures separately from a PCZT.
  - `batch`, a submodule whose `BatchSignRequest` and `BatchSignResponse` types
    (with their own `EncodingError` and `ParseError`) transport batches of PCZTs
    to an external signer and return their Orchard and Ironwood spend
    authorization signatures in request order, in a versioned Postcard wire
    format. Request/response correlation is left to the application transport.
- `pczt::roles::low_level_signer`:
  - `Signer::sign_ironwood_with`.
  - `OrchardParseError`, the error type the low-level signing closures must be
    able to wrap; its `SigningClosureModifiedActions` variant is returned (and
    the PCZT left unmodified) if a closure adds, removes, or reorders actions.
- `pczt::roles::verifier::Verifier::with_ironwood`, and
  `pczt::roles::verifier::OrchardError::UnsupportedConsensusBranchId`.
- `pczt::roles::prover`:
  - `Prover::{requires_ironwood_proof, create_ironwood_proof}` and
    `pczt::roles::prover::orchard::IronwoodError`.
  - `InconsistentWitness` variants on `OrchardError`, `SaplingError`, and
    `pczt::roles::prover::orchard::IronwoodError`, reported when a
    non-zero-valued spend's witness does not root to the bundle anchor.
  - `OrchardError::UnsupportedConsensusBranchId`.
- `pczt::roles::redactor`:
  - `Redactor::redact_ironwood_with`.
  - `orchard::OrchardRedactor::{clear_anchor, compact_resolvable_fields}` and
    `orchard::ActionRedactor::{clear_cv_net, clear_cmx,
    replace_enc_ciphertext_with_memo_plaintext,
    replace_enc_ciphertext_with_decrypted_memo_plaintext}`, which produce compact
    redacted PCZTs whose fields `resolve_fields` can restore.
  - `sapling::SaplingRedactor::clear_anchor`.
- `pczt::roles::tx_extractor::IronwoodError` and
  `pczt::roles::tx_extractor::Error::Ironwood`.
- `pczt::roles::io_finalizer::Error::IronwoodFinalize`.

### Changed
- MSRV is now 1.88.
- Migrated to `zcash_protocol 0.10.0`, `zcash_transparent 0.10.0`,
  `zcash_primitives 0.30.0`, `zcash_proofs 0.30.0`, `orchard 0.15`,
  `shardtree 0.7`.
- `pczt::Pczt::serialize` now consumes `self` and returns
  `Result<Vec<u8>, pczt::EncodingError>` (previously `&self -> Vec<u8>`),
  producing the version 2 format; `pczt::Pczt::parse` now accepts both the
  version 1 and version 2 formats. Use `pczt::v1::Pczt` for the previous
  always-version-1 behavior.
- `pczt::roles::creator::Creator::{new, build, with_orchard_flags}` are now
  fallible, returning `Result<_, pczt::roles::creator::Error>`. `Creator::new`
  now takes `Option` Sapling and Orchard anchors and derives the transaction
  format (v5, or v6 at NU6.3 or later) and the Orchard bundle version from the
  consensus branch ID; the previously caller-supplied Orchard flags are now
  validated against that version. v5 transactions still require an anchor for
  each non-empty shielded bundle by the time the PCZT is built.
- Shielded anchors are now optional throughout the logical model, so a bundle's
  anchor may be deferred to proving time (ZIP 374):
  - `pczt::orchard::Bundle::anchor`, `pczt::sapling::Bundle::anchor`,
    `pczt::orchard::Action::cv_net`, and `pczt::orchard::Output::cmx` are now
    `Option<[u8; 32]>`, changing their getters' return types accordingly. Absent
    `cv_net` and `cmx` values are resolved from the surrounding note fields when
    parsing; absent anchors stay absent until restored by another PCZT copy or a
    caller.
  - `pczt::orchard::Output::enc_ciphertext` is now a
    `pczt::orchard::EncCiphertext`, changing its getter's return type.
  - Roles that do not consume shielded anchors now preserve absent anchors while
    parsing v6 transactions; proving and transaction extraction still require an
    anchor for each non-empty Sapling, Orchard, and Ironwood bundle.
- The `Parse` / `Parser` variants of the `pczt::roles::{updater, verifier,
  prover}` Orchard and Sapling error types now wrap the crate's own
  `pczt::orchard::ParseError` / `pczt::sapling::ParseError` instead of
  `orchard::pczt::ParseError` / `sapling::pczt::ParseError`; the same applies to
  `pczt::ExtractError::{OrchardParse, SaplingParse}`.
- `pczt::roles::low_level_signer::Signer::sign_orchard_with` now bounds its error
  parameter by `From<pczt::roles::low_level_signer::OrchardParseError>` (and
  `sign_sapling_with` by `From<pczt::sapling::ParseError>`). These methods now
  parse without deriving each spend's full viewing key — callers must first run
  the `Verifier` over the identical PCZT bytes — but preserve the wire `fvk`
  bytes unchanged in the returned PCZT.
- The Sapling, Orchard, and Ironwood `Prover`s now reject non-zero-valued spends
  whose witnesses do not root to the bundle anchor before creating proofs.
- The empty states of the transparent, Sapling, Orchard, and Ironwood bundles
  now have a single canonical representation, so copies of a PCZT taken through
  different serialization paths continue to merge. The version 1 format refuses
  to encode v6 (NU6.3) PCZTs and PCZTs whose Ironwood bundle is not canonically
  empty.
- Transaction extraction rejects v6 PCZTs whose consensus branch ID predates
  NU6.3, and non-v6 PCZTs that carry non-canonical Ironwood bundle data.

### Removed
- The logical `pczt::Pczt` and `pczt::orchard::{Bundle, Action, Spend, Output}`
  types no longer implement `serde::Serialize` / `serde::Deserialize`; use the
  versioned `pczt::v1` / `pczt::v2` encodings (or `pczt::Pczt::{parse,
  serialize}`) instead. The `pczt::sapling` and `pczt::transparent` logical types
  retain their `serde` implementations.

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
