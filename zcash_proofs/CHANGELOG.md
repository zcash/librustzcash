# Changelog
All notable changes to this library will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this library adheres to Rust's notion of
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Future releases are
indicated by the `PLANNED` status in order to make it possible to correctly
represent the transitive `semver` implications of changes within the enclosing
workspace.

## [Unreleased]

## [0.26.0] - PLANNED

### Changed
- Migrated to `zcash_protocol 0.7`

## [0.25.0] - 2025-09-25

### Changed
- Migrated to `zcash_primitives 0.25`.

## [0.24.0] - 2025-07-31

### Changed
- Migrated to `zcash_primitives 0.24`.

## [0.23.0] - 2025-05-30

### Changed
- Migrated to `zcash_primitives 0.23`.

## [0.22.0] - 2025-02-21

### Changed
- MSRV is now 1.81.0.
- Migrated to `redjubjub 0.8`, `zcash_primitives 0.22`.

## [0.21.0] - 2024-12-16
### Added
- `zcash_proofs::prover::LocalTxProver::verifying_keys`

### Changed
- Migrated to `sapling-crypto` version `0.4`, `zcash_primitives 0.21`.

## [0.20.0] - 2024-11-14

### Changed
- Migrated to `zcash_primitives 0.20`.
- MSRV is now 1.77.0.

## [0.19.0] - 2024-10-02

### Changed
- Migrated to `zcash_primitives 0.19`.

### Fixed
- The previous release of `zcash_primitives` did not bump `zcash_address` and
  ended up depending on multiple versions of `zcash_protocol`, which didn't
  cause a code conflict but results in two different consensus protocol states
  being present in the dependency tree.

## [0.18.0] - 2024-10-02

### Changed
- Migrated to `sapling-crypto 0.3`, `zcash_primitives 0.18`.

## [0.17.0] - 2024-08-26

### Changed
- Migrated to `zcash_primitives 0.17`.

## [0.16.0] - 2024-08-19

### Changed
- MSRV is now 1.70.0.
- Migrated to `zcash_primitives 0.16`.

## [0.15.0] - 2024-03-25

### Changed
- Migrated to `zcash_primitives 0.15`.

## [0.14.0] - 2024-03-01
### Added
- `impl zcash_primitives::sapling::prover::{SpendProver, OutputProver}` for
  `zcash_proofs::prover::LocalTxProver`

### Changed
- Migrated to `zcash_primitives 0.14`.
- The `zcash_proofs::ZcashParameters` Sapling fields now use the parameter and
  viewing key newtypes defined in `zcash_primitives::sapling::circuit`.

### Removed
- `zcash_proofs::circuit::sapling` (moved to `zcash_primitives::sapling::circuit`).
- `zcash_proofs::circuit::{ecc, pedersen_hash}`
- `zcash_proofs::constants`
- `zcash_proofs::sapling`:
  - `BatchValidator` (moved to `zcash_primitives::sapling`).
  - `SaplingProvingContext`
  - `SaplingVerificationContext` (moved to `zcash_primitives::sapling`).

## [0.13.0] - 2023-09-25
### Changed
- Bumped dependencies to `zcash_primitives 0.13`.

### Removed
- Unused `incrementalmerkletree` dependency.

## [0.12.1] - 2023-06-28
### Changed
- Replaced internal `directories` dependency which now transitively depends on
  MPL-licensed code.

## [0.12.0] - 2023-06-06
### Changed
- Bumped dependencies to `incrementalmerkletree 0.4`, `zcash_primitives 0.12`
- MSRV is now 1.65.0.

### Removed
- `circuit::sapling::TREE_DEPTH` use `zcash_primitives::sapling::NOTE_COMMITMENT_TREE_DEPTH` instead

## [0.11.0] - 2023-04-15
### Changed
- Bumped dependencies to `bls12_381 0.8`, `group 0.13`, `jubjub 0.10`,
  `bellman 0.14`, `redjubjub 0.7`, `zcash_primitives 0.11`.

## [0.10.0] - 2023-02-01
### Added
- `zcash_proofs::circuit::sapling`:
  - `ValueCommitmentOpening`
  - A `value_commitment_opening` field on `Spend` and `Output`.

### Changed
- MSRV is now 1.60.0.
- Bumped dependencies to `zcash_primitives 0.10`.
- Note commitments now use
  `zcash_primitives::sapling::note::ExtractedNoteCommitment` instead of
  `bls12_381::Scalar` in `zcash_proofs::sapling`:
  - `SaplingVerificationContext::check_output`
- Value commitments now use `zcash_primitives::sapling::value::ValueCommitment`
  instead of `jubjub::ExtendedPoint` in `zcash_proofs::sapling`:
  - `SaplingProvingContext::{spend_proof, output_proof}`
  - `SaplingVerificationContext::{check_spend, check_output}`

### Removed
- `zcash_proofs::circuit::sapling`:
  - The `value_commitment` field of `Spend` and `Output` (use
    `value_commitment_opening` instead).

## [0.9.0] - 2022-11-12
### Changed
- Bumped dependencies to `zcash_primitives 0.9`.

## [0.8.0] - 2022-10-19
### Changed
- Bumped dependencies to `zcash_primitives 0.8`.

## [0.7.1] - 2022-07-05
### Added
- `zcash_proofs::sapling::BatchValidator`

## [0.7.0] - 2022-06-24
### Changed
- Bumped dependencies to `zcash_primitives 0.7`.

## [0.6.0] - 2022-05-11
### Changed
- MSRV is now 1.56.1.
- Bumped dependencies to `ff 0.12`, `group 0.12`, `bellman 0.13`,
  `bls12_381 0.7`, `jubjub 0.9`.
- `zcash_proofs::sapling::SaplingVerificationContext::new` now takes a
  `zip216_enabled` boolean; this is used to control how RedJubjub signatures are
  validated.
- Renamed the following in `zcash_proofs::circuit::sprout` to use lower-case
  abbreviations (matching Rust naming conventions):
  - `JSInput` to `JsInput`
  - `JSOutput` to `JsOutput`

### Removed
- `zcash_proofs::sapling::SaplingVerificationContext: Default`

## [0.5.0] - 2021-03-26
### Added
- `zcash_proofs::ZcashParameters`
- `zcash_proofs::parse_parameters`
- `zcash_proofs::prover::LocalTxProver::from_bytes`
- The `zcash_proofs::constants` module, containing constants and helpers used by
  the `zcash_proofs::circuit::ecc::fixed_base_multiplication` gadget:
  - The `FixedGeneratorOwned` type alias.
  - `generate_circuit_generator`
  - The six Zcash fixed generators:
    - `PROOF_GENERATION_KEY_GENERATOR`
    - `NOTE_COMMITMENT_RANDOMNESS_GENERATOR`
    - `NULLIFIER_POSITION_GENERATOR`
    - `VALUE_COMMITMENT_VALUE_GENERATOR`
    - `VALUE_COMMITMENT_RANDOMNESS_GENERATOR`
    - `SPENDING_KEY_GENERATOR`
- `zcash_proofs::sapling::SaplingProvingContext: Default`
- `zcash_proofs::sapling::SaplingVerificationContext: Default`

### Changed
- MSRV is now 1.47.0.
- `zcash_proofs::load_parameters` now returns `ZcashParameters`.

## [0.4.0] - 2020-09-09
### Changed
- MSRV is now 1.44.1.
- Bumped dependencies to `ff 0.8`, `group 0.8`, `bellman 0.8`,
  `bls12_381 0.3.1`, `jubjub 0.5.1`.

## Fixed
- Performance regressions to Sapling proof creation in 0.3.0 have been partially
  mitigated by fixes in `bellman 0.8`.

## [0.3.0] - 2020-08-24
TBD

## [0.2.0] - 2020-03-13
TBD

## [0.1.0] - 2019-10-08
Initial release.
