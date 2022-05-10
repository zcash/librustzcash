# Changelog
All notable changes to this library will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this library adheres to Rust's notion of
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
- `zcash_proofs::prover::LocalProver::from_bytes`
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
