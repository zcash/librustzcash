# Changelog
All notable changes to this library will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this library adheres to Rust's notion of
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
TBD

## [0.4.0] - 2020-09-09
### Added
- `zcash_primitives::note_encryption::OutgoingCipherKey` - a symmetric key that
  can be used to recover a single Sapling output. This will eventually be used
  to implement Sapling payment disclosures.

### Changed
- MSRV is now 1.44.1.
- `zcash_primitives::note_encryption`:
  - `SaplingNoteEncryption::new` now takes `Option<OutgoingViewingKey>`. Setting
    this to `None` prevents the note from being recovered from the block chain
    by the sender.
    - The `rng: &mut R` parameter (where `R: RngCore + CryptoRng`) has been
      changed to `rng: R` to enable this use case.
  - `prf_ock` now returns `OutgoingCipherKey`.
  - `try_sapling_output_recovery_with_ock` now takes `&OutgoingCipherKey`.
- `zcash_primitives::transaction::builder`:
  - `SaplingOutput::new` and `Builder::add_sapling_output` now take
    `Option<OutgoingViewingKey>` (exposing the new unrecoverable note option).
- Bumped dependencies to `ff 0.8`, `group 0.8`, `bls12_381 0.3.1`,
  `jubjub 0.5.1`, `secp256k1 0.19`.

## [0.3.0] - 2020-08-24
TBD

## [0.2.0] - 2020-03-13
TBD

## [0.1.0] - 2019-10-08
Initial release.
