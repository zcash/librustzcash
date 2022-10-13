# Changelog
All notable changes to this library will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this library adheres to Rust's notion of
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2022-10-13
### Added
- `zcash_note_encryption::Domain`:
  - `Domain::PreparedEphemeralPublicKey` associated type.
  - `Domain::prepare_epk` method, which produces the above type.

### Changed
- MSRV is now 1.56.1.
- `zcash_note_encryption::Domain` now requires `epk` to be converted to
  `Domain::PreparedEphemeralPublicKey` before being passed to
  `Domain::ka_agree_dec`.
- Changes to batch decryption APIs:
  - The return types of `batch::try_note_decryption` and
    `batch::try_compact_note_decryption` have changed. Now, instead of
    returning entries corresponding to the cartesian product of the IVKs used for
    decryption with the outputs being decrypted, this now returns a vector of
    decryption results of the same length and in the same order as the `outputs`
    argument to the function. Each successful result includes the index of the
    entry in `ivks` used to decrypt the value.

## [0.1.0] - 2021-12-17
Initial release.
