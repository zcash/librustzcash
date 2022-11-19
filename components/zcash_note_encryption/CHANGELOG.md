# Changelog
All notable changes to this library will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this library adheres to Rust's notion of
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.4.0] - 2023-06-06
### Changed
- The `esk` and `ephemeral_key` arguments have been removed from 
  `Domain::parse_note_plaintext_without_memo_ovk`. It is therefore no longer
  necessary (or possible) to ensure that `ephemeral_key` is derived from `esk`
  and the diversifier within the note plaintext. We have analyzed the safety of
  this change in the context of callers within `zcash_note_encryption` and
  `orchard`. See https://github.com/zcash/librustzcash/pull/848 and the
  associated issue https://github.com/zcash/librustzcash/issues/802 for
  additional detail.

## [0.3.0] - 2023-03-22
### Changed
- The `recipient` parameter has been removed from `Domain::note_plaintext_bytes`.
- The `recipient` parameter has been removed from `NoteEncryption::new`. Since 
  the `Domain::Note` type is now expected to contain information about the
  recipient of the note, there is no longer any need to pass this information
  in via the encryption context.

## [0.2.0] - 2022-10-13
### Added
- `zcash_note_encryption::Domain`:
  - `Domain::PreparedEphemeralPublicKey` associated type.
  - `Domain::prepare_epk` method, which produces the above type.
- Feature `encrypt-to-recipient`, which allows the encryption of an arbitrary
  payload decryptable by the recipient of a shielded note. This adds the
  following traits and functions:
  - `PayloadEncryptionDomain`
  - `decrypt_associated_ciphertext_ivk`
  - `decrypt_associated_ciphertext_ovk`
- A new `KeyedOutput` supertrait for `zcash_note_encryption::ShieldedOutput`
- A new `RecoverableOutput` subtrait for `zcash_note_encryption::ShieldedOutput`,
  which is used to simplify the type signatures of `try_output_recovery_with_ock`
  and `try_output_recovery_with_ovk`.

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
- Changes to the `zcash_note_encryption::ShieldedOutput` trait:
  - The `ephemeral_key` and `cmstar_bytes` method have been moved into
    a `KeyedOutput` supertrait of `ShieldedOutput`, for use in methods that
    do not require the `enc_ciphertext` capability, such as
    `decrypt_associated_ciphertext_ivk`.
- The signatures of `try_output_recovery_with_ovk` and
  `try_output_recovery_with_ock` have been changed to no longer take `cv` and
  `out_ciphertext` parameters; instead, the output passed to these functions
  must implement the `RecoverableOutput` trait. This ensures that the value
  commitment and `out_ciphertext` values must correspond to the output being
  decrypted, and simplifies the API.

## [0.1.0] - 2021-12-17
Initial release.
