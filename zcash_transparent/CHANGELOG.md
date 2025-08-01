# Changelog
All notable changes to this library will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this library adheres to Rust's notion of
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Future releases are
indicated by the `PLANNED` status in order to make it possible to correctly
represent the transitive `semver` implications of changes within the enclosing
workspace.

## [Unreleased]

## [0.4.0] - 2025-07-31

### Added
- `zcash_transparent::address::TransparentAddress::from_pubkey`

### Changed
- Migrated to `zcash_protocol 0.6`, `zcash_address 0.9`
- The type of `zcash_transparent::bundle::Bundle::value_balance` has changed.
  The closure provided to this method for input retrieval can now indicate that
  an input for the given outpoint is not available, and `value_balance` will
  return `Ok(None)` when this is the case. 

### Removed
- Removed deprecated method `zcash_transparent::keys::pubkey_to_address`;
  use `zcash_transparent::address::TransparentAddress::from_pubkey` instead.

## [0.3.0] - 2025-05-30

### Changed
- Migrated to `zcash_address 0.8`.

## [0.2.3] - 2025-04-04

### Added
- `zcash_transparent::sighash::SignableInput::from_parts`

## [0.2.2] - 2025-04-02

### Added
- `zcash_transparent::keys::NonHardenedChildRange`
- `zcash_transparent::keys::NonHardenedChildIter`
- `zcash_transparent::keys::NonHardenedChildIndex::const_from_index`

## [0.2.1] - 2025-03-19

### Added
- `zcash_transparent::keys::NonHardenedChildIndex::saturating_sub`
- `zcash_transparent::keys::NonHardenedChildIndex::saturating_add`
- `zcash_transparent::keys::NonHardenedChildIndex::MAX`
- `impl From<NonHardenedChildIndex> for zip32::DiversifierIndex`
- `impl TryFrom<zip32::DiversifierIndex> for NonHardenedChildIndex`
- `impl {PartialOrd, Ord} for NonHardenedChildIndex`

## [0.2.0] - 2025-02-21

### Fixed
- `zcash_transparent::keys::AccountPubKey::derive_pubkey_at_bip32_path` now
  returns the correct result for valid paths instead of an error or panic.

### Added
- `zcash_transparent::pczt::Bip32Derivation::extract_bip_44_fields`

### Changed
- MSRV is now 1.81.0.
- Migrated to `bip32 =0.6.0-pre.1`, `secp256k1 0.29`, `zcash_encoding 0.3`,
  `zcash_protocol 0.5`, `zcash_address 0.7`.

## [0.1.0] - 2024-12-16

The entries below are relative to the `zcash_primitives` crate as of the tag
`zcash_primitives-0.20.0`.

### Added
- `zcash_transparent::keys::AccountPubKey::derive_pubkey_at_bip32_path`
