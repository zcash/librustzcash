# Changelog
All notable changes to this library will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this library adheres to Rust's notion of
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
