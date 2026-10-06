# Changelog
All notable changes to this library will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this library adheres to Rust's notion of
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Future releases are
indicated by the `PLANNED` status in order to make it possible to correctly
represent the transitive `semver` implications of changes within the enclosing
workspace.

## [Unreleased]

## [0.14.0-pre.1] - 2026-10-06

### Added
- `zcash_address::unified::ParseError::{InvalidEncodedLength, NotDefinedInRevision}`

### Changed
- `zcash_address::unified::Encoding::try_from_items` now rejects the items that
  decoding the resulting container would reject:
  - At `Revision::R0`, an expiry height or expiry time metadata item, and a P2SH
    viewing key item, return `ParseError::NotDefinedInRevision`.
  - At any revision, an unknown metadata item with a MUST-understand typecode
    returns `ParseError::NotUnderstood`.
  - A container whose raw encoding plus padding is outside
    `f4jumble::VALID_LENGTH` returns `ParseError::InvalidEncodedLength`.
    Encoding such a container previously panicked.

## [0.14.0-pre.0] - 2026-09-30

### Added
- `zcash_address::unified::DataTypecode`
- `zcash_address::unified::DataTypecode::{is_transparent, preference_order}`
- `zcash_address::unified::MetadataTypecode`
- `zcash_address::unified::Typecode::{P2PKH, P2SH, SAPLING, ORCHARD}`
- `zcash_address::unified::Typecode::{typecode_value, is_transparent_data}`
- `zcash_address::unified::MetadataItem`
- `zcash_address::unified::Uitem`
- `zcash_address::unified::Revision` (re-exported from `zcash_protocol`)
- `zcash_address::unified::Fvk::P2sh`
- `zcash_address::unified::Ivk::P2sh`
- `zcash_address::unified::P2shItemKind`
- `zcash_address::unified::P2shItemError`
- `zcash_address::unified::ParseError::{InvalidMetadataLength, InvalidP2shItem,
  NoDataItems, NotUnderstood, TransparentReceiverInR2Address}`
- `zcash_address::unified::testing::{arb_known_shielded_typecode,
  arb_metadata_items, arb_r2_shielded_address,
  arb_r2_transparent_including_address}` (behind the `test-dependencies`
  feature)
- ZIP 316 Revision 2 support:
  - Metadata item parsing and serialization (expiry height, expiry time).
  - Revision-aware encoding/decoding with distinct HRPs for R0 and R2.
  - MUST-understand metadata typecodes (0xE0-0xFC) enforced per revision.
  - R2 Unified Addresses use two HRP prefixes per updated ZIP 316:
    `zu` for shielded-only addresses and `tu` for transparent-including
    addresses. Transparent receivers are permitted in R2 `unified::Address`
    containers.
  - R2 Unified Viewing Keys allow transparent-only configurations.
  - P2SH viewing key items (BIP 388 wallet policies) are accepted in R2
    UFVKs and UIVKs, with structural validation of the policy payload.

### Changed
- Migrated to `zcash_protocol 0.11.0-pre.0`.
- `zcash_address::unified::Typecode` now distinguishes data and metadata items
  via `Typecode::Data(DataTypecode)` and `Typecode::Metadata(MetadataTypecode)`.
  Its former `P2pkh`, `P2sh`, `Sapling`, `Orchard`, and `Unknown` variants are
  now the corresponding `DataTypecode` variants; the known data typecodes are
  also available as the `Typecode::{P2PKH, P2SH, SAPLING, ORCHARD}` constants.
  `Typecode::preference_order` orders every metadata typecode after every data
  typecode.
- `zcash_address::unified::testing::{arb_transparent_typecode,
  arb_shielded_typecode}` now generate `DataTypecode` values, and
  `arb_typecodes` generates a `BTreeSet<DataTypecode>`.
- `zcash_address::unified::Encoding::try_from_items` now takes a `Revision`
  parameter, and returns `ParseError::InvalidTypecodeValue` for an item whose
  typecode exceeds `zcash_encoding::MAX_COMPACT_SIZE`.
- `zcash_address::unified::Encoding::decode` now returns a 3-tuple
  `(NetworkType, Revision, Self)`.
- `zcash_address::unified::Container::items_as_parsed` now returns
  `&[Uitem<Self::Item>]` to represent both data and metadata items.
- The `zcash_address::unified::private::SealedItem` trait no longer requires
  `TryFrom<(u32, &[u8])>`. It now has a `parse(DataTypecode, &[u8])` method
  instead, and its `typecode()` method now returns `DataTypecode`.

### Removed
- `impl TryFrom<(u32, &[u8])>` for `zcash_address::unified::Receiver`,
  `zcash_address::unified::Fvk`, and `zcash_address::unified::Ivk`. These
  types are now parsed via the `SealedItem::parse` trait method instead.

## [0.13.0] - 2026-07-09

### Changed
- Migrated to `zcash_protocol 0.10.0`.

## [0.13.0-pre.0] - 2026-06-30

### Changed
- MSRV is now 1.88
- Migrated to `zcash_protocol 0.10.0-pre.0`.

## [0.12.0] - 2026-06-02

### Changed
- Migrated to `zcash_protocol 0.9.0`.

## [0.11.0] - 2026-04-23

### Added
- `zcash_address::ZcashAddress::is_transparent_only`

### Changed
- MSRV is now 1.85.1
- Migrated to `zcash_encoding 0.4`, `zcash_protocol 0.8`.
- Migrated from the yanked `core2` crate to `corez 0.1.1`.

### Fixed
- `Debug` output for `zcash_address::unified::{Fvk, Ivk}` now
  redacts viewing key material instead of emitting raw key bytes.

### Removed

- Removed deprecated `zcash_address::Network`, use `zcash_protocol::consensus::Network` instead.

## [0.10.1] - 2025-10-18

### Fixed
- Adjusted doc features to fix builds on docs.rs after nightly Rust update.

## [0.10.0] - 2025-10-02

### Changed
- Migrated to `zcash_protocol 0.7`

## [0.9.0] - 2025-07-31
### Changed
- Migrated to `zcash_protocol 0.6`

## [0.8.0] - 2025-05-30
### Changed
- The following methods with generic parameter `T` now require `T: TryFromAddress`
  instead of `T: TryFromRawAddress`:
  - `zcash_address::ZcashAddress::convert_if_network`
  - The blanket `impl zcash_address::TryFromAddress for (NetworkType, T)`

### Removed
- `zcash_address::TryFromRawAddress` has been removed. All of its
  functions can be served by `TryFromAddress` impls, and its presence adds
  complexity and some pitfalls to the API.

## [0.6.3, 0.7.1] - 2025-05-07
### Added
- `zcash_address::Converter`
- `zcash_address::ZcashAddress::convert_with`

## [0.7.0] - 2025-02-21
### Added
- `zcash_address::unified::Item` to expose the opaque typed encoding of unified
  items.

### Changed
- Migrated to `zcash_encoding 0.3`, `zcash_protocol 0.5`.

### Deprecated
- `zcash_address::Network` (use `zcash_protocol::consensus::NetworkType` instead).

## [0.6.2] - 2024-12-13
### Fixed
- Migrated to `f4jumble 0.1.1` to fix `no-std` support.

## [0.6.1] - 2024-12-13
### Added
- `no-std` support, via a default-enabled `std` feature flag.

## [0.6.0] - 2024-10-02
### Changed
- Migrated to `zcash_protocol 0.4`.

## [0.5.0] - 2024-08-26
### Changed
- Updated `zcash_protocol` dependency to version `0.3`

## [0.4.0] - 2024-08-19
### Added
- `zcash_address::ZcashAddress::{can_receive_memo, can_receive_as, matches_receiver}`
- `zcash_address::unified::Address::{can_receive_memo, has_receiver_of_type, contains_receiver}`
- Module `zcash_address::testing` under the `test-dependencies` feature.
- Module `zcash_address::unified::address::testing` under the
  `test-dependencies` feature.

### Changed
- Updated `zcash_protocol` dependency to version `0.2`

## [0.3.2] - 2024-03-06
### Added
- `zcash_address::convert`:
  - `TryFromRawAddress::try_from_raw_tex`
  - `TryFromAddress::try_from_tex`
  - `ToAddress::from_tex`

## [0.3.1] - 2024-01-12
### Fixed
- Stubs for `zcash_address::convert` traits that are created by `rust-analyzer`
  and similar LSPs no longer reference crate-private type aliases.

## [0.3.0] - 2023-06-06
### Changed
- Bumped bs58 dependency to `0.5`.

## [0.2.1] - 2023-04-15
### Changed
- Bumped internal dependency to `bech32 0.9`.

## [0.2.0] - 2022-10-19
### Added
- `zcash_address::ConversionError`
- `zcash_address::TryFromAddress`
- `zcash_address::TryFromRawAddress`
- `zcash_address::ZcashAddress::convert_if_network`
- A `TryFrom<Typecode>` implementation for `usize`.

### Changed
- MSRV is now 1.52

### Removed
- `zcash_address::FromAddress` (use `TryFromAddress` instead).

## [0.1.0] - 2022-05-11
Initial release.
