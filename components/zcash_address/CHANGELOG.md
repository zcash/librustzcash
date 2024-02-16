 Changelog
All notable changes to this library will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this library adheres to Rust's notion of
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `zcash_address::unified`:
  - `Address::receivers`
  - `DataTypecode`
  - `Item`
  - `MetadataItem`
  - `MetadataTypecode`
  - `Revision`
- `impl serde::{Serialize, Deserialize} for zcash_address::ZcashAddress` behind
  the `serde` feature flag.

### Changed
- `zcash_address::unified`:
  - `Typecode` has changed. Instead of having a variant for each receiver type,
    it now has two variants, `Typecode::Data` and `Typecode::Metadata`.
  - `Encoding::try_from_items` arguments have changed.
  - The result type of `Container::items_as_parsed` has changed.
  - The `Container` trait has an added `revision` accessor method.
  - `ParseError::InvalidTypecodeValue` now wraps a `u32` instead of a `u64`.
  - `ParseError` has added variant `NotUnderstood`.

### Deprecated
- `zcash_address::Network` (use `zcash_protocol::consensus::NetworkType` instead).

### Removed
- `zcash_address::unified::Container::items` Preference order is only
  significant when considering unified address receivers; use
  `Address::receivers` instead.
- `zcash_address::kind::unified::address::testing`:
  - `{arb_transparent_typecode,, arb_shielded_typecode, arb_typecodes, arb_unified_address_for_typecodes}`

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
- `zcash_address::ZcashAddress::{has_receiver_of_type, contains_receiver, contains_receiver}`
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
