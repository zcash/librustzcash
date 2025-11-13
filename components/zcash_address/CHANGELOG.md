# Changelog
All notable changes to this library will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this library adheres to Rust's notion of
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Future releases are
indicated by the `PLANNED` status in order to make it possible to correctly
represent the transitive `semver` implications of changes within the enclosing
workspace.

## [Unreleased]

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
