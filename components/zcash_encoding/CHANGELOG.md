# Changelog
All notable changes to this library will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this library adheres to Rust's notion of
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `zcash_encoding::CompactSize::{read_unbounded, write_unbounded}`, which use the
  same wire format as `CompactSize::{read, write}` but span the full `u64` range
  instead of enforcing the `MAX_COMPACT_SIZE` consensus limit.
- `zcash_encoding::testing::check_roundtrip` (behind the new `test-dependencies`
  feature), a helper that asserts a `write`/`read` codec pair are exact inverses
  and that the encoding is stable across a round-trip.

### Changed
- MSRV is now 1.88
- `zcash_encoding::CompactSize::write` now returns an error when the provided
  value exceeds `MAX_COMPACT_SIZE`, rather than silently writing a value that
  `CompactSize::read` would reject. This mirrors the bound already enforced by
  `CompactSize::read`; callers that may legitimately encode larger values should
  use the new `CompactSize::write_unbounded`.

## [0.4.0] - 2026-04-23

### Added
- `zcash_encoding::ReverseHex::{encode, decode}`

### Changed
- MSRV updated to 1.85.1
- Migrated from the yanked `core2` crate to `corez 0.1.1`.

## [0.3.0] - 2025-02-21
### Changed
- Migrated to `nonempty 0.11`

## [0.2.2] - 2024-12-13
### Added
- `no-std` support, via a default-enabled `std` feature flag.

## [0.2.1] - 2024-08-19
### Added
- `zcash_encoding::CompactSize::serialized_size`
- `zcash_encoding::Vector::serialized_size_of_u8_vec`

## [0.2.0] - 2022-10-19
### Changed
- MSRV is now 1.56.1

## [0.1.0] - 2022-05-11
Initial release.
