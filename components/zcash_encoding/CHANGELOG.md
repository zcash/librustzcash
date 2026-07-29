# Changelog
All notable changes to this library will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this library adheres to Rust's notion of
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `zcash_encoding::Encodable`, `zcash_encoding::Decodable` and the
  `zcash_encoding::Codec` marker alias over the pair, naming the canonical
  binary encoding of a type. `Decodable` is parameterized by the context the
  byte stream does not itself provide, which is `()` when the encoding is
  self-describing; a decoder generic over its context implements the trait for
  each context it accepts.
  Implementations are provided for `Vec<T>`, `Option<T>` and `NonEmpty<T>`,
  which encode exactly as `Vector`, `Optional` and `Vector::write_nonempty` do,
  so a codec for `T` yields codecs for all of them.
- `zcash_encoding::codec::Unprefixed`, the `Array` encoding (no length prefix,
  element count supplied via `Decodable::Args`) as a type.
- `zcash_encoding::testing::{check_codec_roundtrip, check_codec_roundtrip_with}`,
  the round-trip property expressed over `Encodable`/`Decodable` rather than
  over a pair of closures.
- `zcash_encoding::testing::check_canonical`, which asserts that a codec admits
  no more than one encoding per value. Unlike the round-trip property this
  quantifies over arbitrary byte strings, so drive it with a fuzzer or a
  `proptest` byte-string strategy.

### Changed
- `zcash_encoding::testing::check_roundtrip` no longer asserts that re-encoding
  the decoded value reproduces the input bytes. That assertion was implied by
  the round-trip assertion that precedes it, and so never tested the canonicity
  it claimed to test. Use `check_canonical` for that property.

## [0.5.0] - 2026-07-24

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
