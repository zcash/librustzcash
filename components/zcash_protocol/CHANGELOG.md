# Changelog
All notable changes to this library will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this library adheres to Rust's notion of
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
The entries below are relative to the `zcash_primitives` crate as of the tag
`zcash_primitives-0.14.0`.

### Added
- The following modules have been extracted from `zcash_primitives` and
  moved to this crate:
  - `consensus`
  - `constants`
  - `zcash_protocol::value` replaces `zcash_primitives::transcation::components::amount`
- `zcash_protocol::value::Amount::into_u64`
- `impl TryFrom<u64> for zcash_protocol::value::NonNegativeAmount`
- Added in `zcash_protocol::value`:
  - `NonNegativeAmount::into_u64`
  - `TryFrom<u64> for NonNegativeAmount`

### Removed
- The following conversions have been removed from `zcash_protocol::value`, as
  `zcash_protocol` does not depend on the `orchard` or `sapling-crypto` crates.
  - `From<NonNegativeAmount> for orchard::NoteValue>`
  - `TryFrom<orchard::ValueSum> for Amount`
  - `From<NonNegativeAmount> for sapling::value::NoteValue>`
  - `TryFrom<sapling::value::NoteValue> for NonNegativeAmount`
