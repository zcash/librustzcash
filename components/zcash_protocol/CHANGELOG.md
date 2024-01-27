# Changelog
All notable changes to this library will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this library adheres to Rust's notion of
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
The entries below are relative to the `zcash_primitives` crate as of the tag
`zcash_primitives-0.13.0`.

### Added
- The following modules have been extracted from `zcash_primitives` and
  moved to this crate: 
  - `consensus`
  - `constants`
- `zcash_protocol::value::Amount::into_u64`
- `impl TryFrom<u64> for zcash_protocol::value::NonNegativeAmount`

### Moved
- `zcash_primitives::transcation::components::amount` has been moved to
  `zcash_protocol::value`

