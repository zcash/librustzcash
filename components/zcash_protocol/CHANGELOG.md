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
- `zcash_protocol::value::ZatBalance::into_u64`
- `impl TryFrom<u64> for zcash_protocol::value::Zatoshis`
- `zcash_protocol::value::MAX_BALANCE` has been added to replace previous
  instances where `zcash_protocol::value::MAX_MONEY` was used as a signed
  value.

### Moved
- `zcash_primitives::transcation::components::amount` has been moved to
  `zcash_protocol::value`
- `zcash_primitives::transcation::components::amount::NonNegativeAmount` has
  been renamed to `zcash_protocol::value::Zatoshis`
- `zcash_primitives::transcation::components::amount::Amount` has been renamed 
  to `zcash_protocol::value::ZatBalance`

### Changed
- `zcash_protocol::value::COIN` has been changed from an `i64` to a `u64`
- `zcash_protocol::value::MAX_MONEY` has been changed from an `i64` to a `u64`
- `zcash_primitives::transcation::components::amount::NonNegativeAmount` has
  been renamed to `zcash_protocol::value::Zatoshis`
- `zcash_primitives::transcation::components::amount::Amount` has been renamed 
  to `zcash_protocol::value::ZatBalance`
