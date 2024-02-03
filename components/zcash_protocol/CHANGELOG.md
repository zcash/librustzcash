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
  - `zcash_protocol::value` replaces `zcash_primitives::transaction::components::amount`
- `zcash_protocol::consensus`:
  - `NetworkConstants` has been extracted from the `Parameters` trait.
  - `NetworkType`
  - `Parameters::b58_sprout_address_prefix`
- `zcash_protocol::constants::{mainnet, testnet}::B58_SPROUT_ADDRESS_PREFIX`
- Added in `zcash_protocol::value`:
  - `Zatoshis`
  - `ZatBalance`
  - `MAX_BALANCE` has been added to replace previous instances where
    `zcash_protocol::value::MAX_MONEY` was used as a signed value.

### Changed
- `zcash_protocol::value::COIN` has been changed from an `i64` to a `u64`
- `zcash_protocol::value::MAX_MONEY` has been changed from an `i64` to a `u64`

### Removed
- From `zcash_protocol::value`:
  - `NonNegativeAmount` (use `Zatoshis` instead.)
  - `Amount` (use `ZatBalance` instead.)
  - The following conversions have been removed relative to `zcash_primitives-0.14.0`,
    as `zcash_protocol` does not depend on the `orchard` or `sapling-crypto` crates.
    - `From<NonNegativeAmount> for orchard::NoteValue>`
    - `TryFrom<orchard::ValueSum> for Amount`
    - `From<NonNegativeAmount> for sapling::value::NoteValue>`
    - `TryFrom<sapling::value::NoteValue> for NonNegativeAmount`
- `zcash_protocol::consensus::Parameters` has been split into two traits, with
  the `NetworkConstants` trait providing all network constant accessors. Also,
  the `address_network` method has been replaced with a new `network_type`
  method that serves the same purpose.
