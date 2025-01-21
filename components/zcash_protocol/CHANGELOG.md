# Changelog
All notable changes to this library will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this library adheres to Rust's notion of
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `zcash_protocol::address::Revision`
- `zcash_protocol::constants::`
  - `{mainnet|testnet|regtest}::HRP_UNIFIED_ADDRESS_R0`
  - `{mainnet|testnet|regtest}::HRP_UNIFIED_IVK_R0`
  - `{mainnet|testnet|regtest}::HRP_UNIFIED_FVK_R0`
  - `{mainnet|testnet|regtest}::HRP_UNIFIED_ADDRESS_R1`
  - `{mainnet|testnet|regtest}::HRP_UNIFIED_IVK_R1`
  - `{mainnet|testnet|regtest}::HRP_UNIFIED_FVK_R1`

### Changed
- `zcash_protocol::consensus::NetworkConstants` has added methods:
  - `hrp_unified_address`
  - `hrp_unified_fvk`
  - `hrp_unified_ivk`

### Removed
- `zcash_protocol::constants::`
  - `{mainnet|testnet|regtest}::HRP_UNIFIED_ADDRESS` have been replaced by
    `{mainnet|testnet|regtest}::HRP_UNIFIED_ADDRESS_R0` respectively.
  - `{mainnet|testnet|regtest}::HRP_UNIFIED_IVK` have been replaced by
    `{mainnet|testnet|regtest}::HRP_UNIFIED_IVK_R0` respectively.
  - `{mainnet|testnet|regtest}::HRP_UNIFIED_FVK` have been replaced by
    `{mainnet|testnet|regtest}::HRP_UNIFIED_FVK_R0` respectively.

## [0.4.3] - 2024-12-16
### Added
- `zcash_protocol::TxId` (moved from `zcash_primitives::transaction`).

## [0.4.2] - 2024-12-13
### Added
- `no-std` compatibility (`alloc` is required). A default-enabled `std` feature
  flag has been added gating the `std::error::Error` and `memuse` usage.

## [0.4.1] - 2024-11-13
### Added
- `zcash_protocol::value::QuotRem`
- `zcash_protocol::value::Zatoshis::div_with_remainder`
- `impl Mul<u64> for zcash_protocol::value::Zatoshis`
- `impl Div<NonZeroU64> for zcash_protocol::value::Zatoshis`

## [0.4.0] - 2024-10-02
### Added
- `impl Sub<BlockHeight> for BlockHeight` unlike the implementation that was
  removed in version `0.3.0`, a saturating subtraction for block heights having
  a return type of `u32` makes sense for `BlockHeight`. Subtracting one block
  height from another yields the delta between them.

### Changed
- Mainnet activation height has been set for `consensus::BranchId::Nu6`.
- Adding a delta to a `BlockHeight` now uses saturating addition.
- Subtracting a delta to a `BlockHeight` now uses saturating subtraction.

## [0.3.0] - 2024-08-26
### Changed
- Testnet activation height has been set for `consensus::BranchId::Nu6`.

### Removed
- `impl {Add, Sub} for BlockHeight` - these operations were unused, and it
  does not make sense to add block heights (it is not a monoid.)

## [0.2.0] - 2024-08-19
### Added
- `zcash_protocol::PoolType::{TRANSPARENT, SAPLING, ORCHARD}`

### Changed
- MSRV is now 1.70.0.
- `consensus::BranchId` now has an additional `Nu6` variant.

## [0.1.1] - 2024-03-25
### Added
- `zcash_protocol::memo`:
  - `impl TryFrom<&MemoBytes> for Memo`

### Removed
- `unstable-nu6` and `zfuture` feature flags (use `--cfg zcash_unstable=\"nu6\"`
  or `--cfg zcash_unstable=\"zfuture\"` in `RUSTFLAGS` and `RUSTDOCFLAGS`
  instead).

## [0.1.0] - 2024-03-06
The entries below are relative to the `zcash_primitives` crate as of the tag
`zcash_primitives-0.14.0`.

### Added
- The following modules have been extracted from `zcash_primitives` and
  moved to this crate:
  - `consensus`
  - `constants`
  - `zcash_protocol::value` replaces `zcash_primitives::transaction::components::amount`
- `zcash_protocol::consensus`:
  - `NetworkConstants` has been extracted from the `Parameters` trait. Relative to the
    state prior to the extraction:
    - The Bech32 prefixes now return `&'static str` instead of `&str`.
    - Added `NetworkConstants::hrp_tex_address`.
  - `NetworkType`
  - `Parameters::b58_sprout_address_prefix`
- `zcash_protocol::consensus`:
  - `impl Hash for LocalNetwork`
- `zcash_protocol::constants::{mainnet, testnet}::B58_SPROUT_ADDRESS_PREFIX`
- Added in `zcash_protocol::value`:
  - `Zatoshis`
  - `ZatBalance`
  - `MAX_BALANCE` has been added to replace previous instances where
    `zcash_protocol::value::MAX_MONEY` was used as a signed value.

### Changed
- `zcash_protocol::value::COIN` has been changed from an `i64` to a `u64`
- `zcash_protocol::value::MAX_MONEY` has been changed from an `i64` to a `u64`
- `zcash_protocol::consensus::Parameters` has been split into two traits, with
  the newly added `NetworkConstants` trait providing all network constant
  accessors. Also, the `address_network` method has been replaced with a new
  `network_type` method that serves the same purpose. A blanket impl of
  `NetworkConstants` is provided for all types that implement `Parameters`,
  so call sites for methods that have moved to `NetworkConstants` should
  remain unchanged (though they may require an additional `use` statement.)

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
  - `impl AddAssign for NonNegativeAmount`
  - `impl SubAssign for NonNegativeAmount`
