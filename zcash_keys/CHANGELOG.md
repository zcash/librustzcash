All notable changes to this library will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this library adheres to Rust's notion of
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `zcash_keys::keys::UnifiedIncomingViewingKey::{has_sapling, has_orchard,
  has_transparent, receiver_requirements, to_receiver_requirements}`
- `zcash_keys::keys::ReceiverRequirements`

### Changed
- `zcash_keys::keys::UnifiedAddressRequest` is now an enum instead of a struct.
  The `new` and `unsafe_new` methods have been replaced by `custom` and
  `unsafe_custom` respectively.
- Arguments to `zcash_keys::keys::UnifiedIncomingViewingKey::address` have been
  modified; the `request` argument to this method now has type
  `UnifiedAddressRequest` instead of `Option<UnifiedAddressRequest>`. Use
  `UnifiedAddressRequest::AllAvailableKeys` where `None` was previously
  used to obtain the same semantics.

### Removed
- `UnifiedAddressRequest::{new, unsafe_new}`: use `{custom, unsafe_custom}`
  respectively instead.
- `UnifiedAddressRequest::intersect`: a replacement for this method is now
  provided with the newly-added `ReceiverRequirements` type.

## [0.7.0] - 2025-02-21

### Added
- `no-std` compatibility (`alloc` is required). A default-enabled `std` feature
  flag has been added gating the `std::error::Error` usage.
- `zcash_keys::keys::ReceiverRequirement`
- `zcash_keys::Address::to_transparent_address`

### Changed
- MSRV is now 1.81.0.
- Migrated to `bip32 =0.6.0-pre.1`, `nonempty 0.11`, `orchard 0.11`,
  `sapling-crypto 0.5`, `zcash_encoding 0.3`, `zcash_protocol 0.5`,
  `zcash_address 0.7`, `zcash_transparent 0.2`.
- `zcash_keys::keys::UnifiedAddressRequest` has been substantially modified;
  instead of a collection of boolean flags, it is now a collection of
  `ReceiverRequirement` values that describe how addresses may be constructed
  in the case that keys for a particular protocol are absent or it is not
  possible to generate a specific receiver at a given diversifier index.
  Behavior of methods that accept a `UnifiedAddressRequest` have been modified
  accordingly. In addition, request construction methods that previously
  returned `None` to indicate an attempt to generate an invalid request now
  return `Err(())`

### Removed
- `zcash_keys::keys::UnifiedAddressRequest::all` (use
  `UnifiedAddressRequest::ALLOW_ALL` or
  `UnifiedFullViewingKey::to_address_request` instead)

## [0.6.0] - 2024-12-16

### Changed
- Migrated to `bech32 0.11`, `sapling-crypto 0.4`.
- Added dependency on `zcash_transparent 0.1` to replace dependency
  on `zcash_primitives`.
- The `UnifiedAddressRequest` argument to the following methods is now optional:
  - `zcash_keys::keys::UnifiedSpendingKey::address`
  - `zcash_keys::keys::UnifiedSpendingKey::default_address`
  - `zcash_keys::keys::UnifiedFullViewingKey::find_address`
  - `zcash_keys::keys::UnifiedFullViewingKey::default_address`
  - `zcash_keys::keys::UnifiedIncomingViewingKey::address`
  - `zcash_keys::keys::UnifiedIncomingViewingKey::find_address`
  - `zcash_keys::keys::UnifiedIncomingViewingKey::default_address`

## [0.5.0] - 2024-11-14

### Changed
- Migrated to `zcash_primitives 0.20.0`
- MSRV is now 1.77.0.

## [0.4.0] - 2024-10-04

### Added
- `zcash_keys::encoding::decode_extfvk_with_network`
- `impl std::error::Error for Bech32DecodeError`
- `impl std::error::Error for DecodingError`
- `impl std::error::Error for DerivationError`

### Changed
- Migrated to `orchard 0.10`, `sapling-crypto 0.3`, `zcash_address 0.6`,
  `zcash_primitives 0.19`, `zcash_protocol 0.4`.

## [0.3.0] - 2024-08-19
### Notable changes
- `zcash_keys`:
  - Now supports TEX (transparent-source-only) addresses as specified
    in [ZIP 320](https://zips.z.cash/zip-0320).
  - An `unstable-frost` feature has been added in order to be able to
    temporarily expose API features that are needed specifically when creating
    FROST threshold signatures. The features under this flag will be removed
    once key derivation for FROST has been fully specified and implemented.

### Added
- `zcash_keys::address::Address::try_from_zcash_address`
- `zcash_keys::address::Receiver`
- `zcash_keys::keys::UnifiedAddressRequest`
  - `intersect`
  - `to_address_request`

### Changed
- MSRV is now 1.70.0.
- Updated dependencies:
  - `zcash_address-0.4`
  - `zcash_encoding-0.2.1`
  - `zcash_primitives-0.16`
  - `zcash_protocol-0.2`
- `zcash_keys::Address` has a new variant `Tex`.
- `zcash_keys::address::Address::has_receiver` has been renamed to `can_receive_as`.
- `zcash_keys::keys`:
  - The (unstable) encoding of `UnifiedSpendingKey` has changed.
  - `DerivationError::Transparent` now contains `bip32::Error`.

## [0.2.0] - 2024-03-25

### Added
- `zcash_keys::address::Address::has_receiver`
- `impl Display for zcash_keys::keys::AddressGenerationError`
- `impl std::error::Error for zcash_keys::keys::AddressGenerationError`
- `impl From<hdwallet::error::Error> for zcash_keys::keys::DerivationError`
  when the `transparent-inputs` feature is enabled.
- `zcash_keys::keys::DecodingError`
- `zcash_keys::keys::UnifiedFullViewingKey::{parse, to_unified_incoming_viewing_key}`
- `zcash_keys::keys::UnifiedIncomingViewingKey`

### Changed
- `zcash_keys::keys::UnifiedFullViewingKey::{find_address, default_address}`
  now return `Result<(UnifiedAddress, DiversifierIndex), AddressGenerationError>`
  (instead of `Option<(UnifiedAddress, DiversifierIndex)>` for `find_address`).
- `zcash_keys::keys::AddressGenerationError`
  - Added `DiversifierSpaceExhausted` variant.
- At least one of the `orchard`, `sapling`, or `transparent-inputs` features
  must be enabled for the `keys` module to be accessible.
- Updated to `zcash_primitives-0.15.0`

### Removed
- `UnifiedFullViewingKey::new` has been placed behind the `test-dependencies`
  feature flag. UFVKs should only be produced by derivation from the USK, or
  parsed from their string representation.

### Fixed
- `UnifiedFullViewingKey::find_address` can now find an address for a diversifier
  index outside the valid transparent range if you aren't requesting a
  transparent receiver.

## [0.1.1] - 2024-03-04

### Added
- `zcash_keys::keys::UnifiedAddressRequest::all`

### Fixed
- A missing application of the `sapling` feature flag was remedied;
  prior to this fix it was not possible to use this crate without the
  `sapling` feature enabled.

## [0.1.0] - 2024-03-01
The entries below are relative to the `zcash_client_backend` crate as of
`zcash_client_backend 0.10.0`.

### Added
- `zcash_keys::address` (moved from `zcash_client_backend::address`). Further
  additions to this module:
  - `UnifiedAddress::{has_orchard, has_sapling, has_transparent}`
  - `UnifiedAddress::receiver_types`
  - `UnifiedAddress::unknown`
- `zcash_keys::encoding` (moved from `zcash_client_backend::encoding`).
- `zcash_keys::keys` (moved from `zcash_client_backend::keys`). Further
  additions to this module:
  - `AddressGenerationError`
  - `UnifiedAddressRequest`
- A new `orchard` feature flag has been added to make it possible to
  build client code without `orchard` dependendencies.
- `zcash_keys::address::Address::to_zcash_address`

### Changed
- The following methods and enum variants have been placed behind an `orchard`
  feature flag:
  - `zcash_keys::address::UnifiedAddress::orchard`
  - `zcash_keys::keys::DerivationError::Orchard`
  - `zcash_keys::keys::UnifiedSpendingKey::orchard`
- `zcash_keys::address`:
  - `RecipientAddress` has been renamed to `Address`.
  - `Address::Shielded` has been renamed to `Address::Sapling`.
  - `UnifiedAddress::from_receivers` no longer takes an Orchard receiver
    argument unless the `orchard` feature is enabled.
- `zcash_keys::keys`:
  - `UnifiedSpendingKey::address` now takes an argument that specifies the
    receivers to be generated in the resulting address. Also, it now returns
    `Result<UnifiedAddress, AddressGenerationError>` instead of
    `Option<UnifiedAddress>` so that we may better report to the user how
    address generation has failed.
  - `UnifiedSpendingKey::transparent` is now only available when the
    `transparent-inputs` feature is enabled.
  - `UnifiedFullViewingKey::new` no longer takes an Orchard full viewing key
    argument unless the `orchard` feature is enabled.

### Removed
- `zcash_keys::address::AddressMetadata`
  (use `zcash_client_backend::data_api::TransparentAddressMetadata` instead).
