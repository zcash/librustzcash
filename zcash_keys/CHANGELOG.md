All notable changes to this library will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this library adheres to Rust's notion of
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
### Added
- `zcash_keys::address::Address::try_from_zcash_address`
- `zcash_keys::address::Receiver`

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
