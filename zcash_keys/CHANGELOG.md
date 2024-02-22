All notable changes to this library will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this library adheres to Rust's notion of
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
The entries below are relative to the `zcash_client_backend` crate as of
`zcash_client_backend 0.10.0`.

### Added
- The following modules have been extracted from `zcash_client_backend` and
  moved to this crate: 
  - `address`
  - `encoding`
  - `keys`
- `zcash_keys::address::UnifiedAddress::{unknown, has_orchard, has_sapling, 
   has_transparent, receiver_types}`:
- `zcash_keys::keys`:
  - `AddressGenerationError`
  - `UnifiedAddressRequest`
- A new `orchard` feature flag has been added to make it possible to
  build client code without `orchard` dependendencies.

### Changed
- `zcash_keys::address`:
  - `RecipientAddress` has been renamed to `Address`
  - `Address::Shielded` has been renamed to `Address::Sapling`
  - `UnifiedAddress::from_receivers` no longer takes an Orchard receiver
    argument unless the `orchard` feature is enabled.
  - `UnifiedAddress::orchard` is now only available when the `orchard` feature
    is enabled.

- `zcash_keys::keys`:
  - `DerivationError::Orchard` is now only available when the `orchard` feature
    is enabled.
  - `UnifiedSpendingKey::address` now takes an argument that specifies the
    receivers to be generated in the resulting address. Also, it now returns
    `Result<UnifiedAddress, AddressGenerationError>` instead of
    `Option<UnifiedAddress>` so that we may better report to the user how
    address generation has failed.
  - `UnifiedSpendingKey::orchard` is now only available when the `orchard`
    feature is enabled.
  - `UnifiedSpendingKey::transparent` is now only available when the
    `transparent-inputs` feature is enabled.
  - `UnifiedFullViewingKey::new` no longer takes an Orchard full viewing key
    argument unless the `orchard` feature is enabled.

### Removed
- `zcash_keys::address::AddressMetadata` has been moved to 
  `zcash_client_backend::data_api::TransparentAddressMetadata` and fields changed.
