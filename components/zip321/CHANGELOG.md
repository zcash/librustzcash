# Changelog
All notable changes to this library will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this library adheres to Rust's notion of
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Future releases are
indicated by the `PLANNED` status in order to make it possible to correctly
represent the transitive `semver` implications of changes within the enclosing
workspace.

## [Unreleased]

## [0.5.0] - 2025-07-31
### Changed
- Migrated to `zcash_protocol 0.6`, `zcash_address 0.9`.

## [0.4.0] - 2025-05-30
### Changed
- Migrated to `zcash_address 0.8`.

## [0.3.0] - 2025-02-21
### Changed
- MSRV is now 1.81.0.
- Migrated to `zcash_protocol 0.5`, `zcash_address 0.7`.

## [0.2.0] 2024-10-04

### Changed
- Migrated to `zcash_address 0.6`

## [0.1.0] 2024-08-20

The contents of this crate were factored out from `zcash_client_backend` to
provide a better separation of concerns and simpler integration with WASM
builds. The entries below are relative to the `zcash_client_backend` crate as
of `zcash_client_backend-0.10.0`.

### Added
- `zip321::Payment::new`
- `impl From<zcash_address:ConversionError<E>> for Zip321Error`

### Changed
- Fields of `zip321::Payment` are now private. Accessors have been provided for
  the fields that are no longer public, and `Payment::new` has been added to
  serve the needs of payment construction.
- `zip321::Payment::recipient_address()` returns `zcash_address::ZcashAddress`
- `zip321::Payment::without_memo` now takes a `zcash_address::ZcashAddress` for
  its `recipient_address` argument.
- Uses of `zcash_primitives::transaction::components::amount::NonNegartiveAmount`
  have been replace with `zcash_protocol::value::Zatoshis`. Also, some incorrect
  uses of the signed `zcash_primitives::transaction::components::Amount`
  type have been corrected via replacement with the `Zatoshis` type.
- The following methods that previously required a
  `zcash_primitives::consensus::Parameters` argument to facilitate address
  parsing no longer take such an argument.
  - `zip321::TransactionRequest::{to_uri, from_uri}`
  - `zip321::render::addr_param`
  - `zip321::parse::{lead_addr, zcashparam}`
- `zip321::Param::Memo` now boxes its argument.
- `zip321::Param::Addr` now wraps a `zcash_address::ZcashAddress`
- MSRV is now 1.70.0.
