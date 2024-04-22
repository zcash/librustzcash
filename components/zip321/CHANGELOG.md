# Changelog
All notable changes to this library will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this library adheres to Rust's notion of
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
The entries below are relative to the `zcash_client_backend` crate as of
`zcash_client_backend-0.10.0`.

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
