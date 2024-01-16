# Changelog
All notable changes to this library will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this library adheres to Rust's notion of
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
The entries below are relative to the `zcash_client_backend` crate as of
`zcash_client_backend-0.10.0`.

### Added
- `impl From<zcash_address:ConversionError<E>> for Zip321Error`

### Changed
- `zip321::Payment::recipient_address` now has type `zcash_address::ZcashAddress`
- Uses of `zcash_primitives::transaction::components::amount::NonNegartiveAmount`
  have been replace with `zcash_protocol::value::Zatoshis`. Also, some incorrect
  uses of the signed `zcash_primitibves::transaction::components::amount Amount`
  type have been corrected via replacement with the `Zatoshis` type.
- Methods that previously required a `zcash_primitives::consensus::Parameters`
  argument to facilitate address parsing no longer take such an argument.
- `zip321::Param::Memo` now boxes its argument.
