# Changelog
All notable changes to this library will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this library adheres to Rust's notion of
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
### Added
- `zcash_address::ConversionError`
- `zcash_address::TryFromAddress`
- `zcash_address::TryFromRawAddress`
- `zcash_address::ZcashAddress::convert_if_network`

### Removed
- `zcash_address::FromAddress` (use `TryFromAddress` instead).

## [0.1.0] - 2022-05-11
Initial release.
