# Changelog
All notable changes to this library will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this library adheres to Rust's notion of
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed
- The minimum supported input length for `f4jumble` / `f4jumble_inv` has been
  reduced from 48 to 38 bytes, to support transparent-only Revision 2 Unified
  Addresses as specified in ZIP 316.

## [0.1.1] - 2024-12-13
### Added
- `alloc` feature flag as a mid-point between full `no-std` support and the
  `std` feature flag.

## [0.1.0] - 2022-05-11
Initial release.
MSRV is 1.51
