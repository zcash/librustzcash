# Changelog
All notable changes to this library will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this library adheres to Rust's notion of
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.2] - 2026-10-06

### Changed
- `f4jumble::VALID_LENGTH` now starts at 38 bytes instead of 48, as ZIP 316
  specifies. `f4jumble`, `f4jumble_inv`, `f4jumble_mut`, and `f4jumble_inv_mut`
  accept inputs of 38 to 47 bytes, which they previously rejected.

## [0.1.1] - 2024-12-13
### Added
- `alloc` feature flag as a mid-point between full `no-std` support and the
  `std` feature flag.

## [0.1.0] - 2022-05-11
Initial release.
MSRV is 1.51
