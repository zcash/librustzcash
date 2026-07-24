# Changelog
All notable changes to this library will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this library adheres to Rust's notion of
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed
- MSRV is now 1.88
- Migrated to `zcash_primitives 0.30.0`.

### Fixed
- Updated to crate versions that fix an Orchard soundness vulnerability
  (GHSA-ww9q-8r59-xv46) and Orchard non-canonical proof size issue
  (GHSA-2x4w-pxqw-58v9).

## [0.1.0] - 2024-07-15
Initial release that re-exports other crates. Expect that the API surface of
this crate will change significantly in future releases.
MSRV is 1.70.0.
