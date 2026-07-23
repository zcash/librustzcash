# Changelog
All notable changes to this library will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this library adheres to Rust's notion of
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed
- Invalid history node height ranges are now rejected during deserialization,
  and leaf ranges starting at block height zero no longer underflow.

## [0.5.0] - 2026-07-09

### Changed
- MSRV is now 1.88
- `zcash_history::MAX_NODE_DATA_SIZE` is now 317 bytes and the derived
  `zcash_history::MAX_ENTRY_SIZE` is now 326 bytes, to account for Ironwood
  history node metadata.

### Added
- `zcash_history::Entry::data`
- `zcash_history::NodeDataV2`, exposing the V2 history tree node metadata type.
- `zcash_history::NodeDataV3`, representing the history tree node metadata for
  the Ironwood shielded pool.
- `zcash_history::V3`, marking the history tree version for Ironwood.

## [0.4.0] - 2023-03-01
### Changed
- MSRV is now 1.65.0.
- Bumped dependencies to `primitive-types 0.12`.

## [0.3.0] - 2022-05-11
### Added
- Support for multiple history tree versions:
  - `zcash_history::Version` trait.
  - `zcash_history::V1`, marking the original history tree version.
  - `zcash_history::V2`, marking the history tree version from NU5.
- `zcash_history::Entry::new_leaf`

### Changed
- MSRV is now 1.56.1.
- `zcash_history::{Entry, IndexedNode, Tree}` now have a `Version` parameter.

### Removed
- `impl From<NodeData> for Entry` (replaced by `Entry::new_leaf`).

## [0.2.0] - 2020-03-13
No changes, just a version bump.

## [0.0.1] - 2020-03-04
Initial release.
