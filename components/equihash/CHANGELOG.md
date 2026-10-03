# Changelog
All notable changes to this library will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this library adheres to Rust's notion of
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `unsafe-solver` feature flag, which improves the performance of
  `equihash::tromp::solve_200_9` on x86-64 and Linux using `unsafe` Rust
  to access platform-specific intrinsics.

### Fixed
- `equihash::is_valid_solution` now returns an error for parameters whose
  required solution size overflows the platform's size limits, instead of
  panicking or using an incorrect solution size.

### Changed
- Improved the performance of `equihash::is_valid_solution`.
- Improved the performance of `equihash::tromp::solve_200_9`. It also no longer
  requires a C/C++ compiler.

## [0.3.0] - 2026-04-23

### Changed
- MSRV is now 1.85.1
- Migrated from yanked `core2` crate to `corez 0.1.1`.

## [0.2.2] - 2025-03-04

Documentation improvements and rendering fix; no code changes.

## [0.2.1] - 2025-02-21
### Added
- `equihash::tromp` module behind the experimental `solver` feature flag.

## [0.2.0] - 2022-06-24
### Changed
- MSRV is now 1.56.1.
- Bumped dependencies to `blake2b_simd 1`.

## [0.1.0] - 2020-07-10
Initial release.
