# Changelog
All notable changes to this library will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this library adheres to Rust's notion of
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed
- Migrated to `rand_core 0.10`, and to the `orchard` release that uses it.
- Public APIs that took an `RngCore` now require a `rand_core::Rng` in its
  place.

## [0.1.0] - 2026-08-18

Initial release.
