# Changelog
All notable changes to this library will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this library adheres to Rust's notion of
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-10-21

### Added
- `zcash_pool_migration::scheduling::{AnchorGrid, BlockSpacing}` (re-exported from
  `zcash_protocol::zip318`).
- `zcash_pool_migration::satisfiability::AdvanceConfig::block_spacing`

### Changed
- MSRV is now 1.89
- Migrated to `incrementalmerkletree 0.9`, `orchard 0.16`, `pczt 0.10.0`,
  `rand_core 0.10`, `shardtree 0.8`, `zcash_client_backend 0.25.0`,
  `zcash_keys 0.17.0`, `zcash_primitives 0.31.0`, `zcash_protocol 0.11.0`, and
  `zip32 0.3`.
- `zcash_pool_migration::build::sign_pczt` takes an additional `rng` first
  argument that implements `rand_core::{Rng, CryptoRng}`.
- `zcash_pool_migration::wallet::WalletMigrationProver` has an additional type
  parameter `R` for the RNG it uses to create proofs, and
  `WalletMigrationProver::new` takes that RNG as an additional `rng` argument,
  following `wallet`. It implements `MigrationProver` when `R` implements
  `rand_core::{Rng, CryptoRng}`.
- Public APIs that took an `RngCore` now require a `rand_core::Rng` in its
  place.
- A migration's schedule keeps its duration across the NU7 block spacing change:
  from NU7 activation, the delays between broadcasts, the anchor grid, and the
  canonical expiry span three times as many blocks, and a delay that crosses
  activation keeps its exact length in time.
- `zcash_pool_migration::scheduling::{schedule, schedule_broadcast_heights,
  schedule_prep_broadcast_heights}` take a `&BlockSpacing` argument.
- `zcash_pool_migration::scheduling::{draw_anchor_boundary,
  redraw_anchor_boundary, earliest_broadcast_height}` take an `AnchorGrid` in place
  of an `AnchorBucketInterval`.
- `zcash_pool_migration::scheduling::expiry_height` takes a `&BlockSpacing`
  argument.
- `zcash_pool_migration::satisfiability::AdvanceConfig::new` takes the
  `BlockSpacing` of the migration's network. The overdue-shift tolerance is
  measured in time, and a shift moves the pending schedule by the time the
  wallet was behind.

## [0.1.0] - 2026-08-18

Initial release.
