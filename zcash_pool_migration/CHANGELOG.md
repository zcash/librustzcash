# Changelog
All notable changes to this library will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this library adheres to Rust's notion of
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed
- Heights in this crate's target-height convention (the height of the next
  block, one above the chain tip) are now typed as
  `zcash_primitives::transaction::TargetHeight` instead of `BlockHeight`. Chain
  tips, anchor boundaries, expiry heights and mined heights remain
  `BlockHeight`. A caller holding a chain tip `tip` passes
  `TargetHeight::from(tip + 1)` where a target height is now required, and
  converts a returned `TargetHeight` with `BlockHeight::from` where it needs a
  `BlockHeight`. The affected items are:
  - `zcash_pool_migration::scheduling`:
    - `Schedule::broadcast_height(&self) -> BlockHeight` has been renamed to
      `Schedule::scheduled_height(&self) -> TargetHeight`.
    - `schedule_broadcast_heights(.., commit_height: BlockHeight, ..) -> Vec<BlockHeight>`
      has been renamed to
      `schedule_heights(.., commit_target: TargetHeight, ..) -> Vec<TargetHeight>`.
    - `schedule_prep_broadcast_heights(.., start: BlockHeight, ..) -> Vec<BlockHeight>`
      has been renamed to
      `schedule_prep_heights(.., start: TargetHeight, ..) -> Vec<TargetHeight>`.
    - `schedule(.., commit_height: BlockHeight, ..)` now takes
      `commit_target: TargetHeight`.
    - `schedule_sync_wakeups` now takes
      `transfers: &[(T, BlockHeight, TargetHeight)]` in place of
      `&[(T, BlockHeight, BlockHeight)]`; the third element is the transfer's
      scheduled height.
    - `expiry_height` is no longer a re-export of
      `zcash_protocol::zip318::expiry_height`. It now takes
      `(spacing: &BlockSpacing, scheduled_height: TargetHeight)` and returns the
      same `BlockHeight` that `zip318::expiry_height` returns for that height.
    - `earliest_broadcast_height(..) -> BlockHeight` has been renamed to
      `earliest_scheduled_height(..) -> TargetHeight`, and its value is one
      greater: it previously returned the first chain tip at which a candidate
      anchor exists, and now returns the earliest target height at which a
      transfer may be scheduled, one above that tip.
    - `draw_anchor_boundary`'s fourth argument has changed from
      `chain_tip_height: BlockHeight` to `target_height: TargetHeight`, and the
      candidate set is evaluated at the chain tip one below it. A caller that
      passed an observed chain tip `tip` passes `TargetHeight::from(tip + 1)`;
      a caller drawing for a scheduled transaction passes its scheduled height.
    - `redraw_anchor_boundary`'s third argument has changed from
      `scheduled_height: BlockHeight` to `scheduled_height: TargetHeight`, and
      the candidate set is evaluated at the chain tip one below it, rather than
      at the scheduled height itself.
  - `zcash_pool_migration::engine`:
    - `MigrationTransaction::scheduled_height` now returns `TargetHeight`, and
      `MigrationTransaction::from_parts` takes `scheduled_height: TargetHeight`.
    - `MigrationPlan::prep_schedule` now returns `&[Vec<TargetHeight>]`.
    - `commit_preparation`, `commit_preparation_with_funding` and
      `build_preparation_unsigned` now take `target_height: TargetHeight`.
  - `zcash_pool_migration::satisfiability`:
    - `DuenessTargets::new` and `DuenessTargets::at` now take `TargetHeight`
      arguments, and `DuenessTargets::{scanned, effective}` return
      `TargetHeight`.
    - `Advance::next` now returns `Option<(TargetHeight, StepKind)>`.
  - `zcash_pool_migration::state::TransactionStatus::scheduled_height` now
    returns `TargetHeight`.
  - `zcash_pool_migration::signing_rounds::PlannedTx::new` now takes
    `scheduled_height: Option<TargetHeight>`, and
    `PlannedTx::scheduled_height` returns `Option<TargetHeight>`.
  - `zcash_pool_migration::build::{build_prep_tx, build_transfer_pczt}` now
    take `target_height: TargetHeight` in place of `target_height: u32`.

### Fixed
- `zcash_pool_migration::engine::plan_migration` and its variants no longer
  schedule a transfer whose only candidate anchor at its broadcast tip would be
  the most recent boundary (an age-0 anchor, which ZIP 318 forbids). Every
  transfer now has a candidate anchor at the tip it is broadcast from.
- `zcash_pool_migration::engine::plan_migration` and its variants no longer
  schedule a preparation or transfer at the chain tip, a height that is already
  mined; every scheduled height is now above it.
- The anchor boundaries that `zcash_pool_migration::engine` draws for scheduled
  transfers (at commit, at rebuild, and when the overdue shift redraws them)
  are never age 0. Previously, when a transfer's scheduled height landed
  exactly on an anchor boundary, the drawn anchor could be the most recent
  boundary at the tip the transfer is broadcast from.

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
