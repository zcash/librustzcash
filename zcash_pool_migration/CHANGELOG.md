# Changelog
All notable changes to this library will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this library adheres to Rust's notion of
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `zcash_pool_migration::engine::MigrationTransaction::orchard_change`
- `zcash_pool_migration::state::TransactionStatus::orchard_change`

### Changed
- Migrated to `zcash_client_backend 0.26.0`, `zcash_primitives 0.32.0`.
- `zcash_pool_migration::engine::MigrationTransaction::from_parts` takes an additional
  `orchard_change: Option<Zatoshis>` last argument, the value the transaction returns to
  the Orchard pool as change (`None` for a transaction that produces none).
- `zcash_pool_migration::engine::{plan_migration, plan_migration_with,
  plan_migration_for_signer, plan_migration_for_signer_with, plan_migration_sized_with,
  estimate_migration_runs, estimate_migration_runs_with,
  estimate_migration_runs_for_signer, estimate_migration_runs_for_signer_with,
  estimate_migration_runs_sized_with}` size notes and fees with the ZIP 317 marginal fee
  in effect at the height after the chain tip (5000 zatoshis per logical action below
  `FEE_REDUCTION_HEIGHT`, 1000 from it; ZIP 2009). Previously always 5000.
- `zcash_pool_migration::engine::{commit_preparation, commit_preparation_with_funding,
  build_preparation_unsigned}` return `CommitError::StalePlan` when the plan's transfer
  fee buffer is not the canonical crossing fee at `target_height`, which callers must pass
  as `chain_tip_height() + 1` (a plan re-made at the same tip is otherwise stale again).
  They build each transfer at the later of its scheduled height and `target_height`,
  paying the fee in effect there and returning the funding note's surplus as one Orchard
  change output recorded in `MigrationTransaction::orchard_change`; a transfer with change
  presents two Orchard spends to sign (the real spend and a zero-valued one paired with the
  change output), where previously every transfer was built at `target_height`, carried no
  change and presented one.
- `zcash_pool_migration::engine::{rebuild_expired_transfer,
  rebuild_expired_transfer_unsigned}` build the replacement at its scheduled height and
  return the funding note's surplus over the fee in effect there as one Orchard change
  output recorded in `MigrationTransaction::orchard_change`; previously the replacement
  was built at the height after the chain tip and carried no change. A replacement with
  change presents two Orchard spends to sign (the real spend and a zero-valued one paired
  with the change output). They return `RebuildError::Build(BuildError::Balance)` when the
  funding note does not cover the crossing plus that fee.
- `zcash_pool_migration::build::{build_prep_tx, build_transfer_pczt}` charge the ZIP 317
  marginal fee in effect at `target_height`.

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
