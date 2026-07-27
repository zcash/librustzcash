# Changelog
All notable changes to this library will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this library adheres to Rust's notion of
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `zcash_pool_migration::build::AccountDerivation`, the ZIP 32 account whose
  spending key authorizes a migration's Orchard spends. Behind the `orchard`
  feature; convertible from `zcash_client_backend`'s `Zip32Derivation` behind
  the `wallet` feature.
- `zcash_pool_migration::scheduling::{WakeupParams, SyncWakeup, WakeupScheduleError, schedule_sync_wakeups}`,
  computing the minimal schedule of sync-and-proving wake-up heights implied by a
  transfer schedule's drawn anchor boundaries and broadcast heights.
- `zcash_pool_migration::engine::MigrationState::sync_wakeup_schedule`, the above computed over a
  committed migration's transfers that still need proofs.

### Changed
- `zcash_pool_migration::build::{build_prep_tx, build_transfer_pczt}` take an
  additional `Option<&AccountDerivation>` argument, before the RNG. When it is
  supplied, every spend the built transaction still needs a signature for is
  stamped with the account's Orchard ZIP 32 key path, so an external Signer can
  identify those spends as the account's; previously they carried no derivation
  and such a Signer skipped them, leaving transactions that could not be
  extracted. Pass the account's derivation whenever the wallet knows it; pass
  `None` only for an account with no known derivation, whose transactions then
  only an in-process signer (which matches by key) can authorize.
- `zcash_pool_migration::engine::MigrationCrypto` has a new required method,
  `account_derivation`, supplying the above to the builders. Implement it by
  returning the account's derivation as the wallet records it.
- `zcash_pool_migration::wallet::WalletMigration` implements `MigrationCrypto`
  only where the wallet's `WalletRead::AccountId` and `InputSource::AccountId`
  are the same type, which is required to read the account's derivation.

## [0.1.0-rc.3] - 2026-07-26

### Changed
- Migrated to `zcash_client_backend 0.24.0-rc.4`.

### Removed
- The `transparent-inputs` feature flag. It enabled nothing, existing only as a
  marker for an end-to-end test that has moved to `zcash_client_sqlite`.

## [0.1.0-rc.2] - 2026-07-26

Initial release of the `zcash_pool_migration` crate.
