# Changelog
All notable changes to this library will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this library adheres to Rust's notion of
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `zcash_pool_migration::engine::MigrationTxState::Invalid` (with its
  `invalid_reason` accessor) and `zcash_pool_migration::engine::InvalidReason`
  (plus `ParseInvalidReasonError` and its `AsRef<str>` / `TryFrom<&str>` wire
  codec): the event-based failure state for a transaction the consumer has
  observed can never mine — a funding note spent outside the migration, or a
  network-rejected broadcast. It is a state variant rather than an orthogonal
  flag so that every state-matched query excludes an invalid transaction
  automatically, and a run containing one never reaches `Complete`.
- `zcash_pool_migration::engine::MigrationState::mark_invalid`, recording that
  evidence. A `Mined` transaction is never marked (it succeeded, so the
  evidence is stale), `mark_mined` supersedes an invalidity verdict (chain
  inclusion outranks it), and `mark_broadcast` leaves one standing (a
  submission is not evidence of validity).
- `zcash_pool_migration::state::AdvanceStep::Attend`, surfaced by `next_step`
  ahead of all actionable work whenever any transaction is invalid: no
  automatic step can advance that part of the migration, and the consumer
  resolves it out-of-band, typically by cancelling the migration and
  re-planning the remaining balance.
- `zcash_pool_migration::state::Blocker::Invalid`, the per-transaction view of
  the same fact in `transaction_statuses` (reported not-ready with no action;
  the reason rides in the status's `state`).
- `zcash_pool_migration::engine::RebuildError::Invalid`: the rebuild entry
  points reject an invalid transfer — even one whose expiry height has also
  passed — rather than re-spend a funding note that may be gone or reissue an
  artifact the network rejected.
- `zcash_pool_migration::state::DuenessTargets` and the estimate-aware query
  variants `engine::MigrationState::next_provable_at` /
  `next_broadcastable_at`, for a consumer whose scanned chain view lags the
  real chain between syncs: a wall-clock estimate of the real target height
  may ACCELERATE schedule due-ness (and, in `next_broadcastable_at`, withhold
  a broadcast the estimate says the node would reject as expired), while
  expiry, rebuild eligibility, and anchor-boundary settledness evaluate on the
  scanned target only. The single-target `next_provable` /
  `next_broadcastable` are now delegating wrappers over these with both
  targets equal — no behavior change.
- `zcash_pool_migration::testing::arb_invalid_reason`; the
  `arb_migration_tx_state` strategy now also generates `Invalid` states, so
  store conformance suites cover the new state's persistence.

### Changed
- `engine::MigrationState::next_step` now returns a due `AdvanceStep::Broadcast`
  in preference to `AdvanceStep::Prove` (previously the reverse), so a wallet
  that wakes to find a transaction ready to broadcast can submit it and end the
  session without syncing; proving work is surfaced only once no broadcast is
  due.
- `state::AdvanceStep::Prove` now also carries the transaction's
  `engine::MigrationTxKind`, so a consumer can tell without a lookup whether it
  is proving a preparation transaction — by construction due on its broadcast
  schedule, so broadcastable at the same wake-up once proved — or a transfer,
  whose broadcast follows at its own scheduled height. Match with
  `AdvanceStep::Prove { id, kind }`.
- `engine::MigrationTxState::from_stored` takes the stored invalid reason as a
  fourth argument (`None` for every row written before the `Invalid` state
  existed).
- `engine::MigrationState::expired_transactions` never reports a transaction
  marked `Invalid` (and no query treats one as expired): its death is already
  recorded and surfaced through `AdvanceStep::Attend`, not the expiry path's
  rebuild.

## [0.1.0-rc.5] - 2026-07-29

### Changed
- Migrated to `zcash_client_backend 0.24.0-rc.6`.
- `scheduling::SchedulingParams::ZIP_318` adopts the revised ZIP 318 timing:
  transfer delays now have a mean of 66 blocks (previously 144) and
  preparation delays a mean of 16 blocks (previously a provisional 24), with
  both caps unchanged; the preparation delay is now defined by
  `zcash_protocol::zip318::{PREP_DELAY_MEAN, PREP_DELAY_CAP}`. The re-exported
  `scheduling::ANCHOR_AGE_CAP` is now 4 boundaries (previously 16).
- `scheduling::SchedulingParams::new_with_default_distributions` now scales
  each ZIP 318 delay mean and cap by the ratio of the given interval to the
  ZIP 318 one, instead of deriving the delays from fixed cap/mean ratios.

### Removed
- `scheduling::DELAY_CAP_RATIO` and `scheduling::PREP_MEAN_DIVISOR`; the
  revised ZIP 318 delay parameters are no longer related by fixed ratios. Read
  the means and caps from a `SchedulingParams` instead.

## [0.1.0-rc.4] - 2026-07-28

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
- Migrated to `zcash_client_backend 0.24.0-rc.5`.
- The ZIP 318 constants this crate defined are now defined by `zcash_protocol::zip318`
  and re-exported from their existing paths. `denomination::MIGRATION_MAX_DENOMINATION_ZEC`
  is renamed to `denomination::DENOM_CAP` and `denomination::RESIDUAL_MIGRATION_MIN` to
  `denomination::MAX_RESIDUAL_VALUE`; `scheduling::{AnchorBucketInterval, DELAY_CAP_RATIO,
  ANCHOR_AGE_CAP, EXPIRY_MODULUS, EXPIRY_WINDOW}` and `preparation::PREP_TX_ACTIONS` keep
  their paths and values, as does `scheduling::expiry_height`.
- `denomination::DENOM_CAP` is a `Zatoshis` rather than a count of whole ZEC, and
  `CanonicalOneTwoFive::new` takes its maximum denomination as a `Zatoshis`. Pass the
  `Zatoshis` directly and drop any `* COIN`.
- `scheduling::AnchorBucketInterval` and `zcash_client_backend`'s
  `AnchorRetentionInterval` are now the same type; the `From` conversion between them is
  gone. Remove any `.into()` at that boundary.
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
