# Changelog
All notable changes to this library will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this library adheres to Rust's notion of
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `engine::MigrationStatus::Superseded` (wire name `"superseded"`) and
  `engine::MigrationState::mark_superseded`, the terminal status and transition
  recording that a migration's remaining value is being re-planned; a superseded
  migration is terminal, so the commit guard accepts a replacement.
- `engine::ReplanThreshold`, the integer percent of planned transfer value,
  unsatisfiable, above which a migration is re-planned immediately rather than
  after satisfiable work drains; stamped on the migration at commit.
- `engine::MigrationState::{replan_threshold, replan_required}`: the accessor
  for the stamped threshold, and the derived determination of whether the
  unsatisfiable share of planned transfer value strictly exceeds it.
- `engine::ReorgSettleDepth`, the caller-supplied number of blocks the chain
  must advance past a divergence before a displacement is treated as
  permanent.
- `engine::StepSatisfiability` and `engine::UnsatisfiableCause`: a store's
  answer to whether the environment obstructs a pre-signed transaction —
  executable now, not yet, or never (and why).
- `engine::InputObservation` and `engine::classify_input_observations`, the
  pure fold from per-nullifier observations plus the transaction-level expiry
  judgment into a `StepSatisfiability`, so every store implementation shares
  one classification and precedence.
- `engine::MigrationTransferId` now implements `PartialOrd` and `Ord`.
- `state::AdvanceStep::Replan`, the step directing the consumer to mark the
  migration superseded and re-plan its remaining balance through the ordinary
  planning flow.
- `state::Blocker::Unsatisfiable`, reported (ahead of `Blocker::Expired`) for a
  transaction whose inputs can never again all exist unspent on chain, directly
  observed or inherited from a dead dependency.

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
- `engine::MigrationTxState::Mined` now carries the mined transaction's txid
  alongside its height, and `engine::MigrationState::mark_mined` takes it;
  `MigrationTxState::from_stored` requires the txid payload for `"mined"` rows,
  and `broadcast_txid` also answers for mined transactions.
- `engine::MigrationTransaction::from_parts` takes two further parameters,
  `unsatisfiable_at` (the chain height backing a spent-input observation, when
  the transaction has been determined unsatisfiable) and `spend_nullifiers`
  (the transaction's real-spend nullifiers, cached from the built PCZT); both
  have accessors.
- `engine::MigrationState::from_parts` and the `engine::commit_preparation`,
  `engine::build_preparation_unsigned`, and
  `engine::commit_preparation_with_funding` entry points each take a further
  `engine::ReplanThreshold` parameter, stamped on the committed migration.
- `engine::MigrationState::next_step` takes a further `set_aside` parameter,
  the drive loop's call-local list of transaction ids to skip (candidates whose
  satisfiability check answered "not yet"); pass `&[]` when driving without an
  oracle. Transactions that can never mine — marked unsatisfiable, expired
  unmined, or dependent on either — are no longer offered for proving,
  broadcast, or rebuild; `AdvanceStep::Replan` is returned after due broadcasts
  but ahead of proving when `replan_required` holds, and in preference to
  `AdvanceStep::Waiting` when dead value is stranded with no live work left (a
  migration no longer waits forever in that state).
- `engine::MigrationState::{next_provable, next_broadcastable}` take two
  further parameters: the set of transaction ids judged unable to ever mine and
  a set-aside list, both excluded from the queue. `next_step` supplies both;
  pass an empty set and `&[]` to reproduce the previous behaviour.
- `engine::MigrationState::sync_wakeup_schedule` also excludes transfers marked
  unsatisfiable or dependent on a transaction that can never mine, alongside
  the expired transfers it already excluded.
- `engine::PoolMigrationRead` has a new required method,
  `check_step_satisfiability`: an implementation reports, for each cached
  real-spend nullifier of the given transaction, whether the note is unspent,
  seen spent in a mined transaction, known with a dead unmined creator, or
  unknown — plus the transaction-level expiry judgment and, for a
  broadcast-unmined transaction, whether its installed anchor survives on the
  chain judged settled per the supplied `engine::ReorgSettleDepth` — and
  composes `engine::classify_input_observations` into a
  `engine::StepSatisfiability`. An empty nullifier cache on a non-mined
  transaction must surface the store's own error, never an answer.

### Fixed
- `engine::rebuild_expired_transfer` and
  `engine::rebuild_expired_transfer_unsigned` no longer fail for a transfer
  that was proved or broadcast before it expired; the rebuild now identifies
  the funding note from the persisted real-spend nullifier cache instead of
  the stored (by then proven) PCZT.

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
