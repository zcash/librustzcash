# Changelog
All notable changes to this library will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this library adheres to Rust's notion of
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.16.2] - 2025-04-02

### Fixed
- This release fixes a migration error that could cause some wallets
  to crash on startup due to an attempt to associate a received transparent
  output with an address that does not exist in the wallet's `addresses`
  table.

## [0.16.1] - 2025-03-26

### Fixed
- This release fixes a migration error that could cause some wallets
  to crash on startup due to an attempt to derive a unified address with
  a Sapling receiver at an index for which no Sapling receiver can exist.

## [0.16.0] - 2025-03-19

### Added
- `zcash_client_sqlite::WalletDb::with_gap_limits`
- `zcash_client_sqlite::GapLimits`
- `zcash_client_sqlite::util`
- `zcash_client_sqlite::schedule_ephemeral_address_checks` has been added under
  the `transparent-inputs` feature flag.
- `zcash_client_sqlite::wallet::transparent::SchedulingError`

### Changed
- Updated to `zcash_keys 0.8`, `zcash_client_backend 0.18`
- `zcash_client_sqlite::WalletDb` has added fields and type parameters:
    - a `clock` field and corresponding type parameter. Tests that make use of
      `WalletDb` now use a `zcash_client_sqlite::util::FixedClock` for this
      field value.
    - an `rng` field and corresponding type parameter. Tests that make use of
      `WalletDb` now use a `ChaChaRng` value initialized with the all-zeros
      seed for this field value.
    - the following methods have been changed to accept additional parameters
      as a result of these changes:
      - `WalletDb::for_path`
      - `WalletDb::from_connection`
      - `wallet::init::init_wallet_db` has additional type constraints
- `zcash_client_sqlite::WalletDb::get_address_for_index` now returns some of
  its failure modes via `Err(SqliteClientError::AddressGeneration)` instead of
  `Ok(None)`.
- `zcash_client_sqlite::error::SqliteClientError` variants have changed:
  - The `EphemeralAddressReuse` variant has been removed and replaced
    by a new generalized `AddressReuse` error variant.
  - The `ReachedGapLimit` variant no longer includes the account UUID
    for the account that reached the limit in its payload. In addition
    to the transparent address index, it also contains the key scope
    involved when the error was encountered.
  - A new `DiversifierIndexReuse` variant has been added.
  - A new `Scheduling` variant has been added.
- Each row returned from the `v_received_outputs` view now exposes an
  internal identifier for the address that received that output. This should
  be ignored by external consumers of this view.

## [0.15.0] - 2025-02-21

### Added
- `zcash_client_sqlite::WalletDb::from_connection`
- `zcash_client_sqlite::WalletDb::check_witnesses`
- `zcash_client_sqlite::WalletDb::queue_rescans`

### Changed
- MSRV is now 1.81.0.
- Migrated to `bip32 =0.6.0-pre.1`, `nonempty 0.11`.`incrementalmerkletree 0.8`,
  `shardtree 0.6`, `orchard 0.11`, `sapling-crypto 0.5`, `zcash_encoding 0.3`,
  `zcash_protocol 0.5`, `zcash_address 0.7`, `zcash_transparent 0.2`,
  `zcash_primitives 0.22`, `zcash_keys 0.7`, `zcash_client_backend 0.17`.
- `zcash_client_sqlite::wallet::init::init_wallet_db` now has an additional
  generic parameter, enabling it to be used with wallets constructed via
  `WalletDb::from_connection`.
- The `v_transactions` view has added columns `total_spent` and `total_received`.

## [0.14.0] - 2024-12-16

### Added
- `zcash_client_sqlite::AccountUuid`

### Changed
- Migrated to `sapling-crypto 0.4`, `zcash_keys 0.6`, `zcash_primitives 0.21`,
  `zcash_proofs 0.21`, `zcash_client_backend 0.16`
- The `v_transactions` view has been modified:
  - The `account_id` column has been replaced with `account_uuid`.
- The `v_tx_outputs` view has been modified:
  - The `from_account_id` column has been replaced with `from_account_uuid`.
  - The `to_account_id` column has been replaced with `to_account_uuid`.
- The `WalletRead` and `InputSource` impls for `WalletDb` now set the `AccountId`
  associated type to `AccountUuid`.
- Variants of `SqliteClientError` have changed:
  - The `AccountCollision` and `ReachedGapLimit` now carry `AccountUuid` values
    instead of `AccountId`s.
  - `SqliteClientError::AccountIdDiscontinuity` has been removed as it is now
    unused.
  - `SqliteClientError::AccountIdOutOfRange` has been renamed to
    `Zip32AccountIndexOutOfRange`.

### Removed
- `zcash_client_sqlite::AccountId` (use `AccountUuid` instead).

## [0.13.0] - 2024-11-14

### Added
- Exposed `AccountId::from_u32` and `AccountId::as_u32` conversions under the
  `unstable` feature flag.

### Changed
- MSRV is now 1.77.0.
- Migrated to `zcash_primitives 0.20`, `zcash_keys 0.5`,
  `zcash_client_backend 0.15`.
- Migrated from `schemer` to our fork `schemerz`.
- Migrated to `rusqlite 0.32`.
- `error::SqliteClientError` has additional variant `NoteFilterInvalid`

### Fixed
- `zcash_client_sqlite::WalletDb`'s implementation of
  `zcash_client_backend::data_api::WalletRead::get_wallet_summary` has been
  fixed to take account of `min_confirmations` for transparent balances.
  (Previously, it would treat transparent balances as though
  `min_confirmations` were `1` even if it was set to a higher value.)
  Note that this implementation treats `min_confirmations == 0` the same
  as `min_confirmations == 1` for both shielded and transparent TXOs.
  It also does not currently distinguish between pending change and
  non-change; the pending value is all counted as non-change (issue
  [#1592](https://github.com/zcash/librustzcash/issues/1592)).

## [0.12.2] - 2024-10-21

### Fixed
- Fixes an error in determining the minimum checkpoint height to which it's
  possible to rewind in the case of a reorg, when no other truncation height
  information is available.

## [0.12.1] - 2024-10-10

### Fixed
- An error in scan progress computation was fixed. As part of this fix, wallet
  summary information is now only returned in the case that some note
  commitment tree size information can be determined, either from subtree root
  download or from downloaded block data. NOTE: The recovery progress ratio may
  be present as `0:0` in the case that the recovery range contains no notes;
  this was not adequately documented in the previous release.

## [0.12.0] - 2024-10-04

### Added
- `impl WalletTest for WalletDb` is now available under the `test-dependencies`
  feature flag.

### Changed
- Migrated to `zcash_client_backend 0.14`, `orchard 0.10`,
  `sapling-crypto 0.3`, `shardtree 0.5`, `zcash_address 0.6`,
  `zcash_primitives 0.19`, `zcash_proofs 0.19`, `zcash_protocol 0.4`.
- `zcash_client_sqlite::error::SqliteClientError::RequestedRewindInvalid`
  is now a structured variant.

## [0.11.2] - 2024-08-21

### Changed
- The `v_tx_outputs` view was modified slightly to support older versions of
  `sqlite`. Queries to the exposed `v_tx_outputs` and `v_transactions` views
  are supported for SQLite versions back to `3.19.x`.
- `zcash_client_sqlite::wallet::init::WalletMigrationError` has an additional
  variant, `DatabaseNotSupported`. The `init_wallet_db` function now checks
  that the sqlite version in use is compatible with the features required by
  the wallet and returns this error if not. SQLite version `3.35` or higher
  is required for use with `zcash_client_sqlite`.

## [0.11.1] - 2024-08-21

### Fixed
- The dependencies of the `tx_retrieval_queue` migration have been fixed to
  enable migrating wallets containing certain kinds of transactions.

## [0.11.0] - 2024-08-20

`zcash_client_sqlite` now provides capabilities for the management of ephemeral
transparent addresses in support of the creation of ZIP 320 transaction pairs.

In addition, `zcash_client_sqlite` now provides improved tracking of transparent
wallet history in support of the API changes in `zcash_client_backend 0.13`,
and the `v_transactions` view has been modified to provide additional metadata
about the relationship of each transaction to the wallet, in particular whether
or not the transaction represents a wallet-internal shielding operation.

### Changed
- MSRV is now 1.70.0.
- Updated dependencies:
  - `zcash_address 0.4`
  - `zcash_client_backend 0.13`
  - `zcash_encoding 0.2.1`
  - `zcash_keys 0.3`
  - `zcash_primitives 0.16`
  - `zcash_protocol 0.2`
- `zcash_client_sqlite::error::SqliteClientError` has a new `ReachedGapLimit` and
  `EphemeralAddressReuse` variants when the "transparent-inputs" feature is enabled.
- `zcash_client_sqlite::error::SqliteClientError` has changed variants:
  - Removed `HdwalletError`.
  - Added `AccountCollision`.
  - Added `TransparentDerivation`.
- The `v_transactions` view has been modified:
  - The `block` column has been renamed to `mined_height`.
  - A `spent_note_count` column has been added.
  - An `is_shielding` column has been added, which is true for transactions where the
    spends from the wallet are all transparent, and the outputs to the wallet are all
    shielded.
- The `v_tx_outputs` view has been modified:
  - The result can now include transparent outputs with unknown height.

### Fixed
- The `to_address` column of the `v_tx_outputs` view is now `NULL` for
  transparent outputs received by the wallet. This column is only intended to
  contain addresses for outputs sent to external recipients. The fix aligns
  received transparent outputs with received shielded outputs (which have always
  returned `NULL`).

## [0.10.3] - 2024-04-08

### Added
- Added a migration to ensure that the default address for existing wallets is
  upgraded to include an Orchard receiver.

### Fixed
- A bug in the SQL query for `WalletDb::get_account_birthday` was fixed.

## [0.10.2] - 2024-03-27

### Fixed
- A bug in the SQL query for `WalletDb::get_unspent_transparent_output` was fixed.

## [0.10.1] - 2024-03-25

### Fixed
- The `sent_notes` table's `received_note` constraint was excessively restrictive
 after zcash/librustzcash#1306. Any databases that have migrations from
 zcash_client_sqlite 0.10.0 applied should be wiped and restored from seed.
 In order to ensure that the incorrect migration is not used, the migration
 id for the `full_account_ids` migration has been changed from
 `0x1b104345_f27e_42da_a9e3_1de22694da43` to `0x6d02ec76_8720_4cc6_b646_c4e2ce69221c`

## [0.10.0] - 2024-03-25

This version was yanked, use 0.10.1 instead.

### Added
- A new `orchard` feature flag has been added to make it possible to
  build client code without `orchard` dependendencies.
- `zcash_client_sqlite::AccountId`
- `zcash_client_sqlite::wallet::Account`
- `impl From<zcash_keys::keys::AddressGenerationError> for SqliteClientError`

### Changed
- Many places that `AccountId` appeared in the API changed from
  using `zcash_primitives::zip32::AccountId` to using an opaque `zcash_client_sqlite::AccountId`
  type.
  - The enum variant `zcash_client_sqlite::error::SqliteClientError::AccountUnknown`
    no longer has a `zcash_primitives::zip32::AccountId` data value.
  - Changes to the implementation of the `WalletWrite` trait:
    - `create_account` function returns a unique identifier for the new account (as before),
      except that this ID no longer happens to match the ZIP-32 account index.
      To get the ZIP-32 account index, use the new `WalletRead::get_account` function.
  - Two columns in the `transactions` view were renamed. They refer to the primary key field in the `accounts` table, which no longer equates to a ZIP-32 account index.
    - `to_account` -> `to_account_id`
    - `from_account` -> `from_account_id`
- `zcash_client_sqlite::error::SqliteClientError` has changed variants:
  - Added `AddressGeneration`
  - Added `UnknownZip32Derivation`
  - Added `BadAccountData`
  - Removed `DiversifierIndexOutOfRange`
  - Removed `InvalidNoteId`
- `zcash_client_sqlite::wallet`:
  - `init::WalletMigrationError` has added variants:
    - `WalletMigrationError::AddressGeneration`
    - `WalletMigrationError::CannotRevert`
    - `WalletMigrationError::SeedNotRelevant`
- The `v_transactions` and `v_tx_outputs` views now include Orchard notes.

## [0.9.1] - 2024-03-09

### Fixed
- Documentation now correctly builds with all feature flags.

## [0.9.0] - 2024-03-01

### Changed
- Migrated to `orchard 0.7`, `zcash_primitives 0.14`, `zcash_client_backend 0.11`.
- `zcash_client_sqlite::error::SqliteClientError` has new error variants:
  - `SqliteClientError::UnsupportedPoolType`
  - `SqliteClientError::BalanceError`
  - The `Bech32DecodeError` variant has been replaced with a more general
    `DecodingError` type.

## [0.8.1] - 2023-10-18

### Fixed
- Fixed a bug in `v_transactions` that was omitting value from identically-valued notes

## [0.8.0] - 2023-09-25

### Notable Changes
- The `v_transactions` and `v_tx_outputs` views have changed in terms of what
  columns are returned, and which result columns may be null. Please see the
  `Changed` section below for additional details.

### Added
- `zcash_client_sqlite::commitment_tree` Types related to management of note
  commitment trees using the `shardtree` crate.
- A new default-enabled feature flag `multicore`. This allows users to disable
  multicore support by setting `default_features = false` on their
  `zcash_primitives`, `zcash_proofs`, and `zcash_client_sqlite` dependencies.
- `zcash_client_sqlite::ReceivedNoteId`
- `zcash_client_sqlite::wallet::commitment_tree` A new module containing a
  sqlite-backed implementation of `shardtree::store::ShardStore`.
- `impl zcash_client_backend::data_api::WalletCommitmentTrees for WalletDb`

### Changed
- MSRV is now 1.65.0.
- Bumped dependencies to `hdwallet 0.4`, `incrementalmerkletree 0.5`, `bs58 0.5`,
  `prost 0.12`, `rusqlite 0.29`, `schemer-rusqlite 0.2.2`, `time 0.3.22`,
  `tempfile 3.5`, `zcash_address 0.3`, `zcash_note_encryption 0.4`,
  `zcash_primitives 0.13`, `zcash_client_backend 0.10`.
- Added dependencies on `shardtree 0.0`, `zcash_encoding 0.2`, `byteorder 1`
- A `CommitmentTree` variant has been added to `zcash_client_sqlite::wallet::init::WalletMigrationError`
- `min_confirmations` parameter values are now more strongly enforced. Previously,
  a note could be spent with fewer than `min_confirmations` confirmations if the
  wallet did not contain enough observed blocks to satisfy the `min_confirmations`
  value specified; this situation is now treated as an error.
- `zcash_client_sqlite::error::SqliteClientError` has new error variants:
  - `SqliteClientError::AccountUnknown`
  - `SqliteClientError::BlockConflict`
  - `SqliteClientError::CacheMiss`
  - `SqliteClientError::ChainHeightUnknown`
  - `SqliteClientError::CommitmentTree`
  - `SqliteClientError::NonSequentialBlocks`
- `zcash_client_backend::FsBlockDbError` has a new error variant:
  - `FsBlockDbError::CacheMiss`
- `zcash_client_sqlite::FsBlockDb::write_block_metadata` now overwrites any
  existing metadata entries that have the same height as a new entry.
- The `v_transactions` and `v_tx_outputs` views no longer return the
  internal database identifier for the transaction. The `txid` column should
  be used instead. The `tx_index`, `expiry_height`, `raw`, `fee_paid`, and
  `expired_unmined` columns will be null for received transparent
  transactions, in addition to the other columns that were previously
  permitted to be null.

### Removed
- The empty `wallet::transact` module has been removed.
- `zcash_client_sqlite::NoteId` has been replaced with `zcash_client_sqlite::ReceivedNoteId`
  as the `SentNoteId` variant is now unused following changes to
  `zcash_client_backend::data_api::WalletRead`.
- `zcash_client_sqlite::wallet::init::{init_blocks_table, init_accounts_table}`
  have been removed. `zcash_client_backend::data_api::WalletWrite::create_account`
  should be used instead; the initialization of the note commitment tree
  previously performed by `init_blocks_table` is now handled by passing an
  `AccountBirthday` containing the note commitment tree frontier as of the
  end of the birthday height block to `create_account` instead.
- `zcash_client_sqlite::DataConnStmtCache` has been removed in favor of using
  `rusqlite` caching for prepared statements.
- `zcash_client_sqlite::prepared` has been entirely removed.

### Fixed
- Fixed an off-by-one error in the `BlockSource` implementation for the SQLite-backed
 `BlockDb` block database which could result in blocks being skipped at the start of
 scan ranges.
- `zcash_client_sqlite::{BlockDb, FsBlockDb}::with_blocks` now return an error
  if `from_height` is set to a block height that does not exist in the cache.
- `WalletDb::get_transaction` no longer returns an error when called on a transaction
  that has not yet been mined, unless the transaction's consensus branch ID cannot be
  determined by other means.
- Fixed an error in `v_transactions` wherein received transparent outputs did not
  result in a transaction entry appearing in the transaction history.

## [0.7.1] - 2023-05-17

### Fixed
- Fixes a potential crash that could occur when attempting to read a memo from
  sqlite when the memo value is `NULL`. At present, we return the empty memo
  in this case; in the future, the `get_memo` API will be updated to reflect
  the potential absence of memo data.

## [0.7.0] - 2023-04-28
### Changed
- Bumped dependencies to `zcash_client_backend 0.9`.

### Removed
- The following deprecated types and methods have been removed from the public API:
  - `wallet::ShieldedOutput`
  - `wallet::block_height_extrema`
  - `wallet::get_address`
  - `wallet::get_all_nullifiers`
  - `wallet::get_balance`
  - `wallet::get_balance_at`
  - `wallet::get_block_hash`
  - `wallet::get_commitment_tree`
  - `wallet::get_nullifiers`
  - `wallet::get_received_memo`
  - `wallet::get_rewind_height`
  - `wallet::get_sent_memo`
  - `wallet::get_spendable_sapling_notes`
  - `wallet::get_transaction`
  - `wallet::get_tx_height`
  - `wallet::get_unified_full_viewing_keys`
  - `wallet::get_witnesses`
  - `wallet::insert_block`
  - `wallet::insert_witnesses`
  - `wallet::is_valid_account_extfvk`
  - `wallet::mark_sapling_note_spent`
  - `wallet::put_tx_data`
  - `wallet::put_tx_meta`
  - `wallet::prune_witnesses`
  - `wallet::select_spendable_sapling_notes`
  - `wallet::update_expired_notes`
  - `wallet::transact::get_spendable_sapling_notes`
  - `wallet::transact::select_spendable_sapling_notes`

## [0.6.0] - 2023-04-15
### Added
- SQLite view `v_tx_outputs`, exposing the history of transaction outputs sent
  from and received by the wallet. See `zcash_client_sqlite::wallet` for view
  documentation.

### Fixed
- In a previous crate release, `WalletDb` was modified to start tracking Sapling
  change notes in both the `sent_notes` and `received_notes` tables, as a form
  of double-entry accounting. This broke assumptions in the `v_transactions`
  SQLite view, and also left the `sent_notes` table in an inconsistent state. A
  migration has been added to this release which fixes the `sent_notes` table to
  consistently store Sapling change notes.
- The SQLite view `v_transactions` had several bugs independently from the above
  issue, and has been rewritten. See `zcash_client_sqlite::wallet` for view
  documentation.

### Changed
- Bumped dependencies to `group 0.13`, `jubjub 0.10`, `zcash_primitives 0.11`,
  `zcash_client_backend 0.8`.
- The dependency on `zcash_primitives` no longer enables the `multicore` feature
  by default in order to support compilation under `wasm32-wasi`. Users of other
  platforms may need to include an explicit dependency on `zcash_primitives`
  without `default-features = false` or otherwise explicitly enable the
  `zcash_primitives/multicore` feature if they did not already depend
  upon `zcash_primitives` with default features enabled.

### Removed
- SQLite views `v_tx_received` and `v_tx_sent` (use `v_tx_outputs` instead).

## [0.5.0] - 2023-02-01
### Added
- `zcash_client_sqlite::FsBlockDb::rewind_to_height` rewinds the BlockMeta Db
 to the specified height following the same logic as homonymous functions on
 `WalletDb`. This function does not delete the files referenced by the rows
 that might be present and are deleted by this function call.
- `zcash_client_sqlite::FsBlockDb::find_block`
- `zcash_client_sqlite::chain`:
  - `impl {Clone, Copy, Debug, PartialEq, Eq} for BlockMeta`

### Changed
- MSRV is now 1.60.0.
- Bumped dependencies to `zcash_primitives 0.10`, `zcash_client_backend 0.7`.
- `zcash_client_backend::FsBlockDbError`:
  - Renamed `FsBlockDbError::{DbError, FsError}` to `FsBlockDbError::{Db, Fs}`.
  - Added `FsBlockDbError::MissingBlockPath`.
  - `impl fmt::Display for FsBlockDbError`

## [0.4.2] - 2022-12-13
### Fixed
- `zcash_client_sqlite::WalletDb::get_transparent_balances` no longer returns an
  error if the wallet has no UTXOs.

## [0.4.1] - 2022-12-06
### Added
- `zcash_client_sqlite::DataConnStmtCache::advance_by_block` now generates a
  `tracing` span, which can be used for profiling.

## [0.4.0] - 2022-11-12
### Added
- Implementations of `zcash_client_backend::data_api::WalletReadTransparent`
  and `WalletWriteTransparent` have been added. These implementations
  are available only when the `transparent-inputs` feature flag is
  enabled.
- New error variants:
  - `SqliteClientError::TransparentAddress`, to support handling of errors in
    transparent address decoding.
  - `SqliteClientError::RequestedRewindInvalid`, to report when requested
    rewinds exceed supported bounds.
  - `SqliteClientError::DiversifierIndexOutOfRange`, to report when the space
    of available diversifier indices has been exhausted.
  - `SqliteClientError::AccountIdDiscontinuity`, to report when a user attempts
    to initialize the accounts table with a noncontiguous set of account identifiers.
  - `SqliteClientError::AccountIdOutOfRange`, to report when the maximum account
    identifier has been reached.
  - `SqliteClientError::Protobuf`, to support handling of errors in serialized
    protobuf data decoding.
- An `unstable` feature flag; this is added to parts of the API that may change
  in any release. It enables `zcash_client_backend`'s `unstable` feature flag.
- New summary views that may be directly accessed in the sqlite database.
  The structure of these views should be considered unstable; they may
  be replaced by accessors provided by the data access API at some point
  in the future:
  - `v_transactions`
  - `v_tx_received`
  - `v_tx_sent`
- `zcash_client_sqlite::wallet::init::WalletMigrationError`
- A filesystem-backed `BlockSource` implementation
  `zcash_client_sqlite::FsBlockDb`. This block source expects blocks to be
  stored on disk in individual files named following the pattern
  `<blockmeta_root>/blocks/<blockheight>-<blockhash>-compactblock`. A SQLite
  database stored at `<blockmeta_root>/blockmeta.sqlite`stores metadata for
  this block source.
  - `zcash_client_sqlite::chain::init::init_blockmeta_db` creates the required
    metadata cache database.
- Implementations of `PartialEq`, `Eq`, `PartialOrd`, and `Ord` for `NoteId`

### Changed
- Various **BREAKING CHANGES** have been made to the database tables. These will
  require migrations, which may need to be performed in multiple steps. Migrations
  will now be automatically performed for any user using
  `zcash_client_sqlite::wallet::init_wallet_db` and it is recommended to use this
  method to maintain the state of the database going forward.
  - The `extfvk` column in the `accounts` table has been replaced by a `ufvk`
    column. Values for this column should be derived from the wallet's seed and
    the account number; the Sapling component of the resulting Unified Full
    Viewing Key should match the old value in the `extfvk` column.
  - The `address` and `transparent_address` columns of the `accounts` table have
    been removed.
    - A new `addresses` table stores Unified Addresses, keyed on their `account`
      and `diversifier_index`, to enable storing diversifed Unified Addresses.
    - Transparent addresses for an account should be obtained by extracting the
      transparent receiver of a Unified Address for the account.
  - A new non-null column, `output_pool` has been added to the `sent_notes`
    table to enable distinguishing between Sapling and transparent outputs
    (and in the future, outputs to other pools). Values for this column should
    be assigned by inference from the address type in the stored data.
- MSRV is now 1.56.1.
- Bumped dependencies to `ff 0.12`, `group 0.12`, `jubjub 0.9`,
  `zcash_primitives 0.9`, `zcash_client_backend 0.6`.
- Renamed the following to use lower-case abbreviations (matching Rust
  naming conventions):
  - `zcash_client_sqlite::BlockDB` to `BlockDb`
  - `zcash_client_sqlite::WalletDB` to `WalletDb`
  - `zcash_client_sqlite::error::SqliteClientError::IncorrectHRPExtFVK` to
    `IncorrectHrpExtFvk`.
- The SQLite implementations of `zcash_client_backend::data_api::WalletRead`
  and `WalletWrite` have been updated to reflect the changes to those
  traits.
- `zcash_client_sqlite::wallet`:
  - `get_spendable_notes` has been renamed to `get_spendable_sapling_notes`.
  - `select_spendable_notes` has been renamed to `select_spendable_sapling_notes`.
  - `get_spendable_sapling_notes` and `select_spendable_sapling_notes` have also
    been changed to take a parameter that permits the caller to specify a set of
    notes to exclude from consideration.
  - `init_wallet_db` has been modified to take the wallet seed as an argument so
    that it can correctly perform migrations that require re-deriving key
    material. In particular for this upgrade, the seed is used to derive UFVKs
    to replace the currently stored Sapling ExtFVKs (without losing information)
    as part of the migration process.

### Removed
- The following functions have been removed from the public interface of
  `zcash_client_sqlite::wallet`. Prefer methods defined on
  `zcash_client_backend::data_api::{WalletRead, WalletWrite}` instead.
  - `get_extended_full_viewing_keys` (use `WalletRead::get_unified_full_viewing_keys` instead).
  - `insert_sent_note` (use `WalletWrite::store_sent_tx` instead).
  - `insert_sent_utxo` (use `WalletWrite::store_sent_tx` instead).
  - `put_sent_note` (use `WalletWrite::store_decrypted_tx` instead).
  - `put_sent_utxo` (use `WalletWrite::store_decrypted_tx` instead).
  - `delete_utxos_above` (use `WalletWrite::rewind_to_height` instead).
- `zcash_client_sqlite::with_blocks` (use
  `zcash_client_backend::data_api::BlockSource::with_blocks` instead).
- `zcash_client_sqlite::error::SqliteClientError` variants:
  - `SqliteClientError::IncorrectHrpExtFvk`
  - `SqliteClientError::Base58`
  - `SqliteClientError::BackendError`

### Fixed
- The `zcash_client_backend::data_api::WalletRead::get_address` implementation
  for `zcash_client_sqlite::WalletDb` now correctly returns `Ok(None)` if the
  account identifier does not correspond to a known account.

### Deprecated
- A number of public API methods that are used internally to support the
  `zcash_client_backend::data_api::{WalletRead, WalletWrite}` interfaces have
  been deprecated, and will be removed from the public API in a future release.
  Users should depend upon the versions of these methods exposed via the
  `zcash_client_backend::data_api` traits mentioned above instead.
  - Deprecated in `zcash_client_sqlite::wallet`:
    - `get_address`
    - `is_valid_account_extfvk`
    - `get_balance`
    - `get_balance_at`
    - `get_sent_memo`
    - `block_height_extrema`
    - `get_tx_height`
    - `get_block_hash`
    - `get_rewind_height`
    - `get_commitment_tree`
    - `get_witnesses`
    - `get_nullifiers`
    - `insert_block`
    - `put_tx_meta`
    - `put_tx_data`
    - `mark_sapling_note_spent`
    - `put_receiverd_note`
    - `insert_witness`
    - `prune_witnesses`
    - `update_expired_notes`
    - `get_address`
  - Deprecated in `zcash_client_sqlite::wallet::transact`:
    - `get_spendable_sapling_notes`
    - `select_spendable_sapling_notes`

## [0.3.0] - 2021-03-26
This release contains a major refactor of the APIs to leverage the new Data
Access API in the `zcash_client_backend` crate. API names are almost all the
same as before, but have been reorganized.

### Added
- `zcash_client_sqlite::BlockDB`, a read-only wrapper for the SQLite connection
  to the block cache database.
- `zcash_client_sqlite::WalletDB`, a read-only wrapper for the SQLite connection
  to the wallet database.
- `zcash_client_sqlite::DataConnStmtCache`, a read-write wrapper for the SQLite
  connection to the wallet database. Returned by `WalletDB::get_update_ops`.
- `zcash_client_sqlite::NoteId`

### Changed
- MSRV is now 1.47.0.
- APIs now take `&BlockDB` and `&WalletDB<P>` arguments, instead of paths to the
  block cache and wallet databases.
- The library no longer uses the `mainnet` feature flag to specify the network
  type. APIs now take a `P: zcash_primitives::consensus::Parameters` variable.

### Removed
- `zcash_client_sqlite::address` module (moved to `zcash_client_backend`).

### Fixed
- Shielded transactions created by the wallet that have no change output (fully
  spending their input notes) are now correctly detected as mined when scanning
  compact blocks.
- Unshielding transactions created by the wallet (with a transparent recipient
  address) that have no change output no longer cause a panic.

## [0.2.1] - 2020-10-24
### Fixed
- `transact::create_to_address` now correctly reconstructs notes from the data
  DB after Canopy activation (zcash/librustzcash#311). This is critcal to correct
  operation of spends after Canopy.

## [0.2.0] - 2020-09-09
### Changed
- MSRV is now 1.44.1.
- Bumped dependencies to `ff 0.8`, `group 0.8`, `jubjub 0.5.1`, `protobuf 2.15`,
  `rusqlite 0.24`, `zcash_primitives 0.4`, `zcash_client_backend 0.4`.

## [0.1.0] - 2020-08-24
Initial release.
