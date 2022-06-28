# Changelog
All notable changes to this library will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this library adheres to Rust's notion of
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
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

### Changed
- Various **BREAKING CHANGES** have been made to the database tables. These will
  require migrations, which may need to be performed in multiple steps.
  - The `extfvk` column in the `accounts` table has been replaced by a `ufvk`
    column. Values for this column should be derived from the wallet's seed and
    the account number; the Sapling component of the resulting Unified Full
    Viewing Key should match the old value in the `extfvk` column.
  - A new non-null column, `output_pool` has been added to the `sent_notes`
    table to enable distinguishing between Sapling and transparent outputs
    (and in the future, outputs to other pools). Values for this column should
    be assigned by inference from the address type in the stored data.
- MSRV is now 1.56.1.
- Bumped dependencies to `ff 0.12`, `group 0.12`, `jubjub 0.9`.
- Renamed the following to use lower-case abbreviations (matching Rust
  naming conventions):
  - `zcash_client_sqlite::BlockDB` to `BlockDb`
  - `zcash_client_sqlite::WalletDB` to `WalletDb`
  - `zcash_client_sqlite::error::SqliteClientError::IncorrectHRPExtFVK` to
    `IncorrectHrpExtFvk`.
- The SQLite implementations of `zcash_client_backend::data_api::WalletRead`
  and `WalletWrite` have been updated to reflect the changes to those
  traits.
- Renamed the following to reflect their Sapling-specific nature:
  - `zcash_client_sqlite::wallet`:
    - `get_spendable_notes` to `get_spendable_sapling_notes`.
    - `select_spendable_notes` to `select_spendable_sapling_notes`.
- Altered the arguments to `zcash_client_sqlite::wallet::put_sent_note`
  to take the components of a `DecryptedOutput` value to allow this
  method to be used in contexts where a transaction has just been
  constructed, rather than only in the case that a transaction has
  been decrypted after being retrieved from the network.

### Removed
- `zcash_client_sqlite::wallet`:
  - `get_extended_full_viewing_keys` (use
    `zcash_client_backend::data_api::WalletRead::get_unified_full_viewing_keys`
    instead).

### Deprecated
- A number of public API methods that are used internally to support the
  `zcash_client_backend::data_api::{WalletRead, WalletWrite}` interfaces have
  been deprecated, and will be removed from the public API in a future release.
  Users should depend upon the versions of these methods exposed via the
  `zcash_client_backend::data_api` traits mentioned above instead.
  - Deprecated in `zcash_client_sqlite::wallet`:
    - `get_address`
    - `get_extended_full_viewing_keys`
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
    - `delete_utxos_above`
    - `put_receiverd_note`
    - `insert_witness`
    - `prune_witnesses`
    - `update_expired_notes`
    - `put_sent_note`
    - `put_sent_utxo`
    - `insert_sent_note`
    - `insert_sent_utxo`
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
