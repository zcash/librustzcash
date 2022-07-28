# Changelog
All notable changes to this library will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this library adheres to Rust's notion of
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Functionality that enables the receiving and spending of transparent funds,
  behind the new `transparent-inputs` feature flag.
  - A new `data_api::wallet::shield_transparent_funds` method has been added
    to facilitate the automatic shielding of transparent funds received
    by the wallet.
  - `zcash_client_backend::data_api::WalletReadTransparent` read-only operations
    related to information the wallet maintains about transparent funds.
  - `zcash_client_backend::data_api::WalletWriteTransparent` operations
    related persisting information the wallet maintains about transparent funds.
  - A `zcash_client_backend::wallet::WalletTransparentOutput` type
    has been added under the `transparent-inputs` feature flag in support
    of autoshielding functionality.
- A new `data_api::wallet::spend` method has been added, which is
  intended to supersede the `data_api::wallet::create_spend_to_address`
  method. This new method now constructs transactions via interpretation
  of a `zcash_client_backend::zip321::TransactionRequest` value.
  This facilitates the implementation of ZIP 321 support in wallets and
  provides substantially greater flexibility in transaction creation.
- `zcash_client_backend::address`:
  - `RecipientAddress::Unified`
- `zcash_client_backend::data_api`:
    `WalletRead::get_unified_full_viewing_keys`
- `zcash_client_backend::proto`:
  - `actions` field on `compact_formats::CompactTx`
  - `compact_formats::CompactOrchardAction`
- `zcash_client_backend::zip321::TransactionRequest` methods:
  - `TransactionRequest::new` for constructing a request from `Vec<Payment>`.
  - `TransactionRequest::payments` for accessing the `Payments` that make up a
    request.
- New experimental APIs that should be considered unstable, and are
  likely to be modified and/or moved to a different module in a future
  release:
  - `zcash_client_backend::address::UnifiedAddress`
  - `zcash_client_backend::keys::{UnifiedSpendingKey`, `UnifiedFullViewingKey`}
  - `zcash_client_backend::encoding::AddressCodec`
  - `zcash_client_backend::encoding::encode_payment_address`
  - `zcash_client_backend::encoding::encode_transparent_address`

### Changed
- MSRV is now 1.56.1.
- Bumped dependencies to `ff 0.12`, `group 0.12`, `bls12_381 0.7`, `jubjub 0.9`,
  `zcash_primitives 0.7`.
- `zcash_client_backend::proto`:
  - `compact_formats::CompactSpend` has been renamed to `CompactSaplingSpend`,
    and its `epk` field (and associated `set_epk` method) has been renamed to
    `ephemeralKey` (and `set_ephemeralKey`).
  - `compact_formats::CompactOutput` has been renamed to `CompactSaplingOutput`.
- `epk: jubjub::ExtendedPoint` has been replaced by
  `ephemeral_key: zcash_note_encryption::EphemeralKeyBytes` in various places:
  - `zcash_client_backend::wallet::WalletShieldedOutput`: the `epk` field has
    been replaced by `ephemeral_key`.
  - `zcash_client_backend::proto::compact_formats::CompactSaplingOutput`: the
    `epk` method has been replaced by `ephemeral_key`.
- `data_api::wallet::spend_to_address` now takes a `min_confirmations`
  parameter, which the caller can provide to specify the minimum number of
  confirmations required for notes being selected. A default value of 10
  confirmations is recommended.
- Renamed the following in `zcash_client_backend::data_api` to use lower-case
  abbreviations (matching Rust naming conventions):
  - `error::Error::InvalidExtSK` to `Error::InvalidExtSk`
  - `testing::MockWalletDB` to `testing::MockWalletDb`
- Changes to the `data_api::WalletRead` trait:
  - `WalletRead::get_target_and_anchor_heights` now takes
    a `min_confirmations` argument that is used to compute an upper bound on
    the anchor height being returned; this had previously been hardcoded to
    `data_api::wallet::ANCHOR_OFFSET`.
  - `WalletRead::get_spendable_notes` has been renamed to
    `get_spendable_sapling_notes`
  - `WalletRead::select_spendable_notes` has been renamed to
    `select_spendable_sapling_notes`
  - `WalletRead::get_all_nullifiers` has been
    added. This method provides access to all Sapling nullifiers, including
    for notes that have been previously marked spent.
- The `zcash_client_backend::data_api::SentTransaction` type has been
  substantially modified to accommodate handling of transparent inputs.
  Per-output data has been split out into a new struct `SentTransactionOutput`
  and `SentTransaction` can now contain multiple outputs.
- `data_api::WalletWrite::store_received_tx` has been renamed to
  `store_decrypted_tx`.
- `data_api::ReceivedTransaction` has been renamed to `DecryptedTransaction`,
  and its `outputs` field has been renamed to `sapling_outputs`.
- An `Error::MemoForbidden` error has been added to the
  `data_api::error::Error` enum to report the condition where a memo was
  specified to be sent to a transparent recipient.
- `zcash_client_backend::decrypt`:
  - `decrypt_transaction` now takes a `HashMap<_, UnifiedFullViewingKey>`
    instead of `HashMap<_, ExtendedFullViewingKey>`.
- If no memo is provided when sending to a shielded recipient, the
  empty memo will be used
- `zcash_client_backend::keys::spending_key` has been moved to the
  `zcash_client_backend::keys::sapling` module.
- `zcash_client_backend::zip321::MemoError` has been renamed and
  expanded into a more comprehensive `Zip321Error` type, and functions in the
  `zip321` module have been updated to use this unified error type. The
  following error cases have been added:
  - `Zip321Error::TooManyPayments(usize)`
  - `Zip321Error::DuplicateParameter(parse::Param, usize)`
  - `Zip321Error::TransparentMemo(usize)`
  - `Zip321Error::RecipientMissing(usize)`
  - `Zip321Error::ParseError(String)`
- The api of `welding_rig::ScanningKey` has changed to accommodate batch
  decryption and to correctly handle scanning with the internal (change) keys
  derived from ZIP 316 UFVKs and UIVKs.
- `welding_rig::scan_block` now uses batching for trial-decryption of
  transaction outputs.


### Removed
- `zcash_client_backend::data_api`:
  - `WalletRead::get_extended_full_viewing_keys` (use
    `WalletRead::get_unified_full_viewing_keys` instead).
- The hardcoded `data_api::wallet::ANCHOR_OFFSET` constant.
- `zcash_client_backend::wallet::AccountId` (moved to `zcash_primitives::zip32::AccountId`).


## [0.5.0] - 2021-03-26
### Added
- `zcash_client_backend::address::RecipientAddress`
- `zcash_client_backend::data_api` module, containing the Data Access API.
- `zcash_client_backend::wallet`:
  - `AccountId`
  - `SpendableNote`
  - `OvkPolicy`
- `zcash_client_backend::welding_rig::ScanningKey` trait, representing a key
  which can be used for trial decryption of outputs, and optionally nullifier
  computation. This trait is implemented for
  `zcash_primitives::zip32:ExtendedFullViewingKey` and
  `zcash_primitives::primitives::SaplingIvk`.
- First alpha of TZE support, behind the `zfuture` feature flag.

### Changed
- MSRV is now 1.47.0.
- `epk` fields and return values were changed from a `jubjub::SubgroupPoint` to
  a `jubjub::ExtendedPoint`, to match the change to the `zcash_primitives`
  decryption APIs:
  - `zcash_client_backend::proto::compact_formats::CompactOutput::epk()`
  - The `epk` field of `zcash_client_backend::wallet::WalletShieldedOutput`.
- `zcash_client_backend::decrypt`:
  - `decrypt_transaction` now takes a variable with type
    `P: zcash_primitives::consensus::Parameters`.
  - The `memo` field of `DecryptedOutput` now has type `MemoBytes`.
- `zcash_client_backend::wallet`:
  - The `nf` property of `WalletShieldedSpend` now has the type `Nullifier`.
  - The `account` property of `WalletShieldedSpend` and `WalletShieldedOutput`
    now has the type `AccountId`.
- `zcash_client_backend::welding_rig`:
  - `scan_block` now takes `&[(AccountId, K: ScanningKey)]`, instead of a
    slice of extended full viewing keys with implicit account IDs.
  - The `nullifiers` argument to `scan_block` now has the type
    `&[(AccountId, Nullifier)]`.

### Removed
- `zcash_client_backend::constants` module (its sub-modules have been moved into
  `zcash_primitives::constants`, and more generally replaced by the new methods
  on the `zcash_primitives::consensus::Parameters` trait).

## [0.4.0] - 2020-09-09
### Changed
- MSRV is now 1.44.1.
- Bumped dependencies to `ff 0.8`, `group 0.8`, `bls12_381 0.3.1`,
  `jubjub 0.5.1`, `protobuf 2.15`.

## [0.3.0] - 2020-08-24
TBD

## [0.2.0] - 2020-03-13
TBD

## [0.1.0] - 2019-10-08
Initial release.
