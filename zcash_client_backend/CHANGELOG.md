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
  - A `zcash_client_backend::wallet::WalletTransparentOutput` type
    in support of `transparent-inputs` functionality.
- A new `data_api::wallet::spend` method has been added, which is
  intended to supersede the `data_api::wallet::create_spend_to_address`
  method. This new method now constructs transactions via interpretation
  of a `zcash_client_backend::zip321::TransactionRequest` value.
  This facilitates the implementation of ZIP 321 support in wallets and
  provides substantially greater flexibility in transaction creation.
- An `unstable` feature flag; this is added to parts of the API that may change
  in any release.
- `zcash_client_backend::address`:
  - `RecipientAddress::Unified`
  - `AddressMetadata`
- `zcash_client_backend::data_api`:
  - `PoolType`
  - `Recipient`
  - `SentTransactionOutput`
  - `WalletRead::get_unified_full_viewing_keys`
  - `WalletRead::get_account_for_ufvk`
  - `WalletRead::get_current_address`
  - `WalletRead::get_all_nullifiers`
  - `WalletRead::get_transparent_receivers`
  - `WalletRead::get_unspent_transparent_outputs`
  - `WalletRead::get_transparent_balances`
  - `WalletWrite::create_account`
  - `WalletWrite::remove_unmined_tx` (behind the `unstable` feature flag).
  - `WalletWrite::get_next_available_address`
  - `WalletWrite::put_received_transparent_utxo`
  - `impl From<prost::DecodeError> for error::Error`
- `zcash_client_backend::decrypt`:
  - `TransferType`
- `zcash_client_backend::proto`:
  - `actions` field on `compact_formats::CompactTx`
  - `compact_formats::CompactOrchardAction`
  - gRPC bindings for the `lightwalletd` server, behind a `lightwalletd-tonic`
    feature flag.
- `zcash_client_backend::zip321::TransactionRequest` methods:
  - `TransactionRequest::new` for constructing a request from `Vec<Payment>`.
  - `TransactionRequest::payments` for accessing the `Payments` that make up a
    request.
- `zcash_client_backend::encoding`
  - `KeyError`
  - `AddressCodec` implementations for `sapling::PaymentAddress` and
    `UnifiedAddress`
- `zcash_client_backend::fees`
  - `ChangeError`
  - `ChangeStrategy`
  - `ChangeValue`
  - `TransactionBalance`
  - `BasicFixedFeeChangeStrategy` - a `ChangeStrategy` implementation that
    reproduces current wallet change behavior
- New experimental APIs that should be considered unstable, and are
  likely to be modified and/or moved to a different module in a future
  release:
  - `zcash_client_backend::address::UnifiedAddress`
  - `zcash_client_backend::keys::{UnifiedSpendingKey`, `UnifiedFullViewingKey`, `Era`, `DecodingError`}
  - `zcash_client_backend::encoding::AddressCodec`
  - `zcash_client_backend::encoding::encode_payment_address`
  - `zcash_client_backend::encoding::encode_transparent_address`

### Changed
- MSRV is now 1.56.1.
- Bumped dependencies to `ff 0.12`, `group 0.12`, `bls12_381 0.7`, `jubjub 0.9`,
  `zcash_primitives 0.8`, `orchard 0.3`.
- `zcash_client_backend::proto`:
  - The Protocol Buffers bindings are now generated for `prost 0.11` instead of
    `protobuf 2`.
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
- The `zcash_client_backend::data_api::SentTransaction` type has been
  substantially modified to accommodate handling of transparent inputs.
  Per-output data has been split out into a new struct `SentTransactionOutput`
  and `SentTransaction` can now contain multiple outputs, and tracks the
  fee paid.
- `data_api::WalletWrite::store_received_tx` has been renamed to
  `store_decrypted_tx`.
- `data_api::ReceivedTransaction` has been renamed to `DecryptedTransaction`,
  and its `outputs` field has been renamed to `sapling_outputs`.
- `data_api::error::Error::Protobuf` now wraps `prost::DecodeError` instead of
  `protobuf::ProtobufError`.
- `data_api::error::Error` has the following additional cases:
  - `Error::BalanceError` in the case of amount addition overflow
    or subtraction underflow.
  - `Error::MemoForbidden` to report the condition where a memo was
    specified to be sent to a transparent recipient.
  - `Error::TransparentInputsNotSupported` to represent the condition
    where a transparent spend has been requested of a wallet compiled without
    the `transparent-inputs` feature.
  - `Error::AddressNotRecognized` to indicate that a transparent address from
    which funds are being requested to be spent does not appear to be associated
    with this wallet.
  - `Error::ChildIndexOutOfRange` to indicate that a diversifier index for an
    address is out of range for valid transparent child indices.
  - `Error::NoteMismatch` to indicate that a note being spent is not associated
    with either the internal or external full viewing keys corresponding to the
    provided spending key.
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
- The return type of the following methods in `zcash_client_backend::encoding`
  have been changed to improve error reporting:
  - `decode_extended_spending_key`
  - `decode_extended_full_viewing_key`
  - `decode_payment_address`
- `data_api::wallet::create_spend_to_address` has been modified to use a unified
  spending key rather than a Sapling extended spending key.

### Removed
- `zcash_client_backend::data_api`:
  - `WalletRead::get_extended_full_viewing_keys` (use
    `WalletRead::get_unified_full_viewing_keys` instead).
  - `WalletRead::get_address` (use `WalletRead::get_current_address` or
    `WalletWrite::get_next_available_address` instead.)
  - `impl From<protobuf::ProtobufError> for error::Error`
- `zcash_client_backend::proto::compact_formats`:
  - `Compact*::new` methods (use `Default::default` or struct instantiation
    instead).
  - Getters (use dedicated typed methods or direct field access instead).
  - Setters (use direct field access instead).
- The hardcoded `data_api::wallet::ANCHOR_OFFSET` constant.
- `zcash_client_backend::wallet::AccountId` (moved to `zcash_primitives::zip32::AccountId`).
- The implementation of `welding_rig::ScanningKey` for `ExtendedFullViewingKey`
  has been removed. Use `DiversifiableFullViewingKey` instead.

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
