# Changelog
All notable changes to this library will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this library adheres to Rust's notion of
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
### Added
- `impl Eq for zcash_client_backend::address::RecipientAddress`
- `impl Eq for zcash_client_backend::zip321::{Payment, TransactionRequest}`
- `data_api::NullifierQuery` for use with `WalletRead::get_sapling_nullifiers`

### Changed
- MSRV is now 1.65.0.
- Bumped dependencies to `hdwallet 0.4`, `zcash_primitives 0.12`, `zcash_note_encryption 0.4`,
  `incrementalmerkletree 0.4`, `orchard 0.5`, `bs58 0.5`
- `WalletRead::get_memo` now returns `Result<Option<Memo>, Self::Error>`
  instead of `Result<Memo, Self::Error>` in order to make representable
  wallet states where the full note plaintext is not available.
- `WalletRead::get_nullifiers` has been renamed to `WalletRead::get_sapling_nullifiers`
  and its signature has changed; it now subsumes the removed `WalletRead::get_all_nullifiers`.
- `wallet::SpendableNote` has been renamed to `wallet::ReceivedSaplingNote`.

### Removed
- `WalletRead::get_all_nullifiers`

## [0.9.0] - 2023-04-28
### Added
- `data_api::SentTransactionOutput::from_parts`
- `data_api::WalletRead::get_min_unspent_height`

### Changed
- `decrypt::DecryptedOutput` is now parameterized by a `Note` type parameter,
  to allow reuse of the data structure for non-Sapling contexts.
- `data_api::SentTransactionOutput` must now be constructed using
  `SentTransactionOutput::from_parts`. The internal state of `SentTransactionOutput`
  is now private, and accessible via methods that have the same names as the
  previously exposed fields.

### Renamed
- The following types and fields have been renamed in preparation for supporting
  `orchard` in wallet APIs:
  - `WalletTx::shielded_spends`  -> `WalletTx::sapling_spends`
  - `WalletTx::shielded_outputs` -> `WalletTx::sapling_outputs`
  - `WalletShieldedSpend` -> `WalletSaplingSpend`. Also, the internals of this
    data structure have been made private.
  - `WalletShieldedOutput` -> `WalletSaplingOutput`. Also, the internals of this
    data structure have been made private.
- The `data_api::WalletWrite::rewind_to_height` method has been renamed to
  `truncate_to_height` to better reflect its semantics.

### Removed
  - `wallet::WalletTx::num_spends`
  - `wallet::WalletTx::num_outputs`
  - `wallet::WalletSaplingOutput::to` is redundant and has been removed; the
    recipient address can be obtained from the note.
  - `decrypt::DecryptedOutput::to` is redundant and has been removed; the
    recipient address can be obtained from the note.

## [0.8.0] - 2023-04-15
### Changed
- Bumped dependencies to `bls12_381 0.8`, `group 0.13`, `orchard 0.4`,
  `tonic 0.9`, `base64 0.21`, `bech32 0.9`, `zcash_primitives 0.11`.
- The dependency on `zcash_primitives` no longer enables the `multicore` feature
  by default in order to support compilation under `wasm32-wasi`. Users of other
  platforms may need to include an explicit dependency on `zcash_primitives`
  without `default-features = false` or otherwise explicitly enable the
  `zcash_primitives/multicore` feature if they did not already depend
  upon `zcash_primitives` with default features enabled.

### Fixed
- `zcash_client_backend::fees::zip317::SingleOutputChangeStrategy` now takes
  into account the Sapling output padding behaviour of
  `zcash_primitives::transaction::components::sapling::builder::SaplingBuilder`.

## [0.7.0] - 2023-02-01
### Added
- `zcash_client_backend::data_api::wallet`:
  - `input_selection::Proposal::{is_shielding, target_height}`
  - `propose_transfer`
  - `propose_shielding`
  - `create_proposed_transaction`

### Changed
- MSRV is now 1.60.0.
- Bumped dependencies to `zcash_primitives 0.10`.
- `zcash_client_backend::data_api::chain`:
  - `BlockSource::with_blocks` now takes `from_height` as `Option<BlockHeight>`
    instead of `BlockHeight`. Trait implementors should return all available
    blocks in the datastore when `from_height` is `None`.
  - Various **breaking changes** to `validate_chain`:
    - The `parameters: &ParamsT` argument has been removed. When `None` is given
      as the `validate_from` argument, `validate_chain` will now pass `None` to
      `BlockSource::with_blocks` (instead of the Sapling network upgrade's
      activation height).
    - A `limit: Option<u32>` argument has been added. This enables callers to
      validate smaller intervals of blocks already present on the provided
      `BlockSource`, shortening processing times of the function call at the
      expense of obtaining a partial result. When providing a `limit`, a result
      of `Ok(())` means that the chain has been validated on its continuity of
      heights and hashes in the range `[validate_from, validate_from + limit)`.
      Callers are responsible for making subsequent calls to `validate_chain` in
      order to complete validating the totality of `block_source`.
- `zcash_client_backend::data_api::wallet`:
  - `input_selection::Proposal` no longer has a `TransparentInput` generic
    parameter, and `Proposal::transparent_inputs` now returns
    `&[zcash_client_backend::wallet::WalletTransparentOutput]`.
  - `shield_transparent_funds` now takes a `shielding_threshold` argument that
    can be used to specify the minimum value allowed as input to a shielding
    transaction. Previously the shielding threshold was fixed at 100000 zatoshis.
- Note commitments now use
  `zcash_primitives::sapling::note::ExtractedNoteCommitment` instead of
  `bls12_381::Scalar` in the following places:
  - The `cmu` field of `zcash_client_backend::wallet::WalletShieldedOutput`.
  - `zcash_client_backend::proto::compact_formats::CompactSaplingOutput::cmu`.

### Removed
- `zcash_client_backend::data_api`:
  - `WalletWrite::remove_unmined_tx` (was behind the `unstable` feature flag).

## [0.6.1] - 2022-12-06
### Added
- `zcash_client_backend::data_api::chain::scan_cached_blocks` now generates
  `tracing` spans, which can be used for profiling.

### Fixed
- `zcash_client_backend:zip321` no longer returns an error when trying to parse
  a URI without query parameters.

## [0.6.0] - 2022-11-12
### Added
- Functionality that enables the receiving and spending of transparent funds,
  behind the new `transparent-inputs` feature flag.
  - A new `zcash_client_backend::data_api::wallet::shield_transparent_funds`
    method has been added to facilitate the automatic shielding of transparent
    funds received by the wallet.
  - A `zcash_client_backend::wallet::WalletTransparentOutput` type in support of
    `transparent-inputs` functionality.
- An `unstable` feature flag; this is added to parts of the API that may change
  in any release.
- `zcash_client_backend::address`:
  - `RecipientAddress::Unified`
  - `AddressMetadata`
  - `impl Eq for UnifiedAddress`
- `zcash_client_backend::data_api`:
  - `wallet::spend` method, intended to supersede the `wallet::create_spend_to_address`
    method. This new method now constructs transactions via interpretation of a
    `zcash_client_backend::zip321::TransactionRequest` value. This facilitates
    the implementation of ZIP 321 support in wallets and provides substantially
    greater flexibility in transaction creation.
  - `PoolType`
  - `ShieldedPool`
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
  - `chain::error`: a module containing error types type that that can occur only
    in chain validation and sync have been separated out from errors related to
    other wallet operations.
  - `input_selection`: a module containing types related to the process
    of selecting inputs to be spent, given a transaction request.
- `zcash_client_backend::decrypt`:
  - `TransferType`
- `zcash_client_backend::proto`:
  - `actions` field on `compact_formats::CompactTx`
  - `compact_formats::CompactOrchardAction`
  - gRPC bindings for the `lightwalletd` server, behind a `lightwalletd-tonic`
    feature flag.
- `zcash_client_backend::zip321::TransactionRequest` methods:
  - `TransactionRequest::empty` for constructing a new empty request.
  - `TransactionRequest::new` for constructing a request from `Vec<Payment>`.
  - `TransactionRequest::payments` for accessing the `Payments` that make up a
    request.
- `zcash_client_backend::encoding`
  - `KeyError`
  - `AddressCodec` implementations for `sapling::PaymentAddress` and
    `UnifiedAddress`.
- `zcash_client_backend::fees`
  - `ChangeError`
  - `ChangeStrategy`
  - `ChangeValue`
  - `TransactionBalance`
  - `fixed`, a module containing change selection strategies for the old fixed
    fee rule.
  - `zip317`, a module containing change selection strategies for the ZIP 317
    fee rule.
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
- Bumped dependencies to `ff 0.12`, `group 0.12`, `bls12_381 0.7`
  `zcash_primitives 0.9`, `orchard 0.3`.
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
- `zcash_client_backend::data_api`:
  - Renamed the following to use lower-case abbreviations (matching Rust naming
    conventions):
    - `testing::MockWalletDB` to `testing::MockWalletDb`
  - Changes to the `WalletRead` trait:
    - `WalletRead::get_target_and_anchor_heights` now takes
      a `min_confirmations` argument that is used to compute an upper bound on
      the anchor height being returned; this had previously been hardcoded to
      `wallet::ANCHOR_OFFSET`.
    - `WalletRead::get_spendable_notes` has been renamed to
      `get_spendable_sapling_notes`, and now takes as an argument a vector of
      note IDs to be excluded from consideration.
    - `WalletRead::select_spendable_notes` has been renamed to
      `select_spendable_sapling_notes`, and now takes as an argument a vector of
      note IDs to be excluded from consideration.
    - The `WalletRead::NoteRef` and `WalletRead::TxRef` associated types are now
      required to implement `Eq` and `Ord`
  - `WalletWrite::store_received_tx` has been renamed to `store_decrypted_tx`.
  - `wallet::decrypt_and_store_transaction` now always stores the transaction by
    calling `WalletWrite::store_decrypted_tx`, even if no outputs could be
    decrypted. The error type produced by the provided `WalletWrite` instance is
    also now returned directly.
  - The `SentTransaction` type has been substantially modified to accommodate
    handling of transparent inputs. Per-output data has been split out into a
    new struct `SentTransactionOutput`, and `SentTransaction` can now contain
    multiple outputs, and tracks the fee paid.
  - `ReceivedTransaction` has been renamed to `DecryptedTransaction`, and its
    `outputs` field has been renamed to `sapling_outputs`.
  - `BlockSource` has been moved to the `chain` module.
  - The types of the `with_row` callback argument to `BlockSource::with_blocks`
    and the return type of this method have been modified to return
    `chain::error::Error`.
  - `testing::MockBlockSource` has been moved to
    `chain::testing::MockBlockSource` module.
  - `chain::{validate_chain, scan_cached_blocks}` have altered parameters and
    result types. The latter have been modified to return`chain::error::Error`
    instead of abstract error types. This new error type now wraps the errors of
    the block source and wallet database to which these methods delegate IO
    operations directly, which simplifies error handling in cases where callback
    functions are involved.
  - `error::ChainInvalid` has been moved to `chain::error`.
  - `error::Error` has been substantially modified. It now wraps database,
    note selection, builder, and other errors.
    - Added new error cases:
      - `Error::DataSource`
      - `Error::NoteSelection`
      - `Error::BalanceError`
      - `Error::MemoForbidden`
      - `Error::AddressNotRecognized`
      - `Error::ChildIndexOutOfRange`
      - `Error::NoteMismatch`
    - `Error::InsufficientBalance` has been renamed to `InsufficientFunds` and
      restructured to have named fields.
    - `Error::Protobuf` has been removed; these decoding errors are now
      produced as data source and/or block-source implementation-specific
      errors.
    - `Error::InvalidChain` has been removed; its former purpose is now served
      by `chain::ChainError`.
    - `Error::InvalidNewWitnessAnchor` and `Error::InvalidWitnessAnchor` have
      been moved to `chain::error::ContinuityError`.
    - `Error::InvalidExtSk` (now unused) has been removed.
    - `Error::KeyNotFound` (now unused) has been removed.
    - `Error::KeyDerivationError` (now unused) has been removed.
    - `Error::SaplingNotActive` (now unused) has been removed.
- `zcash_client_backend::decrypt`:
  - `decrypt_transaction` now takes a `HashMap<_, UnifiedFullViewingKey>`
    instead of `HashMap<_, ExtendedFullViewingKey>`.
- If no memo is provided when sending to a shielded recipient, the
  empty memo will be used.
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
- `zcash_client_backend::welding_rig`:
  - The API of `ScanningKey` has changed to accommodate batch decryption and to
    correctly handle scanning with the internal (change) keys derived from ZIP
    316 UFVKs and UIVKs.
  - `scan_block` now uses batching for trial-decryption of transaction outputs.
- The return type of the following methods in `zcash_client_backend::encoding`
  have been changed to improve error reporting:
  - `decode_extended_spending_key`
  - `decode_extended_full_viewing_key`
  - `decode_payment_address`
- `zcash_client_backend::wallet::SpendableNote` is now parameterized by a note
  identifier type and has an additional `note_id` field that is used to hold the
  identifier used to refer to the note in the wallet database.

### Deprecated
- `zcash_client_backend::data_api::wallet::create_spend_to_address` has been
  deprecated. Use `zcash_client_backend::data_api::wallet::spend` instead. If
  you wish to continue using `create_spend_to_address`, note that the arguments
  to the function has been modified to take a unified spending key instead of a
  Sapling extended spending key, and now also requires a `min_confirmations`
  argument that the caller can provide to specify a minimum number of
  confirmations required for notes being selected. A minimum of 10
  confirmations is recommended.

### Removed
- `zcash_client_backend::data_api`:
  - `wallet::ANCHOR_OFFSET`
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
- `zcash_client_backend::wallet::AccountId` (moved to `zcash_primitives::zip32::AccountId`).
- `impl zcash_client_backend::welding_rig::ScanningKey for ExtendedFullViewingKey`
  (use `DiversifiableFullViewingKey` instead).

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
