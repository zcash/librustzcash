# Changelog
All notable changes to this library will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this library adheres to Rust's notion of
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- A new `orchard` feature flag has been added to make it possible to
  build client code without `orchard` dependendencies. Additions and
  changes related to `Orchard` below are introduced under this feature
  flag.
- `zcash_client_backend::data_api`:
  - `AccountBalance::with_orchard_balance_mut`
  - `BlockMetadata::orchard_tree_size`
  - `ScannedBlock::orchard`
  - `ScannedBlockCommitments::orchard`
- `zcash_client_backend::fees::orchard`
- `zcash_client_backend::fees::ChangeValue::orchard`
- `zcash_client_backend::wallet`:
  - `Note::Orchard`

### Changed
- `zcash_client_backend::data_api`:
  - Arguments to `BlockMetadata::from_parts` have changed.
  - Arguments to `ScannedBlock::from_parts` have changed.
  - Changes to the `WalletRead` trait:
    - Added `get_orchard_nullifiers`
  - `ShieldedProtocol` has a new `Orchard` variant.
- `zcash_client_backend::fees`:
  - Arguments to `ChangeStrategy::compute_balance` have changed.

## [0.11.0-pre-release] Unreleased

### Added
- `zcash_client_backend::PoolType::is_receiver`
- `zcash_client_backend::data_api`:
  - `InputSource`
  - `ScannedBlock::{into_commitments, sapling}`
  - `ScannedBundles`
  - `ScannedBlockCommitments`
  - `Balance::{add_spendable_value, add_pending_change_value, add_pending_spendable_value}`
  - `AccountBalance::{
      with_sapling_balance_mut,
      add_unshielded_value
    }`
  - `WalletSummary::next_sapling_subtree_index`
  - `wallet::propose_standard_transfer_to_address`
  - `wallet::create_proposed_transactions`
  - `wallet::input_selection::ShieldedInputs`
  - `wallet::input_selection::ShieldingSelector` has been
    factored out from the `InputSelector` trait to separate out transparent
    functionality and move it behind the `transparent-inputs` feature flag.
  - `impl std::error::Error for wallet::input_selection::InputSelectorError`
- `zcash_client_backend::fees::{standard, sapling}`
- `zcash_client_backend::fees::ChangeValue::new`
- `zcash_client_backend::wallet`:
  - `Note`
  - `ReceivedNote`
  - `WalletSaplingOutput::recipient_key_scope`
  - `TransparentAddressMetadata` (which replaces `zcash_keys::address::AddressMetadata`).
  - `impl {Debug, Clone} for OvkPolicy`
- `zcash_client_backend::zip321::TransactionRequest::total`
- `zcash_client_backend::zip321::parse::Param::name`
- `zcash_client_backend::proposal`:
  - `Proposal::{shielded_inputs, payment_pools, single_step, multi_step}`
  - `Step`
- `zcash_client_backend::proto`:
  - `PROPOSAL_SER_V1`
  - `ProposalDecodingError`
  - `proposal` module, for parsing and serializing transaction proposals.
- `impl Clone for zcash_client_backend::{
     zip321::{Payment, TransactionRequest, Zip321Error, parse::Param, parse::IndexedParam},
     wallet::{ReceivedSaplingNote, WalletTransparentOutput},
     proposal::{Proposal, SaplingInputs},
   }`
- `impl {PartialEq, Eq} for zcash_client_backend::{
     zip321::{Zip321Error, parse::Param, parse::IndexedParam},
     wallet::{ReceivedSaplingNote, WalletTransparentOutput},
     proposal::{Proposal, SaplingInputs},
   }`
- `zcash_client_backend::zip321`:
  - `TransactionRequest::{total, from_indexed}`
  - `parse::Param::name`

### Moved
- `zcash_client_backend::data_api::{PoolType, ShieldedProtocol}` have
  been moved into the `zcash_client_backend` root module.
- `zcash_client_backend::data_api::{NoteId, Recipient}` have
  been moved into the `zcash_client_backend::wallet` module.
- `ScannedBlock::{sapling_tree_size, sapling_nullifier_map, sapling_commitments}`
  have been moved to `ScannedBlockSapling` and in that context are now
  named `{tree_size, nullifier_map, commitments}` respectively.

### Changed
- `zcash_client_backend::data_api`:
  - `BlockMetadata::sapling_tree_size` now returns an `Option<u32>` instead of
    a `u32` for future consistency with Orchard.
  - `WalletShieldedOutput` has an additional type parameter which is used for
    key scope. `WalletShieldedOutput::from_parts` now takes an additional
    argument of this type.
  - `WalletTx` has an additional type parameter as a consequence of the
    `WalletShieldedOutput` change.
  - `ScannedBlock` has an additional type parameter as a consequence of the
    `WalletTx` change.
  - `ScannedBlock::metadata` has been renamed to `to_block_metadata` and now
    returns an owned value rather than a reference.
  - Fields of `Balance` and `AccountBalance` have been made private and the values
    of these fields have been made available via methods having the same names
    as the previously-public fields.
  - `WalletSummary::new` now takes an additional `next_sapling_subtree_index`
    argument.
  - `WalletWrite::get_next_available_address` now takes an additional
    `UnifiedAddressRequest` argument.
  - `chain::scan_cached_blocks` now returns a `ScanSummary` containing metadata
    about the scanned blocks on success.
  - `error::Error` enum changes:
    - The `NoteMismatch` variant now wraps a `NoteId` instead of a
      backend-specific note identifier. The related `NoteRef` type parameter has
      been removed from `error::Error`.
    - New variants have been added:
      - `Error::UnsupportedPoolType`
      - `Error::NoSupportedReceivers`
      - `Error::NoSpendingKey`
      - `Error::Proposal`
      - `Error::ProposalNotSupported`
    - Variant `ChildIndexOutOfRange` has been removed.
  - `wallet::shield_transparent_funds` no longer takes a `memo` argument;
    instead, memos to be associated with the shielded outputs should be
    specified in the construction of the value of the `input_selector`
    argument, which is used to construct the proposed shielded values as
    internal "change" outputs. Also, it returns its result as a `NonEmpty<TxId>`
    instead of a single `TxId`.
  - `wallet::create_proposed_transaction` has been replaced by
    `wallet::create_proposed_transactions`. Relative to the prior method,
    the new method has the following changes:
    - It no longer takes a `change_memo` argument; instead, change memos are
      represented in the individual values of the `proposed_change` field of
      the `Proposal`'s `TransactionBalance`.
    - `wallet::create_proposed_transactions` takes its `proposal` argument
      by reference instead of as an owned value.
    - `wallet::create_proposed_transactions` no longer takes a `min_confirmations`
      argument. Instead, it uses the anchor height from its `proposal` argument.
    - `wallet::create_proposed_transactions` forces implementations to ignore
      the database identifiers for its contained notes by universally quantifying
      the `NoteRef` type parameter.
    - It returns a `NonEmpty<TxId>` instead of a single `TxId` value.
  - `wallet::create_spend_to_address` now takes an additional `change_memo`
    argument. It also returns its result as a `NonEmpty<TxId>` instead of a
    single `TxId`.
  - `wallet::spend` returns its result as a `NonEmpty<TxId>` instead of a
    single `TxId`.
  - The error type of `wallet::create_spend_to_address` has been changed to use
    `zcash_primitives::transaction::fees::zip317::FeeError` instead of
    `zcash_primitives::transaction::components::amount::BalanceError`.
  - The following methods now take `&impl SpendProver, &impl OutputProver`
    instead of `impl TxProver`:
    - `wallet::create_proposed_transactions`
    - `wallet::create_spend_to_address`
    - `wallet::shield_transparent_funds`
    - `wallet::spend`
  - `wallet::input_selection::InputSelector::propose_shielding`,
    has been moved out to the newly-created `ShieldingSelector` trait.
    - `ShieldingSelector::propose_shielding` has been altered such that it takes
      an explicit `target_height` in order to minimize the capabilities that the
      `data_api::InputSource` trait must expose. Also, it now takes its
      `min_confirmations` argument as `u32` instead of `NonZeroU32`.
  - The `wallet::input_selection::InputSelector::DataSource`
    associated type has been renamed to `InputSource`.
  - `wallet::input_selection::InputSelectorError` has added variant `Proposal`
  - The signature of `wallet:input_selection::InputSelector::propose_transaction`
    has been altered such that it longer takes `min_confirmations` as an
    argument, instead taking explicit `target_height` and `anchor_height`
    arguments. This helps to minimize the set of capabilities that the
    `data_api::InputSource` must expose.
  - Changes to the `WalletRead` trait:
    - `get_checkpoint_depth` has been removed without replacement. This
      is no longer needed given the change to use the stored anchor height for
      transaction proposal execution.
    - `is_valid_account_extfvk` has been removed; it was unused in
      the ECC mobile wallet SDKs and has been superseded by `get_account_for_ufvk`.
    - `get_spendable_sapling_notes`, `select_spendable_sapling_notes`, and
      `get_unspent_transparent_outputs` have been removed; use
      `data_api::InputSource` instead.
    - Added `get_account_ids`.
    - `get_transparent_receivers` and `get_transparent_balances` are now
      guarded by the `transparent-inputs` feature flag, with noop default
      implementations provided.
    - `get_transparent_receivers` now returns
      `Option<zcash_client_backend::wallet::TransparentAddressMetadata>` as part of
      its result where previously it returned `zcash_keys::address::AddressMetadata`.
  - `wallet::{propose_shielding, shield_transparent_funds}` now takes their
    `min_confirmations` arguments as `u32` rather than a `NonZeroU32` to permit
    implmentations to enable zero-conf shielding.
  - `wallet::input_selection::GreedyInputSelector` now has relaxed requirements
    for its `InputSource` associated type.

- `zcash_client_backend::proposal`:
  - Arguments to `Proposal::from_parts` have changed.
  - `Proposal::min_anchor_height` has been removed in favor of storing this
    value in `SaplingInputs`.
  - `Proposal::sapling_inputs` has been replaced by `Proposal::shielded_inputs`
  - In addition to having been moved to the `zcash_client_backend::proposal`
    module, the `Proposal` type has been substantially modified in order to make
    it possible to represent multi-step transactions, such as a deshielding
    transaction followed by a zero-conf transfer as required by ZIP 320. Individual
    transaction proposals are now represented by the `proposal::Step` type.
  - `ProposalError` has new variants:
    - `ReferenceError`
    - `StepDoubleSpend`
    - `ChainDoubleSpend`
    - `PaymentPoolsMismatch`

- `zcash_client_backend::fees`:
  - `ChangeStrategy::compute_balance` arguments have changed.
  - `ChangeValue` is now a struct. In addition to the existing change value, it
    now also provides the output pool to which change should be sent and an
    optional memo to be associated with the change output.
  - `ChangeError` has a new `BundleError` variant.
  - `fixed::SingleOutputChangeStrategy::new` and
    `zip317::SingleOutputChangeStrategy::new` each now accept an additional
    `change_memo` argument.
- `zcash_client_backend::wallet`:
  - The fields of `ReceivedSaplingNote` are now private. Use
    `ReceivedSaplingNote::from_parts` for construction instead. Accessor methods
    are provided for each previously public field.
- `zcash_client_backend::scanning::ScanError` has a new variant, `TreeSizeInvalid`.
- `zcash_client_backend::zip321::TransactionRequest::payments` now returns a
  `BTreeMap<usize, Payment>` instead of `&[Payment]` so that parameter
  indices may be preserved.
- `zcash_client_backend::zip321::to_uri` now returns a `String` rather than an
  `Option<String>` and provides canonical serialization for the empty proposal.
- `zcash_client_backend::zip321::from_uri` previously stripped payment indices,
  meaning that round-trip serialization was not supported. Payment indices are
  now retained.
- The following fields now have type `NonNegativeAmount` instead of `Amount`:
  - `zcash_client_backend::data_api`:
    - `error::Error::InsufficientFunds.{available, required}`
    - `wallet::input_selection::InputSelectorError::InsufficientFunds.{available, required}`
  - `zcash_client_backend::fees`:
    - `ChangeError::InsufficientFunds.{available, required}`
  - `zcash_client_backend::zip321::Payment.amount`
- The following methods now take `NonNegativeAmount` instead of `Amount`:
  - `zcash_client_backend::data_api`:
    - `SentTransactionOutput::from_parts`
    - `wallet::create_spend_to_address`
    - `wallet::input_selection::InputSelector::propose_shielding`
  - `zcash_client_backend::fees`:
    - `ChangeValue::sapling`
    - `DustOutputPolicy::new`
    - `TransactionBalance::new`
  - `zcash_client_backend::wallet::ReceivedSaplingNote::from_parts`
- The following methods now return `NonNegativeAmount` instead of `Amount`:
  - `zcash_client_backend::data_api::SentTransactionOutput::value`
  - `zcash_client_backend::fees`:
    - `ChangeValue::value`
    - `DustOutputPolicy::dust_threshold`
    - `TransactionBalance::{fee_required, total}`
  - `zcash_client_backend::wallet`:
    - `ReceivedSaplingNote::value`
    - `WalletTransparentOutput::value`

### Removed
- `zcash_client_backend::wallet::ReceivedSaplingNote` has been replaced by
  `zcash_client_backend::ReceivedNote`.
- `zcash_client_backend::::wallet::input_selection::{Proposal, ShieldedInputs, ProposalError}`
  have been moved to `zcash_client_backend::proposal`.
- `zcash_client_backend::data_api`
- `zcash_client_backend::data_api::ScannedBlock::from_parts` has been made crate-private.
- `zcash_client_backend::data_api::ScannedBlock::into_sapling_commitments` has been
  replaced by `into_commitments` which returns a `ScannedBlockCommitments` value.
- `zcash_client_backend::data_api::wallet::create_proposed_transaction`

## [0.10.0] - 2023-09-25

### Notable Changes
- `zcash_client_backend` now supports out-of-order scanning of blockchain history.
  See the module documentation for `zcash_client_backend::data_api::chain`
  for details on how to make use of the new scanning capabilities.
- This release of `zcash_client_backend` defines the concept of an account
  birthday. The account birthday is defined as the minimum height among blocks
  to be scanned when recovering an account.
- Account creation now requires the caller to provide account birthday information,
  including the state of the note commitment tree at the end of the block prior
  to the birthday height. A wallet's birthday is the earliest birthday height
  among accounts maintained by the wallet.

### Added
- `impl Eq for zcash_client_backend::address::RecipientAddress`
- `impl Eq for zcash_client_backend::zip321::{Payment, TransactionRequest}`
- `impl Debug` for `zcash_client_backend::{data_api::wallet::input_selection::Proposal, wallet::ReceivedSaplingNote}`
- `zcash_client_backend::data_api`:
  - `AccountBalance`
  - `AccountBirthday`
  - `Balance`
  - `BirthdayError`
  - `BlockMetadata`
  - `NoteId`
  - `NullifierQuery` for use with `WalletRead::get_sapling_nullifiers`
  - `Ratio`
  - `ScannedBlock`
  - `ShieldedProtocol`
  - `WalletCommitmentTrees`
  - `WalletSummary`
  - `WalletRead::{
       chain_height, block_metadata, block_max_scanned, block_fully_scanned,
       suggest_scan_ranges, get_wallet_birthday, get_account_birthday, get_wallet_summary
     }`
  - `WalletWrite::{put_blocks, update_chain_tip}`
  - `chain::CommitmentTreeRoot`
  - `scanning` A new module containing types required for `suggest_scan_ranges`
  - `testing::MockWalletDb::new`
  - `wallet::input_sellection::Proposal::{min_target_height, min_anchor_height}`
  - `SAPLING_SHARD_HEIGHT` constant
- `zcash_client_backend::proto::compact_formats`:
  - `impl<A: sapling::Authorization> From<&sapling::SpendDescription<A>> for CompactSaplingSpend`
  - `impl<A: sapling::Authorization> From<&sapling::OutputDescription<A>> for CompactSaplingOutput`
  - `impl<SpendAuth> From<&orchard::Action<SpendAuth>> for CompactOrchardAction`
- `zcash_client_backend::wallet::WalletSaplingOutput::note_commitment_tree_position`
- `zcash_client_backend::scanning`:
  - `ScanError`
  - `impl<K: ScanningKey> ScanningKey for &K`
  - `impl ScanningKey for (zip32::Scope, sapling::SaplingIvk, sapling::NullifierDerivingKey)`
- Test utility functions `zcash_client_backend::keys::UnifiedSpendingKey::{default_address,
  default_transparent_address}` are now available under the `test-dependencies` feature flag.

### Changed
- MSRV is now 1.65.0.
- Bumped dependencies to `hdwallet 0.4`, `zcash_primitives 0.13`, `zcash_note_encryption 0.4`,
  `incrementalmerkletree 0.5`, `orchard 0.6`, `bs58 0.5`, `tempfile 3.5.0`, `prost 0.12`,
  `tonic 0.10`.
- `zcash_client_backend::data_api`:
  - `WalletRead::TxRef` has been removed in favor of consistently using `TxId` instead.
  - `WalletRead::get_transaction` now takes a `TxId` as its argument.
  - `WalletRead::create_account` now takes an additional `birthday` argument.
  - `WalletWrite::{store_decrypted_tx, store_sent_tx}` now return `Result<(), Self::Error>`
    as the `WalletRead::TxRef` associated type has been removed. Use
    `WalletRead::get_transaction` with the transaction's `TxId` instead.
  - `WalletRead::get_memo` now takes a `NoteId` as its argument instead of `Self::NoteRef`
    and returns `Result<Option<Memo>, Self::Error>` instead of `Result<Memo,
    Self::Error>` in order to make representable wallet states where the full
    note plaintext is not available.
  - `WalletRead::get_nullifiers` has been renamed to `WalletRead::get_sapling_nullifiers`
    and its signature has changed; it now subsumes the removed `WalletRead::get_all_nullifiers`.
  - `WalletRead::get_target_and_anchor_heights` now takes its argument as a `NonZeroU32`
  - `chain::scan_cached_blocks` now takes a `from_height` argument that
    permits the caller to control the starting position of the scan range.
    In addition, the `limit` parameter is now required and has type `usize`.
  - `chain::BlockSource::with_blocks` now takes its limit as an `Option<usize>`
    instead of `Option<u32>`. It is also now required to return an error if
    `from_height` is set to a block that does not exist in `self`.
  - A new `CommitmentTree` variant has been added to `data_api::error::Error`
  - `wallet::{create_spend_to_address, create_proposed_transaction,
    shield_transparent_funds}` all now require that `WalletCommitmentTrees` be
    implemented for the type passed to them for the `wallet_db` parameter.
  - `wallet::create_proposed_transaction` now takes an additional
    `min_confirmations` argument.
  - `wallet::{spend, create_spend_to_address, shield_transparent_funds,
    propose_transfer, propose_shielding, create_proposed_transaction}` now take their
    respective `min_confirmations` arguments as `NonZeroU32`
  - A new `Scan` variant replaces the `Chain` variant of `data_api::chain::error::Error`.
    The `NoteRef` parameter to `data_api::chain::error::Error` has been removed
    in favor of using `NoteId` to report the specific note for which a failure occurred.
  - A new `SyncRequired` variant has been added to `data_api::wallet::input_selection::InputSelectorError`.
  - The variants of the `PoolType` enum have changed; the `PoolType::Sapling` variant has been
    removed in favor of a `PoolType::Shielded` variant that wraps a `ShieldedProtocol` value.
- `zcash_client_backend::wallet`:
  - `SpendableNote` has been renamed to `ReceivedSaplingNote`.
  - Arguments to `WalletSaplingOutput::from_parts` have changed.
- `zcash_client_backend::data_api::wallet::input_selection::InputSelector`:
  - Arguments to `{propose_transaction, propose_shielding}` have changed.
  - `InputSelector::{propose_transaction, propose_shielding}`
    now take their respective `min_confirmations` arguments as `NonZeroU32`
- `zcash_client_backend::data_api::wallet::{create_spend_to_address, spend,
  create_proposed_transaction, shield_transparent_funds}` now return the `TxId`
  for the newly created transaction instead an internal database identifier.
- `zcash_client_backend::wallet::ReceivedSaplingNote::note_commitment_tree_position`
  has replaced the `witness` field in the same struct.
- `zcash_client_backend::welding_rig` has been renamed to `zcash_client_backend::scanning`
- `zcash_client_backend::scanning::ScanningKey::sapling_nf` has been changed to
  take a note position instead of an incremental witness for the note.
- Arguments to `zcash_client_backend::scanning::scan_block` have changed. This
  method now takes an optional `BlockMetadata` argument instead of a base commitment
  tree and incremental witnesses for each previously-known note. In addition, the
  return type has now been updated to return a `Result<ScannedBlock, ScanError>`.
- `zcash_client_backend::proto::service`:
  - The module is no longer behind the `lightwalletd-tonic` feature flag; that
    now only gates the `service::compact_tx_streamer_client` submodule. This
    exposes the service types to parse messages received by other gRPC clients.
  - The module has been updated to include the new gRPC endpoints supported by
    `lightwalletd` v0.4.15.

### Removed
- `zcash_client_backend::data_api`:
  - `WalletRead::block_height_extrema` has been removed. Use `chain_height`
    instead to obtain the wallet's view of the chain tip instead, or
    `suggest_scan_ranges` to obtain information about blocks that need to be
    scanned.
  - `WalletRead::get_balance_at` has been removed. Use `WalletRead::get_wallet_summary`
    instead.
  - `WalletRead::{get_all_nullifiers, get_commitment_tree, get_witnesses}` have
    been removed without replacement. The utility of these methods is now
    subsumed by those available from the `WalletCommitmentTrees` trait.
  - `WalletWrite::advance_by_block` (use `WalletWrite::put_blocks` instead).
  - `PrunedBlock` has been replaced by `ScannedBlock`
  - `testing::MockWalletDb`, which is available under the `test-dependencies`
    feature flag, has been modified by the addition of a `sapling_tree` property.
  - `wallet::input_selection`:
    - `Proposal::target_height` (use `Proposal::min_target_height` instead).
- `zcash_client_backend::data_api::chain::validate_chain` (logic merged into
  `chain::scan_cached_blocks`.
- `zcash_client_backend::data_api::chain::error::{ChainError, Cause}` have been
  replaced by `zcash_client_backend::scanning::ScanError`
- `zcash_client_backend::proto::compact_formats`:
  - `impl<A> From<sapling::OutputDescription<A>> for CompactSaplingOutput`
    (use `From<&sapling::OutputDescription<A>>` instead).
- `zcash_client_backend::wallet::WalletSaplingOutput::{witness, witness_mut}`
  have been removed as individual incremental witnesses are no longer tracked on a
  per-note basis. The global note commitment tree for the wallet should be used
  to obtain witnesses for spend operations instead.
- Default implementations of `zcash_client_backend::data_api::WalletRead::{
    get_target_and_anchor_heights, get_max_height_hash
  }` have been removed. These should be implemented in a backend-specific fashion.


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
