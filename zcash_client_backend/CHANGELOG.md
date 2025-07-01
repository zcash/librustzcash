# Changelog
All notable changes to this library will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this library adheres to Rust's notion of
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Future releases are
indicated by the `PLANNED` status in order to make it possible to correctly
represent the transitive `semver` implications of changes within the enclosing
workspace.

## [Unreleased]
### Added
- `zcash_client_backend::fees`:
  - `sapling::OutputView`: trait implemented of `Zatoshis`
  - `orchard::OutputView`: trait implemented of `Zatoshis`
- `zcash_client_backend::data_api::wallet`:
  - `SpendableNotes::total`: returns the sum of all spendable notes in `Zatoshis`
  - `propose_send_max_transfer`: Selects transaction inputs, computes fees, and 
    constructs a proposal for a transaction (or series of them) that would spend all
    the available funds from the given spend pools.
  - `input_selection::propose_send_max`: Performs input selection and returns 
    a proposal for the construction of a transaction that sends the maximum 
    amount possible from a given account to the specified recipient ignoring
    notes that are below MARGINAL_FEE amount.
  - `zcash_client_sqlite::error::SqliteClientError`:
    - `IneligibleNotes`: used `spendable_notes` is called with `TargetValue::MaxSpensable` 
      and there are funds that haven't been confirmed and all spendable notes can't
      be selected.
- `zcash_client_backend::tor`:
  - `Client::set_dormant`
  - `DormantMode`

### Changed
- `zcash_client_backend::data_api`:
  - `select_spendable_notes`: parameter `target_value` now is a `TargetValue`. 
    Existing calls to this function that used `Zatoshis` now use 
    `TargetValue::AtLeast(Zatoshis)`
  - `select_spendable_notes`: parameter `target_value` now is a `TargetValue`. 
    Existing calls to this function that used `Zatoshis` now use `TargetValue::MinValue(Zatoshis)`
  - `zcash_client_backend::fees::ChangeStrategy`: Associated error type of this trait 
    has to be of `FeeRule` kind as well. 
  - `zcash_client_backend::proposal::ProposalError`:
    - `SendsMemoToTransparentRecipient`: signals an attempt to send a memo to a 
      transparent recipient
    - `ResultingPaymentInvalid(Zip321Error)`: details the ZIP-321 error that the
      proposal resulting causes.
## [0.19.0] - 2025-05-30

### Added
- `zcash_client_backend::data_api`:
  - `TargetValue`: An intent of representing spendable value to reach a certain
    targeted amount.
- `zcash_client_backend::proto::service`:
  - `LightdInfo.donation_address` field.
  - Helper methods for parsing `LightdInfo` fields:
    - `LightdInfo::chain_name`
    - `LightdInfo::sapling_activation_height`
    - `LightdInfo::consensus_branch_id`
    - `LightdInfo::block_height`
    - `LightdInfo::estimated_height`
    - `LightdInfo::donation_address`
- `zcash_client_backend::tor`:
  - `http::Retry`
  - `Client::http_get`
  - `Client::http_get_json`
  - `Client::http_post`
  - `Client::set_dormant`
  - `DormantMode`

### Changed
- Migrated to `arti-client 0.28`, `dynosaur 0.2`, `tonic 0.13`, `zcash_address 0.8`,
  `zip321 0.4`, `zcash_transparent 0.3`, `zcash_primitives 0.23`,
  `zcash_proofs 0.23`, `zcash_keys 0.9`, `pczt 0.3`
- `zcash_client_backend::data_api`:
  - `select_spendable_notes`: parameter `target_value` now is a `TargetValue`.
    Existing calls to this function that used `Zatoshis` now use
    `TargetValue::AtLeast(Zatoshis)`
- Migrated to `arti-client 0.28`, `dynosaur 0.2`, `tonic 0.13`.
- `zcash_client_backend::tor`:
  - `Client::{connect_to_lightwalletd, get_latest_zec_to_usd_rate}` now ensure
    that the inner Tor client is ready for traffic, and re-bootstrap it if
    necessary.
  - The exchanges in `http::cryptex::exchanges` will now retry queries once on
    failure, and will use isolated circuits for the retry if the error looks
    like a blocked Tor exit node.

## [0.18.0] - 2025-03-19

### Added
- `zcash_client_backend::data_api`:
  - `AddressInfo`
- `zcash_client_backend::data_api::testing`:
  - `struct transparent::GapLimits`
  - `transparent::gap_limits` high-level test for gap limit handling
- `zcash_client_backend::data_api::{TransactionStatusFilter, OutputStatusFilter}`

### Changed
- Updated to `zcash_keys 0.8`
- `zcash_client_backend::data_api::WalletRead`:
  - `get_transparent_receivers` now takes additional `include_change` and
    `include_ephemeral` arguments.
  - `get_known_ephemeral_addresses` now takes a
    `Range<zcash_transparent::keys::NonHardenedChildIndex>` as its argument
    instead of a `Range<u32>`
  - Has added method `utxo_query_height` when the `transparent-inputs` feature
    flag is active.
  - has removed method `get_current_address`. It has been replaced by
    added method `WalletRead::get_last_generated_address_matching`
  - Has added method `list_addresses`.
- `zcash_client_backend::data_api::WalletWrite`:
  - has added method `get_address_for_index`. Please note the WARNINGS section
    in the documentation for use of this method.
  - `get_next_available_address` now returns the diversifier index at which the
    address was generated in addition to the address. In addition, the
    `UnifiedAddressRequest` argument is now non-optional; use
    `UnifiedAddressRequest::AllAvailableKeys` to indicate that all available
    keys should be used to generate receivers instead of `None`.
  - Arguments to `get_address_for_index` have changed: the
    `UnifiedAddressRequest` argument is now non-optional; use
    `UnifiedAddressRequest::AllAvailableKeys` to indicate that all available
    keys should be used to generate receivers instead of `None`.
  - `TransactionDataRequest::SpendsFromAddress` has been renamed to
    `TransactionDataRequest::TransactionsInvolvingAddress` and has added struct
    fields `request_at`, `tx_status_filter`, and `output_status_filter`.
- Arguments to `zcash_client_backend::decrypt::decrypt_transaction` have changed.
  It now takes separate `mined_height` and `chain_tip_height` parameters; this
  fixes https://github.com/zcash/librustzcash/issues/1746 as described in the
  `Fixed` section below.

### Removed
- `zcash_client_backend::data_api::GAP_LIMIT` gap limits are now configured
  based upon the key scope that they're associated with; there is no longer a
  globally applicable gap limit.

### Fixed
- This release fixes https://github.com/zcash/librustzcash/issues/1746, which
  made it possible for `zcash_client_backend::decrypt_and_store_transaction`
  to incorrectly set a `mined_height` value for a mempool transaction.

## [0.17.0] - 2025-02-21

### Added
- `zcash_client_backend::data_api::testing::TransactionSummary` has added
  accessor methods `total_spent` and `total_received`.

### Changed
- MSRV is now 1.81.0.
- Migrated to `bip32 =0.6.0-pre.1`, `nonempty 0.11`, `incrementalmerkletree 0.8`,
  `shardtree 0.6`, `orchard 0.11`, `pczt 0.2`, `sapling-crypto 0.5`, `zcash_encoding 0.3`,
  `zcash_protocol 0.5`, `zcash_address 0.7`, `zip321 0.3`, `zcash_transparent 0.2`,
  `zcash_primitives 0.22`, `zcash_proofs 0.22`, `zcash_keys 0.7`.
- `zcash_client_backend::tor`:
  - `tor::Client::create` now takes a `with_permissions` argument for configuring
    `fs_mistrust::Mistrust`. If you don't need to configure it, pass `|_| ()`
    (the empty closure).
- `zcash_client_backend::wallet::Recipient` has changed:
  - The `Recipient::External` variant is now a structured variant.
  - The `Recipient::EphemeralTransparent` variant is now only available if
    `zcash_client_backend` is built using the `transparent-inputs` feature flag.
  - The `N` and `O` type pararameters to this type have been replaced by
    concrete uses of `Box<Note>` and `Outpoint` instead. The
    `map_internal_account_note` and `map_ephemeral_transparent_outpoint` and
    `internal_account_note_transpose_option` methods have consequently been
    removed.
- `zcash_client_backend::data_api::testing::TransactionSummary::from_parts`
  has been modified; it now requires additional `total_spent` and `total_received`
  arguments.

### Deprecated
- `zcash_client_backend::address` (use `zcash_keys::address` instead)
- `zcash_client_backend::encoding` (use `zcash_keys::encoding` instead)
- `zcash_client_backend::keys` (use `zcash_keys::keys` instead)
- `zcash_client_backend::zip321` (use the `zip321` crate instead)
- `zcash_client_backend::PoolType` (use `zcash_protocol::PoolType` instead)
- `zcash_client_backend::ShieldedProtocol` (use `zcash_protocol::ShieldedProtocol` instead)

## [0.16.0] - 2024-12-16

### Added
- `zcash_client_backend::data_api`
  - `AccountSource::key_derivation`
  - `error::PcztError`
  - `wallet::ExtractErrT`
  - `wallet::create_pczt_from_proposal`
  - `wallet::extract_and_store_transaction_from_pczt`

### Changed
- Migrated to `sapling-crypto 0.4`, `zcash_keys 0.6`, `zcash_primitives 0.21`,
  `zcash_proofs 0.21`.
- `zcash_client_backend::data_api::AccountBalance`: Refactored to use `Balance`
  for transparent funds (issue #1411). It now has an `unshielded_balance()`
  method that returns `Balance`, allowing the unshielded spendable, unshielded
  pending change, and unshielded pending non-change values to be tracked
  separately.
- `zcash_client_backend::data_api::WalletRead`:
  - The `create_account`, `import_account_hd`, and `import_account_ufvk`
    methods now each take additional `account_name` and `key_source` arguments.
    These allow the wallet backend to store additional metadata that is useful
    to applications managing these accounts.
- `zcash_client_backend::data_api::AccountSource`:
  - Both `Derived` and `Imported` alternatives of `AccountSource` now have an
    additional `key_source` field that is used to convey application-specific
    key source metadata.
  - The `Copy` impl for this type has been removed.
  - The `request` argument to `WalletRead::get_next_available_address` is now optional.
- `zcash_client_backend::data_api::Account` has an additional `name` method
  that returns the human-readable name of the account, if any.
- `zcash_client_backend::data_api::error::Error` has new variants:
    - `AccountIdNotRecognized`
    - `AccountCannotSpend`
    - `Pczt`

### Deprecated
- `AccountBalance::unshielded`. Instead use `unshielded_balance` which
  provides a `Balance` value. Its `total()` method can be used to obtain the
  total of transparent funds.

### Removed
- `zcash_client_backend::AccountBalance::add_unshielded_value`. Instead use
  `AccountBalance::with_unshielded_balance_mut` with a closure that calls
  the appropriate `add_*_value` method(s) of `Balance` on its argument.
  Note that the appropriate method(s) depend on whether the funds are
  spendable, pending change, or pending non-change (previously, only the
  total unshielded value was tracked).

## [0.15.0] - 2024-11-14

### Added
- `zcash_client_backend::data_api`:
  - `Progress`
  - `WalletSummary::progress`
  - `PoolMeta`
  - `AccountMeta`
  - `impl Default for wallet::input_selection::GreedyInputSelector`
  - `BoundedU8`
  - `NoteFilter`
- `zcash_client_backend::fees`
  - `SplitPolicy`
  - `StandardFeeRule` has been moved here from `zcash_primitives::fees`. Relative
    to that type, the deprecated `PreZip313` and `Zip313` variants have been
    removed.
  - `zip317::{MultiOutputChangeStrategy, Zip317FeeRule}`
  - `standard::MultiOutputChangeStrategy`
- A new feature flag, `non-standard-fees`, has been added. This flag is now
  required in order to make use of any types or methods that enable non-standard
  fee calculation.
- `zcash_client_backend::tor::http::cryptex`:
  - `LocalExchange`, a variant of the `Exchange` trait without `Send` bounds.
  - `DynExchange`
  - `DynLocalExchange`

### Changed
- MSRV is now 1.77.0.
- Migrated to `zcash_primitives 0.20.0`, `zcash_keys 0.5.0`.
- Migrated to `arti-client 0.23`.
- `zcash_client_backend::data_api`:
  - `InputSource` has an added method `get_account_metadata`
  - `error::Error` has additional variant `Error::Change`. This necessitates
    the addition of two type parameters to the `Error` type,
    `ChangeErrT` and `NoteRefT`.
  - The following methods each now take an additional `change_strategy`
    argument, along with an associated `ChangeT` type parameter:
    - `wallet::spend`
    - `wallet::propose_transfer`
    - `wallet::propose_shielding`. This method also now takes an additional
      `to_account` argument.
    - `wallet::shield_transparent_funds`. This method also now takes an
      additional `to_account` argument.
  - `wallet::input_selection::InputSelectionError` now has an additional `Change`
    variant. This necessitates the addition of two type parameters.
  - `wallet::input_selection::InputSelector::propose_transaction` takes an
    additional `change_strategy` argument, along with an associated `ChangeT`
    type parameter.
  - The `wallet::input_selection::InputSelector::FeeRule` associated type has
    been removed. The fee rule is now part of the change strategy passed to
    `propose_transaction`.
  - `wallet::input_selection::ShieldingSelector::propose_shielding` takes an
    additional `change_strategy` argument, along with an associated `ChangeT`
    type parameter. In addition, it also takes a new `to_account` argument
    that identifies the destination account for the shielded notes.
  - The `wallet::input_selection::ShieldingSelector::FeeRule` associated type
    has been removed. The fee rule is now part of the change strategy passed to
    `propose_shielding`.
  - The `Change` variant of `wallet::input_selection::GreedyInputSelectorError`
    has been removed, along with the additional type parameters it necessitated.
  - The arguments to `wallet::input_selection::GreedyInputSelector::new` have
    changed.
- `zcash_client_backend::fees`:
  - `ChangeStrategy` has changed. It has two new associated types, `MetaSource`
    and `AccountMetaT`, and its `FeeRule` associated type now has an additional
    `Clone` bound. In addition, it defines a new `fetch_wallet_meta` method, and
    the arguments to `compute_balance` have changed.
  - `zip317::SingleOutputChangeStrategy` has been made polymorphic in the fee
    rule type, and takes an additional type parameter as a consequence.
  - The following methods now take an additional `DustOutputPolicy` argument,
    and carry an additional type parameter:
    - `fixed::SingleOutputChangeStrategy::new`
    - `standard::SingleOutputChangeStrategy::new`
    - `zip317::SingleOutputChangeStrategy::new`
- `zcash_client_backend::proto::ProposalDecodingError` has modified variants.
  `ProposalDecodingError::FeeRuleNotSpecified` has been removed, and
  `ProposalDecodingError::FeeRuleNotSupported` has been added to replace it.
- `zcash_client_backend::data_api::fees::fixed` is now available only via the
  use of the `non-standard-fees` feature flag.
- `zcash_client_backend::tor::http::cryptex`:
  - The `Exchange` trait is no longer object-safe. Replace any existing uses of
    `dyn Exchange` with `DynExchange`.

### Removed
- `zcash_client_backend::data_api`:
  - `WalletSummary::scan_progress` and `WalletSummary::recovery_progress` have
    been removed. Use `WalletSummary::progress` instead.
  - `testing::input_selector` use explicit `InputSelector` constructors
    directly instead.
  - The deprecated `wallet::create_spend_to_address` and `wallet::spend`
    methods have been removed. Use `propose_transfer` and
    `create_proposed_transaction` instead.
- `zcash_client_backend::fees`:
  - `impl From<BalanceError> for ChangeError<...>`

## [0.14.0] - 2024-10-04

### Added
- `zcash_client_backend::data_api`:
  - `GAP_LIMIT`
  - `WalletSummary::recovery_progress`
  - `SpendableNotes::{take_sapling, take_orchard}`
  - Tests and testing infrastructure have been migrated from the
    `zcash_client_sqlite` internal tests to the `testing` module, and have been
    generalized so that they may be used for testing arbitrary implementations
    of the `zcash_client_backend::data_api` interfaces. The following have been
    added under the `test-dependencies` feature flag as part of this migration:
    - `WalletTest`
    - `testing::AddressType`
    - `testing::CachedBlock`
    - `testing::DataStoreFactory`
    - `testing::FakeCompactOutput`
    - `testing::InitialChainState`
    - `testing::NoteCommitments`
    - `testing::Reset`
    - `testing::TestAccount`
    - `testing::TestBuilder`
    - `testing::TestCache`
    - `testing::TestFvk`
    - `testing::TestState`
    - `testing::TransactionSummary`
    - `testing::input_selector`
    - `testing::orchard`
    - `testing::pool`
    - `testing::sapling`

### Changed
- Migrated to `orchard 0.10`, `sapling-crypto 0.3`, `shardtree 0.5`,
  `zcash_address 0.6`, `zcash_primitives 0.19`, `zcash_proofs 0.19`,
  `zcash_protocol 0.4`.
- The `Account` trait now uses an associated type for its `AccountId`
  type instead of a type parameter. This change allows for the simplification
  of some type signatures.
- `zcash_client_backend::data_api`:
  - `WalletSummary::scan_progress` now only reports progress for scanning blocks
    "near" the chain tip. Progress for scanning earlier blocks is now reported
    via `WalletSummary::recovery_progress`.
  - `WalletRead::get_min_unspent_height` has been removed. This was added to make
    it possible to obtain a "safe truncation" height in order to facilitate rewinds
    to a greater depth than the available note commitment tree checkpoints provide,
    but such rewinds are no longer supported.
- `zcash_client_backend::sync::run`:
  - Transparent outputs are now refreshed in addition to shielded notes.
- `zcash_client_backend::proposal::ProposalError` has a new `AnchorNotFound`
  variant.

### Fixed
- `zcash_client_backend::tor::grpc` now needs the `lightwalletd-tonic-tls-webpki-roots`
  feature flag instead of `lightwalletd-tonic`, to fix compilation issues.

## [0.13.0] - 2024-08-20

`zcash_client_backend` now supports TEX (transparent-source-only) addresses as specified
in ZIP 320. Sending to one or more TEX addresses will automatically create a multi-step
proposal that uses two transactions.

In order to take advantage of this support, client wallets will need to be able to send
multiple transactions created from `zcash_client_backend::data_api::wallet::create_proposed_transactions`.
This API was added in `zcash_client_backend` 0.11.0 but previously could only return a
single transaction.

**Note:** This feature changes the use of transparent addresses in ways that are relevant
to security and access to funds, and that may interact with other wallet behaviour. In
particular it exposes new ephemeral transparent addresses belonging to the wallet, which
need to be scanned in order to recover funds if the first transaction of the proposal is
mined but the second is not, or if someone (e.g. the TEX-address recipient) sends back
funds to those addresses. See [ZIP 320](https://zips.z.cash/zip-0320) for details.

### Added
- `zcash_client_backend::data_api`:
  - `chain::BlockCache` trait, behind the `sync` feature flag.
  - `WalletRead::get_spendable_transparent_outputs`
  - `DecryptedTransaction::mined_height`
  - `TransactionDataRequest`
  - `TransactionStatus`
  - `AccountType`
- `zcash_client_backend::fees`:
  - `EphemeralBalance`
  - `ChangeValue::shielded, is_ephemeral`
  - `ChangeValue::ephemeral_transparent` (when "transparent-inputs" is enabled)
  - `sapling::EmptyBundleView`
  - `orchard::EmptyBundleView`
- `zcash_client_backend::proposal`:
  - `impl Hash for {StepOutput, StepOutputIndex}`
- `zcash_client_backend::scanning`:
  - `testing` module
- `zcash_client_backend::sync` module, behind the `sync` feature flag.
- `zcash_client_backend::tor` module, behind the `tor` feature flag.
- `zcash_client_backend::wallet`:
    - `Recipient::map_ephemeral_transparent_outpoint`
    - `WalletTransparentOutput::mined_height`

### Changed
- MSRV is now 1.70.0.
- Updated dependencies:
  - `zcash_address 0.4`
  - `zcash_encoding 0.2.1`
  - `zcash_keys 0.3`
  - `zcash_primitives 0.16`
  - `zcash_protocol 0.2`
  - `zip321 0.1`
- Migrated to `tonic 0.12`.
  - The `lightwalletd-tonic` feature flag no longer works on `wasm32-wasi` due
    to https://github.com/hyperium/tonic/issues/1783.
- `zcash_client_backend::{fixed,standard,zip317}::SingleOutputChangeStrategy`
  now implement a different strategy for choosing whether there will be any
  change, and its value. This can avoid leaking information about note amounts
  in some cases. It also ensures that there will be a change output whenever a
  `change_memo` is given, and defends against losing money by using
  `DustAction::AddDustToFee` with a too-high dust threshold.
  See [#1430](https://github.com/zcash/librustzcash/pull/1430) for details.
- `zcash_client_backend::zip321` has been extracted to, and is now a reexport
  of the root module of the `zip321` crate. Several of the APIs of this module
  have changed as a consequence of this extraction; please see the `zip321`
  CHANGELOG for details.
- `zcash_client_backend::data_api`:
  - `WalletRead` has a new `transaction_data_requests` method.
  - `WalletRead` has new `get_known_ephemeral_addresses`,
    `find_account_for_ephemeral_address`, and `get_transparent_address_metadata`
    methods when the "transparent-inputs" feature is enabled.
  - `WalletWrite` has a new `reserve_next_n_ephemeral_addresses` method when
    the "transparent-inputs" feature is enabled.
  - `WalletWrite` has new methods `import_account_hd`, `import_account_ufvk`,
    and `set_transaction_status`.
  - `error::Error` has new `Address` and (when the "transparent-inputs" feature
    is enabled) `PaysEphemeralTransparentAddress` variants.
  - The `WalletWrite::store_sent_tx` method has been renamed to
    `store_transactions_to_be_sent`, and its signature changed to take a slice
    of `SentTransaction`s. This can be used by the wallet storage backend (e.g.
    `zcash_client_sqlite`) to improve transactionality of writes for multi-step
    proposals.
  - `wallet::input_selection::InputSelectorError` has a new `Address` variant.
  - `wallet::decrypt_and_store_transaction` now takes an additional optional
    `mined_height` argument that can be used to provide the mined height
    returned by the light wallet server in a `RawTransaction` value directly to
    the back end.
  - `DecryptedTransaction::new` takes an additional `mined_height` argument.
  - `SentTransaction` now stores its `outputs` and `utxos_spent` fields as
    references to slices, with a corresponding change to `SentTransaction::new`.
  - `SentTransaction` takes an additional `target_height` argument, which is used
    to record the target height used in transaction generation.
  - `AccountSource::Imported` is now a struct variant with a `purpose` field.
  - The `Account` trait now defines a new `purpose` method with a default
    implementation (which need not be overridden.)
- `zcash_client_backend::data_api::fees`
  - When the "transparent-inputs" feature is enabled, `ChangeValue` can also
    represent an ephemeral transparent output in a proposal. Accordingly, the
    return type of `ChangeValue::output_pool` has (unconditionally) changed
    from `ShieldedProtocol` to `zcash_protocol::PoolType`.
  - `ChangeStrategy::compute_balance`: this trait method has an additional
    `Option<&EphemeralBalance>` parameter. If the "transparent-inputs" feature is
    enabled, this can be used to specify whether the change memo should be
    ignored, and the amounts of additional transparent P2PKH inputs and
    outputs. Passing `None` will retain the previous
    behaviour (and is necessary when the "transparent-inputs" feature is
    not enabled).
- `zcash_client_backend::input_selection::GreedyInputSelectorError` has a
  new variant `UnsupportedTexAddress`.
- `zcash_client_backend::proposal::ProposalError` has new variants
  `SpendsChange`, `EphemeralOutputLeftUnspent`, and `PaysTexFromShielded`.
  (the last two are conditional on the "transparent-inputs" feature).
- `zcash_client_backend::proto`:
  - `ProposalDecodingError` has a new variant `InvalidEphemeralRecipient`.
  - `proposal::Proposal::{from_standard_proposal, try_into_standard_proposal}`
    each no longer require a `consensus::Parameters` argument.
- `zcash_client_backend::wallet::Recipient` variants have changed. Instead of
  wrapping protocol-address types, the `External` and `InternalAccount` variants
  now wrap a `zcash_address::ZcashAddress`. This simplifies the process of
  tracking the original address to which value was sent. There is also a new
  `EphemeralTransparent` variant, and an additional generic parameter for the
  type of metadata associated with an ephemeral transparent outpoint.
- `zcash_client_backend::wallet::WalletTransparentOutput::from_parts`
  now takes its height argument as `Option<BlockHeight>` rather than
  `BlockHeight`.

### Removed
- `zcash_client_backend::data_api`:
  - `WalletRead::get_unspent_transparent_outputs` has been removed because its
    semantics were unclear and could not be clarified. Use
    `WalletRead::get_spendable_transparent_outputs` instead.
- `zcash_client_backend::fees::ChangeValue::new`. Use `ChangeValue::shielded`
  or `ChangeValue::ephemeral_transparent` instead.
- `zcash_client_backend::wallet::WalletTransparentOutput::height`
  (use `WalletTransparentOutput::mined_height` instead).

## [0.12.1] - 2024-03-27

### Fixed
- This release fixes a problem in note selection when sending to a transparent
  recipient, whereby available funds were being incorrectly excluded from
  input selection.

## [0.12.0] - 2024-03-25

### Added
- A new `orchard` feature flag has been added to make it possible to
  build client code without `orchard` dependencies. Additions and
  changes related to `Orchard` below are introduced under this feature
  flag.
- `zcash_client_backend::data_api`:
  - `Account`
  - `AccountBalance::with_orchard_balance_mut`
  - `AccountBirthday::orchard_frontier`
  - `AccountSource`
  - `BlockMetadata::orchard_tree_size`
  - `DecryptedTransaction::{new, tx(), orchard_outputs()}`
  - `NoteRetention`
  - `ScannedBlock::orchard`
  - `ScannedBlockCommitments::orchard`
  - `SeedRelevance`
  - `SentTransaction::new`
  - `SpendableNotes`
  - `ORCHARD_SHARD_HEIGHT`
  - `BlockMetadata::orchard_tree_size`
  - `WalletSummary::next_orchard_subtree_index`
  - `chain::ChainState`
  - `chain::ScanSummary::{spent_orchard_note_count, received_orchard_note_count}`
  - `impl Debug for chain::CommitmentTreeRoot`
- `zcash_client_backend::fees`:
  - `orchard`
  - `ChangeValue::orchard`
- `zcash_client_backend::proto`:
  - `service::TreeState::orchard_tree`
  - `service::TreeState::to_chain_state`
  - `impl TryFrom<&CompactOrchardAction> for CompactAction`
  - `CompactOrchardAction::{cmx, nf, ephemeral_key}`
- `zcash_client_backend::scanning`:
  - `impl ScanningKeyOps<OrchardDomain, ..> for ScanningKey<..>` for Orchard key types.
  - `ScanningKeys::orchard`
  - `Nullifiers::{orchard, extend_orchard, retain_orchard}`
  - `TaggedOrchardBatch`
  - `TaggedOrchardBatchRunner`
- `zcash_client_backend::wallet`:
  - `Note::Orchard`
  - `WalletOrchardSpend`
  - `WalletOrchardOutput`
  - `WalletTx::{orchard_spends, orchard_outputs}`
  - `ReceivedNote::map_note`
  - `ReceivedNote<_, sapling::Note>::note_value`
  - `ReceivedNote<_, orchard::note::Note>::note_value`
- `zcash_client_backend::zip321::Payment::without_memo`

### Changed
- `zcash_client_backend::data_api`:
  - Arguments to `AccountBirthday::from_parts` have changed.
  - Arguments to `BlockMetadata::from_parts` have changed.
  - Arguments to `ScannedBlock::from_parts` have changed.
  - Changes to the `WalletRead` trait:
    - Added `Account` associated type.
    - Added `validate_seed` method.
    - Added `is_seed_relevant_to_any_derived_accounts` method.
    - Added `get_account` method.
    - Added `get_derived_account` method.
    - `get_account_for_ufvk` now returns `Self::Account` instead of a bare
      `AccountId`.
    - Added `get_orchard_nullifiers` method.
    - `get_transaction` now returns `Result<Option<Transaction>, _>` rather
      than returning an `Err` if the `txid` parameter does not correspond to
      a transaction in the database.
  - `WalletWrite::create_account` now takes its `AccountBirthday` argument by
    reference.
  - Changes to the `InputSource` trait:
    - `select_spendable_notes` now takes its `target_value` argument as a
      `NonNegativeAmount`. Also, it now returns a `SpendableNotes` data
      structure instead of a vector.
  - Fields of `DecryptedTransaction` are now private. Use `DecryptedTransaction::new`
    and the newly provided accessors instead.
  - Fields of `SentTransaction` are now private. Use `SentTransaction::new`
    and the newly provided accessors instead.
  - `ShieldedProtocol` has a new `Orchard` variant.
  - `WalletCommitmentTrees`
    - `type OrchardShardStore`
    - `fn with_orchard_tree_mut`
    - `fn put_orchard_subtree_roots`
  - Removed `Error::AccountNotFound` variant.
  - `WalletSummary::new` now takes an additional `next_orchard_subtree_index`
    argument when the `orchard` feature flag is enabled.
- `zcash_client_backend::decrypt`:
  - Fields of `DecryptedOutput` are now private. Use `DecryptedOutput::new`
    and the newly provided accessors instead.
  - `decrypt_transaction` now returns a `DecryptedTransaction<AccountId>`
    instead of a `DecryptedOutput<sapling::Note>` and will decrypt Orchard
    outputs when the `orchard` feature is enabled. In addition, the type
    constraint on its `<AccountId>` parameter has been strengthened to `Copy`.
- `zcash_client_backend::fees`:
  - Arguments to `ChangeStrategy::compute_balance` have changed.
  - `ChangeError::DustInputs` now has an `orchard` field behind the `orchard`
    feature flag.
- `zcash_client_backend::proto`:
  - `ProposalDecodingError` has a new variant `TransparentMemo`.
- `zcash_client_backend::wallet::Recipient::InternalAccount` is now a structured
  variant with an additional `external_address` field.
- `zcash_client_backend::zip321::render::amount_str` now takes a
  `NonNegativeAmount` rather than a signed `Amount` as its argument.
- `zcash_client_backend::zip321::parse::parse_amount` now parses a
  `NonNegativeAmount` rather than a signed `Amount`.
- `zcash_client_backend::zip321::TransactionRequest::total` now
  returns `Result<_, BalanceError>` instead of `Result<_, ()>`.

### Removed
- `zcash_client_backend::PoolType::is_receiver`: use
  `zcash_keys::Address::has_receiver` instead.
- `zcash_client_backend::wallet::ReceivedNote::traverse_opt` removed as
  unnecessary.

### Fixed
- This release fixes an error in amount parsing in `zip321` that previously
  allowed amounts having a decimal point but no decimal value to be parsed
  as valid.

## [0.11.1] - 2024-03-09

### Fixed
- Documentation now correctly builds with all feature flags.

## [0.11.0] - 2024-03-01

### Added
- `zcash_client_backend`:
  - `{PoolType, ShieldedProtocol}` (moved from `zcash_client_backend::data_api`).
  - `PoolType::is_receiver`
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
  - `wallet`:
    - `propose_standard_transfer_to_address`
    - `create_proposed_transactions`
    - `input_selection`:
      - `ShieldingSelector`, behind the `transparent-inputs` feature flag
        (refactored out from the `InputSelector` trait).
      - `impl std::error::Error for InputSelectorError`
- `zcash_client_backend::fees`:
  - `standard` and `sapling` modules.
  - `ChangeValue::new`
- `zcash_client_backend::wallet`:
  - `{NoteId, Recipient}` (moved from `zcash_client_backend::data_api`).
  - `Note`
  - `ReceivedNote`
  - `Recipient::{map_internal_account, internal_account_transpose_option}`
  - `WalletOutput`
  - `WalletSaplingOutput::{key_source, account_id, recipient_key_scope}`
  - `WalletSaplingSpend::account_id`
  - `WalletSpend`
  - `WalletTx::new`
  - `WalletTx` getter methods `{txid, block_index, sapling_spends, sapling_outputs}`
    (replacing what were previously public fields.)
  - `TransparentAddressMetadata` (which replaces `zcash_keys::address::AddressMetadata`).
  - `impl {Debug, Clone} for OvkPolicy`
- `zcash_client_backend::proposal`:
  - `Proposal::{shielded_inputs, payment_pools, single_step, multi_step}`
  - `ShieldedInputs`
  - `Step`
- `zcash_client_backend::proto`:
  - `PROPOSAL_SER_V1`
  - `ProposalDecodingError`
  - `proposal` module, for parsing and serializing transaction proposals.
  - `impl TryFrom<&CompactSaplingOutput> for CompactOutputDescription`
- `zcash_client_backend::scanning`:
  - `ScanningKeyOps` has replaced the `ScanningKey` trait.
  - `ScanningKeys`
  - `Nullifiers`
- `impl Clone for zcash_client_backend::{
     zip321::{Payment, TransactionRequest, Zip321Error, parse::Param, parse::IndexedParam},
     wallet::WalletTransparentOutput,
     proposal::Proposal,
   }`
- `impl {PartialEq, Eq} for zcash_client_backend::{
     zip321::{Zip321Error, parse::Param, parse::IndexedParam},
     wallet::WalletTransparentOutput,
     proposal::Proposal,
   }`
- `zcash_client_backend::zip321`:
  - `TransactionRequest::{total, from_indexed}`
  - `parse::Param::name`

### Changed
- Migrated to `zcash_primitives 0.14`, `orchard 0.7`.
- Several structs and functions now take an `AccountId` type parameter
  in order to decouple the concept of an account identifier from
  the ZIP 32 account index. Many APIs that previously referenced
  `zcash_primitives::zip32::AccountId` now reference the generic type.
  Impacted types and functions are:
  - `zcash_client_backend::data_api`:
    - `WalletRead` now has an associated `AccountId` type.
    - `WalletRead::{
        get_account_birthday,
        get_current_address,
        get_unified_full_viewing_keys,
        get_account_for_ufvk,
        get_wallet_summary,
        get_sapling_nullifiers,
        get_transparent_receivers,
        get_transparent_balances,
        get_account_ids
      }` now refer to the `WalletRead::AccountId` associated type.
    - `WalletWrite::{create_account, get_next_available_address}`
      now refer to the `WalletRead::AccountId` associated type.
    - `ScannedBlock` now takes an additional `AccountId` type parameter.
    - `DecryptedTransaction` is now parameterized by `AccountId`
    - `SentTransaction` is now parameterized by `AccountId`
    - `SentTransactionOutput` is now parameterized by `AccountId`
    - `WalletSummary` is now parameterized by `AccountId`
  - `zcash_client_backend::decrypt`
    - `DecryptedOutput` is now parameterized by `AccountId`
    - `decrypt_transaction` is now parameterized by `AccountId`
  - `zcash_client_backend::scanning::scan_block` is now parameterized by `AccountId`
  - `zcash_client_backend::wallet`:
    - `Recipient` now takes an additional `AccountId` type parameter.
    - `WalletTx` now takes an additional `AccountId` type parameter.
    - `WalletSaplingSpend` now takes an additional `AccountId` type parameter.
    - `WalletSaplingOutput` now takes an additional `AccountId` type parameter.
- `zcash_client_backend::data_api`:
  - `BlockMetadata::sapling_tree_size` now returns an `Option<u32>` instead of
    a `u32` for future consistency with Orchard.
  - `ScannedBlock` is no longer parameterized by the nullifier type as a consequence
    of the `WalletTx` change.
  - `ScannedBlock::metadata` has been renamed to `to_block_metadata` and now
    returns an owned value rather than a reference.
  - Fields of `Balance` and `AccountBalance` have been made private and the values
    of these fields have been made available via methods having the same names
    as the previously-public fields.
  - `WalletSummary::new` now takes an additional `next_sapling_subtree_index` argument.
  - `WalletSummary::new` now takes a `HashMap` instead of a `BTreeMap` for its
    `account_balances` argument.
  - `WalletSummary::account_balances` now returns a `HashMap` instead of a `BTreeMap`.
  - Changes to the `WalletRead` trait:
    - Added associated type `AccountId`.
    - Added `get_account` function.
    - `get_checkpoint_depth` has been removed without replacement. This is no
      longer needed given the change to use the stored anchor height for
      transaction proposal execution.
    - `is_valid_account_extfvk` has been removed; it was unused in the ECC
      mobile wallet SDKs and has been superseded by `get_account_for_ufvk`.
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
  - `WalletWrite::get_next_available_address` now takes an additional
    `UnifiedAddressRequest` argument.
  - `chain::scan_cached_blocks` now returns a `ScanSummary` containing metadata
    about the scanned blocks on success.
  - `error::Error` enum changes:
    - The `NoteMismatch` variant now wraps a `NoteId` instead of a
      backend-specific note identifier. The related `NoteRef` type parameter has
      been removed from `error::Error`.
    - New variants have been added:
      - `Error::UnsupportedChangeType`
      - `Error::NoSupportedReceivers`
      - `Error::NoSpendingKey`
      - `Error::Proposal`
      - `Error::ProposalNotSupported`
    - Variant `ChildIndexOutOfRange` has been removed.
  - `wallet`:
    - `shield_transparent_funds` no longer takes a `memo` argument; instead,
      memos to be associated with the shielded outputs should be specified in
      the construction of the value of the `input_selector` argument, which is
      used to construct the proposed shielded values as internal "change"
      outputs. Also, it returns its result as a `NonEmpty<TxId>` instead of a
      single `TxId`.
    - `create_proposed_transaction` has been replaced by
      `create_proposed_transactions`. Relative to the prior method, the new
      method has the following changes:
      - It no longer takes a `change_memo` argument; instead, change memos are
        represented in the individual values of the `proposed_change` field of
        the `Proposal`'s `TransactionBalance`.
      - `create_proposed_transactions` takes its `proposal` argument by
        reference instead of as an owned value.
      - `create_proposed_transactions` no longer takes a `min_confirmations`
        argument. Instead, it uses the anchor height from its `proposal`
        argument.
      - `create_proposed_transactions` forces implementations to ignore the
        database identifiers for its contained notes by universally quantifying
        the `NoteRef` type parameter.
      - It returns a `NonEmpty<TxId>` instead of a single `TxId` value.
    - `create_spend_to_address` now takes additional `change_memo` and
      `fallback_change_pool` arguments. It also returns its result as a
      `NonEmpty<TxId>` instead of a single `TxId`.
    - `spend` returns its result as a `NonEmpty<TxId>` instead of a single
      `TxId`.
    - The error type of `create_spend_to_address` has been changed to use
      `zcash_primitives::transaction::fees::zip317::FeeError` instead of
      `zcash_primitives::transaction::components::amount::BalanceError`. Yes
      this is confusing because `create_spend_to_address` is explicitly not
      using ZIP 317 fees; it's just an artifact of the internal implementation,
      and the error variants are not specific to ZIP 317.
    - The following methods now take `&impl SpendProver, &impl OutputProver`
      instead of `impl TxProver`:
      - `create_proposed_transactions`
      - `create_spend_to_address`
      - `shield_transparent_funds`
      - `spend`
    - `propose_shielding` and `shield_transparent_funds` now take their
      `min_confirmations` arguments as `u32` rather than a `NonZeroU32`, to
      permit implementations to enable zero-conf shielding.
    - `input_selection`:
      - `InputSelector::propose_shielding` has been moved out to the
        newly-created `ShieldingSelector` trait.
        - `ShieldingSelector::propose_shielding` has been altered such that it
          takes an explicit `target_height` in order to minimize the
          capabilities that the `data_api::InputSource` trait must expose. Also,
          it now takes its `min_confirmations` argument as `u32` instead of
          `NonZeroU32`.
      - The `InputSelector::DataSource` associated type has been renamed to
        `InputSource`.
      - `InputSelectorError` has added variant `Proposal`.
      - The signature of `InputSelector::propose_transaction` has been altered
        such that it longer takes `min_confirmations` as an argument, instead
        taking explicit `target_height` and `anchor_height` arguments. This
        helps to minimize the set of capabilities that the
        `data_api::InputSource` must expose.
      - `GreedyInputSelector` now has relaxed requirements for its `InputSource`
        associated type.
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
  - `fixed::SingleOutputChangeStrategy::new`,
    `zip317::SingleOutputChangeStrategy::new`, and
    `standard::SingleOutputChangeStrategy::new` each now accept additional
    `change_memo` and `fallback_change_pool` arguments.
- `zcash_client_backend::wallet`:
  - `Recipient` is now polymorphic in the type of the payload for wallet-internal
    recipients. This simplifies the handling of wallet-internal outputs.
  - `SentTransactionOutput::from_parts` now takes a `Recipient<Note>`.
  - `SentTransactionOutput::recipient` now returns a `Recipient<Note>`.
  - `OvkPolicy::Custom` is now a structured variant that can contain independent
    Sapling and Orchard `OutgoingViewingKey`s.
  - `WalletSaplingOutput::from_parts` arguments have changed.
  - `WalletSaplingOutput::nf` now returns an `Option<sapling::Nullifier>`.
  - `WalletTx` is no longer parameterized by the nullifier type; instead, the
    nullifier is present as an optional value.
- `zcash_client_backend::scanning`:
  - Arguments to `scan_blocks` have changed.
  - `ScanError` has new variants `TreeSizeInvalid` and `EncodingInvalid`.
  - `ScanningKey` is now a concrete type that bundles an incoming viewing key
    with an optional nullifier key and key source metadata. The trait that
    provides uniform access to scanning key information is now `ScanningKeyOps`.
- `zcash_client_backend::zip321`:
  - `TransactionRequest::payments` now returns a `BTreeMap<usize, Payment>`
    instead of `&[Payment]` so that parameter indices may be preserved.
  - `TransactionRequest::to_uri` now returns a `String` instead of an
    `Option<String>` and provides canonical serialization for the empty
    proposal.
  - `TransactionRequest::from_uri` previously stripped payment indices, meaning
    that round-trip serialization was not supported. Payment indices are now
    retained.
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
- The following methods now return `NonNegativeAmount` instead of `Amount`:
  - `zcash_client_backend::data_api::SentTransactionOutput::value`
  - `zcash_client_backend::fees`:
    - `ChangeValue::value`
    - `DustOutputPolicy::dust_threshold`
    - `TransactionBalance::{fee_required, total}`
  - `zcash_client_backend::wallet::WalletTransparentOutput::value`

### Deprecated
- `zcash_client_backend::data_api::wallet`:
  - `spend` (use `propose_transfer` and `create_proposed_transactions` instead).

### Removed
- `zcash_client_backend::wallet`:
  - `ReceivedSaplingNote` (use `zcash_client_backend::ReceivedNote` instead).
  - `input_selection::{Proposal, ShieldedInputs, ProposalError}` (moved to
    `zcash_client_backend::proposal`).
  - `SentTransactionOutput::sapling_change_to` - the note created by an internal
    transfer is now conveyed in the `recipient` field.
  - `WalletSaplingOutput::cmu` (use `WalletSaplingOutput::note` and
    `sapling_crypto::Note::cmu` instead).
  - `WalletSaplingOutput::account` (use `WalletSaplingOutput::account_id` instead)
  - `WalletSaplingSpend::account` (use `WalletSaplingSpend::account_id` instead)
  - `WalletTx` fields `{txid, index, sapling_spends, sapling_outputs}` (use
    the new getters instead.)
- `zcash_client_backend::data_api`:
  - `{PoolType, ShieldedProtocol}` (moved to `zcash_client_backend`).
  - `{NoteId, Recipient}` (moved to `zcash_client_backend::wallet`).
  - `ScannedBlock::from_parts`
  - `ScannedBlock::{sapling_tree_size, sapling_nullifier_map, sapling_commitments}`
    (use `ScannedBundles::{tree_size, nullifier_map, commitments}` instead).
  - `ScannedBlock::into_sapling_commitments`
    (use `ScannedBlock::into_commitments` instead).
  - `wallet::create_proposed_transaction`
    (use `wallet::create_proposed_transactions` instead).
  - `chain::ScanSummary::from_parts`
- `zcash_client_backend::proposal`:
  - `Proposal::min_anchor_height` (use `ShieldedInputs::anchor_height` instead).
  - `Proposal::sapling_inputs` (use `Proposal::shielded_inputs` instead).

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
  - `wallet::input_selection::Proposal::{min_target_height, min_anchor_height}`
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
  `chain::scan_cached_blocks`).
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
  - `chain::error`: a module containing error types that can occur only
    in chain validation and sync, separated out from errors related to
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
  - `zcash_client_backend::keys::{UnifiedSpendingKey, UnifiedFullViewingKey, Era, DecodingError}`
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
