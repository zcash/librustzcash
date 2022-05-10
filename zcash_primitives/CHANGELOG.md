# Changelog
All notable changes to this library will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this library adheres to Rust's notion of
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.6.0] - 2022-05-11
### Added
- `zcash_primitives::sapling::redjubjub::PublicKey::verify_with_zip216`, for
  controlling how RedJubjub signatures are validated. `PublicKey::verify` has
  been altered to always use post-ZIP 216 validation rules.
- `zcash_primitives::transaction::Builder::with_progress_notifier`, for setting
  a notification channel on which transaction build progress updates will be
  sent.
- `zcash_primitives::transaction::Txid::{read, write, from_bytes}`
- `zcash_primitives::sapling::NoteValue` a typesafe wrapper for Sapling note values.
- `zcash_primitives::consensus::BranchId::{height_range, height_bounds}` functions
  to provide range values for branch active heights.
- `zcash_primitives::consensus::NetworkUpgrade::Nu5` value representing the Nu5 upgrade.
- `zcash_primitives::consensus::BranchId::Nu5` value representing the Nu5 consensus branch.
- New modules under `zcash_primitives::transaction::components` for building parts of
  transactions:
  - `sapling::builder` for Sapling transaction components.
  - `transparent::builder` for transparent transaction components.
  - `tze::builder` for TZE transaction components.
  - `orchard` parsing and serialization for Orchard transaction components.
- `zcash_primitives::transaction::Authorization` a trait representing a type-level
  record of authorization types that correspond to signatures, witnesses, and
  proofs for each Zcash sub-protocol (transparent, Sprout, Sapling, TZE, and
  Orchard). This type makes it possible to encode a type-safe state machine
  for the application of authorizing data to a transaction; implementations of
  this trait represent different states of the authorization process.
- New bundle types under the `zcash_primitives::transaction` submodules, one for
  each Zcash sub-protocol. These are now used instead of bare fields
  within the `TransactionData` type.
  - `components::sapling::Bundle` bundle of
    Sapling transaction elements. This new struct is parameterized by a
    type bounded on a newly added `sapling::Authorization` trait which
    is used to enable static reasoning about the state of Sapling proofs and
    authorizing data, as described above.
  - `components::transparent::Bundle` bundle of
    transparent transaction elements. This new struct is parameterized by a
    type bounded on a newly added `transparent::Authorization` trait which
    is used to enable static reasoning about the state of transparent witness
    data, as described above.
  - `components::tze::Bundle` bundle of TZE
    transaction elements. This new struct is parameterized by a
    type bounded on a newly added `tze::Authorization` trait which
    is used to enable static reasoning about the state of TZE witness
    data, as described above.
- `zcash_primitives::serialize` has been factored out as a new `zcash_encoding`
  crate, which can be found in the `components` directory.
- `zcash_primitives::transaction::components::Amount` now implements
  `memuse::DynamicUsage`, to enable `orchard::Bundle<_, Amount>::dynamic_usage`.
- `zcash_primitives::zip32::diversifier` has been renamed to `find_sapling_diversifier`
  and `sapling_diversifier` has been added. `find_sapling_diversifier` searches the
  diversifier index space, whereas `sapling_diversifier` just attempts to use the
  provided diversifier index and returns `None` if it does not produce a valid
  diversifier.
- `zcash_primitives::zip32::DiversifierKey::diversifier` has been renamed to
  `find_diversifier` and the `diversifier` method has new semantics.
  `find_diversifier` searches the diversifier index space to find a diversifier
  index which produces a valid diversifier, whereas `diversifier` just attempts
  to use the provided diversifier index and returns `None` if it does not
  produce a valid diversifier.
- `zcash_primitives::zip32::ExtendedFullViewingKey::address` has been renamed
  to `find_address` and the `address` method has new semantics. `find_address`
  searches the diversifier index space until it obtains a valid diversifier,
  and returns the address corresponding to that diversifier, whereas `address`
  just attempts to create an address corresponding to the diversifier derived
  from the provided diversifier index and returns `None` if the provided index
  does not produce a valid diversifier.
- `zcash_primitives::zip32::ExtendedSpendingKey.derive_internal` has been
  added to facilitate the derivation of an internal (change) spending key.
  This spending key can be used to spend change sent to an internal address
  corresponding to the associated full viewing key as specified in
  [ZIP 316](https://zips.z.cash/zip-0316#encoding-of-unified-full-incoming-viewing-keys)..
- `zcash_primitives::zip32::ExtendedFullViewingKey.derive_internal` has been
  added to facilitate the derivation of an internal (change) spending key.
  This spending key can be used to spend change sent to an internal address
  corresponding to the associated full viewing key as specified in
  [ZIP 32](https://zips.z.cash/zip-0032#deriving-a-sapling-internal-spending-key).
- `zcash_primitives::zip32::sapling_derive_internal_fvk` provides the
  internal implementation of `ExtendedFullViewingKey.derive_internal` but does
  not require a complete extended full viewing key, just the full viewing key
  and the diversifier key. In the future, this function will likely be
  refactored to become a member function of a new `DiversifiableFullViewingKey`
  type, which represents the ability to derive IVKs, OVKs, and addresses, but
  not child viewing keys.
- A new module `zcash_primitives::legacy::keys` has been added under the
  `transparent-inputs` feature flag to support types related to supporting
  transparent components of unified addresses and derivation of OVKs for
  shielding funds from the transparent pool.
- A `zcash_primitives::transaction::components::amount::Amount::sum`
  convenience method has been added to facilitate bounds-checked summation of
  account values.
- The `zcash_primitives::zip32::AccountId`, a type-safe wrapper for ZIP 32
  account indices.
- In `zcash_primitives::transaction::components::amount`:
  - `impl Sum<&Amount> for Option<Amount>`

### Changed
- MSRV is now 1.56.1.
- Bumped dependencies to `ff 0.12`, `group 0.12`, `bls12_381 0.7`, `jubjub 0.9`,
  `bitvec 1`.
- The following modules and helpers have been moved into
  `zcash_primitives::sapling`:
  - `zcash_primitives::group_hash`
  - `zcash_primitives::keys`
    - `zcash_primitives::sapling::keys::{prf_expand, prf_expand_vec, OutgoingViewingKey}`
      have all been moved into to the this module to reflect the fact that they
      are used outside of the Sapling protocol.
  - `zcash_primitives::pedersen_hash`
  - `zcash_primitives::primitives::*` (moved into `zcash_primitives::sapling`)
  - `zcash_primitives::prover`
  - `zcash_primitives::redjubjub`
  - `zcash_primitives::util::{hash_to_scalar, generate_random_rseed}`
- Renamed `zcash_primitives::transaction::components::JSDescription` to
  `JsDescription` (matching Rust naming conventions).
- `zcash_primitives::transaction::TxId` contents is now private.
- Renamed `zcash_primitives::transaction::components::tze::hash` to
  `zcash_primitives::transaction::components::tze::txid`
- `zcash_primitives::transaction::components::tze::TzeOutPoint` constructor
  now taxes a TxId rather than a raw byte array.
- `zcash_primitives::transaction::components::Amount` addition, subtraction,
  and summation now return `Option` rather than panicing on overflow.
- `zcash_primitives::transaction::builder`:
  - `Error` has been modified to wrap the error types produced by its child
    builders.
  - `Builder::build` no longer takes a consensus branch ID parameter. The
    builder now selects the correct consensus branch ID for the given target
    height.
- The `zcash_primitives::transaction::TransactionData` struct has been modified
  such that it now contains common header information, and then contains
  a separate `Bundle` value for each sub-protocol (transparent, Sprout, Sapling,
  and TZE) and an Orchard bundle value has been added. `TransactionData` is now
  parameterized by a type bounded on the newly added
  `zcash_primitives::transaction::Authorization` trait. This bound has been
  propagated to the individual transaction builders, such that the authorization
  state of a transaction is clearly represented in the type and the presence
  or absence of witness and/or proof data is statically known, instead of being only
  determined at runtime via the presence or absence of `Option`al values.
- `zcash_primitives::transaction::components::sapling` parsing and serialization
  have been adapted for use with the new `sapling::Bundle` type.
- `zcash_primitives::transaction::Transaction` parsing and serialization
  have been adapted for use with the new `TransactionData` organization.
- Generators for property testing have been moved out of the main transaction
  module such that they are now colocated in the modules with the types
  that they generate.
- The `ephemeral_key` field of `OutputDescription` has had its type changed from
  `jubjub::ExtendedPoint` to `zcash_note_encryption::EphemeralKeyBytes`.
- The `epk: jubjub::ExtendedPoint` field of `CompactOutputDescription ` has been
  replaced by `ephemeral_key: zcash_note_encryption::EphemeralKeyBytes`.
- The `zcash_primitives::transaction::Builder::add_sapling_output` method
  now takes its `MemoBytes` argument as a required field rather than an
  optional one. If the empty memo is desired, use
  `MemoBytes::from(Memo::Empty)` explicitly.

## [0.5.0] - 2021-03-26
### Added
- Support for implementing candidate ZIPs before they have been selected for a
  network upgrade, behind the `zfuture` feature flag.
  - At runtime, these ZIPs are gated behind the new `NetworkUpgrade::ZFuture`
    enum case, which is inaccessible without the `zfuture` feature flag. This
    pseudo-NU can be enabled for private testing using a custom implementation
    of the `Parameters` trait.
- New structs and methods:
  - `zcash_primitives::consensus`:
    - `BlockHeight`
    - New methods on the `Parameters` trait:
      - `coin_type`
      - `hrp_sapling_extended_spending_key`
      - `hrp_sapling_extended_full_viewing_key`
      - `hrp_sapling_payment_address`
      - `b58_pubkey_address_prefix`
      - `b58_script_address_prefix`
    - The `Network` enum, which enables code to be generic over the network type
      at runtime.
  - `zcash_primitives::memo`:
    - `MemoBytes`, a minimal wrapper around the memo bytes, that only imposes
      the existence of null-padding for shorter memos. `MemoBytes` is guaranteed
      to be round-trip encodable (modulo null padding).
    - `Memo`, an enum that implements the memo field format defined in
      [ZIP 302](https://zips.z.cash/zip-0302). It can be converted to and from
      `MemoBytes`.
  - `zcash_primitives::primitives::Nullifier` struct.
  - `zcash_primitives::transaction`:
    - `TxVersion` enum, representing the set of valid transaction format
      versions.
    - `SignableInput` enum, encapsulating per-input data used when
      creating transaction signatures.
  - `zcash_primitives::primitives::SaplingIvk`, a newtype wrapper around `jubjub::Fr`
    values that are semantically Sapling incoming viewing keys.
- Test helpers, behind the `test-dependencies` feature flag:
  - `zcash_primitives::prover::mock::MockTxProver`, for building transactions in
    tests without creating proofs.
  - `zcash_primitives::transaction::Builder::test_only_new_with_rng` constructor
    which accepts a non-`CryptoRng` randomness source (for e.g. deterministic
    tests).
  - `proptest` APIs for generating arbitrary Zcash types.
- New constants:
  - `zcash_primitives::consensus`:
    - `H0`, the height of the genesis block.
    - `MAIN_NETWORK`
    - `TEST_NETWORK`
  - `zcash_primitives::constants::{mainnet, testnet, regtest}` modules,
    containing network-specific constants.
  - `zcash_primitives::note_encryption`:
    - `ENC_CIPHERTEXT_SIZE`
    - `OUT_CIPHERTEXT_SIZE`
  - `zcash_primitives::transaction::components::amount`:
    - `COIN`
    - `MAX_MONEY`
- More implementations of standard traits:
  - `zcash_primitives::consensus`:
    - `Parameters: Clone`
    - `MainNetwork: PartialEq`
    - `TestNetwork: PartialEq`
  - `zcash_primitives::legacy`:
    - `Script: PartialEq`
    - `TransparentAddress: Clone + PartialOrd + Hash`
  - `zcash_primitives::redjubjub::PublicKey: Clone`
  - `zcash_primitives::transaction`:
    - `Transaction: Clone`
    - `TransactionData: Clone + Default`
    - `components::Amount: Eq + PartialOrd + Ord`
    - `components::TxIn: Clone + PartialEq`
    - `components::TxOut: PartialEq`
    - `components::SpendDescription: Clone`
    - `components::OutputDescription: Clone`
    - `components::SproutProof: Clone`
    - `components::JSDescription: Clone`
  - `zcash_primitives::zip32::DiversifierIndex: Default`

### Changed
- MSRV is now 1.47.0.
- Trial decryption using the APIs in `zcash_primitives::note_encryption` is now
  over 60% faster at detecting which notes are relevant.
  - Part of this improvement was achieved by changing the APIs to take `epk` as
    a `&jubjub::ExtendedPoint` instead of a `&SubgroupPoint`.
- Various APIs now take the network parameters as an explicit variable instead
  of a type parameter:
  - `zcash_primitives::consensus::BranchId::for_height`
  - The `zcash_primitives::note_encryption` APIs.
  - `zcash_primitives::transaction::builder`:
    - `SaplingOutput::new`
    - `Builder::new`
    - `Builder::new_with_rng`
  - `Parameters::activation_height` and `Parameters::is_nu_active` now take
    `&self`.
- `zcash_primitives::merkle_tree::CommitmentTree::new` has been renamed to
  `CommitmentTree::empty`.
- `zcash_primitives::note_encryption`:
  - `SaplingNoteEncryption::new` now takes `MemoBytes`.
  - The following APIs now return `MemoBytes`:
    - `try_sapling_note_decryption`
    - `try_sapling_output_recovery`
    - `try_sapling_output_recovery_with_ock`
- `zcash_primitives::primitives::SaplingIvk` is now used where functions
  previously used undistinguished `jubjub::Fr` values; this affects Sapling
  note decryption and handling of IVKs by the wallet backend code.
- `zcash_primitives::primitives::ViewingKey::ivk` now returns `SaplingIvk`
- `zcash_primitives::primitives::Note::nf` now returns `Nullifier`.
- `zcash_primitives::transaction`:
  - The `overwintered`, `version`, and `version_group_id` properties of the
    `Transaction` and `TransactionData` structs have been replaced by
    `version: TxVersion`.
  - `components::amount::DEFAULT_FEE` is now 1000 zatoshis, following
    [ZIP 313](https://zips.z.cash/zip-0313).
  - The `nullifier` property of `components::SpendDescription` now has the type
    `Nullifier`.
  - `signature_hash` and `signature_hash_data` now take a `SignableInput`
    argument instead of a `transparent_input` argument.
  - `builder::SaplingOutput::new` and `builder::Builder::add_sapling_output` now
    take `Option<MemoBytes>`.

### Removed
- `zcash_primitives::note_encryption::Memo` (replaced by
  `zcash_primitives::memo::{Memo, MemoBytes}`).

## [0.4.0] - 2020-09-09
### Added
- `zcash_primitives::note_encryption::OutgoingCipherKey` - a symmetric key that
  can be used to recover a single Sapling output. This will eventually be used
  to implement Sapling payment disclosures.

### Changed
- MSRV is now 1.44.1.
- `zcash_primitives::note_encryption`:
  - `SaplingNoteEncryption::new` now takes `Option<OutgoingViewingKey>`. Setting
    this to `None` prevents the note from being recovered from the block chain
    by the sender.
    - The `rng: &mut R` parameter (where `R: RngCore + CryptoRng`) has been
      changed to `rng: R` to enable this use case.
  - `prf_ock` now returns `OutgoingCipherKey`.
  - `try_sapling_output_recovery_with_ock` now takes `&OutgoingCipherKey`.
- `zcash_primitives::transaction::builder`:
  - `SaplingOutput::new` and `Builder::add_sapling_output` now take
    `Option<OutgoingViewingKey>` (exposing the new unrecoverable note option).
- Bumped dependencies to `ff 0.8`, `group 0.8`, `bls12_381 0.3.1`,
  `jubjub 0.5.1`, `secp256k1 0.19`.

## [0.3.0] - 2020-08-24
TBD

## [0.2.0] - 2020-03-13
TBD

## [0.1.0] - 2019-10-08
Initial release.
