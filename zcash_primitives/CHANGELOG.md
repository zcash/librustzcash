# Changelog
All notable changes to this library will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this library adheres to Rust's notion of
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
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
  - `zcash_primitives::primitives::Nullifier` struct.
  - `zcash_primitives::transaction`:
    - `TxVersion` enum, representing the set of valid transaction format
      versions.
    - `SignableInput` enum, encapsulating per-input data used when
      creating transaction signatures.
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
