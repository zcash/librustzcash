# Changelog
All notable changes to this library will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this library adheres to Rust's notion of
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `pczt::common`:
  - `Global::{tx_version, version_group_id, consensus_branch_id, expiry_height}`
  - `determine_lock_time`
  - `LockTimeInput` trait
- `pczt::orchard`:
  - `Bundle::{flags, value_sum, anchor}`
  - `Action::cv_net`
  - `Spend::rk`
  - `Output::{cmx, ephemeral_key, enc_ciphertext, out_ciphertext}`
- `pczt::roles`:
  - `low_level_signer` module
  - `prover::Prover::{requires_sapling_proofs, requires_orchard_proof}`
  - `redactor` module
- `pczt::sapling`:
  - `Bundle::{value_sum, anchor}`
  - `Spend::{cv, nullifier, rk}`
  - `Output::{cv, cmu, ephemeral_key, enc_ciphertext, out_ciphertext}`
- `pczt::transparent`:
  - `Input::{sequence, script_pubkey}`
  - `Output::{value, script_pubkey}`

### Changed
- MSRV is now 1.81.0.
- Migrated to `nonempty 0.11`, `secp256k1 0.29`.

## [0.1.0] - 2024-12-16
Initial release supporting the PCZT v1 format.
