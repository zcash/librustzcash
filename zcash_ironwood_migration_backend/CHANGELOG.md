# Changelog
All notable changes to this library will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this library adheres to Rust's notion of
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial scaffolding of the Orchard -> Ironwood value-pool migration engine crate.
- The public data types the engine exchanges with the platform: `TransferId`,
  `NoteSplitProposal`, `TransferProposal`, `MigrationSchedule`, `MigrationProgress`,
  `PreparedTransfer`, `MigrationState`, `AttentionReason`, and `TransferResult`. These have
  private fields with `from_parts`-style constructors and accessor methods, and derive no `serde`.
- `TransferPczt<State>`, a transfer PCZT whose signing state (`Unsigned` / `Signed`) is tracked at
  the type level, with the `Unsigned -> Signed` transition (`TransferPczt::into_signed`) as the
  only way to reach the signed state. `UnsignedTransferPczt` and `SignedTransferPczt` are aliases
  for the two states.
- `types::testing` proptest strategies for every public type, behind the `test-dependencies`
  feature, for reuse by later modules and dependent crates.
- The error types `MigrationError` and `InvalidStateError`. `MigrationError` is backend-agnostic:
  wallet-backend and storage failures are carried as opaque messages (`Backend(String)` /
  `Store(String)`), so it names no backend-specific type; it exposes a stable `error_code` for the
  FFI boundary and derives no `serde`.
- Self-funding denomination planning (`plan_denominations`): decomposes a spendable Orchard balance
  into notes whose crossing values follow the `{1, 2, 5} * 10^k` ZEC series (1, 2, 5, 10, ... ZEC),
  each note holding its crossing value plus a fixed fee buffer, leaving any residual (including
  dust) as Orchard change rather than folding it into a fee.
