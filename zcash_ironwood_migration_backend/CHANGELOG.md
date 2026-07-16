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
- Height-based transfer scheduling (`build_schedule`): assigns each crossing value a send window
  and expiry, sharing the wallet's natural anchor across a schedule and sampling the gap between
  successive transfers from an exponential distribution (floored at one block).
- The internal PCZT pipeline (prove / sign / finalize / combine / extract, plus the shared Orchard
  proving key): the pure steps the engine drives a built PCZT through, needing only `pczt` /
  `orchard` / `zcash_keys` and no wallet backend. This adds those shielded-protocol dependencies to
  the crate.
- The `wallet::WalletMigrationBackend` trait, the backend-agnostic wallet interface the migration
  engine is generic over, plus its plain-data types (`PoolBalances`, `NoteRef`, `SpentNote`,
  `SplitOutputs`, `TransferBuild`). A backend implements the wallet reads and PCZT-building
  operations; the engine performs the pure PCZT steps itself. Note references cross the boundary as
  `NoteRef` pairs and builds return an unproven `pczt::Pczt`, so no backend-specific type appears in
  the interface.
- `state::Phase`, a migration run's fine-grained 14-value phase, with its stable persisted string
  form (`Phase::as_str` / `Phase::parse`).
