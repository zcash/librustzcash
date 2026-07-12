# Changelog
All notable changes to this library will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this library adheres to Rust's notion of
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial scaffold of the Orchard → Ironwood value-pool migration engine.
- `MigrationError`/`InvalidStateError` error types, and the public data types backing the
  engine's API: `TransferId`, `NoteSplitProposal`, `TransferProposal`, `MigrationSchedule`,
  `MigrationProgress`, `PreparedTransfer`, `UnsignedTransferPczt`, `SignedTransferPczt`,
  `MigrationState`, `AttentionReason`, and `TransferResult`.
- Self-funding power-of-ten denomination planning: decomposes a spendable Orchard balance into
  notes each holding a power-of-ten crossing value plus a fixed fee buffer, leaving any residual
  (including dust) as Orchard change rather than folding it into a fee.
- Height-based transfer scheduling: assigns each crossing value a send window and expiry, sharing
  the wallet's natural anchor across a schedule and sampling the gap between successive transfers
  from an exponential distribution (floored at one block) so a wallet's own transfers are neither
  uniformly spaced nor correlated.
- Migration run state machine (`state`) and its SQLite persistence layer (`store`): five additive
  `ext_ironwood_migration_*` tables recording runs, prepared notes, the note-split transaction,
  scheduled transfers, and staged external-signer PCZTs, plus the phase-string model that
  `MigrationState` is derived from.
- Note-split PCZT construction (`split`) and a reserving `InputSource` adapter
  (`reserved_source`): builds the denomination-prep transaction that fans a consolidated Orchard
  balance into the planned self-funding notes, keeping any residual as a plain Orchard change
  output (never folded into a migration note), and excludes reserved / migration-locked notes
  from selection.
