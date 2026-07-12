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
