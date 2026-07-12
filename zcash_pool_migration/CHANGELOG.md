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
