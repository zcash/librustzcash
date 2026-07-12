# Changelog
All notable changes to this library will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this library adheres to Rust's notion of
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial release of the Orchard → Ironwood value-pool migration engine.
- `zcash_pool_migration::MigrationContext`, the crate's facade over a wallet database. It plans
  a note split into self-funding power-of-ten denominations, proposes and signs migration
  transfers as PCZTs scheduled by block height, tracks progress through a 6-value
  `MigrationState` machine, and hands the platform pre-signed transactions to broadcast via
  `next_due_transfer` / `extract_broadcast_tx` / `record_transfer_result`. Both a software-signing
  flow (`sign_note_split`, `sign_and_store_migration_schedule`, given a `UnifiedSpendingKey`) and
  an external-signer (Keystone-style hardware wallet) flow are supported, the latter staging
  proven-but-unsigned PCZTs and accepting signed ones back (`create_unsigned_note_split_pczt` /
  `store_signed_note_split_pczt`, `create_unsigned_transfer_pczts` / `store_signed_schedule_pczts`).
- The public data types backing the above: `TransferId`, `NoteSplitProposal`, `TransferProposal`,
  `MigrationSchedule`, `MigrationProgress`, `PreparedTransfer`, `UnsignedTransferPczt`,
  `SignedTransferPczt`, `MigrationState`, `AttentionReason`, and `TransferResult`, along with
  `MigrationError`/`InvalidStateError` for error reporting.
- Self-funding power-of-ten denomination planning: decomposes a spendable Orchard balance into
  notes each holding a power-of-ten crossing value plus a fixed fee buffer, leaving any residual
  (including dust) as Orchard change rather than folding it into a fee.
- Height-based transfer scheduling: assigns each crossing value a send window and expiry, sharing
  the wallet's natural anchor across a schedule and sampling the gap between successive transfers
  from an exponential distribution (floored at one block).
- Migration run state machine and its SQLite persistence: five additive
  `ext_ironwood_migration_*` tables recording runs, prepared notes, the note-split transaction,
  scheduled transfers, and staged external-signer PCZTs.
- Note-split PCZT construction and a reserving `InputSource` adapter, and the wallet-backend
  transaction pipeline (balance/height reads, self-funding transfer construction, and the shared
  PCZT prove/sign/finalize pipeline).
- Seeded-wallet end-to-end test coverage (`tests/migration_e2e.rs`, gated behind the
  `expensive-tests` feature) exercising the note-split and migration-transfer pipelines — including
  a real Ironwood proof — against a wallet database scanned by the upstream `data_api::testing`
  harness, alongside unit tests for every module.
