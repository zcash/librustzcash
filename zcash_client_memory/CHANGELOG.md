# Changelog
All notable changes to this library will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this library adheres to Rust's notion of
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `ReceivedNote::from_decrypted_sapling_output` and
  `ReceivedNote::from_decrypted_orchard_output` for constructing received notes
  from decrypted incoming transaction outputs.
- `ReceivedNote::note()` and `ReceivedNote::memo()` public accessor methods.
- `SentNote::from_account_id()`, `SentNote::to()`, `SentNote::value()`, and
  `SentNote::memo()` public accessor methods.
- `TransactionEntry::expiry_height()`, `TransactionEntry::status()`, and
  `TransactionEntry::mined_height()` are now public.
- `MemoryWalletDb::received_notes()`, `MemoryWalletDb::sent_notes()`,
  `MemoryWalletDb::tx_table()`, and `MemoryWalletDb::get_block_time()` public
  accessor methods for transaction history queries.
- `ReceivedNoteTable::from_notes()` constructor that rebuilds indexes from a
  `Vec<ReceivedNote>`.
- `ReceivedNoteTable` now maintains O(1) lookup indexes by nullifier and note ID.
- Unit tests for `ReceivedNoteTable` indexed lookup operations.
- `WalletRead::list_addresses()` implementation.
- `WalletRead::get_last_generated_address_matching()` implementation.
- `WalletRead::utxo_query_height()` implementation (behind `transparent-inputs`
  feature flag).
- `WalletRead::get_transparent_address_metadata()` implementation (behind
  `transparent-inputs` feature flag).
- `TransparentKeyScope` serialization field in protobuf for
  `ReceivedTransparentOutput`, with backwards-compatible deserialization that
  defaults to `EXTERNAL` for old data.
- `Account::find_key_scope_for_transparent_address()` for looking up the key
  scope of a transparent address across ephemeral, unified, and legacy addresses.
- `WalletWrite::store_decrypted_tx()` now stores incoming Sapling and Orchard
  notes instead of panicking.
- `WalletWrite::notify_address_checked()` is now a no-op instead of panicking.
- `ReceivedNote`, `ReceivedNoteTable`, `SentNote`, `SentNoteTable`,
  `TransactionEntry`, and `TransactionTable` are now re-exported as public types.

### Fixed
- `get_wallet_summary()` no longer incorrectly filters mined transactions by
  expiry height. Only expired *unmined* transactions are now excluded from
  balance calculations.
- `get_transparent_receivers()` no longer panics when `include_change` or
  `include_standalone` are true; it now returns external addresses regardless
  of these flags.
- `TransparentKeyScope` deserialization no longer panics with
  `TransparentKeyScope::custom(u32::MAX).expect("FIXME")`; it now properly
  deserializes the stored scope value with backwards compatibility.
- Transparent output insertion no longer panics with
  `todo!("look up the key scope for the address")`; it now looks up the correct
  key scope from the account's address data.
- Replaced `unwrap()` with `ok()` / `ok_or_else()` in serialization for
  resilience against edge cases (birthday, commitment trees, shard lookups).
- Replaced `println!` with `tracing::debug!` for nullifier spend logging.

### Changed
- `ReceivedNoteTable` is now a struct with indexed fields instead of a newtype
  around `Vec<ReceivedNote>`. It provides O(1) lookups by nullifier and note ID
  via `find_by_nullifier()` and `find_by_note_id()` methods. The `Deref` and
  `DerefMut` implementations now delegate to the inner `notes` field.
- `block_fully_scanned()` now uses `min_by_key` instead of collecting, sorting,
  and taking the first element.
- `get_wallet_summary()` now hoists `unscanned_ranges()` out of the inner loop
  for better performance.
