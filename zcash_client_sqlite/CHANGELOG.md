# Changelog
All notable changes to this library will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this library adheres to Rust's notion of
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Future releases are
indicated by the `PLANNED` status in order to make it possible to correctly
represent the transitive `semver` implications of changes within the enclosing
workspace.

## [Unreleased]

## [0.22.0-rc.8] - 2026-08-07

### Added
- Support for `WalletWrite::import_standalone_transparent_address` (under the
  `transparent-key-import` feature): a watch-only transparent address is
  stored as a `key_scope = -1` row of the `addresses` table with neither
  imported-material column set. A schema migration relaxes the `addresses`
  table constraint to admit this shape. Importing the corresponding pubkey or
  redeem script with `WalletWrite::import_standalone_transparent_pubkey` /
  `import_standalone_transparent_script` now upgrades such a row in place.
  Outputs received by an address imported without key material contribute to
  the account balance but are excluded from spendable-output selection.
- `wallet::init::migrations` release-state constants backfilling every
  published crate version whose migration-graph state had no constant:
  `V_0_7_0`, `V_0_8_0_RC1`, `V_0_8_0_RC4`, `V_0_8_0_RC5`, `V_0_8_1`,
  `V_0_22_0_RC5`, and `V_0_22_0_RC6`. Each was computed from the corresponding
  crate artifact published on crates.io.
- The `v_migration_transactions` view: one row per SCHEDULED pool-migration
  transaction (belonging to a non-terminal migration and not yet broadcast),
  with its identity, kind, lifecycle state, scheduled and expiry heights,
  values, and ZIP 318 classification code.
- The `v_transactions_with_pending_migrations` view: `v_transactions` plus the
  scheduled migration transactions projected into the same column shape.
  `v_transactions` itself is unchanged; a consumer that wants pending
  migration activity in one merged feed reads this view instead.
- `pool_migration::orchard_ironwood::PoolMigrations::cancel_migration` and
  `pool_migration::CancelOutcome`: cancel the account's migration at the
  user's request. Releases the note reservations of its never-broadcast
  transactions (returning them to default note selection immediately), then
  records the terminal `cancelled` status, without deserializing the migration
  state — so it works on a record that no longer parses. Transactions already
  broadcast cannot be recalled; the outcome reports them rather than refusing.
  With no pending migration, only the repair half runs: the latest retained
  record's reservations are released and its status is untouched.
- `pool_migration::orchard_ironwood::PoolMigrations::take_transaction_for_broadcast`:
  finalizes a proved migration transaction, records it in the wallet's own
  transaction tables, and returns the broadcastable `Transaction`, in one
  database transaction. This — not proving — is now where a migration
  transaction enters the wallet's view (see the Changed entries).
- A schema migration removing the wallet-side transaction records of
  never-broadcast transactions belonging to TERMINAL pool migrations, which
  earlier releases wrote at prove time: their spend marks froze the input
  notes out of the user's balance until each transaction's expiry, with
  nothing left to broadcast them.
- `pool_migration::MigrationUuid`: the stable external identity of one
  pool-migration record, safe to hand across an FFI (row ids are not stable
  across a restore).
- `pool_migration::MigrationSummary` and, on each pool facade
  (`pool_migration::orchard_ironwood::PoolMigrations`), the history read API:
  `latest_migration` (the most recent record whatever its status — what a UI
  renders once `get_migration` reports `None` for a finished migration),
  `list_migrations` (newest-first summaries projected in SQL, reading no
  stored PCZTs), and `get_migration_by_id` (one record's full state,
  historical or pending).
- A schema migration giving each pool-migration record a durable identity — a
  `uuid` column (random per row, backfilled for existing rows) and a nullable
  `committed_height` column (`NULL` for rows that predate it) — and rescoping
  the per-account uniqueness of `orchard_ironwood_migrations` to NON-TERMINAL
  rows, so an account retains every finished migration while holding at most
  one in progress.

### Changed
- Migrated to `zcash_pool_migration 0.1.0-rc.7`.
- The pool-migration transactions table's `txid` column is now a `BLOB` holding
  the transaction id's internal bytes, matching how the wallet's own
  `transactions` table keys them; it was hex `TEXT`. An application querying
  this table directly must bind and read raw bytes, and must not route them
  through the display encoding, which is byte-reversed. The
  `orchard_ironwood_migration_txid_blob` migration converts existing rows.
- `WalletWrite::store_transactions_to_be_sent` now upserts each transaction's
  sent-output records, so storing a transaction the wallet has already
  recorded replaces that record instead of failing.
- Persisting a pool-migration state with any terminal status through
  `replace_migration` now releases the note reservations held by its
  never-broadcast transactions, in the same write: a migration superseded in
  response to `Replan` (or marked failed or cancelled through the engine) no
  longer strands its live transfers' locks until they expire.
- Proving a migration transaction no longer writes it into the wallet's own
  transaction tables: `store_proved_transaction` records the proof in the
  migration store alone, and the wallet-side record (raw transaction, sent
  outputs, input spend marks, status-retrieval queue entry) is written by
  `take_transaction_for_broadcast`, atomically with handing out the
  broadcastable bytes. Consequences a consumer can observe: the user's full
  balance remains spendable through the prove-to-broadcast window (the
  reservation is the advisory note lock taken at proving, overridable via a
  `LockedInputPolicy` naming the migration's lock owners); a never-broadcast
  txid is no longer queued for status retrieval (previously disclosed to the
  light wallet server before broadcast); and a pending migration transaction
  no longer appears in `v_transactions` before broadcast.
- `pool_migration::PoolMigrations::get_migration` now reports only the
  migration IN PROGRESS: a migration persisted with a terminal status is
  retained as history rather than returned here, and committing a replacement
  migration no longer destroys the record of the one it replaces. A caller
  that rendered a finished migration from `get_migration` (which now returns
  `None` for it) should use `latest_migration` (or `list_migrations` /
  `get_migration_by_id`) instead.
- A newly committed pool migration's record is stamped with the wallet's chain
  height at first persistence (`MigrationSummary::committed_height`); records
  that predate the column report `None`.
- Wallet truncation now revisits every retained `complete` pool-migration
  record as well as the pending one, so a reorg that un-mines a PREVIOUS
  migration's transfers demotes that record exactly as it always demoted a
  pending migration's state. `failed`, `superseded`, and `cancelled` records
  are policy determinations and are not revisited.
- The `orchard` feature is now enabled by default. Consumers that require a
  smaller feature set should disable default features and enable only the
  features they need.
- A migration transaction is now classified against ZIP 318 when broadcast stores
  it, in the same database transaction as the record itself, rather than only
  once it has mined and been enhanced.
- `WalletWrite::store_transactions_to_be_sent` now likewise classifies each
  transaction as it stores it, so a transaction the wallet built is labelled
  without waiting for it to mine. This covers canonical crossings built through
  the ordinary proposal flow, not only those the pool-migration engine
  constructs.
- Neither change makes the NOT CLASSIFIED default safe to read as a decision.
  Clients must still render it as "no label yet" rather than as "not a migration
  transaction": rows written before the column existed keep that default, and
  need the transaction rescanned before they can be labelled.

### Fixed
- Anchor-checkpoint retention is no longer owed to a migration that has reached
  any terminal status. The grids of `failed`, `superseded`, and `cancelled`
  migrations were retained for the lifetime of the wallet, because retention
  excluded only `complete` migrations; nothing will drive a terminal migration
  further, so those checkpoints were kept for proofs that will never be
  requested and, the migration being terminal, were never revisited.
- `wallet::init::migrations::V_0_8_0` held the leaf state of the 0.8.1 release
  rather than 0.8.0's: the published 0.8.0 crate's final migration was
  `v_transactions_shielding_balance`, with `v_transactions_note_uniqueness`
  following in 0.8.1. The constant now records the true 0.8.0 state, and the
  0.8.1 state it previously held is the new `V_0_8_1`. An external migration
  anchored on `V_0_8_0` now anchors one migration earlier in the graph, which
  cannot invalidate its ordering because every migration `V_0_8_0` previously
  named is still ordered after the corrected state.

## [0.22.0-rc.7] - 2026-08-03

### Added
- A `zip318_kind` column on the `transactions` table, recording how each transaction
  classifies against ZIP 318 so that a wallet can label a pool-migration transaction
  in its history without a migration plan, which does not survive a seed restore.
  The column defaults to the code for NOT CLASSIFIED. The migration deliberately
  does not classify existing rows: those keep the default and need the transaction
  rescanned. A client must render the default as no label, never as "not a
  migration".
- A `zip318_kind` column on `v_transactions`, carrying that value through to the
  view clients read their transaction history from. The mobile SDKs build their
  history types from this view with their own SQL, so the column reaches them
  with no change to any foreign function interface.
- `pool_migration::orchard_ironwood::Error::ChainStateUnavailable`, returned
  when a satisfiability check has no fully-scanned height to observe from.
- `pool_migration::orchard_ironwood::FinalizeError`, and new
  `pool_migration::orchard_ironwood::Error` variants `UnknownTransaction`,
  `NotProved`, `ViewingKeyUnavailable`, `Finalize`, and `Wallet`, reporting
  failures of the store's new proved-transaction finalization.
- `zcash_client_sqlite::testing::db::TestDb::conn` and `TestDb::conn_mut`, for
  tests that open a sibling store (a `pool_migration` `PoolMigrations`, say)
  over the wallet database's own connection.

### Changed
- Migrated to `zcash_client_backend 0.24.0-rc.7`, `zcash_pool_migration 0.1.0-rc.6`.
- `pool_migration::orchard_ironwood::PoolMigrations` now carries the network
  parameters and a clock — `PoolMigrations::for_account` takes them ahead of
  the connection (`for_account(params, clock, conn, account)`; a caller that
  only reads or writes migration state may pass `()` for both, but the
  `PoolMigrationWrite` implementation requires
  `zcash_protocol::consensus::Parameters` and `util::Clock` values) — and
  implements the new `PoolMigrationWrite::store_proved_transaction` (under the
  `orchard` feature) by finalizing the proved migration transaction and
  persisting it to the wallet's own transaction tables, atomically with the
  migration state, in one database transaction: the raw transaction, its fee,
  its outputs as sent notes, and its input notes marked spent. From the moment
  a migration transaction is proved, the wallet therefore reports its inputs
  spent (its own spends can no longer consume them) and its balance reflects
  the pending transaction, rather than neither until the transaction is mined
  and scanned. The `orchard_ironwood_migration_unsatisfiability` schema
  migration renames `orchard_ironwood_migration_transactions.tx_id` to
  `transfer_id`, and `orchard_ironwood_migration_transaction_deps`'s `tx_id`
  and `depends_on_tx_id` to `transfer_id` and `depends_on_transfer_id`;
  applications querying these tables directly must use the new names.
  `orchard_ironwood_migration_tables` is unchanged and still creates the old
  names, so an external migration anchored between the two sees the schema it
  always has.
- The database schema now includes the `unsatisfiable_at`,
  `unsatisfiable_kind`, and `broadcast_failure_at` columns on
  `orchard_ironwood_migration_transactions`, recording the chain height backing
  a spent-input observation when a pool-migration transaction has been
  determined unsatisfiable, which observation that was (`inputs_spent`,
  `inputs_invalidated`, `anchor_invalidated`, or `inherited`), and the chain tip
  a node reported when it REJECTED a broadcast of the transaction; the
  `orchard_ironwood_migration_spend_nullifiers` table, caching each
  transaction's real-spend nullifiers one row per nullifier, ordered by
  `ordinal` and held to 32 bytes by a `CHECK`; and the
  `replan_threshold` column
  on `orchard_ironwood_migrations`, recording the integer percent of planned
  transfer value, unsatisfiable, above which the migration is re-planned
  immediately. `unsatisfiable_at` and `unsatisfiable_kind` are `NULL` together
  or non-`NULL` together, and a row where they disagree — or one naming a kind
  this release does not know — is reported as corrupt. The migration that adds
  these backfills the nullifier cache for existing rows from their
  stored PCZTs — failing with a corrupted-data error for a not-yet-mined row
  whose stored PCZT is already proven (its real spends are no longer
  identifiable, so the cache cannot be reconstructed), and leaving a mined
  row's cache empty — and `replan_threshold` to the default policy;
  `unsatisfiable_kind` and `broadcast_failure_at` need no backfill, since a
  database lacking `unsatisfiable_at` carried neither marks nor
  broadcast-failure reports.
- `WalletWrite::truncate_to_height` (and everything routed through it) now also
  rolls every stored pool migration back to the height it actually truncated
  to, clearing unsatisfiability marks and broadcast-failure reports that rest on
  discarded chain state, demoting transactions recorded mined above it, and
  reverting a `Complete` status the demotion unsettles. Applications that were calling
  `MigrationState::truncate_to_height` themselves from a reorg hook should stop:
  the wallet now does it, in the same database transaction.
- `pool_migration::orchard_ironwood::PoolMigrations` implements the new
  `zcash_pool_migration` `PoolMigrationRead::check_step_satisfiability`
  method, answering each cached real-spend nullifier from the wallet's
  Orchard note and note-spend tables as observed at the fully-scanned height
  (an unrecognized nullifier reads as not-yet-satisfiable). A pool-migration
  TRANSFER that has been broadcast and is not yet mined is additionally
  reported unsatisfiable through `UnsatisfiableCause::AnchorInvalidated` once
  the Orchard anchor installed in its stored proven PCZT is the root of none of
  the tree states the wallet retains, and the fully-scanned height has
  advanced at least the caller's `ReorgSettleDepth` past the boundary the
  transfer anchored to. A broadcast PREPARATION is never so reported: it
  records no anchor boundary, so neither the root to compare against nor the
  height to settle the comparison at is recoverable. Per-input
  `InputObservation::Invalidated` observations are likewise not produced.
- The pool-migration transactions table's `txid` column now holds EVERY row's transaction id,
  recorded when the transaction is built, rather than appearing only once a transaction is
  broadcast. The `orchard_ironwood_migration_unsatisfiability` migration fills it for existing
  rows by DERIVING each id from that row's own stored PCZT, which works whatever the row's
  lifecycle state; it fails with a corrupted-data error naming any row whose stored PCZT yields
  no id.
- `pool_migration::orchard_ironwood::PoolMigrations` implements the new
  `zcash_pool_migration` `PoolMigrationRead::mined_height` method, answering
  from the wallet's own `transactions` table. The answer is bounded by the
  FULLY-SCANNED height rather than the chain tip: `mined_height` is also written
  by transaction-status retrieval, which can learn that a transaction mined
  before scanning reaches its block, and promoting on that would record `Mined`
  above the region a reorg truncation would roll back. An unsynced wallet
  reports nothing mined rather than erroring. Together with the truncation hook
  above, a stored migration's mined heights now follow the wallet's scan in both
  directions with no consumer hook in either.

## [0.22.0-rc.6] - 2026-07-29

### Added
- The additive `ignore-expensive-tests` feature, which compiles expensive tests
  but marks them as ignored for broad `--all-features` test runs.
- `zcash_client_sqlite::testing::db::TestDbFactory::file_backed`, for tests
  that require database reopening or multiple connections.
- The `v_transactions` view has a new `pool_crossing_value` column, which
  classifies wallet-internal transfers that move an account's own funds between
  shielded pools (for example, ZIP 318 Orchard -> Ironwood migration transfers)
  and reports the amount that crossed. It is non-NULL exactly when every
  wallet-spent note and wallet-received output in the transaction is shielded,
  the account spent at least one note, at least one output was received in a
  pool the account spent nothing from, and no external outputs of the
  transaction are known; its value is then the total received in the pools the
  account did not spend from. Use `pool_crossing_value IS NOT NULL` as the
  classification predicate; a separate boolean column would restate that same
  condition in a second place that could drift.

  For such a transaction `account_balance_delta` is just the negated fee, which
  is not a useful display quantity; clients should present `pool_crossing_value`
  as the migrated amount instead of deriving an amount from `total_spent` or
  `total_received`, both of which overstate the crossing whenever the
  transaction also returns change to a pool it spent from.

  A payment that returns value to one of the wallet's own addresses is
  classified once the wallet has observed the returned output (which the
  scanner marks as change); while such a transaction is unmined it is treated
  as an ordinary payment.

### Changed
- Migrated to `zcash_client_backend 0.24.0-rc.6`, `zcash_pool_migration 0.1.0-rc.5`.
- The `pczt-tests` feature flag now also enables this crate's `orchard` and
  `transparent-inputs` features, which `zcash_client_backend/pczt` forces on in the
  backend; enabling `pczt-tests` alone no longer fails to compile.
- `zcash_client_sqlite::testing::db::TestDbFactory::default` and
  `zcash_client_sqlite::testing::BlockCache::default` now use isolated
  in-memory SQLite databases.

### Fixed
- A wallet created by a build that predates the addition of the
  `anchor_bucket_interval` column to `orchard_ironwood_migrations` no longer
  fails every scan. The column was added to the `orchard_ironwood_migration_tables`
  DDL in place; a wallet that had already applied that migration never acquired
  the column, and the committed-grid query issued by `put_blocks` then failed at
  prepare time with `no such column: anchor_bucket_interval`, regardless of
  whether a pool migration was in progress. Because that query runs on every
  scan, no block could be written and no transaction acquired a mined height. A
  new `orchard_ironwood_migration_anchor_interval` migration adds the column
  where it is missing. An existing row is backfilled with the ZIP 318 grid,
  which is exact on the production network but a reconstruction on a test
  network, where a migration planned under a custom grid will be reported as
  `AnchorIntervalMismatch` and must be re-planned.
- Note selection now draws the oldest eligible notes first, ordering by note
  commitment tree position (chain order). Previously notes were drawn in
  scan-discovery order, which for a restored wallet prefers its most recently
  discovered — typically newest — notes.
- The `to_address` column of the `v_tx_outputs` view now reports transparent
  outputs received by the wallet at the transparent receiver address itself,
  rather than at a unified address containing that receiver, and for outputs
  the wallet created, the recipient address recorded at transaction
  construction time now takes precedence over the receiving address.
  Previously, a payment to one of the wallet's own transparent addresses was
  reported with the receiving account's unified address as its `to_address`.

## [0.22.0-rc.5] - 2026-07-28

### Added
- `zcash_client_sqlite::wallet::init::migrations::V_0_20_0`, `V_0_22_0_RC1` and
  `V_0_22_0_RC2`, the leaf migration sets for the releases published since
  0.19.0, so that an external migration can anchor against any published state
  of the migration graph. Release candidates are published crate versions and so
  are covered here; versions that did not change the migration state relative to
  the preceding constant are omitted, as before.
- `zcash_client_sqlite::wallet::init::migrations::ids`, behind the `unstable`
  feature flag, exposing the identifier of each individual internal migration.
  External migrations registered via `WalletMigrator::with_external_migrations`
  can be anchored against a specific internal migration where the per-release
  constants (such as `migrations::V_0_19_0`) are not precise enough — in
  particular when depending on schema added since the most recent release. These
  identifiers are unstable: the set of them changes between releases, so they are
  intended for development against unreleased schema, with the anchor moved to
  the release constant that covers it once that release exists.
- `zcash_client_sqlite::error::SqliteClientError::BackendError` and the
  `zcash_client_sqlite::error::BackendError` it wraps, reported when a
  `zcash_client_backend` error value carries a variant this crate has no
  translation for; the wrapped value carries the originating error. Those error
  types are `#[non_exhaustive]`, so this is unreachable with the
  `zcash_client_backend` release this crate is built against; it exists so that
  a variant added upstream degrades to a diagnosable error rather than a
  compilation failure.

### Changed
- Migrated to `zcash_client_backend 0.24.0-rc.5`,
  `zcash_pool_migration 0.1.0-rc.4`.
- Every public error enum in this crate is now `#[non_exhaustive]`, so that
  future variants can be added without a breaking release. A `match` over any
  of them must now include a wildcard arm: `error::SqliteClientError`,
  `FsBlockDbError`, `pool_migration::error::Error`,
  `wallet::commitment_tree::Error`, `wallet::init::WalletMigrationError`, and
  `zewif::ZewifImportError`.

### Fixed
- Transaction status requests are now generated from explicit, durable
  observation intent. A sent transaction is queried by txid when this wallet
  cannot observe one of its shielded spends or outputs, including transactions
  funded entirely by transparent inputs whose shielded outputs all belong to
  another wallet. Status intent remains dormant while a transaction is mined
  and becomes active again after a chain rewind. Redundant status requests
  previously synthesized for wallet-observable shielded transactions are no
  longer produced.
- An Ironwood note received on an account's internal address is now classified as
  change once the wallet learns that the same account funded the transaction.
  This was previously applied to Sapling and Orchard notes only, so an Ironwood
  note recorded before its transaction's spends could be linked to the wallet
  kept the wrong classification permanently: `v_transactions` counted it in
  `received_note_count` and `sent_note_count` rather than reporting `has_change`,
  and `v_tx_outputs` reported the account's own change as a non-change output,
  which presents it to the user as a recipient of their own transaction. Balances
  were not affected. Notes already recorded with the wrong classification are
  repaired on upgrade by a new migration; no rescan is required.
- An address that had received only Ironwood notes was treated as never having
  been used. Such an address was still considered unused by the transparent
  address gap-limit search, so it could be handed out again, and the account
  that received the note was not reported as being involved in the transaction
  that paid it. Since NU6.3 every payment to an Orchard receiver is delivered
  in the Ironwood bundle, so this affected ordinary received payments. A
  migration corrects the affected view; no caller action is required beyond
  upgrading.
- The funding account reported for a transparent output by
  `zcash_client_backend::wallet::WalletTransparentOutput::funding_account` now
  takes value spent from the Ironwood pool into account. Ironwood inputs were
  not counted, so an output whose creating transaction was funded entirely from
  Ironwood reported no funding account, and one funded from several pools could
  report an account other than the largest contributor. Post-NU6.3 wallets hold
  their shielded value in Ironwood, so this affected ordinary spends rather than
  only unusual ones.

## [0.22.0-rc.4] - 2026-07-26

### Changed
- Migrated to `zcash_client_backend 0.24.0-rc.4`,
  `zcash_pool_migration 0.1.0-rc.3`.

## [0.22.0-rc.3] - 2026-07-26

### Changed
- Migrated to `zcash_client_backend 0.24.0-rc.3`,
  `zcash_pool_migration 0.1.0-rc.2`.

## [0.22.0-rc.2] - 2026-07-24

### Added
- `WalletDb` now implements the new `zcash_client_backend` storage-trait
  methods `WalletRead::get_wallet_recover_until`,
  `WalletWrite::prune_scan_queue_below`, and
  `WalletCommitmentTrees::{get_sapling_subtree_root, get_orchard_subtree_root,
  get_ironwood_subtree_root}`.
- `WalletDb::get_unspent_ironwood_notes_at_historical_height` returns all Ironwood
  notes that existed and were unspent at a given height.
- `WalletDb::transactionally_with_extension` performs wallet operations and writes to
  application-owned extension tables (created via
  `WalletMigrator::with_external_migrations`) atomically within a single database
  transaction. It provides the closure with an `ExtensionTransaction` handle sharing that
  transaction.
- `ExtensionTransaction` is a restricted statement executor whose `execute` and
  `query_row` methods run each statement under a SQLite authorizer. The authorizer allows
  reads against any table, allows `INSERT`/`UPDATE`/`DELETE` only against tables whose
  names begin with the `ext_` prefix reserved for external migrations, and denies
  everything else (DDL, `PRAGMA`, `ATTACH`/`DETACH`, and transaction control).
- `zewif::ZewifImportReport::addresses_never_exposed` counts transparent
  addresses recorded in a ZeWIF document that are not known to have been
  exposed, and which are therefore deliberately left unexposed on import.
- `zcash_client_sqlite::pool_migration` implements `zcash_pool_migration`'s
  `PoolMigrationRead` / `PoolMigrationWrite` store traits over tables in the
  wallet database, persisting each account's in-progress Orchard -> Ironwood
  value-pool migration (ZIP 318) independently. The store is constructed via
  `PoolMigrations::for_account`, scoped to the account whose migration it
  tracks; the underlying `orchard_ironwood_migrations` table enforces at most
  one migration per account.
- `zcash_client_sqlite::pool_migration::PoolMigrations::migration_lock_owners`
  returns the set of `LockOwner`s under which an account's in-progress pool
  migration has reserved notes. A proposal can pass this set to a
  `LockedInputPolicy` override (`SpendPolicy::with_locked_input_policy`) so it
  may draw on the migration's own locked notes without disturbing any other
  flow's locks.
- A database migration adds `lock_expiry_height` and `lock_owner` columns to the
  `sapling_received_notes`, `orchard_received_notes`, `ironwood_received_notes`,
  and `transparent_received_outputs` tables to support explicit note locking
  during concurrent proposal creation: `lock_expiry_height` bounds how long a
  lock lasts, and `lock_owner` records the flow that acquired it.
- `zcash_client_sqlite::WalletDb::with_anchor_retention_interval` configures the
  interval on which the wallet retains note commitment tree checkpoints as
  durable anchors, for use on test networks where waiting out the ZIP 318
  144-block interval makes exercising a pool migration impractical. The setting
  governs what grid the next migration is planned against; the grid an in-flight
  migration was committed under is recorded with it and keeps being retained
  regardless, so reopening the wallet without reapplying the setting cannot
  strand a migration.
- `zcash_client_sqlite::WalletDb::set_anchor_retention_interval`, the
  by-reference form of `with_anchor_retention_interval`.

### Changed
- Migrated to `zcash_primitives 0.30.0`, `zcash_transparent 0.10.0`,
  `zcash_proofs 0.30.0`, `zcash_keys 0.16.0`, `zcash_client_backend 0.24.0-rc.2`.
- The `zip-233` feature flag now also enables `zcash_client_backend/zip-233`,
  keeping the two crates' feature-gated `zcash_primitives` call signatures in
  agreement when this crate is built with ZIP 233 support.
- `WalletWrite::truncate_to_height` now accepts a truncation height that a
  pool's note commitment tree checkpoints do not cover whenever the truncation
  leaves that pool's tree in a consistent state — the same per-pool tolerances
  applied by `rewind_to_chain_state` (see under "Fixed" above). Callers that
  relied on `RequestedRewindInvalid` being returned for such heights should
  note that the truncation now succeeds, resetting any tree whose scanned
  contents lie entirely above the truncation height to only the roots of
  subtrees completed at or below it.


### Fixed
- The coinbase branch of the transparent account-balance tally now classifies
  locked value into `Balance::locked_value`: previously a mature coinbase UTXO
  locked by an in-flight shielding proposal was still reported as spendable,
  even though note selection (correctly) refused to select it.
- The `zewif` importer no longer marks transparent addresses that have no
  recorded exposure height (`zewif::Address::exposed_at_height() == None`, e.g.
  zcashd keypool reserves) as exposed unconditionally. Previously every such
  address was marked exposed at the account birthday, which could exhaust the
  transparent gap limit (in particular the small internal/change gap) and
  permanently block change-address reservation after a zcashd migration. Such an
  address is now treated as exposed only if the wallet already considers it so
  (which, since the document's transactions are imported first, covers every
  address those transactions show to have been used on-chain, change addresses
  included), or if the document exposes an address at a higher child index under
  the same account and key scope, since transparent addresses are handed out in
  index order.
- `WalletWrite::rewind_to_chain_state` no longer reports `CorruptedData` for a
  shielded pool whose note commitment tree checkpoints do not cover the rewind
  target, provided the truncation leaves that pool's tree in a consistent
  state. On an upgraded wallet, the `orchard_shardtree` or `ironwood_shardtree`
  migration creates the pool's tree tables empty and requeues a rescan; until
  that rescan catches up, the pool's checkpoints may be absent entirely, may
  all lag the rewind target (a backfill in progress), or may all lie above it
  (a rescan that has so far only reached tip-priority blocks near the chain
  tip). All of these states are now tolerated: an empty or lagging tree is left
  untouched, while a tree whose checkpoints all postdate the target is reset to
  only the roots of subtrees completed at or below the target (preserving
  subtree roots downloaded during fast sync, which are required to construct
  witnesses spanning those subtrees), with the rescan re-creating the rest — in
  either case without destroying any note witness that the rescan would not
  re-create. This previously caused
  account creation and import (which rewind via this method) to fail
  deterministically on an upgraded, already-scanned wallet until its NU6.3
  rescan had caught up. A rewind that cannot be executed because it would
  destroy witness data that the rescan would not re-create is refused as
  `RequestedRewindInvalid` (it reflects valid wallet state, not corruption); a
  pool whose checkpoints lie both above and below the truncation height
  without one at it is still reported as corruption.
- Value in immature transparent coinbase outputs is now reported as pending
  spendability (in the `value_pending_spendability` field of the coinbase
  bucket) in wallet-summary account balances. Previously it was incorrectly
  counted as spendable before the coinbase output reached maturity, even
  though it could not be selected for shielding.

## [0.22.0-rc.1] - 2026-07-12

### Added
- `WalletDb` implements the new
  `WalletWrite::import_standalone_transparent_pubkeys` batch method (behind the
  `transparent-key-import` feature flag), resolving the target account a single
  time for the whole batch.
- `WalletDb` now implements the new
  `WalletWrite::reserve_next_n_internal_addresses` method (behind the
  `transparent-inputs` feature flag), reserving internal-scope (change)
  transparent addresses subject to the internal-scope gap limit. This is used
  to allocate recipient addresses for non-ephemeral transparent change
  outputs when a change strategy is configured with
  `zcash_client_backend::fees::TransparentChangePolicy::TransparentChangeAllowed`.
  No new migration is required: internal-scope gap addresses are already
  generated at account creation, and received transparent change outputs are
  recorded via the existing `Recipient::InternalTransparent` handling.
- A new migration adds a `note_version` column to `orchard_received_notes`,
  recording the note plaintext version from which each received note was
  obtained. The Orchard note encryption domain accepts only version 2 note
  plaintexts, so existing rows are backfilled as version 2.
- A new migration adds the `ironwood_received_notes` and
  `ironwood_received_note_spends` tables, mirroring the corresponding Orchard
  tables. Received notes obtained from version 3 (Ironwood) note plaintexts
  are recorded in `ironwood_received_notes`; Ironwood notes are stored
  separately from Orchard notes because the two pools have distinct note
  commitment trees, and because an Orchard action and an Ironwood action in
  the same transaction may share an action index.
- A new migration recreates the `v_received_outputs` and
  `v_received_output_spends` views to include received Ironwood notes and their
  spends, tagged with the Ironwood pool code (4). Ironwood notes now appear in
  `v_transactions`, `v_tx_outputs`, and the balances derived from them.
- The wallet database now persists Ironwood note commitment tree data. A new
  migration adds the `ironwood_tree_shards`, `ironwood_tree_cap`,
  `ironwood_tree_checkpoints`, and `ironwood_tree_checkpoint_marks_removed`
  tables (mirroring the Orchard shard-tree tables), the
  `ironwood_commitment_tree_size` and `ironwood_action_count` columns on
  `blocks`, and the `v_ironwood_shard_scan_ranges`,
  `v_ironwood_shard_unscanned_ranges`, and `v_ironwood_shards_scan_state` views.
  The `WalletCommitmentTrees::with_ironwood_tree_mut` implementation now provides
  the persisted Ironwood tree (Ironwood note commitments are Orchard-shaped, so
  the tree reuses the Orchard shard store under a separate table prefix).
- Block scan-range planning now extends suggested scan ranges to complete
  Ironwood note commitment tree subtrees when Ironwood notes are detected,
  mirroring the existing Sapling and Orchard behavior. The extension activates at
  NU6.3.
- A new database migration adds `sapling_tree_retained_checkpoints` and
  `orchard_tree_retained_checkpoints` tables that back explicit retention of
  note commitment tree checkpoints as durable "anchors". `SqliteShardStore`
  now implements the `shardtree` retained-checkpoint store methods, and once
  the NU6.3 activation height is reached scanning retains roughly four anchors
  per day (see the `zcash_client_backend` changelog).
- `zcash_client_sqlite::error::SqliteClientError::PutBlocksCommitmentTree`, a
  new variant that records the shielded pool and the range of block heights
  being added to the wallet when a note commitment tree error occurs during a
  `put_blocks` operation. Previously such errors (for example a `shardtree`
  `InsertionError::Conflict` raised by `insert_frontier`) surfaced as the
  generic `CommitmentTree` variant, which only reported the conflicting tree
  node address and not the affected pool or block range.
- `zcash_client_sqlite::error::SqliteClientError::TruncateCommitmentTree`, a
  new variant that records the shielded pool and the block height that the
  wallet was being truncated to when a note commitment tree error occurs
  during a truncation operation (`truncate_to_height` or
  `truncate_to_chain_state`). Previously such errors surfaced as the generic
  `CommitmentTree` variant without the affected pool or target height.
- The `InputSource::get_spendable_transparent_outputs` implementation now
  accepts `CoinbaseFilter::NonCoinbaseOnly`, restricting the SQL query to
  outputs that are not from coinbase transactions. Outputs with an unknown
  `tx_index` are treated as non-coinbase.
- Added an implementation of `InputSource::select_spendable_transparent_outputs`
  (behind the `transparent-inputs` feature flag). The query orders eligible
  outputs by descending value (backed by a new
  `idx_transparent_received_outputs_value_zat` index) and accumulates them,
  recomputing the cumulative ZIP 317 marginal fee cost of the gathered
  inputs via the supplied `fee_rule: &StandardFeeRule` at each step, stopping
  once the post-fee accumulated value meets the requested `TargetValue` or
  the supplied `max_inputs` cap is reached, whichever happens first. This
  bounds the work done to the prefix of the table needed to satisfy the
  request, so a wallet with many small transparent UTXOs does not have to
  materialize its full UTXO set to build a small transfer. When an
  `address_allow_list` is supplied, the restriction to the given addresses is
  applied within the SQL query, so that ineligible outputs do not consume
  the value bound.
- `zcash_client_sqlite::error::SqliteClientError::FeeRuleError`, a new variant
  (behind the `transparent-inputs` feature flag) that wraps an error produced
  by a `FeeRule` during transparent input selection.
- `WalletDb::generate_ironwood_witnesses_at_historical_height`, which mirrors
  the existing Orchard historical witness helper over the wallet's Ironwood
  commitment tree shard tables.
- A new `zewif` feature flag adds the `zcash_client_sqlite::zewif` module for
  importing wallets from the Zcash Wallet Interchange Format (ZeWIF).
  `zewif::import_wallet` ingests a ZeWIF document into an already-initialized
  `WalletDb` within a single transaction, delivering any encountered spending-key
  material to a caller-supplied `zewif::SecretSink` (use `zewif::DiscardSecrets`
  to drop it, e.g. for a view-only import) and returning a
  `zewif::ZewifImportReport` describing the imported and skipped items. Import
  failures are reported via `zewif::ZewifImportError`.

### Changed
- MSRV is now 1.88
- Migrated to `zcash_protocol 0.10.0`, `zcash_address 0.13.0`,
  `zcash_transparent 0.9.0`, `zip321 0.9.0-rc.1`, `zcash_keys 0.15.0`,
  `zcash_primitives 0.29.0`, `zcash_proofs 0.29.0`,
  `orchard 0.15`, `shardtree 0.7`, `zcash_client_backend-0.24.0-rc.1`.
- (behind the new `spend-index` feature) `WalletRead::transaction_data_requests`
  emits `TransactionDataRequest::GetSpendingTx` for transparent spend
  detection instead of `TransactionDataRequest::TransactionsInvolvingAddress`.
  `TransactionsInvolvingAddress` is still emitted for ephemeral-address discovery,
  and for spend detection when `spend-index` is disabled.
- The database schema now includes a `UNIQUE` index on
  `addresses.cached_transparent_receiver_address`, making account-by-transparent-address
  lookups index-backed (previously a full table scan) and enforcing that each transparent
  receiver belongs to at most one address record. If a pre-existing database already contains
  duplicate cached transparent receiver addresses, the migration that adds the index resolves
  them in place: within a single account it keeps a canonical record (preferring an HD-derived
  record over an imported one), repoints the affected received outputs to it, and deletes the
  redundant records, preserving the earliest recorded `exposed_at_height` among the merged
  records. A receiver duplicated across more than one account is resolved by derivation:
  when exactly one of the records reproduces the receiver when derived from its own account's
  viewing key at its recorded child index, that record is retained and the received outputs of
  the others are reattributed to it (this can occur for wallets migrated from `zcashd`, where an
  address may have been both imported standalone into one account and derived by another,
  including under the ZIP 32 account index 0x7FFFFFFF used for the `zcashd` legacy account).
  A cross-account duplicate for which no unique record can be verified by derivation causes
  the migration to abort.

## [0.21.1] - 2026-06-19

### Fixed
- Fixed a bug in `WalletDb::delete_account` that caused it to fail with
  `rusqlite::Error::InvalidParameterName(":address")` when the account being
  deleted was referenced by a `sent_notes` row via its `to_account_id` column
  (for example, after an internal transfer to an address belonging to the
  account being deleted). The `sent_notes` update statement bound a parameter
  named `:address` while the SQL expected `:to_address`.

## [0.21.0] - 2026-06-02

### Changed
- Migrated to `zcash_protocol 0.9.0`, `zcash_address 0.12.0`, `zcash_transparent 0.8.0`, `zip321 0.8.0`, `zcash_keys 0.14.0`, `zcash_primitives 0.28.0`, `zcash_proofs 0.28.0`.

### Fixed
- Updated to crate versions that fix an Orchard soundness vulnerability
  (GHSA-ww9q-8r59-xv46) and Orchard non-canonical proof size issue
  (GHSA-2x4w-pxqw-58v9).

## [0.20.2] - 2026-05-07

### Fixed
- Scan-progress accounting (`subtree_scan_progress`) no longer counts outputs
  from blocks whose enclosing scan-queue range has been re-queued for
  scanning. Previously, a wallet that had scanned blocks and then re-queued
  the corresponding range (for example as a consequence of adding a new
  account whose birthday lies within already-scanned territory) would
  over-report scan progress, because the re-queued blocks remained in the
  `blocks` table and were still counted as scanned.

## [0.20.1] - 2026-05-06

### Fixed
- This release fixes a bug in progress estimation that can occur when rewinding
  to a height prior to any existing wallet birthday as a consequence of adding
  an account.

## [0.20.0] - 2026-04-27

### Added
- The following columns have been added to the exposed `v_tx_outputs` view:
  - `transaction_id`
  - `tx_mined_height`
  - `tx_trust_status`
  - `recipient_key_scope`
- `zcash_client_sqlite::TxRef`
- `impl<'a> Borrow<rusqlite::Transaction<'a>> for zcash_client_sqlite::SqlTransaction<'a>`
- `impl zcash_client_backend::data_api::ll::LowLevelWalletRead for WalletDb`
- `impl zcash_client_backend::data_api::ll::LowLevelWalletWrite for WalletDb`
- `impl Hash for zcash_client_sqlite::{ReceivedNoteId, UtxoId, TxRef}`
- `impl {PartialOrd, Ord} for zcash_client_sqlite::UtxoId`
- `impl zcash_keys::keys::transparent::gap_limits::AddressStore for WalletDb`
  (behind the `transparent-inputs` feature flag)
- `zcash_client_sqlite::AccountRef` is now public.
- `impl<'conn, P, CL, R> WalletWrite for WalletDb<SqlTransaction<'conn>, P, CL, R>` to
  enable calling `WalletWrite` methods inside `WalletDb::transactionally` (amortizing the
  database transaction overhead).
- `WalletDb::get_unspent_orchard_notes_at_historical_height` returns all Orchard
  notes that existed and were unspent at a given height.
- `WalletDb::generate_orchard_witnesses_at_historical_height` generates Merkle
  witnesses at a historical height using an ephemeral in-memory
  `shardtree::store::memory::MemoryShardStore`.
- Two new `orchard`-gated variants have been added to
  `zcash_client_sqlite::error::SqliteClientError` to surface the failure modes
  of `WalletDb::generate_orchard_witnesses_at_historical_height`:
  - `HistoricalFrontierInvalid(shardtree::error::InsertionError)` —
    the caller-supplied frontier is inconsistent with the shard data
    reconstructed from the wallet at the requested height.
  - `HistoricalWitnessUnavailable { position, height }` — no witness can be
    produced for the specified position at the specified height (the wallet
    most likely has not synced through that height).
  Shard-read failures continue to surface via the existing
  `SqliteClientError::CommitmentTree` variant.

### Changed
- Migrated to `sapling-crypto 0.7`, `orchard 0.13`, `zcash_encoding 0.4`,
  `zcash_protocol 0.8`, `zcash_address 0.11`, `zip321 0.7`, `zcash_transparent 0.7`,
  `zcash_primitives 0.27`, `zcash_proofs 0.27`, `zcash_keys 0.13`, `pczt 0.6`,
  `zcash_client_backend 0.22`
- The `accounts` table now stores IVK item caches instead of FVK item caches for
  collision detection. A new `p2sh_ivk_item_cache` column is reserved for future
  ZIP 316 Revision 2 P2SH support.
- Account collision detection now uses IVK-based matching, which catches collisions
  between FVK-imported and IVK-imported accounts. Importing an FVK over an existing
  IVK-only account is treated as a capability upgrade if the existing IVK items are
  a subset of those derivable from the new FVK.
- The `InputSource::get_spendable_transparent_outputs` implementation now
  accepts an `output_filter: TransparentOutputFilter` parameter. When set to
  `CoinbaseOnly`, the SQL query restricts results to outputs from coinbase
  transactions (identified by `tx_index = 0`).
- Migrated to `orchard 0.13`, `sapling-crypto 0.7`.
- Renamed `zcash_client_sqlite::error::PubkeyImportConflict` to
  `zcash_client_sqlite::error::StandaloneImportConflict`
- P2SH UTXOs returned by `get_spendable_transparent_outputs` now include a
  precomputed input size for accurate ZIP 317 fee estimation.
- Added a `witness_stabilized` column to the `sapling_received_notes` and
  `orchard_received_notes` tables. The column is set to 1 at the end of each
  scan batch (and once as a backfill by the `witness_stabilized_notes`
  migration) for notes whose containing shard is fully Scanned and whose
  `subtree_end_height` has received at least `PRUNING_DEPTH` confirmations.

### Removed
- `zcash_client_sqlite::GapLimits` use `zcash_keys::keys::transparent::GapLimits` instead.
- `zcash_client_sqlite::UtxoId` contents are now private.
- The inadvertently-exposed `zcash_client_sqlite::chain::migrations::blockmeta::init`
  module has been removed from the public API.

### Fixed
- `get_transparent_balances` no longer fails for standalone transparent addresses
  that have no `TransparentKeyScope`. Previously, it would error when encountering
  a `KeyScope` that could not be converted to a `TransparentKeyScope`.
- Notes are now consistently treated as having "uneconomic value" if their value is less
  than **or equal to** the marginal fee. Previously, some call sites only considered
  note uneconomic if their value was less than the marginal fee.

## [0.19.5] - 2026-03-10

### Fixed
- The following APIs no longer crash in certain regtest mode configurations with
  fewer NUs active:
  - `WalletDb::{create_account, import_account_hd, import_account_ufvk}`
  - `WalletDb::get_wallet_summary`
  - `WalletDb::truncate_to_height`

## [0.18.12, 0.19.4] - 2026-02-26

### Fixed
- Updated to `shardtree 0.6.2` to fix a note commitment tree corruption bug.

## [0.19.3] - 2026-02-19

### Fixed
- Migration no longer crashes in regtest mode.

## [0.18.11, 0.19.2] - 2026-01-30

### Fixed
- Migration no longer fails for wallets last written with certain older versions
  of the crate.

## [0.18.10, 0.19.1] - 2025-11-25

### Fixed
- Fixes a SQL bug that causes unspent note metadata queries to fail.

## [0.19.0] - 2025-11-05

### Added
- `zcash_client_sqlite::wallet::init::migrations::V_0_19_0`

### Changed
- MSRV is now 1.85.1.
- Migrated to `zcash_protocol 0.7`, `zcash_address 0.10`, `zip321 0.6`,
  `zcash_transparent 0.6`, `zcash_primitives 0.26`, `zcash_proofs 0.26`,
  `prost 0.14`, `rusqlite 0.37`.
- The implementation of `zcash_client_backend::WalletWrite` for `WalletDb` has
  additional type constraints. The `R` type parameter is now constrained to
  types that implement `RngCore`.
- The default gap limit for ephemeral address generation has been changed from
  5 addresses to 10. Now that ephemeral addresses are being used for more
  single-use-address use cases than just transactions sending to TEX addresses,
  the case that there will be a series of unused addresses (for example, for
  swap refunds) becomes more common.

### Fixed
- A bug was fixed in `WalletDb::get_transaction` that could cause transaction
  retrieval to return an error instead of `None` for transactions for which the
  raw transaction data was not available.

## [0.18.9] - 2025-10-22

### Fixed
- Fixes a problem whereby dust-valued transparent outputs in the wallet could
  disrupt shielding operations.
- Fixes a bug wherein `WalletDb::get_transparent_balances` was returning
  balance for ephemeral addresses, contradicting its documented requirements.

## [0.18.8] - YANKED

## [0.18.7] - 2025-10-16

### Fixed
- Fixes a data persistence error that could result in a violation of the
  `transactions.min_observed_consistency` constraint.

## [0.18.6] - 2025-10-16

### Fixed
- Fulfilled transaction enhancement requests are now deleted once it is
  determined that there is no wallet involvement with the transaction.

## [0.18.5] - 2025-10-14

### Changed
- This release regularizes our approach to determining when outputs belonging
  to the wallet are unspent. We now track the block height at which we first
  observe a transaction; for transactions discovered by scanning the mempool
  and transactions generated by the wallet, this is equivalent to the mempool
  "height".
- This release introduces a more robust approach to the management of
  transaction status requests. It ensures that we continue to query for
  transaction status for a given transaction until we have positive
  confirmation that either:
    - the transaction has definitely expired, or
    - if expiry information is unavailable, that the transaction has not been
      mined for at least 140 blocks since the block height at which we first
      observed the transaction.

## [0.18.4] - 2025-10-08

### Fixed
- This modifies balance calculation to explicitly ignore balance held in
  ephemeral addresses. This will be altered in a future release; at present,
  the only use of ephemeral addresses is as interstitial addresses in TEX
  address transfers, and so it is safe to ignore these funds. Funds would only
  appear in the case of a partial TEX transfer failure or funds being returned
  to a TEX address, which would not be detected by normal scanning but which
  could be detected by the new mempool detection logic implemented by Zashi.

## [0.18.3] - 2025-09-30

### Changed
- The `zcash_client_sqlite` implementation of `WalletWrite::update_chain_tip`
  now ensures that a transaction status request is queued for any transactions
  for which we do not have mined-height information and which are known to be
  unexpired.
- Transaction status requests are no longer deleted until the transaction in
  question is positively known to be expired.

## [0.18.2] - 2025-09-28

### Changed
- The `zcash_client_sqlite` implementation of `InputSource::get_unspent_transparent_output`
  now correctly selects transparent UTXOs with zero confirmations.

## [0.18.1] - 2025-09-25

### Fixed
- This fixes a bug in zcash_client_sqlite-0.18.0 that could result in
  underreporting of wallet balance.

## [0.18.0] - YANKED

### Added
- A `zcashd-compat` feature flag has been added in service of being able to
  import data from the zcashd `wallet.dat` format. For additional information
  refer to the `zcash_client_backend 0.20.0` release notes.
- `zcash_client_sqlite::wallet::init::migrations::V_0_18_0`

### Changed
- Migrated to `zcash_protocol 0.6`, `zcash_address 0.9`, `zip321 0.5`,
  `zcash_transparent 0.5`, `zcash_primitives 0.25`, `zcash_proofs 0.25`,
  `zcash_keys 0.11`, `zcash_client_backend 0.20`.
- Added dependency `secp256k1` when the `transparent-inputs` feature flag
  is enabled.
- `zcash_client_sqlite::error::SqliteClientError`:
  - An `IneligibleNotes` variant has been added. It is produced when
    `spendable_notes` is called with `TargetValue::MaxSpendable`
    and there are funds that haven't been confirmed and all spendable notes
    can't be selected.
  - A `PubkeyImportConflict` variant has been added. It is produced when
    a call to `WalletWrite::import_standalone_transparent_pubkey` attempts
    to import a transparent pubkey to an account when that pubkey is already
    managed by a different account.
- The `v_tx_outputs` view now includes an additional `diversifier_index_be`
  column, containing the diversifier index (or transparent change-level BIP 44
  index) of the receiving address as a BLOB in big-endian order for received
  outputs. In addition, the `to_address` field is now populated both for sent
  and received outputs; for received outputs, it corresponds to the wallet
  address at which the output was received. For wallet-internal outputs,
  `to_address` and `diversifier_index_be` will be `NULL`.
- `WalletDb::get_tx_height` will now return heights for transactions detected
  via UTXOs, before their corresponding block has been scanned for shielded
  details.

## [0.17.3] - 2025-08-29

### Fixed
- This release fixes possible false positive in the way that the
  `expired_unmined` column of the `v_transactions` view is computed. It now
  checks against the `mined_height` field of the UTXO, instead of joining
  against the `blocks` table to determine whether the UTXO has expired unmined;
  after this change, the corresponding block need not have been scanned in
  order to correctly determine whether the UTXO actually expired.

## [0.16.4, 0.17.2] - 2025-08-19

### Fixed
- `TransactionDataRequest::GetStatus` requests for txids that do not
  correspond to unexpired transactions in the transactions table are now
  deleted from the status check queue when `set_transaction_status` is
  called with a status of either `TxidNotRecognized` or `NotInMainChain`.
- This release fixes a bug that caused transparent UTXO value to be
  double_counted in the wallet summary, contributing to both spendable and
  pending balance, when queried with `min_confirmations == 0`.
- Transaction fees are now restored when possible by calls to
  `WalletDb::store_decrypted_tx`.

## [0.16.3, 0.17.1] - 2025-06-17

### Fixed
- `TransactionDataRequest`s will no longer be generated for coinbase inputs
  (which are represented as having the all-zeros txid).

## [0.17.0] - 2025-05-30

### Added
- `zcash_client_sqlite::wallet::init::WalletMigrator`
- `zcash_client_sqlite::wallet::init::migrations`
- `zcash_client_sqlite::WalletDb::params`

### Changed
- Migrated to `zcash_address 0.8`, `zip321 0.4`, `zcash_transparent 0.3`,
  `zcash_primitives 0.23`, `zcash_proofs 0.23`, `zcash_keys 0.9`, `pczt 0.3`,
  `zcash_client_backend 0.19`
- `zcash_client_sqlite::wallet::init::WalletMigrationError::`
  - Variants `WalletMigrationError::CommitmentTree` and
    `WalletMigrationError::Other` now `Box` their contents.

## [0.16.2] - 2025-04-02

### Fixed
- This release fixes a migration error that could cause some wallets
  to crash on startup due to an attempt to associate a received transparent
  output with an address that does not exist in the wallet's `addresses`
  table.

## [0.16.1] - 2025-03-26

### Fixed
- This release fixes a migration error that could cause some wallets
  to crash on startup due to an attempt to derive a unified address with
  a Sapling receiver at an index for which no Sapling receiver can exist.

## [0.16.0] - 2025-03-19

### Added
- `zcash_client_sqlite::WalletDb::with_gap_limits`
- `zcash_client_sqlite::GapLimits`
- `zcash_client_sqlite::util`
- `zcash_client_sqlite::schedule_ephemeral_address_checks` has been added under
  the `transparent-inputs` feature flag.
- `zcash_client_sqlite::wallet::transparent::SchedulingError`

### Changed
- Updated to `zcash_keys 0.8`, `zcash_client_backend 0.18`
- `zcash_client_sqlite::WalletDb` has added fields and type parameters:
    - a `clock` field and corresponding type parameter. Tests that make use of
      `WalletDb` now use a `zcash_client_sqlite::util::FixedClock` for this
      field value.
    - an `rng` field and corresponding type parameter. Tests that make use of
      `WalletDb` now use a `ChaChaRng` value initialized with the all-zeros
      seed for this field value.
    - the following methods have been changed to accept additional parameters
      as a result of these changes:
      - `WalletDb::for_path`
      - `WalletDb::from_connection`
      - `wallet::init::init_wallet_db` has additional type constraints
- `zcash_client_sqlite::WalletDb::get_address_for_index` now returns some of
  its failure modes via `Err(SqliteClientError::AddressGeneration)` instead of
  `Ok(None)`.
- `zcash_client_sqlite::error::SqliteClientError` variants have changed:
  - The `EphemeralAddressReuse` variant has been removed and replaced
    by a new generalized `AddressReuse` error variant.
  - The `ReachedGapLimit` variant no longer includes the account UUID
    for the account that reached the limit in its payload. In addition
    to the transparent address index, it also contains the key scope
    involved when the error was encountered.
  - A new `DiversifierIndexReuse` variant has been added.
  - A new `Scheduling` variant has been added.
- Each row returned from the `v_received_outputs` view now exposes an
  internal identifier for the address that received that output. This should
  be ignored by external consumers of this view.

## [0.15.0] - 2025-02-21

### Added
- `zcash_client_sqlite::WalletDb::from_connection`
- `zcash_client_sqlite::WalletDb::check_witnesses`
- `zcash_client_sqlite::WalletDb::queue_rescans`

### Changed
- MSRV is now 1.81.0.
- Migrated to `bip32 =0.6.0-pre.1`, `nonempty 0.11`.`incrementalmerkletree 0.8`,
  `shardtree 0.6`, `orchard 0.11`, `sapling-crypto 0.5`, `zcash_encoding 0.3`,
  `zcash_protocol 0.5`, `zcash_address 0.7`, `zcash_transparent 0.2`,
  `zcash_primitives 0.22`, `zcash_keys 0.7`, `zcash_client_backend 0.17`.
- `zcash_client_sqlite::wallet::init::init_wallet_db` now has an additional
  generic parameter, enabling it to be used with wallets constructed via
  `WalletDb::from_connection`.
- The `v_transactions` view has added columns `total_spent` and `total_received`.

## [0.14.0] - 2024-12-16

### Added
- `zcash_client_sqlite::AccountUuid`

### Changed
- Migrated to `sapling-crypto 0.4`, `zcash_keys 0.6`, `zcash_primitives 0.21`,
  `zcash_proofs 0.21`, `zcash_client_backend 0.16`
- The `v_transactions` view has been modified:
  - The `account_id` column has been replaced with `account_uuid`.
- The `v_tx_outputs` view has been modified:
  - The `from_account_id` column has been replaced with `from_account_uuid`.
  - The `to_account_id` column has been replaced with `to_account_uuid`.
- The `WalletRead` and `InputSource` impls for `WalletDb` now set the `AccountId`
  associated type to `AccountUuid`.
- Variants of `SqliteClientError` have changed:
  - The `AccountCollision` and `ReachedGapLimit` now carry `AccountUuid` values
    instead of `AccountId`s.
  - `SqliteClientError::AccountIdDiscontinuity` has been removed as it is now
    unused.
  - `SqliteClientError::AccountIdOutOfRange` has been renamed to
    `Zip32AccountIndexOutOfRange`.

### Removed
- `zcash_client_sqlite::AccountId` (use `AccountUuid` instead).

## [0.13.0] - 2024-11-14

### Added
- Exposed `AccountId::from_u32` and `AccountId::as_u32` conversions under the
  `unstable` feature flag.

### Changed
- MSRV is now 1.77.0.
- Migrated to `zcash_primitives 0.20`, `zcash_keys 0.5`,
  `zcash_client_backend 0.15`.
- Migrated from `schemer` to our fork `schemerz`.
- Migrated to `rusqlite 0.32`.
- `error::SqliteClientError` has additional variant `NoteFilterInvalid`

### Fixed
- `zcash_client_sqlite::WalletDb`'s implementation of
  `zcash_client_backend::data_api::WalletRead::get_wallet_summary` has been
  fixed to take account of `min_confirmations` for transparent balances.
  (Previously, it would treat transparent balances as though
  `min_confirmations` were `1` even if it was set to a higher value.)
  Note that this implementation treats `min_confirmations == 0` the same
  as `min_confirmations == 1` for both shielded and transparent TXOs.
  It also does not currently distinguish between pending change and
  non-change; the pending value is all counted as non-change (issue
  [#1592](https://github.com/zcash/librustzcash/issues/1592)).

## [0.12.2] - 2024-10-21

### Fixed
- Fixes an error in determining the minimum checkpoint height to which it's
  possible to rewind in the case of a reorg, when no other truncation height
  information is available.

## [0.12.1] - 2024-10-10

### Fixed
- An error in scan progress computation was fixed. As part of this fix, wallet
  summary information is now only returned in the case that some note
  commitment tree size information can be determined, either from subtree root
  download or from downloaded block data. NOTE: The recovery progress ratio may
  be present as `0:0` in the case that the recovery range contains no notes;
  this was not adequately documented in the previous release.

## [0.12.0] - 2024-10-04

### Added
- `impl WalletTest for WalletDb` is now available under the `test-dependencies`
  feature flag.

### Changed
- Migrated to `zcash_client_backend 0.14`, `orchard 0.10`,
  `sapling-crypto 0.3`, `shardtree 0.5`, `zcash_address 0.6`,
  `zcash_primitives 0.19`, `zcash_proofs 0.19`, `zcash_protocol 0.4`.
- `zcash_client_sqlite::error::SqliteClientError::RequestedRewindInvalid`
  is now a structured variant.

## [0.11.2] - 2024-08-21

### Changed
- The `v_tx_outputs` view was modified slightly to support older versions of
  `sqlite`. Queries to the exposed `v_tx_outputs` and `v_transactions` views
  are supported for SQLite versions back to `3.19.x`.
- `zcash_client_sqlite::wallet::init::WalletMigrationError` has an additional
  variant, `DatabaseNotSupported`. The `init_wallet_db` function now checks
  that the sqlite version in use is compatible with the features required by
  the wallet and returns this error if not. SQLite version `3.35` or higher
  is required for use with `zcash_client_sqlite`.

## [0.11.1] - 2024-08-21

### Fixed
- The dependencies of the `tx_retrieval_queue` migration have been fixed to
  enable migrating wallets containing certain kinds of transactions.

## [0.11.0] - 2024-08-20

`zcash_client_sqlite` now provides capabilities for the management of ephemeral
transparent addresses in support of the creation of ZIP 320 transaction pairs.

In addition, `zcash_client_sqlite` now provides improved tracking of transparent
wallet history in support of the API changes in `zcash_client_backend 0.13`,
and the `v_transactions` view has been modified to provide additional metadata
about the relationship of each transaction to the wallet, in particular whether
or not the transaction represents a wallet-internal shielding operation.

### Changed
- MSRV is now 1.70.0.
- Updated dependencies:
  - `zcash_address 0.4`
  - `zcash_client_backend 0.13`
  - `zcash_encoding 0.2.1`
  - `zcash_keys 0.3`
  - `zcash_primitives 0.16`
  - `zcash_protocol 0.2`
- `zcash_client_sqlite::error::SqliteClientError` has a new `ReachedGapLimit` and
  `EphemeralAddressReuse` variants when the "transparent-inputs" feature is enabled.
- `zcash_client_sqlite::error::SqliteClientError` has changed variants:
  - Removed `HdwalletError`.
  - Added `AccountCollision`.
  - Added `TransparentDerivation`.
- The `v_transactions` view has been modified:
  - The `block` column has been renamed to `mined_height`.
  - A `spent_note_count` column has been added.
  - An `is_shielding` column has been added, which is true for transactions where the
    spends from the wallet are all transparent, and the outputs to the wallet are all
    shielded.
- The `v_tx_outputs` view has been modified:
  - The result can now include transparent outputs with unknown height.

### Fixed
- The `to_address` column of the `v_tx_outputs` view is now `NULL` for
  transparent outputs received by the wallet. This column is only intended to
  contain addresses for outputs sent to external recipients. The fix aligns
  received transparent outputs with received shielded outputs (which have always
  returned `NULL`).

## [0.10.3] - 2024-04-08

### Added
- Added a migration to ensure that the default address for existing wallets is
  upgraded to include an Orchard receiver.

### Fixed
- A bug in the SQL query for `WalletDb::get_account_birthday` was fixed.

## [0.10.2] - 2024-03-27

### Fixed
- A bug in the SQL query for `WalletDb::get_unspent_transparent_output` was fixed.

## [0.10.1] - 2024-03-25

### Fixed
- The `sent_notes` table's `received_note` constraint was excessively restrictive
 after zcash/librustzcash#1306. Any databases that have migrations from
 zcash_client_sqlite 0.10.0 applied should be wiped and restored from seed.
 In order to ensure that the incorrect migration is not used, the migration
 id for the `full_account_ids` migration has been changed from
 `0x1b104345_f27e_42da_a9e3_1de22694da43` to `0x6d02ec76_8720_4cc6_b646_c4e2ce69221c`

## [0.10.0] - 2024-03-25

This version was yanked, use 0.10.1 instead.

### Added
- A new `orchard` feature flag has been added to make it possible to
  build client code without `orchard` dependendencies.
- `zcash_client_sqlite::AccountId`
- `zcash_client_sqlite::wallet::Account`
- `impl From<zcash_keys::keys::AddressGenerationError> for SqliteClientError`

### Changed
- Many places that `AccountId` appeared in the API changed from
  using `zcash_primitives::zip32::AccountId` to using an opaque `zcash_client_sqlite::AccountId`
  type.
  - The enum variant `zcash_client_sqlite::error::SqliteClientError::AccountUnknown`
    no longer has a `zcash_primitives::zip32::AccountId` data value.
  - Changes to the implementation of the `WalletWrite` trait:
    - `create_account` function returns a unique identifier for the new account (as before),
      except that this ID no longer happens to match the ZIP-32 account index.
      To get the ZIP-32 account index, use the new `WalletRead::get_account` function.
  - Two columns in the `transactions` view were renamed. They refer to the primary key field in the `accounts` table, which no longer equates to a ZIP-32 account index.
    - `to_account` -> `to_account_id`
    - `from_account` -> `from_account_id`
- `zcash_client_sqlite::error::SqliteClientError` has changed variants:
  - Added `AddressGeneration`
  - Added `UnknownZip32Derivation`
  - Added `BadAccountData`
  - Removed `DiversifierIndexOutOfRange`
  - Removed `InvalidNoteId`
- `zcash_client_sqlite::wallet`:
  - `init::WalletMigrationError` has added variants:
    - `WalletMigrationError::AddressGeneration`
    - `WalletMigrationError::CannotRevert`
    - `WalletMigrationError::SeedNotRelevant`
- The `v_transactions` and `v_tx_outputs` views now include Orchard notes.

## [0.9.1] - 2024-03-09

### Fixed
- Documentation now correctly builds with all feature flags.

## [0.9.0] - 2024-03-01

### Changed
- Migrated to `orchard 0.7`, `zcash_primitives 0.14`, `zcash_client_backend 0.11`.
- `zcash_client_sqlite::error::SqliteClientError` has new error variants:
  - `SqliteClientError::UnsupportedPoolType`
  - `SqliteClientError::BalanceError`
  - The `Bech32DecodeError` variant has been replaced with a more general
    `DecodingError` type.

## [0.8.1] - 2023-10-18

### Fixed
- Fixed a bug in `v_transactions` that was omitting value from identically-valued notes

## [0.8.0] - 2023-09-25

### Notable Changes
- The `v_transactions` and `v_tx_outputs` views have changed in terms of what
  columns are returned, and which result columns may be null. Please see the
  `Changed` section below for additional details.

### Added
- `zcash_client_sqlite::commitment_tree` Types related to management of note
  commitment trees using the `shardtree` crate.
- A new default-enabled feature flag `multicore`. This allows users to disable
  multicore support by setting `default_features = false` on their
  `zcash_primitives`, `zcash_proofs`, and `zcash_client_sqlite` dependencies.
- `zcash_client_sqlite::ReceivedNoteId`
- `zcash_client_sqlite::wallet::commitment_tree` A new module containing a
  sqlite-backed implementation of `shardtree::store::ShardStore`.
- `impl zcash_client_backend::data_api::WalletCommitmentTrees for WalletDb`

### Changed
- MSRV is now 1.65.0.
- Bumped dependencies to `hdwallet 0.4`, `incrementalmerkletree 0.5`, `bs58 0.5`,
  `prost 0.12`, `rusqlite 0.29`, `schemer-rusqlite 0.2.2`, `time 0.3.22`,
  `tempfile 3.5`, `zcash_address 0.3`, `zcash_note_encryption 0.4`,
  `zcash_primitives 0.13`, `zcash_client_backend 0.10`.
- Added dependencies on `shardtree 0.0`, `zcash_encoding 0.2`, `byteorder 1`
- A `CommitmentTree` variant has been added to `zcash_client_sqlite::wallet::init::WalletMigrationError`
- `min_confirmations` parameter values are now more strongly enforced. Previously,
  a note could be spent with fewer than `min_confirmations` confirmations if the
  wallet did not contain enough observed blocks to satisfy the `min_confirmations`
  value specified; this situation is now treated as an error.
- `zcash_client_sqlite::error::SqliteClientError` has new error variants:
  - `SqliteClientError::AccountUnknown`
  - `SqliteClientError::BlockConflict`
  - `SqliteClientError::CacheMiss`
  - `SqliteClientError::ChainHeightUnknown`
  - `SqliteClientError::CommitmentTree`
  - `SqliteClientError::NonSequentialBlocks`
- `zcash_client_backend::FsBlockDbError` has a new error variant:
  - `FsBlockDbError::CacheMiss`
- `zcash_client_sqlite::FsBlockDb::write_block_metadata` now overwrites any
  existing metadata entries that have the same height as a new entry.
- The `v_transactions` and `v_tx_outputs` views no longer return the
  internal database identifier for the transaction. The `txid` column should
  be used instead. The `tx_index`, `expiry_height`, `raw`, `fee_paid`, and
  `expired_unmined` columns will be null for received transparent
  transactions, in addition to the other columns that were previously
  permitted to be null.

### Removed
- The empty `wallet::transact` module has been removed.
- `zcash_client_sqlite::NoteId` has been replaced with `zcash_client_sqlite::ReceivedNoteId`
  as the `SentNoteId` variant is now unused following changes to
  `zcash_client_backend::data_api::WalletRead`.
- `zcash_client_sqlite::wallet::init::{init_blocks_table, init_accounts_table}`
  have been removed. `zcash_client_backend::data_api::WalletWrite::create_account`
  should be used instead; the initialization of the note commitment tree
  previously performed by `init_blocks_table` is now handled by passing an
  `AccountBirthday` containing the note commitment tree frontier as of the
  end of the birthday height block to `create_account` instead.
- `zcash_client_sqlite::DataConnStmtCache` has been removed in favor of using
  `rusqlite` caching for prepared statements.
- `zcash_client_sqlite::prepared` has been entirely removed.

### Fixed
- Fixed an off-by-one error in the `BlockSource` implementation for the SQLite-backed
 `BlockDb` block database which could result in blocks being skipped at the start of
 scan ranges.
- `zcash_client_sqlite::{BlockDb, FsBlockDb}::with_blocks` now return an error
  if `from_height` is set to a block height that does not exist in the cache.
- `WalletDb::get_transaction` no longer returns an error when called on a transaction
  that has not yet been mined, unless the transaction's consensus branch ID cannot be
  determined by other means.
- Fixed an error in `v_transactions` wherein received transparent outputs did not
  result in a transaction entry appearing in the transaction history.

## [0.7.1] - 2023-05-17

### Fixed
- Fixes a potential crash that could occur when attempting to read a memo from
  sqlite when the memo value is `NULL`. At present, we return the empty memo
  in this case; in the future, the `get_memo` API will be updated to reflect
  the potential absence of memo data.

## [0.7.0] - 2023-04-28
### Changed
- Bumped dependencies to `zcash_client_backend 0.9`.

### Removed
- The following deprecated types and methods have been removed from the public API:
  - `wallet::ShieldedOutput`
  - `wallet::block_height_extrema`
  - `wallet::get_address`
  - `wallet::get_all_nullifiers`
  - `wallet::get_balance`
  - `wallet::get_balance_at`
  - `wallet::get_block_hash`
  - `wallet::get_commitment_tree`
  - `wallet::get_nullifiers`
  - `wallet::get_received_memo`
  - `wallet::get_rewind_height`
  - `wallet::get_sent_memo`
  - `wallet::get_spendable_sapling_notes`
  - `wallet::get_transaction`
  - `wallet::get_tx_height`
  - `wallet::get_unified_full_viewing_keys`
  - `wallet::get_witnesses`
  - `wallet::insert_block`
  - `wallet::insert_witnesses`
  - `wallet::is_valid_account_extfvk`
  - `wallet::mark_sapling_note_spent`
  - `wallet::put_tx_data`
  - `wallet::put_tx_meta`
  - `wallet::prune_witnesses`
  - `wallet::select_spendable_sapling_notes`
  - `wallet::update_expired_notes`
  - `wallet::transact::get_spendable_sapling_notes`
  - `wallet::transact::select_spendable_sapling_notes`

## [0.6.0] - 2023-04-15
### Added
- SQLite view `v_tx_outputs`, exposing the history of transaction outputs sent
  from and received by the wallet. See `zcash_client_sqlite::wallet` for view
  documentation.

### Fixed
- In a previous crate release, `WalletDb` was modified to start tracking Sapling
  change notes in both the `sent_notes` and `received_notes` tables, as a form
  of double-entry accounting. This broke assumptions in the `v_transactions`
  SQLite view, and also left the `sent_notes` table in an inconsistent state. A
  migration has been added to this release which fixes the `sent_notes` table to
  consistently store Sapling change notes.
- The SQLite view `v_transactions` had several bugs independently from the above
  issue, and has been rewritten. See `zcash_client_sqlite::wallet` for view
  documentation.

### Changed
- Bumped dependencies to `group 0.13`, `jubjub 0.10`, `zcash_primitives 0.11`,
  `zcash_client_backend 0.8`.
- The dependency on `zcash_primitives` no longer enables the `multicore` feature
  by default in order to support compilation under `wasm32-wasi`. Users of other
  platforms may need to include an explicit dependency on `zcash_primitives`
  without `default-features = false` or otherwise explicitly enable the
  `zcash_primitives/multicore` feature if they did not already depend
  upon `zcash_primitives` with default features enabled.

### Removed
- SQLite views `v_tx_received` and `v_tx_sent` (use `v_tx_outputs` instead).

## [0.5.0] - 2023-02-01
### Added
- `zcash_client_sqlite::FsBlockDb::rewind_to_height` rewinds the BlockMeta Db
 to the specified height following the same logic as homonymous functions on
 `WalletDb`. This function does not delete the files referenced by the rows
 that might be present and are deleted by this function call.
- `zcash_client_sqlite::FsBlockDb::find_block`
- `zcash_client_sqlite::chain`:
  - `impl {Clone, Copy, Debug, PartialEq, Eq} for BlockMeta`

### Changed
- MSRV is now 1.60.0.
- Bumped dependencies to `zcash_primitives 0.10`, `zcash_client_backend 0.7`.
- `zcash_client_backend::FsBlockDbError`:
  - Renamed `FsBlockDbError::{DbError, FsError}` to `FsBlockDbError::{Db, Fs}`.
  - Added `FsBlockDbError::MissingBlockPath`.
  - `impl fmt::Display for FsBlockDbError`

## [0.4.2] - 2022-12-13
### Fixed
- `zcash_client_sqlite::WalletDb::get_transparent_balances` no longer returns an
  error if the wallet has no UTXOs.

## [0.4.1] - 2022-12-06
### Added
- `zcash_client_sqlite::DataConnStmtCache::advance_by_block` now generates a
  `tracing` span, which can be used for profiling.

## [0.4.0] - 2022-11-12
### Added
- Implementations of `zcash_client_backend::data_api::WalletReadTransparent`
  and `WalletWriteTransparent` have been added. These implementations
  are available only when the `transparent-inputs` feature flag is
  enabled.
- New error variants:
  - `SqliteClientError::TransparentAddress`, to support handling of errors in
    transparent address decoding.
  - `SqliteClientError::RequestedRewindInvalid`, to report when requested
    rewinds exceed supported bounds.
  - `SqliteClientError::DiversifierIndexOutOfRange`, to report when the space
    of available diversifier indices has been exhausted.
  - `SqliteClientError::AccountIdDiscontinuity`, to report when a user attempts
    to initialize the accounts table with a noncontiguous set of account identifiers.
  - `SqliteClientError::AccountIdOutOfRange`, to report when the maximum account
    identifier has been reached.
  - `SqliteClientError::Protobuf`, to support handling of errors in serialized
    protobuf data decoding.
- An `unstable` feature flag; this is added to parts of the API that may change
  in any release. It enables `zcash_client_backend`'s `unstable` feature flag.
- New summary views that may be directly accessed in the sqlite database.
  The structure of these views should be considered unstable; they may
  be replaced by accessors provided by the data access API at some point
  in the future:
  - `v_transactions`
  - `v_tx_received`
  - `v_tx_sent`
- `zcash_client_sqlite::wallet::init::WalletMigrationError`
- A filesystem-backed `BlockSource` implementation
  `zcash_client_sqlite::FsBlockDb`. This block source expects blocks to be
  stored on disk in individual files named following the pattern
  `<blockmeta_root>/blocks/<blockheight>-<blockhash>-compactblock`. A SQLite
  database stored at `<blockmeta_root>/blockmeta.sqlite`stores metadata for
  this block source.
  - `zcash_client_sqlite::chain::init::init_blockmeta_db` creates the required
    metadata cache database.
- Implementations of `PartialEq`, `Eq`, `PartialOrd`, and `Ord` for `NoteId`

### Changed
- Various **BREAKING CHANGES** have been made to the database tables. These will
  require migrations, which may need to be performed in multiple steps. Migrations
  will now be automatically performed for any user using
  `zcash_client_sqlite::wallet::init_wallet_db` and it is recommended to use this
  method to maintain the state of the database going forward.
  - The `extfvk` column in the `accounts` table has been replaced by a `ufvk`
    column. Values for this column should be derived from the wallet's seed and
    the account number; the Sapling component of the resulting Unified Full
    Viewing Key should match the old value in the `extfvk` column.
  - The `address` and `transparent_address` columns of the `accounts` table have
    been removed.
    - A new `addresses` table stores Unified Addresses, keyed on their `account`
      and `diversifier_index`, to enable storing diversifed Unified Addresses.
    - Transparent addresses for an account should be obtained by extracting the
      transparent receiver of a Unified Address for the account.
  - A new non-null column, `output_pool` has been added to the `sent_notes`
    table to enable distinguishing between Sapling and transparent outputs
    (and in the future, outputs to other pools). Values for this column should
    be assigned by inference from the address type in the stored data.
- MSRV is now 1.56.1.
- Bumped dependencies to `ff 0.12`, `group 0.12`, `jubjub 0.9`,
  `zcash_primitives 0.9`, `zcash_client_backend 0.6`.
- Renamed the following to use lower-case abbreviations (matching Rust
  naming conventions):
  - `zcash_client_sqlite::BlockDB` to `BlockDb`
  - `zcash_client_sqlite::WalletDB` to `WalletDb`
  - `zcash_client_sqlite::error::SqliteClientError::IncorrectHRPExtFVK` to
    `IncorrectHrpExtFvk`.
- The SQLite implementations of `zcash_client_backend::data_api::WalletRead`
  and `WalletWrite` have been updated to reflect the changes to those
  traits.
- `zcash_client_sqlite::wallet`:
  - `get_spendable_notes` has been renamed to `get_spendable_sapling_notes`.
  - `select_spendable_notes` has been renamed to `select_spendable_sapling_notes`.
  - `get_spendable_sapling_notes` and `select_spendable_sapling_notes` have also
    been changed to take a parameter that permits the caller to specify a set of
    notes to exclude from consideration.
  - `init_wallet_db` has been modified to take the wallet seed as an argument so
    that it can correctly perform migrations that require re-deriving key
    material. In particular for this upgrade, the seed is used to derive UFVKs
    to replace the currently stored Sapling ExtFVKs (without losing information)
    as part of the migration process.

### Removed
- The following functions have been removed from the public interface of
  `zcash_client_sqlite::wallet`. Prefer methods defined on
  `zcash_client_backend::data_api::{WalletRead, WalletWrite}` instead.
  - `get_extended_full_viewing_keys` (use `WalletRead::get_unified_full_viewing_keys` instead).
  - `insert_sent_note` (use `WalletWrite::store_sent_tx` instead).
  - `insert_sent_utxo` (use `WalletWrite::store_sent_tx` instead).
  - `put_sent_note` (use `WalletWrite::store_decrypted_tx` instead).
  - `put_sent_utxo` (use `WalletWrite::store_decrypted_tx` instead).
  - `delete_utxos_above` (use `WalletWrite::rewind_to_height` instead).
- `zcash_client_sqlite::with_blocks` (use
  `zcash_client_backend::data_api::BlockSource::with_blocks` instead).
- `zcash_client_sqlite::error::SqliteClientError` variants:
  - `SqliteClientError::IncorrectHrpExtFvk`
  - `SqliteClientError::Base58`
  - `SqliteClientError::BackendError`

### Fixed
- The `zcash_client_backend::data_api::WalletRead::get_address` implementation
  for `zcash_client_sqlite::WalletDb` now correctly returns `Ok(None)` if the
  account identifier does not correspond to a known account.

### Deprecated
- A number of public API methods that are used internally to support the
  `zcash_client_backend::data_api::{WalletRead, WalletWrite}` interfaces have
  been deprecated, and will be removed from the public API in a future release.
  Users should depend upon the versions of these methods exposed via the
  `zcash_client_backend::data_api` traits mentioned above instead.
  - Deprecated in `zcash_client_sqlite::wallet`:
    - `get_address`
    - `is_valid_account_extfvk`
    - `get_balance`
    - `get_balance_at`
    - `get_sent_memo`
    - `block_height_extrema`
    - `get_tx_height`
    - `get_block_hash`
    - `get_rewind_height`
    - `get_commitment_tree`
    - `get_witnesses`
    - `get_nullifiers`
    - `insert_block`
    - `put_tx_meta`
    - `put_tx_data`
    - `mark_sapling_note_spent`
    - `put_receiverd_note`
    - `insert_witness`
    - `prune_witnesses`
    - `update_expired_notes`
    - `get_address`
  - Deprecated in `zcash_client_sqlite::wallet::transact`:
    - `get_spendable_sapling_notes`
    - `select_spendable_sapling_notes`

## [0.3.0] - 2021-03-26
This release contains a major refactor of the APIs to leverage the new Data
Access API in the `zcash_client_backend` crate. API names are almost all the
same as before, but have been reorganized.

### Added
- `zcash_client_sqlite::BlockDB`, a read-only wrapper for the SQLite connection
  to the block cache database.
- `zcash_client_sqlite::WalletDB`, a read-only wrapper for the SQLite connection
  to the wallet database.
- `zcash_client_sqlite::DataConnStmtCache`, a read-write wrapper for the SQLite
  connection to the wallet database. Returned by `WalletDB::get_update_ops`.
- `zcash_client_sqlite::NoteId`

### Changed
- MSRV is now 1.47.0.
- APIs now take `&BlockDB` and `&WalletDB<P>` arguments, instead of paths to the
  block cache and wallet databases.
- The library no longer uses the `mainnet` feature flag to specify the network
  type. APIs now take a `P: zcash_primitives::consensus::Parameters` variable.

### Removed
- `zcash_client_sqlite::address` module (moved to `zcash_client_backend`).

### Fixed
- Shielded transactions created by the wallet that have no change output (fully
  spending their input notes) are now correctly detected as mined when scanning
  compact blocks.
- Unshielding transactions created by the wallet (with a transparent recipient
  address) that have no change output no longer cause a panic.

## [0.2.1] - 2020-10-24
### Fixed
- `transact::create_to_address` now correctly reconstructs notes from the data
  DB after Canopy activation (zcash/librustzcash#311). This is critcal to correct
  operation of spends after Canopy.

## [0.2.0] - 2020-09-09
### Changed
- MSRV is now 1.44.1.
- Bumped dependencies to `ff 0.8`, `group 0.8`, `jubjub 0.5.1`, `protobuf 2.15`,
  `rusqlite 0.24`, `zcash_primitives 0.4`, `zcash_client_backend 0.4`.

## [0.1.0] - 2020-08-24
Initial release.
