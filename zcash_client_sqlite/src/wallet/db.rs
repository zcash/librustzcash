//! Documentation about the wallet database structure.
//!
//! The database structure is managed by [`crate::wallet::init::init_wallet_db`], which
//! applies migrations (defined in `crate::wallet::init::migrations`) that produce the
//! current structure.
//!
//! The SQL code in this module's constants encodes the current database structure, as
//! represented internally by SQLite. We do not use these constants at runtime; instead we
//! check the output of the migrations in `crate::wallet::init::tests::verify_schema`, to
//! pin the expected database structure.

// The constants in this module are only used in tests, but `#[cfg(test)]` prevents them
// from showing up in `cargo doc --document-private-items`.
#![allow(dead_code)]

use zcash_client_backend::data_api::scanning::ScanPriority;
use zcash_protocol::consensus::{NetworkUpgrade, Parameters};

use crate::wallet::scanning::priority_code;

/// Stores information about the accounts that the wallet is tracking.
pub(super) const TABLE_ACCOUNTS: &str = r#"
CREATE TABLE "accounts" (
    id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    account_kind INTEGER NOT NULL DEFAULT 0,
    hd_seed_fingerprint BLOB,
    hd_account_index INTEGER,
    ufvk TEXT,
    uivk TEXT NOT NULL,
    orchard_fvk_item_cache BLOB,
    sapling_fvk_item_cache BLOB,
    p2pkh_fvk_item_cache BLOB,
    birthday_height INTEGER NOT NULL,
    birthday_sapling_tree_size INTEGER,
    birthday_orchard_tree_size INTEGER,
    recover_until_height INTEGER,
    CHECK (
        (
        account_kind = 0
        AND hd_seed_fingerprint IS NOT NULL
        AND hd_account_index IS NOT NULL
        AND ufvk IS NOT NULL
        )
        OR
        (
        account_kind = 1
        AND hd_seed_fingerprint IS NULL
        AND hd_account_index IS NULL
        )
    )
)"#;
pub(super) const INDEX_ACCOUNTS_UFVK: &str =
    r#"CREATE UNIQUE INDEX accounts_ufvk ON "accounts" (ufvk)"#;
pub(super) const INDEX_ACCOUNTS_UIVK: &str =
    r#"CREATE UNIQUE INDEX accounts_uivk ON "accounts" (uivk)"#;
pub(super) const INDEX_HD_ACCOUNT: &str =
    r#"CREATE UNIQUE INDEX hd_account ON "accounts" (hd_seed_fingerprint, hd_account_index)"#;

/// Stores diversified Unified Addresses that have been generated from accounts in the
/// wallet.
///
/// - The `cached_transparent_receiver_address` column contains the transparent receiver
///   component of the UA. It is cached directly in the table to make account lookups for
///   transparent outputs more efficient, enabling joins to [`TABLE_UTXOS`].
pub(super) const TABLE_ADDRESSES: &str = r#"
CREATE TABLE "addresses" (
    account_id INTEGER NOT NULL,
    diversifier_index_be BLOB NOT NULL,
    address TEXT NOT NULL,
    cached_transparent_receiver_address TEXT,
    FOREIGN KEY (account_id) REFERENCES accounts(id),
    CONSTRAINT diversification UNIQUE (account_id, diversifier_index_be)
)"#;
pub(super) const INDEX_ADDRESSES_ACCOUNTS: &str = r#"
CREATE INDEX "addresses_accounts" ON "addresses" (
    "account_id" ASC
)"#;

/// Stores information about every block that the wallet has scanned.
///
/// Note that this table does not contain any rows for blocks that the wallet might have
/// observed partial information about (for example, a transparent output fetched and
/// stored in [`TABLE_UTXOS`]). This may change in future.
pub(super) const TABLE_BLOCKS: &str = "
CREATE TABLE blocks (
    height INTEGER PRIMARY KEY,
    hash BLOB NOT NULL,
    time INTEGER NOT NULL,
    sapling_tree BLOB NOT NULL ,
    sapling_commitment_tree_size INTEGER,
    orchard_commitment_tree_size INTEGER,
    sapling_output_count INTEGER,
    orchard_action_count INTEGER)";

/// Stores the wallet's transactions.
///
/// Any transactions that the wallet observes as "belonging to" one of the accounts in
/// [`TABLE_ACCOUNTS`] may be tracked in this table. As a result, this table may contain
/// data that is not recoverable from the chain (for example, transactions created by the
/// wallet that expired before being mined).
///
/// - The `block` column stores the height (in the wallet's chain view) of the mined block
///   containing the transaction. It is `NULL` for transactions that have not yet been
///   observed in scanned blocks, including transactions in the mempool or that have
///   expired.
pub(super) const TABLE_TRANSACTIONS: &str = "
CREATE TABLE transactions (
    id_tx INTEGER PRIMARY KEY,
    txid BLOB NOT NULL UNIQUE,
    created TEXT,
    block INTEGER,
    tx_index INTEGER,
    expiry_height INTEGER,
    raw BLOB,
    fee INTEGER,
    FOREIGN KEY (block) REFERENCES blocks(height)
)";

/// Stores the Sapling notes received by the wallet.
///
/// Note spentness is tracked in [`TABLE_SAPLING_RECEIVED_NOTE_SPENDS`].
pub(super) const TABLE_SAPLING_RECEIVED_NOTES: &str = r#"
CREATE TABLE "sapling_received_notes" (
    id INTEGER PRIMARY KEY,
    tx INTEGER NOT NULL,
    output_index INTEGER NOT NULL,
    account_id INTEGER NOT NULL,
    diversifier BLOB NOT NULL,
    value INTEGER NOT NULL,
    rcm BLOB NOT NULL,
    nf BLOB UNIQUE,
    is_change INTEGER NOT NULL,
    memo BLOB,
    commitment_tree_position INTEGER,
    recipient_key_scope INTEGER,
    FOREIGN KEY (tx) REFERENCES transactions(id_tx),
    FOREIGN KEY (account_id) REFERENCES accounts(id),
    CONSTRAINT tx_output UNIQUE (tx, output_index)
)"#;
pub(super) const INDEX_SAPLING_RECEIVED_NOTES_ACCOUNT: &str = r#"
CREATE INDEX "sapling_received_notes_account" ON "sapling_received_notes" (
    "account_id" ASC
)"#;
pub(super) const INDEX_SAPLING_RECEIVED_NOTES_TX: &str = r#"
CREATE INDEX "sapling_received_notes_tx" ON "sapling_received_notes" (
    "tx" ASC
)"#;

/// A junction table between received Sapling notes and the transactions that spend them.
///
/// Only one mined transaction can spend a note. However, transactions created by the
/// wallet may expire before being mined, and the wallet still tracks the fact that the
/// user created the transaction. The junction table enables the "spent-in" relationship
/// between notes and expired transactions to be preserved; note spent-ness is determined
/// by joining this table with [`TABLE_TRANSACTIONS`] and then filtering out transactions
/// where either `transactions.block` is non-null, or `transactions.expiry_height` is not
/// greater than the wallet's view of the chain tip.
pub(super) const TABLE_SAPLING_RECEIVED_NOTE_SPENDS: &str = "
CREATE TABLE sapling_received_note_spends (
    sapling_received_note_id INTEGER NOT NULL,
    transaction_id INTEGER NOT NULL,
    FOREIGN KEY (sapling_received_note_id)
        REFERENCES sapling_received_notes(id)
        ON DELETE CASCADE,
    FOREIGN KEY (transaction_id)
        -- We do not delete transactions, so this does not cascade
        REFERENCES transactions(id_tx),
    UNIQUE (sapling_received_note_id, transaction_id)
)";

/// Stores the Orchard notes received by the wallet.
///
/// Note spentness is tracked in [`TABLE_ORCHARD_RECEIVED_NOTE_SPENDS`].
pub(super) const TABLE_ORCHARD_RECEIVED_NOTES: &str = "
CREATE TABLE orchard_received_notes (
    id INTEGER PRIMARY KEY,
    tx INTEGER NOT NULL,
    action_index INTEGER NOT NULL,
    account_id INTEGER NOT NULL,
    diversifier BLOB NOT NULL,
    value INTEGER NOT NULL,
    rho BLOB NOT NULL,
    rseed BLOB NOT NULL,
    nf BLOB UNIQUE,
    is_change INTEGER NOT NULL,
    memo BLOB,
    commitment_tree_position INTEGER,
    recipient_key_scope INTEGER,
    FOREIGN KEY (tx) REFERENCES transactions(id_tx),
    FOREIGN KEY (account_id) REFERENCES accounts(id),
    CONSTRAINT tx_output UNIQUE (tx, action_index)
)";
pub(super) const INDEX_ORCHARD_RECEIVED_NOTES_ACCOUNT: &str = r#"
CREATE INDEX orchard_received_notes_account ON orchard_received_notes (
    account_id ASC
)"#;
pub(super) const INDEX_ORCHARD_RECEIVED_NOTES_TX: &str = r#"
CREATE INDEX orchard_received_notes_tx ON orchard_received_notes (
    tx ASC
)"#;

/// A junction table between received Orchard notes and the transactions that spend them.
///
/// This is identical to [`TABLE_SAPLING_RECEIVED_NOTE_SPENDS`]; see its documentation for
/// details.
pub(super) const TABLE_ORCHARD_RECEIVED_NOTE_SPENDS: &str = "
CREATE TABLE orchard_received_note_spends (
    orchard_received_note_id INTEGER NOT NULL,
    transaction_id INTEGER NOT NULL,
    FOREIGN KEY (orchard_received_note_id)
        REFERENCES orchard_received_notes(id)
        ON DELETE CASCADE,
    FOREIGN KEY (transaction_id)
        -- We do not delete transactions, so this does not cascade
        REFERENCES transactions(id_tx),
    UNIQUE (orchard_received_note_id, transaction_id)
)";

/// Stores the current UTXO set for the wallet, as well as any transparent outputs
/// previously observed by the wallet.
///
/// Originally this table only stored the current UTXO set (as of latest refresh), and the
/// table was cleared prior to loading in the latest UTXO set. We now upsert instead of
/// insert into the database, meaning that spent outputs are left in the database. This
/// makes it similar to the `*_received_notes` tables in that it can store history, but
/// has several downsides:
/// - The table has incomplete contents for recovered-from-seed wallets.
/// - The table can have inconsistent contents for seeds loaded into multiple wallets
///   simultaneously.
/// - The wallet's transparent balance can be incorrect prior to "transaction enhancement"
///   (downloading the full transaction containing the transparent output spend).
pub(super) const TABLE_UTXOS: &str = r#"
CREATE TABLE "utxos" (
    id INTEGER PRIMARY KEY,
    received_by_account_id INTEGER NOT NULL,
    address TEXT NOT NULL,
    prevout_txid BLOB NOT NULL,
    prevout_idx INTEGER NOT NULL,
    script BLOB NOT NULL,
    value_zat INTEGER NOT NULL,
    height INTEGER NOT NULL,
    FOREIGN KEY (received_by_account_id) REFERENCES accounts(id),
    CONSTRAINT tx_outpoint UNIQUE (prevout_txid, prevout_idx)
)"#;
pub(super) const INDEX_UTXOS_RECEIVED_BY_ACCOUNT: &str =
    r#"CREATE INDEX utxos_received_by_account ON "utxos" (received_by_account_id)"#;

/// A junction table between received transparent outputs and the transactions that spend
/// them.
///
/// This is identical to [`TABLE_SAPLING_RECEIVED_NOTE_SPENDS`]; see its documentation for
/// details. Note however that [`TABLE_UTXOS`] and [`TABLE_SAPLING_RECEIVED_NOTES`] are
/// not equivalent, and care must be taken when interpreting the result of joining this
/// table to [`TABLE_UTXOS`].
pub(super) const TABLE_TRANSPARENT_RECEIVED_OUTPUT_SPENDS: &str = "
CREATE TABLE transparent_received_output_spends (
    transparent_received_output_id INTEGER NOT NULL,
    transaction_id INTEGER NOT NULL,
    FOREIGN KEY (transparent_received_output_id)
        REFERENCES utxos(id)
        ON DELETE CASCADE,
    FOREIGN KEY (transaction_id)
        -- We do not delete transactions, so this does not cascade
        REFERENCES transactions(id_tx),
    UNIQUE (transparent_received_output_id, transaction_id)
)";

/// Stores the outputs of transactions created by the wallet.
///
/// Unlike with outputs received by the wallet, we store sent outputs for all pools in
/// this table, distinguished by the `output_pool` column. The information we want to
/// record for sent outputs is the same across all pools, whereas for received outputs we
/// want to cache pool-specific data.
pub(super) const TABLE_SENT_NOTES: &str = r#"
CREATE TABLE "sent_notes" (
    id INTEGER PRIMARY KEY,
    tx INTEGER NOT NULL,
    output_pool INTEGER NOT NULL,
    output_index INTEGER NOT NULL,
    from_account_id INTEGER NOT NULL,
    to_address TEXT,
    to_account_id INTEGER,
    value INTEGER NOT NULL,
    memo BLOB,
    FOREIGN KEY (tx) REFERENCES transactions(id_tx),
    FOREIGN KEY (from_account_id) REFERENCES accounts(id),
    FOREIGN KEY (to_account_id) REFERENCES accounts(id),
    CONSTRAINT tx_output UNIQUE (tx, output_pool, output_index),
    CONSTRAINT note_recipient CHECK (
        (to_address IS NOT NULL) OR (to_account_id IS NOT NULL)
    )
)"#;
pub(super) const INDEX_SENT_NOTES_FROM_ACCOUNT: &str =
    r#"CREATE INDEX sent_notes_from_account ON "sent_notes" (from_account_id)"#;
pub(super) const INDEX_SENT_NOTES_TO_ACCOUNT: &str =
    r#"CREATE INDEX sent_notes_to_account ON "sent_notes" (to_account_id)"#;
pub(super) const INDEX_SENT_NOTES_TX: &str = r#"CREATE INDEX sent_notes_tx ON "sent_notes" (tx)"#;

//
// State for shard trees
//

/// Stores the shards of a [`ShardTree`] for the Sapling commitment tree.
///
/// This table contains a row for each 2^16 subtree of the Sapling note commitment tree,
/// keyed by the index of the shard. The `shard_data` column contains the subtree's data
/// as serialized by [`zcash_client_backend::serialization::shardtree::write_shard`].
///
/// [`ShardTree`]: shardtree::ShardTree
pub(super) const TABLE_SAPLING_TREE_SHARDS: &str = "
CREATE TABLE sapling_tree_shards (
    shard_index INTEGER PRIMARY KEY,
    subtree_end_height INTEGER,
    root_hash BLOB,
    shard_data BLOB,
    contains_marked INTEGER,
    CONSTRAINT root_unique UNIQUE (root_hash)
)";

/// Stores the "cap" of the Sapling [`ShardTree`].
///
/// This table will only ever have a single row, in which is serialized the 2^16 "cap"
/// of the Sapling note commitment tree, The `cap_data` column contains the cap data
/// as serialized by [`zcash_client_backend::serialization::shardtree::write_shard`].
///
/// [`ShardTree`]: shardtree::ShardTree
pub(super) const TABLE_SAPLING_TREE_CAP: &str = "
CREATE TABLE sapling_tree_cap (
    -- cap_id exists only to be able to take advantage of `ON CONFLICT`
    -- upsert functionality; the table will only ever contain one row
    cap_id INTEGER PRIMARY KEY,
    cap_data BLOB NOT NULL
)";

/// Stores the checkpointed positions in the Sapling [`ShardTree`].
///
/// Each row in this table stores the note commitment tree position of the last Sapling
/// output in the block having height `checkpoint_id`.
///
/// [`ShardTree`]: shardtree::ShardTree
pub(super) const TABLE_SAPLING_TREE_CHECKPOINTS: &str = "
CREATE TABLE sapling_tree_checkpoints (
    checkpoint_id INTEGER PRIMARY KEY,
    position INTEGER
)";

/// Stores metadata about the positions of Sapling notes that have been spent but for
/// which witness information has not yet been removed from the note commitment tree.
///
/// In the process of updating the note commitment tree in response to the addition of
/// a block, it is necessary to temporarily continue to store witness information for
/// each note so that a spent note can be made spendable again after a rollback of the
/// spending block. This table caches the metadata needed for that restoration.
pub(super) const TABLE_SAPLING_TREE_CHECKPOINT_MARKS_REMOVED: &str = "
CREATE TABLE sapling_tree_checkpoint_marks_removed (
    checkpoint_id INTEGER NOT NULL,
    mark_removed_position INTEGER NOT NULL,
    FOREIGN KEY (checkpoint_id) REFERENCES sapling_tree_checkpoints(checkpoint_id)
    ON DELETE CASCADE,
    CONSTRAINT spend_position_unique UNIQUE (checkpoint_id, mark_removed_position)
)";

/// Stores the shards of a [`ShardTree`] for the Orchard commitment tree.
///
/// This is identical to [`TABLE_SAPLING_TREE_SHARDS`]; see its documentation for details.
///
/// [`ShardTree`]: shardtree::ShardTree
pub(super) const TABLE_ORCHARD_TREE_SHARDS: &str = "
CREATE TABLE orchard_tree_shards (
    shard_index INTEGER PRIMARY KEY,
    subtree_end_height INTEGER,
    root_hash BLOB,
    shard_data BLOB,
    contains_marked INTEGER,
    CONSTRAINT root_unique UNIQUE (root_hash)
)";

/// Stores the "cap" of the Orchard [`ShardTree`].
///
/// This is identical to [`TABLE_SAPLING_TREE_CAP`]; see its documentation for details.
///
/// [`ShardTree`]: shardtree::ShardTree
pub(super) const TABLE_ORCHARD_TREE_CAP: &str = "
CREATE TABLE orchard_tree_cap (
    -- cap_id exists only to be able to take advantage of `ON CONFLICT`
    -- upsert functionality; the table will only ever contain one row
    cap_id INTEGER PRIMARY KEY,
    cap_data BLOB NOT NULL
)";

/// Stores the checkpointed positions in the Orchard [`ShardTree`].
///
/// This is identical to [`TABLE_SAPLING_TREE_CHECKPOINTS`]; see its documentation for
/// details.
///
/// [`ShardTree`]: shardtree::ShardTree
pub(super) const TABLE_ORCHARD_TREE_CHECKPOINTS: &str = "
CREATE TABLE orchard_tree_checkpoints (
    checkpoint_id INTEGER PRIMARY KEY,
    position INTEGER
)";

/// Stores metadata about the positions of Orchard notes that have been spent but for
/// which witness information has not yet been removed from the note commitment tree.
///
/// This is identical to [`TABLE_SAPLING_TREE_CHECKPOINT_MARKS_REMOVED`]; see its
/// documentation for details.
pub(super) const TABLE_ORCHARD_TREE_CHECKPOINT_MARKS_REMOVED: &str = "
CREATE TABLE orchard_tree_checkpoint_marks_removed (
    checkpoint_id INTEGER NOT NULL,
    mark_removed_position INTEGER NOT NULL,
    FOREIGN KEY (checkpoint_id) REFERENCES orchard_tree_checkpoints(checkpoint_id)
    ON DELETE CASCADE,
    CONSTRAINT spend_position_unique UNIQUE (checkpoint_id, mark_removed_position)
)";

//
// Scanning
//

/// Stores the [`ScanPriority`] for all block ranges in the wallet's view of the chain.
///
/// [`ScanPriority`]: zcash_client_backend::data_api::scanning::ScanPriority
pub(super) const TABLE_SCAN_QUEUE: &str = "
CREATE TABLE scan_queue (
    block_range_start INTEGER NOT NULL,
    block_range_end INTEGER NOT NULL,
    priority INTEGER NOT NULL,
    CONSTRAINT range_start_uniq UNIQUE (block_range_start),
    CONSTRAINT range_end_uniq UNIQUE (block_range_end),
    CONSTRAINT range_bounds_order CHECK (
        block_range_start < block_range_end
    )
)";

/// A map from "transaction locators" to transaction IDs for the current chain state.
///
/// `(block_height, tx_index)` is a "transaction locator"; `tx_index` is an index into the
/// list of transactions for the block at height `block_height` in the chain as currently
/// known to the wallet.
///
/// No foreign key constraint is enforced for `block_height` to [`TABLE_BLOCKS`], to allow
/// loading the nullifier map separately from block scanning.
pub(super) const TABLE_TX_LOCATOR_MAP: &str = "
CREATE TABLE tx_locator_map (
    block_height INTEGER NOT NULL,
    tx_index INTEGER NOT NULL,
    txid BLOB NOT NULL UNIQUE,
    PRIMARY KEY (block_height, tx_index)
)";

/// A map from nullifiers to the transaction they were observed in.
///
/// The purpose of this map is to allow non-linear scanning. If the wallet scans a block
/// range `Y..Z` that leaves a gap between the wallet's birthday height and `Y`, then the
/// wallet must assume that any nullifier observed in `Y..Z` might be spending one of its
/// notes (that it has not yet observed), otherwise it will fail to detect those spends
/// and report a too-large balance. Once the wallet has scanned every block between its
/// birthday height and `Y`, the nullifier map contents up to `Z` is no longer necessary
/// and can be dropped.
///
/// The map stores transaction locators instead of transaction IDs for efficiency. SQLite
/// will represent the transaction locator in at most 6 bytes, so a transaction that only
/// spends one shielded note will incur a 12-byte overhead (across both this table and
/// [`TABLE_TX_LOCATOR_MAP`]), but each additional spent note in a transaction saves 26
/// bytes.
pub(super) const TABLE_NULLIFIER_MAP: &str = "
CREATE TABLE nullifier_map (
    spend_pool INTEGER NOT NULL,
    nf BLOB NOT NULL,
    block_height INTEGER NOT NULL,
    tx_index INTEGER NOT NULL,
    CONSTRAINT tx_locator
        FOREIGN KEY (block_height, tx_index)
        REFERENCES tx_locator_map(block_height, tx_index)
        ON DELETE CASCADE
        ON UPDATE RESTRICT,
    CONSTRAINT nf_uniq UNIQUE (spend_pool, nf)
)";
pub(super) const INDEX_NF_MAP_LOCATOR_IDX: &str =
    r#"CREATE INDEX nf_map_locator_idx ON nullifier_map(block_height, tx_index)"#;

//
// Internal tables
//

/// Internal table used by [`schemer`] to manage migrations.
pub(super) const TABLE_SCHEMER_MIGRATIONS: &str = "
CREATE TABLE schemer_migrations (
    id blob PRIMARY KEY
)";

/// Internal table created by SQLite when we started using `AUTOINCREMENT`.
pub(super) const TABLE_SQLITE_SEQUENCE: &str = "CREATE TABLE sqlite_sequence(name,seq)";

//
// Views
//

pub(super) const VIEW_RECEIVED_NOTES: &str = "
CREATE VIEW v_received_notes AS
SELECT
    sapling_received_notes.id AS id_within_pool_table,
    sapling_received_notes.tx,
    2 AS pool,
    sapling_received_notes.output_index AS output_index,
    account_id,
    sapling_received_notes.value,
    is_change,
    sapling_received_notes.memo,
    sent_notes.id AS sent_note_id
FROM sapling_received_notes
LEFT JOIN sent_notes
ON (sent_notes.tx, sent_notes.output_pool, sent_notes.output_index) =
    (sapling_received_notes.tx, 2, sapling_received_notes.output_index)
UNION
SELECT
    orchard_received_notes.id AS id_within_pool_table,
    orchard_received_notes.tx,
    3 AS pool,
    orchard_received_notes.action_index AS output_index,
    account_id,
    orchard_received_notes.value,
    is_change,
    orchard_received_notes.memo,
    sent_notes.id AS sent_note_id
FROM orchard_received_notes
LEFT JOIN sent_notes
ON (sent_notes.tx, sent_notes.output_pool, sent_notes.output_index) =
    (orchard_received_notes.tx, 3, orchard_received_notes.action_index)";

pub(super) const VIEW_RECEIVED_NOTE_SPENDS: &str = "
CREATE VIEW v_received_note_spends AS
SELECT
    2 AS pool,
    sapling_received_note_id AS received_note_id,
    transaction_id
FROM sapling_received_note_spends
UNION
SELECT
    3 AS pool,
    orchard_received_note_id AS received_note_id,
    transaction_id
FROM orchard_received_note_spends";

pub(super) const VIEW_TRANSACTIONS: &str = "
CREATE VIEW v_transactions AS
WITH
notes AS (
    -- Shielded notes received in this transaction
    SELECT v_received_notes.account_id     AS account_id,
            transactions.block              AS block,
            transactions.txid               AS txid,
            v_received_notes.pool           AS pool,
            id_within_pool_table,
            v_received_notes.value          AS value,
            CASE
                WHEN v_received_notes.is_change THEN 1
                ELSE 0
            END AS is_change,
            CASE
                WHEN v_received_notes.is_change THEN 0
                ELSE 1
            END AS received_count,
            CASE
                WHEN (v_received_notes.memo IS NULL OR v_received_notes.memo = X'F6')
                THEN 0
                ELSE 1
            END AS memo_present
    FROM v_received_notes
    JOIN transactions
            ON transactions.id_tx = v_received_notes.tx
    UNION
    -- Transparent TXOs received in this transaction
    SELECT utxos.received_by_account_id AS account_id,
            utxos.height                 AS block,
            utxos.prevout_txid           AS txid,
            0                            AS pool,
            utxos.id                     AS id_within_pool_table,
            utxos.value_zat              AS value,
            0                            AS is_change,
            1                            AS received_count,
            0                            AS memo_present
    FROM utxos
    UNION
    -- Shielded notes spent in this transaction
    SELECT v_received_notes.account_id  AS account_id,
            transactions.block           AS block,
            transactions.txid            AS txid,
            v_received_notes.pool        AS pool,
            id_within_pool_table,
            -v_received_notes.value      AS value,
            0                            AS is_change,
            0                            AS received_count,
            0                            AS memo_present
    FROM v_received_notes
    JOIN v_received_note_spends rns
            ON rns.pool = v_received_notes.pool
            AND rns.received_note_id = v_received_notes.id_within_pool_table
    JOIN transactions
            ON transactions.id_tx = rns.transaction_id
    UNION
    -- Transparent TXOs spent in this transaction
    SELECT utxos.received_by_account_id AS account_id,
            transactions.block           AS block,
            transactions.txid            AS txid,
            0                            AS pool,
            utxos.id                     AS id_within_pool_table,
            -utxos.value_zat             AS value,
            0                            AS is_change,
            0                            AS received_count,
            0                            AS memo_present
    FROM utxos
    JOIN transparent_received_output_spends tros
            ON tros.transparent_received_output_id = utxos.id
    JOIN transactions
            ON transactions.id_tx = tros.transaction_id
),
-- Obtain a count of the notes that the wallet created in each transaction,
-- not counting change notes.
sent_note_counts AS (
    SELECT sent_notes.from_account_id AS account_id,
            transactions.txid       AS txid,
            COUNT(DISTINCT sent_notes.id) as sent_notes,
            SUM(
                CASE
                WHEN (sent_notes.memo IS NULL OR sent_notes.memo = X'F6' OR v_received_notes.tx IS NOT NULL)
                    THEN 0
                ELSE 1
                END
            ) AS memo_count
    FROM sent_notes
    JOIN transactions
            ON transactions.id_tx = sent_notes.tx
    LEFT JOIN v_received_notes
            ON sent_notes.id = v_received_notes.sent_note_id
    WHERE COALESCE(v_received_notes.is_change, 0) = 0
    GROUP BY account_id, txid
),
blocks_max_height AS (
    SELECT MAX(blocks.height) as max_height FROM blocks
)
SELECT notes.account_id                  AS account_id,
        notes.block                       AS mined_height,
        notes.txid                        AS txid,
        transactions.tx_index             AS tx_index,
        transactions.expiry_height        AS expiry_height,
        transactions.raw                  AS raw,
        SUM(notes.value)                  AS account_balance_delta,
        transactions.fee                  AS fee_paid,
        SUM(notes.is_change) > 0          AS has_change,
        MAX(COALESCE(sent_note_counts.sent_notes, 0))  AS sent_note_count,
        SUM(notes.received_count)         AS received_note_count,
        SUM(notes.memo_present) + MAX(COALESCE(sent_note_counts.memo_count, 0)) AS memo_count,
        blocks.time                       AS block_time,
        (
            blocks.height IS NULL
            AND transactions.expiry_height BETWEEN 1 AND blocks_max_height.max_height
        ) AS expired_unmined
FROM notes
LEFT JOIN transactions
        ON notes.txid = transactions.txid
JOIN blocks_max_height
LEFT JOIN blocks ON blocks.height = notes.block
LEFT JOIN sent_note_counts
        ON sent_note_counts.account_id = notes.account_id
        AND sent_note_counts.txid = notes.txid
GROUP BY notes.account_id, notes.txid";

pub(super) const VIEW_TX_OUTPUTS: &str = "
CREATE VIEW v_tx_outputs AS
SELECT transactions.txid              AS txid,
        v_received_notes.pool          AS output_pool,
        v_received_notes.output_index  AS output_index,
        sent_notes.from_account_id     AS from_account_id,
        v_received_notes.account_id    AS to_account_id,
        NULL                           AS to_address,
        v_received_notes.value         AS value,
        v_received_notes.is_change     AS is_change,
        v_received_notes.memo          AS memo
FROM v_received_notes
JOIN transactions
    ON transactions.id_tx = v_received_notes.tx
LEFT JOIN sent_notes
    ON sent_notes.id = v_received_notes.sent_note_id
UNION
SELECT utxos.prevout_txid           AS txid,
        0                            AS output_pool,
        utxos.prevout_idx            AS output_index,
        NULL                         AS from_account_id,
        utxos.received_by_account_id AS to_account_id,
        utxos.address                AS to_address,
        utxos.value_zat              AS value,
        0                            AS is_change,
        NULL                         AS memo
FROM utxos
UNION
SELECT transactions.txid            AS txid,
        sent_notes.output_pool       AS output_pool,
        sent_notes.output_index      AS output_index,
        sent_notes.from_account_id   AS from_account_id,
        v_received_notes.account_id  AS to_account_id,
        sent_notes.to_address        AS to_address,
        sent_notes.value             AS value,
        0                            AS is_change,
        sent_notes.memo              AS memo
FROM sent_notes
JOIN transactions
    ON transactions.id_tx = sent_notes.tx
LEFT JOIN v_received_notes
    ON sent_notes.id = v_received_notes.sent_note_id
WHERE COALESCE(v_received_notes.is_change, 0) = 0";

pub(super) fn view_sapling_shard_scan_ranges<P: Parameters>(params: &P) -> String {
    format!(
        "CREATE VIEW v_sapling_shard_scan_ranges AS
        SELECT
            shard.shard_index,
            shard.shard_index << 16 AS start_position,
            (shard.shard_index + 1) << 16 AS end_position_exclusive,
            IFNULL(prev_shard.subtree_end_height, {}) AS subtree_start_height,
            shard.subtree_end_height,
            shard.contains_marked,
            scan_queue.block_range_start,
            scan_queue.block_range_end,
            scan_queue.priority
        FROM sapling_tree_shards shard
        LEFT OUTER JOIN sapling_tree_shards prev_shard
            ON shard.shard_index = prev_shard.shard_index + 1
        -- Join with scan ranges that overlap with the subtree's involved blocks.
        INNER JOIN scan_queue ON (
            subtree_start_height < scan_queue.block_range_end AND
            (
                scan_queue.block_range_start <= shard.subtree_end_height OR
                shard.subtree_end_height IS NULL
            )
        )",
        u32::from(params.activation_height(NetworkUpgrade::Sapling).unwrap()),
    )
}

pub(super) fn view_sapling_shard_unscanned_ranges() -> String {
    format!(
        "CREATE VIEW v_sapling_shard_unscanned_ranges AS
        WITH wallet_birthday AS (SELECT MIN(birthday_height) AS height FROM accounts)
        SELECT
            shard_index,
            start_position,
            end_position_exclusive,
            subtree_start_height,
            subtree_end_height,
            contains_marked,
            block_range_start,
            block_range_end,
            priority
        FROM v_sapling_shard_scan_ranges
        INNER JOIN wallet_birthday
        WHERE priority > {}
        AND block_range_end > wallet_birthday.height",
        priority_code(&ScanPriority::Scanned)
    )
}

pub(super) const VIEW_SAPLING_SHARDS_SCAN_STATE: &str = "
CREATE VIEW v_sapling_shards_scan_state AS
SELECT
    shard_index,
    start_position,
    end_position_exclusive,
    subtree_start_height,
    subtree_end_height,
    contains_marked,
    MAX(priority) AS max_priority
FROM v_sapling_shard_scan_ranges
GROUP BY
    shard_index,
    start_position,
    end_position_exclusive,
    subtree_start_height,
    subtree_end_height,
    contains_marked";

pub(super) fn view_orchard_shard_scan_ranges<P: Parameters>(params: &P) -> String {
    format!(
        "CREATE VIEW v_orchard_shard_scan_ranges AS
        SELECT
            shard.shard_index,
            shard.shard_index << 16 AS start_position,
            (shard.shard_index + 1) << 16 AS end_position_exclusive,
            IFNULL(prev_shard.subtree_end_height, {}) AS subtree_start_height,
            shard.subtree_end_height,
            shard.contains_marked,
            scan_queue.block_range_start,
            scan_queue.block_range_end,
            scan_queue.priority
        FROM orchard_tree_shards shard
        LEFT OUTER JOIN orchard_tree_shards prev_shard
            ON shard.shard_index = prev_shard.shard_index + 1
        -- Join with scan ranges that overlap with the subtree's involved blocks.
        INNER JOIN scan_queue ON (
            subtree_start_height < scan_queue.block_range_end AND
            (
                scan_queue.block_range_start <= shard.subtree_end_height OR
                shard.subtree_end_height IS NULL
            )
        )",
        u32::from(params.activation_height(NetworkUpgrade::Nu5).unwrap()),
    )
}

pub(super) fn view_orchard_shard_unscanned_ranges() -> String {
    format!(
        "CREATE VIEW v_orchard_shard_unscanned_ranges AS
        WITH wallet_birthday AS (SELECT MIN(birthday_height) AS height FROM accounts)
        SELECT
            shard_index,
            start_position,
            end_position_exclusive,
            subtree_start_height,
            subtree_end_height,
            contains_marked,
            block_range_start,
            block_range_end,
            priority
        FROM v_orchard_shard_scan_ranges
        INNER JOIN wallet_birthday
        WHERE priority > {}
        AND block_range_end > wallet_birthday.height",
        priority_code(&ScanPriority::Scanned),
    )
}

pub(super) const VIEW_ORCHARD_SHARDS_SCAN_STATE: &str = "
CREATE VIEW v_orchard_shards_scan_state AS
SELECT
    shard_index,
    start_position,
    end_position_exclusive,
    subtree_start_height,
    subtree_end_height,
    contains_marked,
    MAX(priority) AS max_priority
FROM v_orchard_shard_scan_ranges
GROUP BY
    shard_index,
    start_position,
    end_position_exclusive,
    subtree_start_height,
    subtree_end_height,
    contains_marked";
