//! Documentation about the wallet database structure.

// The constants in this module are only used in tests, but `#[cfg(test)]` prevents them
// from showing up in `cargo doc --document-private-items`.
#![allow(dead_code)]

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

pub(super) const TABLE_ADDRESSES: &str = r#"
CREATE TABLE "addresses" (
    account_id INTEGER NOT NULL,
    diversifier_index_be BLOB NOT NULL,
    address TEXT NOT NULL,
    cached_transparent_receiver_address TEXT,
    FOREIGN KEY (account_id) REFERENCES accounts(id),
    CONSTRAINT diversification UNIQUE (account_id, diversifier_index_be)
)"#;

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

//
// State for shard trees
//

pub(super) const TABLE_SAPLING_TREE_SHARDS: &str = "
CREATE TABLE sapling_tree_shards (
    shard_index INTEGER PRIMARY KEY,
    subtree_end_height INTEGER,
    root_hash BLOB,
    shard_data BLOB,
    contains_marked INTEGER,
    CONSTRAINT root_unique UNIQUE (root_hash)
)";

pub(super) const TABLE_SAPLING_TREE_CAP: &str = "
CREATE TABLE sapling_tree_cap (
    -- cap_id exists only to be able to take advantage of `ON CONFLICT`
    -- upsert functionality; the table will only ever contain one row
    cap_id INTEGER PRIMARY KEY,
    cap_data BLOB NOT NULL
)";

pub(super) const TABLE_SAPLING_TREE_CHECKPOINTS: &str = "
CREATE TABLE sapling_tree_checkpoints (
    checkpoint_id INTEGER PRIMARY KEY,
    position INTEGER
)";

pub(super) const TABLE_SAPLING_TREE_CHECKPOINT_MARKS_REMOVED: &str = "
CREATE TABLE sapling_tree_checkpoint_marks_removed (
    checkpoint_id INTEGER NOT NULL,
    mark_removed_position INTEGER NOT NULL,
    FOREIGN KEY (checkpoint_id) REFERENCES sapling_tree_checkpoints(checkpoint_id)
    ON DELETE CASCADE,
    CONSTRAINT spend_position_unique UNIQUE (checkpoint_id, mark_removed_position)
)";

pub(super) const TABLE_ORCHARD_TREE_SHARDS: &str = "
CREATE TABLE orchard_tree_shards (
    shard_index INTEGER PRIMARY KEY,
    subtree_end_height INTEGER,
    root_hash BLOB,
    shard_data BLOB,
    contains_marked INTEGER,
    CONSTRAINT root_unique UNIQUE (root_hash)
)";

pub(super) const TABLE_ORCHARD_TREE_CAP: &str = "
CREATE TABLE orchard_tree_cap (
    -- cap_id exists only to be able to take advantage of `ON CONFLICT`
    -- upsert functionality; the table will only ever contain one row
    cap_id INTEGER PRIMARY KEY,
    cap_data BLOB NOT NULL
)";

pub(super) const TABLE_ORCHARD_TREE_CHECKPOINTS: &str = "
CREATE TABLE orchard_tree_checkpoints (
    checkpoint_id INTEGER PRIMARY KEY,
    position INTEGER
)";

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

pub(super) const TABLE_TX_LOCATOR_MAP: &str = "
CREATE TABLE tx_locator_map (
    block_height INTEGER NOT NULL,
    tx_index INTEGER NOT NULL,
    txid BLOB NOT NULL UNIQUE,
    PRIMARY KEY (block_height, tx_index)
)";

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

//
// Internal tables
//

pub(super) const TABLE_SCHEMER_MIGRATIONS: &str = "
CREATE TABLE schemer_migrations (
    id blob PRIMARY KEY
)";

/// Internal table created by SQLite when we started using `AUTOINCREMENT`.
pub(super) const TABLE_SQLITE_SEQUENCE: &str = "CREATE TABLE sqlite_sequence(name,seq)";
