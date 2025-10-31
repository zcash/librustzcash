//! Documentation about the wallet database structure.
//!
//! The database structure is managed by [`crate::wallet::init::WalletMigrator`], which
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
///
/// An account corresponds to a logical "bucket of funds" that has its own balance within the
/// wallet and for which spending operations should treat received value as interchangeable,
/// excepting situations where care must be taken to avoid publicly linking addresses within the
/// account or where turnstile-crossings may have privacy implications.
///
/// ### Columns
///
/// - `id`: Internal primary key for the account record.
/// - `name`: A human-readable reference for the account. This column is present merely as a
///   convenience for front-ends and debugging; it has no stable semantics and values are not
///   required to be unique.
/// - `uuid`: A wallet-instance-specific identifier for the account. This identifier will remain
///   stable for the lifetime of the wallet database, but is not expected or required to be
///   stable across wallet restores and it should not be stored in external backup formats.
/// - `account_kind`: 0 for accounts derived from a mnemonic seed, 1 for imported accounts
///   for which derivation path information may not be available. This column may be removed in the
///   future; the distinction between whether an account is derived or imported is better
///   represented by the presence or absence of HD seed fingerprint and HD account index data.
/// - `hd_seed_fingerprint`: If this account contains funds in keys obtained via HD derivation,
///   the ZIP 32 fingerprint of the root HD seed. If this column is non-null, `hd_account_index`
///   must also be non-null.
/// - `hd_account_index`: If this account contains funds in keys obtained via HD derivation,
///   the BIP 44 account-level component of the HD derivation path. If this column is non-null,
///   `hd_seed_fingerprint` must also be non-null.
/// - `ufvk`: The unified full viewing key for the account, if known.
/// - `uivk`: The unified incoming viewing key for the account.
/// - `orchard_fvk_item_cache`: The serialized representation of the Orchard item of the `ufvk`,
///   if any.
/// - `sapling_fvk_item_cache`: The serialized representation of the Sapling item of the `ufvk`,
///   if any.
/// - `p2pkh_fvk_item_cache`: The serialized representation of the P2PKH item of the `ufvk`,
///   if any.
/// - `birthday_height`: The minimum block height among blocks that may potentially contain
///   shielded funds belonging to the account.
/// - `birthday_sapling_tree_size`: A cache of the size of the Sapling note commitment tree
///   as of the start of the birthday block.
/// - `birthday_orchard_tree_size`: A cache of the size of the Orchard note commitment tree
///   as of the start of the birthday block.
/// - `recover_until_height`: The boundary between recovery and regular scanning for this account.
///   Unscanned blocks up to and excluding this height are counted towards recovery progress. It
///   is initially set via the `AccountBirthday` parameter of the `WalletWrite::import_account_*`
///   methods (usually to the chain tip height at which account recovery was initiated), and may
///   in future be automatically updated by the backend if the wallet is offline for an extended
///   period (to keep the scan progress percentage accurate to what actually needs scanning).
/// - `has_spend_key`: A boolean flag (0 or 1) indicating whether the application that embeds
///   this wallet database has access to spending key(s) for the account.
/// - `zcash_legacy_address_index`: This column is only potentially populated for wallets imported
///   from a `zcashd` `wallet.dat` file, for "standalone" Sapling addresses (each of which
///   corresponds to an independent account) derived after the introduction of mnemonic seed
///   derivation in the `4.7.0` `zcashd` release. This column will only be non-negative in
///   the case that the `hd_account_index` column has the value `0x7FFFFFFF`, in accordance with
///   how post-v4.7.0 Sapling addresses were produced by the `z_getnewaddress` RPC method.
///   This relationship is not currently enforced by a CHECK constraint; such a constraint should
///   be added the next time that the `accounts` table is deleted and re-created to support a
///   SQLite-breaking change to the columns of the table.
pub(super) const TABLE_ACCOUNTS: &str = r#"
CREATE TABLE "accounts" (
    id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    uuid BLOB NOT NULL,
    account_kind INTEGER NOT NULL DEFAULT 0,
    key_source TEXT,
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
    has_spend_key INTEGER NOT NULL DEFAULT 1,
    zcashd_legacy_address_index INTEGER NOT NULL DEFAULT -1,
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
        AND (hd_seed_fingerprint IS NULL) = (hd_account_index IS NULL)
      )
    )
)"#;
pub(super) const INDEX_ACCOUNTS_UUID: &str =
    r#"CREATE UNIQUE INDEX accounts_uuid ON accounts (uuid)"#;
pub(super) const INDEX_ACCOUNTS_UFVK: &str =
    r#"CREATE UNIQUE INDEX accounts_ufvk ON accounts (ufvk)"#;
pub(super) const INDEX_ACCOUNTS_UIVK: &str =
    r#"CREATE UNIQUE INDEX accounts_uivk ON accounts (uivk)"#;
pub(super) const INDEX_HD_ACCOUNT: &str = r#"CREATE UNIQUE INDEX hd_account ON accounts (hd_seed_fingerprint, hd_account_index, zcashd_legacy_address_index)"#;

/// Stores addresses that have been generated from accounts in the wallet.
///
/// ### Columns
///
/// - `account_id`: the account whose IVK was used to derive this address.
/// - `diversifier_index_be`: the diversifier index at which this address was derived.
///   This may be null for imported standalone addresses.
/// - `key_scope`: the BIP 44 change-level index at which this address was derived, or `-1`
///   for imported transparent pubkeys.
/// - `address`: The Unified, Sapling, or transparent address. For Unified and Sapling addresses,
///   only external-key scoped addresses should be stored in this table; for purely transparent
///   addresses, this may be an internal-scope (change) address, so that we can provide
///   compatibility with HD-derived change addresses produced by transparent-only wallets.
/// - `transparent_child_index`: the diversifier index in integer form, if it is in the range of a  `u31`
///   (i.e. a non-hardened transparent address index). It is used for gap limit handling, and is set
///   whenever a transparent address at a given index should be scanned at receive time. This
///   includes:
///   - Unified Addresses with transparent receivers (at any valid index).
///   - Unified Addresses without transparent receivers, but within the gap limit of potential
///     sequential transparent addresses.
///   - Transparent change addresses.
///   - ZIP 320 ephemeral addresses.
///
///   This column exists because the diversifier index is stored as a byte array, meaning that we
///   cannot use SQL integer operations on it for gap limit calculations, and thus need it as an
///   integer as well.
/// - `cached_transparent_receiver_address`: the transparent address derived from the same
///   viewing key and at the same diversifier index as `address`. This may be the same as `address`
///   in the case of an internal-scope transparent change address or a ZIP 320 interstitial
///   address, and it may be a receiver within `address` in the case of a Unified Address with
///   transparent receiver. It is cached directly in the table to make account lookups for
///   transparent outputs more efficient, enabling joins to [`TABLE_TRANSPARENT_RECEIVED_OUTPUTS`].
/// - `exposed_at_height`: Our best knowledge as to when this address was first exposed to the
///   wider ecosystem.
///   - For user-generated addresses, this is the chain tip height at the time that the address was
///     generated by an explicit request by the user or reserved for use in a ZIP 320 transaction.
///     These heights are not recoverable from chain.
///   - In the case of an address with its first use discovered in a transaction obtained by scanning
///     the chain, this will be set to the mined height of that transaction. In recover from seed
///     cases, this is what user-generated addresses will be assigned.
/// - `receiver_flags`: A set of bitflags that describes which receiver types are included in
///   `address`. See the documentation of [`ReceiverFlags`] for details.
/// - `transparent_receiver_next_check_time`: The Unix epoch time at which a client should next
///   check to determine whether any new UTXOs have been received by the cached transparent receiver
///   address. At present, this will ordinarily be populated only for ZIP 320 ephemeral addresses.
//  - `imported_transparent_receiver_pubkey`: The 33-byte pubkey corresponding to the
//    `cached_transparent_receiver_address` value, for imported transparent addresses that were not
//    obtained via derivation from an HD seed associated with the account. In cases that
//    `cached_transparent_receiver_address` is non-null, either this column or
//    `transparent_child_index` must also be non-null.
///
/// [`ReceiverFlags`]: crate::wallet::encoding::ReceiverFlags
pub(super) const TABLE_ADDRESSES: &str = r#"
CREATE TABLE "addresses" (
    id INTEGER NOT NULL PRIMARY KEY,
    account_id INTEGER NOT NULL
        REFERENCES accounts(id) ON DELETE CASCADE,
    key_scope INTEGER NOT NULL,
    diversifier_index_be BLOB,
    address TEXT NOT NULL,
    transparent_child_index INTEGER,
    cached_transparent_receiver_address TEXT,
    exposed_at_height INTEGER,
    receiver_flags INTEGER NOT NULL,
    transparent_receiver_next_check_time INTEGER,
    imported_transparent_receiver_pubkey BLOB,
    UNIQUE (account_id, key_scope, diversifier_index_be),
    UNIQUE (imported_transparent_receiver_pubkey),
    CONSTRAINT ck_addr_transparent_index_consistency CHECK (
        (transparent_child_index IS NULL OR diversifier_index_be < x'0000000F00000000000000')
        AND (
            (
                cached_transparent_receiver_address IS NULL
                AND transparent_child_index IS NULL
                AND imported_transparent_receiver_pubkey IS NULL
            )
            OR (
                cached_transparent_receiver_address IS NOT NULL
                AND (transparent_child_index IS NULL) == (imported_transparent_receiver_pubkey IS NOT NULL)
            )
        )
    ),
    CONSTRAINT ck_addr_foreign_or_diversified CHECK (
        (diversifier_index_be IS NULL) == (key_scope = -1)
    )
)"#;
pub(super) const INDEX_ADDRESSES_ACCOUNTS: &str = r#"
CREATE INDEX idx_addresses_accounts ON addresses (
    account_id ASC
)"#;
pub(super) const INDEX_ADDRESSES_INDICES: &str = r#"
CREATE INDEX idx_addresses_indices ON addresses (
    diversifier_index_be ASC
)"#;
pub(super) const INDEX_ADDRESSES_PUBKEYS: &str = r#"
CREATE INDEX idx_addresses_pubkeys ON addresses (
    imported_transparent_receiver_pubkey ASC
)"#;
pub(super) const INDEX_ADDRESSES_T_INDICES: &str = r#"
CREATE INDEX idx_addresses_t_indices ON addresses (
    transparent_child_index ASC
)"#;

/// Stores information about every block that the wallet has scanned.
///
/// Note that this table does not contain any rows for blocks that the wallet might have
/// observed partial information about (for example, a transparent output fetched and
/// stored in [`TABLE_TRANSPARENT_RECEIVED_OUTPUTS`]). This may change in future.
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
/// Any transactions that the wallet observes as being associated with one of the accounts in
/// [`TABLE_ACCOUNTS`] may be tracked in this table. As a result, this table may contain
/// data that is not recoverable from the chain (for example, transactions created by the
/// wallet that expired before being mined).
///
/// When an account is deleted, all transactions that are associated with that account in some way
/// that are not associated with any *other* account in the wallet must be first be deleted before
/// the account deletion operation is allowed to proceed.
///
/// ### Columns
/// - `created`: The time at which the transaction was created as a string in the format
///   `yyyy-MM-dd HH:mm:ss.fffffffzzz`.
/// - `block`: stores the height (in the wallet's chain view) of the mined block containing the
///   transaction. It is `NULL` for transactions that have not yet been observed in scanned blocks,
///   including transactions in the mempool or that have expired.
/// - `mined_height`: stores the height (in the wallet's chain view) of the mined block containing
///   the transaction. It is present to allow the block height for a retrieved transaction to be
///   stored without requiring that the entire block containing the transaction be scanned; the
///   foreign key constraint on `block` prevents that column from being populated prior to complete
///   scanning of the block. This is constrained to be equal to the `block` column if `block` is
///   non-null.
/// - `tx_index`: the index of the transaction within the block.
/// - `expiry_height`: stores the maximum height at which the transaction may be mined, if known.
/// - `raw`: the original serialized byte representation of the transaction, if it has been
///   retrieved.
/// - `fee`: the fee paid to send the transaction, if known. This should be present for all
///   transactions constructed by this wallet.
/// - `target_height`: stores the target height for which the transaction was constructed, if
///   known. This will ordinarily be null for transactions discovered via chain scanning; it
///   will only be set for transactions created using this wallet specifically, and not any
///   other wallet that uses the same seed (including previous installations of the same
///   wallet application.)
/// - `min_observed_height`: the mempool height at the time that the wallet observed the
///   transaction, or the mined height of the transaction, whichever is less.
/// - `confirmed_unmined_at_height`: the maximum block height at which the wallet has observed
///   positive proof that the transaction has not been mined in a block. Must be NULL if
///   `mined_height` is not null.
/// - `trust_status`: A flag indicating whether the transaction should be considered "trusted".
///   When set to `1`, outputs of this transaction will be considered spendable with `trusted`
///   confirmations instead of `untrusted` confirmations.
pub(super) const TABLE_TRANSACTIONS: &str = r#"
CREATE TABLE "transactions" (
    id_tx INTEGER PRIMARY KEY,
    txid BLOB NOT NULL UNIQUE,
    created TEXT,
    block INTEGER,
    mined_height INTEGER,
    tx_index INTEGER,
    expiry_height INTEGER,
    raw BLOB,
    fee INTEGER,
    target_height INTEGER,
    min_observed_height INTEGER NOT NULL,
    confirmed_unmined_at_height INTEGER,
    trust_status INTEGER,
    FOREIGN KEY (block) REFERENCES blocks(height),
    CONSTRAINT height_consistency CHECK (
        block IS NULL OR mined_height = block
    ),
    CONSTRAINT min_observed_consistency CHECK (
        mined_height IS NULL OR min_observed_height <= mined_height
    ),
    CONSTRAINT confirmed_unmined_consistency CHECK (
        confirmed_unmined_at_height IS NULL OR mined_height IS NULL
    )
)"#;

/// Stores the Sapling notes received by the wallet.
///
/// Note spentness is tracked in [`TABLE_SAPLING_RECEIVED_NOTE_SPENDS`].
///
/// ### Columns
/// - `transaction_id`: a foreign key reference to the transaction that contained this output
/// - `output_index`: the index of this Sapling output in the transaction
/// - `account_id`: a foreign key reference to the account whose ivk decrypted this output
/// - `diversifier`: the diversifier used to construct the note
/// - `value`: the value of the note
/// - `rcm`: the random commitment trapdoor for the note
/// - `nf`: the nullifier that will be exposed when the note is spent
/// - `is_change`: a flag indicating whether the note was received in a transaction where
///   the receiving account also spent notes.
/// - `memo`: the memo output associated with the note, if known
/// - `commitment_tree_position`: the 0-based index of the note in the leaves of the note
///   commitment tree.
/// - `recipient_key_scope`: the ZIP 32 key scope of the key that decrypted this output,
///   encoded as `0` for external scope and `1` for internal scope.
/// - `address_id`: a foreign key to the address that this note was sent to; null in the
///   case that the note was sent to an internally-scoped address (we never store addresses
///   containing internal Sapling receivers in the `addresses` table).
pub(super) const TABLE_SAPLING_RECEIVED_NOTES: &str = r#"
CREATE TABLE "sapling_received_notes" (
    id INTEGER PRIMARY KEY,
    transaction_id INTEGER NOT NULL
        REFERENCES transactions(id_tx) ON DELETE CASCADE,
    output_index INTEGER NOT NULL,
    account_id INTEGER NOT NULL
        REFERENCES accounts(id) ON DELETE CASCADE,
    diversifier BLOB NOT NULL,
    value INTEGER NOT NULL,
    rcm BLOB NOT NULL,
    nf BLOB UNIQUE,
    is_change INTEGER NOT NULL,
    memo BLOB,
    commitment_tree_position INTEGER,
    recipient_key_scope INTEGER,
    address_id INTEGER
        REFERENCES addresses(id) ON DELETE CASCADE,
    UNIQUE (transaction_id, output_index)
)"#;
pub(super) const INDEX_SAPLING_RECEIVED_NOTES_ACCOUNT: &str = r#"
CREATE INDEX idx_sapling_received_notes_account ON sapling_received_notes (
    account_id ASC
)"#;
pub(super) const INDEX_SAPLING_RECEIVED_NOTES_ADDRESS: &str = r#"
CREATE INDEX idx_sapling_received_notes_address ON sapling_received_notes (
    address_id ASC
)"#;
pub(super) const INDEX_SAPLING_RECEIVED_NOTES_TX: &str = r#"
CREATE INDEX idx_sapling_received_notes_tx ON sapling_received_notes (
    transaction_id ASC
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
pub(super) const TABLE_SAPLING_RECEIVED_NOTE_SPENDS: &str = r#"
CREATE TABLE "sapling_received_note_spends" (
    sapling_received_note_id INTEGER NOT NULL
        REFERENCES sapling_received_notes(id) ON DELETE CASCADE,
    transaction_id INTEGER NOT NULL
        REFERENCES transactions(id_tx) ON DELETE CASCADE,
    UNIQUE (sapling_received_note_id, transaction_id)
)"#;
pub(super) const INDEX_SAPLING_RNS_NOTE: &str = r#"
CREATE INDEX idx_sapling_received_note_spends_note_id ON sapling_received_note_spends (
    sapling_received_note_id ASC
)"#;
pub(super) const INDEX_SAPLING_RNS_TX: &str = r#"
CREATE INDEX idx_sapling_received_note_spends_transaction_id ON sapling_received_note_spends (
    transaction_id ASC
)"#;

/// Stores the Orchard notes received by the wallet.
///
/// Note spentness is tracked in [`TABLE_ORCHARD_RECEIVED_NOTE_SPENDS`].
///
/// ### Columns
/// - `transaction_id`: a foreign key reference to the transaction that contained this output
/// - `action_index`: the index of the Orchard action that produced this note in the transaction
/// - `account_id`: a foreign key reference to the account whose ivk decrypted this output
/// - `diversifier`: the diversifier used to construct the note
/// - `value`: the value of the note
/// - `rho`: the rho value used to derive the nullifier of the note
/// - `rseed`: the rseed value used to generate the note
/// - `nf`: the nullifier that will be exposed when the note is spent
/// - `is_change`: a flag indicating whether the note was received in a transaction where
///   the receiving account also spent notes.
/// - `memo`: the memo output associated with the note, if known
/// - `commitment_tree_position`: the 0-based index of the note in the leaves of the note
///   commitment tree.
/// - `recipient_key_scope`: the ZIP 32 key scope of the key that decrypted this output,
///   encoded as `0` for external scope and `1` for internal scope.
/// - `address_id`: a foreign key to the address that this note was sent to; null in the
///   case that the note was sent to an internally-scoped address (we never store addresses
///   containing internal Orchard receivers in the `addresses` table).
pub(super) const TABLE_ORCHARD_RECEIVED_NOTES: &str = r#"
CREATE TABLE "orchard_received_notes" (
    id INTEGER PRIMARY KEY,
    transaction_id INTEGER NOT NULL
        REFERENCES transactions(id_tx) ON DELETE CASCADE,
    action_index INTEGER NOT NULL,
    account_id INTEGER NOT NULL
        REFERENCES accounts(id) ON DELETE CASCADE,
    diversifier BLOB NOT NULL,
    value INTEGER NOT NULL,
    rho BLOB NOT NULL,
    rseed BLOB NOT NULL,
    nf BLOB UNIQUE,
    is_change INTEGER NOT NULL,
    memo BLOB,
    commitment_tree_position INTEGER,
    recipient_key_scope INTEGER,
    address_id INTEGER
        REFERENCES addresses(id) ON DELETE CASCADE,
    UNIQUE (transaction_id, action_index)
)"#;
pub(super) const INDEX_ORCHARD_RECEIVED_NOTES_ACCOUNT: &str = r#"
CREATE INDEX idx_orchard_received_notes_account ON orchard_received_notes (
    account_id ASC
)"#;
pub(super) const INDEX_ORCHARD_RECEIVED_NOTES_ADDRESS: &str = r#"
CREATE INDEX idx_orchard_received_notes_address ON orchard_received_notes (
    address_id ASC
)"#;
pub(super) const INDEX_ORCHARD_RECEIVED_NOTES_TX: &str = r#"
CREATE INDEX idx_orchard_received_notes_tx ON orchard_received_notes (
    transaction_id ASC
)"#;

/// A junction table between received Orchard notes and the transactions that spend them.
///
/// Thie plays the same role for Orchard notes as does [`TABLE_SAPLING_RECEIVED_NOTE_SPENDS`] for
/// Sapling notes; see its documentation for details.
pub(super) const TABLE_ORCHARD_RECEIVED_NOTE_SPENDS: &str = r#"
CREATE TABLE "orchard_received_note_spends" (
    orchard_received_note_id INTEGER NOT NULL
        REFERENCES orchard_received_notes(id) ON DELETE CASCADE,
    transaction_id INTEGER NOT NULL
        REFERENCES transactions(id_tx) ON DELETE CASCADE,
    UNIQUE (orchard_received_note_id, transaction_id)
)"#;
pub(super) const INDEX_ORCHARD_RNS_NOTE: &str = r#"
CREATE INDEX idx_orchard_received_note_spends_note_id ON orchard_received_note_spends (
    orchard_received_note_id ASC
)"#;
pub(super) const INDEX_ORCHARD_RNS_TX: &str = r#"
CREATE INDEX idx_orchard_received_note_spends_transaction_id ON orchard_received_note_spends (
    transaction_id ASC
)"#;

/// Stores the transparent outputs received by the wallet.
///
/// Originally this table only stored the current UTXO set (as of latest refresh), and the
/// table was cleared prior to loading in the latest UTXO set. We now upsert instead of
/// insert into the database, meaning that spent outputs are left in the database. This
/// makes it similar to the `*_received_notes` tables in that it can store history.
/// Depending upon how transparent TXOs for the wallet are discovered, the following
/// may be true:
/// - The table may have incomplete contents for recovered-from-seed wallets.
/// - The table may have inconsistent contents for seeds loaded into multiple wallets
///   simultaneously.
/// - The wallet's transparent balance may be incorrect prior to "transaction enhancement"
///   (downloading the full transaction containing the transparent output spend).
///
/// ### Columns:
/// - `id`: Primary key
/// - `transaction_id`: Reference to the transaction in which this TXO was created
/// - `output_index`: The output index of this TXO in the transaction referred to by `transaction_id`
/// - `account_id`: The account that controls spend authority for this TXO
/// - `address`: The address to which this TXO was sent. We store this address to make querying
///   for UTXOs for a single address easier, because when shielding we always select UTXOs
///   for only a single address at a time to prevent linking addresses in the shielding
///   transaction.
/// - `script`: The full txout script
/// - `value_zat`: The value of the TXO in zatoshis
/// - `max_observed_unspent_height`: The maximum block height at which this TXO was observed to be
///   a member of the UTXO set as of the end of the block.
/// - `address_id`: a foreign key to the address that this note was sent to; non-null because
///   we can only find transparent outputs for known addresses (and therefore we must record
///   both internal and external addresses in the `addresses` table).
pub(super) const TABLE_TRANSPARENT_RECEIVED_OUTPUTS: &str = r#"
CREATE TABLE "transparent_received_outputs" (
    id INTEGER PRIMARY KEY,
    transaction_id INTEGER NOT NULL
        REFERENCES transactions(id_tx) ON DELETE CASCADE,
    output_index INTEGER NOT NULL,
    account_id INTEGER NOT NULL
        REFERENCES accounts(id) ON DELETE CASCADE,
    address TEXT NOT NULL,
    script BLOB NOT NULL,
    value_zat INTEGER NOT NULL,
    max_observed_unspent_height INTEGER,
    address_id INTEGER NOT NULL
        REFERENCES addresses(id) ON DELETE CASCADE,
    UNIQUE (transaction_id, output_index)
)"#;
pub(super) const INDEX_TRANSPARENT_RECEIVED_OUTPUTS_ACCOUNT: &str = r#"
CREATE INDEX idx_transparent_received_outputs_account ON transparent_received_outputs (
    account_id
)"#;
pub(super) const INDEX_TRANSPARENT_RECEIVED_OUTPUTS_ADDRESS: &str = r#"
CREATE INDEX idx_transparent_received_outputs_address ON transparent_received_outputs (
    address_id
)"#;
pub(super) const INDEX_TRANSPARENT_RECEIVED_OUTPUTS_TX: &str = r#"
CREATE INDEX idx_transparent_received_outputs_tx ON transparent_received_outputs (
    transaction_id
)"#;

/// A junction table between received transparent outputs and the transactions that spend them.
///
/// This plays the same role for transparent TXOs as does [`TABLE_SAPLING_RECEIVED_NOTE_SPENDS`]
/// for Sapling notes. However, [`TABLE_TRANSPARENT_RECEIVED_OUTPUTS`] differs from
/// [`TABLE_SAPLING_RECEIVED_NOTES`] and [`TABLE_ORCHARD_RECEIVED_NOTES`] in that an
/// associated `transactions` record may have its `mined_height` set without there existing a
/// corresponding record in the `blocks` table for a block at that height, due to the asymmetries
/// between scanning for shielded notes and retrieving transparent TXOs currently implemented
/// in [`zcash_client_backend`].
pub(super) const TABLE_TRANSPARENT_RECEIVED_OUTPUT_SPENDS: &str = r#"
CREATE TABLE "transparent_received_output_spends" (
    transparent_received_output_id INTEGER NOT NULL
        REFERENCES transparent_received_outputs(id) ON DELETE CASCADE,
    transaction_id INTEGER NOT NULL
        REFERENCES transactions(id_tx) ON DELETE CASCADE,
    UNIQUE (transparent_received_output_id, transaction_id)
)"#;

pub(super) const INDEX_TRANSPARENT_ROS_OUTPUT: &str = r#"
CREATE INDEX idx_transparent_received_output_spends_output_id ON transparent_received_output_spends (
    transparent_received_output_id ASC
)"#;
pub(super) const INDEX_TRANSPARENT_ROS_TX: &str = r#"
CREATE INDEX idx_transparent_received_output_spends_transaction_id ON transparent_received_output_spends (
    transaction_id ASC
)"#;

/// A cache of the relationship between a transaction and the prevout data of its
/// transparent inputs.
///
/// This table is used in out-of-order wallet recovery to cache the information about
/// what transaction(s) spend each transparent outpoint, so that if an output belonging
/// to the wallet is detected after the transaction that spends it has been processed,
/// the spend can also be recorded as part of the process of adding the output to
/// [`TABLE_TRANSPARENT_RECEIVED_OUTPUTS`].
pub(super) const TABLE_TRANSPARENT_SPEND_MAP: &str = r#"
CREATE TABLE "transparent_spend_map" (
    spending_transaction_id INTEGER NOT NULL
        REFERENCES transactions(id_tx) ON DELETE CASCADE,
    prevout_txid BLOB NOT NULL,
    prevout_output_index INTEGER NOT NULL,
    -- NOTE: We can't create a unique constraint on just (prevout_txid, prevout_output_index)
    -- because the same output may be attempted to be spent in multiple transactions, even
    -- though only one will ever be mined.
    UNIQUE (spending_transaction_id, prevout_txid, prevout_output_index)
)"#;
pub(super) const INDEX_TRANSPARENT_SPEND_MAP_TX: &str = r#"
CREATE INDEX idx_transparent_spend_map_transaction_id ON transparent_spend_map (
    spending_transaction_id ASC
)"#;

/// Stores the outputs of transactions created by the wallet.
///
/// Unlike with outputs received by the wallet, we store sent outputs for all pools in
/// this table, distinguished by the `output_pool` column. The information we want to
/// record for sent outputs is the same across all pools, whereas for received outputs we
/// want to cache pool-specific data.
///
/// ### Columns
/// - `(transaction_id, output_pool, output_index)` collectively identify a transaction output.
/// - `from_account_id`: the ID of the account that created the transaction.
///   - On recover-from-seed or when scanning by UFVK, this will be either the account
///     that decrypted the output, or one of the accounts that funded the transaction.
/// - `to_address`: the address of the external recipient of this output, or `NULL` if the
///   output was received by the wallet.
/// - `to_account_id`: the ID of the account that received this output, or `NULL` if the
///   output was for an external recipient.
/// - `value`: the value of the output in zatoshis.
/// - `memo`: the memo bytes associated with this output, if known.
///   - This is always `NULL` for transparent outputs.
///   - This will be set for all shielded outputs of transactions created by the wallet.
///   - On recover-from-seed or when scanning by UFVK, this will only be set for shielded
///     outputs after post-scanning transaction enhancement. For shielded notes sent to
///     external recipients, the transaction needs to have been created with an
///     [`OvkPolicy`] using a known OVK.
///
/// [`OvkPolicy`]: zcash_client_backend::wallet::OvkPolicy
pub(super) const TABLE_SENT_NOTES: &str = r#"
CREATE TABLE "sent_notes" (
    id INTEGER PRIMARY KEY,
    transaction_id INTEGER NOT NULL
        REFERENCES transactions(id_tx) ON DELETE CASCADE,
    output_pool INTEGER NOT NULL,
    output_index INTEGER NOT NULL,
    from_account_id INTEGER NOT NULL
        REFERENCES accounts(id) ON DELETE CASCADE,
    to_address TEXT,
    to_account_id INTEGER
        REFERENCES accounts(id) ON DELETE SET NULL,
    value INTEGER NOT NULL,
    memo BLOB,
    UNIQUE (transaction_id, output_pool, output_index)
)"#;
pub(super) const INDEX_SENT_NOTES_FROM_ACCOUNT: &str = r#"
CREATE INDEX idx_sent_notes_from_account ON sent_notes (
    from_account_id
)"#;
pub(super) const INDEX_SENT_NOTES_TO_ACCOUNT: &str = r#"
CREATE INDEX idx_sent_notes_to_account ON sent_notes (
    to_account_id
)"#;
pub(super) const INDEX_SENT_NOTES_TX: &str = r#"
CREATE INDEX idx_sent_notes_transaction_id ON sent_notes (
    transaction_id
)"#;

/// Stores the set of transaction ids for which the backend required additional data.
///
/// ### Columns:
/// - `txid`: The transaction identifier for the transaction to retrieve state information for.
/// - `query_type`:
///     - `0` for raw transaction (enhancement) data,
///     - `1` for transaction mined-ness information.
/// - `dependent_transaction_id`: If the transaction data request is searching for information
///   about transparent inputs to a transaction, this is a reference to that transaction record.
///   NULL for transactions where the request for enhancement data is based on discovery due
///   to blockchain scanning.
pub(super) const TABLE_TX_RETRIEVAL_QUEUE: &str = r#"
CREATE TABLE "tx_retrieval_queue" (
    txid BLOB NOT NULL UNIQUE,
    query_type INTEGER NOT NULL,
    dependent_transaction_id INTEGER
        REFERENCES transactions(id_tx) ON DELETE CASCADE
)"#;
pub(super) const INDEX_TX_RETIREVAL_QUEUE_DEPENDENT_TX: &str = r#"
CREATE INDEX idx_tx_retrieval_queue_dependent_tx ON tx_retrieval_queue (
    dependent_transaction_id
)"#;

/// Stores the set of transaction outputs received by the wallet for which spend information
/// (if any) should be retrieved.
///
/// This table is populated in the process of wallet recovery when a deshielding transaction
/// with transparent outputs belonging to the wallet (e.g., the deshielding half of a ZIP 320
/// transaction pair) is discovered. It is expected that such a transparent output will be
/// spent soon after it is received in a purely transparent transaction, which the wallet
/// currently has no means of detecting otherwise.
pub(super) const TABLE_TRANSPARENT_SPEND_SEARCH_QUEUE: &str = r#"
CREATE TABLE "transparent_spend_search_queue" (
    address TEXT NOT NULL,
    transaction_id INTEGER NOT NULL
        REFERENCES transactions(id_tx) ON DELETE CASCADE,
    output_index INTEGER NOT NULL,
    UNIQUE (transaction_id, output_index)
)"#;
pub(super) const INDEX_TRANSPARENT_SPEND_SEARCH_TX: &str = r#"
CREATE INDEX idx_tssq_transaction_id ON transparent_spend_search_queue (
    transaction_id
)"#;

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

/// Internal table used by [`schemerz`] to manage migrations.
pub(super) const TABLE_SCHEMERZ_MIGRATIONS: &str = "
CREATE TABLE schemer_migrations (
    id blob PRIMARY KEY
)";

/// Internal table created by SQLite when we started using `AUTOINCREMENT`.
pub(super) const TABLE_SQLITE_SEQUENCE: &str = "CREATE TABLE sqlite_sequence(name,seq)";

//
// Views
//

pub(super) const VIEW_RECEIVED_OUTPUTS: &str = "
CREATE VIEW v_received_outputs AS
    SELECT
        sapling_received_notes.id AS id_within_pool_table,
        sapling_received_notes.transaction_id,
        2 AS pool,
        sapling_received_notes.output_index,
        account_id,
        sapling_received_notes.value,
        is_change,
        sapling_received_notes.memo,
        sent_notes.id AS sent_note_id,
        sapling_received_notes.address_id
    FROM sapling_received_notes
    LEFT JOIN sent_notes
    ON (sent_notes.transaction_id, sent_notes.output_pool, sent_notes.output_index) =
       (sapling_received_notes.transaction_id, 2, sapling_received_notes.output_index)
UNION
    SELECT
        orchard_received_notes.id AS id_within_pool_table,
        orchard_received_notes.transaction_id,
        3 AS pool,
        orchard_received_notes.action_index AS output_index,
        account_id,
        orchard_received_notes.value,
        is_change,
        orchard_received_notes.memo,
        sent_notes.id AS sent_note_id,
        orchard_received_notes.address_id
    FROM orchard_received_notes
    LEFT JOIN sent_notes
    ON (sent_notes.transaction_id, sent_notes.output_pool, sent_notes.output_index) =
       (orchard_received_notes.transaction_id, 3, orchard_received_notes.action_index)
UNION
    SELECT
        u.id AS id_within_pool_table,
        u.transaction_id,
        0 AS pool,
        u.output_index,
        u.account_id,
        u.value_zat AS value,
        0 AS is_change,
        NULL AS memo,
        sent_notes.id AS sent_note_id,
        u.address_id
    FROM transparent_received_outputs u
    LEFT JOIN sent_notes
    ON (sent_notes.transaction_id, sent_notes.output_pool, sent_notes.output_index) =
       (u.transaction_id, 0, u.output_index)";

pub(super) const VIEW_RECEIVED_OUTPUT_SPENDS: &str = "
CREATE VIEW v_received_output_spends AS
SELECT
    2 AS pool,
    s.sapling_received_note_id AS received_output_id,
    s.transaction_id,
    rn.account_id
FROM sapling_received_note_spends s
JOIN sapling_received_notes rn ON rn.id = s.sapling_received_note_id
UNION
SELECT
    3 AS pool,
    s.orchard_received_note_id AS received_output_id,
    s.transaction_id,
    rn.account_id
FROM orchard_received_note_spends s
JOIN orchard_received_notes rn ON rn.id = s.orchard_received_note_id
UNION
SELECT
    0 AS pool,
    s.transparent_received_output_id AS received_output_id,
    s.transaction_id,
    rn.account_id
FROM transparent_received_output_spends s
JOIN transparent_received_outputs rn ON rn.id = s.transparent_received_output_id";

pub(super) const VIEW_TRANSACTIONS: &str = "
CREATE VIEW v_transactions AS
WITH
notes AS (
    -- Outputs received in this transaction
    SELECT ro.account_id              AS account_id,
           ro.transaction_id          AS transaction_id,
           ro.pool                    AS pool,
           id_within_pool_table,
           ro.value                   AS value,
           ro.value                   AS received_value,
           0                          AS spent_value,
           0                          AS spent_note_count,
           CASE
                WHEN ro.is_change THEN 1
                ELSE 0
           END AS change_note_count,
           CASE
                WHEN ro.is_change THEN 0
                ELSE 1
           END AS received_count,
           CASE
             WHEN (ro.memo IS NULL OR ro.memo = X'F6')
               THEN 0
             ELSE 1
           END AS memo_present,
           -- The wallet cannot receive transparent outputs in shielding transactions.
           CASE
             WHEN ro.pool = 0
               THEN 1
             ELSE 0
           END AS does_not_match_shielding
    FROM v_received_outputs ro
    UNION
    -- Outputs spent in this transaction
    SELECT ro.account_id              AS account_id,
           ros.transaction_id         AS transaction_id,
           ro.pool                    AS pool,
           id_within_pool_table,
           -ro.value                  AS value,
           0                          AS received_value,
           ro.value                   AS spent_value,
           1                          AS spent_note_count,
           0                          AS change_note_count,
           0                          AS received_count,
           0                          AS memo_present,
           -- The wallet cannot spend shielded outputs in shielding transactions.
           CASE
             WHEN ro.pool != 0
               THEN 1
             ELSE 0
           END AS does_not_match_shielding
    FROM v_received_outputs ro
    JOIN v_received_output_spends ros
         ON ros.pool = ro.pool
         AND ros.received_output_id = ro.id_within_pool_table
),
-- Obtain a count of the notes that the wallet created in each transaction,
-- not counting change notes.
sent_note_counts AS (
    SELECT sent_notes.from_account_id     AS account_id,
           sent_notes.transaction_id      AS transaction_id,
           COUNT(DISTINCT sent_notes.id)  AS sent_notes,
           SUM(
             CASE
               WHEN (sent_notes.memo IS NULL OR sent_notes.memo = X'F6' OR ro.transaction_id IS NOT NULL)
                 THEN 0
               ELSE 1
             END
           ) AS memo_count
    FROM sent_notes
    LEFT JOIN v_received_outputs ro ON sent_notes.id = ro.sent_note_id
    WHERE COALESCE(ro.is_change, 0) = 0
    GROUP BY account_id, sent_notes.transaction_id
),
blocks_max_height AS (
    SELECT MAX(blocks.height) AS max_height FROM blocks
)
SELECT accounts.uuid                AS account_uuid,
       transactions.mined_height    AS mined_height,
       transactions.txid            AS txid,
       transactions.tx_index        AS tx_index,
       transactions.expiry_height   AS expiry_height,
       transactions.raw             AS raw,
       SUM(notes.value)             AS account_balance_delta,
       SUM(notes.spent_value)       AS total_spent,
       SUM(notes.received_value)    AS total_received,
       transactions.fee             AS fee_paid,
       SUM(notes.change_note_count) > 0  AS has_change,
       MAX(COALESCE(sent_note_counts.sent_notes, 0))  AS sent_note_count,
       SUM(notes.received_count)         AS received_note_count,
       SUM(notes.memo_present) + MAX(COALESCE(sent_note_counts.memo_count, 0)) AS memo_count,
       blocks.time                       AS block_time,
       (
            transactions.mined_height IS NULL
            AND transactions.expiry_height BETWEEN 1 AND blocks_max_height.max_height
       ) AS expired_unmined,
       SUM(notes.spent_note_count) AS spent_note_count,
       (
            -- All of the wallet-spent and wallet-received notes are consistent with a
            -- shielding transaction.
            SUM(notes.does_not_match_shielding) = 0
            -- The transaction contains at least one wallet-spent output.
            AND SUM(notes.spent_note_count) > 0
            -- The transaction contains at least one wallet-received note.
            AND (SUM(notes.received_count) + SUM(notes.change_note_count)) > 0
            -- We do not know about any external outputs of the transaction.
            AND MAX(COALESCE(sent_note_counts.sent_notes, 0)) = 0
       ) AS is_shielding,
       transactions.trust_status
FROM notes
JOIN accounts ON accounts.id = notes.account_id
JOIN transactions ON transactions.id_tx = notes.transaction_id
LEFT JOIN blocks_max_height
LEFT JOIN blocks ON blocks.height = transactions.mined_height
LEFT JOIN sent_note_counts
     ON sent_note_counts.account_id = notes.account_id
     AND sent_note_counts.transaction_id = notes.transaction_id
GROUP BY notes.account_id, notes.transaction_id";

/// Selects all outputs received by the wallet, plus any outputs sent from the wallet to
/// external recipients.
///
/// This will contain:
/// * Outputs received from external recipients
/// * Outputs sent to external recipients
/// * Outputs received as part of a wallet-internal operation, including
///   both outputs received as a consequence of wallet-internal transfers
///   and as change.
///
/// # Columns
/// - `txid`: The id of the transaction in which the output was sent or received.
/// - `output_pool`: The value pool for the transaction; valid values for this are:
///   - 0: Transparent
///   - 2: Sapling
///   - 3: Orchard
/// - `output_index`: The index of the output within the transaction bundle associated with
///   the `output_pool` value; that is, within `vout` for transparent, the vector of
///   Sapling `OutputDescription` values, or the vector of Orchard actions.
/// - `from_account_uuid`: The UUID of the wallet account that created the output, if the wallet
///   spent notes in creating the transaction. Note that if multiple accounts in the wallet
///   contributed funds in creating the associated transaction, redundant rows will exist in the
///   output of this view, one for each such account.
/// - `to_account_uuid`: The UUID of the wallet account that received the output, if any; for
///   outgoing transaction outputs this will be `NULL`.
/// - `address`: The address to which the output was sent; for received outputs, this is the
///   address at which the output was received, or `NULL` for wallet-internal outputs.
/// - `diversifier_index_be`: The big-endian representation of the diversifier index (or, for
///   transparent addresses, the BIP 44 change-level index of the derivation path) of the receiving
///   address. This will be `NULL` for outgoing transaction outputs.
/// - `value`: The value of the output, in zatoshis.
/// - `is_change`: `0` for outgoing outputs and outputs received at external-facing addresses, `1`
///   for outputs received at wallet-internal addresses. This represents a best-effort judgement
///   for whether or not the output should be considered change, and may not be correct for
///   cross-account internal transactions, shielding transactions, or outputs explicitly sent from
///   the wallet to itself. The determination of what counts as change is somewhat subjective and
///   the value of this column should be used with caution.
/// - `memo`: The binary content of the memo associated with the output, if the output is a
///   shielded output and the memo was received by the wallet, sent by the wallet or was able to be
///   decrypted with the wallet's outgoing viewing key.
pub(super) const VIEW_TX_OUTPUTS: &str = "
CREATE VIEW v_tx_outputs AS
WITH unioned AS (
    -- select all outputs received by the wallet
    SELECT transactions.txid            AS txid,
           ro.pool                      AS output_pool,
           ro.output_index              AS output_index,
           from_account.uuid            AS from_account_uuid,
           to_account.uuid              AS to_account_uuid,
           a.address                    AS to_address,
           a.diversifier_index_be       AS diversifier_index_be,
           ro.value                     AS value,
           ro.is_change                 AS is_change,
           ro.memo                      AS memo
    FROM v_received_outputs ro
    JOIN transactions
        ON transactions.id_tx = ro.transaction_id
    LEFT JOIN addresses a ON a.id = ro.address_id
    -- join to the sent_notes table to obtain `from_account_id`
    LEFT JOIN sent_notes ON sent_notes.id = ro.sent_note_id
    -- join on the accounts table to obtain account UUIDs
    LEFT JOIN accounts from_account ON from_account.id = sent_notes.from_account_id
    LEFT JOIN accounts to_account ON to_account.id = ro.account_id
    UNION ALL
    -- select all outputs sent from the wallet to external recipients
    SELECT transactions.txid            AS txid,
           sent_notes.output_pool       AS output_pool,
           sent_notes.output_index      AS output_index,
           from_account.uuid            AS from_account_uuid,
           NULL                         AS to_account_uuid,
           sent_notes.to_address        AS to_address,
           NULL                         AS diversifier_index_be,
           sent_notes.value             AS value,
           0                            AS is_change,
           sent_notes.memo              AS memo
    FROM sent_notes
    JOIN transactions
        ON transactions.id_tx = sent_notes.transaction_id
    LEFT JOIN v_received_outputs ro ON ro.sent_note_id = sent_notes.id
    -- join on the accounts table to obtain account UUIDs
    LEFT JOIN accounts from_account ON from_account.id = sent_notes.from_account_id
)
-- merge duplicate rows while retaining maximum information
SELECT
    txid,
    output_pool,
    output_index,
    max(from_account_uuid) AS from_account_uuid,
    max(to_account_uuid) AS to_account_uuid,
    max(to_address) AS to_address,
    max(value) AS value,
    max(is_change) AS is_change,
    max(memo) AS memo
FROM unioned
GROUP BY txid, output_pool, output_index";

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

pub(super) const VIEW_ADDRESS_USES: &str = "
CREATE VIEW v_address_uses AS
    SELECT orn.address_id, orn.account_id, orn.transaction_id, t.mined_height,
           a.key_scope, a.diversifier_index_be, a.transparent_child_index
    FROM orchard_received_notes orn
    JOIN addresses a ON a.id = orn.address_id
    JOIN transactions t ON t.id_tx = orn.transaction_id
UNION
    SELECT srn.address_id, srn.account_id, srn.transaction_id, t.mined_height,
           a.key_scope, a.diversifier_index_be, a.transparent_child_index
    FROM sapling_received_notes srn
    JOIN addresses a ON a.id = srn.address_id
    JOIN transactions t ON t.id_tx = srn.transaction_id
UNION
    SELECT tro.address_id, tro.account_id, tro.transaction_id, t.mined_height,
           a.key_scope, a.diversifier_index_be, a.transparent_child_index
    FROM transparent_received_outputs tro
    JOIN addresses a ON a.id = tro.address_id
    JOIN transactions t ON t.id_tx = tro.transaction_id";

pub(super) const VIEW_ADDRESS_FIRST_USE: &str = "
    CREATE VIEW v_address_first_use AS
    SELECT
        address_id,
        account_id,
        key_scope,
        diversifier_index_be,
        transparent_child_index,
        MIN(mined_height) AS first_use_height
    FROM v_address_uses
    GROUP BY
        address_id, account_id, key_scope,
        diversifier_index_be, transparent_child_index";
