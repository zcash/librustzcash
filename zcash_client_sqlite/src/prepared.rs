//! Prepared SQL statements used by the wallet.
//!
//! Some `rusqlite` crate APIs are only available on prepared statements; these are stored
//! inside the [`DataConnStmtCache`]. When adding a new prepared statement:
//!
//! - Add it as a private field of `DataConnStmtCache`.
//! - Build the statement in [`DataConnStmtCache::new`].
//! - Add a crate-private helper method to `DataConnStmtCache` for running the statement.

use rusqlite::{named_params, params, Statement, ToSql};
use zcash_primitives::{
    block::BlockHash,
    consensus::{self, BlockHeight},
    memo::MemoBytes,
    merkle_tree::{write_commitment_tree, write_incremental_witness},
    sapling::{self, Diversifier, Nullifier},
    transaction::{components::Amount, TxId},
    zip32::{AccountId, DiversifierIndex},
};

use zcash_client_backend::{
    address::UnifiedAddress,
    data_api::{PoolType, Recipient},
    encoding::AddressCodec,
};

use crate::{error::SqliteClientError, wallet::pool_code, NoteId, WalletDb};

#[cfg(feature = "transparent-inputs")]
use {
    crate::UtxoId, rusqlite::OptionalExtension,
    zcash_client_backend::wallet::WalletTransparentOutput,
    zcash_primitives::transaction::components::transparent::OutPoint,
};

pub(crate) struct InsertAddress<'a> {
    stmt: Statement<'a>,
}

impl<'a> InsertAddress<'a> {
    pub(crate) fn new(conn: &'a rusqlite::Connection) -> Result<Self, rusqlite::Error> {
        Ok(InsertAddress {
            stmt: conn.prepare(
                "INSERT INTO addresses (
                    account,
                    diversifier_index_be,
                    address,
                    cached_transparent_receiver_address
                )
                VALUES (
                    :account,
                    :diversifier_index_be,
                    :address,
                    :cached_transparent_receiver_address
                )",
            )?,
        })
    }

    /// Adds the given address and diversifier index to the addresses table.
    ///
    /// Returns the database row for the newly-inserted address.
    pub(crate) fn execute<P: consensus::Parameters>(
        &mut self,
        params: &P,
        account: AccountId,
        mut diversifier_index: DiversifierIndex,
        address: &UnifiedAddress,
    ) -> Result<(), rusqlite::Error> {
        // the diversifier index is stored in big-endian order to allow sorting
        diversifier_index.0.reverse();
        self.stmt.execute(named_params![
            ":account": &u32::from(account),
            ":diversifier_index_be": &&diversifier_index.0[..],
            ":address": &address.encode(params),
            ":cached_transparent_receiver_address": &address.transparent().map(|r| r.encode(params)),
        ])?;

        Ok(())
    }
}

/// The primary type used to implement [`WalletWrite`] for the SQLite database.
///
/// A data structure that stores the SQLite prepared statements that are
/// required for the implementation of [`WalletWrite`] against the backing
/// store.
///
/// [`WalletWrite`]: zcash_client_backend::data_api::WalletWrite
pub struct DataConnStmtCache<'a, P> {
    pub(crate) wallet_db: &'a WalletDb<P>,
    stmt_insert_block: Statement<'a>,

    stmt_insert_tx_meta: Statement<'a>,
    stmt_update_tx_meta: Statement<'a>,

    stmt_insert_tx_data: Statement<'a>,
    stmt_update_tx_data: Statement<'a>,
    stmt_select_tx_ref: Statement<'a>,

    stmt_mark_sapling_note_spent: Statement<'a>,
    #[cfg(feature = "transparent-inputs")]
    stmt_mark_transparent_utxo_spent: Statement<'a>,

    #[cfg(feature = "transparent-inputs")]
    stmt_insert_received_transparent_utxo: Statement<'a>,
    #[cfg(feature = "transparent-inputs")]
    stmt_update_received_transparent_utxo: Statement<'a>,
    #[cfg(feature = "transparent-inputs")]
    stmt_insert_legacy_transparent_utxo: Statement<'a>,
    #[cfg(feature = "transparent-inputs")]
    stmt_update_legacy_transparent_utxo: Statement<'a>,
    stmt_insert_received_note: Statement<'a>,
    stmt_update_received_note: Statement<'a>,
    stmt_select_received_note: Statement<'a>,

    stmt_insert_sent_output: Statement<'a>,
    stmt_update_sent_output: Statement<'a>,

    stmt_insert_witness: Statement<'a>,
    stmt_prune_witnesses: Statement<'a>,
    stmt_update_expired: Statement<'a>,

    stmt_insert_address: InsertAddress<'a>,
}

impl<'a, P> DataConnStmtCache<'a, P> {
    pub(crate) fn new(wallet_db: &'a WalletDb<P>) -> Result<Self, SqliteClientError> {
        Ok(
            DataConnStmtCache {
                wallet_db,
                stmt_insert_block: wallet_db.conn.prepare(
                    "INSERT INTO blocks (height, hash, time, sapling_tree)
                    VALUES (?, ?, ?, ?)",
                )?,
                stmt_insert_tx_meta: wallet_db.conn.prepare(
                    "INSERT INTO transactions (txid, block, tx_index)
                    VALUES (?, ?, ?)",
                )?,
                stmt_update_tx_meta: wallet_db.conn.prepare(
                    "UPDATE transactions
                    SET block = ?, tx_index = ? WHERE txid = ?",
                )?,
                stmt_insert_tx_data: wallet_db.conn.prepare(
                    "INSERT INTO transactions (txid, created, expiry_height, raw, fee)
                    VALUES (?, ?, ?, ?, ?)",
                )?,
                stmt_update_tx_data: wallet_db.conn.prepare(
                    "UPDATE transactions
                    SET expiry_height = :expiry_height,
                        raw = :raw,
                        fee = IFNULL(:fee, fee)
                    WHERE txid = :txid",
                )?,
                stmt_select_tx_ref: wallet_db.conn.prepare(
                    "SELECT id_tx FROM transactions WHERE txid = ?",
                )?,
                stmt_mark_sapling_note_spent: wallet_db.conn.prepare(
                    "UPDATE sapling_received_notes SET spent = ? WHERE nf = ?"
                )?,
                #[cfg(feature = "transparent-inputs")]
                stmt_mark_transparent_utxo_spent: wallet_db.conn.prepare(
                    "UPDATE utxos SET spent_in_tx = :spent_in_tx
                    WHERE prevout_txid = :prevout_txid
                    AND prevout_idx = :prevout_idx"
                )?,
                #[cfg(feature = "transparent-inputs")]
                stmt_insert_received_transparent_utxo: wallet_db.conn.prepare(
                    "INSERT INTO utxos (
                        received_by_account, address,
                        prevout_txid, prevout_idx, script,
                        value_zat, height)
                    SELECT
                        addresses.account, :address,
                        :prevout_txid, :prevout_idx, :script,
                        :value_zat, :height
                    FROM addresses
                    WHERE addresses.cached_transparent_receiver_address = :address
                    RETURNING id_utxo"
                )?,
                #[cfg(feature = "transparent-inputs")]
                stmt_update_received_transparent_utxo: wallet_db.conn.prepare(
                    "UPDATE utxos
                    SET received_by_account = addresses.account,
                        height = :height,
                        address = :address,
                        script = :script,
                        value_zat = :value_zat
                    FROM addresses
                    WHERE prevout_txid = :prevout_txid
                      AND prevout_idx = :prevout_idx
                      AND addresses.cached_transparent_receiver_address = :address
                    RETURNING id_utxo"
                )?,
                #[cfg(feature = "transparent-inputs")]
                stmt_insert_legacy_transparent_utxo: wallet_db.conn.prepare(
                    "INSERT INTO utxos (
                        received_by_account, address,
                        prevout_txid, prevout_idx, script,
                        value_zat, height)
                    VALUES
                        (:received_by_account, :address,
                        :prevout_txid, :prevout_idx, :script,
                        :value_zat, :height)
                    RETURNING id_utxo"
                )?,
                #[cfg(feature = "transparent-inputs")]
                stmt_update_legacy_transparent_utxo: wallet_db.conn.prepare(
                    "UPDATE utxos
                    SET received_by_account = :received_by_account,
                        height = :height,
                        address = :address,
                        script = :script,
                        value_zat = :value_zat
                    WHERE prevout_txid = :prevout_txid
                      AND prevout_idx = :prevout_idx
                    RETURNING id_utxo"
                )?,
                stmt_insert_received_note: wallet_db.conn.prepare(
                    "INSERT INTO sapling_received_notes (tx, output_index, account, diversifier, value, rcm, memo, nf, is_change)
                    VALUES (:tx, :output_index, :account, :diversifier, :value, :rcm, :memo, :nf, :is_change)",
                )?,
                stmt_update_received_note: wallet_db.conn.prepare(
                    "UPDATE sapling_received_notes
                    SET account = :account,
                        diversifier = :diversifier,
                        value = :value,
                        rcm = :rcm,
                        nf = IFNULL(:nf, nf),
                        memo = IFNULL(:memo, memo),
                        is_change = IFNULL(:is_change, is_change)
                    WHERE tx = :tx AND output_index = :output_index",
                )?,
                stmt_select_received_note: wallet_db.conn.prepare(
                    "SELECT id_note FROM sapling_received_notes WHERE tx = ? AND output_index = ?"
                )?,
                stmt_update_sent_output: wallet_db.conn.prepare(
                    "UPDATE sent_notes
                    SET from_account = :from_account,
                        to_address = :to_address,
                        to_account = :to_account,
                        value = :value,
                        memo = IFNULL(:memo, memo)
                    WHERE tx = :tx
                      AND output_pool = :output_pool
                      AND output_index = :output_index",
                )?,
                stmt_insert_sent_output: wallet_db.conn.prepare(
                    "INSERT INTO sent_notes (
                        tx, output_pool, output_index, from_account,
                        to_address, to_account, value, memo)
                    VALUES (
                        :tx, :output_pool, :output_index, :from_account,
                        :to_address, :to_account, :value, :memo)"
                )?,
                stmt_insert_witness: wallet_db.conn.prepare(
                    "INSERT INTO sapling_witnesses (note, block, witness)
                    VALUES (?, ?, ?)",
                )?,
                stmt_prune_witnesses: wallet_db.conn.prepare(
                    "DELETE FROM sapling_witnesses WHERE block < ?"
                )?,
                stmt_update_expired: wallet_db.conn.prepare(
                    "UPDATE sapling_received_notes SET spent = NULL WHERE EXISTS (
                        SELECT id_tx FROM transactions
                        WHERE id_tx = sapling_received_notes.spent AND block IS NULL AND expiry_height < ?
                    )",
                )?,
                stmt_insert_address: InsertAddress::new(&wallet_db.conn)?
            }
        )
    }

    /// Inserts information about a scanned block into the database.
    pub fn stmt_insert_block(
        &mut self,
        block_height: BlockHeight,
        block_hash: BlockHash,
        block_time: u32,
        commitment_tree: &sapling::CommitmentTree,
    ) -> Result<(), SqliteClientError> {
        let mut encoded_tree = Vec::new();
        write_commitment_tree(commitment_tree, &mut encoded_tree).unwrap();

        self.stmt_insert_block.execute(params![
            u32::from(block_height),
            &block_hash.0[..],
            block_time,
            encoded_tree
        ])?;

        Ok(())
    }

    /// Inserts the given transaction and its block metadata into the wallet.
    ///
    /// Returns the database row for the newly-inserted transaction, or an error if the
    /// transaction exists.
    pub(crate) fn stmt_insert_tx_meta(
        &mut self,
        txid: &TxId,
        height: BlockHeight,
        tx_index: usize,
    ) -> Result<i64, SqliteClientError> {
        self.stmt_insert_tx_meta.execute(params![
            &txid.as_ref()[..],
            u32::from(height),
            (tx_index as i64),
        ])?;

        Ok(self.wallet_db.conn.last_insert_rowid())
    }

    /// Updates the block metadata for the given transaction.
    ///
    /// Returns `false` if the transaction doesn't exist in the wallet.
    pub(crate) fn stmt_update_tx_meta(
        &mut self,
        height: BlockHeight,
        tx_index: usize,
        txid: &TxId,
    ) -> Result<bool, SqliteClientError> {
        match self.stmt_update_tx_meta.execute(params![
            u32::from(height),
            (tx_index as i64),
            &txid.as_ref()[..],
        ])? {
            0 => Ok(false),
            1 => Ok(true),
            _ => unreachable!("txid column is marked as UNIQUE"),
        }
    }

    /// Inserts the given transaction and its data into the wallet.
    ///
    /// Returns the database row for the newly-inserted transaction, or an error if the
    /// transaction exists.
    pub(crate) fn stmt_insert_tx_data(
        &mut self,
        txid: &TxId,
        created_at: Option<time::OffsetDateTime>,
        expiry_height: BlockHeight,
        raw_tx: &[u8],
        fee: Option<Amount>,
    ) -> Result<i64, SqliteClientError> {
        self.stmt_insert_tx_data.execute(params![
            &txid.as_ref()[..],
            created_at,
            u32::from(expiry_height),
            raw_tx,
            fee.map(i64::from)
        ])?;

        Ok(self.wallet_db.conn.last_insert_rowid())
    }

    /// Updates the data for the given transaction.
    ///
    /// Returns `false` if the transaction doesn't exist in the wallet.
    pub(crate) fn stmt_update_tx_data(
        &mut self,
        expiry_height: BlockHeight,
        raw_tx: &[u8],
        fee: Option<Amount>,
        txid: &TxId,
    ) -> Result<bool, SqliteClientError> {
        let sql_args: &[(&str, &dyn ToSql)] = &[
            (":expiry_height", &u32::from(expiry_height)),
            (":raw", &raw_tx),
            (":fee", &fee.map(i64::from)),
            (":txid", &&txid.as_ref()[..]),
        ];
        match self.stmt_update_tx_data.execute(sql_args)? {
            0 => Ok(false),
            1 => Ok(true),
            _ => unreachable!("txid column is marked as UNIQUE"),
        }
    }

    /// Finds the database row for the given `txid`, if the transaction is in the wallet.
    pub(crate) fn stmt_select_tx_ref(&mut self, txid: &TxId) -> Result<i64, SqliteClientError> {
        self.stmt_select_tx_ref
            .query_row([&txid.as_ref()[..]], |row| row.get(0))
            .map_err(SqliteClientError::from)
    }

    /// Marks a given nullifier as having been revealed in the construction of the
    /// specified transaction.
    ///
    /// Marking a note spent in this fashion does NOT imply that the spending transaction
    /// has been mined.
    ///
    /// Returns `false` if the nullifier does not correspond to any received note.
    pub(crate) fn stmt_mark_sapling_note_spent(
        &mut self,
        tx_ref: i64,
        nf: &Nullifier,
    ) -> Result<bool, SqliteClientError> {
        match self
            .stmt_mark_sapling_note_spent
            .execute(params![tx_ref, &nf.0[..]])?
        {
            0 => Ok(false),
            1 => Ok(true),
            _ => unreachable!("nf column is marked as UNIQUE"),
        }
    }

    /// Marks the given UTXO as having been spent.
    ///
    /// Returns `false` if `outpoint` does not correspond to any tracked UTXO.
    #[cfg(feature = "transparent-inputs")]
    pub(crate) fn stmt_mark_transparent_utxo_spent(
        &mut self,
        tx_ref: i64,
        outpoint: &OutPoint,
    ) -> Result<bool, SqliteClientError> {
        let sql_args: &[(&str, &dyn ToSql)] = &[
            (":spent_in_tx", &tx_ref),
            (":prevout_txid", &outpoint.hash().to_vec()),
            (":prevout_idx", &outpoint.n()),
        ];

        match self.stmt_mark_transparent_utxo_spent.execute(sql_args)? {
            0 => Ok(false),
            1 => Ok(true),
            _ => unreachable!("tx_outpoint constraint is marked as UNIQUE"),
        }
    }
}

impl<'a, P: consensus::Parameters> DataConnStmtCache<'a, P> {
    /// Inserts a sent note into the wallet database.
    ///
    /// `output_index` is the index within the transaction that contains the recipient output:
    ///
    /// - If `to` is a Unified address, this is an index into the outputs of the transaction
    ///   within the bundle associated with the recipient's output pool.
    /// - If `to` is a Sapling address, this is an index into the Sapling outputs of the
    ///   transaction.
    /// - If `to` is a transparent address, this is an index into the transparent outputs of
    ///   the transaction.
    /// - If `to` is an internal account, this is an index into the Sapling outputs of the
    ///   transaction.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn stmt_insert_sent_output(
        &mut self,
        tx_ref: i64,
        output_index: usize,
        from_account: AccountId,
        to: &Recipient,
        value: Amount,
        memo: Option<&MemoBytes>,
    ) -> Result<(), SqliteClientError> {
        let (to_address, to_account, pool_type) = match to {
            Recipient::Transparent(addr) => (
                Some(addr.encode(&self.wallet_db.params)),
                None,
                PoolType::Transparent,
            ),
            Recipient::Sapling(addr) => (
                Some(addr.encode(&self.wallet_db.params)),
                None,
                PoolType::Sapling,
            ),
            Recipient::Unified(addr, pool) => {
                (Some(addr.encode(&self.wallet_db.params)), None, *pool)
            }
            Recipient::InternalAccount(id, pool) => (None, Some(u32::from(*id)), *pool),
        };

        self.stmt_insert_sent_output.execute(named_params![
            ":tx": &tx_ref,
            ":output_pool": &pool_code(pool_type),
            ":output_index": &i64::try_from(output_index).unwrap(),
            ":from_account": &u32::from(from_account),
            ":to_address": &to_address,
            ":to_account": &to_account,
            ":value": &i64::from(value),
            ":memo": &memo.filter(|m| *m != &MemoBytes::empty()).map(|m| m.as_slice()),
        ])?;

        Ok(())
    }

    /// Updates the data for the given sent note.
    ///
    /// Returns `false` if the transaction doesn't exist in the wallet.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn stmt_update_sent_output(
        &mut self,
        from_account: AccountId,
        to: &Recipient,
        value: Amount,
        memo: Option<&MemoBytes>,
        tx_ref: i64,
        output_index: usize,
    ) -> Result<bool, SqliteClientError> {
        let (to_address, to_account, pool_type) = match to {
            Recipient::Transparent(addr) => (
                Some(addr.encode(&self.wallet_db.params)),
                None,
                PoolType::Transparent,
            ),
            Recipient::Sapling(addr) => (
                Some(addr.encode(&self.wallet_db.params)),
                None,
                PoolType::Sapling,
            ),
            Recipient::Unified(addr, pool) => {
                (Some(addr.encode(&self.wallet_db.params)), None, *pool)
            }
            Recipient::InternalAccount(id, pool) => (None, Some(u32::from(*id)), *pool),
        };

        match self.stmt_update_sent_output.execute(named_params![
            ":from_account": &u32::from(from_account),
            ":to_address": &to_address,
            ":to_account": &to_account,
            ":value": &i64::from(value),
            ":memo": &memo.filter(|m| *m != &MemoBytes::empty()).map(|m| m.as_slice()),
            ":tx": &tx_ref,
            ":output_pool": &pool_code(pool_type),
            ":output_index": &i64::try_from(output_index).unwrap(),
        ])? {
            0 => Ok(false),
            1 => Ok(true),
            _ => unreachable!("tx_output constraint is marked as UNIQUE"),
        }
    }

    /// Adds the given received UTXO to the datastore.
    ///
    /// Returns the database identifier for the newly-inserted UTXO if the address to which the
    /// UTXO was sent corresponds to a cached transparent receiver in the addresses table, or
    /// Ok(None) if the address is unknown. Returns an error if the UTXO exists.
    #[cfg(feature = "transparent-inputs")]
    pub(crate) fn stmt_insert_received_transparent_utxo(
        &mut self,
        output: &WalletTransparentOutput,
    ) -> Result<Option<UtxoId>, SqliteClientError> {
        self.stmt_insert_received_transparent_utxo
            .query_row(
                named_params![
                    ":address": &output.recipient_address().encode(&self.wallet_db.params),
                    ":prevout_txid": &output.outpoint().hash().to_vec(),
                    ":prevout_idx": &output.outpoint().n(),
                    ":script": &output.txout().script_pubkey.0,
                    ":value_zat": &i64::from(output.txout().value),
                    ":height": &u32::from(output.height()),
                ],
                |row| {
                    let id = row.get(0)?;
                    Ok(UtxoId(id))
                },
            )
            .optional()
            .map_err(SqliteClientError::from)
    }

    /// Adds the given received UTXO to the datastore.
    ///
    /// Returns the database identifier for the updated UTXO if the address to which the UTXO was
    /// sent corresponds to a cached transparent receiver in the addresses table, or Ok(None) if
    /// the address is unknown.
    #[cfg(feature = "transparent-inputs")]
    pub(crate) fn stmt_update_received_transparent_utxo(
        &mut self,
        output: &WalletTransparentOutput,
    ) -> Result<Option<UtxoId>, SqliteClientError> {
        self.stmt_update_received_transparent_utxo
            .query_row(
                named_params![
                    ":prevout_txid": &output.outpoint().hash().to_vec(),
                    ":prevout_idx": &output.outpoint().n(),
                    ":address": &output.recipient_address().encode(&self.wallet_db.params),
                    ":script": &output.txout().script_pubkey.0,
                    ":value_zat": &i64::from(output.txout().value),
                    ":height": &u32::from(output.height()),
                ],
                |row| {
                    let id = row.get(0)?;
                    Ok(UtxoId(id))
                },
            )
            .optional()
            .map_err(SqliteClientError::from)
    }

    /// Adds the given legacy UTXO to the datastore.
    ///
    /// Returns the database row for the newly-inserted UTXO, or an error if the UTXO
    /// exists.
    #[cfg(feature = "transparent-inputs")]
    pub(crate) fn stmt_insert_legacy_transparent_utxo(
        &mut self,
        output: &WalletTransparentOutput,
        received_by_account: AccountId,
    ) -> Result<UtxoId, SqliteClientError> {
        self.stmt_insert_legacy_transparent_utxo
            .query_row(
                named_params![
                    ":received_by_account": &u32::from(received_by_account),
                    ":address": &output.recipient_address().encode(&self.wallet_db.params),
                    ":prevout_txid": &output.outpoint().hash().to_vec(),
                    ":prevout_idx": &output.outpoint().n(),
                    ":script": &output.txout().script_pubkey.0,
                    ":value_zat": &i64::from(output.txout().value),
                    ":height": &u32::from(output.height()),
                ],
                |row| {
                    let id = row.get(0)?;
                    Ok(UtxoId(id))
                },
            )
            .map_err(SqliteClientError::from)
    }

    /// Adds the given legacy UTXO to the datastore.
    ///
    /// Returns the database row for the newly-inserted UTXO, or an error if the UTXO
    /// exists.
    #[cfg(feature = "transparent-inputs")]
    pub(crate) fn stmt_update_legacy_transparent_utxo(
        &mut self,
        output: &WalletTransparentOutput,
        received_by_account: AccountId,
    ) -> Result<Option<UtxoId>, SqliteClientError> {
        self.stmt_update_legacy_transparent_utxo
            .query_row(
                named_params![
                    ":received_by_account": &u32::from(received_by_account),
                    ":prevout_txid": &output.outpoint().hash().to_vec(),
                    ":prevout_idx": &output.outpoint().n(),
                    ":address": &output.recipient_address().encode(&self.wallet_db.params),
                    ":script": &output.txout().script_pubkey.0,
                    ":value_zat": &i64::from(output.txout().value),
                    ":height": &u32::from(output.height()),
                ],
                |row| {
                    let id = row.get(0)?;
                    Ok(UtxoId(id))
                },
            )
            .optional()
            .map_err(SqliteClientError::from)
    }

    /// Adds the given address and diversifier index to the addresses table.
    ///
    /// Returns the database row for the newly-inserted address.
    pub(crate) fn stmt_insert_address(
        &mut self,
        account: AccountId,
        diversifier_index: DiversifierIndex,
        address: &UnifiedAddress,
    ) -> Result<(), SqliteClientError> {
        self.stmt_insert_address.execute(
            &self.wallet_db.params,
            account,
            diversifier_index,
            address,
        )?;

        Ok(())
    }
}

impl<'a, P> DataConnStmtCache<'a, P> {
    /// Inserts the given received note into the wallet.
    ///
    /// This implementation relies on the facts that:
    /// - A transaction will not contain more than 2^63 shielded outputs.
    /// - A note value will never exceed 2^63 zatoshis.
    ///
    /// Returns the database row for the newly-inserted note, or an error if the note
    /// exists.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn stmt_insert_received_note(
        &mut self,
        tx_ref: i64,
        output_index: usize,
        account: AccountId,
        diversifier: &Diversifier,
        value: u64,
        rcm: [u8; 32],
        nf: Option<&Nullifier>,
        memo: Option<&MemoBytes>,
        is_change: bool,
    ) -> Result<NoteId, SqliteClientError> {
        let sql_args: &[(&str, &dyn ToSql)] = &[
            (":tx", &tx_ref),
            (":output_index", &(output_index as i64)),
            (":account", &u32::from(account)),
            (":diversifier", &diversifier.0.as_ref()),
            (":value", &(value as i64)),
            (":rcm", &rcm.as_ref()),
            (":nf", &nf.map(|nf| nf.0.as_ref())),
            (
                ":memo",
                &memo
                    .filter(|m| *m != &MemoBytes::empty())
                    .map(|m| m.as_slice()),
            ),
            (":is_change", &is_change),
        ];

        self.stmt_insert_received_note.execute(sql_args)?;

        Ok(NoteId::ReceivedNoteId(
            self.wallet_db.conn.last_insert_rowid(),
        ))
    }

    /// Updates the data for the given transaction.
    ///
    /// This implementation relies on the facts that:
    /// - A transaction will not contain more than 2^63 shielded outputs.
    /// - A note value will never exceed 2^63 zatoshis.
    ///
    /// Returns `false` if the transaction doesn't exist in the wallet.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn stmt_update_received_note(
        &mut self,
        account: AccountId,
        diversifier: &Diversifier,
        value: u64,
        rcm: [u8; 32],
        nf: Option<&Nullifier>,
        memo: Option<&MemoBytes>,
        is_change: bool,
        tx_ref: i64,
        output_index: usize,
    ) -> Result<bool, SqliteClientError> {
        let sql_args: &[(&str, &dyn ToSql)] = &[
            (":account", &u32::from(account)),
            (":diversifier", &diversifier.0.as_ref()),
            (":value", &(value as i64)),
            (":rcm", &rcm.as_ref()),
            (":nf", &nf.map(|nf| nf.0.as_ref())),
            (
                ":memo",
                &memo
                    .filter(|m| *m != &MemoBytes::empty())
                    .map(|m| m.as_slice()),
            ),
            (":is_change", &is_change),
            (":tx", &tx_ref),
            (":output_index", &(output_index as i64)),
        ];

        match self.stmt_update_received_note.execute(sql_args)? {
            0 => Ok(false),
            1 => Ok(true),
            _ => unreachable!("tx_output constraint is marked as UNIQUE"),
        }
    }

    /// Finds the database row for the given `txid`, if the transaction is in the wallet.
    pub(crate) fn stmt_select_received_note(
        &mut self,
        tx_ref: i64,
        output_index: usize,
    ) -> Result<NoteId, SqliteClientError> {
        self.stmt_select_received_note
            .query_row(params![tx_ref, (output_index as i64)], |row| {
                row.get(0).map(NoteId::ReceivedNoteId)
            })
            .map_err(SqliteClientError::from)
    }

    /// Records the incremental witness for the specified note, as of the given block
    /// height.
    ///
    /// Returns `SqliteClientError::InvalidNoteId` if the note ID is for a sent note.
    pub(crate) fn stmt_insert_witness(
        &mut self,
        note_id: NoteId,
        height: BlockHeight,
        witness: &sapling::IncrementalWitness,
    ) -> Result<(), SqliteClientError> {
        let note_id = match note_id {
            NoteId::ReceivedNoteId(note_id) => Ok(note_id),
            NoteId::SentNoteId(_) => Err(SqliteClientError::InvalidNoteId),
        }?;

        let mut encoded = Vec::new();
        write_incremental_witness(witness, &mut encoded).unwrap();

        self.stmt_insert_witness
            .execute(params![note_id, u32::from(height), encoded])?;

        Ok(())
    }

    /// Removes old incremental witnesses up to the given block height.
    pub(crate) fn stmt_prune_witnesses(
        &mut self,
        below_height: BlockHeight,
    ) -> Result<(), SqliteClientError> {
        self.stmt_prune_witnesses
            .execute([u32::from(below_height)])?;
        Ok(())
    }

    /// Marks notes that have not been mined in transactions as expired, up to the given
    /// block height.
    pub fn stmt_update_expired(&mut self, height: BlockHeight) -> Result<(), SqliteClientError> {
        self.stmt_update_expired.execute([u32::from(height)])?;
        Ok(())
    }
}
