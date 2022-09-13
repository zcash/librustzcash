//! Prepared SQL statements used by the wallet.
//!
//! Some `rusqlite` crate APIs are only available on prepared statements; these are stored
//! inside the [`DataConnStmtCache`]. When adding a new prepared statement:
//!
//! - Add it as a private field of `DataConnStmtCache`.
//! - Build the statement in [`DataConnStmtCache::new`].
//! - Add a crate-private helper method to `DataConnStmtCache` for running the statement.

use rusqlite::{params, Statement, ToSql};
use zcash_primitives::{
    block::BlockHash,
    consensus::{self, BlockHeight},
    memo::MemoBytes,
    merkle_tree::{CommitmentTree, IncrementalWitness},
    sapling::{Diversifier, Node, Nullifier},
    transaction::{components::Amount, TxId},
    zip32::{AccountId, DiversifierIndex},
};

use zcash_client_backend::address::UnifiedAddress;

use crate::{error::SqliteClientError, wallet::PoolType, NoteId, WalletDb};

#[cfg(feature = "transparent-inputs")]
use {
    zcash_client_backend::{encoding::AddressCodec, wallet::WalletTransparentOutput},
    zcash_primitives::{
        legacy::TransparentAddress, transaction::components::transparent::OutPoint,
    },
};

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
    stmt_delete_utxos: Statement<'a>,
    stmt_insert_received_note: Statement<'a>,
    stmt_update_received_note: Statement<'a>,
    stmt_select_received_note: Statement<'a>,

    stmt_insert_sent_note: Statement<'a>,
    stmt_update_sent_note: Statement<'a>,

    stmt_insert_witness: Statement<'a>,
    stmt_prune_witnesses: Statement<'a>,
    stmt_update_expired: Statement<'a>,

    stmt_insert_address: Statement<'a>,
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
                    "UPDATE received_notes SET spent = ? WHERE nf = ?"
                )?,
                #[cfg(feature = "transparent-inputs")]
                stmt_mark_transparent_utxo_spent: wallet_db.conn.prepare(
                    "UPDATE utxos SET spent_in_tx = :spent_in_tx
                    WHERE prevout_txid = :prevout_txid
                    AND prevout_idx = :prevout_idx"
                )?,
                #[cfg(feature = "transparent-inputs")]
                stmt_insert_received_transparent_utxo: wallet_db.conn.prepare(
                    "INSERT INTO utxos (address, prevout_txid, prevout_idx, script, value_zat, height)
                    VALUES (:address, :prevout_txid, :prevout_idx, :script, :value_zat, :height)"
                )?,
                #[cfg(feature = "transparent-inputs")]
                stmt_delete_utxos: wallet_db.conn.prepare(
                    "DELETE FROM utxos WHERE address = :address AND height > :above_height"
                )?,
                stmt_insert_received_note: wallet_db.conn.prepare(
                    "INSERT INTO received_notes (tx, output_index, account, diversifier, value, rcm, memo, nf, is_change)
                    VALUES (:tx, :output_index, :account, :diversifier, :value, :rcm, :memo, :nf, :is_change)",
                )?,
                stmt_update_received_note: wallet_db.conn.prepare(
                    "UPDATE received_notes
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
                    "SELECT id_note FROM received_notes WHERE tx = ? AND output_index = ?"
                )?,
                stmt_update_sent_note: wallet_db.conn.prepare(
                    "UPDATE sent_notes
                    SET from_account = :account,
                        address = :address,
                        value = :value,
                        memo = IFNULL(:memo, memo)
                    WHERE tx = :tx
                      AND output_pool = :output_pool
                      AND output_index = :output_index",
                )?,
                stmt_insert_sent_note: wallet_db.conn.prepare(
                    "INSERT INTO sent_notes (tx, output_pool, output_index, from_account, address, value, memo)
                    VALUES (:tx, :output_pool, :output_index, :from_account, :address, :value, :memo)"
                )?,
                stmt_insert_witness: wallet_db.conn.prepare(
                    "INSERT INTO sapling_witnesses (note, block, witness)
                    VALUES (?, ?, ?)",
                )?,
                stmt_prune_witnesses: wallet_db.conn.prepare(
                    "DELETE FROM sapling_witnesses WHERE block < ?"
                )?,
                stmt_update_expired: wallet_db.conn.prepare(
                    "UPDATE received_notes SET spent = NULL WHERE EXISTS (
                        SELECT id_tx FROM transactions
                        WHERE id_tx = received_notes.spent AND block IS NULL AND expiry_height < ?
                    )",
                )?,
                stmt_insert_address: wallet_db.conn.prepare(
                    "INSERT INTO addresses (account, diversifier_index_be, address)
                    VALUES (:account, :diversifier_index_be, :address)",
                )?,
            }
        )
    }

    /// Inserts information about a scanned block into the database.
    pub fn stmt_insert_block(
        &mut self,
        block_height: BlockHeight,
        block_hash: BlockHash,
        block_time: u32,
        commitment_tree: &CommitmentTree<Node>,
    ) -> Result<(), SqliteClientError> {
        let mut encoded_tree = Vec::new();
        commitment_tree.write(&mut encoded_tree).unwrap();

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
        match self.stmt_update_tx_data.execute_named(sql_args)? {
            0 => Ok(false),
            1 => Ok(true),
            _ => unreachable!("txid column is marked as UNIQUE"),
        }
    }

    /// Finds the database row for the given `txid`, if the transaction is in the wallet.
    pub(crate) fn stmt_select_tx_ref(&mut self, txid: &TxId) -> Result<i64, SqliteClientError> {
        self.stmt_select_tx_ref
            .query_row(&[&txid.as_ref()[..]], |row| row.get(0))
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

        match self
            .stmt_mark_transparent_utxo_spent
            .execute_named(sql_args)?
        {
            0 => Ok(false),
            1 => Ok(true),
            _ => unreachable!("tx_outpoint constraint is marked as UNIQUE"),
        }
    }
}

impl<'a, P: consensus::Parameters> DataConnStmtCache<'a, P> {
    /// Adds the given received UTXO to the datastore.
    ///
    /// Returns the database row for the newly-inserted UTXO, or an error if the UTXO
    /// exists.
    #[cfg(feature = "transparent-inputs")]
    pub(crate) fn stmt_insert_received_transparent_utxo(
        &mut self,
        output: &WalletTransparentOutput,
    ) -> Result<i64, SqliteClientError> {
        let sql_args: &[(&str, &dyn ToSql)] = &[
            (":address", &output.address().encode(&self.wallet_db.params)),
            (":prevout_txid", &output.outpoint.hash().to_vec()),
            (":prevout_idx", &output.outpoint.n()),
            (":script", &output.txout.script_pubkey.0),
            (":value_zat", &i64::from(output.txout.value)),
            (":height", &u32::from(output.height)),
        ];

        self.stmt_insert_received_transparent_utxo
            .execute_named(sql_args)?;

        Ok(self.wallet_db.conn.last_insert_rowid())
    }

    /// Removes all records of UTXOs that were recorded as having been received at block
    /// heights greater than the given height.
    ///
    /// Returns the number of UTXOs that were removed.
    #[cfg(feature = "transparent-inputs")]
    pub(crate) fn stmt_delete_utxos(
        &mut self,
        taddr: &TransparentAddress,
        height: BlockHeight,
    ) -> Result<usize, SqliteClientError> {
        let sql_args: &[(&str, &dyn ToSql)] = &[
            (":address", &taddr.encode(&self.wallet_db.params)),
            (":above_height", &u32::from(height)),
        ];

        let rows = self.stmt_delete_utxos.execute_named(sql_args)?;

        Ok(rows)
    }

    /// Adds the given address and diversifier index to the addresses table.
    ///
    /// Returns the database row for the newly-inserted address.
    pub(crate) fn stmt_insert_address(
        &mut self,
        account: AccountId,
        mut diversifier_index: DiversifierIndex,
        address: &UnifiedAddress,
    ) -> Result<i64, SqliteClientError> {
        diversifier_index.0.reverse();
        let sql_args: &[(&str, &dyn ToSql)] = &[
            (":account", &u32::from(account)),
            (":diversifier_index_be", &&diversifier_index.0[..]),
            (":address", &address.encode(&self.wallet_db.params)),
        ];

        self.stmt_insert_address.execute_named(sql_args)?;

        Ok(self.wallet_db.conn.last_insert_rowid())
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
        nf: &Option<Nullifier>,
        memo: Option<&MemoBytes>,
        is_change: Option<bool>,
    ) -> Result<NoteId, SqliteClientError> {
        let sql_args: &[(&str, &dyn ToSql)] = &[
            (":tx", &tx_ref),
            (":output_index", &(output_index as i64)),
            (":account", &u32::from(account)),
            (":diversifier", &diversifier.0.as_ref()),
            (":value", &(value as i64)),
            (":rcm", &rcm.as_ref()),
            (":nf", &nf.as_ref().map(|nf| nf.0.as_ref())),
            (
                ":memo",
                &memo
                    .filter(|m| *m != &MemoBytes::empty())
                    .map(|m| m.as_slice()),
            ),
            (":is_change", &is_change),
        ];

        self.stmt_insert_received_note.execute_named(sql_args)?;

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
        nf: &Option<Nullifier>,
        memo: Option<&MemoBytes>,
        is_change: Option<bool>,
        tx_ref: i64,
        output_index: usize,
    ) -> Result<bool, SqliteClientError> {
        let sql_args: &[(&str, &dyn ToSql)] = &[
            (":account", &u32::from(account)),
            (":diversifier", &diversifier.0.as_ref()),
            (":value", &(value as i64)),
            (":rcm", &rcm.as_ref()),
            (":nf", &nf.as_ref().map(|nf| nf.0.as_ref())),
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

        match self.stmt_update_received_note.execute_named(sql_args)? {
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

    /// Inserts a sent note into the wallet database.
    ///
    /// `output_index` is the index within the transaction that contains the recipient output:
    ///
    /// - If `to` is a Sapling address, this is an index into the Sapling outputs of the
    ///   transaction.
    /// - If `to` is a transparent address, this is an index into the transparent outputs of
    ///   the transaction.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn stmt_insert_sent_note(
        &mut self,
        tx_ref: i64,
        pool_type: PoolType,
        output_index: usize,
        account: AccountId,
        to_str: &str,
        value: Amount,
        memo: Option<&MemoBytes>,
    ) -> Result<(), SqliteClientError> {
        let sql_args: &[(&str, &dyn ToSql)] = &[
            (":tx", &tx_ref),
            (":output_pool", &pool_type.typecode()),
            (":output_index", &i64::try_from(output_index).unwrap()),
            (":from_account", &u32::from(account)),
            (":address", &to_str),
            (":value", &i64::from(value)),
            (
                ":memo",
                &memo
                    .filter(|m| *m != &MemoBytes::empty())
                    .map(|m| m.as_slice()),
            ),
        ];
        self.stmt_insert_sent_note.execute_named(sql_args)?;
        Ok(())
    }

    /// Updates the data for the given sent note.
    ///
    /// Returns `false` if the transaction doesn't exist in the wallet.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn stmt_update_sent_note(
        &mut self,
        account: AccountId,
        to_str: &str,
        value: Amount,
        memo: Option<&MemoBytes>,
        tx_ref: i64,
        pool_type: PoolType,
        output_index: usize,
    ) -> Result<bool, SqliteClientError> {
        let sql_args: &[(&str, &dyn ToSql)] = &[
            (":account", &u32::from(account)),
            (":address", &to_str),
            (":value", &i64::from(value)),
            (
                ":memo",
                &memo
                    .filter(|m| *m != &MemoBytes::empty())
                    .map(|m| m.as_slice()),
            ),
            (":tx", &tx_ref),
            (":output_pool", &pool_type.typecode()),
            (":output_index", &i64::try_from(output_index).unwrap()),
        ];
        match self.stmt_update_sent_note.execute_named(sql_args)? {
            0 => Ok(false),
            1 => Ok(true),
            _ => unreachable!("tx_output constraint is marked as UNIQUE"),
        }
    }

    /// Records the incremental witness for the specified note, as of the given block
    /// height.
    ///
    /// Returns `SqliteClientError::InvalidNoteId` if the note ID is for a sent note.
    pub(crate) fn stmt_insert_witness(
        &mut self,
        note_id: NoteId,
        height: BlockHeight,
        witness: &IncrementalWitness<Node>,
    ) -> Result<(), SqliteClientError> {
        let note_id = match note_id {
            NoteId::ReceivedNoteId(note_id) => Ok(note_id),
            NoteId::SentNoteId(_) => Err(SqliteClientError::InvalidNoteId),
        }?;

        let mut encoded = Vec::new();
        witness.write(&mut encoded).unwrap();

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
            .execute(&[u32::from(below_height)])?;
        Ok(())
    }

    /// Marks notes that have not been mined in transactions as expired, up to the given
    /// block height.
    pub fn stmt_update_expired(&mut self, height: BlockHeight) -> Result<(), SqliteClientError> {
        self.stmt_update_expired.execute(&[u32::from(height)])?;
        Ok(())
    }
}
