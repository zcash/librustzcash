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
    consensus::{self, BlockHeight},
    merkle_tree::write_incremental_witness,
    sapling,
    zip32::AccountId,
};

use zcash_client_backend::encoding::AddressCodec;

use crate::{error::SqliteClientError, NoteId, WalletDb};

#[cfg(feature = "transparent-inputs")]
use {
    crate::UtxoId, rusqlite::OptionalExtension,
    zcash_client_backend::wallet::WalletTransparentOutput,
    zcash_primitives::transaction::components::transparent::OutPoint,
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

    stmt_insert_witness: Statement<'a>,
    stmt_prune_witnesses: Statement<'a>,
    stmt_update_expired: Statement<'a>,
}

impl<'a, P> DataConnStmtCache<'a, P> {
    pub(crate) fn new(wallet_db: &'a WalletDb<P>) -> Result<Self, SqliteClientError> {
        Ok(
            DataConnStmtCache {
                wallet_db,
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
            }
        )
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
}

impl<'a, P> DataConnStmtCache<'a, P> {
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
