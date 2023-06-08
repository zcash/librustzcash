//! Prepared SQL statements used by the wallet.
//!
//! Some `rusqlite` crate APIs are only available on prepared statements; these are stored
//! inside the [`DataConnStmtCache`]. When adding a new prepared statement:
//!
//! - Add it as a private field of `DataConnStmtCache`.
//! - Build the statement in [`DataConnStmtCache::new`].
//! - Add a crate-private helper method to `DataConnStmtCache` for running the statement.

use rusqlite::{params, Statement};
use zcash_primitives::{consensus::BlockHeight, merkle_tree::write_incremental_witness, sapling};

use crate::{error::SqliteClientError, NoteId, WalletDb};

/// The primary type used to implement [`WalletWrite`] for the SQLite database.
///
/// A data structure that stores the SQLite prepared statements that are
/// required for the implementation of [`WalletWrite`] against the backing
/// store.
///
/// [`WalletWrite`]: zcash_client_backend::data_api::WalletWrite
pub struct DataConnStmtCache<'a, P> {
    pub(crate) wallet_db: &'a WalletDb<P>,

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
