//! This migration revises the `v_tx_outputs` view to support SQLite 3.19.x
//! which did not define `TRUE` and `FALSE` constants. This is required in
//! order to support Android API 27

use std::collections::HashSet;

use schemer_rusqlite::RusqliteMigration;
use uuid::Uuid;

use crate::wallet::init::WalletMigrationError;

use super::v_transactions_transparent_history;

pub(super) const MIGRATION_ID: Uuid = Uuid::from_u128(0xb3e21434_286f_41f3_8d71_44cce968ab2b);

pub(super) struct Migration;

impl schemer::Migration for Migration {
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }

    fn dependencies(&self) -> HashSet<Uuid> {
        [v_transactions_transparent_history::MIGRATION_ID]
            .into_iter()
            .collect()
    }

    fn description(&self) -> &'static str {
        "Updates v_tx_outputs to remove use of `true` and `false` constants for legacy SQLite version support."
    }
}

impl RusqliteMigration for Migration {
    type Error = WalletMigrationError;

    fn up(&self, transaction: &rusqlite::Transaction) -> Result<(), Self::Error> {
        transaction.execute_batch(
            "DROP VIEW v_tx_outputs;
            CREATE VIEW v_tx_outputs AS
            SELECT transactions.txid                   AS txid,
                   2                                   AS output_pool,
                   sapling_received_notes.output_index AS output_index,
                   sent_notes.from_account             AS from_account,
                   sapling_received_notes.account      AS to_account,
                   NULL                                AS to_address,
                   sapling_received_notes.value        AS value,
                   sapling_received_notes.is_change    AS is_change,
                   sapling_received_notes.memo         AS memo
            FROM sapling_received_notes
            JOIN transactions
                 ON transactions.id_tx = sapling_received_notes.tx
            LEFT JOIN sent_notes
                      ON (sent_notes.tx, sent_notes.output_pool, sent_notes.output_index) =
                         (sapling_received_notes.tx, 2, sent_notes.output_index)
            UNION
            SELECT utxos.prevout_txid          AS txid,
                   0                           AS output_pool,
                   utxos.prevout_idx           AS output_index,
                   NULL                        AS from_account,
                   utxos.received_by_account   AS to_account,
                   utxos.address               AS to_address,
                   utxos.value_zat             AS value,
                   0                           AS is_change,
                   NULL                        AS memo
            FROM utxos
            UNION
            SELECT transactions.txid              AS txid,
                   sent_notes.output_pool         AS output_pool,
                   sent_notes.output_index        AS output_index,
                   sent_notes.from_account        AS from_account,
                   sapling_received_notes.account AS to_account,
                   sent_notes.to_address          AS to_address,
                   sent_notes.value               AS value,
                   0                              AS is_change,
                   sent_notes.memo                AS memo
            FROM sent_notes
            JOIN transactions
                 ON transactions.id_tx = sent_notes.tx
            LEFT JOIN sapling_received_notes
                      ON (sent_notes.tx, sent_notes.output_pool, sent_notes.output_index) =
                         (sapling_received_notes.tx, 2, sapling_received_notes.output_index)
            WHERE COALESCE(sapling_received_notes.is_change, 0) = 0;",
        )?;

        Ok(())
    }

    fn down(&self, _transaction: &rusqlite::Transaction) -> Result<(), Self::Error> {
        Err(WalletMigrationError::CannotRevert(MIGRATION_ID))
    }
}
