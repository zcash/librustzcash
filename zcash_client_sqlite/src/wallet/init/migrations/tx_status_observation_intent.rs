//! Separates transaction enhancement intent from durable status observation intent, and removes
//! status requests for transactions that the wallet can observe through shielded compact-block
//! scanning.

use std::collections::HashSet;

use rusqlite::named_params;
use schemerz_rusqlite::RusqliteMigration;
use uuid::Uuid;

use crate::wallet::{
    TxQueryType,
    init::{
        WalletMigrationError,
        migrations::{note_locking, tx_retrieval_queue},
    },
};

/// This migration permits independent enhancement and status intents for a transaction, and
/// removes status requests whose transactions have wallet-observable shielded spends or outputs.
pub const MIGRATION_ID: Uuid = Uuid::from_u128(0xd7ab0ab2_1487_4cb7_ba74_72ece5fdba2f);

pub(super) const DEPENDENCIES: &[Uuid] =
    &[note_locking::MIGRATION_ID, tx_retrieval_queue::MIGRATION_ID];

pub(super) struct Migration;

impl schemerz::Migration<Uuid> for Migration {
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }

    fn dependencies(&self) -> HashSet<Uuid> {
        DEPENDENCIES.iter().copied().collect()
    }

    fn description(&self) -> &'static str {
        "Separates transaction enhancement from status observation and removes redundant status requests."
    }
}

impl RusqliteMigration for Migration {
    type Error = WalletMigrationError;

    fn up(&self, conn: &rusqlite::Transaction) -> Result<(), Self::Error> {
        // A status request is redundant only when the wallet has a concrete shielded association
        // that compact-block scanning can observe: either a note belonging to the wallet or a
        // spend of such a note. Bundle presence alone is insufficient because a transaction may
        // be funded entirely by transparent inputs and send its shielded outputs to another
        // wallet.
        conn.execute(
            "DELETE FROM tx_retrieval_queue
             WHERE query_type = :status_type
             AND EXISTS (
                SELECT 1
                FROM transactions t
                WHERE t.txid = tx_retrieval_queue.txid
                AND (
                    EXISTS (
                        SELECT 1 FROM sapling_received_notes n
                        WHERE n.transaction_id = t.id_tx
                    )
                    OR EXISTS (
                        SELECT 1 FROM sapling_received_note_spends s
                        WHERE s.transaction_id = t.id_tx
                    )
                    OR EXISTS (
                        SELECT 1 FROM orchard_received_notes n
                        WHERE n.transaction_id = t.id_tx
                    )
                    OR EXISTS (
                        SELECT 1 FROM orchard_received_note_spends s
                        WHERE s.transaction_id = t.id_tx
                    )
                    OR EXISTS (
                        SELECT 1 FROM ironwood_received_notes n
                        WHERE n.transaction_id = t.id_tx
                    )
                    OR EXISTS (
                        SELECT 1 FROM ironwood_received_note_spends s
                        WHERE s.transaction_id = t.id_tx
                    )
                )
             )",
            named_params![":status_type": TxQueryType::Status.code()],
        )?;

        // Enhancement and status observation have independent lifecycles. A transaction can need
        // enhancement in order to discover transparent wallet relevance while also needing
        // durable status observation because compact-block scanning cannot reveal its outcome.
        conn.execute_batch(
            "CREATE TABLE tx_retrieval_queue_new (
                txid BLOB NOT NULL,
                query_type INTEGER NOT NULL,
                dependent_transaction_id INTEGER
                    REFERENCES transactions(id_tx) ON DELETE CASCADE,
                CONSTRAINT tx_retrieval_intent UNIQUE (txid, query_type)
            );

            INSERT INTO tx_retrieval_queue_new (
                txid,
                query_type,
                dependent_transaction_id
            )
            SELECT
                txid,
                query_type,
                dependent_transaction_id
            FROM tx_retrieval_queue;

            DROP TABLE tx_retrieval_queue;

            ALTER TABLE tx_retrieval_queue_new RENAME TO tx_retrieval_queue;

            CREATE INDEX idx_tx_retrieval_queue_dependent_tx
            ON tx_retrieval_queue (dependent_transaction_id);",
        )?;

        Ok(())
    }

    fn down(&self, _transaction: &rusqlite::Transaction) -> Result<(), Self::Error> {
        Err(WalletMigrationError::CannotRevert(MIGRATION_ID))
    }
}

#[cfg(test)]
mod tests {
    use crate::wallet::init::migrations::tests::test_migrate;

    #[test]
    fn migrate() {
        test_migrate(&[super::MIGRATION_ID]);
    }
}
