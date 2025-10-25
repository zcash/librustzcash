//! Modifies definitions to avoid keywords that may not be available in older SQLite versions.
use std::collections::HashSet;

use schemerz_rusqlite::RusqliteMigration;
use uuid::Uuid;

use crate::wallet::init::{WalletMigrationError, migrations::tx_retrieval_queue};

pub(super) const MIGRATION_ID: Uuid = Uuid::from_u128(0x156d8c8f_2173_4b59_89b6_75697d5a2103);

const DEPENDENCIES: &[Uuid] = &[tx_retrieval_queue::MIGRATION_ID];

pub(super) struct Migration;

impl schemerz::Migration<Uuid> for Migration {
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }

    fn dependencies(&self) -> HashSet<Uuid> {
        DEPENDENCIES.iter().copied().collect()
    }

    fn description(&self) -> &'static str {
        "Modifies definitions to avoid keywords that may not be available in older SQLite versions."
    }
}

impl RusqliteMigration for Migration {
    type Error = WalletMigrationError;

    fn up(&self, transaction: &rusqlite::Transaction) -> Result<(), WalletMigrationError> {
        transaction.execute_batch(
            r#"
            DROP VIEW v_tx_outputs;
            CREATE VIEW v_tx_outputs AS
            -- select all outputs received by the wallet
            SELECT transactions.txid            AS txid,
                   ro.pool                      AS output_pool,
                   ro.output_index              AS output_index,
                   sent_notes.from_account_id   AS from_account_id,
                   ro.account_id                AS to_account_id,
                   NULL                         AS to_address,
                   ro.value                     AS value,
                   ro.is_change                 AS is_change,
                   ro.memo                      AS memo
            FROM v_received_outputs ro
            JOIN transactions
                ON transactions.id_tx = ro.transaction_id
            -- join to the sent_notes table to obtain `from_account_id`
            LEFT JOIN sent_notes ON sent_notes.id = ro.sent_note_id
            UNION
            -- select all outputs sent from the wallet to external recipients
            SELECT transactions.txid            AS txid,
                   sent_notes.output_pool       AS output_pool,
                   sent_notes.output_index      AS output_index,
                   sent_notes.from_account_id   AS from_account_id,
                   NULL                         AS to_account_id,
                   sent_notes.to_address        AS to_address,
                   sent_notes.value             AS value,
                   0                            AS is_change,
                   sent_notes.memo              AS memo
            FROM sent_notes
            JOIN transactions
                ON transactions.id_tx = sent_notes.tx
            LEFT JOIN v_received_outputs ro ON ro.sent_note_id = sent_notes.id
            -- exclude any sent notes for which a row exists in the v_received_outputs view
            WHERE ro.account_id IS NULL
        "#,
        )?;

        Ok(())
    }

    fn down(&self, _: &rusqlite::Transaction) -> Result<(), WalletMigrationError> {
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
