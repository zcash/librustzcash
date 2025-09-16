//! Adds support for marking transactions as explicitly trusted for the purpose of satisfying the
//! ZIP 315 confirmations policy
use std::collections::HashSet;

use schemerz_rusqlite::RusqliteMigration;
use uuid::Uuid;

use crate::wallet::init::{migrations::fix_v_transactions_expired_unmined, WalletMigrationError};

pub(super) const MIGRATION_ID: Uuid = Uuid::from_u128(0x4e68277f_6269_467e_9437_f3853cc4a41f);

const DEPENDENCIES: &[Uuid] = &[fix_v_transactions_expired_unmined::MIGRATION_ID];

pub(super) struct Migration;

impl schemerz::Migration<Uuid> for Migration {
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }

    fn dependencies(&self) -> HashSet<Uuid> {
        DEPENDENCIES.iter().copied().collect()
    }

    fn description(&self) -> &'static str {
        "Adds support for marking transactions as explicitly trusted."
    }
}

impl RusqliteMigration for Migration {
    type Error = WalletMigrationError;

    fn up(&self, transaction: &rusqlite::Transaction) -> Result<(), WalletMigrationError> {
        transaction.execute_batch(
            "ALTER TABLE transactions ADD COLUMN trust_status INTEGER;

            DROP VIEW v_tx_outputs;
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
                       ro.memo                      AS memo,
                       IFNULL(t.trust_status, 0)    AS is_trusted,
                       tt.mined_height              AS t_input_mined_height,
                       IFNULL(tt.trust_status, 0)   AS t_input_trust_status
                FROM v_received_outputs ro
                JOIN transactions
                    ON transactions.id_tx = ro.transaction_id
                LEFT JOIN addresses a ON a.id = ro.address_id
                -- join to the sent_notes table to obtain `from_account_id`
                LEFT JOIN sent_notes ON sent_notes.id = ro.sent_note_id
                -- join on the accounts table to obtain account UUIDs
                LEFT JOIN accounts from_account ON from_account.id = sent_notes.from_account_id
                LEFT JOIN accounts to_account ON to_account.id = ro.account_id
                -- join to transparent_received_output_spends to gather data about transaction inputs
                LEFT OUTER JOIN transparent_received_output_spends ros
                   ON ros.transaction_id = t.id_tx
                LEFT OUTER JOIN transparent_received_outputs tro
                   ON tro.id = ros.transparent_received_output_id
                LEFT OUTER JOIN transactions tt ON tt.id_tx = tro.transaction_id
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
                       sent_notes.memo              AS memo,
                       1                            AS is_trusted,
                       NULL                         AS t_input_mined_height,
                       1                            AS t_input_trust_status
                FROM sent_notes
                JOIN transactions
                    ON transactions.id_tx = sent_notes.tx
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
                max(memo) AS memo,
                max(t_input_mined_height) AS max_shielding_input_height,
                min(t_input_trust_status) AS min_shielding_input_trust
            FROM unioned
            GROUP BY txid, output_pool, output_index"
        )?;
        Ok(())
    }

    fn down(&self, _transaction: &rusqlite::Transaction) -> Result<(), WalletMigrationError> {
        Ok(())
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
