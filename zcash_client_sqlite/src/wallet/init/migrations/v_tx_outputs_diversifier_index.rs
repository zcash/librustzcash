//! Emits the documented `diversifier_index_be` column from `v_tx_outputs`.
//!
//! The column was selected into the view's `unioned` CTE — and documented as part of the
//! view's output — when receiving-address information was added to `v_tx_outputs`, but the
//! outer merge projection never carried it through, so `SELECT diversifier_index_be FROM
//! v_tx_outputs` has always failed with "no such column". This migration recreates the view
//! with the column projected through the merge: for an output the wallet both sent and
//! received, the received arm's non-`NULL` index survives, and rows for outputs sent to
//! external recipients remain `NULL`. See zcash/librustzcash#2863.
use std::collections::HashSet;

use schemerz_rusqlite::RusqliteMigration;
use uuid::Uuid;

use crate::wallet::init::WalletMigrationError;

use super::v_tx_outputs_transparent_addresses;

/// This migration projects the previously-dropped `diversifier_index_be` column through
/// the outer merge of `v_tx_outputs`.
pub const MIGRATION_ID: Uuid = Uuid::from_u128(0xb61cb2a9_5662_4998_8622_e62f1942cb74);

/// `v_tx_outputs_transparent_addresses` is the prior owner of the `v_tx_outputs` definition
/// this migration recreates.
const DEPENDENCIES: &[Uuid] = &[v_tx_outputs_transparent_addresses::MIGRATION_ID];

pub(super) struct Migration;

impl schemerz::Migration<Uuid> for Migration {
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }

    fn dependencies(&self) -> HashSet<Uuid> {
        DEPENDENCIES.iter().copied().collect()
    }

    fn description(&self) -> &'static str {
        "Emits the documented diversifier_index_be column from v_tx_outputs."
    }
}

impl RusqliteMigration for Migration {
    type Error = WalletMigrationError;

    fn up(&self, transaction: &rusqlite::Transaction) -> Result<(), Self::Error> {
        transaction.execute_batch(
            "DROP VIEW v_tx_outputs;
            CREATE VIEW v_tx_outputs AS
            WITH unioned AS (
                -- select all outputs received by the wallet
                SELECT t.id_tx                      AS transaction_id,
                       t.txid                       AS txid,
                       t.mined_height               AS mined_height,
                       IFNULL(t.trust_status, 0)    AS trust_status,
                       ro.pool                      AS output_pool,
                       ro.output_index              AS output_index,
                       from_account.uuid            AS from_account_uuid,
                       to_account.uuid              AS to_account_uuid,
                       -- for a transparent output, the address at which it was received is
                       -- the transparent receiver itself, not a unified address containing it
                       CASE ro.pool
                            WHEN 0 THEN a.cached_transparent_receiver_address
                            ELSE a.address
                       END                          AS to_address,
                       0                            AS is_sent_row,
                       a.diversifier_index_be       AS diversifier_index_be,
                       ro.value                     AS value,
                       ro.is_change                 AS is_change,
                       ro.memo                      AS memo,
                       a.key_scope                  AS recipient_key_scope
                FROM v_received_outputs ro
                JOIN transactions t
                    ON t.id_tx = ro.transaction_id
                LEFT JOIN addresses a ON a.id = ro.address_id
                -- join to the sent_notes table to obtain `from_account_id`
                LEFT JOIN sent_notes ON sent_notes.id = ro.sent_note_id
                -- join on the accounts table to obtain account UUIDs
                LEFT JOIN accounts from_account ON from_account.id = sent_notes.from_account_id
                LEFT JOIN accounts to_account ON to_account.id = ro.account_id
                UNION ALL
                -- select all outputs sent by the wallet
                SELECT t.id_tx                      AS transaction_id,
                       t.txid                       AS txid,
                       t.mined_height               AS mined_height,
                       IFNULL(t.trust_status, 0)    AS trust_status,
                       sent_notes.output_pool       AS output_pool,
                       sent_notes.output_index      AS output_index,
                       from_account.uuid            AS from_account_uuid,
                       NULL                         AS to_account_uuid,
                       sent_notes.to_address        AS to_address,
                       1                            AS is_sent_row,
                       NULL                         AS diversifier_index_be,
                       sent_notes.value             AS value,
                       0                            AS is_change,
                       sent_notes.memo              AS memo,
                       NULL                         AS recipient_key_scope
                FROM sent_notes
                JOIN transactions t
                    ON t.id_tx = sent_notes.transaction_id
                LEFT JOIN v_received_outputs ro ON ro.sent_note_id = sent_notes.id
                -- join on the accounts table to obtain account UUIDs
                LEFT JOIN accounts from_account ON from_account.id = sent_notes.from_account_id
            )
            -- merge duplicate rows while retaining maximum information
            SELECT
                transaction_id,
                MAX(txid)                   AS txid,
                MAX(mined_height)           AS tx_mined_height,
                MIN(trust_status)           AS tx_trust_status,
                output_pool,
                output_index,
                MAX(from_account_uuid)      AS from_account_uuid,
                MAX(to_account_uuid)        AS to_account_uuid,
                -- the recipient address recorded when the wallet created the output is
                -- authoritative; the receiving address is reported only for outputs the
                -- wallet did not create
                COALESCE(
                    MAX(CASE WHEN is_sent_row THEN to_address END),
                    MAX(CASE WHEN NOT is_sent_row THEN to_address END)
                )                           AS to_address,
                MAX(diversifier_index_be)   AS diversifier_index_be,
                MAX(value)                  AS value,
                MAX(is_change)              AS is_change,
                MAX(memo)                   AS memo,
                MAX(recipient_key_scope)    AS recipient_key_scope
            FROM unioned
            GROUP BY transaction_id, output_pool, output_index;
            ",
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
