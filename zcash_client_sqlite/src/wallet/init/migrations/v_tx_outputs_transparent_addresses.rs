//! Reports transparent outputs in `v_tx_outputs` at their transparent receiver address.
//!
//! The received-output arm of `v_tx_outputs` resolved every receiving address through
//! `addresses.address`, which for an external-scope entry holds the unified encoding; the
//! transparent receiver lives only in `addresses.cached_transparent_receiver_address`. Every
//! transparent output received by the wallet at such an address was therefore reported with
//! the enclosing unified address as its `to_address`, misrepresenting what was observably
//! paid on chain.
//!
//! For a payment the wallet made to one of its own transparent addresses the effect was
//! compounded: the transaction produces both a `sent_notes` row carrying the transparent
//! address that was actually paid and a received-output row carrying the unified address,
//! and the view merged the two with `MAX(to_address)` — under SQLite's BINARY collation
//! `'u' > 't'`, so the unified address deterministically shadowed the recorded recipient.
//!
//! This migration recreates `v_tx_outputs` so that the received-output arm reports the
//! transparent receiver itself for transparent outputs, and so that the merge prefers the
//! recipient address recorded when the wallet created the output over the receiving address,
//! rather than choosing between them by byte order. See zcash/librustzcash#2845.
use std::collections::HashSet;

use schemerz_rusqlite::RusqliteMigration;
use uuid::Uuid;

use crate::wallet::init::WalletMigrationError;

use super::{ironwood_pool_code_views, v_tx_outputs_key_scopes};

/// This migration reports transparent outputs in `v_tx_outputs` at their transparent
/// receiver address, and makes the recorded sent-to address authoritative for outputs the
/// wallet created.
pub const MIGRATION_ID: Uuid = Uuid::from_u128(0x856ecde7_c670_47c1_9345_b80ba5b12c4f);

/// `v_tx_outputs_key_scopes` is the prior owner of the `v_tx_outputs` definition this
/// migration recreates; `ironwood_pool_code_views` supplies the current `v_received_outputs`
/// definition whose pool codes the transparent-receiver case discriminates on.
pub(super) const DEPENDENCIES: &[Uuid] = &[
    v_tx_outputs_key_scopes::MIGRATION_ID,
    ironwood_pool_code_views::MIGRATION_ID,
];

pub(super) struct Migration;

impl schemerz::Migration<Uuid> for Migration {
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }

    fn dependencies(&self) -> HashSet<Uuid> {
        DEPENDENCIES.iter().copied().collect()
    }

    fn description(&self) -> &'static str {
        "Reports transparent outputs in v_tx_outputs at their transparent receiver address."
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
