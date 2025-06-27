//! This migration adds a UUID to each account record, and adds `name` and `key_source` columns. In
//! addition, imported account records are now permitted to include key derivation metadata.

use std::collections::HashSet;

use rusqlite::named_params;
use schemerz_rusqlite::RusqliteMigration;
use uuid::Uuid;
use zcash_client_backend::data_api::{AccountPurpose, AccountSource, Zip32Derivation};
use zip32::fingerprint::SeedFingerprint;

use crate::wallet::{account_kind_code, init::WalletMigrationError};

use super::support_legacy_sqlite;

pub(super) const MIGRATION_ID: Uuid = Uuid::from_u128(0xcccc623f_3243_43c7_b884_ceef25149e04);

const DEPENDENCIES: &[Uuid] = &[support_legacy_sqlite::MIGRATION_ID];

pub(super) struct Migration;

impl schemerz::Migration<Uuid> for Migration {
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }

    fn dependencies(&self) -> HashSet<Uuid> {
        DEPENDENCIES.iter().copied().collect()
    }

    fn description(&self) -> &'static str {
        "Adds a UUID for each account."
    }
}

impl RusqliteMigration for Migration {
    type Error = WalletMigrationError;

    fn up(&self, transaction: &rusqlite::Transaction) -> Result<(), Self::Error> {
        let account_kind_derived = account_kind_code(&AccountSource::Derived {
            derivation: Zip32Derivation::new(
                SeedFingerprint::from_bytes([0; 32]),
                zip32::AccountId::ZERO,
                #[cfg(feature = "zcashd-compat")]
                None,
            ),
            key_source: None,
        });
        let account_kind_imported = account_kind_code(&AccountSource::Imported {
            // the purpose here is irrelevant; we just use it to get the correct code
            // for the account kind
            purpose: AccountPurpose::ViewOnly,
            key_source: None,
        });
        transaction.execute_batch(&format!(
            r#"
            CREATE TABLE accounts_new (
                id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
                name TEXT,
                uuid BLOB NOT NULL,
                account_kind INTEGER NOT NULL DEFAULT {account_kind_derived},
                key_source TEXT,
                hd_seed_fingerprint BLOB,
                hd_account_index INTEGER,
                ufvk TEXT,
                uivk TEXT NOT NULL,
                orchard_fvk_item_cache BLOB,
                sapling_fvk_item_cache BLOB,
                p2pkh_fvk_item_cache BLOB,
                birthday_height INTEGER NOT NULL,
                birthday_sapling_tree_size INTEGER,
                birthday_orchard_tree_size INTEGER,
                recover_until_height INTEGER,
                has_spend_key INTEGER NOT NULL DEFAULT 1,
                CHECK (
                  (
                    account_kind = {account_kind_derived}
                    AND hd_seed_fingerprint IS NOT NULL
                    AND hd_account_index IS NOT NULL
                    AND ufvk IS NOT NULL
                  )
                  OR
                  (
                    account_kind = {account_kind_imported}
                    AND (hd_seed_fingerprint IS NULL) = (hd_account_index IS NULL)
                  )
                )
            );
            "#
        ))?;

        let mut q = transaction.prepare("SELECT * FROM accounts")?;
        let mut rows = q.query([])?;
        while let Some(row) = rows.next()? {
            let preserve = |idx: &str| row.get::<_, rusqlite::types::Value>(idx);
            transaction.execute(
                r#"
                INSERT INTO accounts_new (
                    id, uuid,
                    account_kind, hd_seed_fingerprint, hd_account_index,
                    ufvk, uivk,
                    orchard_fvk_item_cache, sapling_fvk_item_cache, p2pkh_fvk_item_cache,
                    birthday_height, birthday_sapling_tree_size, birthday_orchard_tree_size,
                    recover_until_height,
                    has_spend_key
                )
                VALUES (
                    :account_id, :uuid,
                    :account_kind, :hd_seed_fingerprint, :hd_account_index,
                    :ufvk, :uivk,
                    :orchard_fvk_item_cache, :sapling_fvk_item_cache, :p2pkh_fvk_item_cache,
                    :birthday_height, :birthday_sapling_tree_size, :birthday_orchard_tree_size,
                    :recover_until_height,
                    :has_spend_key
                );
                "#,
                named_params! {
                    ":account_id": preserve("id")?,
                    ":uuid": Uuid::new_v4(),
                    ":account_kind": preserve("account_kind")?,
                    ":hd_seed_fingerprint": preserve("hd_seed_fingerprint")?,
                    ":hd_account_index": preserve("hd_account_index")?,
                    ":ufvk": preserve("ufvk")?,
                    ":uivk": preserve("uivk")?,
                    ":orchard_fvk_item_cache": preserve("orchard_fvk_item_cache")?,
                    ":sapling_fvk_item_cache": preserve("sapling_fvk_item_cache")?,
                    ":p2pkh_fvk_item_cache": preserve("p2pkh_fvk_item_cache")?,
                    ":birthday_height": preserve("birthday_height")?,
                    ":birthday_sapling_tree_size": preserve("birthday_sapling_tree_size")?,
                    ":birthday_orchard_tree_size": preserve("birthday_orchard_tree_size")?,
                    ":recover_until_height": preserve("recover_until_height")?,
                    ":has_spend_key": preserve("has_spend_key")?,
                },
            )?;
        }

        transaction.execute_batch(
            "PRAGMA legacy_alter_table = ON;
            DROP TABLE accounts;
            ALTER TABLE accounts_new RENAME TO accounts;
            PRAGMA legacy_alter_table = OFF;

            -- Add the new index.
            CREATE UNIQUE INDEX accounts_uuid ON accounts (uuid);

            -- Recreate the existing indices now that the original ones have been deleted.
            CREATE UNIQUE INDEX hd_account ON accounts (hd_seed_fingerprint, hd_account_index);
            CREATE UNIQUE INDEX accounts_uivk ON accounts (uivk);
            CREATE UNIQUE INDEX accounts_ufvk ON accounts (ufvk);

            -- Replace accounts.id with accounts.uuid in v_transactions.
            DROP VIEW v_transactions;
            CREATE VIEW v_transactions AS
            WITH
            notes AS (
                -- Outputs received in this transaction
                SELECT ro.account_id              AS account_id,
                       transactions.mined_height  AS mined_height,
                       transactions.txid          AS txid,
                       ro.pool                    AS pool,
                       id_within_pool_table,
                       ro.value                   AS value,
                       0                          AS spent_note_count,
                       CASE
                            WHEN ro.is_change THEN 1
                            ELSE 0
                       END AS change_note_count,
                       CASE
                            WHEN ro.is_change THEN 0
                            ELSE 1
                       END AS received_count,
                       CASE
                         WHEN (ro.memo IS NULL OR ro.memo = X'F6')
                           THEN 0
                         ELSE 1
                       END AS memo_present,
                       -- The wallet cannot receive transparent outputs in shielding transactions.
                       CASE
                         WHEN ro.pool = 0
                           THEN 1
                         ELSE 0
                       END AS does_not_match_shielding
                FROM v_received_outputs ro
                JOIN transactions
                     ON transactions.id_tx = ro.transaction_id
                UNION
                -- Outputs spent in this transaction
                SELECT ro.account_id              AS account_id,
                       transactions.mined_height  AS mined_height,
                       transactions.txid          AS txid,
                       ro.pool                    AS pool,
                       id_within_pool_table,
                       -ro.value                  AS value,
                       1                          AS spent_note_count,
                       0                          AS change_note_count,
                       0                          AS received_count,
                       0                          AS memo_present,
                       -- The wallet cannot spend shielded outputs in shielding transactions.
                       CASE
                         WHEN ro.pool != 0
                           THEN 1
                         ELSE 0
                       END AS does_not_match_shielding
                FROM v_received_outputs ro
                JOIN v_received_output_spends ros
                     ON ros.pool = ro.pool
                     AND ros.received_output_id = ro.id_within_pool_table
                JOIN transactions
                     ON transactions.id_tx = ros.transaction_id
            ),
            -- Obtain a count of the notes that the wallet created in each transaction,
            -- not counting change notes.
            sent_note_counts AS (
                SELECT sent_notes.from_account_id     AS account_id,
                       transactions.txid              AS txid,
                       COUNT(DISTINCT sent_notes.id)  AS sent_notes,
                       SUM(
                         CASE
                           WHEN (sent_notes.memo IS NULL OR sent_notes.memo = X'F6' OR ro.transaction_id IS NOT NULL)
                             THEN 0
                           ELSE 1
                         END
                       ) AS memo_count
                FROM sent_notes
                JOIN transactions
                     ON transactions.id_tx = sent_notes.tx
                LEFT JOIN v_received_outputs ro
                     ON sent_notes.id = ro.sent_note_id
                WHERE COALESCE(ro.is_change, 0) = 0
                GROUP BY account_id, txid
            ),
            blocks_max_height AS (
                SELECT MAX(blocks.height) AS max_height FROM blocks
            )
            SELECT accounts.uuid                AS account_uuid,
                   notes.mined_height           AS mined_height,
                   notes.txid                   AS txid,
                   transactions.tx_index        AS tx_index,
                   transactions.expiry_height   AS expiry_height,
                   transactions.raw             AS raw,
                   SUM(notes.value)             AS account_balance_delta,
                   transactions.fee             AS fee_paid,
                   SUM(notes.change_note_count) > 0  AS has_change,
                   MAX(COALESCE(sent_note_counts.sent_notes, 0))  AS sent_note_count,
                   SUM(notes.received_count)         AS received_note_count,
                   SUM(notes.memo_present) + MAX(COALESCE(sent_note_counts.memo_count, 0)) AS memo_count,
                   blocks.time                       AS block_time,
                   (
                        blocks.height IS NULL
                        AND transactions.expiry_height BETWEEN 1 AND blocks_max_height.max_height
                   ) AS expired_unmined,
                   SUM(notes.spent_note_count) AS spent_note_count,
                   (
                        -- All of the wallet-spent and wallet-received notes are consistent with a
                        -- shielding transaction.
                        SUM(notes.does_not_match_shielding) = 0
                        -- The transaction contains at least one wallet-spent output.
                        AND SUM(notes.spent_note_count) > 0
                        -- The transaction contains at least one wallet-received note.
                        AND (SUM(notes.received_count) + SUM(notes.change_note_count)) > 0
                        -- We do not know about any external outputs of the transaction.
                        AND MAX(COALESCE(sent_note_counts.sent_notes, 0)) = 0
                   ) AS is_shielding
            FROM notes
            LEFT JOIN accounts ON accounts.id = notes.account_id
            LEFT JOIN transactions
                 ON notes.txid = transactions.txid
            JOIN blocks_max_height
            LEFT JOIN blocks ON blocks.height = notes.mined_height
            LEFT JOIN sent_note_counts
                 ON sent_note_counts.account_id = notes.account_id
                 AND sent_note_counts.txid = notes.txid
            GROUP BY notes.account_id, notes.txid;

            -- Replace accounts.id with accounts.uuid in v_tx_outputs.
            DROP VIEW v_tx_outputs;
            CREATE VIEW v_tx_outputs AS
            WITH unioned AS (
                -- select all outputs received by the wallet
                SELECT transactions.txid            AS txid,
                       ro.pool                      AS output_pool,
                       ro.output_index              AS output_index,
                       from_account.uuid            AS from_account_uuid,
                       to_account.uuid              AS to_account_uuid,
                       NULL                         AS to_address,
                       ro.value                     AS value,
                       ro.is_change                 AS is_change,
                       ro.memo                      AS memo
                FROM v_received_outputs ro
                JOIN transactions
                    ON transactions.id_tx = ro.transaction_id
                -- join to the sent_notes table to obtain `from_account_id`
                LEFT JOIN sent_notes ON sent_notes.id = ro.sent_note_id
                -- join on the accounts table to obtain account UUIDs
                LEFT JOIN accounts from_account ON from_account.id = sent_notes.from_account_id
                LEFT JOIN accounts to_account ON to_account.id = ro.account_id
                UNION ALL
                -- select all outputs sent from the wallet to external recipients
                SELECT transactions.txid            AS txid,
                       sent_notes.output_pool       AS output_pool,
                       sent_notes.output_index      AS output_index,
                       from_account.uuid            AS from_account_uuid,
                       NULL                         AS to_account_uuid,
                       sent_notes.to_address        AS to_address,
                       sent_notes.value             AS value,
                       0                            AS is_change,
                       sent_notes.memo              AS memo
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
                max(memo) AS memo
            FROM unioned
            GROUP BY txid, output_pool, output_index",
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
