use std::{collections::HashSet, rc::Rc};

use crate::wallet::{account_kind_code, init::WalletMigrationError};
use rusqlite::{named_params, OptionalExtension, Transaction};
use schemer_rusqlite::RusqliteMigration;
use secrecy::{ExposeSecret, SecretVec};
use uuid::Uuid;
use zcash_client_backend::{data_api::AccountSource, keys::UnifiedSpendingKey};
use zcash_keys::keys::UnifiedFullViewingKey;
use zcash_primitives::consensus;
use zip32::fingerprint::SeedFingerprint;

use super::{
    add_account_birthdays, receiving_key_scopes, v_transactions_note_uniqueness, wallet_summaries,
};

/// The migration that switched from presumed seed-derived account IDs to supporting
/// HD accounts and all sorts of imported keys.
pub(super) const MIGRATION_ID: Uuid = Uuid::from_u128(0x6d02ec76_8720_4cc6_b646_c4e2ce69221c);

pub(crate) struct Migration<P: consensus::Parameters> {
    pub(super) seed: Option<Rc<SecretVec<u8>>>,
    pub(super) params: P,
}

impl<P: consensus::Parameters> schemer::Migration for Migration<P> {
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }

    fn dependencies(&self) -> HashSet<Uuid> {
        [
            receiving_key_scopes::MIGRATION_ID,
            add_account_birthdays::MIGRATION_ID,
            v_transactions_note_uniqueness::MIGRATION_ID,
            wallet_summaries::MIGRATION_ID,
        ]
        .into_iter()
        .collect()
    }

    fn description(&self) -> &'static str {
        "Replaces the `account` column in the `accounts` table with columns to support all kinds of account and key types."
    }
}

impl<P: consensus::Parameters> RusqliteMigration for Migration<P> {
    type Error = WalletMigrationError;

    fn up(&self, transaction: &Transaction) -> Result<(), WalletMigrationError> {
        let account_kind_derived = account_kind_code(AccountSource::Derived {
            seed_fingerprint: SeedFingerprint::from_bytes([0; 32]),
            account_index: zip32::AccountId::ZERO,
        });
        let account_kind_imported = account_kind_code(AccountSource::Imported);
        transaction.execute_batch(&format!(
            r#"
            PRAGMA foreign_keys = OFF;
            PRAGMA legacy_alter_table = ON;

            CREATE TABLE accounts_new (
                id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
                account_kind INTEGER NOT NULL DEFAULT {account_kind_derived},
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
                    AND hd_seed_fingerprint IS NULL
                    AND hd_account_index IS NULL
                  )
                )
            );
            CREATE UNIQUE INDEX hd_account ON accounts_new (hd_seed_fingerprint, hd_account_index);
            CREATE UNIQUE INDEX accounts_uivk ON accounts_new (uivk);
            CREATE UNIQUE INDEX accounts_ufvk ON accounts_new (ufvk);
            "#
        ))?;

        // We require the seed *if* there are existing accounts in the table.
        if transaction.query_row("SELECT COUNT(*) FROM accounts", [], |row| {
            Ok(row.get::<_, u32>(0)? > 0)
        })? {
            if let Some(seed) = &self.seed {
                let seed_id = SeedFingerprint::from_seed(seed.expose_secret())
                    .expect("Seed is between 32 and 252 bytes in length.");

                // We track whether we have determined seed relevance or not, in order to
                // correctly report errors when checking the seed against an account:
                //
                // - If we encounter an error with the first account, we can assert that
                //   the seed is not relevant to the wallet by assuming that:
                //   - All accounts are from the same seed (which is historically the only
                //     use case that this migration supported), and
                //   - All accounts in the wallet must have been able to derive their USKs
                //     (in order to derive UIVKs).
                //
                // - Once the seed has been determined to be relevant (because it matched
                //   the first account), any subsequent account derivation failure is
                //   proving wrong our second assumption above, and we report this as
                //   corrupted data.
                let mut seed_is_relevant = false;

                let mut q = transaction.prepare("SELECT * FROM accounts")?;
                let mut rows = q.query([])?;
                while let Some(row) = rows.next()? {
                    let account_index: u32 = row.get("account")?;
                    let birthday_height: u32 = row.get("birthday_height")?;
                    let recover_until_height: Option<u32> = row.get("recover_until_height")?;

                    // Although 'id' is an AUTOINCREMENT column, we'll set it explicitly to match the old account value
                    // strictly as a matter of convenience to make this migration script easier,
                    // specifically around updating tables with foreign keys to this one.
                    let account_id = account_index;

                    // Verify that the UFVK is as expected by re-deriving it.
                    let ufvk: String = row.get("ufvk")?;
                    let ufvk_parsed = UnifiedFullViewingKey::decode(&self.params, &ufvk)
                        .map_err(|_| WalletMigrationError::CorruptedData("Bad UFVK".to_string()))?;
                    let usk = UnifiedSpendingKey::from_seed(
                        &self.params,
                        seed.expose_secret(),
                        zip32::AccountId::try_from(account_index).map_err(|_| {
                            WalletMigrationError::CorruptedData("Bad account index".to_string())
                        })?,
                    )
                    .map_err(|_| {
                        if seed_is_relevant {
                            WalletMigrationError::CorruptedData(
                                "Unable to derive spending key from seed.".to_string(),
                            )
                        } else {
                            WalletMigrationError::SeedNotRelevant
                        }
                    })?;
                    let expected_ufvk = usk.to_unified_full_viewing_key();
                    if ufvk != expected_ufvk.encode(&self.params) {
                        return Err(if seed_is_relevant {
                            WalletMigrationError::CorruptedData(
                                "UFVK does not match expected value.".to_string(),
                            )
                        } else {
                            WalletMigrationError::SeedNotRelevant
                        });
                    }

                    // We made it past one derived account, so the seed must be relevant.
                    seed_is_relevant = true;

                    let uivk = ufvk_parsed
                        .to_unified_incoming_viewing_key()
                        .encode(&self.params);

                    #[cfg(feature = "transparent-inputs")]
                    let transparent_item = ufvk_parsed.transparent().map(|k| k.serialize());
                    #[cfg(not(feature = "transparent-inputs"))]
                    let transparent_item: Option<Vec<u8>> = None;

                    // Get the tree sizes for the birthday height from the blocks table, if
                    // available.
                    let (birthday_sapling_tree_size, birthday_orchard_tree_size) = transaction
                        .query_row(
                            "SELECT sapling_commitment_tree_size - sapling_output_count,
                                    orchard_commitment_tree_size - orchard_action_count
                             FROM blocks
                             WHERE height = :birthday_height",
                            named_params![":birthday_height": birthday_height],
                            |row| {
                                Ok(row
                                    .get::<_, Option<u32>>(0)?
                                    .zip(row.get::<_, Option<u32>>(1)?))
                            },
                        )
                        .optional()?
                        .flatten()
                        .map_or((None, None), |(s, o)| (Some(s), Some(o)));

                    transaction.execute(
                        r#"
                        INSERT INTO accounts_new (
                            id, account_kind, hd_seed_fingerprint, hd_account_index,
                            ufvk, uivk,
                            orchard_fvk_item_cache, sapling_fvk_item_cache, p2pkh_fvk_item_cache,
                            birthday_height, birthday_sapling_tree_size, birthday_orchard_tree_size,
                            recover_until_height
                        )
                        VALUES (
                            :account_id, :account_kind, :seed_id, :account_index,
                            :ufvk, :uivk,
                            :orchard_fvk_item_cache, :sapling_fvk_item_cache, :p2pkh_fvk_item_cache,
                            :birthday_height, :birthday_sapling_tree_size, :birthday_orchard_tree_size,
                            :recover_until_height
                        );
                        "#,
                        named_params![
                            ":account_id": account_id,
                            ":account_kind": account_kind_derived,
                            ":seed_id": seed_id.to_bytes(),
                            ":account_index": account_index,
                            ":ufvk": ufvk,
                            ":uivk": uivk,
                            ":orchard_fvk_item_cache": ufvk_parsed.orchard().map(|k| k.to_bytes()),
                            ":sapling_fvk_item_cache": ufvk_parsed.sapling().map(|k| k.to_bytes()),
                            ":p2pkh_fvk_item_cache": transparent_item,
                            ":birthday_height": birthday_height,
                            ":birthday_sapling_tree_size": birthday_sapling_tree_size,
                            ":birthday_orchard_tree_size": birthday_orchard_tree_size,
                            ":recover_until_height": recover_until_height,
                        ],
                    )?;
                }
            } else {
                return Err(WalletMigrationError::SeedRequired);
            }
        }

        transaction.execute_batch(
            r#"
            DROP TABLE accounts;
            ALTER TABLE accounts_new RENAME TO accounts;

            -- Migrate addresses table
            CREATE TABLE addresses_new (
                account_id INTEGER NOT NULL,
                diversifier_index_be BLOB NOT NULL,
                address TEXT NOT NULL,
                cached_transparent_receiver_address TEXT,
                FOREIGN KEY (account_id) REFERENCES accounts(id),
                CONSTRAINT diversification UNIQUE (account_id, diversifier_index_be)
            );
            CREATE INDEX "addresses_accounts" ON "addresses_new" (
                "account_id" ASC
            );
            INSERT INTO addresses_new (account_id, diversifier_index_be, address, cached_transparent_receiver_address)
            SELECT account, diversifier_index_be, address, cached_transparent_receiver_address
            FROM addresses;

            DROP TABLE addresses;
            ALTER TABLE addresses_new RENAME TO addresses;

            -- Migrate sapling_received_notes table
            CREATE TABLE sapling_received_notes_new (
                id INTEGER PRIMARY KEY,
                tx INTEGER NOT NULL,
                output_index INTEGER NOT NULL,
                account_id INTEGER NOT NULL,
                diversifier BLOB NOT NULL,
                value INTEGER NOT NULL,
                rcm BLOB NOT NULL,
                nf BLOB UNIQUE,
                is_change INTEGER NOT NULL,
                memo BLOB,
                commitment_tree_position INTEGER,
                recipient_key_scope INTEGER,
                FOREIGN KEY (tx) REFERENCES transactions(id_tx),
                FOREIGN KEY (account_id) REFERENCES accounts(id),
                CONSTRAINT tx_output UNIQUE (tx, output_index)
            );
            CREATE INDEX "sapling_received_notes_account" ON "sapling_received_notes_new" (
                "account_id" ASC
            );
            CREATE INDEX "sapling_received_notes_tx" ON "sapling_received_notes_new" (
                "tx" ASC
            );

            -- Replace the `spent` column in `sapling_received_notes` with a junction table between
            -- received notes and the transactions that spend them. This is necessary as otherwise
            -- we cannot compute the correct value of transactions that expire unmined.
            CREATE TABLE sapling_received_note_spends (
                sapling_received_note_id INTEGER NOT NULL,
                transaction_id INTEGER NOT NULL,
                FOREIGN KEY (sapling_received_note_id)
                    REFERENCES sapling_received_notes(id)
                    ON DELETE CASCADE,
                FOREIGN KEY (transaction_id)
                    -- We do not delete transactions, so this does not cascade
                    REFERENCES transactions(id_tx),
                UNIQUE (sapling_received_note_id, transaction_id)
            );

            INSERT INTO sapling_received_note_spends (sapling_received_note_id, transaction_id)
            SELECT id_note, spent
            FROM sapling_received_notes
            WHERE spent IS NOT NULL;

            INSERT INTO sapling_received_notes_new (
                id, tx, output_index, account_id,
                diversifier, value, rcm, nf, is_change, memo, commitment_tree_position,
                recipient_key_scope
            )
            SELECT
                id_note, tx, output_index, account,
                diversifier, value, rcm, nf, is_change, memo, commitment_tree_position,
                recipient_key_scope
            FROM sapling_received_notes;

            DROP TABLE sapling_received_notes;
            ALTER TABLE sapling_received_notes_new RENAME TO sapling_received_notes;

            -- Migrate sent_notes table
            CREATE TABLE sent_notes_new (
                id INTEGER PRIMARY KEY,
                tx INTEGER NOT NULL,
                output_pool INTEGER NOT NULL,
                output_index INTEGER NOT NULL,
                from_account_id INTEGER NOT NULL,
                to_address TEXT,
                to_account_id INTEGER,
                value INTEGER NOT NULL,
                memo BLOB,
                FOREIGN KEY (tx) REFERENCES transactions(id_tx),
                FOREIGN KEY (from_account_id) REFERENCES accounts(id),
                FOREIGN KEY (to_account_id) REFERENCES accounts(id),
                CONSTRAINT tx_output UNIQUE (tx, output_pool, output_index),
                CONSTRAINT note_recipient CHECK (
                    (to_address IS NOT NULL) OR (to_account_id IS NOT NULL)
                )
            );
            CREATE INDEX sent_notes_tx ON sent_notes_new (tx);
            CREATE INDEX sent_notes_from_account ON sent_notes_new (from_account_id);
            CREATE INDEX sent_notes_to_account ON sent_notes_new (to_account_id);
            INSERT INTO sent_notes_new (id, tx, output_pool, output_index, from_account_id, to_address, to_account_id, value, memo)
            SELECT id_note, tx, output_pool, output_index, from_account, to_address, to_account, value, memo
            FROM sent_notes;

            DROP TABLE sent_notes;
            ALTER TABLE sent_notes_new RENAME TO sent_notes;

            -- No one uses this table any more, and it contains a reference to columns we renamed.
            DROP TABLE sapling_witnesses;

            -- Migrate utxos table
            CREATE TABLE utxos_new (
                id INTEGER PRIMARY KEY,
                received_by_account_id INTEGER NOT NULL,
                address TEXT NOT NULL,
                prevout_txid BLOB NOT NULL,
                prevout_idx INTEGER NOT NULL,
                script BLOB NOT NULL,
                value_zat INTEGER NOT NULL,
                height INTEGER NOT NULL,
                FOREIGN KEY (received_by_account_id) REFERENCES accounts(id),
                CONSTRAINT tx_outpoint UNIQUE (prevout_txid, prevout_idx)
            );
            CREATE INDEX utxos_received_by_account ON utxos_new (received_by_account_id);

            INSERT INTO utxos_new (id, received_by_account_id, address, prevout_txid, prevout_idx, script, value_zat, height)
            SELECT id_utxo, received_by_account, address, prevout_txid, prevout_idx, script, value_zat, height
            FROM utxos;

            -- Replace the `spent_in_tx` column in `utxos` with a junction table between received
            -- outputs and the transactions that spend them. This is necessary as otherwise we
            -- cannot compute the correct value of transactions that expire unmined.
            CREATE TABLE transparent_received_output_spends (
                transparent_received_output_id INTEGER NOT NULL,
                transaction_id INTEGER NOT NULL,
                FOREIGN KEY (transparent_received_output_id)
                    REFERENCES utxos(id)
                    ON DELETE CASCADE,
                FOREIGN KEY (transaction_id)
                    -- We do not delete transactions, so this does not cascade
                    REFERENCES transactions(id_tx),
                UNIQUE (transparent_received_output_id, transaction_id)
            );

            INSERT INTO transparent_received_output_spends (transparent_received_output_id, transaction_id)
            SELECT id_utxo, spent_in_tx
            FROM utxos
            WHERE spent_in_tx IS NOT NULL;

            DROP TABLE utxos;
            ALTER TABLE utxos_new RENAME TO utxos;
            "#,
        )?;

        // Rewrite v_transactions view
        transaction.execute_batch(
                "DROP VIEW v_transactions;
                CREATE VIEW v_transactions AS
                WITH
                notes AS (
                    SELECT sapling_received_notes.id             AS id,
                           sapling_received_notes.account_id     AS account_id,
                           transactions.block                    AS block,
                           transactions.txid                     AS txid,
                           2                                     AS pool,
                           sapling_received_notes.value          AS value,
                           CASE
                                WHEN sapling_received_notes.is_change THEN 1
                                ELSE 0
                           END AS is_change,
                           CASE
                                WHEN sapling_received_notes.is_change THEN 0
                                ELSE 1
                           END AS received_count,
                           CASE
                             WHEN (sapling_received_notes.memo IS NULL OR sapling_received_notes.memo = X'F6')
                               THEN 0
                             ELSE 1
                           END AS memo_present
                    FROM sapling_received_notes
                    JOIN transactions
                         ON transactions.id_tx = sapling_received_notes.tx
                    UNION
                    SELECT utxos.id                      AS id,
                           utxos.received_by_account_id  AS account_id,
                           utxos.height                  AS block,
                           utxos.prevout_txid            AS txid,
                           0                             AS pool,
                           utxos.value_zat               AS value,
                           0                             AS is_change,
                           1                             AS received_count,
                           0                             AS memo_present
                    FROM utxos
                    UNION
                    SELECT sapling_received_notes.id             AS id,
                           sapling_received_notes.account_id     AS account_id,
                           transactions.block                    AS block,
                           transactions.txid                     AS txid,
                           2                                     AS pool,
                           -sapling_received_notes.value         AS value,
                           0                             AS is_change,
                           0                             AS received_count,
                           0                             AS memo_present
                    FROM sapling_received_notes
                    JOIN sapling_received_note_spends
                         ON sapling_received_note_id = sapling_received_notes.id
                    JOIN transactions
                         ON transactions.id_tx = sapling_received_note_spends.transaction_id
                    UNION
                    SELECT utxos.id                      AS id,
                           utxos.received_by_account_id  AS account_id,
                           transactions.block            AS block,
                           transactions.txid             AS txid,
                           0                             AS pool,
                           -utxos.value_zat              AS value,
                           0                             AS is_change,
                           0                             AS received_count,
                           0                             AS memo_present
                    FROM utxos
                JOIN transparent_received_output_spends txo_spends
                     ON txo_spends.transparent_received_output_id = txos.id
                JOIN transactions
                     ON transactions.id_tx = txo_spends.transaction_id
                ),
                sent_note_counts AS (
                    SELECT sent_notes.from_account_id AS account_id,
                           transactions.txid       AS txid,
                           COUNT(DISTINCT sent_notes.id) as sent_notes,
                           SUM(
                             CASE
                               WHEN (sent_notes.memo IS NULL OR sent_notes.memo = X'F6' OR sapling_received_notes.tx IS NOT NULL)
                                 THEN 0
                               ELSE 1
                             END
                           ) AS memo_count
                    FROM sent_notes
                    JOIN transactions
                         ON transactions.id_tx = sent_notes.tx
                    LEFT JOIN sapling_received_notes
                              ON (sent_notes.tx, sent_notes.output_pool, sent_notes.output_index) =
                                 (sapling_received_notes.tx, 2, sapling_received_notes.output_index)
                    WHERE COALESCE(sapling_received_notes.is_change, 0) = 0
                    GROUP BY account_id, txid
                ),
                blocks_max_height AS (
                    SELECT MAX(blocks.height) as max_height FROM blocks
                )
                SELECT notes.account_id                  AS account_id,
                       notes.block                       AS mined_height,
                       notes.txid                        AS txid,
                       transactions.tx_index             AS tx_index,
                       transactions.expiry_height        AS expiry_height,
                       transactions.raw                  AS raw,
                       SUM(notes.value)                  AS account_balance_delta,
                       transactions.fee                  AS fee_paid,
                       SUM(notes.is_change) > 0          AS has_change,
                       MAX(COALESCE(sent_note_counts.sent_notes, 0))  AS sent_note_count,
                       SUM(notes.received_count)         AS received_note_count,
                       SUM(notes.memo_present) + MAX(COALESCE(sent_note_counts.memo_count, 0)) AS memo_count,
                       blocks.time                       AS block_time,
                       (
                            blocks.height IS NULL
                            AND transactions.expiry_height BETWEEN 1 AND blocks_max_height.max_height
                       ) AS expired_unmined
                FROM notes
                LEFT JOIN transactions
                     ON notes.txid = transactions.txid
                JOIN blocks_max_height
                LEFT JOIN blocks ON blocks.height = notes.block
                LEFT JOIN sent_note_counts
                          ON sent_note_counts.account_id = notes.account_id
                          AND sent_note_counts.txid = notes.txid
                GROUP BY notes.account_id, notes.txid;

                DROP VIEW v_tx_outputs;
                CREATE VIEW v_tx_outputs AS
                SELECT transactions.txid                   AS txid,
                       2                                   AS output_pool,
                       sapling_received_notes.output_index AS output_index,
                       sent_notes.from_account_id          AS from_account_id,
                       sapling_received_notes.account_id   AS to_account_id,
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
                SELECT utxos.prevout_txid           AS txid,
                       0                            AS output_pool,
                       utxos.prevout_idx            AS output_index,
                       NULL                         AS from_account_id,
                       utxos.received_by_account_id AS to_account_id,
                       utxos.address                AS to_address,
                       utxos.value_zat              AS value,
                       0                            AS is_change,
                       NULL                         AS memo
                FROM utxos
                UNION
                SELECT transactions.txid                 AS txid,
                       sent_notes.output_pool            AS output_pool,
                       sent_notes.output_index           AS output_index,
                       sent_notes.from_account_id        AS from_account_id,
                       sapling_received_notes.account_id AS to_account_id,
                       sent_notes.to_address             AS to_address,
                       sent_notes.value                  AS value,
                       0                                 AS is_change,
                       sent_notes.memo                   AS memo
                FROM sent_notes
                JOIN transactions
                     ON transactions.id_tx = sent_notes.tx
                LEFT JOIN sapling_received_notes
                          ON (sent_notes.tx, sent_notes.output_pool, sent_notes.output_index) =
                             (sapling_received_notes.tx, 2, sapling_received_notes.output_index)
                WHERE COALESCE(sapling_received_notes.is_change, 0) = 0;
            ")?;

        transaction.execute_batch(
            r#"
                PRAGMA legacy_alter_table = OFF;
                PRAGMA foreign_keys = ON;
            "#,
        )?;

        Ok(())
    }

    fn down(&self, _transaction: &Transaction) -> Result<(), WalletMigrationError> {
        Err(WalletMigrationError::CannotRevert(MIGRATION_ID))
    }
}
