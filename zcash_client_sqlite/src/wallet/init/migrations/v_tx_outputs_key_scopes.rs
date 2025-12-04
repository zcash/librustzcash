//! This migration adds missing key scope information to the `v_received_outputs` and
//! `v_tx_outputs` views.
use std::collections::HashSet;

use schemerz_rusqlite::RusqliteMigration;
use uuid::Uuid;

use crate::wallet::init::{WalletMigrationError, migrations::account_delete_cascade};

pub(super) const MIGRATION_ID: Uuid = Uuid::from_u128(0x97ac36a9_196f_4dd9_993d_722bde95bebc);

const DEPENDENCIES: &[Uuid] = &[account_delete_cascade::MIGRATION_ID];

pub(super) struct Migration;

impl schemerz::Migration<Uuid> for Migration {
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }

    fn dependencies(&self) -> HashSet<Uuid> {
        DEPENDENCIES.iter().copied().collect()
    }

    fn description(&self) -> &'static str {
        "Adds `ON DELETE CASCADE` to foreign keys to support account deletion."
    }
}

impl RusqliteMigration for Migration {
    type Error = WalletMigrationError;

    fn up(&self, conn: &rusqlite::Transaction) -> Result<(), Self::Error> {
        conn.execute_batch(
            r#"
            DROP VIEW v_tx_outputs;
            CREATE VIEW v_tx_outputs AS
            WITH unioned AS (
                -- select all outputs received by the wallet
                SELECT transactions.id_tx           AS transaction_id,
                       transactions.txid            AS txid,
                       transactions.mined_height    AS mined_height,
                       ro.pool                      AS output_pool,
                       ro.output_index              AS output_index,
                       from_account.uuid            AS from_account_uuid,
                       to_account.uuid              AS to_account_uuid,
                       a.address                    AS to_address,
                       a.diversifier_index_be       AS diversifier_index_be,
                       ro.value                     AS value,
                       ro.is_change                 AS is_change,
                       ro.memo                      AS memo,
                       a.key_scope                  AS recipient_key_scope
                FROM v_received_outputs ro
                JOIN transactions
                    ON transactions.id_tx = ro.transaction_id
                LEFT JOIN addresses a ON a.id = ro.address_id
                -- join to the sent_notes table to obtain `from_account_id`
                LEFT JOIN sent_notes ON sent_notes.id = ro.sent_note_id
                -- join on the accounts table to obtain account UUIDs
                LEFT JOIN accounts from_account ON from_account.id = sent_notes.from_account_id
                LEFT JOIN accounts to_account ON to_account.id = ro.account_id
                UNION ALL
                -- select all outputs sent from the wallet to external recipients
                SELECT transactions.id_tx           AS transaction_id,
                       transactions.txid            AS txid,
                       transactions.mined_height    AS mined_height,
                       sent_notes.output_pool       AS output_pool,
                       sent_notes.output_index      AS output_index,
                       from_account.uuid            AS from_account_uuid,
                       NULL                         AS to_account_uuid,
                       sent_notes.to_address        AS to_address,
                       NULL                         AS diversifier_index_be,
                       sent_notes.value             AS value,
                       0                            AS is_change,
                       sent_notes.memo              AS memo,
                       NULL                         AS recipient_key_scope
                FROM sent_notes
                JOIN transactions
                    ON transactions.id_tx = sent_notes.transaction_id
                LEFT JOIN v_received_outputs ro ON ro.sent_note_id = sent_notes.id
                -- join on the accounts table to obtain account UUIDs
                LEFT JOIN accounts from_account ON from_account.id = sent_notes.from_account_id
            )
            -- merge duplicate rows while retaining maximum information
            SELECT
                transaction_id,
                MAX(txid),
                MAX(mined_height) AS mined_height,
                output_pool,
                output_index,
                MAX(from_account_uuid) AS from_account_uuid,
                MAX(to_account_uuid) AS to_account_uuid,
                MAX(to_address) AS to_address,
                MAX(value) AS value,
                MAX(is_change) AS is_change,
                MAX(memo) AS memo,
                MAX(recipient_key_scope) AS recipient_key_scope
            FROM unioned
            GROUP BY transaction_id, output_pool, output_index;
            "#,
        )?;

        Ok(())
    }

    fn down(&self, _transaction: &rusqlite::Transaction) -> Result<(), Self::Error> {
        Err(WalletMigrationError::CannotRevert(MIGRATION_ID))
    }
}

#[cfg(test)]
mod tests {
    use zcash_client_backend::data_api::testing::{pool::dsl::TestDsl, sapling::SaplingPoolTester};
    use zcash_protocol::{PoolType, value::Zatoshis};

    use crate::{
        error::SqliteClientError,
        testing::{BlockCache, db::TestDbFactory},
        wallet::{KeyScope, encoding::parse_pool_code, init::migrations::tests::test_migrate},
    };

    #[test]
    fn migrate() {
        test_migrate(&[super::MIGRATION_ID]);
    }

    #[test]
    fn v_tx_outputs_validity() {
        let dsf = TestDbFactory::default();
        let cache = BlockCache::new();
        let mut st =
            TestDsl::with_sapling_birthday_account(dsf, cache).build::<SaplingPoolTester>();

        // Add funds to the wallet in a single note
        let (h, _, _) = st.add_a_single_note_checking_balance(Zatoshis::const_from_u64(60000));

        let mut stmt = st.wallet().conn().prepare(
            "SELECT transaction_id, output_pool, output_index, value, recipient_key_scope FROM v_tx_outputs"
        ).unwrap();

        let results = stmt
            .query_and_then::<_, SqliteClientError, _, _>([], |row| {
                let txid = row.get::<_, i64>("transaction_id")?;
                let pool = parse_pool_code(row.get("output_pool")?)?;
                let output_index = row.get::<_, u32>("output_index")?;
                let value = row.get::<_, u32>("value")?;
                let recipient_key_scope = row
                    .get::<_, Option<i64>>("recipient_key_scope")?
                    .map(KeyScope::decode)
                    .transpose()?;

                Ok((txid, pool, output_index, value, recipient_key_scope))
            })
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        assert_eq!(results.len(), 1);
        let (_, pool, _, value, recipient_key_scope) = results[0];
        assert_eq!(pool, PoolType::SAPLING);
        assert_eq!(value, 60000);
        assert_eq!(recipient_key_scope, Some(KeyScope::EXTERNAL));
    }
}
