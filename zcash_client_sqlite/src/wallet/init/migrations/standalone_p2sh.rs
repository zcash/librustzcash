//! This migration relaxes the addresses table constraint to allow standalone P2SH addresses
//! that have an imported transparent receiver script but no imported public key and no
//! transparent child index.

use std::collections::HashSet;

use schemerz_rusqlite::RusqliteMigration;
use uuid::Uuid;

use crate::wallet::init::WalletMigrationError;

use super::account_delete_cascade;

pub(super) const MIGRATION_ID: Uuid = Uuid::from_u128(0x944f8a1e_bdfa_4d52_90ca_663dee8efc62);

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
        "Relaxes the addresses table constraint to allow standalone P2SH addresses."
    }
}

impl RusqliteMigration for Migration {
    type Error = WalletMigrationError;

    fn up(&self, transaction: &rusqlite::Transaction) -> Result<(), Self::Error> {
        // Recreate the addresses table with the relaxed constraint.
        // The new constraint allows rows where:
        // - transparent_child_index IS NULL AND imported_transparent_receiver_pubkey IS NULL
        //   as long as key_scope = -1 (Foreign) AND imported_transparent_receiver_script IS NOT NULL
        //   (this is the standalone P2SH case)
        transaction.execute_batch(
            r#"
            CREATE TABLE addresses_new (
                id INTEGER NOT NULL PRIMARY KEY,
                account_id INTEGER NOT NULL
                    REFERENCES accounts(id) ON DELETE CASCADE,
                key_scope INTEGER NOT NULL,
                diversifier_index_be BLOB,
                address TEXT NOT NULL,
                transparent_child_index INTEGER,
                cached_transparent_receiver_address TEXT,
                exposed_at_height INTEGER,
                receiver_flags INTEGER NOT NULL,
                transparent_receiver_next_check_time INTEGER,
                imported_transparent_receiver_pubkey BLOB,
                imported_transparent_receiver_script BLOB,
                UNIQUE (account_id, key_scope, diversifier_index_be),
                UNIQUE (imported_transparent_receiver_pubkey),
                UNIQUE (imported_transparent_receiver_script),
                CONSTRAINT ck_addr_transparent_index_consistency CHECK (
                    (transparent_child_index IS NULL OR diversifier_index_be < x'0000000F00000000000000')
                    AND (
                        (
                            cached_transparent_receiver_address IS NULL
                            AND transparent_child_index IS NULL
                            AND imported_transparent_receiver_pubkey IS NULL
                            AND imported_transparent_receiver_script IS NULL
                        )
                        OR (
                            cached_transparent_receiver_address IS NOT NULL
                            AND (
                                (transparent_child_index IS NULL) == (
                                    key_scope = -1 AND (
                                        imported_transparent_receiver_pubkey IS NOT NULL
                                        OR imported_transparent_receiver_script IS NOT NULL
                                    )
                                )
                            )
                        )
                    )
                ),
                CONSTRAINT ck_addr_foreign_or_diversified CHECK (
                    (diversifier_index_be IS NULL) == (key_scope = -1)
                )
            );

            INSERT INTO addresses_new (
                id, account_id, key_scope, diversifier_index_be, address,
                transparent_child_index, cached_transparent_receiver_address,
                exposed_at_height, receiver_flags, transparent_receiver_next_check_time,
                imported_transparent_receiver_pubkey
            )
            SELECT
                id, account_id, key_scope, diversifier_index_be, address,
                transparent_child_index, cached_transparent_receiver_address,
                exposed_at_height, receiver_flags, transparent_receiver_next_check_time,
                imported_transparent_receiver_pubkey
            FROM addresses;

            PRAGMA legacy_alter_table = ON;

            DROP TABLE addresses;
            ALTER TABLE addresses_new RENAME TO addresses;

            PRAGMA legacy_alter_table = OFF;

            -- Recreate the existing indices
            CREATE INDEX idx_addresses_accounts ON addresses (
                account_id ASC
            );
            CREATE INDEX idx_addresses_indices ON addresses (
                diversifier_index_be ASC
            );
            CREATE INDEX idx_addresses_pubkeys ON addresses (
                imported_transparent_receiver_pubkey ASC
            );
            CREATE INDEX idx_addresses_t_indices ON addresses (
                transparent_child_index ASC
            );
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
    use rusqlite::named_params;
    use secrecy::Secret;
    use tempfile::NamedTempFile;
    use zcash_keys::keys::UnifiedSpendingKey;
    use zcash_protocol::consensus::Network;

    use crate::{
        WalletDb,
        testing::db::{test_clock, test_rng},
        wallet::init::{WalletMigrator, migrations::tests::test_migrate},
    };

    use super::{DEPENDENCIES, MIGRATION_ID};

    #[test]
    fn migrate() {
        test_migrate(&[MIGRATION_ID]);
    }

    #[test]
    fn migrate_preserves_data() {
        let network = Network::TestNetwork;
        let data_file = NamedTempFile::new().unwrap();
        let mut db_data =
            WalletDb::for_path(data_file.path(), network, test_clock(), test_rng()).unwrap();

        let seed_bytes = vec![0xab; 32];

        // Migrate to database state just prior to this migration.
        WalletMigrator::new()
            .with_seed(Secret::new(seed_bytes.clone()))
            .ignore_seed_relevance()
            .init_or_migrate_to(&mut db_data, DEPENDENCIES)
            .unwrap();

        // Insert a test account with a valid UFVK so post-migration checks pass.
        let usk = UnifiedSpendingKey::from_seed(&network, &seed_bytes[..], zip32::AccountId::ZERO)
            .unwrap();
        let ufvk = usk.to_unified_full_viewing_key();
        let ufvk_str = ufvk.encode(&network);
        let uivk_str = ufvk.to_unified_incoming_viewing_key().encode(&network);

        db_data
            .conn
            .execute(
                "INSERT INTO accounts (uuid, account_kind, hd_seed_fingerprint,
                 hd_account_index, ufvk, uivk, has_spend_key, birthday_height)
                 VALUES (X'0000000000000000000000000000AAAA', 0, X'00000000000000000000000000000000000000000000000000000000000000AB',
                 0, :ufvk, :uivk, 1, 1)",
                named_params![":ufvk": ufvk_str, ":uivk": uivk_str],
            )
            .unwrap();

        let account_id: i64 = db_data
            .conn
            .query_row(
                "SELECT id FROM accounts WHERE uuid = X'0000000000000000000000000000AAAA'",
                [],
                |row| row.get(0),
            )
            .unwrap();

        // Insert three address types that exist in production databases.

        // 1. Derived transparent address (most common row type)
        db_data
            .conn
            .execute(
                "INSERT INTO addresses (account_id, key_scope, diversifier_index_be, address,
                 transparent_child_index, cached_transparent_receiver_address, receiver_flags)
                 VALUES (?1, 0, X'00000000000000000000000000', 'addr_derived', 0, 't_derived', 5)",
                [account_id],
            )
            .unwrap();

        // 2. Shielded-only address (no transparent receiver — all transparent fields NULL)
        db_data
            .conn
            .execute(
                "INSERT INTO addresses (account_id, key_scope, diversifier_index_be, address,
                 receiver_flags)
                 VALUES (?1, 0, X'00000000000000000100000000', 'addr_shielded', 4)",
                [account_id],
            )
            .unwrap();

        // 3. Standalone P2PKH address
        db_data
            .conn
            .execute(
                "INSERT INTO addresses (account_id, key_scope, address,
                 cached_transparent_receiver_address, receiver_flags,
                 imported_transparent_receiver_pubkey)
                 VALUES (?1, -1, 'ttest_addr', 'ttest_addr', 1, X'0000000000000000000000000000000000000000000000000000000000000001')",
                [account_id],
            )
            .unwrap();

        // Run the standalone_p2sh migration.
        WalletMigrator::new()
            .with_seed(Secret::new(seed_bytes))
            .ignore_seed_relevance()
            .init_or_migrate_to(&mut db_data, &[MIGRATION_ID])
            .unwrap();

        // 1. Verify all 3 rows survived the migration.
        let count: i64 = db_data
            .conn
            .query_row(
                "SELECT COUNT(*) FROM addresses WHERE account_id = ?1",
                [account_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 3);

        // Verify each row has imported_transparent_receiver_script IS NULL.
        let rows: Vec<(String, Option<Vec<u8>>)> = {
            let mut stmt = db_data
                .conn
                .prepare(
                    "SELECT address, imported_transparent_receiver_script FROM addresses
                     WHERE account_id = ?1 ORDER BY address",
                )
                .unwrap();
            stmt.query_map([account_id], |row| Ok((row.get(0)?, row.get(1)?)))
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap()
        };
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].0, "addr_derived");
        assert!(rows[0].1.is_none());
        assert_eq!(rows[1].0, "addr_shielded");
        assert!(rows[1].1.is_none());
        assert_eq!(rows[2].0, "ttest_addr");
        assert!(rows[2].1.is_none());

        // 2. Verify P2SH insert succeeds with the new constraint.
        db_data
            .conn
            .execute(
                "INSERT INTO addresses (account_id, key_scope, address,
                 cached_transparent_receiver_address, receiver_flags, imported_transparent_receiver_script)
                 VALUES (?1, -1, 't_p2sh', 't_p2sh', 2, X'0102030405')",
                [account_id],
            )
            .unwrap();

        // 3. Verify invalid P2SH is rejected (imported_transparent_receiver_script NOT NULL but
        //    cached_transparent_receiver_address IS NULL).
        let result = db_data.conn.execute(
            "INSERT INTO addresses (account_id, key_scope, address,
             receiver_flags, imported_transparent_receiver_script)
             VALUES (?1, -1, 't_p2sh_bad', 2, X'AABBCCDD')",
            [account_id],
        );
        assert!(result.is_err());

        // 4. Verify non-foreign address with imported_transparent_receiver_script is rejected.
        let result = db_data.conn.execute(
            "INSERT INTO addresses (account_id, key_scope, diversifier_index_be, address,
             cached_transparent_receiver_address, receiver_flags, imported_transparent_receiver_script)
             VALUES (?1, 0, X'00000000000000000200000000', 'bad_non_foreign_p2sh', 'bad_non_foreign_p2sh', 2, X'AABBCCDD')",
            [account_id],
        );
        assert!(result.is_err());
    }
}
