//! This migration adds the `standalone_spendable` column to the `addresses` table, recording
//! whether the application has declared that it holds the secret key material required to spend
//! outputs received at a standalone (`key_scope = -1`) transparent import.

use std::collections::HashSet;

use schemerz_rusqlite::RusqliteMigration;
use uuid::Uuid;

use crate::wallet::init::WalletMigrationError;

use super::standalone_address;

/// This migration adds the `standalone_spendable` column to the `addresses` table.
pub const MIGRATION_ID: Uuid = Uuid::from_u128(0x3f6b8e1a_7d24_4c0b_9a5e_2b1f0c8d7e63);

pub(super) const DEPENDENCIES: &[Uuid] = &[standalone_address::MIGRATION_ID];

pub(super) struct Migration;

impl schemerz::Migration<Uuid> for Migration {
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }

    fn dependencies(&self) -> HashSet<Uuid> {
        DEPENDENCIES.iter().copied().collect()
    }

    fn description(&self) -> &'static str {
        "Adds the standalone_spendable column to the addresses table, recording whether the application holds the key material for a standalone transparent import."
    }
}

impl RusqliteMigration for Migration {
    type Error = WalletMigrationError;

    fn up(&self, transaction: &rusqlite::Transaction) -> Result<(), Self::Error> {
        // Recreate the addresses table with the new column. The wallet database cannot know
        // whether the application holds the secret keys corresponding to imported key material,
        // so every existing standalone import is marked watch-only (`standalone_spendable = 0`);
        // the application must reclassify the imports for which it holds the keys via
        // `WalletWrite::set_standalone_transparent_spendability`.
        //
        // The new constraint permits the spendable marker only on standalone rows that carry
        // key material: a derived address never needs the marker (its spendability is that of
        // the account), and an address-only import has nothing to spend with.
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
                standalone_spendable INTEGER NOT NULL DEFAULT 0,
                UNIQUE (account_id, key_scope, diversifier_index_be),
                UNIQUE (imported_transparent_receiver_pubkey),
                UNIQUE (imported_transparent_receiver_script),
                CONSTRAINT ck_addr_transparent_index_consistency CHECK (
                    (transparent_child_index IS NULL OR diversifier_index_be < x'0000000F00000000000000')
                    AND (
                        -- no transparent receiver: all transparent columns are absent
                        (
                            cached_transparent_receiver_address IS NULL
                            AND transparent_child_index IS NULL
                            AND imported_transparent_receiver_pubkey IS NULL
                            AND imported_transparent_receiver_script IS NULL
                        )
                        OR (
                            cached_transparent_receiver_address IS NOT NULL
                            -- a transparent receiver has a child index iff it was derived
                            AND ((transparent_child_index IS NULL) == (key_scope = -1))
                            -- at most one kind of imported key material
                            AND NOT (
                                imported_transparent_receiver_pubkey IS NOT NULL
                                AND imported_transparent_receiver_script IS NOT NULL
                            )
                            -- imported key material appears only on imported (key_scope = -1) rows
                            AND (
                                key_scope = -1 OR (
                                    imported_transparent_receiver_pubkey IS NULL
                                    AND imported_transparent_receiver_script IS NULL
                                )
                            )
                        )
                    )
                ),
                CONSTRAINT ck_addr_foreign_or_diversified CHECK (
                    (diversifier_index_be IS NULL) == (key_scope = -1)
                ),
                -- the spendable marker may only be set on imported rows that carry key material
                CONSTRAINT ck_addr_standalone_spendable CHECK (
                    standalone_spendable = 0 OR (
                        key_scope = -1 AND (
                            imported_transparent_receiver_pubkey IS NOT NULL
                            OR imported_transparent_receiver_script IS NOT NULL
                        )
                    )
                )
            );

            INSERT INTO addresses_new (
                id, account_id, key_scope, diversifier_index_be, address,
                transparent_child_index, cached_transparent_receiver_address,
                exposed_at_height, receiver_flags, transparent_receiver_next_check_time,
                imported_transparent_receiver_pubkey, imported_transparent_receiver_script
            )
            SELECT
                id, account_id, key_scope, diversifier_index_be, address,
                transparent_child_index, cached_transparent_receiver_address,
                exposed_at_height, receiver_flags, transparent_receiver_next_check_time,
                imported_transparent_receiver_pubkey, imported_transparent_receiver_script
            FROM addresses;

            PRAGMA legacy_alter_table = ON;

            DROP TABLE addresses;
            ALTER TABLE addresses_new RENAME TO addresses;

            PRAGMA legacy_alter_table = OFF;

            -- Recreate the existing indices
            CREATE INDEX idx_addresses_accounts ON addresses (
                account_id ASC
            );
            CREATE UNIQUE INDEX idx_addresses_cached_transparent_receiver_address ON addresses (
                cached_transparent_receiver_address ASC
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
    fn migrate_marks_existing_imports_watch_only() {
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

        // Insert the address row shapes that exist in production databases.

        // 1. Derived transparent address
        db_data
            .conn
            .execute(
                "INSERT INTO addresses (account_id, key_scope, diversifier_index_be, address,
                 transparent_child_index, cached_transparent_receiver_address, receiver_flags)
                 VALUES (?1, 0, X'00000000000000000000000000', 'addr_derived', 0, 't_derived', 5)",
                [account_id],
            )
            .unwrap();

        // 2. Standalone P2PKH import with key material
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

        // 3. Standalone P2SH import with key material
        db_data
            .conn
            .execute(
                "INSERT INTO addresses (account_id, key_scope, address,
                 cached_transparent_receiver_address, receiver_flags,
                 imported_transparent_receiver_script)
                 VALUES (?1, -1, 't_p2sh', 't_p2sh', 2, X'0102030405')",
                [account_id],
            )
            .unwrap();

        // 4. Address-only standalone import
        db_data
            .conn
            .execute(
                "INSERT INTO addresses (account_id, key_scope, address,
                 cached_transparent_receiver_address, receiver_flags)
                 VALUES (?1, -1, 't_addr_only', 't_addr_only', 1)",
                [account_id],
            )
            .unwrap();

        // Run the standalone_spendability migration.
        WalletMigrator::new()
            .with_seed(Secret::new(seed_bytes))
            .ignore_seed_relevance()
            .init_or_migrate_to(&mut db_data, &[MIGRATION_ID])
            .unwrap();

        // Verify all rows survived the migration, and that every one of them is marked
        // watch-only: the migration cannot know which keys the application holds.
        let (count, spendable_count): (i64, i64) = db_data
            .conn
            .query_row(
                "SELECT COUNT(*), SUM(standalone_spendable) FROM addresses WHERE account_id = ?1",
                [account_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(count, 4);
        assert_eq!(spendable_count, 0);

        // Standalone imports with key material may be marked spendable.
        for addr in ["ttest_addr", "t_p2sh"] {
            let updated = db_data
                .conn
                .execute(
                    "UPDATE addresses SET standalone_spendable = 1
                     WHERE cached_transparent_receiver_address = :addr",
                    named_params![":addr": addr],
                )
                .unwrap();
            assert_eq!(updated, 1);
        }

        // The constraint rejects the marker on derived rows and address-only imports.
        for addr in ["t_derived", "t_addr_only"] {
            let result = db_data.conn.execute(
                "UPDATE addresses SET standalone_spendable = 1
                 WHERE cached_transparent_receiver_address = :addr",
                named_params![":addr": addr],
            );
            assert!(result.is_err());
        }

        // The constraint rejects a spendable derived row on insert as well.
        let result = db_data.conn.execute(
            "INSERT INTO addresses (account_id, key_scope, diversifier_index_be, address,
             transparent_child_index, cached_transparent_receiver_address, receiver_flags,
             standalone_spendable)
             VALUES (?1, 0, X'00000000000000000100000000', 'bad_derived', 1, 'bad_derived', 1, 1)",
            [account_id],
        );
        assert!(result.is_err());
    }
}
