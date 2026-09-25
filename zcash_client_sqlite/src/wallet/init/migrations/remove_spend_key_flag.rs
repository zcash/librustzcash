//! Replaces the `has_spend_key` column of the `accounts` table with a record, on each standalone
//! transparent public key, of whether the application holds its spending key.
//!
//! The wallet no longer records whether the application holds spending keys for an account.
//! Callers state their spend authority per query instead. Each standalone public key records
//! the spending key custody that its account's `has_spend_key` flag implied.
use std::collections::HashSet;

use schemerz_rusqlite::RusqliteMigration;
use uuid::Uuid;

use crate::wallet::{
    encoding::{SPENDING_KEY_CUSTODY_HELD, SPENDING_KEY_CUSTODY_WATCH_ONLY},
    init::WalletMigrationError,
};

use super::{ivk_item_cache, standalone_address, v_address_uses_ironwood};

/// The migration that replaces the `has_spend_key` column of the `accounts` table with the
/// spending key custody of each standalone public key.
pub const MIGRATION_ID: Uuid = Uuid::from_u128(0xded77015_af01_474e_b6e8_77baf12513c6);

/// The migrations that last touched the `accounts` and `addresses` tables.
pub(super) const DEPENDENCIES: &[Uuid] = &[
    ivk_item_cache::MIGRATION_ID,
    standalone_address::MIGRATION_ID,
    v_address_uses_ironwood::MIGRATION_ID,
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
        "Replaces the has_spend_key column of the accounts table with the spending key custody of each standalone public key."
    }
}

impl RusqliteMigration for Migration {
    type Error = WalletMigrationError;

    fn up(&self, transaction: &rusqlite::Transaction) -> Result<(), Self::Error> {
        transaction.execute_batch(&format!(
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
                imported_transparent_receiver_pubkey_custody INTEGER,
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
                CONSTRAINT ck_addr_pubkey_custody CHECK (
                    (imported_transparent_receiver_pubkey_custody IS NULL)
                        == (imported_transparent_receiver_pubkey IS NULL)
                    AND (
                        imported_transparent_receiver_pubkey_custody IS NULL
                        OR imported_transparent_receiver_pubkey_custody IN (0, 1)
                    )
                )
            );
            INSERT INTO addresses_new (
                id, account_id, key_scope, diversifier_index_be, address,
                transparent_child_index, cached_transparent_receiver_address,
                exposed_at_height, receiver_flags, transparent_receiver_next_check_time,
                imported_transparent_receiver_pubkey, imported_transparent_receiver_script,
                imported_transparent_receiver_pubkey_custody
            )
            SELECT
                addresses.id, addresses.account_id, addresses.key_scope,
                addresses.diversifier_index_be, addresses.address,
                addresses.transparent_child_index, addresses.cached_transparent_receiver_address,
                addresses.exposed_at_height, addresses.receiver_flags,
                addresses.transparent_receiver_next_check_time,
                addresses.imported_transparent_receiver_pubkey,
                addresses.imported_transparent_receiver_script,
                CASE
                    WHEN addresses.imported_transparent_receiver_pubkey IS NULL THEN NULL
                    WHEN accounts.has_spend_key THEN {SPENDING_KEY_CUSTODY_HELD}
                    ELSE {SPENDING_KEY_CUSTODY_WATCH_ONLY}
                END
            FROM addresses
            JOIN accounts ON accounts.id = addresses.account_id;

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

            ALTER TABLE accounts DROP COLUMN has_spend_key;
            "#
        ))?;
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
        wallet::{
            encoding::{SPENDING_KEY_CUSTODY_HELD, SPENDING_KEY_CUSTODY_WATCH_ONLY},
            init::{WalletMigrator, migrations::tests::test_migrate},
        },
    };

    use super::{DEPENDENCIES, MIGRATION_ID};

    #[test]
    fn migrate() {
        test_migrate(&[MIGRATION_ID]);
    }

    #[test]
    fn standalone_pubkeys_take_custody_from_their_account() {
        let network = Network::TestNetwork;
        let data_file = NamedTempFile::new().unwrap();
        let mut db_data =
            WalletDb::for_path(data_file.path(), network, test_clock(), test_rng()).unwrap();
        let seed_bytes = vec![0xab; 32];

        WalletMigrator::new()
            .with_seed(Secret::new(seed_bytes.clone()))
            .ignore_seed_relevance()
            .init_or_migrate_to(&mut db_data, DEPENDENCIES)
            .unwrap();

        // One account for which the application held spending keys, and one for which it held
        // only viewing keys, each with a standalone public key.
        for (account_index, has_spend_key, pubkey_byte) in [(0u32, true, 1u8), (1, false, 2)] {
            let usk = UnifiedSpendingKey::from_seed(
                &network,
                &seed_bytes[..],
                zip32::AccountId::try_from(account_index).unwrap(),
            )
            .unwrap();
            let ufvk = usk.to_unified_full_viewing_key();
            let account_id: i64 = db_data
                .conn
                .query_row(
                    "INSERT INTO accounts (uuid, account_kind, ufvk, uivk, has_spend_key,
                     birthday_height)
                     VALUES (:uuid, 1, :ufvk, :uivk, :has_spend_key, 1)
                     RETURNING id",
                    named_params![
                        ":uuid": uuid::Uuid::from_u128(u128::from(pubkey_byte)).as_bytes().to_vec(),
                        ":ufvk": ufvk.encode(&network),
                        ":uivk": ufvk.to_unified_incoming_viewing_key().encode(&network),
                        ":has_spend_key": has_spend_key,
                    ],
                    |row| row.get(0),
                )
                .unwrap();
            let mut pubkey = [0u8; 33];
            pubkey[32] = pubkey_byte;
            db_data
                .conn
                .execute(
                    "INSERT INTO addresses (account_id, key_scope, address,
                     cached_transparent_receiver_address, receiver_flags,
                     imported_transparent_receiver_pubkey)
                     VALUES (:account_id, -1, :address, :address, 1, :pubkey)",
                    named_params![
                        ":account_id": account_id,
                        ":address": format!("t_standalone_{pubkey_byte}"),
                        ":pubkey": pubkey.to_vec(),
                    ],
                )
                .unwrap();
        }

        WalletMigrator::new()
            .with_seed(Secret::new(seed_bytes))
            .ignore_seed_relevance()
            .init_or_migrate_to(&mut db_data, &[MIGRATION_ID])
            .unwrap();

        let custody_of = |address: &str| -> i64 {
            db_data
                .conn
                .query_row(
                    "SELECT imported_transparent_receiver_pubkey_custody FROM addresses
                     WHERE cached_transparent_receiver_address = :address",
                    named_params![":address": address],
                    |row| row.get(0),
                )
                .unwrap()
        };
        assert_eq!(custody_of("t_standalone_1"), SPENDING_KEY_CUSTODY_HELD);
        assert_eq!(custody_of("t_standalone_2"), SPENDING_KEY_CUSTODY_WATCH_ONLY);
    }
}
