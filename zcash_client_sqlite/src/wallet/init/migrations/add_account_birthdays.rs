//! This migration adds a birthday height to each account record.

use std::collections::HashSet;

use schemerz_rusqlite::RusqliteMigration;
use uuid::Uuid;
use zcash_protocol::consensus::{self, NetworkUpgrade};

use crate::wallet::init::WalletMigrationError;

use super::shardtree_support;

pub(super) const MIGRATION_ID: Uuid = Uuid::from_u128(0xeeec0d0d_fee0_4231_8c68_5f3a7c7c2245);

const DEPENDENCIES: &[Uuid] = &[shardtree_support::MIGRATION_ID];

pub(super) struct Migration<P> {
    pub(super) params: P,
}

impl<P> schemerz::Migration<Uuid> for Migration<P> {
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }

    fn dependencies(&self) -> HashSet<Uuid> {
        DEPENDENCIES.iter().copied().collect()
    }

    fn description(&self) -> &'static str {
        "Adds a birthday height for each account."
    }
}

impl<P: consensus::Parameters> RusqliteMigration for Migration<P> {
    type Error = WalletMigrationError;

    fn up(&self, transaction: &rusqlite::Transaction) -> Result<(), Self::Error> {
        transaction.execute_batch(&format!(
            "ALTER TABLE accounts ADD COLUMN birthday_height INTEGER;

            -- set the birthday height to the height of the first block in the blocks table
            UPDATE accounts SET birthday_height = MIN(blocks.height) FROM blocks;
            -- if the blocks table is empty, set the birthday height to Sapling activation - 1
            UPDATE accounts SET birthday_height = {} WHERE birthday_height IS NULL;

            CREATE TABLE accounts_new (
                account INTEGER PRIMARY KEY,
                ufvk TEXT NOT NULL,
                birthday_height INTEGER NOT NULL,
                recover_until_height INTEGER
            );

            INSERT INTO accounts_new (account, ufvk, birthday_height)
            SELECT account, ufvk, birthday_height FROM accounts;

            PRAGMA legacy_alter_table = ON;
            DROP TABLE accounts;
            ALTER TABLE accounts_new RENAME TO accounts;
            PRAGMA legacy_alter_table = OFF;",
            u32::from(
                self.params
                    .activation_height(NetworkUpgrade::Sapling)
                    .unwrap()
            )
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
    use zip32::AccountId;

    use super::{DEPENDENCIES, MIGRATION_ID};
    use crate::{wallet::init::init_wallet_db_internal, WalletDb};

    #[test]
    fn migrate() {
        let data_file = NamedTempFile::new().unwrap();
        let network = Network::TestNetwork;
        let mut db_data = WalletDb::for_path(data_file.path(), network).unwrap();

        let seed_bytes = vec![0xab; 32];
        init_wallet_db_internal(
            &mut db_data,
            Some(Secret::new(seed_bytes.clone())),
            DEPENDENCIES,
            false,
        )
        .unwrap();

        let usk =
            UnifiedSpendingKey::from_seed(&network, &seed_bytes[..], AccountId::ZERO).unwrap();
        let ufvk_str = usk.to_unified_full_viewing_key().encode(&network);

        db_data
            .conn
            .execute(
                "INSERT INTO accounts (account, ufvk) VALUES (0, :ufvk_str)",
                named_params![":ufvk_str": ufvk_str],
            )
            .unwrap();
        db_data
            .conn
            .execute_batch(
                "INSERT INTO addresses (account, diversifier_index_be, address) 
                VALUES (0, X'', 'not_a_real_address');",
            )
            .unwrap();

        init_wallet_db_internal(
            &mut db_data,
            Some(Secret::new(seed_bytes)),
            &[MIGRATION_ID],
            false,
        )
        .unwrap();
    }
}
