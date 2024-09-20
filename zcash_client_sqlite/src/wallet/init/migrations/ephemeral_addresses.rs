//! The migration that records ephemeral addresses for each account.
use std::collections::HashSet;

use rusqlite;
use schemer;
use schemer_rusqlite::RusqliteMigration;
use uuid::Uuid;
use zcash_protocol::consensus;

use crate::wallet::init::WalletMigrationError;

#[cfg(feature = "transparent-inputs")]
use crate::wallet::{self, init, transparent::ephemeral};

use super::utxos_to_txos;

pub(super) const MIGRATION_ID: Uuid = Uuid::from_u128(0x0e1d4274_1f8e_44e2_909d_689a4bc2967b);

const DEPENDENCIES: &[Uuid] = &[utxos_to_txos::MIGRATION_ID];

#[allow(dead_code)]
pub(super) struct Migration<P> {
    pub(super) params: P,
}

impl<P> schemer::Migration for Migration<P> {
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }

    fn dependencies(&self) -> HashSet<Uuid> {
        DEPENDENCIES.iter().copied().collect()
    }

    fn description(&self) -> &'static str {
        "Record ephemeral addresses for each account."
    }
}

impl<P: consensus::Parameters> RusqliteMigration for Migration<P> {
    type Error = WalletMigrationError;

    fn up(&self, transaction: &rusqlite::Transaction) -> Result<(), WalletMigrationError> {
        transaction.execute_batch(
            "CREATE TABLE ephemeral_addresses (
                account_id INTEGER NOT NULL,
                address_index INTEGER NOT NULL,
                -- nullability of this column is controlled by the index_range_and_address_nullity check
                address TEXT,
                used_in_tx INTEGER,
                seen_in_tx INTEGER,
                FOREIGN KEY (account_id) REFERENCES accounts(id),
                FOREIGN KEY (used_in_tx) REFERENCES transactions(id_tx),
                FOREIGN KEY (seen_in_tx) REFERENCES transactions(id_tx),
                PRIMARY KEY (account_id, address_index),
                CONSTRAINT ephemeral_addr_uniq UNIQUE (address),
                CONSTRAINT used_implies_seen CHECK (
                    used_in_tx IS NULL OR seen_in_tx IS NOT NULL
                ),
                CONSTRAINT index_range_and_address_nullity CHECK (
                    (address_index BETWEEN 0 AND 0x7FFFFFFF AND address IS NOT NULL) OR
                    (address_index BETWEEN 0x80000000 AND 0x7FFFFFFF + 20 AND address IS NULL AND used_in_tx IS NULL AND seen_in_tx IS NULL)
                )
            ) WITHOUT ROWID;"
        )?;

        // Make sure that at least `GAP_LIMIT` ephemeral transparent addresses are
        // stored in each account.
        #[cfg(feature = "transparent-inputs")]
        for account_id in wallet::get_account_ids(transaction)? {
            ephemeral::init_account(transaction, &self.params, account_id)
                .map_err(init::sqlite_client_error_to_wallet_migration_error)?;
        }
        Ok(())
    }

    fn down(&self, _transaction: &rusqlite::Transaction) -> Result<(), WalletMigrationError> {
        Err(WalletMigrationError::CannotRevert(MIGRATION_ID))
    }
}

#[cfg(test)]
mod tests {
    use crate::wallet::init::migrations::tests::test_migrate;

    #[cfg(feature = "transparent-inputs")]
    use {
        rusqlite::{named_params, Connection},
        secrecy::{ExposeSecret, Secret, SecretVec},
        tempfile::NamedTempFile,
        zcash_client_backend::{
            data_api::{AccountBirthday, AccountSource},
            wallet::TransparentAddressMetadata,
        },
        zcash_keys::keys::UnifiedSpendingKey,
        zcash_primitives::{block::BlockHash, legacy::keys::NonHardenedChildIndex},
        zcash_protocol::consensus::Network,
        zip32::{fingerprint::SeedFingerprint, AccountId as Zip32AccountId},
    };

    #[cfg(feature = "transparent-inputs")]
    use {
        crate::{
            error::SqliteClientError,
            wallet::{
                self, account_kind_code, init::init_wallet_db_internal, transparent::ephemeral,
            },
            AccountId, WalletDb,
        },
        zcash_client_backend::data_api::GAP_LIMIT,
    };

    /// This is a minimized copy of [`wallet::create_account`] as of the time of the
    /// creation of this migration.
    #[cfg(feature = "transparent-inputs")]
    fn create_account(
        wdb: &mut WalletDb<Connection, Network>,
        seed: &SecretVec<u8>,
        birthday: &AccountBirthday,
    ) -> Result<(AccountId, UnifiedSpendingKey), SqliteClientError> {
        wdb.transactionally(|wdb| {
            let seed_fingerprint =
                SeedFingerprint::from_seed(seed.expose_secret()).ok_or_else(|| {
                    SqliteClientError::BadAccountData(
                        "Seed must be between 32 and 252 bytes in length.".to_owned(),
                    )
                })?;
            let account_index = wallet::max_zip32_account_index(wdb.conn.0, &seed_fingerprint)?
                .map(|a| a.next().ok_or(SqliteClientError::AccountIdOutOfRange))
                .transpose()?
                .unwrap_or(zip32::AccountId::ZERO);

            let usk =
                UnifiedSpendingKey::from_seed(&wdb.params, seed.expose_secret(), account_index)
                    .map_err(|_| SqliteClientError::KeyDerivationError(account_index))?;
            let ufvk = usk.to_unified_full_viewing_key();

            #[cfg(feature = "orchard")]
            let orchard_item = ufvk.orchard().map(|k| k.to_bytes());
            #[cfg(not(feature = "orchard"))]
            let orchard_item: Option<Vec<u8>> = None;

            let sapling_item = ufvk.sapling().map(|k| k.to_bytes());

            #[cfg(feature = "transparent-inputs")]
            let transparent_item = ufvk.transparent().map(|k| k.serialize());
            #[cfg(not(feature = "transparent-inputs"))]
            let transparent_item: Option<Vec<u8>> = None;

            let birthday_sapling_tree_size = Some(birthday.sapling_frontier().tree_size());
            #[cfg(feature = "orchard")]
            let birthday_orchard_tree_size = Some(birthday.orchard_frontier().tree_size());
            #[cfg(not(feature = "orchard"))]
            let birthday_orchard_tree_size: Option<u64> = None;

            let account_id: AccountId = wdb.conn.0.query_row(
                r#"
                INSERT INTO accounts (
                    account_kind, hd_seed_fingerprint, hd_account_index,
                    ufvk, uivk,
                    orchard_fvk_item_cache, sapling_fvk_item_cache, p2pkh_fvk_item_cache,
                    birthday_height, birthday_sapling_tree_size, birthday_orchard_tree_size,
                    recover_until_height
                )
                VALUES (
                    :account_kind, :hd_seed_fingerprint, :hd_account_index,
                    :ufvk, :uivk,
                    :orchard_fvk_item_cache, :sapling_fvk_item_cache, :p2pkh_fvk_item_cache,
                    :birthday_height, :birthday_sapling_tree_size, :birthday_orchard_tree_size,
                    :recover_until_height
                )
                RETURNING id;
                "#,
                named_params![
                    ":account_kind": 0, // 0 == Derived
                    ":hd_seed_fingerprint": seed_fingerprint.to_bytes(),
                    ":hd_account_index": u32::from(account_index),
                    ":ufvk": ufvk.encode(&wdb.params),
                    ":uivk": ufvk.to_unified_incoming_viewing_key().encode(&wdb.params),
                    ":orchard_fvk_item_cache": orchard_item,
                    ":sapling_fvk_item_cache": sapling_item,
                    ":p2pkh_fvk_item_cache": transparent_item,
                    ":birthday_height": u32::from(birthday.height()),
                    ":birthday_sapling_tree_size": birthday_sapling_tree_size,
                    ":birthday_orchard_tree_size": birthday_orchard_tree_size,
                    ":recover_until_height": birthday.recover_until().map(u32::from)
                ],
                |row| Ok(AccountId(row.get(0)?)),
            )?;

            // Initialize the `ephemeral_addresses` table.
            #[cfg(feature = "transparent-inputs")]
            wallet::transparent::ephemeral::init_account(wdb.conn.0, &wdb.params, account_id)?;

            Ok((account_id, usk))
        })
    }

    #[test]
    fn migrate() {
        test_migrate(&[super::MIGRATION_ID]);
    }

    #[test]
    #[cfg(feature = "transparent-inputs")]
    fn initialize_table() {
        let network = Network::TestNetwork;
        let data_file = NamedTempFile::new().unwrap();
        let mut db_data = WalletDb::for_path(data_file.path(), network).unwrap();

        let seed0 = vec![0x00; 32];
        init_wallet_db_internal(
            &mut db_data,
            Some(Secret::new(seed0.clone())),
            super::DEPENDENCIES,
            false,
        )
        .unwrap();

        let birthday = AccountBirthday::from_sapling_activation(&network, BlockHash([0; 32]));

        // Simulate creating an account prior to this migration.
        let account0_index = Zip32AccountId::ZERO;
        let account0_seed_fp = [0u8; 32];
        let account0_kind = account_kind_code(AccountSource::Derived {
            seed_fingerprint: SeedFingerprint::from_seed(&account0_seed_fp).unwrap(),
            account_index: account0_index,
        });
        assert_eq!(u32::from(account0_index), 0);
        let account0_id = crate::AccountId(0);

        let usk0 = UnifiedSpendingKey::from_seed(&network, &seed0, account0_index).unwrap();
        let ufvk0 = usk0.to_unified_full_viewing_key();
        let uivk0 = ufvk0.to_unified_incoming_viewing_key();

        db_data
            .conn
            .execute(
                "INSERT INTO accounts (id, account_kind, hd_seed_fingerprint, hd_account_index, ufvk, uivk, birthday_height)
                 VALUES (:id, :account_kind, :hd_seed_fingerprint, :hd_account_index, :ufvk, :uivk, :birthday_height)",
                named_params![
                    ":id": account0_id.0,
                    ":account_kind": account0_kind,
                    ":hd_seed_fingerprint": account0_seed_fp,
                    ":hd_account_index": u32::from(account0_index),
                    ":ufvk": ufvk0.encode(&network),
                    ":uivk": uivk0.encode(&network),
                    ":birthday_height": u32::from(birthday.height()),
                ],
            )
            .unwrap();

        // The `ephemeral_addresses` table is expected not to exist before migration.
        assert_matches!(
            ephemeral::first_unstored_index(&db_data.conn, account0_id),
            Err(SqliteClientError::DbError(_))
        );

        let check = |db: &WalletDb<_, _>, account_id| {
            eprintln!("checking {account_id:?}");
            assert_matches!(ephemeral::first_unstored_index(&db.conn, account_id), Ok(addr_index) if addr_index == GAP_LIMIT);
            assert_matches!(ephemeral::first_unreserved_index(&db.conn, account_id), Ok(addr_index) if addr_index == 0);

            let known_addrs =
                ephemeral::get_known_ephemeral_addresses(&db.conn, &db.params, account_id, None)
                    .unwrap();

            let expected_metadata: Vec<TransparentAddressMetadata> = (0..GAP_LIMIT)
                .map(|i| ephemeral::metadata(NonHardenedChildIndex::from_index(i).unwrap()))
                .collect();
            let actual_metadata: Vec<TransparentAddressMetadata> =
                known_addrs.into_iter().map(|(_, meta)| meta).collect();
            assert_eq!(actual_metadata, expected_metadata);
        };

        // The migration should initialize `ephemeral_addresses`.
        init_wallet_db_internal(
            &mut db_data,
            Some(Secret::new(seed0)),
            &[super::MIGRATION_ID],
            false,
        )
        .unwrap();
        check(&db_data, account0_id);

        // Creating a new account should initialize `ephemeral_addresses` for that account.
        let seed1 = vec![0x01; 32];
        let (account1_id, _usk) =
            create_account(&mut db_data, &Secret::new(seed1), &birthday).unwrap();
        assert_ne!(account0_id, account1_id);
        check(&db_data, account1_id);
    }
}
