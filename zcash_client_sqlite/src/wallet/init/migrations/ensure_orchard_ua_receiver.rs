//! This migration ensures that an Orchard receiver exists in the wallet's default Unified address.
use std::collections::HashSet;

use rusqlite::named_params;
use schemer_rusqlite::RusqliteMigration;
use uuid::Uuid;

use zcash_client_backend::keys::{
    UnifiedAddressRequest, UnifiedFullViewingKey, UnifiedIncomingViewingKey,
};
use zcash_primitives::consensus;

use super::orchard_received_notes;
use crate::{wallet::init::WalletMigrationError, UA_ORCHARD, UA_TRANSPARENT};

pub(super) const MIGRATION_ID: Uuid = Uuid::from_u128(0x604349c7_5ce5_4768_bea6_12d106ccda93);

pub(super) struct Migration<P> {
    pub(super) params: P,
}

impl<P> schemer::Migration for Migration<P> {
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }

    fn dependencies(&self) -> HashSet<Uuid> {
        [orchard_received_notes::MIGRATION_ID].into_iter().collect()
    }

    fn description(&self) -> &'static str {
        "Ensures that the wallet's default address contains an Orchard receiver."
    }
}

impl<P: consensus::Parameters> RusqliteMigration for Migration<P> {
    type Error = WalletMigrationError;

    fn up(&self, transaction: &rusqlite::Transaction<'_>) -> Result<(), Self::Error> {
        let mut get_accounts = transaction.prepare(
            r#"
            SELECT id, ufvk, uivk
            FROM accounts
            "#,
        )?;

        let mut update_address = transaction.prepare(
            r#"UPDATE "addresses"
               SET address = :address
               WHERE account_id = :account_id
               AND diversifier_index_be = :j
            "#,
        )?;

        let mut accounts = get_accounts.query([])?;
        while let Some(row) = accounts.next()? {
            let account_id = row.get::<_, u32>("id")?;
            let ufvk_str: Option<String> = row.get("ufvk")?;
            let uivk = if let Some(ufvk_str) = ufvk_str {
                UnifiedFullViewingKey::decode(&self.params, &ufvk_str[..])
                    .map_err(|_| {
                        WalletMigrationError::CorruptedData("Unable to decode UFVK".to_string())
                    })?
                    .to_unified_incoming_viewing_key()
            } else {
                let uivk_str: String = row.get("uivk")?;
                UnifiedIncomingViewingKey::decode(&self.params, &uivk_str[..]).map_err(|_| {
                    WalletMigrationError::CorruptedData("Unable to decode UIVK".to_string())
                })?
            };

            let (default_addr, diversifier_index) = uivk.default_address(
                UnifiedAddressRequest::unsafe_new(UA_ORCHARD, true, UA_TRANSPARENT),
            )?;

            let mut di_be = *diversifier_index.as_bytes();
            di_be.reverse();
            update_address.execute(named_params![
                ":address": default_addr.encode(&self.params),
                ":account_id": account_id,
                ":j": &di_be[..],
            ])?;
        }

        Ok(())
    }

    fn down(&self, _transaction: &rusqlite::Transaction<'_>) -> Result<(), Self::Error> {
        Err(WalletMigrationError::CannotRevert(MIGRATION_ID))
    }
}

#[cfg(test)]
mod tests {
    use rusqlite::named_params;
    use secrecy::SecretVec;
    use tempfile::NamedTempFile;

    use zcash_client_backend::keys::{UnifiedAddressRequest, UnifiedSpendingKey};
    use zcash_keys::address::Address;
    use zcash_primitives::consensus::Network;

    use crate::{
        wallet::init::{init_wallet_db, init_wallet_db_internal, migrations::addresses_table},
        WalletDb, UA_ORCHARD, UA_TRANSPARENT,
    };

    #[test]
    fn init_migrate_add_orchard_receiver() {
        let data_file = NamedTempFile::new().unwrap();
        let mut db_data = WalletDb::for_path(data_file.path(), Network::TestNetwork).unwrap();

        let seed = vec![0x10; 32];
        let account_id = 0u32;
        let ufvk = UnifiedSpendingKey::from_seed(
            &db_data.params,
            &seed,
            zip32::AccountId::try_from(account_id).unwrap(),
        )
        .unwrap()
        .to_unified_full_viewing_key();

        assert_matches!(
            init_wallet_db_internal(
                &mut db_data,
                Some(SecretVec::new(seed.clone())),
                &[addresses_table::MIGRATION_ID],
                false
            ),
            Ok(_)
        );

        // Manually create an entry in the addresses table for an address that lacks an Orchard
        // receiver.
        db_data
            .conn
            .execute(
                "INSERT INTO accounts (account, ufvk) VALUES (:account_id, :ufvk)",
                named_params![
                    ":account_id": account_id,
                    ":ufvk": ufvk.encode(&db_data.params)
                ],
            )
            .unwrap();

        let (addr, diversifier_index) = ufvk
            .default_address(UnifiedAddressRequest::unsafe_new(
                false,
                true,
                UA_TRANSPARENT,
            ))
            .unwrap();
        let mut di_be = *diversifier_index.as_bytes();
        di_be.reverse();

        db_data
            .conn
            .execute(
                "INSERT INTO addresses (account, diversifier_index_be, address) 
                 VALUES (:account_id, :j, :address) ",
                named_params![
                    ":account_id": account_id,
                    ":j": &di_be[..],
                    ":address": addr.encode(&db_data.params)
                ],
            )
            .unwrap();

        match db_data
            .conn
            .query_row("SELECT address FROM addresses", [], |row| {
                Ok(Address::decode(&db_data.params, &row.get::<_, String>(0)?).unwrap())
            }) {
            Ok(Address::Unified(ua)) => {
                assert!(ua.orchard().is_none());
                assert!(ua.sapling().is_some());
                assert_eq!(ua.transparent().is_some(), UA_TRANSPARENT);
            }
            other => panic!("Unexpected result from address decoding: {:?}", other),
        }

        assert_matches!(
            init_wallet_db(&mut db_data, Some(SecretVec::new(seed))),
            Ok(_)
        );

        match db_data
            .conn
            .query_row("SELECT address FROM addresses", [], |row| {
                Ok(Address::decode(&db_data.params, &row.get::<_, String>(0)?).unwrap())
            }) {
            Ok(Address::Unified(ua)) => {
                assert_eq!(ua.orchard().is_some(), UA_ORCHARD);
                assert!(ua.sapling().is_some());
                assert_eq!(ua.transparent().is_some(), UA_TRANSPARENT);
            }
            other => panic!("Unexpected result from address decoding: {:?}", other),
        }
    }
}
