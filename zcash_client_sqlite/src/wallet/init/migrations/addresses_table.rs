use std::collections::HashSet;

use rusqlite::{named_params, Transaction};
use schemer;
use schemer_rusqlite::RusqliteMigration;
use uuid::Uuid;
use zcash_client_backend::{address::RecipientAddress, keys::UnifiedFullViewingKey};
use zcash_primitives::{consensus, zip32::AccountId};

use crate::wallet::{init::WalletMigrationError, insert_address};

#[cfg(feature = "transparent-inputs")]
use zcash_primitives::legacy::keys::IncomingViewingKey;

use super::ufvk_support;

/// The migration that removed the address columns from the `accounts` table, and created
/// the `accounts` table.
///
/// d956978c-9c87-4d6e-815d-fb8f088d094c
pub(super) const MIGRATION_ID: Uuid = Uuid::from_fields(
    0xd956978c,
    0x9c87,
    0x4d6e,
    b"\x81\x5d\xfb\x8f\x08\x8d\x09\x4c",
);

pub(crate) struct Migration<P: consensus::Parameters> {
    pub(crate) params: P,
}

impl<P: consensus::Parameters> schemer::Migration for Migration<P> {
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }

    fn dependencies(&self) -> HashSet<Uuid> {
        [ufvk_support::MIGRATION_ID].into_iter().collect()
    }

    fn description(&self) -> &'static str {
        "Adds the addresses table for tracking diversified UAs"
    }
}

impl<P: consensus::Parameters> RusqliteMigration for Migration<P> {
    type Error = WalletMigrationError;

    fn up(&self, transaction: &Transaction) -> Result<(), WalletMigrationError> {
        transaction.execute_batch(
            "CREATE TABLE addresses (
                account INTEGER NOT NULL,
                diversifier_index_be BLOB NOT NULL,
                address TEXT NOT NULL,
                cached_transparent_receiver_address TEXT,
                FOREIGN KEY (account) REFERENCES accounts(account),
                CONSTRAINT diversification UNIQUE (account, diversifier_index_be)
            );
            CREATE TABLE accounts_new (
                account INTEGER PRIMARY KEY,
                ufvk TEXT NOT NULL
            );",
        )?;

        let mut stmt_fetch_accounts = transaction
            .prepare("SELECT account, ufvk, address, transparent_address FROM accounts")?;

        let mut rows = stmt_fetch_accounts.query([])?;
        while let Some(row) = rows.next()? {
            let account: u32 = row.get(0)?;
            let account = AccountId::from(account);

            let ufvk_str: String = row.get(1)?;
            let ufvk = UnifiedFullViewingKey::decode(&self.params, &ufvk_str)
                .map_err(WalletMigrationError::CorruptedData)?;

            // Verify that the address column contains the expected value.
            let address: String = row.get(2)?;
            let decoded = RecipientAddress::decode(&self.params, &address).ok_or_else(|| {
                WalletMigrationError::CorruptedData(format!(
                    "Could not decode {} as a valid Zcash address.",
                    address
                ))
            })?;
            let decoded_address = if let RecipientAddress::Unified(ua) = decoded {
                ua
            } else {
                return Err(WalletMigrationError::CorruptedData(
                    "Address in accounts table was not a Unified Address.".to_string(),
                ));
            };
            let (expected_address, idx) = ufvk.default_address();
            if decoded_address != expected_address {
                return Err(WalletMigrationError::CorruptedData(format!(
                    "Decoded UA {} does not match the UFVK's default address {} at {:?}.",
                    address,
                    RecipientAddress::Unified(expected_address).encode(&self.params),
                    idx,
                )));
            }

            // The transparent_address column might not be filled, depending on how this
            // crate was compiled.
            if let Some(transparent_address) = row.get::<_, Option<String>>(3)? {
                let decoded_transparent =
                    RecipientAddress::decode(&self.params, &transparent_address).ok_or_else(
                        || {
                            WalletMigrationError::CorruptedData(format!(
                                "Could not decode {} as a valid Zcash address.",
                                address
                            ))
                        },
                    )?;
                let decoded_transparent_address = if let RecipientAddress::Transparent(addr) =
                    decoded_transparent
                {
                    addr
                } else {
                    return Err(WalletMigrationError::CorruptedData(
                        "Address in transparent_address column of accounts table was not a transparent address.".to_string(),
                    ));
                };

                // Verify that the transparent_address column contains the expected value,
                // so we can confidently delete the column knowing we can regenerate the
                // values from the stored UFVKs.

                // We can only check if it is the expected transparent address if the
                // transparent-inputs feature flag is enabled.
                #[cfg(feature = "transparent-inputs")]
                {
                    let expected_address = ufvk
                        .transparent()
                        .and_then(|k| k.derive_external_ivk().ok().map(|k| k.default_address().0));
                    if Some(decoded_transparent_address) != expected_address {
                        return Err(WalletMigrationError::CorruptedData(format!(
                            "Decoded transparent address {} is not the default transparent address.",
                            transparent_address,
                        )));
                    }
                }

                // If the transparent_address column is not empty, and we can't check its
                // value, return an error.
                #[cfg(not(feature = "transparent-inputs"))]
                {
                    let _ = decoded_transparent_address;
                    return Err(WalletMigrationError::CorruptedData(
                        "Database needs transparent-inputs feature flag enabled to migrate"
                            .to_string(),
                    ));
                }
            }

            transaction.execute(
                "INSERT INTO accounts_new (account, ufvk)
                 VALUES (:account, :ufvk)",
                named_params![
                    ":account": u32::from(account),
                    ":ufvk": ufvk.encode(&self.params),
                ],
            )?;

            let (address, d_idx) = ufvk.default_address();
            insert_address(transaction, &self.params, account, d_idx, &address)?;
        }

        transaction.execute_batch(
            "DROP TABLE accounts;
            ALTER TABLE accounts_new RENAME TO accounts;",
        )?;

        Ok(())
    }

    fn down(&self, _transaction: &Transaction) -> Result<(), WalletMigrationError> {
        // TODO: something better than just panic?
        panic!("Cannot revert this migration.");
    }
}
