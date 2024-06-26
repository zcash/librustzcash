use std::collections::HashSet;

use rusqlite::{named_params, Transaction};
use schemer;
use schemer_rusqlite::RusqliteMigration;
use uuid::Uuid;
use zcash_client_backend::{address::Address, keys::UnifiedFullViewingKey};
use zcash_keys::{address::UnifiedAddress, encoding::AddressCodec, keys::UnifiedAddressRequest};
use zcash_primitives::consensus;
use zip32::{AccountId, DiversifierIndex};

use crate::{wallet::init::WalletMigrationError, UA_TRANSPARENT};

#[cfg(feature = "transparent-inputs")]
use zcash_primitives::legacy::keys::IncomingViewingKey;

use super::ufvk_support;

/// The migration that removed the address columns from the `accounts` table, and created
/// the `accounts` table.
pub(super) const MIGRATION_ID: Uuid = Uuid::from_u128(0xd956978c_9c87_4d6e_815d_fb8f088d094c);

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
            let account = AccountId::try_from(row.get::<_, u32>(0)?).map_err(|_| {
                WalletMigrationError::CorruptedData("Invalid ZIP-32 account index.".to_owned())
            })?;

            let ufvk_str: String = row.get(1)?;
            let ufvk = UnifiedFullViewingKey::decode(&self.params, &ufvk_str)
                .map_err(WalletMigrationError::CorruptedData)?;

            // Verify that the address column contains the expected value.
            let address: String = row.get(2)?;
            let decoded = Address::decode(&self.params, &address).ok_or_else(|| {
                WalletMigrationError::CorruptedData(format!(
                    "Could not decode {} as a valid Zcash address.",
                    address
                ))
            })?;
            let decoded_address = if let Address::Unified(ua) = decoded {
                ua
            } else {
                return Err(WalletMigrationError::CorruptedData(
                    "Address in accounts table was not a Unified Address.".to_string(),
                ));
            };
            let (expected_address, idx) = ufvk.default_address(
                UnifiedAddressRequest::unsafe_new(false, true, UA_TRANSPARENT),
            )?;
            if decoded_address != expected_address {
                return Err(WalletMigrationError::CorruptedData(format!(
                    "Decoded UA {} does not match the UFVK's default address {} at {:?}.",
                    address,
                    Address::Unified(expected_address).encode(&self.params),
                    idx,
                )));
            }

            // The transparent_address column might not be filled, depending on how this
            // crate was compiled.
            if let Some(transparent_address) = row.get::<_, Option<String>>(3)? {
                let decoded_transparent = Address::decode(&self.params, &transparent_address)
                    .ok_or_else(|| {
                        WalletMigrationError::CorruptedData(format!(
                            "Could not decode {} as a valid Zcash address.",
                            address
                        ))
                    })?;
                let decoded_transparent_address = if let Address::Transparent(addr) =
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

            let (address, d_idx) = ufvk.default_address(UnifiedAddressRequest::unsafe_new(
                false,
                true,
                UA_TRANSPARENT,
            ))?;
            insert_address(transaction, &self.params, account, d_idx, &address)?;
        }

        transaction.execute_batch(
            "DROP TABLE accounts;
            ALTER TABLE accounts_new RENAME TO accounts;",
        )?;

        Ok(())
    }

    fn down(&self, _transaction: &Transaction) -> Result<(), WalletMigrationError> {
        Err(WalletMigrationError::CannotRevert(MIGRATION_ID))
    }
}

/// Adds the given address and diversifier index to the addresses table.
fn insert_address<P: consensus::Parameters>(
    conn: &rusqlite::Connection,
    params: &P,
    account: AccountId,
    diversifier_index: DiversifierIndex,
    address: &UnifiedAddress,
) -> Result<(), rusqlite::Error> {
    let mut stmt = conn.prepare_cached(
        "INSERT INTO addresses (
            account,
            diversifier_index_be,
            address,
            cached_transparent_receiver_address
        )
        VALUES (
            :account,
            :diversifier_index_be,
            :address,
            :cached_transparent_receiver_address
        )",
    )?;

    // the diversifier index is stored in big-endian order to allow sorting
    let mut di_be = *diversifier_index.as_bytes();
    di_be.reverse();
    stmt.execute(named_params![
        ":account": u32::from(account),
        ":diversifier_index_be": &di_be[..],
        ":address": &address.encode(params),
        ":cached_transparent_receiver_address": &address.transparent().map(|r| r.encode(params)),
    ])?;

    Ok(())
}
