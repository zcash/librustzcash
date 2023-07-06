//! Migration that adds support for unified full viewing keys.
use std::collections::HashSet;

use rusqlite::{self, named_params, params};
use schemer;
use schemer_rusqlite::RusqliteMigration;
use secrecy::{ExposeSecret, SecretVec};
use uuid::Uuid;

use zcash_client_backend::{
    address::RecipientAddress,
    data_api::{PoolType, ShieldedProtocol},
    keys::UnifiedSpendingKey,
};
use zcash_primitives::{consensus, zip32::AccountId};

#[cfg(feature = "transparent-inputs")]
use zcash_primitives::legacy::keys::IncomingViewingKey;

#[cfg(feature = "transparent-inputs")]
use zcash_client_backend::encoding::AddressCodec;

use crate::wallet::{
    init::{migrations::initial_setup, WalletMigrationError},
    pool_code,
};

pub(super) const MIGRATION_ID: Uuid = Uuid::from_fields(
    0xbe57ef3b,
    0x388e,
    0x42ea,
    b"\x97\xe2\x67\x8d\xaf\xcf\x97\x54",
);

pub(super) struct Migration<P> {
    pub(super) params: P,
    pub(super) seed: Option<SecretVec<u8>>,
}

impl<P> schemer::Migration for Migration<P> {
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }

    fn dependencies(&self) -> HashSet<Uuid> {
        [initial_setup::MIGRATION_ID].into_iter().collect()
    }

    fn description(&self) -> &'static str {
        "Add support for unified full viewing keys"
    }
}

impl<P: consensus::Parameters> RusqliteMigration for Migration<P> {
    type Error = WalletMigrationError;

    fn up(&self, transaction: &rusqlite::Transaction) -> Result<(), WalletMigrationError> {
        //
        // Update the accounts table to store ufvks rather than extfvks
        //

        transaction.execute_batch(
            "CREATE TABLE accounts_new (
                account INTEGER PRIMARY KEY,
                ufvk TEXT NOT NULL,
                address TEXT,
                transparent_address TEXT
            );",
        )?;

        let mut stmt_fetch_accounts =
            transaction.prepare("SELECT account, address FROM accounts")?;

        let mut rows = stmt_fetch_accounts.query([])?;
        while let Some(row) = rows.next()? {
            // We only need to check for the presence of the seed if we have keys that
            // need to be migrated; otherwise, it's fine to not supply the seed if this
            // migration is being used to initialize an empty database.
            if let Some(seed) = &self.seed {
                let account: u32 = row.get(0)?;
                let account = AccountId::from(account);
                let usk =
                    UnifiedSpendingKey::from_seed(&self.params, seed.expose_secret(), account)
                        .unwrap();
                let ufvk = usk.to_unified_full_viewing_key();

                let address: String = row.get(1)?;
                let decoded =
                    RecipientAddress::decode(&self.params, &address).ok_or_else(|| {
                        WalletMigrationError::CorruptedData(format!(
                            "Could not decode {} as a valid Zcash address.",
                            address
                        ))
                    })?;
                match decoded {
                    RecipientAddress::Shielded(decoded_address) => {
                        let dfvk = ufvk.sapling().expect(
                            "Derivation should have produced a UFVK containing a Sapling component.",
                        );
                        let (idx, expected_address) = dfvk.default_address();
                        if decoded_address != expected_address {
                            return Err(WalletMigrationError::CorruptedData(
                                format!("Decoded Sapling address {} does not match the ufvk's Sapling address {} at {:?}.",
                                    address,
                                    RecipientAddress::Shielded(expected_address).encode(&self.params),
                                    idx)));
                        }
                    }
                    RecipientAddress::Transparent(_) => {
                        return Err(WalletMigrationError::CorruptedData(
                            "Address field value decoded to a transparent address; should have been Sapling or unified.".to_string()));
                    }
                    RecipientAddress::Unified(decoded_address) => {
                        let (expected_address, idx) = ufvk.default_address();
                        if decoded_address != expected_address {
                            return Err(WalletMigrationError::CorruptedData(
                                format!("Decoded unified address {} does not match the ufvk's default address {} at {:?}.",
                                    address,
                                    RecipientAddress::Unified(expected_address).encode(&self.params),
                                    idx)));
                        }
                    }
                }

                let ufvk_str: String = ufvk.encode(&self.params);
                let address_str: String = ufvk.default_address().0.encode(&self.params);

                // This migration, and the wallet behaviour before it, stored the default
                // transparent address in the `accounts` table. This does not necessarily
                // match the transparent receiver in the default Unified Address. Starting
                // from `AddressesTableMigration` below, we no longer store transparent
                // addresses directly, but instead extract them from the Unified Address
                // (or from the UFVK if the UA was derived without a transparent receiver,
                // which is not the case for UAs generated by this crate).
                #[cfg(feature = "transparent-inputs")]
                let taddress_str: Option<String> = ufvk.transparent().and_then(|k| {
                    k.derive_external_ivk()
                        .ok()
                        .map(|k| k.default_address().0.encode(&self.params))
                });
                #[cfg(not(feature = "transparent-inputs"))]
                let taddress_str: Option<String> = None;

                transaction.execute(
                    "INSERT INTO accounts_new (account, ufvk, address, transparent_address)
                    VALUES (:account, :ufvk, :address, :transparent_address)",
                    named_params![
                        ":account": &<u32>::from(account),
                        ":ufvk": &ufvk_str,
                        ":address": &address_str,
                        ":transparent_address": &taddress_str,
                    ],
                )?;
            } else {
                return Err(WalletMigrationError::SeedRequired);
            }
        }

        transaction.execute_batch(
            "DROP TABLE accounts;
            ALTER TABLE accounts_new RENAME TO accounts;",
        )?;

        //
        // Update the sent_notes table to include an output_pool column that
        // is respected by the uniqueness constraint
        //

        transaction.execute_batch(
            "CREATE TABLE sent_notes_new (
                id_note INTEGER PRIMARY KEY,
                tx INTEGER NOT NULL,
                output_pool INTEGER NOT NULL ,
                output_index INTEGER NOT NULL,
                from_account INTEGER NOT NULL,
                address TEXT NOT NULL,
                value INTEGER NOT NULL,
                memo BLOB,
                FOREIGN KEY (tx) REFERENCES transactions(id_tx),
                FOREIGN KEY (from_account) REFERENCES accounts(account),
                CONSTRAINT tx_output UNIQUE (tx, output_pool, output_index)
            );",
        )?;

        // we query in a nested scope so that the col_names iterator is correctly
        // dropped and doesn't maintain a lock on the table.
        let has_output_pool = {
            let mut stmt_fetch_columns = transaction.prepare("PRAGMA TABLE_INFO('sent_notes')")?;
            let mut col_names = stmt_fetch_columns.query_map([], |row| {
                let col_name: String = row.get(1)?;
                Ok(col_name)
            })?;

            col_names.any(|cname| cname == Ok("output_pool".to_string()))
        };

        if has_output_pool {
            transaction.execute_batch(
                "INSERT INTO sent_notes_new
                    (id_note, tx, output_pool, output_index, from_account, address, value, memo)
                    SELECT id_note, tx, output_pool, output_index, from_account, address, value, memo
                    FROM sent_notes;"
            )?;
        } else {
            let mut stmt_fetch_sent_notes = transaction.prepare(
                "SELECT id_note, tx, output_index, from_account, address, value, memo
                    FROM sent_notes",
            )?;

            let mut stmt_insert_sent_note = transaction.prepare(
                "INSERT INTO sent_notes_new
                    (id_note, tx, output_pool, output_index, from_account, address, value, memo)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            )?;

            let mut rows = stmt_fetch_sent_notes.query([])?;
            while let Some(row) = rows.next()? {
                let id_note: i64 = row.get(0)?;
                let tx_ref: i64 = row.get(1)?;
                let output_index: i64 = row.get(2)?;
                let account_id: u32 = row.get(3)?;
                let address: String = row.get(4)?;
                let value: i64 = row.get(5)?;
                let memo: Option<Vec<u8>> = row.get(6)?;

                let decoded_address =
                    RecipientAddress::decode(&self.params, &address).ok_or_else(|| {
                        WalletMigrationError::CorruptedData(format!(
                            "Could not decode {} as a valid Zcash address.",
                            address
                        ))
                    })?;
                let output_pool = match decoded_address {
                    RecipientAddress::Shielded(_) => {
                        Ok(pool_code(PoolType::Shielded(ShieldedProtocol::Sapling)))
                    }
                    RecipientAddress::Transparent(_) => Ok(pool_code(PoolType::Transparent)),
                    RecipientAddress::Unified(_) => Err(WalletMigrationError::CorruptedData(
                        "Unified addresses should not yet appear in the sent_notes table."
                            .to_string(),
                    )),
                }?;

                stmt_insert_sent_note.execute(params![
                    id_note,
                    tx_ref,
                    output_pool,
                    output_index,
                    account_id,
                    address,
                    value,
                    memo
                ])?;
            }
        }

        transaction.execute_batch(
            "DROP TABLE sent_notes;
            ALTER TABLE sent_notes_new RENAME TO sent_notes;",
        )?;

        Ok(())
    }

    fn down(&self, _transaction: &rusqlite::Transaction) -> Result<(), WalletMigrationError> {
        // TODO: something better than just panic?
        panic!("Cannot revert this migration.");
    }
}
