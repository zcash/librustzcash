//! A migration that adds an identifier for the account that received a UTXO to the utxos table
use rusqlite;
use schemer;
use schemer_rusqlite::RusqliteMigration;
use std::collections::HashSet;
use uuid::Uuid;
use zcash_primitives::consensus;

use super::{addresses_table, utxos_table};
use crate::wallet::init::WalletMigrationError;

#[cfg(feature = "transparent-inputs")]
use {
    crate::error::SqliteClientError,
    rusqlite::{named_params, OptionalExtension},
    std::collections::HashMap,
    zcash_client_backend::{
        encoding::AddressCodec, keys::UnifiedFullViewingKey, wallet::TransparentAddressMetadata,
    },
    zcash_keys::address::Address,
    zcash_primitives::legacy::{
        keys::{IncomingViewingKey, NonHardenedChildIndex},
        TransparentAddress,
    },
    zip32::{AccountId, DiversifierIndex, Scope},
};

/// This migration adds an account identifier column to the UTXOs table.
pub(super) const MIGRATION_ID: Uuid = Uuid::from_u128(0x761884d6_30d8_44ef_b204_0b82551c4ca1);

pub(super) struct Migration<P> {
    pub(super) _params: P,
}

impl<P> schemer::Migration for Migration<P> {
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }

    fn dependencies(&self) -> HashSet<Uuid> {
        [utxos_table::MIGRATION_ID, addresses_table::MIGRATION_ID]
            .into_iter()
            .collect()
    }

    fn description(&self) -> &'static str {
        "Adds an identifier for the account that received a UTXO to the utxos table"
    }
}

impl<P: consensus::Parameters> RusqliteMigration for Migration<P> {
    type Error = WalletMigrationError;

    fn up(&self, transaction: &rusqlite::Transaction) -> Result<(), WalletMigrationError> {
        transaction.execute_batch("ALTER TABLE utxos ADD COLUMN received_by_account INTEGER;")?;

        #[cfg(feature = "transparent-inputs")]
        {
            let mut stmt_update_utxo_account = transaction.prepare(
                "UPDATE utxos SET received_by_account = :account WHERE address = :address",
            )?;

            let mut stmt_fetch_accounts = transaction.prepare("SELECT account FROM accounts")?;

            let mut rows = stmt_fetch_accounts.query([])?;
            while let Some(row) = rows.next()? {
                let account = AccountId::try_from(row.get::<_, u32>(0)?).map_err(|_| {
                    WalletMigrationError::CorruptedData(
                        "Unexpected ZIP-32 account index.".to_string(),
                    )
                })?;
                let taddrs = get_transparent_receivers(transaction, &self._params, account)
                    .map_err(|e| match e {
                        SqliteClientError::DbError(e) => WalletMigrationError::DbError(e),
                        SqliteClientError::CorruptedData(s) => {
                            WalletMigrationError::CorruptedData(s)
                        }
                        other => WalletMigrationError::CorruptedData(format!(
                            "Unexpected error in migration: {}",
                            other
                        )),
                    })?;

                for (taddr, _) in taddrs {
                    stmt_update_utxo_account.execute(named_params![
                        ":account": u32::from(account),
                        ":address": &taddr.encode(&self._params),
                    ])?;
                }
            }
        }

        transaction.execute_batch(
            "CREATE TABLE utxos_new (
                id_utxo INTEGER PRIMARY KEY,
                received_by_account INTEGER NOT NULL,
                address TEXT NOT NULL,
                prevout_txid BLOB NOT NULL,
                prevout_idx INTEGER NOT NULL,
                script BLOB NOT NULL,
                value_zat INTEGER NOT NULL,
                height INTEGER NOT NULL,
                spent_in_tx INTEGER,
                FOREIGN KEY (received_by_account) REFERENCES accounts(account),
                FOREIGN KEY (spent_in_tx) REFERENCES transactions(id_tx),
                CONSTRAINT tx_outpoint UNIQUE (prevout_txid, prevout_idx)
            );
            INSERT INTO utxos_new (
                id_utxo, received_by_account, address,
                prevout_txid, prevout_idx, script, value_zat,
                height, spent_in_tx)
            SELECT
                id_utxo, received_by_account, address,
                prevout_txid, prevout_idx, script, value_zat,
                height, spent_in_tx
            FROM utxos;",
        )?;

        transaction.execute_batch(
            "DROP TABLE utxos;
            ALTER TABLE utxos_new RENAME TO utxos;",
        )?;

        Ok(())
    }

    fn down(&self, _transaction: &rusqlite::Transaction) -> Result<(), WalletMigrationError> {
        Err(WalletMigrationError::CannotRevert(MIGRATION_ID))
    }
}

#[cfg(feature = "transparent-inputs")]
fn get_transparent_receivers<P: consensus::Parameters>(
    conn: &rusqlite::Connection,
    params: &P,
    account: AccountId,
) -> Result<HashMap<TransparentAddress, Option<TransparentAddressMetadata>>, SqliteClientError> {
    let mut ret: HashMap<TransparentAddress, Option<TransparentAddressMetadata>> = HashMap::new();

    // Get all UAs derived
    let mut ua_query = conn
        .prepare("SELECT address, diversifier_index_be FROM addresses WHERE account = :account")?;
    let mut rows = ua_query.query(named_params![":account": u32::from(account)])?;

    while let Some(row) = rows.next()? {
        let ua_str: String = row.get(0)?;
        let di_vec: Vec<u8> = row.get(1)?;
        let mut di: [u8; 11] = di_vec.try_into().map_err(|_| {
            SqliteClientError::CorruptedData("Diversifier index is not an 11-byte value".to_owned())
        })?;
        di.reverse(); // BE -> LE conversion

        let ua = Address::decode(params, &ua_str)
            .ok_or_else(|| {
                SqliteClientError::CorruptedData("Not a valid Zcash recipient address".to_owned())
            })
            .and_then(|addr| match addr {
                Address::Unified(ua) => Ok(ua),
                _ => Err(SqliteClientError::CorruptedData(format!(
                    "Addresses table contains {} which is not a unified address",
                    ua_str,
                ))),
            })?;

        if let Some(taddr) = ua.transparent() {
            let index = NonHardenedChildIndex::from_index(
                DiversifierIndex::from(di).try_into().map_err(|_| {
                    SqliteClientError::CorruptedData(
                        "Unable to get diversifier for transparent address.".to_owned(),
                    )
                })?,
            )
            .ok_or_else(|| {
                SqliteClientError::CorruptedData(
                    "Unexpected hardened index for transparent address.".to_owned(),
                )
            })?;

            ret.insert(
                *taddr,
                Some(TransparentAddressMetadata::new(
                    Scope::External.into(),
                    index,
                )),
            );
        }
    }

    if let Some((taddr, child_index)) = get_legacy_transparent_address(params, conn, account)? {
        ret.insert(
            taddr,
            Some(TransparentAddressMetadata::new(
                Scope::External.into(),
                child_index,
            )),
        );
    }

    Ok(ret)
}

#[cfg(feature = "transparent-inputs")]
fn get_legacy_transparent_address<P: consensus::Parameters>(
    params: &P,
    conn: &rusqlite::Connection,
    account: AccountId,
) -> Result<Option<(TransparentAddress, NonHardenedChildIndex)>, SqliteClientError> {
    // Get the UFVK for the account.
    let ufvk_str: Option<String> = conn
        .query_row(
            "SELECT ufvk FROM accounts WHERE account = :account",
            [u32::from(account)],
            |row| row.get(0),
        )
        .optional()?;

    if let Some(uvk_str) = ufvk_str {
        let ufvk = UnifiedFullViewingKey::decode(params, &uvk_str)
            .map_err(SqliteClientError::CorruptedData)?;

        // Derive the default transparent address (if it wasn't already part of a derived UA).
        ufvk.transparent()
            .map(|tfvk| {
                tfvk.derive_external_ivk()
                    .map(|tivk| tivk.default_address())
                    .map_err(SqliteClientError::HdwalletError)
            })
            .transpose()
    } else {
        Ok(None)
    }
}
