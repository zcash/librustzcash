//! A migration that adds an identifier for the account that received a UTXO to the utxos table
use std::collections::HashSet;

use rusqlite;
use schemer;
use schemer_rusqlite::RusqliteMigration;
use uuid::Uuid;

use zcash_primitives::consensus;

use super::{addresses_table, utxos_table};
use crate::wallet::init::WalletMigrationError;

#[cfg(feature = "transparent-inputs")]
use {
    crate::{error::SqliteClientError, wallet::get_transparent_receivers},
    rusqlite::named_params,
    zcash_client_backend::encoding::AddressCodec,
    zcash_primitives::zip32::AccountId,
};

/// This migration adds an account identifier column to the UTXOs table.
///
/// 761884d6-30d8-44ef-b204-0b82551c4ca1
pub(super) const MIGRATION_ID: Uuid = Uuid::from_fields(
    0x761884d6,
    0x30d8,
    0x44ef,
    b"\xb2\x04\x0b\x82\x55\x1c\x4c\xa1",
);

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
                let account: u32 = row.get(0)?;
                let taddrs =
                    get_transparent_receivers(transaction, &self._params, AccountId::from(account))
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
                        ":account": &account,
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
        // TODO: something better than just panic?
        panic!("Cannot revert this migration.");
    }
}
