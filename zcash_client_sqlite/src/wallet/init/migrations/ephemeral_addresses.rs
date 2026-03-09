//! The migration that records ephemeral addresses for each account.
use std::collections::HashSet;

use schemerz_rusqlite::RusqliteMigration;
use uuid::Uuid;
use zcash_protocol::consensus;

use crate::wallet::init::WalletMigrationError;

use super::utxos_to_txos;

#[cfg(feature = "transparent-inputs")]
use {
    crate::{AccountRef, GapLimits, error::SqliteClientError},
    rusqlite::named_params,
    transparent::keys::NonHardenedChildIndex,
    zcash_keys::{
        encoding::AddressCodec,
        keys::{AddressGenerationError, UnifiedFullViewingKey},
    },
    zip32::DiversifierIndex,
};

pub(super) const MIGRATION_ID: Uuid = Uuid::from_u128(0x0e1d4274_1f8e_44e2_909d_689a4bc2967b);

const DEPENDENCIES: &[Uuid] = &[utxos_to_txos::MIGRATION_ID];

#[allow(dead_code)]
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
        "Record ephemeral addresses for each account."
    }
}

#[cfg(feature = "transparent-inputs")]
fn init_accounts<P: consensus::Parameters>(
    transaction: &rusqlite::Transaction,
    params: &P,
) -> Result<(), SqliteClientError> {
    let ephemeral_gap_limit = GapLimits::default().ephemeral();

    let mut stmt = transaction.prepare("SELECT id, ufvk FROM accounts")?;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        let account_id = AccountRef(row.get(0)?);
        let ufvk_str: Option<String> = row.get(1)?;
        if let Some(ufvk_str) = ufvk_str {
            if let Some(tfvk) = UnifiedFullViewingKey::decode(params, &ufvk_str)
                .map_err(SqliteClientError::CorruptedData)?
                .transparent()
            {
                let ephemeral_ivk = tfvk.derive_ephemeral_ivk().map_err(|_| {
                    SqliteClientError::CorruptedData(
                        "Unexpected failure to derive ephemeral transparent IVK".to_owned(),
                    )
                })?;

                let mut ea_insert = transaction.prepare(
                    "INSERT INTO ephemeral_addresses (account_id, address_index, address)
                     VALUES (:account_id, :address_index, :address)",
                )?;

                // NB: we have reduced the initial space of generated ephemeral addresses
                // from 20 addresses to 5, as ephemeral addresses should always be used in
                // a transaction immediately after being reserved, and as a consequence
                // there is no significant benefit in having a larger gap limit.
                for i in 0..ephemeral_gap_limit {
                    let address = ephemeral_ivk
                        .derive_ephemeral_address(
                            NonHardenedChildIndex::from_index(i).expect("index is valid"),
                        )
                        .map_err(|_| {
                            AddressGenerationError::InvalidTransparentChildIndex(
                                DiversifierIndex::from(i),
                            )
                        })?;

                    ea_insert.execute(named_params! {
                        ":account_id": account_id.0,
                        ":address_index": i,
                        ":address": address.encode(params)
                    })?;
                }
            }
        }
    }

    Ok(())
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

        // Make sure that at least `GapLimits::default().ephemeral()` ephemeral transparent addresses are
        // stored in each account.
        #[cfg(feature = "transparent-inputs")]
        {
            init_accounts(transaction, &self.params)?;
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

    #[test]
    fn migrate() {
        test_migrate(&[super::MIGRATION_ID]);
    }
}
