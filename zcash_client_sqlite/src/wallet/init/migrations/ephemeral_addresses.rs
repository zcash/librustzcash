//! The migration that records ephemeral addresses for each account.
use std::collections::HashSet;

use schemerz_rusqlite::RusqliteMigration;
use uuid::Uuid;
use zcash_protocol::consensus;

use crate::wallet::init::WalletMigrationError;

#[cfg(feature = "transparent-inputs")]
use crate::{wallet::transparent::ephemeral, AccountRef};

use super::utxos_to_txos;

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
        {
            let mut stmt = transaction.prepare("SELECT id FROM accounts")?;
            let mut rows = stmt.query([])?;
            while let Some(row) = rows.next()? {
                let account_id = AccountRef(row.get(0)?);
                ephemeral::init_account(transaction, &self.params, account_id)?;
            }
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
