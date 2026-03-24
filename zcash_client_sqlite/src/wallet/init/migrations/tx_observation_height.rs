//! Adds minimum observation height to transaction records.

use rusqlite::Transaction;
use schemerz_rusqlite::RusqliteMigration;
use std::collections::HashSet;
use uuid::Uuid;
use zcash_protocol::consensus::{self, BlockHeight};

use crate::wallet::{
    init::{WalletMigrationError, migrations::fix_transparent_received_outputs},
    mempool_height,
};

pub(super) const MIGRATION_ID: Uuid = Uuid::from_u128(0xab1be47e_dbfd_439a_876a_55a7e4a0ea0b);

const DEPENDENCIES: &[Uuid] = &[fix_transparent_received_outputs::MIGRATION_ID];

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
        "Adds minimum observation height to transaction records."
    }
}

impl<P: consensus::Parameters> RusqliteMigration for Migration<P> {
    type Error = WalletMigrationError;

    fn up(&self, conn: &Transaction) -> Result<(), WalletMigrationError> {
        // We use the target height as the minimum observed height for transactions
        // for which we don't already have any other height information.
        //
        // chain_tip_height should only be `None` for a brand new wallet, in which case there
        // should be no entries in the `transactions` table and the Sapling activation height will
        // end up unused; we fall back to it just for defense in depth.
        let fallback_height = u32::from(mempool_height(conn)?.map_or_else(
            || {
                self.params
                    .activation_height(consensus::NetworkUpgrade::Sapling)
                    .expect("sapling network upgrade has activated")
            },
            BlockHeight::from,
        ));

        conn.execute_batch(&format!(
            r#"
            PRAGMA legacy_alter_table = ON;

            CREATE TABLE transactions_new (
                id_tx INTEGER PRIMARY KEY,
                txid BLOB NOT NULL UNIQUE,
                created TEXT,
                block INTEGER,
                mined_height INTEGER,
                tx_index INTEGER,
                expiry_height INTEGER,
                raw BLOB,
                fee INTEGER,
                target_height INTEGER,
                min_observed_height INTEGER NOT NULL,
                confirmed_unmined_at_height INTEGER,
                FOREIGN KEY (block) REFERENCES blocks(height),
                CONSTRAINT height_consistency CHECK (
                    block IS NULL OR mined_height = block
                ),
                CONSTRAINT min_observed_consistency CHECK (
                    mined_height IS NULL OR min_observed_height <= mined_height
                ),
                CONSTRAINT confirmed_unmined_consistency CHECK (
                    confirmed_unmined_at_height IS NULL OR mined_height IS NULL
                )
            );

            INSERT INTO transactions_new
            SELECT
                id_tx,
                txid,
                created,
                block,
                mined_height,
                tx_index,
                expiry_height,
                raw,
                fee,
                target_height,
                MIN(
                    IFNULL(target_height, {fallback_height}),
                    IFNULL(mined_height, {fallback_height}),
                    {fallback_height}
                ),
                NULL  -- no transactions are initially confirmed as having expired without being mined
            FROM transactions;

            DROP TABLE transactions;
            ALTER TABLE transactions_new RENAME TO transactions;

            PRAGMA legacy_alter_table = OFF;
            "#
        ))?;

        Ok(())
    }

    fn down(&self, _conn: &Transaction) -> Result<(), WalletMigrationError> {
        Err(WalletMigrationError::CannotRevert(MIGRATION_ID))
    }
}
#[cfg(test)]
mod tests {
    use super::MIGRATION_ID;
    use crate::wallet::init::migrations::tests::test_migrate;

    #[test]
    fn migrate() {
        test_migrate(&[MIGRATION_ID]);
    }
}
