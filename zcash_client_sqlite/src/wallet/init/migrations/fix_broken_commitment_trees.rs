//! Truncates away bad note commitment tree state for users whose wallets were broken by incorrect
//! reorg handling.
use std::collections::HashSet;

use rusqlite::OptionalExtension;
use schemerz_rusqlite::RusqliteMigration;
use uuid::Uuid;
use zcash_protocol::consensus::{self, BlockHeight};

use crate::wallet::{
    self,
    init::{migrations::support_legacy_sqlite, WalletMigrationError},
};

#[cfg(feature = "transparent-inputs")]
use crate::GapLimits;

pub(super) const MIGRATION_ID: Uuid = Uuid::from_u128(0x9fa43ce0_a387_45d1_be03_57a3edc76d01);

const DEPENDENCIES: &[Uuid] = &[support_legacy_sqlite::MIGRATION_ID];

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
        "Truncates away bad note commitment tree state for users whose wallets were broken by bad reorg handling."
    }
}

impl<P: consensus::Parameters> RusqliteMigration for Migration<P> {
    type Error = WalletMigrationError;

    fn up(&self, transaction: &rusqlite::Transaction) -> Result<(), WalletMigrationError> {
        #[cfg(not(feature = "orchard"))]
        let max_height_query = r#"
            SELECT MAX(height) FROM blocks
            JOIN sapling_tree_checkpoints sc ON sc.checkpoint_id = height
        "#;
        #[cfg(feature = "orchard")]
        let max_height_query = r#"
            SELECT MAX(height) FROM blocks
            JOIN sapling_tree_checkpoints sc ON sc.checkpoint_id = height
            JOIN orchard_tree_checkpoints oc ON oc.checkpoint_id = height
        "#;

        let max_block_height = transaction
            .query_row(max_height_query, [], |row| {
                let cid = row.get::<_, Option<u32>>(0)?;
                Ok(cid.map(BlockHeight::from))
            })
            .optional()?
            .flatten();

        if let Some(h) = max_block_height {
            wallet::truncate_to_height(
                transaction,
                &self.params,
                #[cfg(feature = "transparent-inputs")]
                &GapLimits::default(),
                h,
            )?;
        }

        Ok(())
    }

    fn down(&self, _: &rusqlite::Transaction) -> Result<(), WalletMigrationError> {
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
