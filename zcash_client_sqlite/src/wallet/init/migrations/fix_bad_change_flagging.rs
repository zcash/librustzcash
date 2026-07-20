//! Sets the `is_change` flag on output notes received by an internal key when input value was
//! provided from the account corresponding to that key.
use std::collections::HashSet;

use rusqlite::named_params;
use schemerz_rusqlite::RusqliteMigration;
use uuid::Uuid;

use crate::{
    SAPLING_TABLES_PREFIX,
    wallet::{
        KeyScope,
        init::{WalletMigrationError, migrations::fix_broken_commitment_trees},
    },
};

#[cfg(feature = "orchard")]
use crate::ORCHARD_TABLES_PREFIX;

pub(super) const MIGRATION_ID: Uuid = Uuid::from_u128(0x6d36656d_533b_4b65_ae91_dcb95c4ad289);

const DEPENDENCIES: &[Uuid] = &[fix_broken_commitment_trees::MIGRATION_ID];

pub(super) struct Migration;

impl schemerz::Migration<Uuid> for Migration {
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }

    fn dependencies(&self) -> HashSet<Uuid> {
        DEPENDENCIES.iter().copied().collect()
    }

    fn description(&self) -> &'static str {
        "Sets the `is_change` flag on output notes received by an internal key when input value was provided from the account corresponding to that key."
    }
}

impl RusqliteMigration for Migration {
    type Error = WalletMigrationError;

    fn up(&self, transaction: &rusqlite::Transaction) -> Result<(), WalletMigrationError> {
        let fix_change_flag = |table_prefix| {
            transaction.execute(
                &format!(
                    "UPDATE {table_prefix}_received_notes
                     SET is_change = 1
                     FROM sent_notes sn
                     WHERE sn.tx = {table_prefix}_received_notes.tx
                     AND sn.from_account_id = {table_prefix}_received_notes.account_id
                     AND {table_prefix}_received_notes.recipient_key_scope = :internal_scope"
                ),
                named_params! {":internal_scope": KeyScope::INTERNAL.encode()},
            )
        };

        fix_change_flag(SAPLING_TABLES_PREFIX)?;
        #[cfg(feature = "orchard")]
        fix_change_flag(ORCHARD_TABLES_PREFIX)?;

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
