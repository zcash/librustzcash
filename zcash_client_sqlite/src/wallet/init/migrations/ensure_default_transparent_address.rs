//! Ensures that an external transparent address exists in the `addresses` table for each
//! non-hardened child index starting at index 0 and ending at the index corresponding to default
//! address for the account.

use std::collections::HashSet;
use uuid::Uuid;

use rusqlite::Transaction;
use schemerz_rusqlite::RusqliteMigration;
use zcash_protocol::consensus;

use super::transparent_gap_limit_handling;
use crate::wallet::init::WalletMigrationError;

pub(super) const MIGRATION_ID: Uuid = Uuid::from_u128(0x702cf97b_8395_4edc_b584_5c9f87f0ef35);

const DEPENDENCIES: &[Uuid] = &[transparent_gap_limit_handling::MIGRATION_ID];

pub(super) struct Migration<P> {
    pub(super) _params: P,
}

impl<P> schemerz::Migration<Uuid> for Migration<P> {
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }

    fn dependencies(&self) -> HashSet<Uuid> {
        DEPENDENCIES.iter().copied().collect()
    }

    fn description(&self) -> &'static str {
        "Ensures the existence of transparent addresses in the range 0..<default_address_idx>"
    }
}

impl<P: consensus::Parameters> RusqliteMigration for Migration<P> {
    type Error = WalletMigrationError;

    fn up(&self, _conn: &Transaction) -> Result<(), WalletMigrationError> {
        #[cfg(feature = "transparent-inputs")]
        transparent_gap_limit_handling::insert_initial_transparent_addrs(_conn, &self._params)?;

        Ok(())
    }

    fn down(&self, _: &Transaction) -> Result<(), WalletMigrationError> {
        Err(WalletMigrationError::CannotRevert(MIGRATION_ID))
    }
}
