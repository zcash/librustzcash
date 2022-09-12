mod addresses_table;
pub(super) use addresses_table::AddressesTableMigration;

mod add_transaction_views;

use schemer_rusqlite::RusqliteMigration;
use secrecy::SecretVec;
use zcash_primitives::consensus;

use super::{WalletMigration0, WalletMigration1, WalletMigration2, WalletMigrationError};

pub(super) fn all_migrations<P: consensus::Parameters + 'static>(
    params: &P,
    seed: Option<SecretVec<u8>>,
) -> Vec<Box<dyn RusqliteMigration<Error = WalletMigrationError>>> {
    vec![
        Box::new(WalletMigration0 {}),
        Box::new(WalletMigration1 {}),
        Box::new(WalletMigration2 {
            params: params.clone(),
            seed,
        }),
        Box::new(AddressesTableMigration {
            params: params.clone(),
        }),
        Box::new(add_transaction_views::Migration {
            params: params.clone(),
        }),
    ]
}
