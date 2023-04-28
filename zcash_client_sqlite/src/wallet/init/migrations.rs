mod add_transaction_views;
mod add_utxo_account;
mod addresses_table;
mod initial_setup;
mod received_notes_nullable_nf;
mod sent_notes_to_internal;
mod ufvk_support;
mod utxos_table;
mod v_transactions_net;

use schemer_rusqlite::RusqliteMigration;
use secrecy::SecretVec;
use zcash_primitives::consensus;

use super::WalletMigrationError;

pub(super) fn all_migrations<P: consensus::Parameters + 'static>(
    params: &P,
    seed: Option<SecretVec<u8>>,
) -> Vec<Box<dyn RusqliteMigration<Error = WalletMigrationError>>> {
    //      initial_setup
    //      /           \
    // utxos_table     ufvk_support ----------
    //      \                \                \
    //       \         addresses_table   sent_notes_to_internal
    //        \              /                /
    //        add_utxo_account               /
    //                       \              /
    //                    add_transaction_views
    //                       /
    //        v_transactions_net
    vec![
        Box::new(initial_setup::Migration {}),
        Box::new(utxos_table::Migration {}),
        Box::new(ufvk_support::Migration {
            params: params.clone(),
            seed,
        }),
        Box::new(addresses_table::Migration {
            params: params.clone(),
        }),
        Box::new(add_utxo_account::Migration {
            _params: params.clone(),
        }),
        Box::new(sent_notes_to_internal::Migration {}),
        Box::new(add_transaction_views::Migration),
        Box::new(v_transactions_net::Migration),
        Box::new(received_notes_nullable_nf::Migration),
    ]
}
