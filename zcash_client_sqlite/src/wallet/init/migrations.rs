mod add_account_birthdays;
mod add_transaction_views;
mod add_utxo_account;
mod addresses_table;
mod ensure_orchard_ua_receiver;
mod full_account_ids;
mod initial_setup;
mod nullifier_map;
mod orchard_received_notes;
mod orchard_shardtree;
mod received_notes_nullable_nf;
mod receiving_key_scopes;
mod sapling_memo_consistency;
mod sent_notes_to_internal;
mod shardtree_support;
mod ufvk_support;
mod utxos_table;
mod v_sapling_shard_unscanned_ranges;
mod v_transactions_net;
mod v_transactions_note_uniqueness;
mod v_transactions_shielding_balance;
mod v_transactions_transparent_history;
mod v_tx_outputs_use_legacy_false;
mod wallet_summaries;

use std::rc::Rc;

use schemer_rusqlite::RusqliteMigration;
use secrecy::SecretVec;
use zcash_protocol::consensus;

use super::WalletMigrationError;

pub(super) fn all_migrations<P: consensus::Parameters + 'static>(
    params: &P,
    seed: Option<Rc<SecretVec<u8>>>,
) -> Vec<Box<dyn RusqliteMigration<Error = WalletMigrationError>>> {
    //                                   initial_setup
    //                                   /           \
    //                          utxos_table         ufvk_support
    //                             |                 /         \
    //                             |    addresses_table   sent_notes_to_internal
    //                             |          /                /
    //                           add_utxo_account             /
    //                                        \              /
    //                                     add_transaction_views
    //                                               |
    //                                       v_transactions_net
    //                                               |
    //                                            received_notes_nullable_nf------
    //                                            /           |                   \
    //                                           /            |                    \
    //           --------------- shardtree_support    sapling_memo_consistency   nullifier_map
    //          /                     /           \                       \
    // orchard_shardtree   add_account_birthdays   receiving_key_scopes   v_transactions_transparent_history
    //                        |                 \            |                     |
    //       v_sapling_shard_unscanned_ranges    \           |       v_tx_outputs_use_legacy_false
    //                        |                   \          |                     |
    //                wallet_summaries             \         |      v_transactions_shielding_balance
    //                        \                     \        |                     |
    //                         \                     \       |       v_transactions_note_uniqueness
    //                          \                     \      |        /
    //                           -------------------- full_account_ids
    //                                                       |
    //                                             orchard_received_notes
    //                                                       |
    //                                           ensure_orchard_ua_receiver
    vec![
        Box::new(initial_setup::Migration {}),
        Box::new(utxos_table::Migration {}),
        Box::new(ufvk_support::Migration {
            params: params.clone(),
            seed: seed.clone(),
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
        Box::new(shardtree_support::Migration {
            params: params.clone(),
        }),
        Box::new(nullifier_map::Migration),
        Box::new(sapling_memo_consistency::Migration {
            params: params.clone(),
        }),
        Box::new(add_account_birthdays::Migration {
            params: params.clone(),
        }),
        Box::new(v_sapling_shard_unscanned_ranges::Migration {
            params: params.clone(),
        }),
        Box::new(wallet_summaries::Migration),
        Box::new(v_transactions_transparent_history::Migration),
        Box::new(v_tx_outputs_use_legacy_false::Migration),
        Box::new(v_transactions_shielding_balance::Migration),
        Box::new(v_transactions_note_uniqueness::Migration),
        Box::new(receiving_key_scopes::Migration {
            params: params.clone(),
        }),
        Box::new(full_account_ids::Migration {
            seed,
            params: params.clone(),
        }),
        Box::new(orchard_shardtree::Migration {
            params: params.clone(),
        }),
        Box::new(orchard_received_notes::Migration),
        Box::new(ensure_orchard_ua_receiver::Migration {
            params: params.clone(),
        }),
    ]
}
