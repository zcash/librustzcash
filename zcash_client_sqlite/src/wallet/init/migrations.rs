mod add_account_birthdays;
mod add_transaction_views;
mod add_utxo_account;
mod addresses_table;
mod ensure_orchard_ua_receiver;
mod ephemeral_addresses;
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
mod spend_key_available;
mod tx_retrieval_queue;
mod ufvk_support;
mod utxos_table;
mod utxos_to_txos;
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
use uuid::Uuid;
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
    //                                               |                \
    //                                  orchard_received_notes        spend_key_available
    //                                       /         \
    //                ensure_orchard_ua_receiver     utxos_to_txos
    //                                                     |
    //                                             ephemeral_addresses
    //                                                     |
    //                                             tx_retrieval_queue
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
        Box::new(utxos_to_txos::Migration),
        Box::new(ephemeral_addresses::Migration {
            params: params.clone(),
        }),
        Box::new(spend_key_available::Migration),
        Box::new(tx_retrieval_queue::Migration {
            params: params.clone(),
        }),
    ]
}

/// All states of the migration DAG that have been exposed in a public crate release, in
/// the order that crate users would have encountered them.
///
/// Omitted versions had the same migration state as the first prior version that is
/// included.
#[allow(dead_code)]
const PUBLIC_MIGRATION_STATES: &[&[Uuid]] = &[
    V_0_4_0, V_0_6_0, V_0_8_0, V_0_9_0, V_0_10_0, V_0_10_3, V_0_11_0, V_0_11_1,
];

/// Leaf migrations in the 0.4.0 release.
const V_0_4_0: &[Uuid] = &[add_transaction_views::MIGRATION_ID];

/// Leaf migrations in the 0.6.0 release.
const V_0_6_0: &[Uuid] = &[v_transactions_net::MIGRATION_ID];

/// Leaf migrations in the 0.8.0 release.
const V_0_8_0: &[Uuid] = &[
    nullifier_map::MIGRATION_ID,
    v_transactions_note_uniqueness::MIGRATION_ID,
    wallet_summaries::MIGRATION_ID,
];

/// Leaf migrations in the 0.9.0 release.
const V_0_9_0: &[Uuid] = &[
    nullifier_map::MIGRATION_ID,
    receiving_key_scopes::MIGRATION_ID,
    v_transactions_note_uniqueness::MIGRATION_ID,
    wallet_summaries::MIGRATION_ID,
];

/// Leaf migrations in the 0.10.0 release.
const V_0_10_0: &[Uuid] = &[
    nullifier_map::MIGRATION_ID,
    orchard_received_notes::MIGRATION_ID,
    orchard_shardtree::MIGRATION_ID,
];

/// Leaf migrations in the 0.10.3 release.
const V_0_10_3: &[Uuid] = &[
    ensure_orchard_ua_receiver::MIGRATION_ID,
    nullifier_map::MIGRATION_ID,
    orchard_shardtree::MIGRATION_ID,
];

/// Leaf migrations in the 0.11.0 release.
const V_0_11_0: &[Uuid] = &[
    ensure_orchard_ua_receiver::MIGRATION_ID,
    ephemeral_addresses::MIGRATION_ID,
    nullifier_map::MIGRATION_ID,
    orchard_shardtree::MIGRATION_ID,
    spend_key_available::MIGRATION_ID,
    tx_retrieval_queue::MIGRATION_ID,
];

/// Leaf migrations in the 0.11.1 release.
const V_0_11_1: &[Uuid] = &[
    ensure_orchard_ua_receiver::MIGRATION_ID,
    nullifier_map::MIGRATION_ID,
    orchard_shardtree::MIGRATION_ID,
    spend_key_available::MIGRATION_ID,
    tx_retrieval_queue::MIGRATION_ID,
];

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use rusqlite::Connection;
    use secrecy::Secret;
    use tempfile::NamedTempFile;
    use uuid::Uuid;
    use zcash_protocol::consensus::Network;

    use crate::{wallet::init::init_wallet_db_internal, WalletDb};

    /// Tests that we can migrate from a completely empty wallet database to the target
    /// migrations.
    pub(crate) fn test_migrate(migrations: &[Uuid]) {
        let data_file = NamedTempFile::new().unwrap();
        let mut db_data = WalletDb::for_path(data_file.path(), Network::TestNetwork).unwrap();

        let seed = [0xab; 32];
        assert_matches!(
            init_wallet_db_internal(
                &mut db_data,
                Some(Secret::new(seed.to_vec())),
                migrations,
                false
            ),
            Ok(_)
        );
    }

    #[test]
    fn migrate_between_releases_without_data() {
        let data_file = NamedTempFile::new().unwrap();
        let mut db_data = WalletDb::for_path(data_file.path(), Network::TestNetwork).unwrap();

        let seed = [0xab; 32].to_vec();

        let mut prev_state = HashSet::new();
        let mut ensure_migration_state_changed = |conn: &Connection| {
            let new_state = conn
                .prepare_cached("SELECT * FROM schemer_migrations")
                .unwrap()
                .query_map([], |row| row.get::<_, [u8; 16]>(0).map(Uuid::from_bytes))
                .unwrap()
                .collect::<Result<HashSet<Uuid>, _>>()
                .unwrap();
            assert!(prev_state != new_state);
            prev_state = new_state;
        };

        let mut prev_leaves: &[Uuid] = &[];
        for migrations in super::PUBLIC_MIGRATION_STATES {
            assert_matches!(
                init_wallet_db_internal(
                    &mut db_data,
                    Some(Secret::new(seed.clone())),
                    migrations,
                    false
                ),
                Ok(_)
            );

            // If we have any new leaves, ensure the migration state changed. This lets us
            // represent releases that changed the graph edges without introducing any new
            // migrations.
            if migrations.iter().any(|m| !prev_leaves.contains(m)) {
                ensure_migration_state_changed(&db_data.conn);
            }

            prev_leaves = *migrations;
        }

        // Now check that we can migrate from the last public release to the current
        // migration state in this branch.
        assert_matches!(
            init_wallet_db_internal(&mut db_data, Some(Secret::new(seed)), &[], false),
            Ok(_)
        );
        // We don't ensure that the migration state changed, because it may not have.
    }
}
