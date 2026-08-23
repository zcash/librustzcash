//! Migrations for the `zcash_client_sqlite` wallet database.
//!
//! The constants in this module cover all states of the migration DAG that have been
//! exposed in a public crate release, in the order that crate users would have
//! encountered them.
//!
//! Omitted versions had the same migration state as the first prior version that is
//! included.

/// Returns whether `id` appears in any of the given dependency lists.
const fn is_depended_on(id: Uuid, dependencies: &[&[Uuid]]) -> bool {
    let mut i = 0;
    while i < dependencies.len() {
        let deps = dependencies[i];
        let mut j = 0;
        while j < deps.len() {
            if deps[j].as_u128() == id.as_u128() {
                return true;
            }
            j += 1;
        }
        i += 1;
    }
    false
}

/// Counts the identifiers in `ids` that appear in none of the given dependency lists.
const fn count_leaves(ids: &[Uuid], dependencies: &[&[Uuid]]) -> usize {
    let mut count = 0;
    let mut i = 0;
    while i < ids.len() {
        if !is_depended_on(ids[i], dependencies) {
            count += 1;
        }
        i += 1;
    }
    count
}

/// Collects the identifiers in `ids` that appear in none of the given dependency lists,
/// preserving their order in `ids`.
///
/// `N` must equal [`count_leaves`] for the same arguments; const evaluation fails otherwise.
const fn collect_leaves<const N: usize>(ids: &[Uuid], dependencies: &[&[Uuid]]) -> [Uuid; N] {
    let mut leaves = [Uuid::nil(); N];
    let mut count = 0;
    let mut i = 0;
    while i < ids.len() {
        if !is_depended_on(ids[i], dependencies) {
            leaves[count] = ids[i];
            count += 1;
        }
        i += 1;
    }
    assert!(count == N);
    leaves
}

/// Declares the given migration modules, and defines [`CURRENT_LEAF_MIGRATIONS`] as the
/// leaves of the migration dependency graph, computed at compile time.
///
/// Each module contributes its `MIGRATION_ID` and `DEPENDENCIES` constants to the graph;
/// the leaves are the migrations on which no other migration depends. Because this macro
/// is what declares the modules, the graph necessarily covers every migration module.
///
/// Under the `unstable` feature, this also generates the `ids` module, re-exporting each
/// migration's identifier under the SCREAMING_SNAKE_CASE version of its module name.
macro_rules! migration_modules {
    ($($migration:ident),+ $(,)?) => {
        $(mod $migration;)+

        /// The identifiers of all migrations in the dependency graph.
        const ALL_MIGRATION_IDS: &[Uuid] = &[$($migration::MIGRATION_ID),+];

        /// The dependencies of each migration, in the same order as [`ALL_MIGRATION_IDS`].
        const ALL_DEPENDENCIES: &[&[Uuid]] = &[$($migration::DEPENDENCIES),+];

        const LEAF_MIGRATION_IDS: [Uuid; count_leaves(ALL_MIGRATION_IDS, ALL_DEPENDENCIES)] =
            collect_leaves(ALL_MIGRATION_IDS, ALL_DEPENDENCIES);

        /// Leaf migrations as of the current repository state.
        pub const CURRENT_LEAF_MIGRATIONS: &[Uuid] = &LEAF_MIGRATION_IDS;

        #[cfg(feature = "unstable")]
        pastey::paste! {
            /// Identifiers of the individual migrations that make up this crate's internal
            /// migration graph.
            ///
            /// External migrations registered via
            /// [`WalletMigrator::with_external_migrations`] are applied as part of a single
            /// graph alongside the internal ones, so an external migration that reads or
            /// extends internal schema must declare a dependency that orders it after the
            /// migration which creates that schema.
            ///
            /// These identifiers are unstable by nature, which is why they sit behind the
            /// `unstable` feature: each names an individual migration rather than a state of
            /// the graph that a published release exposed, so the set of them, and which of
            /// them are reachable, changes between releases. A release constant such as
            /// [`V_0_19_0`] carries no such risk. The intended shape is therefore to depend
            /// on an identifier here while developing against unreleased schema, and to move
            /// the anchor to the release constant that covers it once that release exists.
            ///
            /// Depending on an identifier here only orders your migration *after* the named
            /// one; it does not prevent later internal migrations from being applied before
            /// yours.
            ///
            /// [`WalletMigrator::with_external_migrations`]: super::WalletMigrator::with_external_migrations
            pub mod ids {
                $(pub use super::$migration::MIGRATION_ID as [<$migration:upper>];)+
            }
        }
    };
}

migration_modules!(
    account_delete_cascade,
    add_account_birthdays,
    add_account_uuids,
    add_transaction_trust_marker,
    add_transaction_views,
    add_transparent_receiver_address_index,
    add_transparent_value_index,
    add_utxo_account,
    addresses_table,
    ensure_default_transparent_address,
    ensure_orchard_ua_receiver,
    ephemeral_addresses,
    fix_bad_change_flagging,
    fix_bad_ironwood_change_flagging,
    fix_broken_commitment_trees,
    fix_transparent_received_outputs,
    fix_v_transactions_expired_unmined,
    fix_v_transactions_multi_account_totals,
    full_account_ids,
    initial_setup,
    ironwood_pool_code_views,
    ironwood_received_notes,
    ironwood_shardtree,
    ivk_item_cache,
    note_locking,
    nullifier_map,
    orchard_ironwood_broadcast_binding,
    orchard_ironwood_migration_anchor_interval,
    orchard_ironwood_migration_history,
    orchard_ironwood_migration_txid_blob,
    orchard_ironwood_migration_tables,
    orchard_ironwood_migration_unsatisfiability,
    orchard_note_version,
    orchard_received_notes,
    orchard_shardtree,
    received_notes_nullable_nf,
    receiving_key_scopes,
    sapling_memo_consistency,
    sent_notes_to_internal,
    shardtree_support,
    spend_key_available,
    standalone_address,
    standalone_p2sh,
    support_legacy_sqlite,
    support_zcashd_wallet_import,
    transparent_gap_limit_handling,
    tree_retained_checkpoints,
    tx_observation_height,
    tx_retrieval_queue,
    tx_retrieval_queue_expiry,
    tx_status_observation_intent,
    ufvk_support,
    utxos_table,
    utxos_to_txos,
    v_address_uses_ironwood,
    v_received_output_spends_account,
    v_sapling_shard_unscanned_ranges,
    v_transactions_additional_totals,
    v_transactions_net,
    v_transactions_note_uniqueness,
    v_transactions_pool_crossing,
    v_transactions_shielding_balance,
    v_transactions_transparent_history,
    v_migration_transactions,
    v_transactions_zip318_kind,
    v_tx_outputs_key_scopes,
    v_tx_outputs_return_addrs,
    v_tx_outputs_transparent_addresses,
    v_tx_outputs_use_legacy_false,
    wallet_summaries,
    witness_stabilized_notes,
    zip318_classification,
);

use std::{rc::Rc, sync::Mutex};

use rand_core::RngCore;
use rusqlite::named_params;
use schemerz_rusqlite::RusqliteMigration;
use secrecy::SecretVec;
use uuid::Uuid;
use zcash_address::unified::{Encoding as _, Ufvk, Uivk};
use zcash_protocol::consensus;

use crate::util::Clock;

use super::WalletMigrationError;

pub(super) fn all_migrations<
    P: consensus::Parameters + 'static,
    C: Clock + Clone + 'static,
    R: RngCore + Clone + 'static,
>(
    params: &P,
    clock: C,
    rng: R,
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
    //                                            received_notes_nullable_nf---------------------.
    //                                            /           |                                   \
    //                                           /            |                                    \
    //           ,-------------- shardtree_support    sapling_memo_consistency                    nullifier_map
    //          /                     /           \                       \                                  |
    // orchard_shardtree   add_account_birthdays   receiving_key_scopes   v_transactions_transparent_history |
    //   |                    |                 \            |                     |                         |
    //   |   v_sapling_shard_unscanned_ranges    \           |       v_tx_outputs_use_legacy_false           |
    //   |                    |                   \          |                     |                         |
    //   |            wallet_summaries             \         |      v_transactions_shielding_balance         /
    //   \                    \                     \        |                     |                        /
    //    \                    \                     \       |      v_transactions_note_uniqueness         /
    //     \                    \                     \      |        /                                   /
    //      \                    `------------------- full_account_ids                                   /
    //       \                                        /               \                                 /
    //        \                         orchard_received_notes        spend_key_available              /
    //         \                            /          \                      /                       /
    //          \     ensure_orchard_ua_receiver     utxos_to_txos           /                       /
    //           \                          \              |                /                       /
    //            \                          \     ephemeral_addresses     /                       /
    //             \                          \            |              /                       /
    //              `----------------------------- tx_retrieval_queue ---------------------------'
    //                                                  /    \
    //                              support_legacy_sqlite    tx_retrieval_queue_expiry ----------------.
    //                                 /              \                                                 \
    //            fix_broken_commitment_trees         add_account_uuids                                  \
    //                       /                                /        \                                  \
    //    fix_bad_change_flagging      transparent_gap_limit_handling   v_transactions_additional_totals   \
    //                       \                       |                      /                               \
    //                        \      ensure_default_transparent_address    /                                 \
    //                         \                     |                    /                                   \
    //                          `---- fix_transparent_received_outputs --'                                     \
    //                                    /         /           \                                              |
    //                                   /         /             \                                             |
    //                                  /         /               \                                            |
    //           support_zcashd_wallet_import    /             fix_v_transactions_expired_unmined              |
    //                \                         /                    /        |         \                      |
    //                 \      tx_observation_height                 /         |          \                     |
    //                  \                       \                  /          |           \                    /
    //                   \                   add_transaction_trust_marker     |  v_tx_outputs_return_addrs    /
    //                    \                       \                           |                     /        /
    //                     \                       \         v_received_output_spends_account      /        /
    //                      \                       \               /                             /        /
    //                       `------------------- account_delete_cascade ---------------------------------'
    //                              /               /                  |              \
    //     add_transparent_value_index  v_tx_outputs_key_scopes  standalone_p2sh    witness_stabilized_notes
    //                                     /        |             /            \
    //                               ivk_item_cache |            /           orchard_note_version
    //                             .----------------'           /                  \
    //                             |  add_transparent_receiver_address_index        \
    //                             |               |                                 \
    //                             |      standalone_address               ironwood_received_notes ----------------
    //                             |                                        /         |          \                  \
    //                             |                     ironwood_pool_code_views     |      note_locking  fix_bad_ironwood_change_flagging
    //                             |                             |          \         |
    //                             |                             |           \ v_address_uses_ironwood
    //                             |                             |            \
    //                             |              v_transactions_pool_crossing \
    //                             `------------------------------------------- v_tx_outputs_transparent_addresses
    //
    let rng = Rc::new(Mutex::new(rng));
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
        Box::new(ironwood_shardtree::Migration {
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
            _params: params.clone(),
        }),
        Box::new(support_legacy_sqlite::Migration),
        Box::new(fix_broken_commitment_trees::Migration {
            params: params.clone(),
        }),
        Box::new(fix_bad_change_flagging::Migration),
        Box::new(add_account_uuids::Migration),
        Box::new(v_transactions_additional_totals::Migration),
        Box::new(transparent_gap_limit_handling::Migration {
            params: params.clone(),
            _clock: clock.clone(),
            _rng: rng.clone(),
        }),
        Box::new(ensure_default_transparent_address::Migration {
            _params: params.clone(),
        }),
        Box::new(tx_retrieval_queue_expiry::Migration),
        Box::new(fix_transparent_received_outputs::Migration),
        Box::new(support_zcashd_wallet_import::Migration),
        Box::new(fix_v_transactions_expired_unmined::Migration),
        Box::new(v_tx_outputs_return_addrs::Migration),
        Box::new(tx_observation_height::Migration {
            params: params.clone(),
        }),
        Box::new(v_received_output_spends_account::Migration),
        Box::new(add_transaction_trust_marker::Migration),
        Box::new(account_delete_cascade::Migration),
        Box::new(v_tx_outputs_key_scopes::Migration),
        Box::new(standalone_p2sh::Migration),
        Box::new(ivk_item_cache::Migration {
            params: params.clone(),
        }),
        Box::new(witness_stabilized_notes::Migration {
            params: params.clone(),
        }),
        Box::new(add_transparent_receiver_address_index::Migration {
            params: params.clone(),
        }),
        Box::new(add_transparent_value_index::Migration),
        Box::new(orchard_note_version::Migration),
        Box::new(ironwood_received_notes::Migration),
        Box::new(ironwood_pool_code_views::Migration),
        Box::new(fix_bad_ironwood_change_flagging::Migration),
        Box::new(v_address_uses_ironwood::Migration),
        Box::new(v_transactions_pool_crossing::Migration),
        Box::new(zip318_classification::Migration),
        Box::new(v_transactions_zip318_kind::Migration),
        Box::new(orchard_ironwood_migration_tables::Migration),
        Box::new(tree_retained_checkpoints::Migration),
        Box::new(note_locking::Migration),
        Box::new(tx_status_observation_intent::Migration),
        Box::new(orchard_ironwood_migration_anchor_interval::Migration),
        Box::new(v_tx_outputs_transparent_addresses::Migration),
        Box::new(orchard_ironwood_migration_unsatisfiability::Migration),
        Box::new(orchard_ironwood_migration_history::Migration),
        Box::new(orchard_ironwood_broadcast_binding::Migration),
        Box::new(orchard_ironwood_migration_txid_blob::Migration),
        Box::new(v_migration_transactions::Migration),
        Box::new(standalone_address::Migration),
        Box::new(fix_v_transactions_multi_account_totals::Migration),
    ]
}

/// All states of the migration DAG that have been exposed in a public crate release, in
/// the order that crate users would have encountered them.
///
/// Omitted versions had the same migration state as the first prior version that is
/// included.
#[allow(dead_code)] // marked as dead code so that this appears in docs with --document-private-items
const PUBLIC_MIGRATION_STATES: &[&[Uuid]] = &[
    V_0_4_0,
    V_0_6_0,
    V_0_7_0,
    V_0_8_0_RC1,
    V_0_8_0_RC4,
    V_0_8_0_RC5,
    V_0_8_0,
    V_0_8_1,
    V_0_9_0,
    V_0_10_0,
    V_0_10_3,
    V_0_11_0,
    V_0_11_1,
    V_0_11_2,
    V_0_12_0,
    V_0_13_0,
    V_0_14_0,
    V_0_15_0,
    V_0_16_0,
    V_0_16_2,
    V_0_16_4,
    V_0_17_0,
    V_0_17_2,
    V_0_17_3,
    V_0_18_0,
    V_0_18_5,
    V_0_19_0,
    V_0_20_0,
    V_0_22_0_RC1,
    V_0_22_0_RC2,
    V_0_22_0_RC5,
    V_0_22_0_RC6,
];

/// Leaf migrations in the 0.4.0 release.
pub const V_0_4_0: &[Uuid] = &[add_transaction_views::MIGRATION_ID];

/// Leaf migrations in the 0.6.0 release.
pub const V_0_6_0: &[Uuid] = &[v_transactions_net::MIGRATION_ID];

/// Leaf migrations in the 0.7.0 release.
pub const V_0_7_0: &[Uuid] = &[received_notes_nullable_nf::MIGRATION_ID];

/// Leaf migrations in the 0.8.0-rc.1 release.
pub const V_0_8_0_RC1: &[Uuid] = &[
    nullifier_map::MIGRATION_ID,
    sapling_memo_consistency::MIGRATION_ID,
    wallet_summaries::MIGRATION_ID,
];

/// Leaf migrations in the 0.8.0-rc.4 release.
pub const V_0_8_0_RC4: &[Uuid] = &[
    nullifier_map::MIGRATION_ID,
    v_transactions_transparent_history::MIGRATION_ID,
    wallet_summaries::MIGRATION_ID,
];

/// Leaf migrations in the 0.8.0-rc.5 release.
pub const V_0_8_0_RC5: &[Uuid] = &[
    nullifier_map::MIGRATION_ID,
    v_tx_outputs_use_legacy_false::MIGRATION_ID,
    wallet_summaries::MIGRATION_ID,
];

/// Leaf migrations in the 0.8.0 release.
pub const V_0_8_0: &[Uuid] = &[
    nullifier_map::MIGRATION_ID,
    v_transactions_shielding_balance::MIGRATION_ID,
    wallet_summaries::MIGRATION_ID,
];

/// Leaf migrations in the 0.8.1 release.
pub const V_0_8_1: &[Uuid] = &[
    nullifier_map::MIGRATION_ID,
    v_transactions_note_uniqueness::MIGRATION_ID,
    wallet_summaries::MIGRATION_ID,
];

/// Leaf migrations in the 0.9.0 release.
pub const V_0_9_0: &[Uuid] = &[
    nullifier_map::MIGRATION_ID,
    receiving_key_scopes::MIGRATION_ID,
    v_transactions_note_uniqueness::MIGRATION_ID,
    wallet_summaries::MIGRATION_ID,
];

/// Leaf migrations in the 0.10.0 release.
pub const V_0_10_0: &[Uuid] = &[
    nullifier_map::MIGRATION_ID,
    orchard_received_notes::MIGRATION_ID,
    orchard_shardtree::MIGRATION_ID,
];

/// Leaf migrations in the 0.10.3 release.
pub const V_0_10_3: &[Uuid] = &[
    ensure_orchard_ua_receiver::MIGRATION_ID,
    nullifier_map::MIGRATION_ID,
    orchard_shardtree::MIGRATION_ID,
];

/// Leaf migrations in the 0.11.0 release.
pub const V_0_11_0: &[Uuid] = &[
    ensure_orchard_ua_receiver::MIGRATION_ID,
    ephemeral_addresses::MIGRATION_ID,
    nullifier_map::MIGRATION_ID,
    orchard_shardtree::MIGRATION_ID,
    spend_key_available::MIGRATION_ID,
    tx_retrieval_queue::MIGRATION_ID,
];

/// Leaf migrations in the 0.11.1 release.
pub const V_0_11_1: &[Uuid] = &[tx_retrieval_queue::MIGRATION_ID];

/// Leaf migrations in the 0.11.2 release.
pub const V_0_11_2: &[Uuid] = &[support_legacy_sqlite::MIGRATION_ID];

/// Leaf migrations in the 0.12.0 release.
pub const V_0_12_0: &[Uuid] = &[fix_broken_commitment_trees::MIGRATION_ID];

/// Leaf migrations in the 0.13.0 release.
pub const V_0_13_0: &[Uuid] = &[fix_bad_change_flagging::MIGRATION_ID];

/// Leaf migrations in the 0.14.0 release.
pub const V_0_14_0: &[Uuid] = &[
    fix_bad_change_flagging::MIGRATION_ID,
    add_account_uuids::MIGRATION_ID,
];

/// Leaf migrations in the 0.15.0 release.
pub const V_0_15_0: &[Uuid] = &[
    fix_bad_change_flagging::MIGRATION_ID,
    v_transactions_additional_totals::MIGRATION_ID,
];

/// Leaf migrations in the 0.16.0 release.
pub const V_0_16_0: &[Uuid] = &[
    fix_bad_change_flagging::MIGRATION_ID,
    v_transactions_additional_totals::MIGRATION_ID,
    transparent_gap_limit_handling::MIGRATION_ID,
];

/// Leaf migrations in the 0.16.2 release.
pub const V_0_16_2: &[Uuid] = &[
    fix_bad_change_flagging::MIGRATION_ID,
    v_transactions_additional_totals::MIGRATION_ID,
    ensure_default_transparent_address::MIGRATION_ID,
];

/// Leaf migrations in the 0.16.4 release.
pub const V_0_16_4: &[Uuid] = &[
    fix_bad_change_flagging::MIGRATION_ID,
    v_transactions_additional_totals::MIGRATION_ID,
    ensure_default_transparent_address::MIGRATION_ID,
    tx_retrieval_queue_expiry::MIGRATION_ID,
];

/// Leaf migrations in the 0.17.0 release.
pub const V_0_17_0: &[Uuid] = &[fix_transparent_received_outputs::MIGRATION_ID];

/// Leaf migrations in the 0.17.2 release.
pub const V_0_17_2: &[Uuid] = &[
    tx_retrieval_queue_expiry::MIGRATION_ID,
    fix_transparent_received_outputs::MIGRATION_ID,
];

/// Leaf migrations in the 0.17.3 release.
pub const V_0_17_3: &[Uuid] = &[
    tx_retrieval_queue_expiry::MIGRATION_ID,
    fix_v_transactions_expired_unmined::MIGRATION_ID,
];

/// Leaf migrations in the 0.18.0 release.
pub const V_0_18_0: &[Uuid] = &[
    tx_retrieval_queue_expiry::MIGRATION_ID,
    support_zcashd_wallet_import::MIGRATION_ID,
    v_tx_outputs_return_addrs::MIGRATION_ID,
];

/// Leaf migrations in the 0.18.5 release.
pub const V_0_18_5: &[Uuid] = &[
    tx_retrieval_queue_expiry::MIGRATION_ID,
    support_zcashd_wallet_import::MIGRATION_ID,
    v_tx_outputs_return_addrs::MIGRATION_ID,
    tx_observation_height::MIGRATION_ID,
];

/// Leaf migrations in the 0.19.0 release.
pub const V_0_19_0: &[Uuid] = &[account_delete_cascade::MIGRATION_ID];

/// Leaf migrations in the 0.20.0 release.
pub const V_0_20_0: &[Uuid] = &[
    v_tx_outputs_key_scopes::MIGRATION_ID,
    ivk_item_cache::MIGRATION_ID,
    witness_stabilized_notes::MIGRATION_ID,
];

/// Leaf migrations in the 0.22.0-rc.1 release.
pub const V_0_22_0_RC1: &[Uuid] = &[
    v_tx_outputs_key_scopes::MIGRATION_ID,
    ivk_item_cache::MIGRATION_ID,
    add_transparent_receiver_address_index::MIGRATION_ID,
    add_transparent_value_index::MIGRATION_ID,
    ironwood_pool_code_views::MIGRATION_ID,
    tree_retained_checkpoints::MIGRATION_ID,
];

/// Leaf migrations in the 0.22.0-rc.2 release.
pub const V_0_22_0_RC2: &[Uuid] = &[
    v_tx_outputs_key_scopes::MIGRATION_ID,
    ivk_item_cache::MIGRATION_ID,
    add_transparent_receiver_address_index::MIGRATION_ID,
    add_transparent_value_index::MIGRATION_ID,
    ironwood_pool_code_views::MIGRATION_ID,
    orchard_ironwood_migration_tables::MIGRATION_ID,
    tree_retained_checkpoints::MIGRATION_ID,
    note_locking::MIGRATION_ID,
];

/// Leaf migrations in the 0.22.0-rc.5 release.
pub const V_0_22_0_RC5: &[Uuid] = &[
    v_tx_outputs_key_scopes::MIGRATION_ID,
    ivk_item_cache::MIGRATION_ID,
    add_transparent_receiver_address_index::MIGRATION_ID,
    add_transparent_value_index::MIGRATION_ID,
    ironwood_pool_code_views::MIGRATION_ID,
    orchard_ironwood_migration_tables::MIGRATION_ID,
    tree_retained_checkpoints::MIGRATION_ID,
    fix_bad_ironwood_change_flagging::MIGRATION_ID,
    v_address_uses_ironwood::MIGRATION_ID,
    tx_status_observation_intent::MIGRATION_ID,
];

/// Leaf migrations in the 0.22.0-rc.6 release.
pub const V_0_22_0_RC6: &[Uuid] = &[
    v_tx_outputs_transparent_addresses::MIGRATION_ID,
    ivk_item_cache::MIGRATION_ID,
    add_transparent_receiver_address_index::MIGRATION_ID,
    add_transparent_value_index::MIGRATION_ID,
    fix_bad_ironwood_change_flagging::MIGRATION_ID,
    v_address_uses_ironwood::MIGRATION_ID,
    v_transactions_pool_crossing::MIGRATION_ID,
    orchard_ironwood_migration_anchor_interval::MIGRATION_ID,
    tree_retained_checkpoints::MIGRATION_ID,
    tx_status_observation_intent::MIGRATION_ID,
];

pub(super) fn verify_network_compatibility<P: consensus::Parameters>(
    conn: &rusqlite::Connection,
    params: &P,
) -> Result<(), WalletMigrationError> {
    // This check runs before any not-yet-applied migrations for the current library version,
    // so the `accounts` table may be in any of its historical shapes, or absent entirely
    // (prior to `initial_setup`). Probe its actual columns directly, rather than keying off
    // the id of the migration that happened to introduce them, so the check states its real
    // precondition and stays correct across future migration reorganizations. Querying
    // `pragma_table_info` for a nonexistent table simply returns no rows, so a wallet with no
    // `accounts` table yet is handled the same way as one that has the table but lacks the
    // column.
    let has_column = |name: &str| -> Result<bool, WalletMigrationError> {
        Ok(conn
            .prepare("SELECT 1 FROM pragma_table_info('accounts') WHERE name = :name")?
            .exists(named_params![":name": name])?)
    };
    let has_ufvk = has_column("ufvk")?;
    let has_uivk = has_column("uivk")?;

    let network_name = |n| match n {
        consensus::NetworkType::Main => "mainnet",
        consensus::NetworkType::Test => "testnet",
        consensus::NetworkType::Regtest => "regtest",
    };
    let mismatch_err = |account_id: i64, key_kind: &str, network: consensus::NetworkType| {
        WalletMigrationError::CorruptedData(format!(
            "Network type mismatch: account {account_id} {key_kind} is for {} but attempting to initialize for {}.",
            network_name(network),
            network_name(params.network_type())
        ))
    };

    if has_uivk {
        // `ufvk` may be NULL for accounts imported by UIVK; `uivk` is otherwise always
        // present for such accounts. Validate the network of whichever key the account
        // actually stores a value for, preferring the UFVK when both are available.
        let mut stmt = conn.prepare("SELECT id, ufvk, uivk FROM accounts")?;
        let mut rows = stmt.query([])?;
        while let Some(row) = rows.next()? {
            let account_id: i64 = row.get(0)?;
            let ufvk_parsed = row
                .get::<_, Option<String>>(1)?
                .map(|ufvk_str| {
                    let (network, _) = Ufvk::decode(&ufvk_str).map_err(|e| {
                        WalletMigrationError::CorruptedData(format!(
                            "Unable to parse UFVK for account {account_id}: {e}"
                        ))
                    })?;
                    Ok::<_, WalletMigrationError>((network, "UFVK"))
                })
                .transpose()?;

            let uivk_parsed = row
                .get::<_, Option<String>>(2)?
                .map(|uivk_str| {
                    let (network, _) = Uivk::decode(&uivk_str).map_err(|e| {
                        WalletMigrationError::CorruptedData(format!(
                            "Unable to parse UIVK for account {account_id}: {e}"
                        ))
                    })?;
                    Ok::<_, WalletMigrationError>((network, "UIVK"))
                })
                .transpose()?;

            let (network, key_kind) =
                ufvk_parsed
                    .or(uivk_parsed)
                    .ok_or(WalletMigrationError::CorruptedData(
                        "account has neither a UFVK nor a UIVK".to_string(),
                    ))?;

            if network != params.network_type() {
                return Err(mismatch_err(account_id, key_kind, network));
            }
        }
    } else if has_ufvk {
        let mut fvks_stmt = conn.prepare("SELECT account, ufvk FROM accounts")?;
        let mut rows = fvks_stmt.query([])?;
        while let Some(row) = rows.next()? {
            let account_id: i64 = row.get(0)?;
            let ufvk_str = row.get::<_, String>(1)?;
            let (network, _) = Ufvk::decode(&ufvk_str).map_err(|e| {
                WalletMigrationError::CorruptedData(format!(
                    "Unable to parse UFVK for account {account_id}: {e}"
                ))
            })?;

            if network != params.network_type() {
                return Err(mismatch_err(account_id, "UFVK", network));
            }
        }
    }

    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use std::collections::HashSet;

    // Used only by the orchard-gated note-generation strategies below.
    #[cfg(feature = "orchard")]
    use proptest::{prelude::any, prop_compose};
    use rusqlite::{Connection, named_params};
    use secrecy::Secret;
    use tempfile::NamedTempFile;
    use uuid::Uuid;
    use zcash_client_backend::data_api::{
        AccountBirthday, AccountPurpose, AccountSource, chain::ChainState,
    };
    use zcash_keys::keys::{UnifiedIncomingViewingKey, UnifiedSpendingKey};
    use zcash_primitives::block::BlockHash;
    use zcash_protocol::consensus::{Network, NetworkUpgrade, Parameters};

    #[cfg(feature = "transparent-inputs")]
    use crate::GapLimits;
    use crate::{
        WalletDb,
        testing::db::{test_clock, test_rng},
        wallet::{self, init::WalletMigrator},
    };
    use schemerz::Migration;

    /// `CURRENT_LEAF_MIGRATIONS` must list exactly the leaves of the migration dependency graph
    /// (the migrations that no other migration depends on), so that migrating to the current
    /// state reaches every migration. This recomputes the leaves from the runtime migration
    /// graph and checks them against the compile-time computation, guarding against divergence
    /// between the two views of the graph.
    #[test]
    fn current_leaf_migrations_are_the_dag_leaves() {
        let migrations =
            super::all_migrations(&Network::TestNetwork, test_clock(), test_rng(), None);

        let all_ids: HashSet<Uuid> = migrations.iter().map(|m| m.id()).collect();
        let depended: HashSet<Uuid> = migrations.iter().flat_map(|m| m.dependencies()).collect();
        let computed_leaves: HashSet<Uuid> = all_ids.difference(&depended).copied().collect();

        let listed_leaves: HashSet<Uuid> = super::CURRENT_LEAF_MIGRATIONS.iter().copied().collect();
        assert_eq!(computed_leaves, listed_leaves);
    }

    /// Every migration module declared via `migration_modules!` must be registered in
    /// `all_migrations`, or the runtime migration graph would be missing migrations that the
    /// compile-time graph includes. (The converse is a compile error: a migration cannot be
    /// registered without its module being declared.)
    #[test]
    fn all_migrations_registers_every_module() {
        let migrations =
            super::all_migrations(&Network::TestNetwork, test_clock(), test_rng(), None);

        let runtime_ids: HashSet<Uuid> = migrations.iter().map(|m| m.id()).collect();
        let listed_ids: HashSet<Uuid> = super::ALL_MIGRATION_IDS.iter().copied().collect();
        assert_eq!(runtime_ids, listed_ids);
    }

    /// A synthetic set of Orchard note payload values, for exercising migrations that touch the
    /// `orchard_received_notes` table.
    ///
    /// The identity columns (`transaction_id`, `action_index`, `nf`) are assigned by the caller so
    /// that they stay unique; this strategy fuzzes only the note payload. Kept in the shared
    /// migration-test module so later migration tests can reuse it.
    #[cfg(feature = "orchard")]
    #[derive(Clone, Debug)]
    pub(crate) struct ArbOrchardNote {
        pub(crate) value: i64,
        pub(crate) diversifier: [u8; 11],
        pub(crate) rho: [u8; 32],
        pub(crate) rseed: [u8; 32],
        pub(crate) is_change: bool,
        pub(crate) memo: Option<Vec<u8>>,
    }

    #[cfg(feature = "orchard")]
    prop_compose! {
        /// A strategy generating arbitrary [`ArbOrchardNote`] payload values. Note values are
        /// constrained to the non-negative `i64` range, matching the on-chain 2^63 value bound.
        pub(crate) fn arb_orchard_note()(
            value in 0i64..=i64::MAX,
            diversifier in any::<[u8; 11]>(),
            rho in any::<[u8; 32]>(),
            rseed in any::<[u8; 32]>(),
            is_change in any::<bool>(),
            memo in proptest::option::of(proptest::collection::vec(any::<u8>(), 0..64)),
        ) -> ArbOrchardNote {
            ArbOrchardNote {
                value,
                diversifier,
                rho,
                rseed,
                is_change,
                memo,
            }
        }
    }

    /// A synthetic set of Ironwood note payload values, for exercising migrations that touch the
    /// `ironwood_received_notes` table.
    ///
    /// Ironwood notes ([ZIP 2005], NU6.3) are Orchard-protocol notes obtained from version 3 note
    /// plaintexts, so the payload columns mirror those of [`ArbOrchardNote`]; the type is kept
    /// distinct to follow Ironwood naming and to leave room for the two to diverge. The identity
    /// columns (`transaction_id`, `action_index`, `nf`) are assigned by the caller so that they
    /// stay unique; this strategy fuzzes only the note payload.
    ///
    /// [ZIP 2005]: https://zips.z.cash/zip-2005
    #[cfg(feature = "orchard")]
    #[derive(Clone, Debug)]
    pub(crate) struct ArbIronwoodNote {
        pub(crate) value: i64,
        pub(crate) diversifier: [u8; 11],
        pub(crate) rho: [u8; 32],
        pub(crate) rseed: [u8; 32],
        pub(crate) is_change: bool,
        pub(crate) memo: Option<Vec<u8>>,
    }

    #[cfg(feature = "orchard")]
    prop_compose! {
        /// A strategy generating arbitrary [`ArbIronwoodNote`] payload values. Note values are
        /// constrained to the non-negative `i64` range, matching the on-chain 2^63 value bound.
        pub(crate) fn arb_ironwood_note()(
            value in 0i64..=i64::MAX,
            diversifier in any::<[u8; 11]>(),
            rho in any::<[u8; 32]>(),
            rseed in any::<[u8; 32]>(),
            is_change in any::<bool>(),
            memo in proptest::option::of(proptest::collection::vec(any::<u8>(), 0..64)),
        ) -> ArbIronwoodNote {
            ArbIronwoodNote {
                value,
                diversifier,
                rho,
                rseed,
                is_change,
                memo,
            }
        }
    }

    /// Tests that we can migrate from a completely empty wallet database to the target
    /// migrations.
    pub(crate) fn test_migrate(migrations: &[Uuid]) {
        let data_file = NamedTempFile::new().unwrap();
        let mut db_data = WalletDb::for_path(
            data_file.path(),
            Network::TestNetwork,
            test_clock(),
            test_rng(),
        )
        .unwrap();

        let seed = [0xab; 32];
        assert_matches!(
            WalletMigrator::new()
                .with_seed(Secret::new(seed.to_vec()))
                .ignore_seed_relevance()
                .init_or_migrate_to(&mut db_data, migrations),
            Ok(_)
        );
    }

    #[test]
    fn migrate_between_releases_without_data() {
        let data_file = NamedTempFile::new().unwrap();
        let mut db_data = WalletDb::for_path(
            data_file.path(),
            Network::TestNetwork,
            test_clock(),
            test_rng(),
        )
        .unwrap();

        let seed = [0xab; 32].to_vec();

        let read_applied_state = |conn: &Connection| {
            conn.prepare_cached("SELECT * FROM schemer_migrations")
                .unwrap()
                .query_map([], |row| row.get::<_, [u8; 16]>(0).map(Uuid::from_bytes))
                .unwrap()
                .collect::<Result<HashSet<Uuid>, _>>()
                .unwrap()
        };

        let mut prev_state = HashSet::new();
        for migrations in super::PUBLIC_MIGRATION_STATES {
            // A release may target a leaf that an earlier release already applied (its
            // successors having been introduced and later superseded on a parallel branch
            // of the graph), so novelty is judged against the applied set, not against the
            // previous release's leaf list.
            let expect_change = migrations.iter().any(|m| !prev_state.contains(m));

            assert_matches!(
                WalletMigrator::new()
                    .with_seed(Secret::new(seed.clone()))
                    .ignore_seed_relevance()
                    .init_or_migrate_to(&mut db_data, migrations),
                Ok(_)
            );

            let new_state = read_applied_state(&db_data.conn);
            if expect_change {
                assert!(prev_state != new_state);
            }
            prev_state = new_state;
        }

        // Now check that we can migrate from the last public release to the current
        // migration state in this branch.
        assert_matches!(
            WalletMigrator::new()
                .with_seed(Secret::new(seed))
                .ignore_seed_relevance()
                .init_or_migrate(&mut db_data),
            Ok(_)
        );
        // We don't ensure that the migration state changed, because it may not have.
    }

    /// A UIVK-only account (one imported without a UFVK, e.g. via an incoming viewing key)
    /// stores `NULL` in the `accounts.ufvk` column. `verify_network_compatibility` must fall
    /// back to checking the network of the account's `uivk` in that case, rather than choking
    /// on the `NULL` `ufvk` as it did prior to this fix.
    ///
    /// The account is imported through the real `wallet::add_account` path a UIVK import
    /// takes (`ViewingKey::Incoming`, as in `lib.rs`'s `ivk_only_account_upgrade_paths`),
    /// against a wallet migrated only to the most recent published release rather than the
    /// crate's current (possibly unreleased) schema. This reproduces the state a real
    /// upgrading wallet is in, and, since the subsequent `init_or_migrate` call then has
    /// migrations left to apply, also confirms that those migrations tolerate a `NULL`
    /// `ufvk`.
    #[test]
    fn uivk_only_account_is_network_compatible() {
        let data_file = NamedTempFile::new().unwrap();
        let mut db_data = WalletDb::for_path(
            data_file.path(),
            Network::TestNetwork,
            test_clock(),
            test_rng(),
        )
        .unwrap();

        let seed = [0xab; 32];
        WalletMigrator::new()
            .with_seed(Secret::new(seed.to_vec()))
            .ignore_seed_relevance()
            .init_or_migrate_to(&mut db_data, super::V_0_22_0_RC6)
            .unwrap();

        let uivk =
            UnifiedSpendingKey::from_seed(&Network::TestNetwork, &seed, zip32::AccountId::ZERO)
                .unwrap()
                .to_unified_full_viewing_key()
                .to_unified_incoming_viewing_key();

        let birthday_height = Network::TestNetwork
            .activation_height(NetworkUpgrade::Sapling)
            .unwrap();
        let birthday = AccountBirthday::from_parts(
            ChainState::empty(birthday_height - 1, BlockHash([0; 32])),
            None,
        );

        db_data
            .transactionally(|wdb| {
                wallet::add_account(
                    wdb.conn.0,
                    &wdb.params,
                    "uivk-only",
                    &AccountSource::Imported {
                        purpose: AccountPurpose::ViewOnly,
                        key_source: None,
                    },
                    wallet::ViewingKey::Incoming(Box::new(uivk)),
                    &birthday,
                    #[cfg(feature = "transparent-inputs")]
                    &GapLimits::default(),
                )
            })
            .unwrap();

        // Re-running the migrator is exactly what a wallet upgrade does; it must succeed
        // rather than failing with an `InvalidColumnType` error on the NULL `ufvk`, and the
        // migrations still pending since V_0_22_0_RC6 must not choke on it either.
        assert_matches!(
            WalletMigrator::new()
                .with_seed(Secret::new(seed.to_vec()))
                .ignore_seed_relevance()
                .init_or_migrate(&mut db_data),
            Ok(())
        );
    }

    /// Pins the `has_ufvk`-but-not-`has_uivk` branch of `verify_network_compatibility`
    /// against a wallet actually carrying an account row in that era's shape, rather than
    /// only against empty databases. At `V_0_9_0`, `accounts` predates `full_account_ids`:
    /// `account` is the primary key and `ufvk` is the sole (non-nullable) viewing key column;
    /// `uivk` does not exist yet. Migrating such a wallet the rest of the way to the current
    /// schema exercises `full_account_ids` carrying real account data across the shape
    /// change, immediately after the pre-existing branch has validated it.
    #[test]
    fn ufvk_only_account_predating_uivk_column_migrates() {
        let data_file = NamedTempFile::new().unwrap();
        let mut db_data = WalletDb::for_path(
            data_file.path(),
            Network::TestNetwork,
            test_clock(),
            test_rng(),
        )
        .unwrap();

        let seed = [0xab; 32];
        WalletMigrator::new()
            .with_seed(Secret::new(seed.to_vec()))
            .ignore_seed_relevance()
            .init_or_migrate_to(&mut db_data, super::V_0_9_0)
            .unwrap();

        let ufvk =
            UnifiedSpendingKey::from_seed(&Network::TestNetwork, &seed, zip32::AccountId::ZERO)
                .unwrap()
                .to_unified_full_viewing_key();
        db_data
            .conn
            .execute(
                "INSERT INTO accounts (account, ufvk, birthday_height) VALUES (0, :ufvk, 0)",
                named_params![":ufvk": ufvk.encode(&Network::TestNetwork)],
            )
            .unwrap();

        assert_matches!(
            WalletMigrator::new()
                .with_seed(Secret::new(seed.to_vec()))
                .ignore_seed_relevance()
                .init_or_migrate(&mut db_data),
            Ok(())
        );
    }

    /// Inserts a UIVK-only account row directly, mirroring the shape `wallet::add_account`
    /// writes for an [`AccountPurpose::ViewOnly`](zcash_client_backend::data_api::AccountPurpose)
    /// import: `account_kind = 1` (imported), no HD derivation metadata, and a `NULL` `ufvk`.
    /// This bypasses `add_account` itself, which is not usable here: it always encodes the
    /// stored `uivk` with the wallet's own [`consensus::Parameters`], so it structurally
    /// cannot produce a row whose key is encoded for a different network. The IVK-cache
    /// columns are deliberately left `NULL`; they are irrelevant to
    /// `verify_network_compatibility`, so this is not a faithful general-purpose account
    /// fixture.
    fn insert_uivk_only_account(
        conn: &Connection,
        uuid: [u8; 16],
        uivk: &UnifiedIncomingViewingKey,
        uivk_network: &Network,
    ) {
        conn.execute(
            "INSERT INTO accounts (uuid, account_kind, ufvk, uivk, has_spend_key, birthday_height)
             VALUES (:uuid, :account_kind, NULL, :uivk, 0, :birthday_height)",
            named_params![
                ":uuid": &uuid[..],
                ":account_kind": 1,
                ":uivk": uivk.encode(uivk_network),
                ":birthday_height": 0,
            ],
        )
        .unwrap();
    }

    /// A UIVK-only account whose stored `uivk` was encoded for a different network must still
    /// be caught by `verify_network_compatibility`, exactly as a `ufvk`-bearing account is.
    #[test]
    fn uivk_only_account_network_mismatch_is_rejected() {
        let data_file = NamedTempFile::new().unwrap();
        let mut db_data = WalletDb::for_path(
            data_file.path(),
            Network::TestNetwork,
            test_clock(),
            test_rng(),
        )
        .unwrap();

        let seed = [0xab; 32];
        WalletMigrator::new()
            .with_seed(Secret::new(seed.to_vec()))
            .ignore_seed_relevance()
            .init_or_migrate(&mut db_data)
            .unwrap();

        // Encode the account's `uivk` for mainnet while the wallet itself is testnet.
        let uivk =
            UnifiedSpendingKey::from_seed(&Network::MainNetwork, &seed, zip32::AccountId::ZERO)
                .unwrap()
                .to_unified_full_viewing_key()
                .to_unified_incoming_viewing_key();
        insert_uivk_only_account(&db_data.conn, [7; 16], &uivk, &Network::MainNetwork);

        assert_matches!(
            WalletMigrator::new()
                .with_seed(Secret::new(seed.to_vec()))
                .ignore_seed_relevance()
                .init_or_migrate(&mut db_data),
            Err(schemerz::MigratorError::Adapter(
                super::WalletMigrationError::CorruptedData(msg)
            )) if msg.contains("UIVK")
        );
    }
}
