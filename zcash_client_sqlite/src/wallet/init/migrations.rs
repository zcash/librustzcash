//! Migrations for the `zcash_client_sqlite` wallet database.
//!
//! The constants in this module cover all states of the migration DAG that have been
//! exposed in a public crate release, in the order that crate users would have
//! encountered them.
//!
//! Omitted versions had the same migration state as the first prior version that is
//! included.

mod account_delete_cascade;
mod add_account_birthdays;
mod add_account_uuids;
mod add_transaction_trust_marker;
mod add_transaction_views;
mod add_transparent_receiver_address_index;
mod add_transparent_value_index;
mod add_utxo_account;
mod addresses_table;
mod ensure_default_transparent_address;
mod ensure_orchard_ua_receiver;
mod ephemeral_addresses;
mod fix_bad_change_flagging;
mod fix_bad_ironwood_change_flagging;
mod fix_broken_commitment_trees;
mod fix_transparent_received_outputs;
mod fix_v_transactions_expired_unmined;
mod full_account_ids;
mod initial_setup;
mod ironwood_pool_code_views;
mod ironwood_received_notes;
mod ironwood_shardtree;
mod ivk_item_cache;
mod note_locking;
mod nullifier_map;
mod orchard_ironwood_migration_anchor_interval;
mod orchard_ironwood_migration_tables;
mod orchard_note_version;
mod orchard_received_notes;
mod orchard_shardtree;
mod received_notes_nullable_nf;
mod receiving_key_scopes;
mod sapling_memo_consistency;
mod sent_notes_to_internal;
mod shardtree_support;
mod spend_key_available;
mod standalone_p2sh;
mod support_legacy_sqlite;
mod support_zcashd_wallet_import;
mod transparent_gap_limit_handling;
mod tree_retained_checkpoints;
mod tx_observation_height;
mod tx_retrieval_queue;
mod tx_retrieval_queue_expiry;
mod tx_status_observation_intent;
mod ufvk_support;
mod utxos_table;
mod utxos_to_txos;
mod v_address_uses_ironwood;
mod v_received_output_spends_account;
mod v_sapling_shard_unscanned_ranges;
mod v_transactions_additional_totals;
mod v_transactions_net;
mod v_transactions_note_uniqueness;
mod v_transactions_pool_crossing;
mod v_transactions_shielding_balance;
mod v_transactions_transparent_history;
mod v_tx_outputs_key_scopes;
mod v_tx_outputs_return_addrs;
mod v_tx_outputs_transparent_addresses;
mod v_tx_outputs_use_legacy_false;
mod wallet_summaries;
mod witness_stabilized_notes;

use std::{rc::Rc, sync::Mutex};

use rand_core::RngCore;
use rusqlite::{OptionalExtension, named_params};
use schemerz_rusqlite::RusqliteMigration;
use secrecy::SecretVec;
use uuid::Uuid;
use zcash_address::unified::{Encoding as _, Ufvk};
use zcash_protocol::consensus;

use crate::util::Clock;

use super::WalletMigrationError;

/// Identifiers of the individual migrations that make up this crate's internal migration graph.
///
/// External migrations registered via
/// [`WalletMigrator::with_external_migrations`] are applied as part of a single graph alongside
/// the internal ones, so an external migration that reads or extends internal schema must
/// declare a dependency that orders it after the migration which creates that schema.
///
/// These identifiers are unstable by nature, which is why they sit behind the `unstable`
/// feature: each names an individual migration rather than a state of the graph that a
/// published release exposed, so the set of them, and which of them are reachable, changes
/// between releases. A release constant such as [`V_0_19_0`] carries no such risk. The
/// intended shape is therefore to depend on an identifier here while developing against
/// unreleased schema, and to move the anchor to the release constant that covers it once
/// that release exists.
///
/// Depending on an identifier here only orders your migration *after* the named one; it does
/// not prevent later internal migrations from being applied before yours.
///
/// [`WalletMigrator::with_external_migrations`]: super::WalletMigrator::with_external_migrations
#[cfg(feature = "unstable")]
pub mod ids {
    pub use super::account_delete_cascade::MIGRATION_ID as ACCOUNT_DELETE_CASCADE;
    pub use super::add_account_birthdays::MIGRATION_ID as ADD_ACCOUNT_BIRTHDAYS;
    pub use super::add_account_uuids::MIGRATION_ID as ADD_ACCOUNT_UUIDS;
    pub use super::add_transaction_trust_marker::MIGRATION_ID as ADD_TRANSACTION_TRUST_MARKER;
    pub use super::add_transaction_views::MIGRATION_ID as ADD_TRANSACTION_VIEWS;
    pub use super::add_transparent_receiver_address_index::MIGRATION_ID as ADD_TRANSPARENT_RECEIVER_ADDRESS_INDEX;
    pub use super::add_transparent_value_index::MIGRATION_ID as ADD_TRANSPARENT_VALUE_INDEX;
    pub use super::add_utxo_account::MIGRATION_ID as ADD_UTXO_ACCOUNT;
    pub use super::addresses_table::MIGRATION_ID as ADDRESSES_TABLE;
    pub use super::ensure_default_transparent_address::MIGRATION_ID as ENSURE_DEFAULT_TRANSPARENT_ADDRESS;
    pub use super::ensure_orchard_ua_receiver::MIGRATION_ID as ENSURE_ORCHARD_UA_RECEIVER;
    pub use super::ephemeral_addresses::MIGRATION_ID as EPHEMERAL_ADDRESSES;
    pub use super::fix_bad_change_flagging::MIGRATION_ID as FIX_BAD_CHANGE_FLAGGING;
    pub use super::fix_bad_ironwood_change_flagging::MIGRATION_ID as FIX_BAD_IRONWOOD_CHANGE_FLAGGING;
    pub use super::fix_broken_commitment_trees::MIGRATION_ID as FIX_BROKEN_COMMITMENT_TREES;
    pub use super::fix_transparent_received_outputs::MIGRATION_ID as FIX_TRANSPARENT_RECEIVED_OUTPUTS;
    pub use super::fix_v_transactions_expired_unmined::MIGRATION_ID as FIX_V_TRANSACTIONS_EXPIRED_UNMINED;
    pub use super::full_account_ids::MIGRATION_ID as FULL_ACCOUNT_IDS;
    pub use super::initial_setup::MIGRATION_ID as INITIAL_SETUP;
    pub use super::ironwood_pool_code_views::MIGRATION_ID as IRONWOOD_POOL_CODE_VIEWS;
    pub use super::ironwood_received_notes::MIGRATION_ID as IRONWOOD_RECEIVED_NOTES;
    pub use super::ironwood_shardtree::MIGRATION_ID as IRONWOOD_SHARDTREE;
    pub use super::ivk_item_cache::MIGRATION_ID as IVK_ITEM_CACHE;
    pub use super::note_locking::MIGRATION_ID as NOTE_LOCKING;
    pub use super::nullifier_map::MIGRATION_ID as NULLIFIER_MAP;
    pub use super::orchard_ironwood_migration_anchor_interval::MIGRATION_ID as ORCHARD_IRONWOOD_MIGRATION_ANCHOR_INTERVAL;
    pub use super::orchard_ironwood_migration_tables::MIGRATION_ID as ORCHARD_IRONWOOD_MIGRATION_TABLES;
    pub use super::orchard_note_version::MIGRATION_ID as ORCHARD_NOTE_VERSION;
    pub use super::orchard_received_notes::MIGRATION_ID as ORCHARD_RECEIVED_NOTES;
    pub use super::orchard_shardtree::MIGRATION_ID as ORCHARD_SHARDTREE;
    pub use super::received_notes_nullable_nf::MIGRATION_ID as RECEIVED_NOTES_NULLABLE_NF;
    pub use super::receiving_key_scopes::MIGRATION_ID as RECEIVING_KEY_SCOPES;
    pub use super::sapling_memo_consistency::MIGRATION_ID as SAPLING_MEMO_CONSISTENCY;
    pub use super::sent_notes_to_internal::MIGRATION_ID as SENT_NOTES_TO_INTERNAL;
    pub use super::shardtree_support::MIGRATION_ID as SHARDTREE_SUPPORT;
    pub use super::spend_key_available::MIGRATION_ID as SPEND_KEY_AVAILABLE;
    pub use super::standalone_p2sh::MIGRATION_ID as STANDALONE_P2SH;
    pub use super::support_legacy_sqlite::MIGRATION_ID as SUPPORT_LEGACY_SQLITE;
    pub use super::support_zcashd_wallet_import::MIGRATION_ID as SUPPORT_ZCASHD_WALLET_IMPORT;
    pub use super::transparent_gap_limit_handling::MIGRATION_ID as TRANSPARENT_GAP_LIMIT_HANDLING;
    pub use super::tree_retained_checkpoints::MIGRATION_ID as TREE_RETAINED_CHECKPOINTS;
    pub use super::tx_observation_height::MIGRATION_ID as TX_OBSERVATION_HEIGHT;
    pub use super::tx_retrieval_queue::MIGRATION_ID as TX_RETRIEVAL_QUEUE;
    pub use super::tx_retrieval_queue_expiry::MIGRATION_ID as TX_RETRIEVAL_QUEUE_EXPIRY;
    pub use super::tx_status_observation_intent::MIGRATION_ID as TX_STATUS_OBSERVATION_INTENT;
    pub use super::ufvk_support::MIGRATION_ID as UFVK_SUPPORT;
    pub use super::utxos_table::MIGRATION_ID as UTXOS_TABLE;
    pub use super::utxos_to_txos::MIGRATION_ID as UTXOS_TO_TXOS;
    pub use super::v_address_uses_ironwood::MIGRATION_ID as V_ADDRESS_USES_IRONWOOD;
    pub use super::v_received_output_spends_account::MIGRATION_ID as V_RECEIVED_OUTPUT_SPENDS_ACCOUNT;
    pub use super::v_sapling_shard_unscanned_ranges::MIGRATION_ID as V_SAPLING_SHARD_UNSCANNED_RANGES;
    pub use super::v_transactions_additional_totals::MIGRATION_ID as V_TRANSACTIONS_ADDITIONAL_TOTALS;
    pub use super::v_transactions_net::MIGRATION_ID as V_TRANSACTIONS_NET;
    pub use super::v_transactions_note_uniqueness::MIGRATION_ID as V_TRANSACTIONS_NOTE_UNIQUENESS;
    pub use super::v_transactions_pool_crossing::MIGRATION_ID as V_TRANSACTIONS_POOL_CROSSING;
    pub use super::v_transactions_shielding_balance::MIGRATION_ID as V_TRANSACTIONS_SHIELDING_BALANCE;
    pub use super::v_transactions_transparent_history::MIGRATION_ID as V_TRANSACTIONS_TRANSPARENT_HISTORY;
    pub use super::v_tx_outputs_key_scopes::MIGRATION_ID as V_TX_OUTPUTS_KEY_SCOPES;
    pub use super::v_tx_outputs_return_addrs::MIGRATION_ID as V_TX_OUTPUTS_RETURN_ADDRS;
    pub use super::v_tx_outputs_transparent_addresses::MIGRATION_ID as V_TX_OUTPUTS_TRANSPARENT_ADDRESSES;
    pub use super::v_tx_outputs_use_legacy_false::MIGRATION_ID as V_TX_OUTPUTS_USE_LEGACY_FALSE;
    pub use super::wallet_summaries::MIGRATION_ID as WALLET_SUMMARIES;
    pub use super::witness_stabilized_notes::MIGRATION_ID as WITNESS_STABILIZED_NOTES;
}

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
    //                             |                                                 \
    //                             |                                        ironwood_received_notes ----------------
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
        Box::new(orchard_ironwood_migration_tables::Migration),
        Box::new(tree_retained_checkpoints::Migration),
        Box::new(note_locking::Migration),
        Box::new(tx_status_observation_intent::Migration),
        Box::new(orchard_ironwood_migration_anchor_interval::Migration),
        Box::new(v_tx_outputs_transparent_addresses::Migration),
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
    V_0_8_0,
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
    V_0_17_2,
    V_0_17_3,
    V_0_18_0,
    V_0_18_5,
    V_0_19_0,
    V_0_20_0,
    V_0_22_0_RC1,
    V_0_22_0_RC2,
];

/// Leaf migrations in the 0.4.0 release.
pub const V_0_4_0: &[Uuid] = &[add_transaction_views::MIGRATION_ID];

/// Leaf migrations in the 0.6.0 release.
pub const V_0_6_0: &[Uuid] = &[v_transactions_net::MIGRATION_ID];

/// Leaf migrations in the 0.8.0 release.
pub const V_0_8_0: &[Uuid] = &[
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

/// Leaf migrations as of the current repository state.
pub const CURRENT_LEAF_MIGRATIONS: &[Uuid] = &[
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
    // Ensure that the `ufvk_support` migration has been applied; if it hasn't, we won't be able to
    // validate that the UFVKs in the wallet correspond to the network type that the wallet is
    // being migrated for.
    let has_ufvk = conn
        .query_row(
            &format!(
                "SELECT 1 FROM {} WHERE id = :migration_id",
                super::MIGRATIONS_TABLE
            ),
            named_params![":migration_id": &ufvk_support::MIGRATION_ID.as_bytes()[..]],
            |row| row.get::<_, bool>(0),
        )
        .optional()?
        == Some(true);

    if has_ufvk {
        let mut fvks_stmt = conn.prepare("SELECT ufvk FROM accounts")?;
        let mut rows = fvks_stmt.query([])?;
        while let Some(row) = rows.next()? {
            let ufvk_str = row.get::<_, String>(0)?;
            let (network, _) = Ufvk::decode(&ufvk_str).map_err(|e| {
                WalletMigrationError::CorruptedData(format!("Unable to parse UFVK: {e}"))
            })?;

            if network != params.network_type() {
                let network_name = |n| match n {
                    consensus::NetworkType::Main => "mainnet",
                    consensus::NetworkType::Test => "testnet",
                    consensus::NetworkType::Regtest => "regtest",
                };
                return Err(WalletMigrationError::CorruptedData(format!(
                    "Network type mismatch: account UFVK is for {} but attempting to initialize for {}.",
                    network_name(network),
                    network_name(params.network_type())
                )));
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
    use proptest::prelude::any;
    #[cfg(feature = "orchard")]
    use proptest::prop_compose;
    use rusqlite::Connection;
    use secrecy::Secret;
    use tempfile::NamedTempFile;
    use uuid::Uuid;
    use zcash_protocol::consensus::Network;

    use crate::{
        WalletDb,
        testing::db::{test_clock, test_rng},
        wallet::init::WalletMigrator,
    };

    /// `CURRENT_LEAF_MIGRATIONS` must list exactly the leaves of the migration dependency graph
    /// (the migrations that no other migration depends on), so that migrating to the current
    /// state reaches every migration. This recomputes the leaves from the graph and checks them
    /// against the constant, so a newly added migration that supersedes an existing leaf cannot
    /// silently leave a stale entry behind.
    #[test]
    fn current_leaf_migrations_are_the_dag_leaves() {
        use schemerz::Migration;

        let migrations =
            super::all_migrations(&Network::TestNetwork, test_clock(), test_rng(), None);

        let all_ids: HashSet<Uuid> = migrations.iter().map(|m| m.id()).collect();
        let depended: HashSet<Uuid> = migrations.iter().flat_map(|m| m.dependencies()).collect();
        let computed_leaves: HashSet<Uuid> = all_ids.difference(&depended).copied().collect();

        let listed_leaves: HashSet<Uuid> = super::CURRENT_LEAF_MIGRATIONS.iter().copied().collect();
        assert_eq!(computed_leaves, listed_leaves);
    }

    /// Every migration in the graph must have a publicly-exported identifier, so that an
    /// external migration can always anchor itself precisely. Listing them here rather than
    /// deriving them means a migration added without an `ids` entry fails this test.
    #[test]
    #[cfg(feature = "unstable")]
    fn ids_module_covers_every_migration() {
        use super::ids;
        use schemerz::Migration;

        let exported: HashSet<Uuid> = HashSet::from([
            ids::ACCOUNT_DELETE_CASCADE,
            ids::ADD_ACCOUNT_BIRTHDAYS,
            ids::ADD_ACCOUNT_UUIDS,
            ids::ADD_TRANSACTION_TRUST_MARKER,
            ids::ADD_TRANSACTION_VIEWS,
            ids::ADD_TRANSPARENT_RECEIVER_ADDRESS_INDEX,
            ids::ADD_TRANSPARENT_VALUE_INDEX,
            ids::ADD_UTXO_ACCOUNT,
            ids::ADDRESSES_TABLE,
            ids::ENSURE_DEFAULT_TRANSPARENT_ADDRESS,
            ids::ENSURE_ORCHARD_UA_RECEIVER,
            ids::EPHEMERAL_ADDRESSES,
            ids::FIX_BAD_CHANGE_FLAGGING,
            ids::FIX_BAD_IRONWOOD_CHANGE_FLAGGING,
            ids::FIX_BROKEN_COMMITMENT_TREES,
            ids::FIX_TRANSPARENT_RECEIVED_OUTPUTS,
            ids::FIX_V_TRANSACTIONS_EXPIRED_UNMINED,
            ids::FULL_ACCOUNT_IDS,
            ids::INITIAL_SETUP,
            ids::IRONWOOD_POOL_CODE_VIEWS,
            ids::IRONWOOD_RECEIVED_NOTES,
            ids::IRONWOOD_SHARDTREE,
            ids::IVK_ITEM_CACHE,
            ids::NOTE_LOCKING,
            ids::NULLIFIER_MAP,
            ids::ORCHARD_IRONWOOD_MIGRATION_ANCHOR_INTERVAL,
            ids::ORCHARD_IRONWOOD_MIGRATION_TABLES,
            ids::ORCHARD_NOTE_VERSION,
            ids::ORCHARD_RECEIVED_NOTES,
            ids::ORCHARD_SHARDTREE,
            ids::RECEIVED_NOTES_NULLABLE_NF,
            ids::RECEIVING_KEY_SCOPES,
            ids::SAPLING_MEMO_CONSISTENCY,
            ids::SENT_NOTES_TO_INTERNAL,
            ids::SHARDTREE_SUPPORT,
            ids::SPEND_KEY_AVAILABLE,
            ids::STANDALONE_P2SH,
            ids::SUPPORT_LEGACY_SQLITE,
            ids::SUPPORT_ZCASHD_WALLET_IMPORT,
            ids::TRANSPARENT_GAP_LIMIT_HANDLING,
            ids::TREE_RETAINED_CHECKPOINTS,
            ids::TX_OBSERVATION_HEIGHT,
            ids::TX_RETRIEVAL_QUEUE,
            ids::TX_RETRIEVAL_QUEUE_EXPIRY,
            ids::TX_STATUS_OBSERVATION_INTENT,
            ids::UFVK_SUPPORT,
            ids::UTXOS_TABLE,
            ids::UTXOS_TO_TXOS,
            ids::V_ADDRESS_USES_IRONWOOD,
            ids::V_RECEIVED_OUTPUT_SPENDS_ACCOUNT,
            ids::V_SAPLING_SHARD_UNSCANNED_RANGES,
            ids::V_TRANSACTIONS_ADDITIONAL_TOTALS,
            ids::V_TRANSACTIONS_NET,
            ids::V_TRANSACTIONS_NOTE_UNIQUENESS,
            ids::V_TRANSACTIONS_POOL_CROSSING,
            ids::V_TRANSACTIONS_SHIELDING_BALANCE,
            ids::V_TRANSACTIONS_TRANSPARENT_HISTORY,
            ids::V_TX_OUTPUTS_KEY_SCOPES,
            ids::V_TX_OUTPUTS_RETURN_ADDRS,
            ids::V_TX_OUTPUTS_TRANSPARENT_ADDRESSES,
            ids::V_TX_OUTPUTS_USE_LEGACY_FALSE,
            ids::WALLET_SUMMARIES,
            ids::WITNESS_STABILIZED_NOTES,
        ]);

        let migrations =
            super::all_migrations(&Network::TestNetwork, test_clock(), test_rng(), None);
        let all_ids: HashSet<Uuid> = migrations.iter().map(|m| m.id()).collect();

        assert_eq!(all_ids, exported);
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
                WalletMigrator::new()
                    .with_seed(Secret::new(seed.clone()))
                    .ignore_seed_relevance()
                    .init_or_migrate_to(&mut db_data, migrations),
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
            WalletMigrator::new()
                .with_seed(Secret::new(seed))
                .ignore_seed_relevance()
                .init_or_migrate(&mut db_data),
            Ok(_)
        );
        // We don't ensure that the migration state changed, because it may not have.
    }
}
