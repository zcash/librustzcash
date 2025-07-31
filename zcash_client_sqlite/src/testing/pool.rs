//! Test logic involving a single shielded pool.
//!
//! Generalised for sharing across the Sapling and Orchard implementations.

use crate::{
    testing::{db::TestDbFactory, BlockCache},
    SAPLING_TABLES_PREFIX,
};
use zcash_client_backend::data_api::testing::{
    pool::ShieldedPoolTester, sapling::SaplingPoolTester,
};

#[cfg(feature = "orchard")]
use {
    crate::ORCHARD_TABLES_PREFIX,
    zcash_client_backend::data_api::testing::orchard::OrchardPoolTester,
};

pub(crate) trait ShieldedPoolPersistence {
    const TABLES_PREFIX: &'static str;
}

impl ShieldedPoolPersistence for SaplingPoolTester {
    const TABLES_PREFIX: &'static str = SAPLING_TABLES_PREFIX;
}

#[cfg(feature = "orchard")]
impl ShieldedPoolPersistence for OrchardPoolTester {
    const TABLES_PREFIX: &'static str = ORCHARD_TABLES_PREFIX;
}

pub(crate) fn send_single_step_proposed_transfer<T: ShieldedPoolTester>() {
    zcash_client_backend::data_api::testing::pool::send_single_step_proposed_transfer::<T>(
        TestDbFactory::default(),
        BlockCache::new(),
    )
}

pub(crate) fn send_with_multiple_change_outputs<T: ShieldedPoolTester>() {
    zcash_client_backend::data_api::testing::pool::send_with_multiple_change_outputs::<T>(
        TestDbFactory::default(),
        BlockCache::new(),
    )
}

#[cfg(feature = "transparent-inputs")]
pub(crate) fn send_multi_step_proposed_transfer<T: ShieldedPoolTester>() {
    zcash_client_backend::data_api::testing::pool::send_multi_step_proposed_transfer::<T, _>(
        TestDbFactory::default(),
        BlockCache::new(),
        |e, _, expected_bad_index| {
            matches!(
                e,
                crate::error::SqliteClientError::ReachedGapLimit(_, bad_index)
                if bad_index == &expected_bad_index)
        },
    )
}

#[cfg(feature = "transparent-inputs")]
pub(crate) fn proposal_fails_if_not_all_ephemeral_outputs_consumed<T: ShieldedPoolTester>() {
    zcash_client_backend::data_api::testing::pool::proposal_fails_if_not_all_ephemeral_outputs_consumed::<T, _>(
        TestDbFactory::default(),
        BlockCache::new(),
    )
}

pub(crate) fn create_to_address_fails_on_incorrect_usk<T: ShieldedPoolTester>() {
    zcash_client_backend::data_api::testing::pool::create_to_address_fails_on_incorrect_usk::<T, _>(
        TestDbFactory::default(),
    )
}

pub(crate) fn proposal_fails_with_no_blocks<T: ShieldedPoolTester>() {
    zcash_client_backend::data_api::testing::pool::proposal_fails_with_no_blocks::<T, _>(
        TestDbFactory::default(),
    )
}

pub(crate) fn spend_fails_on_unverified_notes<T: ShieldedPoolTester>() {
    zcash_client_backend::data_api::testing::pool::spend_fails_on_unverified_notes::<T>(
        TestDbFactory::default(),
        BlockCache::new(),
    )
}

pub(crate) fn spend_fails_on_locked_notes<T: ShieldedPoolTester>() {
    zcash_client_backend::data_api::testing::pool::spend_fails_on_locked_notes::<T>(
        TestDbFactory::default(),
        BlockCache::new(),
    )
}

pub(crate) fn ovk_policy_prevents_recovery_from_chain<T: ShieldedPoolTester>() {
    zcash_client_backend::data_api::testing::pool::ovk_policy_prevents_recovery_from_chain::<T, _>(
        TestDbFactory::default(),
        BlockCache::new(),
    )
}

pub(crate) fn spend_succeeds_to_t_addr_zero_change<T: ShieldedPoolTester>() {
    zcash_client_backend::data_api::testing::pool::spend_succeeds_to_t_addr_zero_change::<T>(
        TestDbFactory::default(),
        BlockCache::new(),
    )
}

pub(crate) fn change_note_spends_succeed<T: ShieldedPoolTester>() {
    zcash_client_backend::data_api::testing::pool::change_note_spends_succeed::<T>(
        TestDbFactory::default(),
        BlockCache::new(),
    )
}

pub(crate) fn external_address_change_spends_detected_in_restore_from_seed<
    T: ShieldedPoolTester,
>() {
    zcash_client_backend::data_api::testing::pool::external_address_change_spends_detected_in_restore_from_seed::<T, _>(
        TestDbFactory::default(),
        BlockCache::new(),
    )
}

#[allow(dead_code)]
pub(crate) fn zip317_spend<T: ShieldedPoolTester>() {
    zcash_client_backend::data_api::testing::pool::zip317_spend::<T, _>(
        TestDbFactory::default(),
        BlockCache::new(),
    )
}

#[cfg(feature = "transparent-inputs")]
pub(crate) fn shield_transparent<T: ShieldedPoolTester>() {
    zcash_client_backend::data_api::testing::pool::shield_transparent::<T, _>(
        TestDbFactory::default(),
        BlockCache::new(),
    )
}

// FIXME: This requires fixes to the test framework.
#[allow(dead_code)]
pub(crate) fn birthday_in_anchor_shard<T: ShieldedPoolTester>() {
    zcash_client_backend::data_api::testing::pool::birthday_in_anchor_shard::<T>(
        TestDbFactory::default(),
        BlockCache::new(),
    )
}

pub(crate) fn checkpoint_gaps<T: ShieldedPoolTester>() {
    zcash_client_backend::data_api::testing::pool::checkpoint_gaps::<T, _>(
        TestDbFactory::default(),
        BlockCache::new(),
    )
}

#[cfg(feature = "orchard")]
pub(crate) fn pool_crossing_required<P0: ShieldedPoolTester, P1: ShieldedPoolTester>() {
    zcash_client_backend::data_api::testing::pool::pool_crossing_required::<P0, P1>(
        TestDbFactory::default(),
        BlockCache::new(),
    )
}

#[cfg(feature = "orchard")]
pub(crate) fn fully_funded_fully_private<P0: ShieldedPoolTester, P1: ShieldedPoolTester>() {
    zcash_client_backend::data_api::testing::pool::fully_funded_fully_private::<P0, P1>(
        TestDbFactory::default(),
        BlockCache::new(),
    )
}

#[cfg(all(feature = "orchard", feature = "transparent-inputs"))]
pub(crate) fn fully_funded_send_to_t<P0: ShieldedPoolTester, P1: ShieldedPoolTester>() {
    zcash_client_backend::data_api::testing::pool::fully_funded_send_to_t::<P0, P1>(
        TestDbFactory::default(),
        BlockCache::new(),
    )
}

#[cfg(feature = "orchard")]
pub(crate) fn multi_pool_checkpoint<P0: ShieldedPoolTester, P1: ShieldedPoolTester>() {
    zcash_client_backend::data_api::testing::pool::multi_pool_checkpoint::<P0, P1>(
        TestDbFactory::default(),
        BlockCache::new(),
    )
}

#[cfg(feature = "orchard")]
pub(crate) fn multi_pool_checkpoints_with_pruning<
    P0: ShieldedPoolTester,
    P1: ShieldedPoolTester,
>() {
    zcash_client_backend::data_api::testing::pool::multi_pool_checkpoints_with_pruning::<P0, P1>(
        TestDbFactory::default(),
        BlockCache::new(),
    )
}

pub(crate) fn valid_chain_states<T: ShieldedPoolTester>() {
    zcash_client_backend::data_api::testing::pool::valid_chain_states::<T>(
        TestDbFactory::default(),
        BlockCache::new(),
    )
}

// FIXME: This requires fixes to the test framework.
#[allow(dead_code)]
pub(crate) fn invalid_chain_cache_disconnected<T: ShieldedPoolTester>() {
    zcash_client_backend::data_api::testing::pool::invalid_chain_cache_disconnected::<T>(
        TestDbFactory::default(),
        BlockCache::new(),
    )
}

pub(crate) fn data_db_truncation<T: ShieldedPoolTester>() {
    zcash_client_backend::data_api::testing::pool::data_db_truncation::<T, _>(
        TestDbFactory::default(),
        BlockCache::new(),
    )
}

pub(crate) fn reorg_to_checkpoint<T: ShieldedPoolTester>() {
    zcash_client_backend::data_api::testing::pool::reorg_to_checkpoint::<T, _, _>(
        TestDbFactory::default(),
        BlockCache::new(),
    )
}

pub(crate) fn scan_cached_blocks_allows_blocks_out_of_order<T: ShieldedPoolTester>() {
    zcash_client_backend::data_api::testing::pool::scan_cached_blocks_allows_blocks_out_of_order::<T>(
        TestDbFactory::default(),
        BlockCache::new(),
    )
}

pub(crate) fn scan_cached_blocks_finds_received_notes<T: ShieldedPoolTester>() {
    zcash_client_backend::data_api::testing::pool::scan_cached_blocks_finds_received_notes::<T, _>(
        TestDbFactory::default(),
        BlockCache::new(),
    )
}

// TODO: This test can probably be entirely removed, as the following test duplicates it entirely.
pub(crate) fn scan_cached_blocks_finds_change_notes<T: ShieldedPoolTester>() {
    zcash_client_backend::data_api::testing::pool::scan_cached_blocks_finds_change_notes::<T, _>(
        TestDbFactory::default(),
        BlockCache::new(),
    )
}

pub(crate) fn scan_cached_blocks_detects_spends_out_of_order<T: ShieldedPoolTester>() {
    zcash_client_backend::data_api::testing::pool::scan_cached_blocks_detects_spends_out_of_order::<
        T,
        _,
    >(TestDbFactory::default(), BlockCache::new())
}

pub(crate) fn metadata_queries_exclude_unwanted_notes<T: ShieldedPoolTester>() {
    zcash_client_backend::data_api::testing::pool::metadata_queries_exclude_unwanted_notes::<T, _, _>(
        TestDbFactory::default(),
        BlockCache::new(),
    )
}

#[cfg(feature = "pczt-tests")]
pub(crate) fn pczt_single_step<P0: ShieldedPoolTester, P1: ShieldedPoolTester>() {
    zcash_client_backend::data_api::testing::pool::pczt_single_step::<P0, P1, _>(
        TestDbFactory::default(),
        BlockCache::new(),
    )
}

#[cfg(feature = "transparent-inputs")]
pub(crate) fn wallet_recovery_computes_fees<T: ShieldedPoolTester>() {
    use rusqlite::named_params;

    zcash_client_backend::data_api::testing::pool::wallet_recovery_computes_fees::<T, _>(
        TestDbFactory::default(),
        BlockCache::new(),
        |db, txid| {
            db.db_mut().conn.execute(
                "UPDATE transactions
                 SET fee = NULL
                 WHERE txid = :txid",
                named_params! {
                     ":txid": txid.as_ref(),
                },
            )?;
            Ok(())
        },
    )
}

pub(crate) fn can_spend_inputs_by_confirmations_policy<T: ShieldedPoolTester>() {
    for is_trusted in [false, true] {
        zcash_client_backend::data_api::testing::pool::zip_315_confirmations_test_steps::<T>(
            TestDbFactory::default(),
            BlockCache::new(),
            is_trusted,
        );
    }
}
