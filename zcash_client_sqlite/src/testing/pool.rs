//! Test logic involving a single shielded pool.
//!
//! Generalised for sharing across the Sapling and Orchard implementations.

use core::num::{NonZeroU8, NonZeroU32};
use std::convert::Infallible;

use incrementalmerkletree::frontier::Frontier;
use zcash_primitives::block::BlockHash;

use crate::{
    SAPLING_TABLES_PREFIX,
    error::SqliteClientError,
    testing::{BlockCache, db::TestDbFactory},
    wallet::{
        common::unscanned_tip_exists,
        get_target_and_anchor_heights,
        scanning::{priority_code, suggest_scan_ranges},
    },
};
use zcash_client_backend::{
    data_api::{
        Account as _, TargetValue, WalletWrite,
        anchor_retention::AnchorRetentionInterval,
        chain::{ChainState, CommitmentTreeRoot, error::Error},
        scanning::{ScanPriority, spanning_tree::testing::scan_range},
        testing::{
            AddressType, InitialChainState, TestBuilder,
            pool::{
                InputTrust, ShieldedPoolTester,
                dsl::{TestDsl, TestScenario},
            },
            sapling::SaplingPoolTester,
        },
        wallet::{ConfirmationsPolicy, TargetHeight},
    },
    fees::StandardFeeRule,
    wallet::OvkPolicy,
};

#[cfg(feature = "transparent-inputs")]
use rusqlite::named_params;
use zcash_protocol::{
    consensus::{BlockHeight, NetworkUpgrade, Parameters},
    value::Zatoshis,
};
#[cfg(feature = "orchard")]
use {
    crate::ORCHARD_TABLES_PREFIX,
    zcash_client_backend::data_api::testing::orchard::OrchardPoolTester,
    zcash_protocol::ShieldedPool,
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

pub(crate) fn scan_full_block_detects_outputs<T: ShieldedPoolTester>() {
    zcash_client_backend::data_api::testing::pool::scan_full_block_detects_outputs::<T>(
        TestDbFactory::default(),
        BlockCache::new(),
    )
}

pub(crate) fn spend_max_spendable_single_step_proposed_transfer<T: ShieldedPoolTester>() {
    zcash_client_backend::data_api::testing::pool::spend_max_spendable_single_step_proposed_transfer::<
        T,
    >(TestDbFactory::default(), BlockCache::new())
}

pub(crate) fn spend_everything_single_step_proposed_transfer<T: ShieldedPoolTester>() {
    zcash_client_backend::data_api::testing::pool::spend_everything_single_step_proposed_transfer::<T>(
        TestDbFactory::default(),
        BlockCache::new(),
    )
}

#[cfg(feature = "orchard")]
pub(crate) fn send_max_spends_inputs_across_pools<
    P0: ShieldedPoolTester,
    P1: ShieldedPoolTester,
>() {
    zcash_client_backend::data_api::testing::pool::send_max_spends_inputs_across_pools::<P0, P1>(
        TestDbFactory::default(),
        BlockCache::new(),
    )
}

#[cfg(feature = "transparent-inputs")]
pub(crate) fn send_max_fee_overflow_is_an_error<T: ShieldedPoolTester>() {
    zcash_client_backend::data_api::testing::pool::send_max_fee_overflow_is_an_error::<T>(
        TestDbFactory::default(),
        BlockCache::new(),
    )
}

#[cfg(not(feature = "transparent-inputs"))]
pub(crate) fn send_max_to_tex_fails_without_transparent_inputs<T: ShieldedPoolTester>() {
    zcash_client_backend::data_api::testing::pool::send_max_to_tex_fails_without_transparent_inputs::<
        T,
    >(TestDbFactory::default(), BlockCache::new())
}

#[cfg(feature = "transparent-inputs")]
pub(crate) fn send_max_spendable_to_transparent<T: ShieldedPoolTester>() {
    zcash_client_backend::data_api::testing::pool::send_max_spendable_to_transparent::<T>(
        TestDbFactory::default(),
        BlockCache::new(),
    )
}

#[cfg(feature = "transparent-inputs")]
pub(crate) fn fails_to_send_max_to_transparent_with_memo<T: ShieldedPoolTester>() {
    zcash_client_backend::data_api::testing::pool::fails_to_send_max_spendable_to_transparent_with_memo::<T>(
        TestDbFactory::default(),
        BlockCache::new(),
    )
}

#[cfg(not(feature = "orchard"))]
pub(crate) fn send_max_delivers_via_sapling_when_orchard_is_unavailable<T: ShieldedPoolTester>() {
    zcash_client_backend::data_api::testing::pool::send_max_delivers_via_sapling_when_orchard_is_unavailable::<
        T,
    >(TestDbFactory::default(), BlockCache::new())
}

#[cfg(not(feature = "orchard"))]
pub(crate) fn send_max_to_orchard_only_ua_fails_without_orchard<T: ShieldedPoolTester>() {
    zcash_client_backend::data_api::testing::pool::send_max_to_orchard_only_ua_fails_without_orchard::<
        T,
    >(TestDbFactory::default(), BlockCache::new())
}

pub(crate) fn send_max_fails_when_balance_is_consumed_by_fees<T: ShieldedPoolTester>() {
    zcash_client_backend::data_api::testing::pool::send_max_fails_when_balance_is_consumed_by_fees::<
        T,
    >(TestDbFactory::default(), BlockCache::new())
}

pub(crate) fn send_max_proposal_fails_when_unconfirmed_funds_present<T: ShieldedPoolTester>() {
    zcash_client_backend::data_api::testing::pool::spend_everything_proposal_fails_when_unconfirmed_funds_present::<T>(
        TestDbFactory::default(),
        BlockCache::new(),
    )
}

#[cfg(feature = "transparent-inputs")]
pub(crate) fn spend_everything_multi_step_many_notes_proposed_transfer<T: ShieldedPoolTester>() {
    zcash_client_backend::data_api::testing::pool::spend_everything_multi_step_many_notes_proposed_transfer::<
        T,
        _,
    >(
        TestDbFactory::default(),
        BlockCache::new(),
    )
}

#[cfg(feature = "transparent-inputs")]
pub(crate) fn spend_everything_multi_step_with_marginal_notes_proposed_transfer<
    T: ShieldedPoolTester,
>() {
    zcash_client_backend::data_api::testing::pool::spend_everything_multi_step_with_marginal_notes_proposed_transfer::<
        T,
        _,
    >(
        TestDbFactory::default(),
        BlockCache::new(),
    )
}

#[cfg(feature = "transparent-inputs")]
pub(crate) fn spend_everything_multi_step_single_note_proposed_transfer<T: ShieldedPoolTester>() {
    zcash_client_backend::data_api::testing::pool::spend_everything_multi_step_single_note_proposed_transfer::<
        T,
        _,
    >(
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

pub(crate) fn spend_all_funds_single_step_proposed_transfer<T: ShieldedPoolTester>() {
    zcash_client_backend::data_api::testing::pool::spend_all_funds_single_step_proposed_transfer::<T>(
        TestDbFactory::default(),
        BlockCache::new(),
    )
}

#[cfg(feature = "transparent-inputs")]
pub(crate) fn spend_all_funds_multi_step_proposed_transfer<T: ShieldedPoolTester>() {
    zcash_client_backend::data_api::testing::pool::spend_all_funds_multi_step_proposed_transfer::<
        T,
        _,
    >(TestDbFactory::default(), BlockCache::new())
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

pub(crate) fn account_deletion<T: ShieldedPoolTester>() {
    zcash_client_backend::data_api::testing::pool::account_deletion::<T, _>(
        TestDbFactory::default(),
        BlockCache::new(),
    )
}

pub(crate) fn account_deletion_with_internal_transfer<T: ShieldedPoolTester>() {
    zcash_client_backend::data_api::testing::pool::account_deletion_with_internal_transfer::<T, _>(
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

/// Runs the deep-scan retention check at the ZIP 318 interval and at a short configured one, so
/// that the wallet is shown to retain exactly the grid it was configured with rather than a
/// hard-coded 144-block one.
pub(crate) fn anchor_checkpoints_retained_across_deep_scan<T: ShieldedPoolTester>() {
    for interval in [
        AnchorRetentionInterval::ZIP_318,
        AnchorRetentionInterval::custom(NonZeroU32::new(12).expect("nonzero")),
    ] {
        zcash_client_backend::data_api::testing::pool::anchor_checkpoints_retained_across_deep_scan::<
            T,
            _,
        >(TestDbFactory::default(), BlockCache::new(), interval)
    }
}

pub(crate) fn oldest_note_is_selected_first<T: ShieldedPoolTester>() {
    zcash_client_backend::data_api::testing::pool::oldest_note_is_selected_first::<T, _>(
        TestDbFactory::default(),
        BlockCache::new(),
    )
}

/// Runs the empty-boundary retention check at a short interval, so a handful of filler blocks
/// crosses two boundaries.
#[cfg(feature = "orchard")]
pub(crate) fn empty_boundary_blocks_are_checkpointed_and_retained<T: ShieldedPoolTester>() {
    zcash_client_backend::data_api::testing::pool::empty_boundary_blocks_are_checkpointed_and_retained::<
        T,
        _,
    >(
        TestDbFactory::default(),
        BlockCache::new(),
        AnchorRetentionInterval::custom(NonZeroU32::new(7).expect("nonzero")),
    )
}

#[cfg(feature = "orchard")]
pub(crate) fn canonical_crossing_is_bucketed_and_unpadded() {
    zcash_client_backend::data_api::testing::pool::canonical_crossing_is_bucketed_and_unpadded(
        TestDbFactory::default(),
        BlockCache::new(),
    )
}

#[cfg(feature = "orchard")]
pub(crate) fn canonical_crossing_builds_at_empty_boundary_block() {
    zcash_client_backend::data_api::testing::pool::canonical_crossing_builds_at_empty_boundary_block(
        TestDbFactory::default(),
        BlockCache::new(),
    )
}

/// Deletes every checkpoint record at `height`, simulating a wallet that scanned past NU6.3
/// activation before boundary checkpointing was repaired and so is permanently missing the
/// boundary.
#[cfg(feature = "orchard")]
pub(crate) fn canonical_crossing_abandoned_without_anchor_checkpoint() {
    zcash_client_backend::data_api::testing::pool::canonical_crossing_abandoned_without_anchor_checkpoint(
        TestDbFactory::default(),
        BlockCache::new(),
        |st, height| {
            let conn = st.wallet().conn();
            for table in [
                "sapling_tree_checkpoints",
                "orchard_tree_checkpoints",
                "ironwood_tree_checkpoints",
                "sapling_tree_retained_checkpoints",
                "orchard_tree_retained_checkpoints",
                "ironwood_tree_retained_checkpoints",
            ] {
                conn.execute(
                    &format!("DELETE FROM {table} WHERE checkpoint_id = :height"),
                    rusqlite::named_params![":height": u32::from(height)],
                )
                .expect("checkpoint records can be deleted");
            }
        },
    )
}

#[cfg(feature = "orchard")]
pub(crate) fn canonical_crossing_prefers_single_note() {
    zcash_client_backend::data_api::testing::pool::canonical_crossing_prefers_single_note(
        TestDbFactory::default(),
        BlockCache::new(),
    )
}

#[cfg(feature = "orchard")]
pub(crate) fn multi_note_crossing_is_not_bucketed() {
    zcash_client_backend::data_api::testing::pool::multi_note_crossing_is_not_bucketed(
        TestDbFactory::default(),
        BlockCache::new(),
    )
}

#[cfg(feature = "orchard")]
pub(crate) fn self_migration_keeps_spending_orchard() {
    zcash_client_backend::data_api::testing::pool::self_migration_keeps_spending_orchard(
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

pub(crate) fn truncate_to_chain_state<T: ShieldedPoolTester>() {
    zcash_client_backend::data_api::testing::pool::truncate_to_chain_state::<T, _>(
        TestDbFactory::default(),
        BlockCache::new(),
    )
}

pub(crate) fn truncate_to_chain_state_below_birthday<T: ShieldedPoolTester>() {
    zcash_client_backend::data_api::testing::pool::truncate_to_chain_state_below_birthday::<T, _>(
        TestDbFactory::default(),
        BlockCache::new(),
    )
}

pub(crate) fn truncate_to_chain_state_above_scanned<T: ShieldedPoolTester>() {
    zcash_client_backend::data_api::testing::pool::truncate_to_chain_state_above_scanned::<T, _>(
        TestDbFactory::default(),
        BlockCache::new(),
    )
}

/// Regression test: a note-commitment-tree error encountered while inserting the chain-state
/// frontier during `truncate_to_chain_state` must surface as
/// [`SqliteClientError::TruncateCommitmentTree`], carrying the affected shielded pool and the
/// target height, rather than as the bare `CommitmentTree` variant (which reported only an opaque
/// tree-node address).
///
/// The error is forced by replaying the same pruned scenario as
/// [`truncate_to_chain_state_above_scanned`] (where the target-height checkpoint has been pruned,
/// so `truncate_to_chain_state` reaches `insert_frontier`) but feeding it a *foreign* frontier:
/// one captured from a second wallet that scanned the same number of blocks with different note
/// values, so it has the same tree shape but conflicting node hashes.
pub(crate) fn truncate_to_chain_state_commitment_tree_error<T: ShieldedPoolTester>() {
    // `zcash_client_backend::data_api::ll::wallet::PRUNING_DEPTH` is crate-private; mirror it
    // here. Scanning this far past the captured height guarantees its checkpoint is pruned.
    const PRUNING_DEPTH: u32 = 100;

    // Wallet A: scan blocks to populate the note commitment tree, capture a consistent chain
    // state, then scan well past the pruning depth so that the captured height's checkpoint is
    // pruned (forcing `truncate_to_chain_state` down the `insert_frontier` path).
    let mut wallet_a =
        TestDsl::with_sapling_birthday_account(TestDbFactory::default(), BlockCache::new())
            .build::<T>();
    let activation = wallet_a
        .network()
        .activation_height(NetworkUpgrade::Sapling)
        .unwrap();
    // The first block pays wallet A's own account: with a witnessed note below the capture
    // height, the pruned checkpoint cannot be recovered from by emptying the tree, forcing
    // `truncate_to_chain_state` down the `insert_frontier` path this test exercises.
    let account_fvk_a = T::test_account_fvk(&wallet_a);
    let fvk_a = T::sk_to_fvk(&T::sk(&[1u8; 32]));
    let initial_blocks = 8u32;
    wallet_a.generate_next_block(
        &account_fvk_a,
        AddressType::DefaultExternal,
        Zatoshis::const_from_u64(10_000),
    );
    for _ in 1..initial_blocks {
        wallet_a.generate_next_block(
            &fvk_a,
            AddressType::DefaultExternal,
            Zatoshis::const_from_u64(10_000),
        );
    }
    wallet_a.scan_cached_blocks(activation, initial_blocks as usize);

    let capture_height = activation + initial_blocks - 1;
    let captured = wallet_a
        .latest_cached_block()
        .expect("should have cached blocks")
        .chain_state()
        .clone();
    assert_eq!(captured.block_height(), capture_height);

    let extra_blocks = PRUNING_DEPTH + 10;
    for _ in 0..extra_blocks {
        wallet_a.generate_next_block(
            &fvk_a,
            AddressType::DefaultExternal,
            Zatoshis::const_from_u64(5_000),
        );
    }
    wallet_a.scan_cached_blocks(capture_height + 1, extra_blocks as usize);

    // Wallet B: identical structure but different note values, so its frontier at the same height
    // has the same shape with conflicting node hashes.
    let mut wallet_b =
        TestDsl::with_sapling_birthday_account(TestDbFactory::default(), BlockCache::new())
            .build::<T>();
    let fvk_b = T::sk_to_fvk(&T::sk(&[2u8; 32]));
    for _ in 0..initial_blocks {
        wallet_b.generate_next_block(
            &fvk_b,
            AddressType::DefaultExternal,
            Zatoshis::const_from_u64(7_000),
        );
    }
    wallet_b.scan_cached_blocks(activation, initial_blocks as usize);
    let foreign = wallet_b
        .latest_cached_block()
        .expect("should have cached blocks")
        .chain_state()
        .clone();
    assert_eq!(foreign.block_height(), capture_height);

    // Claim wallet A's captured height/hash, but substitute wallet B's frontier for pool `T`.
    // Neither wallet holds Ironwood notes, so the Ironwood tree is empty in either case.
    #[cfg(feature = "orchard")]
    let ironwood_initial_tree = incrementalmerkletree::frontier::Frontier::empty();
    #[cfg(feature = "orchard")]
    let bad_chain_state = match T::SHIELDED_PROTOCOL {
        ShieldedPool::Sapling => ChainState::new(
            capture_height,
            captured.block_hash(),
            foreign.final_sapling_tree().clone(),
            captured.final_orchard_tree().clone(),
            ironwood_initial_tree,
        ),
        ShieldedPool::Orchard => ChainState::new(
            capture_height,
            captured.block_hash(),
            captured.final_sapling_tree().clone(),
            foreign.final_orchard_tree().clone(),
            ironwood_initial_tree,
        ),
        ShieldedPool::Ironwood => ChainState::new(
            capture_height,
            captured.block_hash(),
            captured.final_sapling_tree().clone(),
            captured.final_orchard_tree().clone(),
            foreign.final_ironwood_tree().clone(),
        ),
    };
    #[cfg(not(feature = "orchard"))]
    let bad_chain_state = ChainState::new(
        capture_height,
        captured.block_hash(),
        foreign.final_sapling_tree().clone(),
    );

    match wallet_a
        .wallet_mut()
        .truncate_to_chain_state(bad_chain_state)
    {
        Err(SqliteClientError::TruncateCommitmentTree { pool, height, .. }) => {
            assert_eq!(pool, T::SHIELDED_PROTOCOL);
            assert_eq!(height, capture_height);
        }
        other => panic!("expected TruncateCommitmentTree error, got {other:?}"),
    }
}

/// Regression test: a note-commitment-tree error encountered while storing scanned blocks via
/// `put_blocks` must surface as [`SqliteClientError::PutBlocksCommitmentTree`], carrying the
/// affected shielded pool and the range of block heights being added, rather than as the bare
/// `CommitmentTree` variant.
///
/// The error is forced by scanning a contiguous range of wallet A's blocks but supplying a
/// `from_state` whose frontier was captured from a second wallet that scanned the same number of
/// blocks with different note values: the chain state has the same tree shape (so it passes
/// `put_blocks`' sequentiality checks) but conflicting node hashes, so `insert_frontier` inside
/// `put_blocks` fails.
pub(crate) fn put_blocks_commitment_tree_error<T: ShieldedPoolTester>() {
    // Wallet A: scan an initial range of blocks and capture its (consistent) chain state at the
    // last scanned height.
    let mut wallet_a =
        TestDsl::with_sapling_birthday_account(TestDbFactory::default(), BlockCache::new())
            .build::<T>();
    let activation = wallet_a
        .network()
        .activation_height(NetworkUpgrade::Sapling)
        .unwrap();
    let fvk_a = T::sk_to_fvk(&T::sk(&[1u8; 32]));
    let initial_blocks = 8u32;
    for _ in 0..initial_blocks {
        wallet_a.generate_next_block(
            &fvk_a,
            AddressType::DefaultExternal,
            Zatoshis::const_from_u64(10_000),
        );
    }
    wallet_a.scan_cached_blocks(activation, initial_blocks as usize);

    let from_height = activation + initial_blocks;
    let captured = wallet_a
        .latest_cached_block()
        .expect("should have cached blocks")
        .chain_state()
        .clone();
    assert_eq!(captured.block_height(), from_height - 1);

    // Generate (but do not scan) a further range of wallet A's blocks; these will be scanned with
    // the conflicting `from_state` below.
    let scan_blocks = 3u32;
    for _ in 0..scan_blocks {
        wallet_a.generate_next_block(
            &fvk_a,
            AddressType::DefaultExternal,
            Zatoshis::const_from_u64(5_000),
        );
    }

    // Wallet B: identical structure but different note values, so its frontier at the same height
    // has the same shape with conflicting node hashes.
    let mut wallet_b =
        TestDsl::with_sapling_birthday_account(TestDbFactory::default(), BlockCache::new())
            .build::<T>();
    let fvk_b = T::sk_to_fvk(&T::sk(&[2u8; 32]));
    for _ in 0..initial_blocks {
        wallet_b.generate_next_block(
            &fvk_b,
            AddressType::DefaultExternal,
            Zatoshis::const_from_u64(7_000),
        );
    }
    wallet_b.scan_cached_blocks(activation, initial_blocks as usize);
    let foreign = wallet_b
        .latest_cached_block()
        .expect("should have cached blocks")
        .chain_state()
        .clone();
    assert_eq!(foreign.block_height(), from_height - 1);

    // Build a `from_state` claiming wallet A's last-scanned height/hash, but substituting wallet
    // B's frontier for pool `T`.
    // Neither wallet holds Ironwood notes, so the Ironwood tree is empty in either case.
    #[cfg(feature = "orchard")]
    let ironwood_initial_tree = incrementalmerkletree::frontier::Frontier::empty();
    #[cfg(feature = "orchard")]
    let bad_from_state = match T::SHIELDED_PROTOCOL {
        ShieldedPool::Sapling => ChainState::new(
            from_height - 1,
            captured.block_hash(),
            foreign.final_sapling_tree().clone(),
            captured.final_orchard_tree().clone(),
            ironwood_initial_tree,
        ),
        ShieldedPool::Orchard => ChainState::new(
            from_height - 1,
            captured.block_hash(),
            captured.final_sapling_tree().clone(),
            foreign.final_orchard_tree().clone(),
            ironwood_initial_tree,
        ),
        ShieldedPool::Ironwood => ChainState::new(
            from_height - 1,
            captured.block_hash(),
            captured.final_sapling_tree().clone(),
            captured.final_orchard_tree().clone(),
            foreign.final_ironwood_tree().clone(),
        ),
    };
    #[cfg(not(feature = "orchard"))]
    let bad_from_state = ChainState::new(
        from_height - 1,
        captured.block_hash(),
        foreign.final_sapling_tree().clone(),
    );

    match wallet_a.try_scan_cached_blocks_with_state(
        from_height,
        &bad_from_state,
        scan_blocks as usize,
    ) {
        Err(Error::Wallet(SqliteClientError::PutBlocksCommitmentTree {
            pool,
            block_range,
            ..
        })) => {
            assert_eq!(pool, T::SHIELDED_PROTOCOL);
            // `put_blocks` reports the range as `from_state.block_height()..(last_scanned + 1)`,
            // i.e. starting at the frontier/`from_state` height and ending one past the last
            // scanned block.
            assert_eq!(block_range, (from_height - 1)..(from_height + scan_blocks));
        }
        other => panic!("expected PutBlocksCommitmentTree error, got {other:?}"),
    }
}

pub(crate) fn rewind_to_chain_state_deep<T: ShieldedPoolTester>() {
    zcash_client_backend::data_api::testing::pool::rewind_to_chain_state_deep::<T, _>(
        TestDbFactory::default(),
        BlockCache::new(),
    )
}

pub(crate) fn rewind_to_chain_state_shallow<T: ShieldedPoolTester>() {
    zcash_client_backend::data_api::testing::pool::rewind_to_chain_state_shallow::<T, _>(
        TestDbFactory::default(),
        BlockCache::new(),
    )
}

pub(crate) fn rewind_after_non_contiguous_scan<T: ShieldedPoolTester>() {
    zcash_client_backend::data_api::testing::pool::rewind_after_non_contiguous_scan::<T, _>(
        TestDbFactory::default(),
        BlockCache::new(),
    )
}

#[cfg(feature = "expensive-tests")]
pub(crate) fn stabilized_note_spendable_after_deep_rewind<T: ShieldedPoolTester>() {
    zcash_client_backend::data_api::testing::pool::stabilized_note_spendable_after_deep_rewind::<T, _>(
        TestDbFactory::default(),
        BlockCache::new(),
    )
}

#[cfg(feature = "expensive-tests")]
pub(crate) fn newly_discovered_notes_become_stabilized<T: ShieldedPoolTester>() {
    zcash_client_backend::data_api::testing::pool::newly_discovered_notes_become_stabilized::<T, _>(
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
pub(crate) fn pczt_single_step<P0: ShieldedPoolTester, P1: ShieldedPoolTester>(
    pin_expiry_above_target: Option<u32>,
) {
    zcash_client_backend::data_api::testing::pool::pczt_single_step::<P0, P1, _>(
        TestDbFactory::default(),
        BlockCache::new(),
        pin_expiry_above_target,
    )
}

#[cfg(feature = "transparent-inputs")]
pub(crate) fn wallet_recovery_computes_fees<T: ShieldedPoolTester>() {
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
    for trust in [
        InputTrust::Internal,
        InputTrust::ExternalUntrusted,
        InputTrust::ExternalTrusted,
    ] {
        zcash_client_backend::data_api::testing::pool::zip_315_confirmations_test_steps::<T>(
            TestDbFactory::default(),
            BlockCache::new(),
            trust,
        );
    }
}

pub(crate) fn receive_two_notes_with_same_value<T: ShieldedPoolTester>() {
    zcash_client_backend::data_api::testing::pool::receive_two_notes_with_same_value::<T>(
        TestDbFactory::default(),
        BlockCache::new(),
    )
}

#[cfg(all(feature = "pczt-tests", feature = "transparent-inputs"))]
pub(crate) fn immature_coinbase_outputs_are_excluded_from_note_selection<T: ShieldedPoolTester>() {
    zcash_client_backend::data_api::testing::pool::immature_coinbase_outputs_are_excluded_from_note_selection::<T>(
        TestDbFactory::default(),
        BlockCache::new(),
    );
}

#[cfg(all(feature = "pczt-tests", feature = "transparent-inputs"))]
pub(crate) fn coinbase_only_filtering<T: ShieldedPoolTester>() {
    zcash_client_backend::data_api::testing::pool::coinbase_only_filtering::<T, _>(
        TestDbFactory::default(),
        BlockCache::new(),
    );
}

#[cfg(all(feature = "pczt-tests", feature = "transparent-inputs"))]
pub(crate) fn propose_shielding_coinbase_succeeds<T: ShieldedPoolTester>() {
    zcash_client_backend::data_api::testing::pool::propose_shielding_coinbase_succeeds::<T, _>(
        TestDbFactory::default(),
        BlockCache::new(),
    );
}

#[cfg(all(feature = "pczt-tests", feature = "transparent-inputs"))]
pub(crate) fn proposal_without_confirmations_policy_builds<T: ShieldedPoolTester>() {
    zcash_client_backend::data_api::testing::pool::proposal_without_confirmations_policy_builds::<
        T,
        _,
    >(TestDbFactory::default(), BlockCache::new());
}

#[cfg(all(feature = "pczt-tests", feature = "transparent-inputs"))]
pub(crate) fn propose_shielding_coinbase_transparent_recipient_rejected<T: ShieldedPoolTester>() {
    zcash_client_backend::data_api::testing::pool::propose_shielding_coinbase_transparent_recipient_rejected::<T, _>(
        TestDbFactory::default(),
        BlockCache::new(),
    );
}

#[cfg(all(feature = "pczt-tests", feature = "transparent-inputs"))]
pub(crate) fn propose_shielding_coinbase_with_memo_succeeds<T: ShieldedPoolTester>() {
    zcash_client_backend::data_api::testing::pool::propose_shielding_coinbase_with_memo_succeeds::<
        T,
        _,
    >(TestDbFactory::default(), BlockCache::new());
}

#[cfg(all(feature = "pczt-tests", feature = "transparent-inputs"))]
pub(crate) fn propose_shielding_coinbase_with_limit_truncates_inputs<T: ShieldedPoolTester>() {
    zcash_client_backend::data_api::testing::pool::propose_shielding_coinbase_with_limit_truncates_inputs::<T, _>(
        TestDbFactory::default(),
        BlockCache::new(),
    );
}

#[cfg(all(feature = "pczt-tests", feature = "transparent-inputs"))]
pub(crate) fn propose_shielding_coinbase_with_zero_limit_insufficient_funds<
    T: ShieldedPoolTester,
>() {
    zcash_client_backend::data_api::testing::pool::propose_shielding_coinbase_with_zero_limit_insufficient_funds::<T, _>(
        TestDbFactory::default(),
        BlockCache::new(),
    );
}

#[cfg(all(feature = "pczt-tests", feature = "transparent-inputs"))]
pub(crate) fn propose_and_build_shielding_coinbase_succeeds<T: ShieldedPoolTester>() {
    zcash_client_backend::data_api::testing::pool::propose_and_build_shielding_coinbase_succeeds::<
        T,
        _,
    >(TestDbFactory::default(), BlockCache::new());
}

#[cfg(all(
    feature = "orchard",
    feature = "pczt-tests",
    feature = "transparent-inputs"
))]
pub(crate) fn shielding_coinbase_to_orchard_receiver_delivers_via_ironwood() {
    zcash_client_backend::data_api::testing::pool::shielding_coinbase_to_orchard_receiver_delivers_via_ironwood(
        TestDbFactory::default(),
        BlockCache::new(),
    );
}

#[cfg(feature = "orchard")]
pub(crate) fn orchard_to_ironwood_payment_reports_net_value_delta() {
    zcash_client_backend::data_api::testing::pool::orchard_to_ironwood_payment_reports_net_value_delta(
        TestDbFactory::default(),
        BlockCache::new(),
    );
}

#[cfg(feature = "orchard")]
pub(crate) fn orchard_to_ironwood_self_migration_reports_fee_only_delta() {
    zcash_client_backend::data_api::testing::pool::orchard_to_ironwood_self_migration_reports_fee_only_delta(
        TestDbFactory::default(),
        BlockCache::new(),
    );
}

#[cfg(feature = "orchard")]
pub(crate) fn propose_v5_payment_to_orchard_receiver_is_rejected() {
    zcash_client_backend::data_api::testing::pool::propose_v5_payment_to_orchard_receiver_is_rejected(
        TestDbFactory::default(),
        BlockCache::new(),
    );
}

#[cfg(all(feature = "orchard", feature = "pczt-tests"))]
pub(crate) fn create_pczt_supports_ironwood_output() {
    zcash_client_backend::data_api::testing::pool::create_pczt_supports_ironwood_output(
        TestDbFactory::default(),
        BlockCache::new(),
    );
}

#[cfg(feature = "orchard")]
pub(crate) fn proposal_records_and_serializes_proposed_version() {
    zcash_client_backend::data_api::testing::pool::proposal_records_and_serializes_proposed_version(
        TestDbFactory::default(),
        BlockCache::new(),
    );
}

/// Builds a wallet whose birthday lies within the second (incomplete) note commitment tree
/// shard of each pool, with the first shard having been completed ten blocks before the
/// birthday. This is the steady state of a wallet on a live chain: the completed prior shard
/// gives `update_chain_tip` a tip shard to complete, so that advancing the chain tip queues a
/// `ChainTip` range rather than the `Historic` range used for linear scanning.
fn tip_shard_scenario<T: ShieldedPoolTester>() -> TestDsl<TestScenario<T, BlockCache, TestDbFactory>>
{
    // The frontiers at the block prior to the birthday sit 1234 notes into the second shard.
    let frontier_tree_size: u32 = (0x1 << 16) + 1234;
    let builder = TestBuilder::new()
        .with_data_store_factory(TestDbFactory::default())
        .with_block_cache(BlockCache::new())
        .with_initial_chain_state(|rng, network| {
            let birthday_height = network.activation_height(NetworkUpgrade::Nu5).unwrap() + 76;
            let shard_end_height = birthday_height - 10;

            let (prior_sapling_roots, sapling_initial_tree) =
                Frontier::random_with_prior_subtree_roots(
                    rng,
                    frontier_tree_size.into(),
                    NonZeroU8::new(16).unwrap(),
                );
            let prior_sapling_roots = prior_sapling_roots
                .into_iter()
                .map(|root| CommitmentTreeRoot::from_parts(shard_end_height, root))
                .collect::<Vec<_>>();

            #[cfg(feature = "orchard")]
            let (prior_orchard_roots, orchard_initial_tree) =
                Frontier::random_with_prior_subtree_roots(
                    rng,
                    frontier_tree_size.into(),
                    NonZeroU8::new(16).unwrap(),
                );
            #[cfg(feature = "orchard")]
            let prior_orchard_roots = prior_orchard_roots
                .into_iter()
                .map(|root| CommitmentTreeRoot::from_parts(shard_end_height, root))
                .collect::<Vec<_>>();

            InitialChainState {
                chain_state: ChainState::new(
                    birthday_height - 1,
                    BlockHash([0; 32]),
                    sapling_initial_tree,
                    #[cfg(feature = "orchard")]
                    orchard_initial_tree,
                    #[cfg(feature = "orchard")]
                    Frontier::empty(),
                ),
                prior_sapling_roots,
                #[cfg(feature = "orchard")]
                prior_orchard_roots,
            }
        })
        .with_account_having_current_birthday();

    TestDsl::from(builder).build::<T>()
}

/// Receives a single note into the (incomplete) tip shard and scans the block containing it,
/// so that the wallet is scanned to its view of the chain tip. Checks that the note is not
/// stabilized and is spendable according to both the wallet summary and note selection, and
/// returns the height at which it was received.
fn receive_note_in_tip_shard<T: ShieldedPoolTester + ShieldedPoolPersistence>(
    st: &mut TestDsl<TestScenario<T, BlockCache, TestDbFactory>>,
    value: Zatoshis,
) -> BlockHeight {
    let account_id = st.get_account().id();
    let (h, _, _) = st.add_a_single_note_checking_balance(value);

    // The note is in the (incomplete) tip shard and has not been stabilized, so its
    // spendability is governed by the shard scan state.
    let witness_stabilized: bool = st
        .wallet()
        .conn()
        .query_row(
            &format!(
                "SELECT witness_stabilized FROM {}_received_notes",
                T::TABLES_PREFIX
            ),
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(!witness_stabilized);

    // Scanned to the tip: the note is spendable at one confirmation, both according to the
    // wallet summary and to note selection.
    assert_eq!(
        st.get_spendable_balance(account_id, ConfirmationsPolicy::MIN),
        value
    );
    let spendable = T::select_spendable_notes(
        st,
        account_id,
        TargetValue::AtLeast(value),
        TargetHeight::from(h + 1),
        ConfirmationsPolicy::MIN,
        &[],
    )
    .unwrap();
    assert_eq!(spendable.len(), 1);

    h
}

/// Advances the wallet's view of the chain tip by `blocks` without scanning, and asserts that
/// a `ChainTip` range beginning just above the previously scanned height was queued.
fn advance_chain_tip_without_scanning<T: ShieldedPoolTester + ShieldedPoolPersistence>(
    st: &mut TestDsl<TestScenario<T, BlockCache, TestDbFactory>>,
    max_scanned: BlockHeight,
    blocks: u32,
) -> BlockHeight {
    let new_tip = max_scanned + blocks;
    st.wallet_mut().update_chain_tip(new_tip).unwrap();

    let queued = suggest_scan_ranges(st.wallet().conn(), ScanPriority::ChainTip).unwrap();
    assert_eq!(
        queued,
        vec![scan_range(
            (max_scanned + 1).into()..(new_tip + 1).into(),
            ScanPriority::ChainTip
        )]
    );

    // The premise of the fix: `update_chain_tip` raises the target height to `new_tip + 1` but
    // creates no checkpoints, and the anchor is clamped to the newest checkpoint at or below
    // `target - min_confirmations`, so it remains at the old scan frontier, strictly below the
    // start of the queued `ChainTip` range.
    let (target_height, anchor_height) =
        get_target_and_anchor_heights(st.wallet().conn(), ConfirmationsPolicy::default().trusted())
            .unwrap()
            .expect("chain tip and anchor are known");
    assert_eq!(target_height, TargetHeight::from(new_tip + 1));
    assert_eq!(anchor_height, max_scanned);
    assert!(anchor_height < queued[0].block_range().start);

    new_tip
}

/// Asserts that the per-pool gate (`unscanned_tip_exists`, shared by the wallet summary and
/// note selection), the wallet summary's spendable balance, and note selection all agree on
/// whether the wallet's single note is spendable under `policy`.
fn assert_gates_agree<T: ShieldedPoolTester + ShieldedPoolPersistence>(
    st: &TestDsl<TestScenario<T, BlockCache, TestDbFactory>>,
    policy: ConfirmationsPolicy,
    value: Zatoshis,
    expect_spendable: bool,
) {
    let account_id = st.get_account().id();
    let (target_height, anchor_height) =
        get_target_and_anchor_heights(st.wallet().conn(), policy.trusted())
            .unwrap()
            .expect("chain tip and anchor are known");

    let tip_unscanned =
        unscanned_tip_exists(st.wallet().conn(), anchor_height, T::TABLES_PREFIX).unwrap();
    assert_eq!(tip_unscanned, !expect_spendable);

    let (expected_spendable, expected_pending) = if expect_spendable {
        (value, Zatoshis::ZERO)
    } else {
        (Zatoshis::ZERO, value)
    };
    assert_eq!(
        st.get_spendable_balance(account_id, policy),
        expected_spendable
    );
    assert_eq!(
        st.get_pending_shielded_balance(account_id, policy),
        expected_pending
    );

    let spendable = T::select_spendable_notes(
        st,
        account_id,
        TargetValue::AtLeast(value),
        target_height,
        policy,
        &[],
    )
    .unwrap();
    assert_eq!(spendable.len(), usize::from(expect_spendable));
    if let Some(note) = spendable.first() {
        assert_eq!(T::note_value(note.note()), value);
    }
}

/// A non-stabilized note in the tip shard remains spendable, both according to the wallet
/// summary and to note selection, after the wallet's view of the chain tip is advanced without
/// the intervening blocks having been scanned. The `ChainTip` range queued by `update_chain_tip`
/// lies entirely above the anchor and so cannot affect the witness at the anchor.
///
/// This is the mobile-wallet failure mode in which the UI reports a spendable balance and a
/// subsequent proposal fails with `InsufficientFunds { available: 0 }`.
pub(crate) fn tip_shard_notes_remain_spendable_after_chain_tip_update<
    T: ShieldedPoolTester + ShieldedPoolPersistence,
>() {
    let mut st = tip_shard_scenario::<T>();
    let account = st.get_account();
    let account_id = account.id();

    let value = Zatoshis::const_from_u64(100_000);
    let h = receive_note_in_tip_shard(&mut st, value);

    // Advance the chain tip without scanning; the tip-shard `ChainTip` range now overlaps the
    // note's shard, but begins above the anchor.
    advance_chain_tip_without_scanning(&mut st, h, 50);

    // The per-pool gate, the summary and note selection all still report the note as
    // spendable. The default policy requires more confirmations than the minimum, which the
    // note has (relative to the advanced tip) even though it did not at the time it was
    // scanned.
    for policy in [ConfirmationsPolicy::MIN, ConfirmationsPolicy::default()] {
        assert_gates_agree(&st, policy, value, true);
    }

    // A transfer proposal therefore succeeds.
    let to = T::sk_default_address(&T::sk(&[0xf5; 32]));
    let proposal = st
        .propose_standard_transfer::<Infallible>(
            account_id,
            StandardFeeRule::Zip317,
            ConfirmationsPolicy::default(),
            &to,
            Zatoshis::const_from_u64(60_000),
            None,
            None,
            T::SHIELDED_PROTOCOL,
        )
        .unwrap();
    assert_eq!(proposal.steps().len(), 1);
    assert_eq!(
        proposal
            .steps()
            .head
            .shielded_inputs()
            .map(|i| i.notes().len()),
        Some(1)
    );

    // Executing the proposal (which constructs the witness at the anchor) also succeeds.
    st.create_proposed_transactions::<Infallible, _, Infallible, _>(
        account.usk(),
        OvkPolicy::Sender,
        &proposal,
    )
    .unwrap();
}

/// An unscanned range that begins at or below the anchor height still renders a non-stabilized
/// note in the affected shard unspendable, according to both the wallet summary and note
/// selection, since it may contain note commitments that are part of the tree state at the
/// anchor.
pub(crate) fn unscanned_range_below_anchor_blocks_spendability<
    T: ShieldedPoolTester + ShieldedPoolPersistence,
>() {
    let mut st = tip_shard_scenario::<T>();

    let value = Zatoshis::const_from_u64(100_000);
    let h = receive_note_in_tip_shard(&mut st, value);
    advance_chain_tip_without_scanning(&mut st, h, 50);
    assert_gates_agree(&st, ConfirmationsPolicy::MIN, value, true);

    // Simulate the state following a rewind in which the block at the anchor height (the block
    // in which the note was received) must be re-verified: the scan queue entry covering that
    // block is marked `Verify`, so a range starting at or below the anchor is now unscanned.
    let updated = st
        .wallet()
        .conn()
        .execute(
            "UPDATE scan_queue SET priority = :priority
             WHERE block_range_start <= :height AND block_range_end > :height",
            rusqlite::named_params![
                ":priority": priority_code(&ScanPriority::Verify),
                ":height": u32::from(h),
            ],
        )
        .unwrap();
    assert_eq!(updated, 1);

    // The per-pool gate, the summary and note selection all now report the note as not
    // spendable.
    for policy in [ConfirmationsPolicy::MIN, ConfirmationsPolicy::default()] {
        assert_gates_agree(&st, policy, value, false);
    }

    // A transfer proposal therefore fails for lack of spendable funds.
    let to = T::sk_default_address(&T::sk(&[0xf5; 32]));
    st.expect_insufficient_funds_with(
        &to,
        Zatoshis::const_from_u64(60_000),
        ConfirmationsPolicy::default(),
        Zatoshis::ZERO,
        Zatoshis::const_from_u64(70_000),
    );
}
