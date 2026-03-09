use crate::testing;

use zcash_client_backend::data_api::testing::orchard::OrchardPoolTester;
use zcash_client_backend::data_api::testing::sapling::SaplingPoolTester;

#[test]
fn send_single_step_proposed_transfer() {
    testing::pool::send_single_step_proposed_transfer::<OrchardPoolTester>()
}

#[test]
#[ignore] //FIXME
#[cfg(feature = "transparent-inputs")]
fn send_multi_step_proposed_transfer() {
    testing::pool::send_multi_step_proposed_transfer::<OrchardPoolTester>()
}

#[test]
#[ignore] //FIXME
#[cfg(feature = "transparent-inputs")]
fn proposal_fails_if_not_all_ephemeral_outputs_consumed() {
    testing::pool::proposal_fails_if_not_all_ephemeral_outputs_consumed::<OrchardPoolTester>()
}

#[test]
#[allow(deprecated)]
fn create_to_address_fails_on_incorrect_usk() {
    testing::pool::create_to_address_fails_on_incorrect_usk::<OrchardPoolTester>()
}

#[test]
#[allow(deprecated)]
fn proposal_fails_with_no_blocks() {
    testing::pool::proposal_fails_with_no_blocks::<OrchardPoolTester>()
}

#[test]
#[ignore] //FIXME
fn spend_fails_on_unverified_notes() {
    testing::pool::spend_fails_on_unverified_notes::<OrchardPoolTester>()
}

#[test]
#[ignore] //FIXME
fn spend_fails_on_locked_notes() {
    testing::pool::spend_fails_on_locked_notes::<OrchardPoolTester>()
}

#[test]
#[ignore] //FIXME
fn ovk_policy_prevents_recovery_from_chain() {
    testing::pool::ovk_policy_prevents_recovery_from_chain::<OrchardPoolTester>()
}

#[test]
#[ignore] //FIXME
fn spend_succeeds_to_t_addr_zero_change() {
    testing::pool::spend_succeeds_to_t_addr_zero_change::<OrchardPoolTester>()
}

#[test]
#[ignore] //FIXME
fn change_note_spends_succeed() {
    testing::pool::change_note_spends_succeed::<OrchardPoolTester>()
}

#[test]
fn external_address_change_spends_detected_in_restore_from_seed() {
    testing::pool::external_address_change_spends_detected_in_restore_from_seed::<OrchardPoolTester>(
    )
}

#[test]
#[ignore] // FIXME: #1316 This requires support for dust outputs.
fn zip317_spend() {
    testing::pool::zip317_spend::<OrchardPoolTester>()
}

#[test]
#[ignore] //FIXME
#[cfg(feature = "transparent-inputs")]
fn shield_transparent() {
    testing::pool::shield_transparent::<OrchardPoolTester>()
}

#[test]
fn birthday_in_anchor_shard() {
    testing::pool::birthday_in_anchor_shard::<OrchardPoolTester>()
}

#[test]
fn checkpoint_gaps() {
    testing::pool::checkpoint_gaps::<OrchardPoolTester>()
}

#[test]
#[cfg(feature = "orchard")]
fn pool_crossing_required() {
    testing::pool::pool_crossing_required::<OrchardPoolTester, SaplingPoolTester>()
}

#[test]
#[cfg(feature = "orchard")]
fn fully_funded_fully_private() {
    testing::pool::fully_funded_fully_private::<OrchardPoolTester, SaplingPoolTester>()
}

#[test]
#[cfg(all(feature = "orchard", feature = "transparent-inputs"))]
#[ignore] //FIXME
fn fully_funded_send_to_t() {
    testing::pool::fully_funded_send_to_t::<OrchardPoolTester, SaplingPoolTester>()
}

#[test]
#[cfg(feature = "orchard")]
fn multi_pool_checkpoint() {
    testing::pool::multi_pool_checkpoint::<OrchardPoolTester, SaplingPoolTester>()
}

#[test]
#[cfg(feature = "orchard")]
fn multi_pool_checkpoints_with_pruning() {
    testing::pool::multi_pool_checkpoints_with_pruning::<OrchardPoolTester, SaplingPoolTester>()
}

#[test]
fn valid_chain_states() {
    testing::pool::valid_chain_states::<OrchardPoolTester>()
}

#[test]
fn invalid_chain_cache_disconnected() {
    testing::pool::invalid_chain_cache_disconnected::<OrchardPoolTester>()
}

#[test]
fn data_db_truncation() {
    testing::pool::data_db_truncation::<OrchardPoolTester>()
}

#[test]
fn scan_cached_blocks_allows_blocks_out_of_order() {
    testing::pool::scan_cached_blocks_allows_blocks_out_of_order::<OrchardPoolTester>()
}

#[test]
fn scan_cached_blocks_finds_received_notes() {
    testing::pool::scan_cached_blocks_finds_received_notes::<OrchardPoolTester>()
}

#[test]
fn scan_cached_blocks_finds_change_notes() {
    testing::pool::scan_cached_blocks_finds_change_notes::<OrchardPoolTester>()
}

#[test]
fn scan_cached_blocks_detects_spends_out_of_order() {
    testing::pool::scan_cached_blocks_detects_spends_out_of_order::<OrchardPoolTester>()
}

#[test]
#[ignore] //FIXME
fn receive_two_notes_with_same_value() {
    testing::pool::receive_two_notes_with_same_value::<OrchardPoolTester>()
}
