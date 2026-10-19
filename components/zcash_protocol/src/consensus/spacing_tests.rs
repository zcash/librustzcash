//! Tests for the height-dependent block target spacing.

use core::time::Duration;

use super::{
    BlockHeight, MAIN_NETWORK, NU7_POW_TARGET_SPACING_RATIO, NetworkUpgrade,
    POST_BLOSSOM_POW_TARGET_SPACING, POST_NU7_POW_TARGET_SPACING, PRE_BLOSSOM_POW_TARGET_SPACING,
    Parameters, TEST_NETWORK, pow_target_spacing, target_time_between,
};

/// A local network on which only Blossom and NU7 can activate, at the given heights.
#[cfg(feature = "local-consensus")]
fn spacing_test_network(
    blossom: Option<BlockHeight>,
    nu7: Option<BlockHeight>,
) -> crate::local_consensus::LocalNetwork {
    crate::local_consensus::LocalNetwork {
        overwinter: None,
        sapling: None,
        blossom,
        heartwood: None,
        canopy: None,
        nu5: None,
        nu6: None,
        nu6_1: None,
        nu6_2: None,
        nu6_3: None,
        nu7,
        #[cfg(zcash_unstable = "nutachyon")]
        nu_tachyon: None,
    }
}

#[test]
fn target_spacings_match_the_zip_208_and_zip_218_values() {
    /// The target spacing before Blossom activation defined by ZIP 208, in seconds.
    const PRE_BLOSSOM_SECS: u64 = 150;
    /// The target spacing from Blossom activation defined by ZIP 208, in seconds.
    const POST_BLOSSOM_SECS: u64 = 75;
    /// The target spacing from NU7 activation defined by ZIP 218, in seconds.
    const POST_NU7_SECS: u64 = 25;

    let nu7 = TEST_NETWORK.activation_height(NetworkUpgrade::Nu7).unwrap();

    assert_eq!(
        PRE_BLOSSOM_POW_TARGET_SPACING,
        Duration::from_secs(PRE_BLOSSOM_SECS)
    );
    assert_eq!(
        POST_BLOSSOM_POW_TARGET_SPACING,
        Duration::from_secs(POST_BLOSSOM_SECS)
    );
    assert_eq!(
        POST_NU7_POW_TARGET_SPACING,
        Duration::from_secs(POST_NU7_SECS)
    );

    assert_eq!(
        pow_target_spacing(&TEST_NETWORK, BlockHeight(0)),
        Duration::from_secs(PRE_BLOSSOM_SECS)
    );
    assert_eq!(
        pow_target_spacing(&TEST_NETWORK, nu7 - 1),
        Duration::from_secs(POST_BLOSSOM_SECS)
    );
    assert_eq!(
        pow_target_spacing(&TEST_NETWORK, nu7),
        Duration::from_secs(POST_NU7_SECS)
    );
}

#[test]
fn nu7_spacing_ratio_relates_the_post_blossom_and_post_nu7_spacings() {
    assert_eq!(
        POST_NU7_POW_TARGET_SPACING * NU7_POW_TARGET_SPACING_RATIO,
        POST_BLOSSOM_POW_TARGET_SPACING
    );
}

#[test]
fn pow_target_spacing_changes_at_blossom_and_nu7_on_testnet() {
    let blossom = TEST_NETWORK
        .activation_height(NetworkUpgrade::Blossom)
        .unwrap();
    let nu7 = TEST_NETWORK.activation_height(NetworkUpgrade::Nu7).unwrap();

    assert_eq!(
        pow_target_spacing(&TEST_NETWORK, BlockHeight(0)),
        PRE_BLOSSOM_POW_TARGET_SPACING
    );
    assert_eq!(
        pow_target_spacing(&TEST_NETWORK, blossom - 1),
        PRE_BLOSSOM_POW_TARGET_SPACING
    );
    assert_eq!(
        pow_target_spacing(&TEST_NETWORK, blossom),
        POST_BLOSSOM_POW_TARGET_SPACING
    );
    assert_eq!(
        pow_target_spacing(&TEST_NETWORK, nu7 - 1),
        POST_BLOSSOM_POW_TARGET_SPACING
    );
    assert_eq!(
        pow_target_spacing(&TEST_NETWORK, nu7),
        POST_NU7_POW_TARGET_SPACING
    );
    assert_eq!(
        pow_target_spacing(&TEST_NETWORK, BlockHeight(u32::MAX)),
        POST_NU7_POW_TARGET_SPACING
    );
}

#[test]
fn target_time_between_uses_the_spacing_of_each_later_block() {
    let blossom = TEST_NETWORK
        .activation_height(NetworkUpgrade::Blossom)
        .unwrap();
    let nu7 = TEST_NETWORK.activation_height(NetworkUpgrade::Nu7).unwrap();

    // The block at `nu7` is the first to follow its parent by the post-NU7 spacing.
    assert_eq!(
        target_time_between(&TEST_NETWORK, nu7 - 1, nu7),
        POST_NU7_POW_TARGET_SPACING
    );
    assert_eq!(
        target_time_between(&TEST_NETWORK, nu7 - 2, nu7),
        POST_BLOSSOM_POW_TARGET_SPACING + POST_NU7_POW_TARGET_SPACING
    );
    // Likewise at Blossom activation.
    assert_eq!(
        target_time_between(&TEST_NETWORK, blossom - 1, blossom),
        POST_BLOSSOM_POW_TARGET_SPACING
    );
    assert_eq!(
        target_time_between(&TEST_NETWORK, blossom - 2, blossom),
        PRE_BLOSSOM_POW_TARGET_SPACING + POST_BLOSSOM_POW_TARGET_SPACING
    );
    // Across both changes: the block at `blossom - 1`, the blocks `blossom..nu7`, and the
    // block at `nu7`.
    assert_eq!(
        target_time_between(&TEST_NETWORK, blossom - 2, nu7),
        PRE_BLOSSOM_POW_TARGET_SPACING
            + POST_BLOSSOM_POW_TARGET_SPACING * (nu7 - blossom)
            + POST_NU7_POW_TARGET_SPACING
    );
}

#[test]
fn target_time_between_is_zero_for_empty_and_reversed_ranges() {
    let nu7 = TEST_NETWORK.activation_height(NetworkUpgrade::Nu7).unwrap();

    assert_eq!(target_time_between(&TEST_NETWORK, nu7, nu7), Duration::ZERO);
    assert_eq!(
        target_time_between(&TEST_NETWORK, nu7, nu7 - 1),
        Duration::ZERO
    );
    assert_eq!(
        target_time_between(&MAIN_NETWORK, BlockHeight(u32::MAX), BlockHeight(u32::MAX)),
        Duration::ZERO
    );
    assert_eq!(
        target_time_between(&MAIN_NETWORK, BlockHeight(u32::MAX), BlockHeight(0)),
        Duration::ZERO
    );
}

#[test]
#[cfg(feature = "local-consensus")]
fn network_without_nu7_keeps_the_post_blossom_spacing() {
    /// A height far above the Blossom activation height.
    const FAR_FUTURE_HEIGHT: BlockHeight = BlockHeight(10_000_000);
    // Blossom activates at its mainnet height, and NU7 never activates.
    let blossom = MAIN_NETWORK
        .activation_height(NetworkUpgrade::Blossom)
        .unwrap();
    let network = spacing_test_network(Some(blossom), None);

    assert_eq!(network.activation_height(NetworkUpgrade::Nu7), None);
    assert_eq!(
        pow_target_spacing(&network, FAR_FUTURE_HEIGHT),
        POST_BLOSSOM_POW_TARGET_SPACING
    );
    assert_eq!(
        pow_target_spacing(&network, BlockHeight(u32::MAX - 1)),
        POST_BLOSSOM_POW_TARGET_SPACING
    );

    // Every height from 1 through `u32::MAX`, without overflow: the heights `1..blossom`
    // precede Blossom activation and the heights `blossom..=u32::MAX` follow it.
    let pre_blossom_blocks = u32::from(blossom) - 1;
    let post_blossom_blocks = u32::MAX - u32::from(blossom) + 1;
    assert_eq!(
        target_time_between(&network, BlockHeight(0), BlockHeight(u32::MAX)),
        PRE_BLOSSOM_POW_TARGET_SPACING * pre_blossom_blocks
            + POST_BLOSSOM_POW_TARGET_SPACING * post_blossom_blocks
    );
}

#[test]
#[cfg(feature = "local-consensus")]
fn nu7_without_blossom_keeps_the_pre_blossom_spacing() {
    /// NU7 activates at the first block after genesis, as on a typical regtest network.
    const NU7_ACTIVATION: BlockHeight = BlockHeight(1);
    let network = spacing_test_network(None, Some(NU7_ACTIVATION));

    for height in [BlockHeight(0), NU7_ACTIVATION, BlockHeight(u32::MAX)] {
        assert_eq!(
            pow_target_spacing(&network, height),
            PRE_BLOSSOM_POW_TARGET_SPACING
        );
    }
    assert_eq!(
        target_time_between(&network, BlockHeight(0), BlockHeight(u32::MAX)),
        PRE_BLOSSOM_POW_TARGET_SPACING * u32::MAX
    );
}

#[test]
#[cfg(feature = "local-consensus")]
fn target_time_between_matches_the_sum_of_per_block_spacings() {
    /// Candidate activation heights for Blossom and NU7. Pairing every candidate with every
    /// other covers each upgrade never activating, and NU7 activating before, with, and after
    /// Blossom.
    const ACTIVATIONS: [Option<BlockHeight>; 3] =
        [None, Some(BlockHeight(3)), Some(BlockHeight(6))];
    /// Every range whose endpoints both lie below this height is checked; it exceeds every
    /// candidate activation height.
    const HEIGHT_LIMIT: u32 = 10;

    for blossom in ACTIVATIONS {
        for nu7 in ACTIVATIONS {
            let network = spacing_test_network(blossom, nu7);
            for from in (0..HEIGHT_LIMIT).map(BlockHeight) {
                for to in (0..HEIGHT_LIMIT).map(BlockHeight) {
                    let per_block_sum = (u32::from(from) + 1..=u32::from(to))
                        .map(|h| pow_target_spacing(&network, BlockHeight(h)))
                        .sum::<Duration>();
                    assert_eq!(
                        target_time_between(&network, from, to),
                        per_block_sum,
                        "from {from}, to {to}, network {network:?}"
                    );
                }
            }
        }
    }
}
