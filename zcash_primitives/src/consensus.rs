//! Consensus parameters.

/// A globally-unique identifier for a set of consensus rules within the Zcash chain.
///
/// Each branch ID in this enum corresponds to one of the epochs between a pair of Zcash
/// network upgrades. For example, `BranchId::Overwinter` corresponds to the blocks
/// starting at Overwinter activation, and ending the block before Sapling activation.
///
/// The main use of the branch ID is in signature generation: transactions commit to a
/// specific branch ID by including it as part of [`signature_hash`]. This ensures
/// two-way replay protection for transactions across network upgrades.
///
/// See [ZIP 200](https://zips.z.cash/zip-0200) for more details.
///
/// [`signature_hash`]: crate::transaction::signature_hash
#[derive(Clone, Copy, Debug)]
pub enum BranchId {
    /// The consensus rules at the launch of Zcash.
    Sprout,
    /// The consensus rules deployed in the [Overwinter] network upgrade.
    ///
    /// [Overwinter]: https://z.cash/upgrade/overwinter/
    Overwinter,
    /// The consensus rules deployed in the [Sapling] network upgrade.
    ///
    /// [Sapling]: https://z.cash/upgrade/sapling/
    Sapling,
    /// The consensus rules deployed in the [Blossom] network upgrade.
    ///
    /// [Blossom]: https://z.cash/upgrade/blossom/
    Blossom,
    /// The consensus rules deployed in the [Heartwood] network upgrade.
    ///
    /// [Heartwood]: https://z.cash/upgrade/heartwood/
    Heartwood,
}

impl From<BranchId> for u32 {
    fn from(consensus_branch_id: BranchId) -> u32 {
        match consensus_branch_id {
            BranchId::Sprout => 0,
            BranchId::Overwinter => 0x5ba8_1b19,
            BranchId::Sapling => 0x76b8_09bb,
            BranchId::Blossom => 0x2bb4_0e60,
            BranchId::Heartwood => 0xf5b9_230b,
        }
    }
}
