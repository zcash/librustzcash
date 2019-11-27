//! Consensus parameters.

use std::convert::TryFrom;
use std::fmt;

/// Zcash consensus parameters.
pub trait Parameters {
    fn activation_height(nu: NetworkUpgrade) -> Option<u32>;

    fn is_nu_active(nu: NetworkUpgrade, height: u32) -> bool {
        match Self::activation_height(nu) {
            Some(h) if h <= height => true,
            _ => false,
        }
    }
}

/// Marker struct for the production network.
#[derive(Clone, Copy, Debug)]
pub struct MainNetwork;

impl Parameters for MainNetwork {
    fn activation_height(nu: NetworkUpgrade) -> Option<u32> {
        match nu {
            NetworkUpgrade::Overwinter => Some(347_500),
            NetworkUpgrade::Sapling => Some(419_200),
            NetworkUpgrade::Blossom => Some(653_600),
            NetworkUpgrade::Heartwood => None,
        }
    }
}

/// Marker struct for the test network.
#[derive(Clone, Copy, Debug)]
pub struct TestNetwork;

impl Parameters for TestNetwork {
    fn activation_height(nu: NetworkUpgrade) -> Option<u32> {
        match nu {
            NetworkUpgrade::Overwinter => Some(207_500),
            NetworkUpgrade::Sapling => Some(280_000),
            NetworkUpgrade::Blossom => Some(584_000),
            NetworkUpgrade::Heartwood => None,
        }
    }
}

/// An event that occurs at a specified height on the Zcash chain, at which point the
/// consensus rules enforced by the network are altered.
///
/// See [ZIP 200](https://zips.z.cash/zip-0200) for more details.
#[derive(Clone, Copy, Debug)]
pub enum NetworkUpgrade {
    /// The [Overwinter] network upgrade.
    ///
    /// [Overwinter]: https://z.cash/upgrade/overwinter/
    Overwinter,
    /// The [Sapling] network upgrade.
    ///
    /// [Sapling]: https://z.cash/upgrade/sapling/
    Sapling,
    /// The [Blossom] network upgrade.
    ///
    /// [Blossom]: https://z.cash/upgrade/blossom/
    Blossom,
    /// The [Heartwood] network upgrade.
    ///
    /// [Heartwood]: https://z.cash/upgrade/heartwood/
    Heartwood,
}

impl fmt::Display for NetworkUpgrade {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NetworkUpgrade::Overwinter => write!(f, "Overwinter"),
            NetworkUpgrade::Sapling => write!(f, "Sapling"),
            NetworkUpgrade::Blossom => write!(f, "Blossom"),
            NetworkUpgrade::Heartwood => write!(f, "Heartwood"),
        }
    }
}

impl NetworkUpgrade {
    fn branch_id(self) -> BranchId {
        match self {
            NetworkUpgrade::Overwinter => BranchId::Overwinter,
            NetworkUpgrade::Sapling => BranchId::Sapling,
            NetworkUpgrade::Blossom => BranchId::Blossom,
            NetworkUpgrade::Heartwood => BranchId::Heartwood,
        }
    }
}

/// The network upgrades on the Zcash chain in order of activation.
///
/// This order corresponds to the activation heights, but because Rust enums are
/// full-fledged algebraic data types, we need to define it manually.
const UPGRADES_IN_ORDER: &[NetworkUpgrade] = &[
    NetworkUpgrade::Overwinter,
    NetworkUpgrade::Sapling,
    NetworkUpgrade::Blossom,
    NetworkUpgrade::Heartwood,
];

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
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum BranchId {
    /// The consensus rules at the launch of Zcash.
    Sprout,
    /// The consensus rules deployed by [`NetworkUpgrade::Overwinter`].
    Overwinter,
    /// The consensus rules deployed by [`NetworkUpgrade::Sapling`].
    Sapling,
    /// The consensus rules deployed by [`NetworkUpgrade::Blossom`].
    Blossom,
    /// The consensus rules deployed by [`NetworkUpgrade::Heartwood`].
    Heartwood,
}

impl TryFrom<u32> for BranchId {
    type Error = &'static str;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(BranchId::Sprout),
            0x5ba8_1b19 => Ok(BranchId::Overwinter),
            0x76b8_09bb => Ok(BranchId::Sapling),
            0x2bb4_0e60 => Ok(BranchId::Blossom),
            0xf5b9_230b => Ok(BranchId::Heartwood),
            _ => Err("Unknown consensus branch ID"),
        }
    }
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

impl BranchId {
    /// Returns the branch ID corresponding to the consensus rule set that is active at
    /// the given height.
    ///
    /// This is the branch ID that should be used when creating transactions.
    pub fn for_height<C: Parameters>(height: u32) -> Self {
        for nu in UPGRADES_IN_ORDER.iter().rev() {
            if C::is_nu_active(*nu, height) {
                return nu.branch_id();
            }
        }

        // Sprout rules apply before any network upgrade
        BranchId::Sprout
    }
}

#[cfg(test)]
mod tests {
    use std::convert::TryFrom;

    use super::{BranchId, MainNetwork, NetworkUpgrade, Parameters, UPGRADES_IN_ORDER};

    #[test]
    fn nu_ordering() {
        for i in 1..UPGRADES_IN_ORDER.len() {
            let nu_a = UPGRADES_IN_ORDER[i - 1];
            let nu_b = UPGRADES_IN_ORDER[i];
            match (
                MainNetwork::activation_height(nu_a),
                MainNetwork::activation_height(nu_b),
            ) {
                (Some(a), Some(b)) if a < b => (),
                (Some(_), None) => (),
                (None, None) => (),
                _ => panic!(
                    "{} should not be before {} in UPGRADES_IN_ORDER",
                    nu_a, nu_b
                ),
            }
        }
    }

    #[test]
    fn nu_is_active() {
        assert!(!MainNetwork::is_nu_active(NetworkUpgrade::Overwinter, 0));
        assert!(!MainNetwork::is_nu_active(
            NetworkUpgrade::Overwinter,
            347_499
        ));
        assert!(MainNetwork::is_nu_active(
            NetworkUpgrade::Overwinter,
            347_500
        ));
    }

    #[test]
    fn branch_id_from_u32() {
        assert_eq!(BranchId::try_from(0), Ok(BranchId::Sprout));
        assert!(BranchId::try_from(1).is_err());
    }

    #[test]
    fn branch_id_for_height() {
        assert_eq!(BranchId::for_height::<MainNetwork>(0), BranchId::Sprout,);
        assert_eq!(
            BranchId::for_height::<MainNetwork>(419_199),
            BranchId::Overwinter,
        );
        assert_eq!(
            BranchId::for_height::<MainNetwork>(419_200),
            BranchId::Sapling,
        );
        assert_eq!(
            BranchId::for_height::<MainNetwork>(5_000_000),
            BranchId::Blossom,
        );
    }
}
