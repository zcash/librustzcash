//! Consensus parameters for local networks, such as regtest networks.

use core::fmt;

use crate::consensus::{BlockHeight, NetworkType, NetworkUpgrade, Parameters, UPGRADES_IN_ORDER};

/// The consensus parameters of a local network, such as a regtest network: the activation
/// height of each network upgrade that activates on it.
///
/// A `LocalNetwork` is built from activation steps, each of which activates the network
/// upgrades that follow those already activated. Its activation heights therefore always
/// respect the [activation order](Parameters#activation-order) that [`Parameters`] requires.
/// Callers shall choose the heights that the full nodes they connect to are configured with.
///
/// # Examples
///
/// A regtest `zcashd` that activates every network upgrade through NU6 at height 1 has the
/// following `zcash.conf`:
///
/// ```text
/// ## NUPARAMS
/// nuparams=5ba81b19:1 # Overwinter
/// nuparams=76b809bb:1 # Sapling
/// nuparams=2bb40e60:1 # Blossom
/// nuparams=f5b9230b:1 # Heartwood
/// nuparams=e9ff75a6:1 # Canopy
/// nuparams=c2d6d0b4:1 # NU5
/// nuparams=c8e71055:1 # NU6
/// ```
///
/// One step describes it, and no later upgrade activates:
///
/// ```
/// use zcash_protocol::{
///     consensus::{BlockHeight, NetworkUpgrade, Parameters},
///     local_consensus::LocalNetwork,
/// };
///
/// let regtest = LocalNetwork::new(&[(NetworkUpgrade::Nu6, BlockHeight::from_u32(1))])?;
///
/// assert_eq!(
///     regtest.activation_height(NetworkUpgrade::Sapling),
///     Some(BlockHeight::from_u32(1))
/// );
/// assert_eq!(regtest.activation_height(NetworkUpgrade::Nu6_1), None);
/// # Ok::<(), zcash_protocol::local_consensus::ActivationOrderError>(())
/// ```
///
/// A network that activates its upgrades at several heights takes one step for each height:
///
/// ```
/// use zcash_protocol::{
///     consensus::{BlockHeight, NetworkUpgrade, Parameters},
///     local_consensus::LocalNetwork,
/// };
///
/// let regtest = LocalNetwork::new(&[
///     (NetworkUpgrade::Canopy, BlockHeight::from_u32(1)),
///     (NetworkUpgrade::Nu5, BlockHeight::from_u32(10)),
///     (NetworkUpgrade::Nu6, BlockHeight::from_u32(20)),
/// ])?;
///
/// assert_eq!(
///     regtest.activation_height(NetworkUpgrade::Heartwood),
///     Some(BlockHeight::from_u32(1))
/// );
/// assert_eq!(
///     regtest.activation_height(NetworkUpgrade::Nu5),
///     Some(BlockHeight::from_u32(10))
/// );
/// # Ok::<(), zcash_protocol::local_consensus::ActivationOrderError>(())
/// ```
#[derive(Clone, PartialEq, Eq, Copy, Debug, Hash)]
pub struct LocalNetwork {
    overwinter: Option<BlockHeight>,
    sapling: Option<BlockHeight>,
    blossom: Option<BlockHeight>,
    heartwood: Option<BlockHeight>,
    canopy: Option<BlockHeight>,
    nu5: Option<BlockHeight>,
    nu6: Option<BlockHeight>,
    nu6_1: Option<BlockHeight>,
    nu6_2: Option<BlockHeight>,
    nu6_3: Option<BlockHeight>,
    nu7: Option<BlockHeight>,
    #[cfg(zcash_unstable = "nutachyon")]
    nu_tachyon: Option<BlockHeight>,
}

impl LocalNetwork {
    /// The local network on which no network upgrade activates.
    const NO_UPGRADES: Self = Self {
        overwinter: None,
        sapling: None,
        blossom: None,
        heartwood: None,
        canopy: None,
        nu5: None,
        nu6: None,
        nu6_1: None,
        nu6_2: None,
        nu6_3: None,
        nu7: None,
        #[cfg(zcash_unstable = "nutachyon")]
        nu_tachyon: None,
    };

    /// Returns the local network that activates its network upgrades in the given steps.
    ///
    /// Each step `(upgrade, height)` activates at `height` every network upgrade up to and
    /// including `upgrade` that no earlier step activates. A network upgrade after the upgrade of
    /// the last step never activates. With no steps, no network upgrade activates.
    ///
    /// # Errors
    ///
    /// Returns the error of [`Self::activating_through`] for the first step that the network
    /// built from the steps before it cannot take.
    pub const fn new(
        steps: &[(NetworkUpgrade, BlockHeight)],
    ) -> Result<Self, ActivationOrderError> {
        let mut network = Self::NO_UPGRADES;
        let mut i = 0;
        while i < steps.len() {
            let (upgrade, height) = steps[i];
            network = match network.activating_through(upgrade, height) {
                Ok(extended) => extended,
                Err(e) => return Err(e),
            };
            i += 1;
        }
        Ok(network)
    }

    /// Returns the network that this network becomes when every network upgrade up to and
    /// including `upgrade` that does not activate on it activates at `height`. The activation
    /// heights that this network has are unchanged.
    ///
    /// # Errors
    ///
    /// - [`ActivationOrderError::AlreadyActivates`] if `upgrade` activates on this network.
    /// - [`ActivationOrderError::HeightBelowEarlierUpgrade`] if `height` is below the activation
    ///   height of a network upgrade that activates on this network.
    pub const fn activating_through(
        self,
        upgrade: NetworkUpgrade,
        height: BlockHeight,
    ) -> Result<Self, ActivationOrderError> {
        let mut network = self;
        // The latest upgrade that activates on this network, with its height.
        let mut latest: Option<(NetworkUpgrade, BlockHeight)> = None;
        let mut reached_upgrade = false;
        let mut i = 0;
        while i < UPGRADES_IN_ORDER.len() && !reached_upgrade {
            let current = UPGRADES_IN_ORDER[i];
            reached_upgrade = current as u8 == upgrade as u8;
            match self.activation(current) {
                Some(current_height) => {
                    if reached_upgrade {
                        return Err(ActivationOrderError::AlreadyActivates {
                            upgrade,
                            height: current_height,
                        });
                    }
                    latest = Some((current, current_height));
                }
                // The upgrades that activate on this network precede every upgrade that does
                // not, so `latest` is final here.
                None => {
                    if let Some((earlier_upgrade, earlier_height)) = latest
                        && height.to_u32() < earlier_height.to_u32()
                    {
                        return Err(ActivationOrderError::HeightBelowEarlierUpgrade {
                            upgrade,
                            height,
                            earlier_upgrade,
                            earlier_height,
                        });
                    }
                    network = network.with_activation(current, height);
                }
            }
            i += 1;
        }
        Ok(network)
    }

    /// Returns the activation height of `upgrade`, or `None` if it does not activate.
    const fn activation(&self, upgrade: NetworkUpgrade) -> Option<BlockHeight> {
        match upgrade {
            NetworkUpgrade::Overwinter => self.overwinter,
            NetworkUpgrade::Sapling => self.sapling,
            NetworkUpgrade::Blossom => self.blossom,
            NetworkUpgrade::Heartwood => self.heartwood,
            NetworkUpgrade::Canopy => self.canopy,
            NetworkUpgrade::Nu5 => self.nu5,
            NetworkUpgrade::Nu6 => self.nu6,
            NetworkUpgrade::Nu6_1 => self.nu6_1,
            NetworkUpgrade::Nu6_2 => self.nu6_2,
            NetworkUpgrade::Nu6_3 => self.nu6_3,
            NetworkUpgrade::Nu7 => self.nu7,
            #[cfg(zcash_unstable = "nutachyon")]
            NetworkUpgrade::NuTachyon => self.nu_tachyon,
        }
    }

    /// Returns this network with the activation height of `upgrade` set to `height`. The caller
    /// is responsible for the activation order.
    const fn with_activation(self, upgrade: NetworkUpgrade, height: BlockHeight) -> Self {
        let height = Some(height);
        match upgrade {
            NetworkUpgrade::Overwinter => Self {
                overwinter: height,
                ..self
            },
            NetworkUpgrade::Sapling => Self {
                sapling: height,
                ..self
            },
            NetworkUpgrade::Blossom => Self {
                blossom: height,
                ..self
            },
            NetworkUpgrade::Heartwood => Self {
                heartwood: height,
                ..self
            },
            NetworkUpgrade::Canopy => Self {
                canopy: height,
                ..self
            },
            NetworkUpgrade::Nu5 => Self {
                nu5: height,
                ..self
            },
            NetworkUpgrade::Nu6 => Self {
                nu6: height,
                ..self
            },
            NetworkUpgrade::Nu6_1 => Self {
                nu6_1: height,
                ..self
            },
            NetworkUpgrade::Nu6_2 => Self {
                nu6_2: height,
                ..self
            },
            NetworkUpgrade::Nu6_3 => Self {
                nu6_3: height,
                ..self
            },
            NetworkUpgrade::Nu7 => Self {
                nu7: height,
                ..self
            },
            #[cfg(zcash_unstable = "nutachyon")]
            NetworkUpgrade::NuTachyon => Self {
                nu_tachyon: height,
                ..self
            },
        }
    }
}

/// Parameters implementation for `LocalNetwork`
impl Parameters for LocalNetwork {
    fn network_type(&self) -> NetworkType {
        NetworkType::Regtest
    }

    fn activation_height(&self, nu: NetworkUpgrade) -> Option<BlockHeight> {
        self.activation(nu)
    }
}

/// The reason a [`LocalNetwork`] cannot activate further network upgrades as requested: doing so
/// would violate the [activation order](Parameters#activation-order).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ActivationOrderError {
    /// The network upgrade already activates on the network. A step may only activate upgrades
    /// after those that already activate.
    AlreadyActivates {
        /// The network upgrade that was to be activated.
        upgrade: NetworkUpgrade,
        /// The height at which it already activates.
        height: BlockHeight,
    },
    /// The requested height is below the activation height of an earlier network upgrade.
    HeightBelowEarlierUpgrade {
        /// The network upgrade that was to be activated.
        upgrade: NetworkUpgrade,
        /// The height at which it was to be activated.
        height: BlockHeight,
        /// The latest network upgrade that already activates on the network.
        earlier_upgrade: NetworkUpgrade,
        /// The activation height of `earlier_upgrade`.
        earlier_height: BlockHeight,
    },
}

impl fmt::Display for ActivationOrderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ActivationOrderError::AlreadyActivates { upgrade, height } => write!(
                f,
                "{upgrade} already activates at height {height}, so it cannot be activated again"
            ),
            ActivationOrderError::HeightBelowEarlierUpgrade {
                upgrade,
                height,
                earlier_upgrade,
                earlier_height,
            } => write!(
                f,
                "{upgrade} cannot activate at height {height}, below the height \
                 {earlier_height} at which the earlier upgrade {earlier_upgrade} activates"
            ),
        }
    }
}

impl core::error::Error for ActivationOrderError {}

/// Proptest strategies for local networks.
#[cfg(any(test, feature = "test-dependencies"))]
pub mod testing {
    use alloc::vec::Vec;

    use proptest::prelude::*;

    use crate::consensus::{BlockHeight, NetworkUpgrade, UPGRADES_IN_ORDER};

    use super::LocalNetwork;

    /// An arbitrary activation height. Small heights are frequent, so that several network
    /// upgrades often share one.
    fn arb_activation_height() -> impl Strategy<Value = BlockHeight> {
        prop_oneof![0u32..4, 0u32..5_000_000, any::<u32>()].prop_map(BlockHeight::from_u32)
    }

    /// Arbitrary activation heights for the first network upgrades in activation order, each no
    /// less than the one before. The upgrades after them do not activate.
    pub(crate) fn arb_activation_heights()
    -> impl Strategy<Value = Vec<(NetworkUpgrade, BlockHeight)>> {
        proptest::collection::vec(arb_activation_height(), 0..=UPGRADES_IN_ORDER.len()).prop_map(
            |mut heights| {
                heights.sort();
                UPGRADES_IN_ORDER.iter().copied().zip(heights).collect()
            },
        )
    }

    /// An arbitrary [`LocalNetwork`]. Every network that respects the activation order can be
    /// generated.
    pub fn arb_local_network() -> impl Strategy<Value = LocalNetwork> {
        arb_activation_heights().prop_map(|heights| {
            LocalNetwork::new(&heights).expect(
                "the heights of successive upgrades in activation order, none decreasing, are \
                 valid steps",
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use proptest::prelude::*;

    use crate::{
        consensus::{
            BlockHeight, BranchId, NetworkConstants, NetworkUpgrade, Parameters, UPGRADES_IN_ORDER,
        },
        constants,
    };

    use super::{
        ActivationOrderError, LocalNetwork,
        testing::{arb_activation_heights, arb_local_network},
    };

    /// Returns the network on which each network upgrade activates one block after the upgrade
    /// before it, starting at height 1, together with those heights.
    fn network_with_one_upgrade_per_height() -> (LocalNetwork, Vec<(NetworkUpgrade, BlockHeight)>) {
        let steps: Vec<_> = UPGRADES_IN_ORDER
            .iter()
            .copied()
            .zip((1u32..).map(BlockHeight::from_u32))
            .collect();
        let network = LocalNetwork::new(&steps).expect("the heights increase with the upgrades");
        (network, steps)
    }

    /// Returns the position of `branch` in the order of the consensus epochs, with the Sprout
    /// epoch first.
    fn epoch_position(branch: BranchId) -> usize {
        branch.network_upgrade().map_or(0, |upgrade| {
            1 + UPGRADES_IN_ORDER
                .iter()
                .position(|listed| *listed == upgrade)
                .expect("every network upgrade is listed in activation order")
        })
    }

    #[test]
    fn regtest_nu_activation() {
        let (regtest, steps) = network_with_one_upgrade_per_height();

        for (upgrade, height) in steps {
            assert!(regtest.is_nu_active(upgrade, height));
            assert!(!regtest.is_nu_active(upgrade, height - 1));
        }
    }

    #[test]
    fn regtest_activation_heights() {
        let (regtest, steps) = network_with_one_upgrade_per_height();

        for (upgrade, height) in steps {
            assert_eq!(regtest.activation_height(upgrade), Some(height));
        }
    }

    #[test]
    fn regtests_constants() {
        let (regtest, _) = network_with_one_upgrade_per_height();

        assert_eq!(regtest.coin_type(), constants::regtest::COIN_TYPE);
    }

    #[test]
    fn no_steps_activate_no_upgrade() {
        let network = LocalNetwork::new(&[]).expect("no step can be out of order");

        for upgrade in UPGRADES_IN_ORDER {
            assert_eq!(network.activation_height(*upgrade), None);
        }
    }

    #[test]
    fn a_step_activates_the_upgrades_no_earlier_step_does() {
        let (early, late) = (BlockHeight::from_u32(5), BlockHeight::from_u32(9));
        let network = LocalNetwork::new(&[
            (NetworkUpgrade::Sapling, early),
            (NetworkUpgrade::Canopy, late),
        ])
        .expect("the steps are in order");

        for (upgrade, expected) in [
            (NetworkUpgrade::Overwinter, Some(early)),
            (NetworkUpgrade::Sapling, Some(early)),
            (NetworkUpgrade::Blossom, Some(late)),
            (NetworkUpgrade::Heartwood, Some(late)),
            (NetworkUpgrade::Canopy, Some(late)),
            (NetworkUpgrade::Nu5, None),
        ] {
            assert_eq!(network.activation_height(upgrade), expected);
        }
    }

    #[test]
    fn steps_out_of_order_are_rejected() {
        let (early, late) = (BlockHeight::from_u32(5), BlockHeight::from_u32(9));

        // A step for an upgrade that an earlier step activates, whether named or not.
        for repeated in [NetworkUpgrade::Canopy, NetworkUpgrade::Sapling] {
            assert_eq!(
                LocalNetwork::new(&[(NetworkUpgrade::Canopy, early), (repeated, late)]),
                Err(ActivationOrderError::AlreadyActivates {
                    upgrade: repeated,
                    height: early,
                })
            );
        }

        // A step at a height below that of the step before it.
        assert_eq!(
            LocalNetwork::new(&[(NetworkUpgrade::Canopy, late), (NetworkUpgrade::Nu5, early)]),
            Err(ActivationOrderError::HeightBelowEarlierUpgrade {
                upgrade: NetworkUpgrade::Nu5,
                height: early,
                earlier_upgrade: NetworkUpgrade::Canopy,
                earlier_height: late,
            })
        );
    }

    proptest! {
        /// Every network respects the activation order: a network upgrade activates only if the
        /// upgrade before it activates, at a height no greater.
        #[test]
        fn networks_respect_the_activation_order(network in arb_local_network()) {
            for pair in UPGRADES_IN_ORDER.windows(2) {
                let earlier = network.activation_height(pair[0]);
                let later = network.activation_height(pair[1]);
                prop_assert!(
                    later.is_none_or(|later| earlier.is_some_and(|earlier| earlier <= later)),
                    "{:?} at {:?} precedes {:?} at {:?}",
                    pair[0], earlier, pair[1], later
                );
            }
        }

        /// Every assignment of heights that respects the activation order is the activation
        /// heights of a network.
        #[test]
        fn every_ordered_assignment_is_a_network(heights in arb_activation_heights()) {
            let network = LocalNetwork::new(&heights);
            prop_assert!(network.is_ok());
            for (i, upgrade) in UPGRADES_IN_ORDER.iter().enumerate() {
                prop_assert_eq!(
                    network.map(|network| network.activation_height(*upgrade)),
                    Ok(heights.get(i).map(|(_, height)| *height))
                );
            }
        }

        /// A network upgrade activates at the height of the first step for it or for a later
        /// upgrade, and never activates if there is no such step.
        #[test]
        fn an_upgrade_activates_at_the_first_step_at_or_after_it(
            heights in arb_activation_heights(),
            is_step in proptest::collection::vec(any::<bool>(), UPGRADES_IN_ORDER.len()),
        ) {
            let steps: Vec<_> = heights
                .iter()
                .copied()
                .zip(&is_step)
                .filter_map(|(step, is_step)| is_step.then_some(step))
                .collect();
            let network = LocalNetwork::new(&steps);
            prop_assert!(network.is_ok());
            for (i, upgrade) in UPGRADES_IN_ORDER.iter().enumerate() {
                let expected = heights
                    .iter()
                    .zip(&is_step)
                    .skip(i)
                    .find_map(|((_, height), is_step)| is_step.then_some(*height));
                prop_assert_eq!(
                    network.map(|network| network.activation_height(*upgrade)),
                    Ok(expected)
                );
            }
        }

        /// The steps of `new` are successive calls to `activating_through`.
        #[test]
        fn new_takes_its_steps_through_activating_through(
            heights in arb_activation_heights(),
        ) {
            let stepwise = heights.iter().try_fold(
                LocalNetwork::new(&[])?,
                |network, (upgrade, height)| network.activating_through(*upgrade, *height),
            );
            prop_assert_eq!(LocalNetwork::new(&heights), stepwise);
        }

        /// An upgrade that already activates cannot be activated again, at any height.
        #[test]
        fn activating_an_active_upgrade_is_rejected(
            network in arb_local_network(),
            height in any::<u32>().prop_map(BlockHeight::from_u32),
        ) {
            for upgrade in UPGRADES_IN_ORDER {
                if let Some(active_from) = network.activation_height(*upgrade) {
                    prop_assert_eq!(
                        network.activating_through(*upgrade, height),
                        Err(ActivationOrderError::AlreadyActivates {
                            upgrade: *upgrade,
                            height: active_from,
                        })
                    );
                }
            }
        }

        /// A further upgrade activates at any height from that of the latest active upgrade on,
        /// and at no height below it. The heights of the active upgrades are kept.
        #[test]
        fn a_further_upgrade_activates_no_earlier_than_the_latest(
            network in arb_local_network(),
            height in any::<u32>().prop_map(BlockHeight::from_u32),
        ) {
            let latest = UPGRADES_IN_ORDER
                .iter()
                .rev()
                .find_map(|upgrade| Some(*upgrade).zip(network.activation_height(*upgrade)));
            for upgrade in UPGRADES_IN_ORDER
                .iter()
                .filter(|upgrade| network.activation_height(**upgrade).is_none())
            {
                let extended = network.activating_through(*upgrade, height);
                match latest {
                    Some((earlier_upgrade, earlier_height)) if height < earlier_height => {
                        prop_assert_eq!(
                            extended,
                            Err(ActivationOrderError::HeightBelowEarlierUpgrade {
                                upgrade: *upgrade,
                                height,
                                earlier_upgrade,
                                earlier_height,
                            })
                        );
                    }
                    _ => {
                        prop_assert!(extended.is_ok());
                        for other in UPGRADES_IN_ORDER {
                            let expected = network.activation_height(*other).or_else(|| {
                                (epoch_position(other.branch_id())
                                    <= epoch_position(upgrade.branch_id()))
                                .then_some(height)
                            });
                            prop_assert_eq!(
                                extended.map(|extended| extended.activation_height(*other)),
                                Ok(expected)
                            );
                        }
                    }
                }
            }
        }

        /// The consensus epoch at a height is the epoch of the latest network upgrade active at
        /// that height: an upgrade is active exactly when its epoch is no later than the epoch
        /// at the height.
        #[test]
        fn an_upgrade_is_active_exactly_from_its_epoch_on(
            network in arb_local_network(),
            height in prop_oneof![0u32..8, any::<u32>()].prop_map(BlockHeight::from_u32),
        ) {
            let epoch = epoch_position(BranchId::for_height(&network, height));
            for upgrade in UPGRADES_IN_ORDER {
                prop_assert_eq!(
                    network.is_nu_active(*upgrade, height),
                    epoch_position(upgrade.branch_id()) <= epoch,
                    "{:?} at height {:?}", upgrade, height
                );
            }
        }
    }
}
