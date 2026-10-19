//! The per-block limits on shielded actions that [ZIP 218] imposes, and a check of a transaction's
//! shielded component counts against them.
//!
//! In a block at a height where NU7 is active, the Orchard actions, the Ironwood actions, the
//! Sapling spends and outputs, and the Sprout JoinSplits are each bounded, and so is their weighted
//! total across all pools. A transaction whose own counts exceed any of these bounds therefore
//! cannot be included in any block at such a height.
//!
//! [`ShieldedActionCounts`] holds the counts of one transaction; [`ShieldedActionCounts::check`]
//! verifies them against the bounds.
//!
//! [ZIP 218]: https://zips.z.cash/zip-0218

use core::{error, fmt};

use crate::consensus::{self, BlockHeight, NetworkUpgrade};

/// The most shielded actions that [ZIP 218] allows in a block across all pools (the ZIP's
/// `GlobalShieldedBudget`), counted by [`ShieldedActionCounts::shielded_cost`].
///
/// [ZIP 218]: https://zips.z.cash/zip-0218
pub const GLOBAL_SHIELDED_BUDGET: usize = 330;

/// The most Orchard actions, and separately the most Ironwood actions, that [ZIP 218] allows in a
/// block (the ZIP's `OrchardProtocolBlockActionLimit`).
///
/// [ZIP 218]: https://zips.z.cash/zip-0218
pub const ORCHARD_PROTOCOL_BLOCK_ACTION_LIMIT: usize = 330;

/// The most Sapling spends and outputs together that [ZIP 218] allows in a block (the ZIP's
/// `SaplingBlockIOLimit`).
///
/// [ZIP 218]: https://zips.z.cash/zip-0218
pub const SAPLING_BLOCK_IO_LIMIT: usize = 300;

/// The most Sprout JoinSplits that [ZIP 218] allows in a block (the ZIP's
/// `SproutBlockJoinSplitLimit`): none.
///
/// [ZIP 218]: https://zips.z.cash/zip-0218
pub const SPROUT_BLOCK_JOINSPLIT_LIMIT: usize = 0;

/// The shielded actions that [ZIP 218] counts one Sprout JoinSplit as, towards
/// [`GLOBAL_SHIELDED_BUDGET`].
///
/// [ZIP 218]: https://zips.z.cash/zip-0218
const SPROUT_JOINSPLIT_SHIELDED_COST: usize = 2;

/// Returns `true` if the [ZIP 218] limits bind a block at `height` on the network that `params`
/// describes, which is the case exactly when NU7 is active at `height`.
///
/// [ZIP 218]: https://zips.z.cash/zip-0218
pub fn limits_apply<P: consensus::Parameters>(params: &P, height: BlockHeight) -> bool {
    params.is_nu_active(NetworkUpgrade::Nu7, height)
}

/// A bound that [ZIP 218] places on the shielded contents of a block.
///
/// [ZIP 218]: https://zips.z.cash/zip-0218
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ShieldedBlockLimit {
    /// The Orchard actions, bounded by [`ORCHARD_PROTOCOL_BLOCK_ACTION_LIMIT`].
    OrchardActions,
    /// The Ironwood actions, bounded by [`ORCHARD_PROTOCOL_BLOCK_ACTION_LIMIT`] separately from
    /// the Orchard actions.
    IronwoodActions,
    /// The Sapling spends and outputs together, bounded by [`SAPLING_BLOCK_IO_LIMIT`].
    SaplingSpendsAndOutputs,
    /// The Sprout JoinSplits, bounded by [`SPROUT_BLOCK_JOINSPLIT_LIMIT`].
    SproutJoinSplits,
    /// The shielded actions across all pools, bounded by [`GLOBAL_SHIELDED_BUDGET`].
    GlobalShieldedBudget,
}

impl ShieldedBlockLimit {
    /// Returns the largest count that this limit allows in a block.
    pub const fn maximum(self) -> usize {
        match self {
            Self::OrchardActions | Self::IronwoodActions => ORCHARD_PROTOCOL_BLOCK_ACTION_LIMIT,
            Self::SaplingSpendsAndOutputs => SAPLING_BLOCK_IO_LIMIT,
            Self::SproutJoinSplits => SPROUT_BLOCK_JOINSPLIT_LIMIT,
            Self::GlobalShieldedBudget => GLOBAL_SHIELDED_BUDGET,
        }
    }
}

impl fmt::Display for ShieldedBlockLimit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::OrchardActions => "Orchard actions",
            Self::IronwoodActions => "Ironwood actions",
            Self::SaplingSpendsAndOutputs => "Sapling spends and outputs",
            Self::SproutJoinSplits => "Sprout JoinSplits",
            Self::GlobalShieldedBudget => "shielded actions across all pools",
        })
    }
}

/// The numbers of shielded components in a transaction, as counted against the [ZIP 218] limits.
///
/// Each count is of the components that the transaction contains, so the padding and dummy
/// components of a built transaction are included.
///
/// [ZIP 218]: https://zips.z.cash/zip-0218
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ShieldedActionCounts {
    pub(crate) orchard_actions: usize,
    pub(crate) ironwood_actions: usize,
    pub(crate) sapling_spends: usize,
    pub(crate) sapling_outputs: usize,
    pub(crate) sprout_joinsplits: usize,
}

impl ShieldedActionCounts {
    /// Counts with no shielded components.
    pub const ZERO: Self = Self {
        orchard_actions: 0,
        ironwood_actions: 0,
        sapling_spends: 0,
        sapling_outputs: 0,
        sprout_joinsplits: 0,
    };

    /// Returns these counts with the number of Orchard actions set to `n`.
    #[must_use]
    pub const fn with_orchard_actions(self, n: usize) -> Self {
        Self {
            orchard_actions: n,
            ..self
        }
    }

    /// Returns these counts with the number of Ironwood actions set to `n`.
    #[must_use]
    pub const fn with_ironwood_actions(self, n: usize) -> Self {
        Self {
            ironwood_actions: n,
            ..self
        }
    }

    /// Returns these counts with the numbers of Sapling spends and outputs set to `spends` and
    /// `outputs`.
    #[must_use]
    pub const fn with_sapling(self, spends: usize, outputs: usize) -> Self {
        Self {
            sapling_spends: spends,
            sapling_outputs: outputs,
            ..self
        }
    }

    /// Returns these counts with the number of Sprout JoinSplits set to `n`.
    #[must_use]
    pub const fn with_sprout_joinsplits(self, n: usize) -> Self {
        Self {
            sprout_joinsplits: n,
            ..self
        }
    }

    /// Returns the number of Orchard actions.
    pub const fn orchard_actions(&self) -> usize {
        self.orchard_actions
    }

    /// Returns the number of Ironwood actions.
    pub const fn ironwood_actions(&self) -> usize {
        self.ironwood_actions
    }

    /// Returns the number of Sapling spends.
    pub const fn sapling_spends(&self) -> usize {
        self.sapling_spends
    }

    /// Returns the number of Sapling outputs.
    pub const fn sapling_outputs(&self) -> usize {
        self.sapling_outputs
    }

    /// Returns the number of Sprout JoinSplits.
    pub const fn sprout_joinsplits(&self) -> usize {
        self.sprout_joinsplits
    }

    /// Returns the Sapling spends and outputs together, saturating at `usize::MAX`.
    const fn sapling_spends_and_outputs(&self) -> usize {
        self.sapling_spends.saturating_add(self.sapling_outputs)
    }

    /// Returns the shielded cost of these counts, which [`GLOBAL_SHIELDED_BUDGET`] bounds: the
    /// Orchard actions, the Ironwood actions, the Sapling spends and outputs, and two for each
    /// Sprout JoinSplit, summed. Saturates at `usize::MAX`.
    pub fn shielded_cost(&self) -> usize {
        self.orchard_actions
            .saturating_add(self.ironwood_actions)
            .saturating_add(self.sapling_spends_and_outputs())
            .saturating_add(
                self.sprout_joinsplits
                    .saturating_mul(SPROUT_JOINSPLIT_SHIELDED_COST),
            )
    }

    /// Checks these counts against the [ZIP 218] limits in this order: Orchard actions, Ironwood
    /// actions, Sapling spends and outputs, Sprout JoinSplits, then the shielded actions across
    /// all pools. A count equal to its maximum passes.
    ///
    /// The check does not depend on a height; [`limits_apply`] says whether the limits bind a
    /// block at a given height.
    ///
    /// # Errors
    ///
    /// Returns [`ShieldedLimitExceeded`] for the first limit in that order that the counts
    /// exceed.
    ///
    /// [ZIP 218]: https://zips.z.cash/zip-0218
    pub fn check(&self) -> Result<(), ShieldedLimitExceeded> {
        let counted = [
            (ShieldedBlockLimit::OrchardActions, self.orchard_actions),
            (ShieldedBlockLimit::IronwoodActions, self.ironwood_actions),
            (
                ShieldedBlockLimit::SaplingSpendsAndOutputs,
                self.sapling_spends_and_outputs(),
            ),
            (ShieldedBlockLimit::SproutJoinSplits, self.sprout_joinsplits),
            (
                ShieldedBlockLimit::GlobalShieldedBudget,
                self.shielded_cost(),
            ),
        ];

        for (limit, count) in counted {
            if count > limit.maximum() {
                return Err(ShieldedLimitExceeded {
                    limit,
                    count,
                    counts: *self,
                });
            }
        }

        Ok(())
    }
}

/// The failure of [`ShieldedActionCounts::check`]: a count exceeds the most that one of the
/// [ZIP 218] limits allows in a block.
///
/// A transaction with these counts cannot be included in any block at a height where NU7 is
/// active.
///
/// [ZIP 218]: https://zips.z.cash/zip-0218
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShieldedLimitExceeded {
    pub(crate) limit: ShieldedBlockLimit,
    pub(crate) count: usize,
    pub(crate) counts: ShieldedActionCounts,
}

impl ShieldedLimitExceeded {
    /// Returns the limit that was exceeded.
    pub const fn limit(&self) -> ShieldedBlockLimit {
        self.limit
    }

    /// Returns the count that exceeds the limit: the number of components that the limit bounds.
    pub const fn count(&self) -> usize {
        self.count
    }

    /// Returns the largest count that the exceeded limit allows.
    pub const fn maximum(&self) -> usize {
        self.limit.maximum()
    }

    /// Returns the counts that were checked.
    pub const fn counts(&self) -> ShieldedActionCounts {
        self.counts
    }
}

impl fmt::Display for ShieldedLimitExceeded {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} exceed the {} that ZIP 218 allows in a block",
            self.count,
            self.limit,
            self.maximum(),
        )
    }
}

impl error::Error for ShieldedLimitExceeded {}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use super::{
        GLOBAL_SHIELDED_BUDGET, ORCHARD_PROTOCOL_BLOCK_ACTION_LIMIT, SAPLING_BLOCK_IO_LIMIT,
        SPROUT_BLOCK_JOINSPLIT_LIMIT, ShieldedActionCounts, ShieldedBlockLimit,
        ShieldedLimitExceeded, limits_apply,
    };
    use crate::consensus::{Network, NetworkUpgrade, Parameters};

    /// Orchard actions in the [ZIP 218] example of a transaction that stays within each
    /// protocol's own limit but overruns the global budget.
    ///
    /// [ZIP 218]: https://zips.z.cash/zip-0218
    const EXAMPLE_ORCHARD_ACTIONS: usize = 200;

    /// Ironwood actions in the same example.
    const EXAMPLE_IRONWOOD_ACTIONS: usize = 200;

    const _: () = assert!(
        EXAMPLE_ORCHARD_ACTIONS <= ORCHARD_PROTOCOL_BLOCK_ACTION_LIMIT
            && EXAMPLE_IRONWOOD_ACTIONS <= ORCHARD_PROTOCOL_BLOCK_ACTION_LIMIT
            && EXAMPLE_ORCHARD_ACTIONS + EXAMPLE_IRONWOOD_ACTIONS > GLOBAL_SHIELDED_BUDGET
    );

    /// Orchard actions that, with the Sapling spends and outputs below, exactly fill the global
    /// budget while each pool stays within its own limit.
    const FILLING_ORCHARD_ACTIONS: usize = 165;

    /// Sapling spends in the same combination.
    const FILLING_SAPLING_SPENDS: usize = 100;

    /// Sapling outputs in the same combination.
    const FILLING_SAPLING_OUTPUTS: usize = 65;

    const _: () = assert!(
        FILLING_ORCHARD_ACTIONS + FILLING_SAPLING_SPENDS + FILLING_SAPLING_OUTPUTS
            == GLOBAL_SHIELDED_BUDGET
    );

    /// Orchard actions that accompany a JoinSplit in the cost example; unlike the JoinSplit, each
    /// counts once.
    const ORCHARD_ACTIONS_NEXT_TO_JOINSPLIT: usize = 10;

    /// What one JoinSplit adds to the global shielded cost. It is restated here, not shared with
    /// the implementation, so that the tests pin the ZIP's weight.
    const JOINSPLIT_COST: usize = 2;

    /// An Orchard action count that differs from every other `DISTINCT_` count, so that a field
    /// mixed up with another shows.
    const DISTINCT_ORCHARD_ACTIONS: usize = 1;

    /// An Ironwood action count that differs from every other `DISTINCT_` count.
    const DISTINCT_IRONWOOD_ACTIONS: usize = 2;

    /// A Sapling spend count that differs from every other `DISTINCT_` count.
    const DISTINCT_SAPLING_SPENDS: usize = 3;

    /// A Sapling output count that differs from every other `DISTINCT_` count.
    const DISTINCT_SAPLING_OUTPUTS: usize = 4;

    /// A Sprout JoinSplit count that differs from every other `DISTINCT_` count.
    const DISTINCT_SPROUT_JOINSPLITS: usize = 5;

    /// Splits `total` into two counts that add up to it, so that neither reaches it alone.
    fn split_in_two(total: usize) -> (usize, usize) {
        let first = total / 2;
        (first, total - first)
    }

    /// Counts in which every field differs from the others.
    fn distinct_counts() -> ShieldedActionCounts {
        ShieldedActionCounts::ZERO
            .with_orchard_actions(DISTINCT_ORCHARD_ACTIONS)
            .with_ironwood_actions(DISTINCT_IRONWOOD_ACTIONS)
            .with_sapling(DISTINCT_SAPLING_SPENDS, DISTINCT_SAPLING_OUTPUTS)
            .with_sprout_joinsplits(DISTINCT_SPROUT_JOINSPLITS)
    }

    /// Returns the error that `counts` fails its check with.
    fn exceeded(counts: ShieldedActionCounts) -> ShieldedLimitExceeded {
        counts
            .check()
            .expect_err("the counts should exceed a limit")
    }

    /// Asserts that `at_maximum` passes its check and that `one_above` fails it on exactly
    /// `limit`, reporting one more than that limit's maximum.
    fn assert_boundary(
        limit: ShieldedBlockLimit,
        at_maximum: ShieldedActionCounts,
        one_above: ShieldedActionCounts,
    ) {
        assert_eq!(at_maximum.check(), Ok(()), "{limit} at its maximum");

        let err = exceeded(one_above);
        assert_eq!(err.limit(), limit);
        assert_eq!(err.count(), limit.maximum() + 1);
        assert_eq!(err.maximum(), limit.maximum());
    }

    #[test]
    fn constants_carry_the_zip_218_values() {
        assert_eq!(GLOBAL_SHIELDED_BUDGET, 330);
        assert_eq!(ORCHARD_PROTOCOL_BLOCK_ACTION_LIMIT, 330);
        assert_eq!(SAPLING_BLOCK_IO_LIMIT, 300);
        assert_eq!(SPROUT_BLOCK_JOINSPLIT_LIMIT, 0);

        assert_eq!(
            ShieldedBlockLimit::OrchardActions.maximum(),
            ORCHARD_PROTOCOL_BLOCK_ACTION_LIMIT
        );
        assert_eq!(
            ShieldedBlockLimit::IronwoodActions.maximum(),
            ORCHARD_PROTOCOL_BLOCK_ACTION_LIMIT
        );
        assert_eq!(
            ShieldedBlockLimit::SaplingSpendsAndOutputs.maximum(),
            SAPLING_BLOCK_IO_LIMIT
        );
        assert_eq!(
            ShieldedBlockLimit::SproutJoinSplits.maximum(),
            SPROUT_BLOCK_JOINSPLIT_LIMIT
        );
        assert_eq!(
            ShieldedBlockLimit::GlobalShieldedBudget.maximum(),
            GLOBAL_SHIELDED_BUDGET
        );
    }

    #[test]
    fn each_limit_passes_at_its_maximum_and_fails_one_above() {
        let zero = ShieldedActionCounts::ZERO;
        assert_eq!(zero.check(), Ok(()));

        assert_boundary(
            ShieldedBlockLimit::OrchardActions,
            zero.with_orchard_actions(ORCHARD_PROTOCOL_BLOCK_ACTION_LIMIT),
            zero.with_orchard_actions(ORCHARD_PROTOCOL_BLOCK_ACTION_LIMIT + 1),
        );

        assert_boundary(
            ShieldedBlockLimit::IronwoodActions,
            zero.with_ironwood_actions(ORCHARD_PROTOCOL_BLOCK_ACTION_LIMIT),
            zero.with_ironwood_actions(ORCHARD_PROTOCOL_BLOCK_ACTION_LIMIT + 1),
        );

        // Spends and outputs share one limit, so split it between them.
        let (spends, outputs) = split_in_two(SAPLING_BLOCK_IO_LIMIT);
        assert_boundary(
            ShieldedBlockLimit::SaplingSpendsAndOutputs,
            zero.with_sapling(spends, outputs),
            zero.with_sapling(spends, outputs + 1),
        );

        assert_boundary(
            ShieldedBlockLimit::SproutJoinSplits,
            zero.with_sprout_joinsplits(SPROUT_BLOCK_JOINSPLIT_LIMIT),
            zero.with_sprout_joinsplits(SPROUT_BLOCK_JOINSPLIT_LIMIT + 1),
        );

        // Orchard and Ironwood actions share the global budget, so split it between them.
        let (orchard, ironwood) = split_in_two(GLOBAL_SHIELDED_BUDGET);
        assert_boundary(
            ShieldedBlockLimit::GlobalShieldedBudget,
            zero.with_orchard_actions(orchard)
                .with_ironwood_actions(ironwood),
            zero.with_orchard_actions(orchard)
                .with_ironwood_actions(ironwood + 1),
        );
    }

    #[test]
    fn orchard_and_ironwood_share_the_global_budget() {
        let counts = ShieldedActionCounts::ZERO
            .with_orchard_actions(EXAMPLE_ORCHARD_ACTIONS)
            .with_ironwood_actions(EXAMPLE_IRONWOOD_ACTIONS);

        // Neither protocol exceeds its own limit; only their sum does.
        let err = exceeded(counts);
        assert_eq!(err.limit(), ShieldedBlockLimit::GlobalShieldedBudget);
        assert_eq!(
            err.count(),
            EXAMPLE_ORCHARD_ACTIONS + EXAMPLE_IRONWOOD_ACTIONS
        );
    }

    #[test]
    fn sapling_and_orchard_actions_fill_the_global_budget() {
        let filling = ShieldedActionCounts::ZERO
            .with_orchard_actions(FILLING_ORCHARD_ACTIONS)
            .with_sapling(FILLING_SAPLING_SPENDS, FILLING_SAPLING_OUTPUTS);
        assert_eq!(filling.shielded_cost(), GLOBAL_SHIELDED_BUDGET);
        assert_eq!(filling.check(), Ok(()));

        // One more Sapling output, or one more Sapling spend, overruns the budget.
        for over in [
            filling.with_sapling(FILLING_SAPLING_SPENDS, FILLING_SAPLING_OUTPUTS + 1),
            filling.with_sapling(FILLING_SAPLING_SPENDS + 1, FILLING_SAPLING_OUTPUTS),
        ] {
            let err = exceeded(over);
            assert_eq!(err.limit(), ShieldedBlockLimit::GlobalShieldedBudget);
            assert_eq!(err.count(), GLOBAL_SHIELDED_BUDGET + 1);
        }
    }

    #[test]
    fn the_first_exceeded_limit_is_reported() {
        let one_over_protocol_limit = ORCHARD_PROTOCOL_BLOCK_ACTION_LIMIT + 1;

        // Orchard and Ironwood are both over: Orchard comes first.
        let counts = ShieldedActionCounts::ZERO
            .with_orchard_actions(one_over_protocol_limit)
            .with_ironwood_actions(one_over_protocol_limit);
        assert_eq!(exceeded(counts).limit(), ShieldedBlockLimit::OrchardActions);

        // Ironwood is over, and Sapling at its maximum pushes the global budget over as well:
        // Ironwood comes first.
        let (spends, outputs) = split_in_two(SAPLING_BLOCK_IO_LIMIT);
        let counts = ShieldedActionCounts::ZERO
            .with_ironwood_actions(one_over_protocol_limit)
            .with_sapling(spends, outputs);
        assert!(counts.shielded_cost() > GLOBAL_SHIELDED_BUDGET);
        assert_eq!(
            exceeded(counts).limit(),
            ShieldedBlockLimit::IronwoodActions
        );

        // With every limit exceeded the earliest is reported, and relaxing it in turn exposes the
        // next one in the order.
        let counts = ShieldedActionCounts::ZERO
            .with_orchard_actions(one_over_protocol_limit)
            .with_ironwood_actions(one_over_protocol_limit)
            .with_sapling(SAPLING_BLOCK_IO_LIMIT + 1, 0)
            .with_sprout_joinsplits(SPROUT_BLOCK_JOINSPLIT_LIMIT + 1);
        assert_eq!(exceeded(counts).limit(), ShieldedBlockLimit::OrchardActions);

        let counts = counts.with_orchard_actions(0);
        assert_eq!(
            exceeded(counts).limit(),
            ShieldedBlockLimit::IronwoodActions
        );

        let counts = counts.with_ironwood_actions(0);
        assert_eq!(
            exceeded(counts).limit(),
            ShieldedBlockLimit::SaplingSpendsAndOutputs
        );

        let counts = counts.with_sapling(0, 0);
        assert_eq!(
            exceeded(counts).limit(),
            ShieldedBlockLimit::SproutJoinSplits
        );

        // The global budget is last: a JoinSplit on top of a full Orchard bundle overruns it too,
        // yet is reported as a JoinSplit.
        let counts = counts.with_orchard_actions(ORCHARD_PROTOCOL_BLOCK_ACTION_LIMIT);
        assert!(counts.shielded_cost() > GLOBAL_SHIELDED_BUDGET);
        assert_eq!(
            exceeded(counts).limit(),
            ShieldedBlockLimit::SproutJoinSplits
        );
    }

    #[test]
    fn joinsplits_count_twice_in_the_global_budget() {
        let counts = ShieldedActionCounts::ZERO
            .with_orchard_actions(ORCHARD_ACTIONS_NEXT_TO_JOINSPLIT)
            .with_sprout_joinsplits(1);
        assert_eq!(
            counts.shielded_cost(),
            ORCHARD_ACTIONS_NEXT_TO_JOINSPLIT + JOINSPLIT_COST
        );
    }

    #[test]
    fn shielded_cost_saturates() {
        let orchard_and_ironwood = ShieldedActionCounts::ZERO
            .with_orchard_actions(usize::MAX)
            .with_ironwood_actions(1);
        assert_eq!(orchard_and_ironwood.shielded_cost(), usize::MAX);

        // Every other way of overflowing the cost saturates as well.
        let sapling = ShieldedActionCounts::ZERO.with_sapling(usize::MAX, 1);
        assert_eq!(sapling.shielded_cost(), usize::MAX);

        let joinsplits = ShieldedActionCounts::ZERO.with_sprout_joinsplits(usize::MAX);
        assert_eq!(joinsplits.shielded_cost(), usize::MAX);

        // The check reports the saturated count instead of overflowing.
        let err = exceeded(orchard_and_ironwood);
        assert_eq!(err.limit(), ShieldedBlockLimit::OrchardActions);
        assert_eq!(err.count(), usize::MAX);

        let err = exceeded(sapling);
        assert_eq!(err.limit(), ShieldedBlockLimit::SaplingSpendsAndOutputs);
        assert_eq!(err.count(), usize::MAX);

        let err = exceeded(joinsplits);
        assert_eq!(err.limit(), ShieldedBlockLimit::SproutJoinSplits);
        assert_eq!(err.count(), usize::MAX);
    }

    #[test]
    fn the_error_reports_its_counts() {
        // Ironwood is over, and so is the JoinSplit count, which comes later in the order.
        let counts =
            distinct_counts().with_ironwood_actions(ORCHARD_PROTOCOL_BLOCK_ACTION_LIMIT + 1);
        let err = exceeded(counts);

        assert_eq!(err.counts(), counts);
        assert_eq!(err.counts().sprout_joinsplits(), DISTINCT_SPROUT_JOINSPLITS);
        assert_eq!(err.limit(), ShieldedBlockLimit::IronwoodActions);
        assert_eq!(err.count(), ORCHARD_PROTOCOL_BLOCK_ACTION_LIMIT + 1);
        assert_eq!(err.maximum(), ORCHARD_PROTOCOL_BLOCK_ACTION_LIMIT);

        assert_eq!(
            err.to_string(),
            "331 Ironwood actions exceed the 330 that ZIP 218 allows in a block"
        );

        // The error is a `core::error::Error`.
        let _: &dyn core::error::Error = &err;
    }

    #[test]
    fn limits_apply_from_the_nu7_activation_height() {
        let nu7 = Network::TestNetwork
            .activation_height(NetworkUpgrade::Nu7)
            .expect("testnet has an NU7 activation height");

        assert!(!limits_apply(&Network::TestNetwork, nu7 - 1));
        assert!(limits_apply(&Network::TestNetwork, nu7));
    }
}
