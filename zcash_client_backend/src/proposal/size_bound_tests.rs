//! Unit tests of [`TransactionSizeBound`] and of the limits it checks against a step's shape.

use assert_matches::assert_matches;
use proptest::prelude::*;
use zcash_protocol::{ShieldedPool, constants::MAX_BLOCK_BYTES};

use super::{SizeBoundViolation, StepShape, TransactionSizeBound};

/// The shielded pools, in the order in which a bound checks their action limits.
const POOLS: [ShieldedPool; 3] = [
    ShieldedPool::Sapling,
    ShieldedPool::Orchard,
    ShieldedPool::Ironwood,
];

/// The number of spends, payment outputs, and change outputs of the test shape in each pool.
const SPENDS: usize = 3;
const PAYMENTS: usize = 1;
const CHANGE: usize = 1;

/// The number of transparent inputs and outputs of the test shape.
const TRANSPARENT_INPUTS: usize = 2;
const TRANSPARENT_OUTPUTS: usize = 2;

/// A number of dummy outputs larger than any padding allowance.
const DUMMY_OUTPUTS: usize = 16;

/// Returns a shape with [`SPENDS`] spends, [`PAYMENTS`] payment outputs and [`CHANGE`] change
/// outputs in each pool in `pools`, and the test numbers of transparent inputs and outputs.
fn shape_in(pools: &[ShieldedPool]) -> StepShape {
    let mut shape = StepShape {
        transparent_input_count: TRANSPARENT_INPUTS,
        transparent_payment_outputs: TRANSPARENT_OUTPUTS - 1,
        transparent_change_outputs: 1,
        ..StepShape::default()
    };
    for pool in pools {
        let (spends, outputs) = match pool {
            ShieldedPool::Sapling => (&mut shape.sapling_spends, &mut shape.sapling_outputs),
            ShieldedPool::Orchard => (&mut shape.orchard_spends, &mut shape.orchard_outputs),
            ShieldedPool::Ironwood => (&mut shape.ironwood_spends, &mut shape.ironwood_outputs),
        };
        *spends = SPENDS;
        *outputs = PAYMENTS + CHANGE;
        shape.shielded_payment_outputs += PAYMENTS;
    }
    shape
}

/// Returns the total number of shielded actions in `shape`.
fn total_actions(shape: &StepShape) -> usize {
    POOLS.iter().map(|pool| shape.pool_actions(*pool)).sum()
}

fn arb_limit() -> impl Strategy<Value = Option<usize>> {
    proptest::option::of(0usize..1000)
}

prop_compose! {
    fn arb_bound()(
        max_bytes in 0..=MAX_BLOCK_BYTES,
        max_shielded_actions in arb_limit(),
        max_sapling_actions in arb_limit(),
        max_orchard_actions in arb_limit(),
        max_ironwood_actions in arb_limit(),
        max_transparent_inputs in arb_limit(),
        max_transparent_outputs in arb_limit(),
        max_shielded_payment_outputs in arb_limit(),
    ) -> TransactionSizeBound {
        /// Applies `with` to `bound` when `limit` is set.
        fn set(
            bound: TransactionSizeBound,
            limit: Option<usize>,
            with: impl Fn(TransactionSizeBound, usize) -> TransactionSizeBound,
        ) -> TransactionSizeBound {
            limit.map_or(bound, |n| with(bound, n))
        }

        let bound = TransactionSizeBound::CONSENSUS.with_max_bytes(max_bytes);
        let bound = set(bound, max_shielded_actions, TransactionSizeBound::with_max_shielded_actions);
        let bound = set(bound, max_sapling_actions, |b, n| {
            b.with_max_pool_actions(ShieldedPool::Sapling, n)
        });
        let bound = set(bound, max_orchard_actions, |b, n| {
            b.with_max_pool_actions(ShieldedPool::Orchard, n)
        });
        let bound = set(bound, max_ironwood_actions, |b, n| {
            b.with_max_pool_actions(ShieldedPool::Ironwood, n)
        });
        let bound = set(bound, max_transparent_inputs, TransactionSizeBound::with_max_transparent_inputs);
        let bound = set(bound, max_transparent_outputs, TransactionSizeBound::with_max_transparent_outputs);
        set(
            bound,
            max_shielded_payment_outputs,
            TransactionSizeBound::with_max_shielded_payment_outputs,
        )
    }
}

/// Returns the smaller of two optional limits, where `None` is no limit.
fn expected_min(a: Option<usize>, b: Option<usize>) -> Option<usize> {
    match (a, b) {
        (Some(a), Some(b)) => Some(a.min(b)),
        _ => a.or(b),
    }
}

#[test]
fn consensus_is_the_block_size_limit_without_count_limits() {
    let bound = TransactionSizeBound::CONSENSUS;
    assert_eq!(bound, TransactionSizeBound::default());
    assert_eq!(bound.max_bytes(), MAX_BLOCK_BYTES);
    assert_eq!(bound.max_shielded_actions(), None);
    for pool in POOLS {
        assert_eq!(bound.max_pool_actions(pool), None);
    }
    assert_eq!(bound.max_transparent_inputs(), None);
    assert_eq!(bound.max_transparent_outputs(), None);
    assert_eq!(bound.max_shielded_payment_outputs(), None);
}

#[test]
fn consensus_admits_any_shape() {
    assert_eq!(
        TransactionSizeBound::CONSENSUS.count_violation(&shape_in(&POOLS)),
        None
    );
}

#[test]
fn max_bytes_is_at_most_the_block_size_limit() {
    let bytes = MAX_BLOCK_BYTES / 2;
    assert_eq!(
        TransactionSizeBound::CONSENSUS
            .with_max_bytes(bytes)
            .max_bytes(),
        bytes
    );
    assert_eq!(
        TransactionSizeBound::CONSENSUS
            .with_max_bytes(MAX_BLOCK_BYTES + 1)
            .max_bytes(),
        MAX_BLOCK_BYTES
    );
}

#[test]
fn each_builder_sets_only_its_own_limit() {
    let limit = 7;
    let consensus = TransactionSizeBound::CONSENSUS;

    let bound = consensus.with_max_shielded_actions(limit);
    assert_eq!(bound.max_shielded_actions(), Some(limit));
    assert_eq!(
        bound
            .with_max_shielded_actions(limit - 1)
            .max_shielded_actions(),
        Some(limit - 1)
    );

    for pool in POOLS {
        let bound = consensus.with_max_pool_actions(pool, limit);
        for other in POOLS {
            let expected = (other == pool).then_some(limit);
            assert_eq!(bound.max_pool_actions(other), expected);
        }
        assert_eq!(bound.max_shielded_actions(), None);
    }

    let bound = consensus.with_max_transparent_inputs(limit);
    assert_eq!(bound.max_transparent_inputs(), Some(limit));
    assert_eq!(bound.max_transparent_outputs(), None);

    let bound = consensus.with_max_transparent_outputs(limit);
    assert_eq!(bound.max_transparent_outputs(), Some(limit));
    assert_eq!(bound.max_transparent_inputs(), None);

    let bound = consensus.with_max_shielded_payment_outputs(limit);
    assert_eq!(bound.max_shielded_payment_outputs(), Some(limit));
    assert_eq!(bound.max_bytes(), MAX_BLOCK_BYTES);
}

#[test]
fn max_shielded_actions_bounds_the_total_over_pools() {
    let shape = shape_in(&POOLS);
    let total = total_actions(&shape);
    let at_limit = TransactionSizeBound::CONSENSUS.with_max_shielded_actions(total);
    assert_eq!(at_limit.count_violation(&shape), None);
    assert_eq!(
        TransactionSizeBound::CONSENSUS
            .with_max_shielded_actions(total - 1)
            .count_violation(&shape),
        Some(SizeBoundViolation::ShieldedActions {
            count: total,
            limit: total - 1
        })
    );
}

#[test]
fn max_pool_actions_bounds_only_its_pool() {
    let shape = shape_in(&POOLS);
    for pool in POOLS {
        let count = shape.pool_actions(pool);
        assert!(count > 0);
        assert_eq!(
            TransactionSizeBound::CONSENSUS
                .with_max_pool_actions(pool, count)
                .count_violation(&shape),
            None
        );
        assert_eq!(
            TransactionSizeBound::CONSENSUS
                .with_max_pool_actions(pool, count - 1)
                .count_violation(&shape),
            Some(SizeBoundViolation::PoolActions {
                pool,
                count,
                limit: count - 1
            })
        );
    }
}

#[test]
fn zero_pool_actions_forbids_only_a_present_bundle() {
    for pool in POOLS {
        let forbidden = TransactionSizeBound::CONSENSUS.with_max_pool_actions(pool, 0);
        let others = POOLS
            .iter()
            .copied()
            .filter(|p| *p != pool)
            .collect::<Vec<_>>();
        let without = shape_in(&others);
        assert_eq!(without.pool_actions(pool), 0);
        assert_eq!(forbidden.count_violation(&without), None);

        let with = shape_in(&POOLS);
        assert_matches!(
            forbidden.count_violation(&with),
            Some(SizeBoundViolation::PoolActions { pool: p, limit: 0, .. }) if p == pool
        );
    }
}

#[test]
fn transparent_limits_bound_transparent_inputs_and_outputs() {
    let shape = shape_in(&POOLS);
    let bound = TransactionSizeBound::CONSENSUS
        .with_max_transparent_inputs(TRANSPARENT_INPUTS)
        .with_max_transparent_outputs(TRANSPARENT_OUTPUTS);
    assert_eq!(bound.count_violation(&shape), None);
    assert_eq!(
        bound
            .with_max_transparent_inputs(TRANSPARENT_INPUTS - 1)
            .count_violation(&shape),
        Some(SizeBoundViolation::TransparentInputs {
            count: TRANSPARENT_INPUTS,
            limit: TRANSPARENT_INPUTS - 1
        })
    );
    assert_eq!(
        bound
            .with_max_transparent_outputs(TRANSPARENT_OUTPUTS - 1)
            .count_violation(&shape),
        Some(SizeBoundViolation::TransparentOutputs {
            count: TRANSPARENT_OUTPUTS,
            limit: TRANSPARENT_OUTPUTS - 1
        })
    );
}

#[test]
fn shielded_payment_outputs_exclude_change() {
    let shape = shape_in(&POOLS);
    let payments = PAYMENTS * POOLS.len();
    assert_eq!(
        TransactionSizeBound::CONSENSUS
            .with_max_shielded_payment_outputs(payments)
            .count_violation(&shape),
        None
    );
    assert_eq!(
        TransactionSizeBound::CONSENSUS
            .with_max_shielded_payment_outputs(payments - 1)
            .count_violation(&shape),
        Some(SizeBoundViolation::ShieldedPaymentOutputs {
            count: payments,
            limit: payments - 1
        })
    );
}

#[test]
fn absent_bundles_have_no_actions() {
    let shape = StepShape::default();
    for pool in POOLS {
        assert_eq!(shape.pool_actions(pool), 0);
    }
}

#[test]
fn dummy_outputs_are_counted_as_actions() {
    let base = StepShape {
        sapling_outputs: PAYMENTS,
        orchard_outputs: PAYMENTS,
        ..StepShape::default()
    };
    let padded = StepShape {
        sapling_dummy: DUMMY_OUTPUTS,
        orchard_dummy: DUMMY_OUTPUTS,
        ..base
    };
    assert_eq!(
        padded.pool_actions(ShieldedPool::Sapling),
        base.pool_actions(ShieldedPool::Sapling) + DUMMY_OUTPUTS
    );
    assert!(padded.pool_actions(ShieldedPool::Orchard) >= PAYMENTS + DUMMY_OUTPUTS);
}

proptest! {
    #[test]
    fn intersect_is_the_component_wise_minimum(a in arb_bound(), b in arb_bound()) {
        let i = a.intersect(&b);
        prop_assert_eq!(i, b.intersect(&a));
        prop_assert_eq!(a.intersect(&a), a);
        prop_assert_eq!(a.intersect(&TransactionSizeBound::CONSENSUS), a);
        prop_assert_eq!(i.max_bytes(), a.max_bytes().min(b.max_bytes()));
        prop_assert_eq!(
            i.max_shielded_actions(),
            expected_min(a.max_shielded_actions(), b.max_shielded_actions())
        );
        for pool in POOLS {
            prop_assert_eq!(
                i.max_pool_actions(pool),
                expected_min(a.max_pool_actions(pool), b.max_pool_actions(pool))
            );
        }
        prop_assert_eq!(
            i.max_transparent_inputs(),
            expected_min(a.max_transparent_inputs(), b.max_transparent_inputs())
        );
        prop_assert_eq!(
            i.max_transparent_outputs(),
            expected_min(a.max_transparent_outputs(), b.max_transparent_outputs())
        );
        prop_assert_eq!(
            i.max_shielded_payment_outputs(),
            expected_min(a.max_shielded_payment_outputs(), b.max_shielded_payment_outputs())
        );
    }

    #[test]
    fn intersect_admits_exactly_what_both_admit(a in arb_bound(), b in arb_bound()) {
        let shape = shape_in(&POOLS);
        let both = a.count_violation(&shape).is_none() && b.count_violation(&shape).is_none();
        prop_assert_eq!(a.intersect(&b).count_violation(&shape).is_none(), both);
    }
}
