//! Utilities for testing code that uses this crate.

use proptest::prelude::*;

use crate::U256;

/// Generates arbitrary [`U256`] values.
///
/// Besides values drawn from the full 256-bit range, the strategy produces `0`,
/// [`U256::MAX`], and values that fit in a `u64`, since a uniform draw almost
/// never yields these.
pub fn arb_u256() -> impl Strategy<Value = U256> {
    prop_oneof![
        Just(U256::zero()),
        Just(U256::MAX),
        any::<u64>().prop_map(U256::from),
        (any::<u128>(), any::<u128>())
            .prop_map(|(upper, lower)| (U256::from(upper) << 128) | U256::from(lower)),
    ]
}
