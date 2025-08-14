//! Change strategies designed for use with a standard fee.

use super::StandardFeeRule;

/// A change strategy that proposes change as a single output. The output pool is chosen
/// as the most current pool that avoids unnecessary pool-crossing (with a specified
/// fallback when the transaction has no shielded inputs). Fee calculation is delegated
/// to the provided fee rule.
pub type SingleOutputChangeStrategy<I> =
    super::zip317::SingleOutputChangeStrategy<StandardFeeRule, I>;

/// A change strategy that proposes change as potentially multiple evenly-sized outputs having at
/// least a threshold value. The output pool is chosen as the most current pool that avoids
/// unnecessary pool-crossing (with a specified fallback when the transaction has no shielded
/// inputs). Fee calculation is delegated to the provided fee rule.
pub type MultiOutputChangeStrategy<I> =
    super::zip317::MultiOutputChangeStrategy<StandardFeeRule, I>;
