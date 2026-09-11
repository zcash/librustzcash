//! Change strategies designed for use with a standard fee.

use super::StandardFeeRule;

/// A change strategy that proposes change as a single output. The output pool is chosen
/// as the most current pool that avoids unnecessary pool-crossing (with a specified
/// fallback when the transaction has no shielded inputs). Fee calculation is delegated
/// to the provided fee rule.
///
/// This strategy never splits change; a splitting note-management policy has no effect under it.
pub type SingleOutputChangeStrategy = super::zip317::SingleOutputChangeStrategy<StandardFeeRule>;

/// A change strategy that realizes the change pieces a note-management policy asks for. The output
/// pool is chosen as the most current pool that avoids unnecessary pool-crossing (with a specified
/// fallback when the transaction has no shielded inputs). Fee calculation is delegated to the
/// provided fee rule.
pub type MultiOutputChangeStrategy = super::zip317::MultiOutputChangeStrategy<StandardFeeRule>;
