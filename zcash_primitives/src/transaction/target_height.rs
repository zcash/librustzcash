//! The height at which a transaction being constructed can first be mined.

use core::ops::{Add, Sub};

use zcash_protocol::consensus::BlockHeight;

/// The height of the next block, one above the chain tip, at which a transaction being constructed
/// can first be mined.
///
/// Addition and subtraction are provided by proxying to [`BlockHeight`].
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct TargetHeight(BlockHeight);

impl TargetHeight {
    /// Subtracts the provided value from this height, returning [`zcash_protocol::consensus::H0`]
    /// if this would result in underflow of the wrapped `u32`.
    pub fn saturating_sub(self, value: u32) -> BlockHeight {
        self.0.saturating_sub(value)
    }
}

impl From<BlockHeight> for TargetHeight {
    fn from(value: BlockHeight) -> Self {
        TargetHeight(value)
    }
}

impl From<TargetHeight> for BlockHeight {
    fn from(value: TargetHeight) -> Self {
        value.0
    }
}

impl From<TargetHeight> for u32 {
    fn from(value: TargetHeight) -> Self {
        u32::from(value.0)
    }
}

impl From<u32> for TargetHeight {
    fn from(value: u32) -> Self {
        TargetHeight(BlockHeight::from_u32(value))
    }
}

impl<I> Add<I> for TargetHeight
where
    BlockHeight: Add<I>,
{
    type Output = <BlockHeight as Add<I>>::Output;

    fn add(self, rhs: I) -> Self::Output {
        self.0 + rhs
    }
}

impl<I> Sub<I> for TargetHeight
where
    BlockHeight: Sub<I>,
{
    type Output = <BlockHeight as Sub<I>>::Output;

    fn sub(self, rhs: I) -> Self::Output {
        self.0 - rhs
    }
}
