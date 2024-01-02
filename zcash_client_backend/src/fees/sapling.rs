//! Types related to computation of fees and change related to the Sapling components
//! of a transaction.

use std::convert::Infallible;

use sapling::builder::{OutputInfo, SpendInfo};
use zcash_primitives::transaction::components::amount::NonNegativeAmount;

/// A trait that provides a minimized view of a Sapling input suitable for use in
/// fee and change calculation.
pub trait InputView<NoteRef> {
    /// An identifier for the input being spent.
    fn note_id(&self) -> &NoteRef;
    /// The value of the input being spent.
    fn value(&self) -> NonNegativeAmount;
}

impl<N> InputView<N> for Infallible {
    fn note_id(&self) -> &N {
        unreachable!()
    }
    fn value(&self) -> NonNegativeAmount {
        unreachable!()
    }
}

// `SpendDescriptionInfo` does not contain a note identifier, so we can only implement
// `InputView<()>`
impl InputView<()> for SpendInfo {
    fn note_id(&self) -> &() {
        &()
    }

    fn value(&self) -> NonNegativeAmount {
        NonNegativeAmount::try_from(self.value())
            .expect("An existing note to be spent must have a valid amount value.")
    }
}

/// A trait that provides a minimized view of a Sapling output suitable for use in
/// fee and change calculation.
pub trait OutputView {
    /// The value of the output being produced.
    fn value(&self) -> NonNegativeAmount;
}

impl OutputView for OutputInfo {
    fn value(&self) -> NonNegativeAmount {
        NonNegativeAmount::try_from(self.value())
            .expect("Output values should be checked at construction.")
    }
}

impl OutputView for Infallible {
    fn value(&self) -> NonNegativeAmount {
        unreachable!()
    }
}
