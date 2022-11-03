//! Abstractions and types related to fee calculations for TZE components of a transaction.

use crate::{
    extensions::transparent::{self as tze},
    transaction::components::{
        amount::Amount,
        tze::{OutPoint, TzeOut},
    },
};

/// This trait provides a minimized view of a TZE input suitable for use in
/// fee computation.
pub trait InputView {
    /// The outpoint to which the input refers.
    fn outpoint(&self) -> &OutPoint;
    /// The previous output being consumed.
    fn coin(&self) -> &TzeOut;
}

/// This trait provides a minimized view of a TZE output suitable for use in
/// fee computation.
pub trait OutputView {
    /// The value of the newly created output
    fn value(&self) -> Amount;
    /// The precondition that must be satisfied in order to spend this output.
    fn precondition(&self) -> &tze::Precondition;
}

impl OutputView for TzeOut {
    fn value(&self) -> Amount {
        self.value
    }

    fn precondition(&self) -> &tze::Precondition {
        &self.precondition
    }
}
