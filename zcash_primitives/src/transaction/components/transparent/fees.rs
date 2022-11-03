//! Types related to computation of fees and change related to the transparent components
//! of a transaction.

use super::TxOut;
use crate::{
    legacy::Script,
    transaction::{components::amount::Amount, OutPoint},
};

/// This trait provides a minimized view of a transparent input suitable for use in
/// fee and change computation.
pub trait InputView {
    /// The outpoint to which the input refers.
    fn outpoint(&self) -> &OutPoint;
    /// The previous output being spent.
    fn coin(&self) -> &TxOut;
}

/// This trait provides a minimized view of a transparent output suitable for use in
/// fee and change computation.
pub trait OutputView {
    /// Returns the value of the output being created.
    fn value(&self) -> Amount;
    /// Returns the script corresponding to the newly created output.
    fn script_pubkey(&self) -> &Script;
}

impl OutputView for TxOut {
    fn value(&self) -> Amount {
        self.value
    }

    fn script_pubkey(&self) -> &Script {
        &self.script_pubkey
    }
}
