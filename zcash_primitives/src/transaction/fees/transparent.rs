//! Types related to computation of fees and change related to the transparent components
//! of a transaction.

use core::convert::Infallible;

use crate::transaction::fees::zip317::P2PKH_STANDARD_INPUT_SIZE;
use transparent::{
    address::Script,
    bundle::{OutPoint, TxOut},
};
use zcash_protocol::value::Zatoshis;
use zcash_script::{script, solver};

#[cfg(feature = "transparent-inputs")]
use transparent::builder::TransparentInputInfo;

/// The size of a transparent input, or the outpoint corresponding to the input
/// if the size of the script required to spend that input is unknown.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InputSize {
    /// The txin size is known.
    Known(usize),
    /// The size of the script required to spend this input (and therefore the txin size)
    /// is unknown.
    Unknown(OutPoint),
}

impl InputSize {
    /// An `InputSize` corresponding to the upper bound on the size of a P2PKH input used by ZIP 317.
    pub const STANDARD_P2PKH: InputSize = InputSize::Known(P2PKH_STANDARD_INPUT_SIZE);
}

/// This trait provides a minimized view of a transparent input suitable for use in
/// fee and change computation.
pub trait InputView: core::fmt::Debug {
    /// The outpoint to which the input refers.
    fn outpoint(&self) -> &OutPoint;

    /// The previous output being spent.
    fn coin(&self) -> &TxOut;

    /// The size of the transparent script required to spend this input.
    fn serialized_size(&self) -> InputSize {
        match script::PubKey::parse(&self.coin().script_pubkey().0)
            .ok()
            .as_ref()
            .and_then(solver::standard)
        {
            Some(solver::ScriptKind::PubKeyHash { .. }) => InputSize::STANDARD_P2PKH,
            _ => InputSize::Unknown(self.outpoint().clone()),
        }
    }
}

#[cfg(feature = "transparent-inputs")]
impl InputView for TransparentInputInfo {
    fn outpoint(&self) -> &OutPoint {
        self.outpoint()
    }

    fn coin(&self) -> &TxOut {
        self.coin()
    }
}

impl InputView for Infallible {
    fn outpoint(&self) -> &OutPoint {
        unreachable!()
    }
    fn coin(&self) -> &TxOut {
        unreachable!()
    }
}

/// This trait provides a minimized view of a transparent output suitable for use in
/// fee and change computation.
pub trait OutputView: core::fmt::Debug {
    /// Returns the value of the output being created.
    fn value(&self) -> Zatoshis;

    /// Returns the script corresponding to the newly created output.
    fn script_pubkey(&self) -> &Script;

    /// Returns the serialized size of the txout.
    fn serialized_size(&self) -> usize {
        // The serialized size of a transparent `TxOut` is the serialized size of an amount
        // plus the serialized size of the script pubkey.
        8 + self.script_pubkey().serialized_size()
    }
}

impl OutputView for TxOut {
    fn value(&self) -> Zatoshis {
        self.value()
    }

    fn script_pubkey(&self) -> &Script {
        self.script_pubkey()
    }
}
