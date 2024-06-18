//! Types related to computation of fees and change related to the transparent components
//! of a transaction.

use std::convert::Infallible;

use crate::{
    legacy::{Script, TransparentAddress},
    transaction::{
        components::{amount::NonNegativeAmount, transparent::TxOut, OutPoint},
        fees::zip317::P2PKH_STANDARD_INPUT_SIZE,
    },
};

#[cfg(feature = "transparent-inputs")]
use crate::transaction::components::transparent::builder::TransparentInputInfo;

/// The size of a transparent input, or the outpoint corresponding to the input
/// if the size of the script required to spend that input is unknown.
pub enum InputSize {
    /// The txin size is known.
    Known(usize),
    /// The size of the script required to spend this input (and therefore the txin size)
    /// is unknown.
    Unknown(OutPoint),
}

impl InputSize {
    pub const STANDARD_P2PKH: InputSize = InputSize::Known(P2PKH_STANDARD_INPUT_SIZE);
}

/// This trait provides a minimized view of a transparent input suitable for use in
/// fee and change computation.
pub trait InputView: std::fmt::Debug {
    /// The outpoint to which the input refers.
    fn outpoint(&self) -> &OutPoint;

    /// The previous output being spent.
    fn coin(&self) -> &TxOut;

    /// The size of the transparent script required to spend this input.
    fn serialized_size(&self) -> InputSize {
        match self.coin().script_pubkey.address() {
            Some(TransparentAddress::PublicKeyHash(_)) => InputSize::STANDARD_P2PKH,
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
pub trait OutputView: std::fmt::Debug {
    /// Returns the value of the output being created.
    fn value(&self) -> NonNegativeAmount;

    /// Returns the script corresponding to the newly created output.
    fn script_pubkey(&self) -> &Script;

    /// Returns the serialized size of the txout.
    fn serialized_size(&self) -> usize {
        let mut buf: Vec<u8> = vec![];
        self.script_pubkey()
            .write(&mut buf)
            .expect("script does not exceed available memory");
        // The length of a transparent TxOut is the length of an amount plus the length of the serialized script pubkey.
        8 + buf.len()
    }
}

impl OutputView for TxOut {
    fn value(&self) -> NonNegativeAmount {
        self.value
    }

    fn script_pubkey(&self) -> &Script {
        &self.script_pubkey
    }
}
