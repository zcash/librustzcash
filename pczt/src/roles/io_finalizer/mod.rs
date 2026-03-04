//! The IO Finalizer role (anyone can execute).
//!
//! - Sets the appropriate bits in `Global.tx_modifiable` to 0.
//! - Updates the various bsk values using the rcv information from spends and outputs.

use rand_core::OsRng;
use zcash_primitives::transaction::{sighash::SignableInput, txid::TxIdDigester};

use crate::{
    ExtractError, ParsedPczt, Pczt,
    common::{
        FLAG_SHIELDED_MODIFIABLE, FLAG_TRANSPARENT_INPUTS_MODIFIABLE,
        FLAG_TRANSPARENT_OUTPUTS_MODIFIABLE,
    },
    sighash,
};

pub struct IoFinalizer {
    pczt: Pczt,
}

impl IoFinalizer {
    /// Instantiates the IO Finalizer role with the given PCZT.
    pub fn new(pczt: Pczt) -> Self {
        Self { pczt }
    }

    /// Finalizes the IO of the PCZT.
    pub fn finalize_io(self) -> Result<Pczt, Error> {
        let Self { pczt } = self;

        let has_shielded_spends =
            !(pczt.sapling.spends.is_empty() && pczt.orchard.actions.is_empty());
        let has_shielded_outputs =
            !(pczt.sapling.outputs.is_empty() && pczt.orchard.actions.is_empty());

        // We can't build a transaction that has no spends or outputs.
        // However, we don't attempt to reject an entirely dummy transaction.
        if pczt.transparent.inputs.is_empty() && !has_shielded_spends {
            return Err(Error::NoSpends);
        }
        if pczt.transparent.outputs.is_empty() && !has_shielded_outputs {
            return Err(Error::NoOutputs);
        }

        let ParsedPczt {
            mut global,
            transparent,
            mut sapling,
            mut orchard,
            tx_data,
        } = pczt.extract_tx_data(
            |t| {
                t.extract_effects()
                    .map_err(ExtractError::TransparentExtract)
            },
            |s| s.extract_effects().map_err(ExtractError::SaplingExtract),
            |o| o.extract_effects().map_err(ExtractError::OrchardExtract),
        )?;

        // After shielded IO finalization, the transaction effects cannot be modified
        // because dummy spends will have been signed.
        if has_shielded_spends || has_shielded_outputs {
            global.tx_modifiable &= !(FLAG_TRANSPARENT_INPUTS_MODIFIABLE
                | FLAG_TRANSPARENT_OUTPUTS_MODIFIABLE
                | FLAG_SHIELDED_MODIFIABLE);
        }
        let txid_parts = tx_data.digest(TxIdDigester);
        let shielded_sighash = sighash(&tx_data, &SignableInput::Shielded, &txid_parts);

        sapling
            .finalize_io(shielded_sighash, OsRng)
            .map_err(Error::SaplingFinalize)?;
        orchard
            .finalize_io(shielded_sighash, OsRng)
            .map_err(Error::OrchardFinalize)?;

        Ok(Pczt {
            global,
            transparent: crate::transparent::Bundle::serialize_from(transparent),
            sapling: crate::sapling::Bundle::serialize_from(sapling),
            orchard: crate::orchard::Bundle::serialize_from(orchard),
        })
    }
}

/// Errors that can occur while finalizing the IO of a PCZT.
#[derive(Debug)]
pub enum Error {
    Extract(crate::ExtractError),
    NoOutputs,
    NoSpends,
    OrchardFinalize(orchard::pczt::IoFinalizerError),
    SaplingFinalize(sapling::pczt::IoFinalizerError),
}

impl From<crate::ExtractError> for Error {
    fn from(e: crate::ExtractError) -> Self {
        Error::Extract(e)
    }
}
