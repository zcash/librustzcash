//! The IO Finalizer role (anyone can execute).
//!
//! - Sets the appropriate bits in `Global.tx_modifiable` to 0.
//! - Updates the various bsk values using the rcv information from spends and outputs.

use rand_core::OsRng;
use zcash_primitives::transaction::{sighash::SignableInput, txid::TxIdDigester};

use super::tx_data::{pczt_to_tx_data, sighash};
use crate::{
    Pczt,
    common::{
        FLAG_SHIELDED_MODIFIABLE, FLAG_TRANSPARENT_INPUTS_MODIFIABLE,
        FLAG_TRANSPARENT_OUTPUTS_MODIFIABLE,
    },
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

        let Pczt {
            mut global,
            transparent,
            sapling,
            orchard,
        } = pczt;

        // After shielded IO finalization, the transaction effects cannot be modified
        // because dummy spends will have been signed.
        if has_shielded_spends || has_shielded_outputs {
            global.tx_modifiable &= !(FLAG_TRANSPARENT_INPUTS_MODIFIABLE
                | FLAG_TRANSPARENT_OUTPUTS_MODIFIABLE
                | FLAG_SHIELDED_MODIFIABLE);
        }

        let transparent = transparent.into_parsed().map_err(Error::TransparentParse)?;
        let mut sapling = sapling.into_parsed().map_err(Error::SaplingParse)?;
        let mut orchard = orchard.into_parsed().map_err(Error::OrchardParse)?;

        let tx_data = pczt_to_tx_data(&global, &transparent, &sapling, &orchard)?;
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
    NoOutputs,
    NoSpends,
    OrchardFinalize(orchard::pczt::IoFinalizerError),
    OrchardParse(orchard::pczt::ParseError),
    SaplingFinalize(sapling::pczt::IoFinalizerError),
    SaplingParse(sapling::pczt::ParseError),
    TransparentParse(transparent::pczt::ParseError),
    TxData(super::tx_data::Error),
}

impl From<super::tx_data::Error> for Error {
    fn from(e: super::tx_data::Error) -> Self {
        Error::TxData(e)
    }
}
