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

        let has_orchard_actions = !pczt.orchard.actions.is_empty();
        let has_ironwood_actions = !pczt.ironwood.actions.is_empty();
        let has_shielded_spends =
            !(pczt.sapling.spends.is_empty() && !has_orchard_actions && !has_ironwood_actions);
        let has_shielded_outputs =
            !(pczt.sapling.outputs.is_empty() && !has_orchard_actions && !has_ironwood_actions);

        // We can't build a transaction that has no spends or outputs.
        // However, we don't attempt to reject an entirely dummy transaction.
        if pczt.transparent.inputs.is_empty() && !has_shielded_spends {
            return Err(Error::NoSpends);
        }
        if pczt.transparent.outputs.is_empty() && !has_shielded_outputs {
            return Err(Error::NoOutputs);
        }
        if has_orchard_actions && pczt.orchard.anchor.is_none() {
            return Err(Error::Extract(ExtractError::OrchardParse(
                ::orchard::pczt::ParseError::InvalidAnchor,
            )));
        }
        if has_ironwood_actions && pczt.ironwood.anchor.is_none() {
            return Err(Error::Extract(ExtractError::IronwoodParse(
                ::orchard::pczt::ParseError::InvalidAnchor,
            )));
        }

        let ParsedPczt {
            mut global,
            transparent,
            mut sapling,
            mut orchard,
            mut ironwood,
            tx_data,
        } = pczt.extract_tx_data(
            |t| {
                t.extract_effects()
                    .map_err(ExtractError::TransparentExtract)
            },
            |s| s.extract_effects().map_err(ExtractError::SaplingExtract),
            |o| o.extract_effects().map_err(ExtractError::OrchardExtract),
            |i| i.extract_effects().map_err(ExtractError::IronwoodExtract),
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

        // The Sapling bundle is always finalized: unlike the Orchard-protocol
        // Transaction Extractor, the Sapling one requires `bsk` to be set even when
        // the bundle is empty.
        sapling
            .finalize_io(shielded_sighash, OsRng)
            .map_err(Error::SaplingFinalize)?;
        // An empty Orchard-protocol bundle carries no value commitment information
        // and contributes nothing to the transaction; leave its `bsk` unset so that
        // it stays in its canonical empty form (and so remains omissible by, or
        // representable in, the serialization formats).
        if has_orchard_actions {
            orchard
                .finalize_io(shielded_sighash, OsRng)
                .map_err(Error::OrchardFinalize)?;
        }
        if has_ironwood_actions {
            ironwood
                .finalize_io(shielded_sighash, OsRng)
                .map_err(Error::IronwoodFinalize)?;
        }

        Ok(Pczt {
            global,
            transparent: crate::transparent::Bundle::serialize_from(transparent),
            sapling: crate::sapling::Bundle::serialize_from(sapling),
            orchard: crate::orchard::Bundle::serialize_from(orchard),
            ironwood: crate::orchard::Bundle::serialize_from(ironwood),
        })
    }
}

/// Errors that can occur while finalizing the IO of a PCZT.
#[derive(Debug)]
pub enum Error {
    Extract(crate::ExtractError),
    NoOutputs,
    NoSpends,
    IronwoodFinalize(orchard::pczt::IoFinalizerError),
    OrchardFinalize(orchard::pczt::IoFinalizerError),
    SaplingFinalize(sapling::pczt::IoFinalizerError),
}

impl From<crate::ExtractError> for Error {
    fn from(e: crate::ExtractError) -> Self {
        Error::Extract(e)
    }
}
