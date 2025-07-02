//! The Spend Finalizer role (anyone can execute).
//!
//! - Combines partial transparent signatures into `script_sig`s.

use crate::Pczt;

pub struct SpendFinalizer {
    pczt: Pczt,
}

impl SpendFinalizer {
    /// Instantiates the Spend Finalizer role with the given PCZT.
    pub fn new(pczt: Pczt) -> Self {
        Self { pczt }
    }

    /// Finalizes the spends of the PCZT.
    pub fn finalize_spends(self) -> Result<Pczt, Error> {
        let Pczt {
            global,
            transparent,
            sapling,
            orchard,
        } = self.pczt;

        let mut transparent = transparent.into_parsed().map_err(Error::TransparentParse)?;

        transparent
            .finalize_spends()
            .map_err(Error::TransparentFinalize)?;

        Ok(Pczt {
            global,
            transparent: crate::transparent::Bundle::serialize_from(transparent),
            sapling,
            orchard,
        })
    }
}

/// Errors that can occur while finalizing the spends of a PCZT.
#[derive(Debug)]
pub enum Error {
    TransparentFinalize(transparent::pczt::SpendFinalizerError),
    TransparentParse(transparent::pczt::ParseError),
}
