use sapling::pczt::{ParseError, Updater, UpdaterError};

use crate::Pczt;

impl super::Updater {
    /// Updates the Sapling bundle with information in the given closure.
    pub fn update_sapling_with<F>(self, f: F) -> Result<Self, SaplingError>
    where
        F: FnOnce(Updater<'_>) -> Result<(), UpdaterError>,
    {
        let Pczt {
            global,
            transparent,
            sapling,
            orchard,
        } = self.pczt;

        let mut bundle = sapling.into_parsed().map_err(SaplingError::Parser)?;

        bundle.update_with(f).map_err(SaplingError::Updater)?;

        Ok(Self {
            pczt: Pczt {
                global,
                transparent,
                sapling: crate::sapling::Bundle::serialize_from(bundle),
                orchard,
            },
        })
    }
}

/// Errors that can occur while updating the Sapling bundle of a PCZT.
#[derive(Debug)]
pub enum SaplingError {
    Parser(ParseError),
    Updater(UpdaterError),
}
