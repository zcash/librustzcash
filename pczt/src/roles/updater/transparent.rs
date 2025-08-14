use transparent::pczt::{ParseError, Updater, UpdaterError};

use crate::Pczt;

impl super::Updater {
    /// Updates the transparent bundle with information in the given closure.
    pub fn update_transparent_with<F>(self, f: F) -> Result<Self, TransparentError>
    where
        F: FnOnce(Updater<'_>) -> Result<(), UpdaterError>,
    {
        let Pczt {
            global,
            transparent,
            sapling,
            orchard,
        } = self.pczt;

        let mut bundle = transparent
            .into_parsed()
            .map_err(TransparentError::Parser)?;

        bundle.update_with(f).map_err(TransparentError::Updater)?;

        Ok(Self {
            pczt: Pczt {
                global,
                transparent: crate::transparent::Bundle::serialize_from(bundle),
                sapling,
                orchard,
            },
        })
    }
}

/// Errors that can occur while updating the transparent bundle of a PCZT.
#[derive(Debug)]
pub enum TransparentError {
    Parser(ParseError),
    Updater(UpdaterError),
}
