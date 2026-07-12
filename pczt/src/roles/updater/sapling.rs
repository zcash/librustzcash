use sapling::pczt::{Updater, UpdaterError};

use crate::{Pczt, common::AnchorRequirement, sapling::ParseError};

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
            ironwood,
        } = self.pczt;
        let anchor_requirement = AnchorRequirement::for_pre_authorization(global.tx_version);

        let mut parsed = sapling
            .into_parsed(anchor_requirement)
            .map_err(SaplingError::Parser)?;

        parsed
            .bundle
            .update_with(f)
            .map_err(SaplingError::Updater)?;

        Ok(Self {
            pczt: Pczt {
                global,
                transparent,
                sapling: parsed.reserialize(),
                orchard,
                ironwood,
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
