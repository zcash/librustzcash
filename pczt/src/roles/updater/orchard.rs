use orchard::pczt::{ParseError, Updater, UpdaterError};

use crate::Pczt;

impl super::Updater {
    /// Updates the Orchard bundle with information in the given closure.
    pub fn update_orchard_with<F>(self, f: F) -> Result<Self, OrchardError>
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

        let mut bundle = orchard
            .into_parsed_with_version(
                global.tx_version,
                crate::orchard::orchard_bundle_version(&global)
                    .ok_or(OrchardError::UnsupportedConsensusBranchId)?,
            )
            .map_err(OrchardError::Parser)?;

        bundle.update_with(f).map_err(OrchardError::Updater)?;

        Ok(Self {
            pczt: Pczt {
                global,
                transparent,
                sapling,
                orchard: crate::orchard::Bundle::serialize_from(bundle),
                ironwood,
            },
        })
    }

    /// Updates the Ironwood bundle with information in the given closure.
    pub fn update_ironwood_with<F>(self, f: F) -> Result<Self, OrchardError>
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

        let mut bundle = ironwood
            .into_ironwood_parsed(global.tx_version)
            .map_err(OrchardError::Parser)?;

        bundle.update_with(f).map_err(OrchardError::Updater)?;

        Ok(Self {
            pczt: Pczt {
                global,
                transparent,
                sapling,
                orchard,
                ironwood: crate::orchard::Bundle::serialize_from(bundle),
            },
        })
    }
}

/// Errors that can occur while updating the Orchard bundle of a PCZT.
#[derive(Debug)]
pub enum OrchardError {
    Parser(ParseError),
    /// The PCZT's consensus branch ID is unrecognized, or predates NU5 (under which
    /// the Orchard protocol is not supported).
    UnsupportedConsensusBranchId,
    Updater(UpdaterError),
}
