use orchard::pczt::{Updater, UpdaterError};

use crate::{Pczt, common::AnchorRequirement, orchard::ParseError};

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
        let anchor_requirement = AnchorRequirement::for_pre_authorization(global.tx_version);

        let mut parsed = orchard
            .into_parsed_with_version(
                crate::orchard::orchard_bundle_version(&global)
                    .ok_or(OrchardError::UnsupportedConsensusBranchId)?,
                anchor_requirement,
            )
            .map_err(OrchardError::Parser)?;

        parsed
            .bundle
            .update_with(f)
            .map_err(OrchardError::Updater)?;

        Ok(Self {
            pczt: Pczt {
                global,
                transparent,
                sapling,
                orchard: parsed.reserialize(),
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
        let anchor_requirement = AnchorRequirement::for_pre_authorization(global.tx_version);

        let mut parsed = ironwood
            .into_ironwood_parsed(anchor_requirement)
            .map_err(OrchardError::Parser)?;

        parsed
            .bundle
            .update_with(f)
            .map_err(OrchardError::Updater)?;

        Ok(Self {
            pczt: Pczt {
                global,
                transparent,
                sapling,
                orchard,
                ironwood: parsed.reserialize(),
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
