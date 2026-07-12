use crate::{Pczt, common::AnchorRequirement};

impl super::Verifier {
    /// Parses the Orchard bundle and then verifies it in the given closure.
    pub fn with_orchard<E, F>(self, f: F) -> Result<Self, OrchardError<E>>
    where
        F: FnOnce(&orchard::pczt::Bundle) -> Result<(), OrchardError<E>>,
    {
        let Pczt {
            global,
            transparent,
            sapling,
            orchard,
            ironwood,
        } = self.pczt;
        let anchor_requirement = AnchorRequirement::for_pre_authorization(global.tx_version);

        let parsed = orchard
            .into_parsed_with_version(
                crate::orchard::orchard_bundle_version(&global)
                    .ok_or(OrchardError::UnsupportedConsensusBranchId)?,
                anchor_requirement,
            )
            .map_err(OrchardError::Parse)?;

        f(&parsed.bundle)?;

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

    /// Parses the Ironwood bundle and then verifies it in the given closure.
    pub fn with_ironwood<E, F>(self, f: F) -> Result<Self, OrchardError<E>>
    where
        F: FnOnce(&orchard::pczt::Bundle) -> Result<(), OrchardError<E>>,
    {
        let Pczt {
            global,
            transparent,
            sapling,
            orchard,
            ironwood,
        } = self.pczt;
        let anchor_requirement = AnchorRequirement::for_pre_authorization(global.tx_version);

        let parsed = ironwood
            .into_ironwood_parsed(anchor_requirement)
            .map_err(OrchardError::Parse)?;

        f(&parsed.bundle)?;

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

/// Errors that can occur while verifying the Orchard bundle of a PCZT.
#[derive(Debug)]
pub enum OrchardError<E> {
    Parse(crate::orchard::ParseError),
    /// The PCZT's consensus branch ID is unrecognized, or predates NU5 (under which
    /// the Orchard protocol is not supported).
    UnsupportedConsensusBranchId,
    Verify(orchard::pczt::VerifyError),
    Custom(E),
}

impl<E> From<orchard::pczt::VerifyError> for OrchardError<E> {
    fn from(e: orchard::pczt::VerifyError) -> Self {
        OrchardError::Verify(e)
    }
}
