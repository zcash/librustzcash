use crate::Pczt;

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
        let anchor = orchard.anchor;

        let bundle = orchard
            .into_parsed_with_version_allowing_missing_anchor(
                crate::orchard::orchard_bundle_version(&global)
                    .ok_or(OrchardError::UnsupportedConsensusBranchId)?,
            )
            .map_err(OrchardError::Parse)?;

        f(&bundle)?;

        Ok(Self {
            pczt: Pczt {
                global,
                transparent,
                sapling,
                orchard: crate::orchard::Bundle::serialize_from_preserving_anchor(bundle, anchor),
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
        let anchor = ironwood.anchor;

        let bundle = ironwood
            .into_ironwood_parsed_allowing_missing_anchor()
            .map_err(OrchardError::Parse)?;

        f(&bundle)?;

        Ok(Self {
            pczt: Pczt {
                global,
                transparent,
                sapling,
                orchard,
                ironwood: crate::orchard::Bundle::serialize_from_preserving_anchor(bundle, anchor),
            },
        })
    }
}

/// Errors that can occur while verifying the Orchard bundle of a PCZT.
#[derive(Debug)]
pub enum OrchardError<E> {
    Parse(orchard::pczt::ParseError),
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
