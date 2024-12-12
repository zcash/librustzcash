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
        } = self.pczt;

        let bundle = orchard.into_parsed().map_err(OrchardError::Parse)?;

        f(&bundle)?;

        Ok(Self {
            pczt: Pczt {
                global,
                transparent,
                sapling,
                orchard: crate::orchard::Bundle::serialize_from(bundle),
            },
        })
    }
}

/// Errors that can occur while verifying the Orchard bundle of a PCZT.
#[derive(Debug)]
pub enum OrchardError<E> {
    Parse(orchard::pczt::ParseError),
    Verify(orchard::pczt::VerifyError),
    Custom(E),
}

impl<E> From<orchard::pczt::VerifyError> for OrchardError<E> {
    fn from(e: orchard::pczt::VerifyError) -> Self {
        OrchardError::Verify(e)
    }
}
