use crate::Pczt;

impl super::Verifier {
    /// Parses the Sapling bundle and then verifies it in the given closure.
    pub fn with_sapling<E, F>(self, f: F) -> Result<Self, SaplingError<E>>
    where
        F: FnOnce(&sapling::pczt::Bundle) -> Result<(), SaplingError<E>>,
    {
        let Pczt {
            global,
            transparent,
            sapling,
            orchard,
        } = self.pczt;

        let bundle = sapling.into_parsed().map_err(SaplingError::Parser)?;

        f(&bundle)?;

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

/// Errors that can occur while verifying the Sapling bundle of a PCZT.
#[derive(Debug)]
pub enum SaplingError<E> {
    Parser(sapling::pczt::ParseError),
    Verifier(sapling::pczt::VerifyError),
    Custom(E),
}

impl<E> From<sapling::pczt::VerifyError> for SaplingError<E> {
    fn from(e: sapling::pczt::VerifyError) -> Self {
        SaplingError::Verifier(e)
    }
}
