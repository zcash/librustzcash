use crate::Pczt;

impl super::Verifier {
    /// Parses the Transparent bundle and then verifies it in the given closure.
    pub fn with_transparent<E, F>(self, f: F) -> Result<Self, TransparentError<E>>
    where
        F: FnOnce(&transparent::pczt::Bundle) -> Result<(), TransparentError<E>>,
    {
        let Pczt {
            global,
            transparent,
            sapling,
            orchard,
        } = self.pczt;

        let bundle = transparent
            .into_parsed()
            .map_err(TransparentError::Parser)?;

        f(&bundle)?;

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

/// Errors that can occur while verifying the Transparent bundle of a PCZT.
#[derive(Debug)]
pub enum TransparentError<E> {
    Parser(transparent::pczt::ParseError),
    Verifier(transparent::pczt::VerifyError),
    Custom(E),
}

impl<E> From<transparent::pczt::VerifyError> for TransparentError<E> {
    fn from(e: transparent::pczt::VerifyError) -> Self {
        TransparentError::Verifier(e)
    }
}
