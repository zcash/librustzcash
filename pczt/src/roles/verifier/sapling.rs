use crate::{Pczt, common::AnchorRequirement};

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
            ironwood,
        } = self.pczt;
        let anchor_requirement = AnchorRequirement::for_pre_authorization(global.tx_version);

        let parsed = sapling
            .into_parsed(anchor_requirement)
            .map_err(SaplingError::Parser)?;

        f(&parsed.bundle)?;

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

/// Errors that can occur while verifying the Sapling bundle of a PCZT.
#[derive(Debug)]
pub enum SaplingError<E> {
    Parser(crate::sapling::ParseError),
    Verifier(sapling::pczt::VerifyError),
    Custom(E),
}

impl<E> From<sapling::pczt::VerifyError> for SaplingError<E> {
    fn from(e: sapling::pczt::VerifyError) -> Self {
        SaplingError::Verifier(e)
    }
}
