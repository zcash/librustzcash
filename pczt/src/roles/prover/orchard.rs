use orchard::circuit::ProvingKey;
use rand_core::OsRng;

use crate::Pczt;

impl super::Prover {
    pub fn create_orchard_proof(self, pk: &ProvingKey) -> Result<Self, OrchardError> {
        let Pczt {
            global,
            transparent,
            sapling,
            orchard,
            #[cfg(any(zcash_unstable = "nu6.3", zcash_unstable = "nu7"))]
            ironwood,
        } = self.pczt;

        let mut bundle = orchard.into_parsed().map_err(OrchardError::Parser)?;

        bundle
            .create_proof(pk, OsRng)
            .map_err(OrchardError::Prover)?;

        Ok(Self {
            pczt: Pczt {
                global,
                transparent,
                sapling,
                orchard: crate::orchard::Bundle::serialize_from(bundle),
                #[cfg(any(zcash_unstable = "nu6.3", zcash_unstable = "nu7"))]
                ironwood,
            },
        })
    }
}

/// Errors that can occur while creating Orchard proofs for a PCZT.
#[derive(Debug)]
pub enum OrchardError {
    Parser(orchard::pczt::ParseError),
    Prover(orchard::pczt::ProverError),
}
