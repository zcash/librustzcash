use crate::Pczt;
use orchard::circuit::ProvingKey;
use orchard::orchard_flavor::OrchardFlavor;
use rand_core::OsRng;

impl super::Prover {
    pub fn create_orchard_proof<D: OrchardFlavor>(
        self,
        pk: &ProvingKey,
    ) -> Result<Self, OrchardError> {
        let Pczt {
            global,
            transparent,
            sapling,
            orchard,
        } = self.pczt;

        let mut bundle = orchard.into_parsed().map_err(OrchardError::Parser)?;

        bundle
            .create_proof::<D, OsRng>(pk, OsRng)
            .map_err(OrchardError::Prover)?;

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

/// Errors that can occur while creating Orchard proofs for a PCZT.
#[derive(Debug)]
pub enum OrchardError {
    Parser(orchard::pczt::ParseError),
    Prover(orchard::pczt::ProverError),
}
