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

        let mut bundle = orchard
            .into_orchard_parsed()
            .map_err(OrchardError::Parser)?;

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

    #[cfg(any(zcash_unstable = "nu6.3", zcash_unstable = "nu7"))]
    pub fn create_ironwood_proof(self, pk: &ProvingKey) -> Result<Self, IronwoodError> {
        let Pczt {
            global,
            transparent,
            sapling,
            orchard,
            ironwood,
        } = self.pczt;

        let mut bundle = ironwood
            .into_ironwood_parsed()
            .map_err(IronwoodError::Parser)?;

        bundle
            .create_proof(pk, OsRng)
            .map_err(IronwoodError::Prover)?;

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

/// Errors that can occur while creating Orchard proofs for a PCZT.
#[derive(Debug)]
pub enum OrchardError {
    Parser(orchard::pczt::ParseError),
    Prover(orchard::pczt::ProverError),
}

/// Errors that can occur while creating Ironwood proofs for a PCZT.
#[cfg(any(zcash_unstable = "nu6.3", zcash_unstable = "nu7"))]
#[derive(Debug)]
pub enum IronwoodError {
    Parser(orchard::pczt::ParseError),
    Prover(orchard::pczt::ProverError),
}
