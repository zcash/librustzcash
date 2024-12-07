use rand_core::OsRng;
use sapling::prover::{OutputProver, SpendProver};

use crate::Pczt;

impl super::Prover {
    pub fn create_sapling_proofs<S, O>(
        self,
        spend_prover: &S,
        output_prover: &O,
    ) -> Result<Self, SaplingError>
    where
        S: SpendProver,
        O: OutputProver,
    {
        let Pczt {
            global,
            transparent,
            sapling,
            orchard,
        } = self.pczt;

        let mut bundle = sapling.into_parsed().map_err(SaplingError::Parser)?;

        bundle
            .create_proofs(spend_prover, output_prover, OsRng)
            .map_err(SaplingError::Prover)?;

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

/// Errors that can occur while creating Sapling proofs for a PCZT.
#[derive(Debug)]
pub enum SaplingError {
    Parser(sapling::pczt::ParseError),
    Prover(sapling::pczt::ProverError),
}
