use crate::Pczt;

#[cfg(feature = "orchard")]
mod orchard;
#[cfg(feature = "orchard")]
pub use orchard::OrchardError;

#[cfg(feature = "sapling")]
mod sapling;
#[cfg(feature = "sapling")]
pub use sapling::SaplingError;

pub struct Prover {
    pczt: Pczt,
}

impl Prover {
    /// Instantiates the Prover role with the given PCZT.
    pub fn new(pczt: Pczt) -> Self {
        Self { pczt }
    }

    /// Returns `true` if this PCZT contains Sapling Spends or Outputs that are missing
    /// proofs.
    pub fn requires_sapling_proofs(&self) -> bool {
        let sapling_bundle = self.pczt.sapling();

        sapling_bundle.spends().iter().any(|s| s.zkproof.is_none())
            || sapling_bundle.outputs().iter().any(|o| o.zkproof.is_none())
    }

    /// Returns `true` if this PCZT contains Orchard Actions but no Orchard proof.
    pub fn requires_orchard_proof(&self) -> bool {
        !self.pczt.orchard().actions().is_empty() && self.pczt.orchard().zkproof.is_none()
    }

    /// Finishes the Prover role, returning the updated PCZT.
    pub fn finish(self) -> Pczt {
        self.pczt
    }
}
