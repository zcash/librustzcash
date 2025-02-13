use crate::Pczt;

#[cfg(feature = "orchard")]
mod orchard;
#[cfg(feature = "orchard")]
pub use orchard::OrchardError;

#[cfg(feature = "sapling")]
mod sapling;
#[cfg(feature = "sapling")]
pub use sapling::SaplingError;

#[cfg(feature = "transparent")]
mod transparent;
#[cfg(feature = "transparent")]
pub use transparent::TransparentError;

pub struct Verifier {
    pczt: Pczt,
}

impl Verifier {
    /// Instantiates the Verifier role with the given PCZT.
    pub fn new(pczt: Pczt) -> Self {
        Self { pczt }
    }

    /// Finishes the Verifier role, returning the updated PCZT.
    pub fn finish(self) -> Pczt {
        self.pczt
    }
}
