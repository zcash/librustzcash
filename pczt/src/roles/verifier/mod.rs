//! The Verifier role (anyone can inspect).
//!
//! This isn't a real role per se; it's instead a way for accessing the parsed
//! protocol-specific bundles for individual access and verification.

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
