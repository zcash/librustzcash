//! A low-level variant of the Signer role, for dependency-constrained environments.

use crate::Pczt;

pub struct Signer {
    pczt: Pczt,
}

impl Signer {
    /// Instantiates the low-level Signer role with the given PCZT.
    pub fn new(pczt: Pczt) -> Self {
        Self { pczt }
    }

    /// Exposes the capability to sign the Orchard spends.
    #[cfg(feature = "orchard")]
    pub fn sign_orchard_with<E, F>(self, f: F) -> Result<Self, E>
    where
        E: From<orchard::pczt::ParseError>,
        F: FnOnce(&Pczt, &mut orchard::pczt::Bundle, &mut u8) -> Result<(), E>,
    {
        let mut pczt = self.pczt;

        let mut tx_modifiable = pczt.global.tx_modifiable;

        let mut bundle = pczt.orchard.clone().into_parsed()?;

        f(&pczt, &mut bundle, &mut tx_modifiable)?;

        pczt.global.tx_modifiable = tx_modifiable;
        pczt.orchard = crate::orchard::Bundle::serialize_from(bundle);

        Ok(Self { pczt })
    }

    /// Exposes the capability to sign the Sapling spends.
    #[cfg(feature = "sapling")]
    pub fn sign_sapling_with<E, F>(self, f: F) -> Result<Self, E>
    where
        E: From<sapling::pczt::ParseError>,
        F: FnOnce(&Pczt, &mut sapling::pczt::Bundle, &mut u8) -> Result<(), E>,
    {
        let mut pczt = self.pczt;

        let mut tx_modifiable = pczt.global.tx_modifiable;

        let mut bundle = pczt.sapling.clone().into_parsed()?;

        f(&pczt, &mut bundle, &mut tx_modifiable)?;

        pczt.global.tx_modifiable = tx_modifiable;
        pczt.sapling = crate::sapling::Bundle::serialize_from(bundle);

        Ok(Self { pczt })
    }

    /// Exposes the capability to sign the transparent spends.
    #[cfg(feature = "transparent")]
    pub fn sign_transparent_with<E, F>(self, f: F) -> Result<Self, E>
    where
        E: From<transparent::pczt::ParseError>,
        F: FnOnce(&Pczt, &mut transparent::pczt::Bundle, &mut u8) -> Result<(), E>,
    {
        let mut pczt = self.pczt;

        let mut tx_modifiable = pczt.global.tx_modifiable;

        let mut bundle = pczt.transparent.clone().into_parsed()?;

        f(&pczt, &mut bundle, &mut tx_modifiable)?;

        pczt.global.tx_modifiable = tx_modifiable;
        pczt.transparent = crate::transparent::Bundle::serialize_from(bundle);

        Ok(Self { pczt })
    }

    /// Finishes the low-level Signer role, returning the updated PCZT.
    pub fn finish(self) -> Pczt {
        self.pczt
    }
}
