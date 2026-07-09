//! The Updater role (anyone can contribute).
//!
//! - Adds information necessary for subsequent entities to proceed, such as key paths
//!   for signing spends.

use alloc::string::String;
use alloc::vec::Vec;

use crate::{Pczt, common::Global};

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

pub struct Updater {
    pczt: Pczt,
}

impl Updater {
    /// Instantiates the Updater role with the given PCZT.
    pub fn new(pczt: Pczt) -> Self {
        Self { pczt }
    }

    /// Updates the global transaction details with information in the given closure.
    pub fn update_global_with<F>(self, f: F) -> Self
    where
        F: FnOnce(GlobalUpdater<'_>),
    {
        let Pczt {
            mut global,
            transparent,
            sapling,
            orchard,
            ironwood,
        } = self.pczt;

        f(GlobalUpdater(&mut global));

        Self {
            pczt: Pczt {
                global,
                transparent,
                sapling,
                orchard,
                ironwood,
            },
        }
    }

    /// Sets the Orchard bundle anchor for a version 6 PCZT on NU6.3 or later.
    ///
    /// Orchard signatures in v6 do not commit to this anchor, so this may be
    /// called after shielded signatures have been added. Orchard proofs do
    /// depend on the anchor, so this must be called before proof creation.
    ///
    /// Returns an error if the PCZT is not version 6 on NU6.3 or later, or if an
    /// Orchard proof is already present.
    #[cfg(feature = "orchard")]
    pub fn set_v6_orchard_anchor(
        mut self,
        anchor: ::orchard::Anchor,
    ) -> Result<Self, OrchardAnchorUpdateError> {
        ensure_v6_consensus_branch(&self.pczt.global)?;
        ensure_no_orchard_proof(&self.pczt.orchard)?;
        self.pczt.orchard.anchor = Some(anchor.to_bytes());
        Ok(self)
    }

    /// Sets the Ironwood bundle anchor for a version 6 PCZT on NU6.3 or later.
    ///
    /// Ironwood signatures in v6 do not commit to this anchor, so this may be
    /// called after shielded signatures have been added. Ironwood proofs do
    /// depend on the anchor, so this must be called before proof creation.
    ///
    /// Returns an error if the PCZT is not version 6 on NU6.3 or later, or if an
    /// Ironwood proof is already present.
    #[cfg(feature = "orchard")]
    pub fn set_v6_ironwood_anchor(
        mut self,
        anchor: ::orchard::Anchor,
    ) -> Result<Self, OrchardAnchorUpdateError> {
        ensure_v6_consensus_branch(&self.pczt.global)?;
        ensure_no_orchard_proof(&self.pczt.ironwood)?;
        self.pczt.ironwood.anchor = Some(anchor.to_bytes());
        Ok(self)
    }

    /// Finishes the Updater role, returning the updated PCZT.
    pub fn finish(self) -> Pczt {
        self.pczt
    }
}

#[cfg(feature = "orchard")]
fn ensure_no_orchard_proof(
    bundle: &crate::orchard::Bundle,
) -> Result<(), OrchardAnchorUpdateError> {
    if bundle.zkproof.is_some() {
        Err(OrchardAnchorUpdateError::ProofAlreadyPresent)
    } else {
        Ok(())
    }
}

#[cfg(feature = "orchard")]
fn ensure_v6_consensus_branch(global: &Global) -> Result<(), OrchardAnchorUpdateError> {
    use zcash_protocol::{
        consensus::BranchId,
        constants::{V6_TX_VERSION, V6_VERSION_GROUP_ID},
    };

    if global.tx_version != V6_TX_VERSION || global.version_group_id != V6_VERSION_GROUP_ID {
        return Err(OrchardAnchorUpdateError::RequiresV6);
    }

    match BranchId::try_from(global.consensus_branch_id) {
        Ok(BranchId::Nu6_3) => Ok(()),
        #[cfg(zcash_unstable = "nu7")]
        Ok(BranchId::Nu7) => Ok(()),
        Ok(_) => Err(OrchardAnchorUpdateError::UnsupportedConsensusBranchId),
        Err(_) => Err(OrchardAnchorUpdateError::UnknownConsensusBranchId),
    }
}

/// An updater for a transparent PCZT output.
pub struct GlobalUpdater<'a>(&'a mut Global);

impl GlobalUpdater<'_> {
    /// Stores the given proprietary value at the given key.
    pub fn set_proprietary(&mut self, key: String, value: Vec<u8>) {
        self.0.proprietary.insert(key, value);
    }
}

/// Errors that can occur while setting Orchard or Ironwood anchors.
#[cfg(feature = "orchard")]
#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum OrchardAnchorUpdateError {
    /// The PCZT must use the version 6 transaction format for this update.
    RequiresV6,
    /// The PCZT's consensus branch ID is unrecognized.
    UnknownConsensusBranchId,
    /// The PCZT's consensus branch ID does not support version 6 PCZTs.
    UnsupportedConsensusBranchId,
    /// The bundle already contains a proof that depends on the current anchor.
    ProofAlreadyPresent,
}

#[cfg(feature = "orchard")]
impl core::fmt::Display for OrchardAnchorUpdateError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            OrchardAnchorUpdateError::RequiresV6 => {
                write!(
                    f,
                    "PCZT must be version 6 for this Orchard or Ironwood anchor update"
                )
            }
            OrchardAnchorUpdateError::UnknownConsensusBranchId => {
                write!(f, "unknown consensus branch ID")
            }
            OrchardAnchorUpdateError::UnsupportedConsensusBranchId => {
                write!(
                    f,
                    "consensus branch ID does not support version 6 Orchard or Ironwood anchor updates"
                )
            }
            OrchardAnchorUpdateError::ProofAlreadyPresent => {
                write!(f, "Orchard or Ironwood proof is already present")
            }
        }
    }
}
