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

    /// Sets spend witnesses for Sapling spends by spend index.
    ///
    /// This may be called after shielded signatures have been added. Sapling
    /// spend proofs depend on the witnesses, so this must be called before proof
    /// creation for the updated spends.
    ///
    /// Returns an error if any witness references a spend index that does not
    /// exist, or if a target spend proof is already present.
    #[cfg(feature = "sapling")]
    pub fn set_sapling_spend_witnesses(
        mut self,
        witnesses: impl IntoIterator<Item = (usize, ::sapling::MerklePath)>,
    ) -> Result<Self, SpendWitnessUpdateError> {
        set_sapling_spend_witnesses(&mut self.pczt.sapling.spends, witnesses)?;

        Ok(self)
    }

    /// Sets spend witnesses for Orchard actions by action index.
    ///
    /// This may be called after shielded signatures have been added. Orchard
    /// proofs depend on the witnesses, so this must be called before proof
    /// creation.
    ///
    /// Returns an error if any witness references an action index that does not
    /// exist, if the Orchard bundle is not using Orchard note plaintexts, or if
    /// an Orchard proof is already present.
    #[cfg(feature = "orchard")]
    pub fn set_orchard_spend_witnesses(
        mut self,
        witnesses: impl IntoIterator<Item = (usize, ::orchard::tree::MerklePath)>,
    ) -> Result<Self, SpendWitnessUpdateError> {
        if self.pczt.orchard.note_version != crate::orchard::NoteVersion::V2 {
            return Err(SpendWitnessUpdateError::UnexpectedNoteVersion);
        }
        ensure_no_orchard_proof(&self.pczt.orchard)?;
        set_orchard_spend_witnesses(&mut self.pczt.orchard.actions, witnesses)?;

        Ok(self)
    }

    /// Sets spend witnesses for Ironwood actions by action index.
    ///
    /// This may be called after shielded signatures have been added. Ironwood
    /// proofs depend on the witnesses, so this must be called before proof
    /// creation.
    ///
    /// Returns an error if any witness references an action index that does not
    /// exist, if the Ironwood bundle is not using Ironwood note plaintexts, or if
    /// an Ironwood proof is already present.
    #[cfg(feature = "orchard")]
    pub fn set_ironwood_spend_witnesses(
        mut self,
        witnesses: impl IntoIterator<Item = (usize, ::orchard::tree::MerklePath)>,
    ) -> Result<Self, SpendWitnessUpdateError> {
        if self.pczt.ironwood.note_version != crate::orchard::NoteVersion::V3 {
            return Err(SpendWitnessUpdateError::UnexpectedNoteVersion);
        }
        ensure_no_orchard_proof(&self.pczt.ironwood)?;
        set_orchard_spend_witnesses(&mut self.pczt.ironwood.actions, witnesses)?;

        Ok(self)
    }

    /// Finishes the Updater role, returning the updated PCZT.
    pub fn finish(self) -> Pczt {
        self.pczt
    }
}

#[cfg(feature = "sapling")]
fn set_sapling_spend_witnesses(
    spends: &mut [crate::sapling::Spend],
    witnesses: impl IntoIterator<Item = (usize, ::sapling::MerklePath)>,
) -> Result<(), SpendWitnessUpdateError> {
    for (spend_index, merkle_path) in witnesses {
        let spend = spends
            .get_mut(spend_index)
            .ok_or(SpendWitnessUpdateError::InvalidSpendIndex(spend_index))?;
        if spend.zkproof.is_some() {
            return Err(SpendWitnessUpdateError::ProofAlreadyPresent);
        }
        let position = u32::try_from(u64::from(merkle_path.position()))
            .map_err(|_| SpendWitnessUpdateError::PositionOutOfRange)?;
        let mut auth_path = [[0; 32]; 32];
        for (target, node) in auth_path.iter_mut().zip(merkle_path.path_elems()) {
            *target = node.to_bytes();
        }
        spend.witness = Some((position, auth_path));
    }

    Ok(())
}

#[cfg(feature = "orchard")]
fn ensure_no_orchard_proof(bundle: &crate::orchard::Bundle) -> Result<(), SpendWitnessUpdateError> {
    if bundle.zkproof.is_some() {
        Err(SpendWitnessUpdateError::ProofAlreadyPresent)
    } else {
        Ok(())
    }
}

#[cfg(feature = "orchard")]
fn set_orchard_spend_witnesses(
    actions: &mut [crate::orchard::Action],
    witnesses: impl IntoIterator<Item = (usize, ::orchard::tree::MerklePath)>,
) -> Result<(), SpendWitnessUpdateError> {
    for (action_index, merkle_path) in witnesses {
        let action = actions
            .get_mut(action_index)
            .ok_or(SpendWitnessUpdateError::InvalidSpendIndex(action_index))?;
        action.spend.witness = Some((
            merkle_path.position(),
            merkle_path.auth_path().map(|node| node.to_bytes()),
        ));
    }

    Ok(())
}

/// An updater for a transparent PCZT output.
pub struct GlobalUpdater<'a>(&'a mut Global);

impl GlobalUpdater<'_> {
    /// Stores the given proprietary value at the given key.
    pub fn set_proprietary(&mut self, key: String, value: Vec<u8>) {
        self.0.proprietary.insert(key, value);
    }
}

/// Errors that can occur while setting Sapling, Orchard, or Ironwood spend witnesses.
#[cfg(any(feature = "sapling", feature = "orchard"))]
#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SpendWitnessUpdateError {
    /// The requested Sapling spend index or Orchard/Ironwood action index does not exist.
    InvalidSpendIndex(usize),
    /// The bundle already contains a proof that depends on the current witness.
    ProofAlreadyPresent,
    /// The witness position cannot be represented in the PCZT wire format.
    PositionOutOfRange,
    /// The bundle's note-plaintext version does not match the pool being updated.
    UnexpectedNoteVersion,
}

#[cfg(any(feature = "sapling", feature = "orchard"))]
impl core::fmt::Display for SpendWitnessUpdateError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SpendWitnessUpdateError::InvalidSpendIndex(index) => {
                write!(f, "spend index {index} does not exist")
            }
            SpendWitnessUpdateError::ProofAlreadyPresent => {
                write!(f, "proof for target spend or bundle is already present")
            }
            SpendWitnessUpdateError::PositionOutOfRange => {
                write!(
                    f,
                    "witness position cannot be represented in the PCZT wire format"
                )
            }
            SpendWitnessUpdateError::UnexpectedNoteVersion => {
                write!(
                    f,
                    "bundle note-plaintext version does not match the pool being updated"
                )
            }
        }
    }
}
