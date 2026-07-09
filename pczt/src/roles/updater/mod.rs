//! The Updater role (anyone can contribute).
//!
//! - Adds information necessary for subsequent entities to proceed, such as key paths
//!   for signing spends.

use alloc::string::String;
use alloc::vec::Vec;

use crate::{Pczt, common::Global};

/// An Orchard-style spend witness to set on an Orchard or Ironwood PCZT action.
#[cfg(feature = "orchard")]
#[derive(Clone, Debug)]
pub struct OrchardSpendWitness {
    action_index: usize,
    merkle_path: ::orchard::tree::MerklePath,
}

#[cfg(feature = "orchard")]
impl OrchardSpendWitness {
    /// Constructs a witness update from a typed Orchard-style Merkle path.
    pub fn from_merkle_path(action_index: usize, merkle_path: ::orchard::tree::MerklePath) -> Self {
        Self {
            action_index,
            merkle_path,
        }
    }

    /// Parses and validates a witness update from serialized Orchard-style Merkle path data.
    pub fn parse(
        action_index: usize,
        position: u32,
        auth_path: [[u8; 32]; 32],
    ) -> Result<Self, OrchardSpendWitnessError> {
        let mut nodes = Vec::with_capacity(32);
        for from in auth_path {
            nodes.push(
                ::orchard::tree::MerkleHashOrchard::from_bytes(&from)
                    .into_option()
                    .ok_or(OrchardSpendWitnessError::InvalidWitness)?,
            );
        }
        let nodes = nodes
            .try_into()
            .map_err(|_| OrchardSpendWitnessError::InvalidWitness)?;

        Ok(Self::from_merkle_path(
            action_index,
            ::orchard::tree::MerklePath::from_parts(position, nodes),
        ))
    }

    fn action_index(&self) -> usize {
        self.action_index
    }

    fn serialized_witness(&self) -> (u32, [[u8; 32]; 32]) {
        (
            self.merkle_path.position(),
            self.merkle_path.auth_path().map(|node| node.to_bytes()),
        )
    }
}

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
    ) -> Result<Self, OrchardSpendWitnessError> {
        ensure_v6_consensus_branch(&self.pczt.global)?;
        ensure_no_orchard_proof(&self.pczt.orchard)?;
        self.pczt.orchard.anchor = Some(anchor.to_bytes());
        Ok(self)
    }

    /// Sets spend witnesses for Orchard actions by action index.
    ///
    /// Returns an error if any witness references an action index that does not exist,
    /// or if an Orchard proof is already present.
    #[cfg(feature = "orchard")]
    pub fn set_orchard_spend_witnesses(
        mut self,
        witnesses: impl IntoIterator<Item = OrchardSpendWitness>,
    ) -> Result<Self, OrchardSpendWitnessError> {
        if self.pczt.orchard.note_version != crate::orchard::NoteVersion::V2 {
            return Err(OrchardSpendWitnessError::UnexpectedNoteVersion);
        }
        ensure_no_orchard_proof(&self.pczt.orchard)?;
        for witness in witnesses {
            let action = self
                .pczt
                .orchard
                .actions
                .get_mut(witness.action_index())
                .ok_or(OrchardSpendWitnessError::InvalidActionIndex(
                    witness.action_index(),
                ))?;
            action.spend.witness = Some(witness.serialized_witness());
        }

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
    ) -> Result<Self, OrchardSpendWitnessError> {
        ensure_v6_consensus_branch(&self.pczt.global)?;
        ensure_no_orchard_proof(&self.pczt.ironwood)?;
        self.pczt.ironwood.anchor = Some(anchor.to_bytes());
        Ok(self)
    }

    /// Sets spend witnesses for Ironwood actions by action index.
    ///
    /// Returns an error if the PCZT is not version 6 on NU6.3 or later, if any
    /// witness references an action index that does not exist, or if an Ironwood
    /// proof is already present.
    #[cfg(feature = "orchard")]
    pub fn set_ironwood_spend_witnesses(
        mut self,
        witnesses: impl IntoIterator<Item = OrchardSpendWitness>,
    ) -> Result<Self, OrchardSpendWitnessError> {
        ensure_v6_consensus_branch(&self.pczt.global)?;
        if self.pczt.ironwood.note_version != crate::orchard::NoteVersion::V3 {
            return Err(OrchardSpendWitnessError::UnexpectedNoteVersion);
        }
        ensure_no_orchard_proof(&self.pczt.ironwood)?;
        for witness in witnesses {
            let action = self
                .pczt
                .ironwood
                .actions
                .get_mut(witness.action_index())
                .ok_or(OrchardSpendWitnessError::InvalidActionIndex(
                    witness.action_index(),
                ))?;
            action.spend.witness = Some(witness.serialized_witness());
        }

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
) -> Result<(), OrchardSpendWitnessError> {
    if bundle.zkproof.is_some() {
        Err(OrchardSpendWitnessError::ProofAlreadyPresent)
    } else {
        Ok(())
    }
}

#[cfg(feature = "orchard")]
fn ensure_v6_consensus_branch(global: &Global) -> Result<(), OrchardSpendWitnessError> {
    use zcash_protocol::{
        consensus::BranchId,
        constants::{V6_TX_VERSION, V6_VERSION_GROUP_ID},
    };

    if global.tx_version != V6_TX_VERSION || global.version_group_id != V6_VERSION_GROUP_ID {
        return Err(OrchardSpendWitnessError::RequiresV6);
    }

    match BranchId::try_from(global.consensus_branch_id) {
        Ok(BranchId::Nu6_3) => Ok(()),
        #[cfg(zcash_unstable = "nu7")]
        Ok(BranchId::Nu7) => Ok(()),
        Ok(_) => Err(OrchardSpendWitnessError::UnsupportedConsensusBranchId),
        Err(_) => Err(OrchardSpendWitnessError::UnknownConsensusBranchId),
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

/// Errors that can occur while setting Orchard or Ironwood anchor or spend witness data.
#[cfg(feature = "orchard")]
#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum OrchardSpendWitnessError {
    /// The requested action index does not exist in the bundle.
    InvalidActionIndex(usize),
    /// The provided serialized witness contains an invalid Orchard-style Merkle node.
    InvalidWitness,
    /// The PCZT must use the version 6 transaction format for this update.
    RequiresV6,
    /// The PCZT's consensus branch ID is unrecognized.
    UnknownConsensusBranchId,
    /// The PCZT's consensus branch ID does not support version 6 PCZTs.
    UnsupportedConsensusBranchId,
    /// The bundle already contains a proof that depends on the current witness data.
    ProofAlreadyPresent,
    /// The bundle's note-plaintext version does not match the pool being updated.
    UnexpectedNoteVersion,
}

#[cfg(feature = "orchard")]
impl core::fmt::Display for OrchardSpendWitnessError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            OrchardSpendWitnessError::InvalidActionIndex(index) => {
                write!(f, "Orchard or Ironwood action index {index} does not exist")
            }
            OrchardSpendWitnessError::InvalidWitness => write!(f, "invalid Orchard-style witness"),
            OrchardSpendWitnessError::RequiresV6 => {
                write!(
                    f,
                    "PCZT must be version 6 for this Orchard or Ironwood update"
                )
            }
            OrchardSpendWitnessError::UnknownConsensusBranchId => {
                write!(f, "unknown consensus branch ID")
            }
            OrchardSpendWitnessError::UnsupportedConsensusBranchId => {
                write!(
                    f,
                    "consensus branch ID does not support version 6 Orchard or Ironwood updates"
                )
            }
            OrchardSpendWitnessError::ProofAlreadyPresent => {
                write!(f, "Orchard or Ironwood proof is already present")
            }
            OrchardSpendWitnessError::UnexpectedNoteVersion => {
                write!(
                    f,
                    "bundle note-plaintext version does not match the pool being updated"
                )
            }
        }
    }
}
