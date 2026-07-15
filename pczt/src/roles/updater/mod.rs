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

    /// Sets the Sapling bundle anchor.
    ///
    /// This may be called after shielded signatures have been added for
    /// transaction formats that do not commit shielded signatures to anchors.
    /// Sapling spend proofs depend on the anchor, so this must be called before
    /// proof creation for Sapling spends.
    ///
    /// Returns an error if the PCZT's transaction format does not support this
    /// update, if any Sapling spend proof is already present, or if the PCZT
    /// already contains a different Sapling anchor.
    #[cfg(feature = "sapling")]
    pub fn set_sapling_anchor(
        mut self,
        anchor: ::sapling::Anchor,
    ) -> Result<Self, AnchorUpdateError> {
        ensure_anchor_update_supported(&self.pczt.global)?;
        ensure_no_sapling_spend_proof(&self.pczt.sapling)?;
        set_anchor(&mut self.pczt.sapling.anchor, anchor.to_bytes())?;
        Ok(self)
    }

    /// Sets the Orchard bundle anchor.
    ///
    /// This may be called after shielded signatures have been added for
    /// transaction formats that do not commit shielded signatures to anchors.
    /// Orchard proofs depend on the anchor, so this must be called before proof
    /// creation.
    ///
    /// Returns an error if the PCZT's transaction format does not support this
    /// update, if an Orchard proof is already present, or if the PCZT already
    /// contains a different Orchard anchor.
    #[cfg(feature = "orchard")]
    pub fn set_orchard_anchor(
        mut self,
        anchor: ::orchard::Anchor,
    ) -> Result<Self, AnchorUpdateError> {
        ensure_anchor_update_supported(&self.pczt.global)?;
        ensure_no_orchard_proof_for_anchor(&self.pczt.orchard)?;
        set_anchor(&mut self.pczt.orchard.anchor, anchor.to_bytes())?;
        Ok(self)
    }

    /// Sets the Ironwood bundle anchor.
    ///
    /// This may be called after shielded signatures have been added for
    /// transaction formats that do not commit shielded signatures to anchors.
    /// Ironwood proofs depend on the anchor, so this must be called before proof
    /// creation.
    ///
    /// Returns an error if the PCZT's transaction format does not support this
    /// update, if an Ironwood proof is already present, or if the PCZT already
    /// contains a different Ironwood anchor.
    #[cfg(feature = "orchard")]
    pub fn set_ironwood_anchor(
        mut self,
        anchor: ::orchard::Anchor,
    ) -> Result<Self, AnchorUpdateError> {
        ensure_anchor_update_supported(&self.pczt.global)?;
        ensure_no_orchard_proof_for_anchor(&self.pczt.ironwood)?;
        set_anchor(&mut self.pczt.ironwood.anchor, anchor.to_bytes())?;
        Ok(self)
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
        ensure_no_orchard_proof_for_witness(&self.pczt.orchard)?;
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
        ensure_no_orchard_proof_for_witness(&self.pczt.ironwood)?;
        set_orchard_spend_witnesses(&mut self.pczt.ironwood.actions, witnesses)?;

        Ok(self)
    }

    /// Finishes the Updater role, returning the updated PCZT.
    pub fn finish(self) -> Pczt {
        self.pczt
    }
}

#[cfg(feature = "sapling")]
fn ensure_no_sapling_spend_proof(bundle: &crate::sapling::Bundle) -> Result<(), AnchorUpdateError> {
    if bundle.spends.iter().any(|spend| spend.zkproof.is_some()) {
        Err(AnchorUpdateError::ProofAlreadyPresent)
    } else {
        Ok(())
    }
}

#[cfg(feature = "orchard")]
fn ensure_no_orchard_proof_for_anchor(
    bundle: &crate::orchard::Bundle,
) -> Result<(), AnchorUpdateError> {
    if bundle.zkproof.is_some() {
        Err(AnchorUpdateError::ProofAlreadyPresent)
    } else {
        Ok(())
    }
}

#[cfg(feature = "orchard")]
fn ensure_no_orchard_proof_for_witness(
    bundle: &crate::orchard::Bundle,
) -> Result<(), SpendWitnessUpdateError> {
    if bundle.zkproof.is_some() {
        Err(SpendWitnessUpdateError::ProofAlreadyPresent)
    } else {
        Ok(())
    }
}

#[cfg(any(feature = "sapling", feature = "orchard"))]
fn ensure_anchor_update_supported(global: &Global) -> Result<(), AnchorUpdateError> {
    use zcash_protocol::{
        consensus::BranchId,
        constants::{V6_TX_VERSION, V6_VERSION_GROUP_ID},
    };

    if global.tx_version < V6_TX_VERSION
        || (global.tx_version == V6_TX_VERSION && global.version_group_id != V6_VERSION_GROUP_ID)
    {
        return Err(AnchorUpdateError::UnsupportedTransactionFormat);
    }

    match BranchId::try_from(global.consensus_branch_id) {
        Ok(BranchId::Nu6_3) => Ok(()),
        #[cfg(zcash_unstable = "nu7")]
        Ok(BranchId::Nu7) => Ok(()),
        Ok(_) => Err(AnchorUpdateError::UnsupportedConsensusBranchId),
        Err(_) => Err(AnchorUpdateError::UnknownConsensusBranchId),
    }
}

#[cfg(any(feature = "sapling", feature = "orchard"))]
fn set_anchor(slot: &mut Option<[u8; 32]>, anchor: [u8; 32]) -> Result<(), AnchorUpdateError> {
    match slot {
        Some(existing) if *existing != anchor => Err(AnchorUpdateError::ConflictingAnchor),
        _ => {
            *slot = Some(anchor);
            Ok(())
        }
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

/// Errors that can occur while setting Sapling, Orchard, or Ironwood anchors.
#[cfg(any(feature = "sapling", feature = "orchard"))]
#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum AnchorUpdateError {
    /// The PCZT transaction format does not support this update.
    UnsupportedTransactionFormat,
    /// The PCZT's consensus branch ID is unrecognized.
    UnknownConsensusBranchId,
    /// The PCZT's consensus branch ID does not support this update.
    UnsupportedConsensusBranchId,
    /// The bundle already contains a proof that depends on the current anchor.
    ProofAlreadyPresent,
    /// The bundle already contains a different anchor.
    ConflictingAnchor,
}

#[cfg(any(feature = "sapling", feature = "orchard"))]
impl core::fmt::Display for AnchorUpdateError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            AnchorUpdateError::UnsupportedTransactionFormat => {
                write!(
                    f,
                    "PCZT transaction format does not support shielded anchor updates"
                )
            }
            AnchorUpdateError::UnknownConsensusBranchId => {
                write!(f, "unknown consensus branch ID")
            }
            AnchorUpdateError::UnsupportedConsensusBranchId => {
                write!(
                    f,
                    "consensus branch ID does not support shielded anchor updates"
                )
            }
            AnchorUpdateError::ProofAlreadyPresent => {
                write!(
                    f,
                    "shielded proof that depends on the anchor is already present"
                )
            }
            AnchorUpdateError::ConflictingAnchor => {
                write!(f, "bundle already contains a different anchor")
            }
        }
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
