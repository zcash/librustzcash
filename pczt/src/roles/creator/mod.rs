//! The Creator role (single entity).
//!
//!  - Creates the base PCZT with no information about spends or outputs.

use alloc::collections::BTreeMap;

use crate::{
    Pczt,
    common::{
        FLAG_SHIELDED_MODIFIABLE, FLAG_TRANSPARENT_INPUTS_MODIFIABLE,
        FLAG_TRANSPARENT_OUTPUTS_MODIFIABLE,
    },
    orchard::{Bundle as OrchardBundle, NoteVersion, ORCHARD_SPENDS_AND_OUTPUTS_ENABLED},
};

use zcash_protocol::consensus::BranchId;
use zcash_protocol::constants::{V5_TX_VERSION, V5_VERSION_GROUP_ID};

/// Initial flags allowing any modification.
const INITIAL_TX_MODIFIABLE: u8 = FLAG_TRANSPARENT_INPUTS_MODIFIABLE
    | FLAG_TRANSPARENT_OUTPUTS_MODIFIABLE
    | FLAG_SHIELDED_MODIFIABLE;

/// Errors that can occur when creating a PCZT.
#[derive(Debug)]
pub enum Error {
    /// The consensus branch ID does not correspond to any known network upgrade.
    UnknownConsensusBranchId,
    /// The network upgrade for the consensus branch ID predates the v5
    /// transaction format, so it cannot be used to create a PCZT.
    UnsupportedConsensusBranchId,
    /// The requested Orchard flags cannot be represented under the Orchard bundle
    /// version implied by the consensus branch ID.
    #[cfg(feature = "orchard")]
    UnrepresentableOrchardFlags,
}

/// Returns the network upgrade for `consensus_branch_id`, rejecting unrecognized
/// branch IDs and any upgrade that predates the v5 transaction format.
fn consensus_branch_id_for_pczt(consensus_branch_id: u32) -> Result<BranchId, Error> {
    match BranchId::try_from(consensus_branch_id).map_err(|_| Error::UnknownConsensusBranchId)? {
        BranchId::Sprout
        | BranchId::Overwinter
        | BranchId::Sapling
        | BranchId::Blossom
        | BranchId::Heartwood
        | BranchId::Canopy => Err(Error::UnsupportedConsensusBranchId),
        branch_id => Ok(branch_id),
    }
}

/// Returns the Orchard bundle version used by the Orchard pool of the given
/// (v5-or-later) network upgrade.
#[cfg(feature = "orchard")]
fn orchard_bundle_version_for_branch(branch_id: BranchId) -> orchard::bundle::BundleVersion {
    use orchard::bundle::BundleVersion;

    match branch_id {
        BranchId::Nu6_2 => BundleVersion::orchard_v2(),
        BranchId::Nu6_3 => BundleVersion::orchard_v3(),
        #[cfg(zcash_unstable = "nu7")]
        BranchId::Nu7 => BundleVersion::orchard_v3(),
        // NU5, NU6, and NU6.1 use the original (pre-NU6.2) Orchard pool; pre-NU5
        // branches are rejected before reaching here.
        _ => BundleVersion::orchard_insecure_v1(),
    }
}
pub struct Creator {
    tx_version: u32,
    version_group_id: u32,
    consensus_branch_id: u32,
    fallback_lock_time: Option<u32>,
    expiry_height: u32,
    coin_type: u32,
    orchard_flags: u8,
    #[cfg(feature = "orchard")]
    orchard_bundle_version: orchard::bundle::BundleVersion,
    sapling_anchor: [u8; 32],
    orchard_anchor: [u8; 32],
}

impl Creator {
    /// Creates a new PCZT for the given consensus branch ID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnknownConsensusBranchId`] if `consensus_branch_id` is not
    /// a recognized branch ID, or [`Error::UnsupportedConsensusBranchId`] if it
    /// predates the v5 transaction format.
    pub fn new(
        consensus_branch_id: u32,
        expiry_height: u32,
        coin_type: u32,
        sapling_anchor: [u8; 32],
        orchard_anchor: [u8; 32],
    ) -> Result<Self, Error> {
        #[cfg_attr(not(feature = "orchard"), allow(unused_variables))]
        let branch_id = consensus_branch_id_for_pczt(consensus_branch_id)?;

        #[cfg(feature = "orchard")]
        let orchard_bundle_version = orchard_bundle_version_for_branch(branch_id);

        Ok(Self {
            // Default to v5 transaction format.
            tx_version: V5_TX_VERSION,
            version_group_id: V5_VERSION_GROUP_ID,
            consensus_branch_id,
            fallback_lock_time: None,
            expiry_height,
            coin_type,
            orchard_flags: ORCHARD_SPENDS_AND_OUTPUTS_ENABLED,
            #[cfg(feature = "orchard")]
            orchard_bundle_version,
            sapling_anchor,
            orchard_anchor,
        })
    }

    pub fn with_fallback_lock_time(mut self, fallback: u32) -> Self {
        self.fallback_lock_time = Some(fallback);
        self
    }

    /// Sets the Orchard flags for the PCZT.
    ///
    /// The flags are validated against, and encoded under, the Orchard bundle
    /// version implied by the consensus branch ID passed to [`Creator::new`]
    /// (which also fixes the note-plaintext version).
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnrepresentableOrchardFlags`] if `flags` cannot be encoded
    /// under that bundle version (e.g. cross-address-enabled flags under a
    /// post-NU6.3 Orchard version).
    #[cfg(feature = "orchard")]
    pub fn with_orchard_flags(
        mut self,
        orchard_flags: orchard::bundle::Flags,
    ) -> Result<Self, Error> {
        self.orchard_flags = orchard_flags
            .to_byte(self.orchard_bundle_version)
            .ok_or(Error::UnrepresentableOrchardFlags)?;
        Ok(self)
    }

    pub fn build(self) -> Pczt {
        Pczt {
            global: crate::common::Global {
                tx_version: self.tx_version,
                version_group_id: self.version_group_id,
                consensus_branch_id: self.consensus_branch_id,
                fallback_lock_time: self.fallback_lock_time,
                expiry_height: self.expiry_height,
                coin_type: self.coin_type,
                tx_modifiable: INITIAL_TX_MODIFIABLE,
                proprietary: BTreeMap::new(),
            },
            transparent: crate::transparent::Bundle {
                inputs: vec![],
                outputs: vec![],
            },
            sapling: crate::sapling::Bundle {
                spends: vec![],
                outputs: vec![],
                value_sum: 0,
                anchor: self.sapling_anchor,
                bsk: None,
            },
            orchard: OrchardBundle {
                actions: vec![],
                flags: self.orchard_flags,
                value_sum: (0, true),
                anchor: self.orchard_anchor,
                // The note-plaintext version is determined by the Orchard bundle version.
                #[cfg(feature = "orchard")]
                note_version: self.orchard_bundle_version.note_version(),
                #[cfg(not(feature = "orchard"))]
                note_version: crate::orchard::NoteVersion::V2,
                zkproof: None,
                bsk: None,
            },
            ironwood: OrchardBundle {
                actions: vec![],
                flags: self.orchard_flags,
                value_sum: (0, true),
                anchor: self.orchard_anchor,
                note_version: NoteVersion::V3,
                zkproof: None,
                bsk: None,
            },
        }
    }

    /// Builds a PCZT from the output of a [`Builder`].
    ///
    /// Returns `None` if the `TxVersion` is incompatible with PCZTs.
    ///
    /// [`Builder`]: zcash_primitives::transaction::builder::Builder
    #[cfg(feature = "zcp-builder")]
    pub fn build_from_parts<P: zcash_protocol::consensus::Parameters>(
        parts: zcash_primitives::transaction::builder::PcztParts<P>,
    ) -> Option<Pczt> {
        use ::transparent::sighash::{SIGHASH_ANYONECANPAY, SIGHASH_SINGLE};
        use zcash_protocol::{consensus::NetworkConstants, constants::V4_TX_VERSION};

        use crate::common::FLAG_HAS_SIGHASH_SINGLE;

        use zcash_protocol::constants::V6_TX_VERSION;

        let tx_version = match parts.version {
            zcash_primitives::transaction::TxVersion::Sprout(_)
            | zcash_primitives::transaction::TxVersion::V3 => None,
            zcash_primitives::transaction::TxVersion::V4 => Some(V4_TX_VERSION),
            zcash_primitives::transaction::TxVersion::V5 => Some(V5_TX_VERSION),
            zcash_primitives::transaction::TxVersion::V6 => Some(V6_TX_VERSION),
        }?;

        // Spends and outputs not modifiable.
        let mut tx_modifiable = 0b0000_0000;
        // Check if any input is using `SIGHASH_SINGLE` (with or without `ANYONECANPAY`).
        if parts.transparent.as_ref().is_some_and(|bundle| {
            bundle.inputs().iter().any(|input| {
                (input.sighash_type().encode() & !SIGHASH_ANYONECANPAY) == SIGHASH_SINGLE
            })
        }) {
            tx_modifiable |= FLAG_HAS_SIGHASH_SINGLE;
        }

        Some(Pczt {
            global: crate::common::Global {
                tx_version,
                version_group_id: parts.version.version_group_id(),
                consensus_branch_id: parts.consensus_branch_id.into(),
                fallback_lock_time: Some(parts.lock_time),
                expiry_height: parts.expiry_height.into(),
                coin_type: parts.params.network_type().coin_type(),
                tx_modifiable,
                proprietary: BTreeMap::new(),
            },
            transparent: parts
                .transparent
                .map(crate::transparent::Bundle::serialize_from)
                .unwrap_or_else(|| crate::transparent::Bundle {
                    inputs: vec![],
                    outputs: vec![],
                }),
            sapling: parts
                .sapling
                .map(crate::sapling::Bundle::serialize_from)
                .unwrap_or_else(|| crate::sapling::Bundle {
                    spends: vec![],
                    outputs: vec![],
                    value_sum: 0,
                    anchor: sapling::Anchor::empty_tree().to_bytes(),
                    bsk: None,
                }),
            orchard: parts
                .orchard
                .map(OrchardBundle::serialize_from)
                .unwrap_or_else(|| OrchardBundle {
                    actions: vec![],
                    flags: ORCHARD_SPENDS_AND_OUTPUTS_ENABLED,
                    value_sum: (0, true),
                    anchor: orchard::Anchor::empty_tree().to_bytes(),
                    note_version: NoteVersion::V2,
                    zkproof: None,
                    bsk: None,
                }),
            ironwood: OrchardBundle {
                actions: vec![],
                flags: ORCHARD_SPENDS_AND_OUTPUTS_ENABLED,
                value_sum: (0, true),
                anchor: orchard::Anchor::empty_tree().to_bytes(),
                note_version: NoteVersion::V3,
                zkproof: None,
                bsk: None,
            },
        })
    }
}
