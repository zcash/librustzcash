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
    orchard::{Bundle as OrchardBundle, ORCHARD_SPENDS_AND_OUTPUTS_ENABLED},
};

#[cfg(feature = "orchard")]
use crate::orchard::bundle_version_for_revision;

use zcash_protocol::consensus::BranchId;
use zcash_protocol::constants::{
    V5_TX_VERSION, V5_VERSION_GROUP_ID, V6_TX_VERSION, V6_VERSION_GROUP_ID,
};

/// Initial flags allowing any modification.
const INITIAL_TX_MODIFIABLE: u8 = FLAG_TRANSPARENT_INPUTS_MODIFIABLE
    | FLAG_TRANSPARENT_OUTPUTS_MODIFIABLE
    | FLAG_SHIELDED_MODIFIABLE;

/// Errors that can occur when creating a PCZT.
#[derive(Debug)]
pub enum Error {
    /// The transaction version implied by the consensus branch ID does not carry an
    /// Ironwood bundle.
    IronwoodNotSupported,
    /// The consensus branch ID does not correspond to any known network upgrade.
    UnknownConsensusBranchId,
    /// The network upgrade for the consensus branch ID predates the v5
    /// transaction format, so it cannot be used to create a PCZT.
    UnsupportedConsensusBranchId,
    /// The requested Orchard-protocol flags cannot be represented under the
    /// Orchard or Ironwood bundle version implied by the consensus branch ID.
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

pub struct Creator {
    tx_version: u32,
    version_group_id: u32,
    consensus_branch_id: BranchId,
    fallback_lock_time: Option<u32>,
    expiry_height: u32,
    coin_type: u32,
    orchard_flags: u8,
    ironwood_flags: u8,
    sapling_anchor: [u8; 32],
    orchard_anchor: [u8; 32],
    ironwood_anchor: [u8; 32],
}

impl Creator {
    /// Creates a new PCZT for the given consensus branch ID.
    ///
    /// The transaction version is implied by the consensus branch ID: the v6
    /// transaction format from NU6.3 onward, and the v5 format for earlier upgrades.
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
        let branch_id = consensus_branch_id_for_pczt(consensus_branch_id)?;

        let (tx_version, version_group_id) = match branch_id {
            // Pre-NU5 branches are rejected by `consensus_branch_id_for_pczt`; NU5
            // through NU6.2 use the v5 transaction format.
            BranchId::Sprout
            | BranchId::Overwinter
            | BranchId::Sapling
            | BranchId::Blossom
            | BranchId::Heartwood
            | BranchId::Canopy
            | BranchId::Nu5
            | BranchId::Nu6
            | BranchId::Nu6_1
            | BranchId::Nu6_2 => (V5_TX_VERSION, V5_VERSION_GROUP_ID),
            BranchId::Nu6_3 => (V6_TX_VERSION, V6_VERSION_GROUP_ID),
            #[cfg(zcash_unstable = "nu7")]
            BranchId::Nu7 => (V6_TX_VERSION, V6_VERSION_GROUP_ID),
        };

        Ok(Self {
            tx_version,
            version_group_id,
            consensus_branch_id: branch_id,
            fallback_lock_time: None,
            expiry_height,
            coin_type,
            orchard_flags: ORCHARD_SPENDS_AND_OUTPUTS_ENABLED,
            ironwood_flags: crate::orchard::IRONWOOD_SPENDS_OUTPUTS_AND_CROSS_ADDRESS_ENABLED,
            sapling_anchor,
            orchard_anchor,
            ironwood_anchor: [0; 32],
        })
    }

    /// Returns the bundle version in effect for the given Orchard-protocol value pool
    /// under this Creator's consensus branch ID, or `None` if the pool is not
    /// supported under that branch.
    #[cfg(feature = "orchard")]
    fn bundle_version(&self, pool: orchard::ValuePool) -> Option<orchard::bundle::BundleVersion> {
        self.consensus_branch_id
            .orchard_protocol_revision()
            .and_then(|revision| bundle_version_for_revision(revision, pool))
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
    /// post-NU6.3 Orchard version, or cross-address-disabled flags under a pre-NU6.3
    /// Orchard version).
    #[cfg(feature = "orchard")]
    pub fn with_orchard_flags(
        mut self,
        orchard_flags: orchard::bundle::Flags,
    ) -> Result<Self, Error> {
        self.orchard_flags = orchard_flags
            .to_byte(
                self.bundle_version(orchard::ValuePool::Orchard)
                    .expect("`Creator::new` rejects branches that predate NU5"),
            )
            .ok_or(Error::UnrepresentableOrchardFlags)?;
        Ok(self)
    }

    /// Sets the Ironwood anchor for the PCZT.
    ///
    /// # Errors
    ///
    /// Returns [`Error::IronwoodNotSupported`] if the transaction version implied by
    /// the consensus branch ID passed to [`Creator::new`] does not carry an Ironwood
    /// bundle.
    pub fn with_ironwood_anchor(mut self, ironwood_anchor: [u8; 32]) -> Result<Self, Error> {
        if self.tx_version != V6_TX_VERSION {
            return Err(Error::IronwoodNotSupported);
        }
        self.ironwood_anchor = ironwood_anchor;
        Ok(self)
    }

    /// Sets the Ironwood flags for the PCZT.
    ///
    /// # Errors
    ///
    /// Returns [`Error::IronwoodNotSupported`] if the transaction version implied by
    /// the consensus branch ID passed to [`Creator::new`] does not carry an Ironwood
    /// bundle, or [`Error::UnrepresentableOrchardFlags`] if `flags` cannot be encoded
    /// under the Ironwood bundle version.
    #[cfg(feature = "orchard")]
    pub fn with_ironwood_flags(
        mut self,
        ironwood_flags: orchard::bundle::Flags,
    ) -> Result<Self, Error> {
        self.ironwood_flags = ironwood_flags
            .to_byte(
                self.bundle_version(orchard::ValuePool::Ironwood)
                    .ok_or(Error::IronwoodNotSupported)?,
            )
            .ok_or(Error::UnrepresentableOrchardFlags)?;
        Ok(self)
    }

    pub fn build(self) -> Pczt {
        let optional_sapling_anchor =
            |anchor| (anchor != crate::sapling::DEFAULT_ANCHOR).then_some(anchor);
        let optional_orchard_anchor =
            |anchor| (anchor != crate::orchard::DEFAULT_ANCHOR).then_some(anchor);

        Pczt {
            global: crate::common::Global {
                tx_version: self.tx_version,
                version_group_id: self.version_group_id,
                consensus_branch_id: self.consensus_branch_id.into(),
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
                anchor: optional_sapling_anchor(self.sapling_anchor),
                bsk: None,
            },
            orchard: OrchardBundle {
                actions: vec![],
                flags: self.orchard_flags,
                value_sum: (0, false),
                anchor: optional_orchard_anchor(self.orchard_anchor),
                // The note-plaintext version is determined by the Orchard bundle version.
                #[cfg(feature = "orchard")]
                note_version: self
                    .bundle_version(orchard::ValuePool::Orchard)
                    .expect("`Creator::new` rejects branches that predate NU5")
                    .note_version(),
                #[cfg(not(feature = "orchard"))]
                note_version: crate::orchard::NoteVersion::V2,
                zkproof: None,
                bsk: None,
            },
            ironwood: OrchardBundle {
                flags: self.ironwood_flags,
                anchor: optional_orchard_anchor(self.ironwood_anchor),
                ..crate::orchard::EMPTY_IRONWOOD
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
                .unwrap_or(crate::transparent::EMPTY_BUNDLE),
            sapling: parts
                .sapling
                .map(crate::sapling::Bundle::serialize_from)
                .unwrap_or(crate::sapling::EMPTY_BUNDLE),
            orchard: parts
                .orchard
                .map(OrchardBundle::serialize_from)
                .unwrap_or(crate::orchard::EMPTY_ORCHARD),
            ironwood: parts
                .ironwood
                .map(OrchardBundle::serialize_from)
                .unwrap_or(crate::orchard::EMPTY_IRONWOOD),
        })
    }
}

#[cfg(test)]
mod tests {
    use zcash_protocol::consensus::BranchId;
    use zcash_protocol::constants::{
        V5_TX_VERSION, V5_VERSION_GROUP_ID, V6_TX_VERSION, V6_VERSION_GROUP_ID,
    };

    use super::{Creator, Error};

    #[test]
    fn tx_version_follows_branch() {
        let pczt = Creator::new(BranchId::Nu6_2.into(), 10_000_000, 133, [0; 32], [0; 32])
            .unwrap()
            .build();
        assert_eq!(pczt.global.tx_version, V5_TX_VERSION);
        assert_eq!(pczt.global.version_group_id, V5_VERSION_GROUP_ID);

        let pczt = Creator::new(BranchId::Nu6_3.into(), 10_000_000, 133, [0; 32], [0; 32])
            .unwrap()
            .build();
        assert_eq!(pczt.global.tx_version, V6_TX_VERSION);
        assert_eq!(pczt.global.version_group_id, V6_VERSION_GROUP_ID);
    }

    #[test]
    fn ironwood_anchor_requires_v6() {
        assert!(matches!(
            Creator::new(BranchId::Nu6_2.into(), 10_000_000, 133, [0; 32], [0; 32])
                .unwrap()
                .with_ironwood_anchor([1; 32]),
            Err(Error::IronwoodNotSupported)
        ));

        let pczt = Creator::new(BranchId::Nu6_3.into(), 10_000_000, 133, [0; 32], [0; 32])
            .unwrap()
            .with_ironwood_anchor([1; 32])
            .unwrap()
            .build();
        assert_eq!(pczt.ironwood.anchor, Some([1; 32]));
    }
}
