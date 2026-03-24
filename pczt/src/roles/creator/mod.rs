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
};

use zcash_protocol::constants::{V5_TX_VERSION, V5_VERSION_GROUP_ID};

/// Initial flags allowing any modification.
const INITIAL_TX_MODIFIABLE: u8 = FLAG_TRANSPARENT_INPUTS_MODIFIABLE
    | FLAG_TRANSPARENT_OUTPUTS_MODIFIABLE
    | FLAG_SHIELDED_MODIFIABLE;

const ORCHARD_SPENDS_AND_OUTPUTS_ENABLED: u8 = 0b0000_0011;

pub struct Creator {
    tx_version: u32,
    version_group_id: u32,
    consensus_branch_id: u32,
    fallback_lock_time: Option<u32>,
    expiry_height: u32,
    coin_type: u32,
    orchard_flags: u8,
    sapling_anchor: [u8; 32],
    orchard_anchor: [u8; 32],
}

impl Creator {
    pub fn new(
        consensus_branch_id: u32,
        expiry_height: u32,
        coin_type: u32,
        sapling_anchor: [u8; 32],
        orchard_anchor: [u8; 32],
    ) -> Self {
        Self {
            // Default to v5 transaction format.
            tx_version: V5_TX_VERSION,
            version_group_id: V5_VERSION_GROUP_ID,
            consensus_branch_id,
            fallback_lock_time: None,
            expiry_height,
            coin_type,
            orchard_flags: ORCHARD_SPENDS_AND_OUTPUTS_ENABLED,
            sapling_anchor,
            orchard_anchor,
        }
    }

    pub fn with_fallback_lock_time(mut self, fallback: u32) -> Self {
        self.fallback_lock_time = Some(fallback);
        self
    }

    #[cfg(feature = "orchard")]
    pub fn with_orchard_flags(mut self, orchard_flags: orchard::bundle::Flags) -> Self {
        self.orchard_flags = orchard_flags.to_byte();
        self
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
            orchard: crate::orchard::Bundle {
                actions: vec![],
                flags: self.orchard_flags,
                value_sum: (0, true),
                anchor: self.orchard_anchor,
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

        #[cfg(zcash_unstable = "nu7")]
        use zcash_protocol::constants::V6_TX_VERSION;

        let tx_version = match parts.version {
            zcash_primitives::transaction::TxVersion::Sprout(_)
            | zcash_primitives::transaction::TxVersion::V3 => None,
            zcash_primitives::transaction::TxVersion::V4 => Some(V4_TX_VERSION),
            zcash_primitives::transaction::TxVersion::V5 => Some(V5_TX_VERSION),
            #[cfg(zcash_unstable = "nu7")]
            zcash_primitives::transaction::TxVersion::V6 => Some(V6_TX_VERSION),
            #[cfg(zcash_unstable = "zfuture")]
            zcash_primitives::transaction::TxVersion::ZFuture => None,
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
                .map(crate::orchard::Bundle::serialize_from)
                .unwrap_or_else(|| crate::orchard::Bundle {
                    actions: vec![],
                    flags: ORCHARD_SPENDS_AND_OUTPUTS_ENABLED,
                    value_sum: (0, true),
                    anchor: orchard::Anchor::empty_tree().to_bytes(),
                    zkproof: None,
                    bsk: None,
                }),
        })
    }
}
