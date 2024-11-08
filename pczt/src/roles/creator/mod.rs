use std::collections::BTreeMap;

use crate::{
    common::{FLAG_INPUTS_MODIFIABLE, FLAG_OUTPUTS_MODIFIABLE},
    Pczt, V5_TX_VERSION, V5_VERSION_GROUP_ID,
};

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
                // Spends and outputs modifiable, no SIGHASH_SINGLE.
                tx_modifiable: FLAG_INPUTS_MODIFIABLE | FLAG_OUTPUTS_MODIFIABLE,
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
}
