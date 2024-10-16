use std::collections::BTreeMap;

use crate::{Pczt, V5_TX_VERSION, V5_VERSION_GROUP_ID};

pub struct Creator {
    tx_version: u32,
    version_group_id: u32,
    consensus_branch_id: u32,
    expiry_height: u32,
    orchard_flags: u8,
}

impl Creator {
    pub fn new(consensus_branch_id: u32, expiry_height: u32) -> Self {
        Self {
            // Default to v5 transaction format.
            tx_version: V5_TX_VERSION,
            version_group_id: V5_VERSION_GROUP_ID,
            consensus_branch_id,
            expiry_height,
            // Spends and outputs enabled.
            orchard_flags: 0b0000_0011,
        }
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
                lock_time: 0,
                expiry_height: self.expiry_height,
                proprietary: BTreeMap::new(),
            },
            transparent: crate::transparent::Bundle {
                inputs: vec![],
                outputs: vec![],
            },
            sapling: crate::sapling::Bundle {
                spends: vec![],
                outputs: vec![],
                value_balance: 0,
                anchor: None,
                bsk: None,
            },
            orchard: crate::orchard::Bundle {
                actions: vec![],
                flags: self.orchard_flags,
                value_balance: 0,
                anchor: None,
                zkproof: None,
                bsk: None,
            },
        }
    }
}
