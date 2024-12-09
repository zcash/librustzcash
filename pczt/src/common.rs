use std::collections::BTreeMap;

use getset::Getters;
use serde::{Deserialize, Serialize};

use crate::roles::combiner::merge_map;

pub(crate) const FLAG_TRANSPARENT_INPUTS_MODIFIABLE: u8 = 0b0000_0001;
pub(crate) const FLAG_TRANSPARENT_OUTPUTS_MODIFIABLE: u8 = 0b0000_0010;
pub(crate) const FLAG_HAS_SIGHASH_SINGLE: u8 = 0b0000_0100;
pub(crate) const FLAG_SHIELDED_MODIFIABLE: u8 = 0b1000_0000;

/// Global fields that are relevant to the transaction as a whole.
#[derive(Clone, Debug, Serialize, Deserialize, Getters)]
pub struct Global {
    //
    // Transaction effecting data.
    //
    // These are required fields that are part of the final transaction, and are filled in
    // by the Creator when initializing the PCZT.
    //
    pub(crate) tx_version: u32,
    pub(crate) version_group_id: u32,

    /// The consensus branch ID for the chain in which this transaction will be mined.
    ///
    /// Non-optional because this commits to the set of consensus rules that will apply to
    /// the transaction; differences therein can affect every role.
    pub(crate) consensus_branch_id: u32,

    /// The transaction locktime to use if no inputs specify a required locktime.
    ///
    /// - This is set by the Creator.
    /// - If omitted, the fallback locktime is assumed to be 0.
    pub(crate) fallback_lock_time: Option<u32>,

    pub(crate) expiry_height: u32,

    /// The [SLIP 44] coin type, indicating the network for which this transaction is
    /// being constructed.
    ///
    /// This is technically information that could be determined indirectly from the
    /// `consensus_branch_id` but is included explicitly to enable easy identification.
    /// Note that this field is not included in the transaction and has no consensus
    /// effect (`consensus_branch_id` fills that role).
    ///
    /// - This is set by the Creator.
    /// - Roles that encode network-specific information (for example, derivation paths
    ///   for key identification) should check against this field for correctness.
    ///
    /// [SLIP 44]: https://github.com/satoshilabs/slips/blob/master/slip-0044.md
    pub(crate) coin_type: u32,

    /// A bitfield for various transaction modification flags.
    ///
    /// - Bit 0 is the Transparent Inputs Modifiable Flag and indicates whether
    ///   transparent inputs can be modified.
    ///   - This is set to `true` by the Creator.
    ///   - This is checked by the Constructor before adding transparent inputs, and may
    ///     be set to `false` by the Constructor.
    ///   - This is set to `false` by the IO Finalizer if there are shielded spends or
    ///     outputs.
    ///   - This is set to `false` by a Signer that adds a signature that does not use
    ///     `SIGHASH_ANYONECANPAY` (which includes all shielded signatures).
    ///   - The Combiner merges this bit towards `false`.
    /// - Bit 1 is the Transparent Outputs Modifiable Flag and indicates whether
    ///   transparent outputs can be modified.
    ///   - This is set to `true` by the Creator.
    ///   - This is checked by the Constructor before adding transparent outputs, and may
    ///     be set to `false` by the Constructor.
    ///   - This is set to `false` by the IO Finalizer if there are shielded spends or
    ///     outputs.
    ///   - This is set to `false` by a Signer that adds a signature that does not use
    ///     `SIGHASH_NONE` (which includes all shielded signatures).
    ///   - The Combiner merges this bit towards `false`.
    /// - Bit 2 is the Has `SIGHASH_SINGLE` Flag and indicates whether the transaction has
    ///   a `SIGHASH_SINGLE` transparent signature who's input and output pairing must be
    ///   preserved.
    ///   - This is set to `false` by the Creator.
    ///   - This is updated by a Constructor.
    ///   - This is set to `true` by a Signer that adds a signature that uses
    ///     `SIGHASH_SINGLE`.
    ///   - This essentially indicates that the Constructor must iterate the transparent
    ///     inputs to determine whether and how to add a transparent input.
    ///   - The Combiner merges this bit towards `true`.
    /// - Bits 3-6 must be 0.
    /// - Bit 7 is the Shielded Modifiable Flag and indicates whether shielded spends or
    ///   outputs can be modified.
    ///   - This is set to `true` by the Creator.
    ///   - This is checked by the Constructor before adding shielded spends or outputs,
    ///     and may be set to `false` by the Constructor.
    ///   - This is set to `false` by the IO Finalizer if there are shielded spends or
    ///     outputs.
    ///   - This is set to `false` by every Signer (as all signatures commit to all
    ///     shielded spends and outputs).
    ///   - The Combiner merges this bit towards `false`.
    pub(crate) tx_modifiable: u8,

    /// Proprietary fields related to the overall transaction.
    #[getset(get = "pub")]
    pub(crate) proprietary: BTreeMap<String, Vec<u8>>,
}

impl Global {
    /// Returns whether transparent inputs can be added to or removed from the
    /// transaction.
    pub fn inputs_modifiable(&self) -> bool {
        (self.tx_modifiable & FLAG_TRANSPARENT_INPUTS_MODIFIABLE) != 0
    }

    /// Returns whether transparent outputs can be added to or removed from the
    /// transaction.
    pub fn outputs_modifiable(&self) -> bool {
        (self.tx_modifiable & FLAG_TRANSPARENT_OUTPUTS_MODIFIABLE) != 0
    }

    /// Returns whether the transaction has a `SIGHASH_SINGLE` transparent signature who's
    /// input and output pairing must be preserved.
    pub fn has_sighash_single(&self) -> bool {
        (self.tx_modifiable & FLAG_HAS_SIGHASH_SINGLE) != 0
    }

    /// Returns whether shielded spends or outputs can be added to or removed from the
    /// transaction.
    pub fn shielded_modifiable(&self) -> bool {
        (self.tx_modifiable & FLAG_SHIELDED_MODIFIABLE) != 0
    }

    pub(crate) fn merge(mut self, other: Self) -> Option<Self> {
        let Self {
            tx_version,
            version_group_id,
            consensus_branch_id,
            fallback_lock_time,
            expiry_height,
            coin_type,
            tx_modifiable,
            proprietary,
        } = other;

        if self.tx_version != tx_version
            || self.version_group_id != version_group_id
            || self.consensus_branch_id != consensus_branch_id
            || self.fallback_lock_time != fallback_lock_time
            || self.expiry_height != expiry_height
            || self.coin_type != coin_type
        {
            return None;
        }

        // `tx_modifiable` is explicitly a bitmap; merge it bit-by-bit.
        // - Bit 0 and Bit 1 merge towards `false`.
        if (tx_modifiable & FLAG_TRANSPARENT_INPUTS_MODIFIABLE) == 0 {
            self.tx_modifiable &= !FLAG_TRANSPARENT_INPUTS_MODIFIABLE;
        }
        if (tx_modifiable & FLAG_TRANSPARENT_OUTPUTS_MODIFIABLE) == 0 {
            self.tx_modifiable &= !FLAG_TRANSPARENT_OUTPUTS_MODIFIABLE;
        }
        // - Bit 2 merges towards `true`.
        if (tx_modifiable & FLAG_HAS_SIGHASH_SINGLE) != 0 {
            self.tx_modifiable |= FLAG_HAS_SIGHASH_SINGLE;
        }
        // - Bits 3-6 must be 0.
        if ((self.tx_modifiable & !FLAG_SHIELDED_MODIFIABLE) >> 3) != 0
            || ((tx_modifiable & !FLAG_SHIELDED_MODIFIABLE) >> 3) != 0
        {
            return None;
        }
        // - Bit 7 merges towards `false`.
        if (tx_modifiable & FLAG_SHIELDED_MODIFIABLE) == 0 {
            self.tx_modifiable &= !FLAG_SHIELDED_MODIFIABLE;
        }

        if !merge_map(&mut self.proprietary, proprietary) {
            return None;
        }

        Some(self)
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub(crate) struct Zip32Derivation {
    /// The [ZIP 32 seed fingerprint](https://zips.z.cash/zip-0032#seed-fingerprints).
    pub(crate) seed_fingerprint: [u8; 32],

    /// The sequence of indices corresponding to the shielded HD path.
    ///
    /// Indices can be hardened or non-hardened (i.e. the hardened flag bit may be set).
    /// When used with a Sapling or Orchard spend, the derivation path will generally be
    /// entirely hardened; when used with a transparent spend, the derivation path will
    /// generally include a non-hardened section matching either the [BIP 44] path, or the
    /// path at which ephemeral addresses are derived for [ZIP 320] transactions.
    ///
    /// [BIP 44]: https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki
    /// [ZIP 320]: https://zips.z.cash/zip-0320
    pub(crate) derivation_path: Vec<u32>,
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::Global;

    #[test]
    fn tx_modifiable() {
        let base = Global {
            tx_version: 0,
            version_group_id: 0,
            consensus_branch_id: 0,
            fallback_lock_time: None,
            expiry_height: 0,
            coin_type: 0,
            tx_modifiable: 0b0000_0000,
            proprietary: BTreeMap::new(),
        };

        for (left, right, expected) in [
            (0b0000_0000, 0b0000_0000, Some(0b0000_0000)),
            (0b0000_0000, 0b0000_0011, Some(0b0000_0000)),
            (0b0000_0001, 0b0000_0011, Some(0b0000_0001)),
            (0b0000_0010, 0b0000_0011, Some(0b0000_0010)),
            (0b0000_0011, 0b0000_0011, Some(0b0000_0011)),
            (0b0000_0000, 0b0000_0100, Some(0b0000_0100)),
            (0b0000_0100, 0b0000_0100, Some(0b0000_0100)),
            (0b0000_0011, 0b0000_0111, Some(0b0000_0111)),
            (0b0000_0000, 0b0000_1000, None),
            (0b0000_0000, 0b0001_0000, None),
            (0b0000_0000, 0b0010_0000, None),
            (0b0000_0000, 0b0100_0000, None),
            (0b0000_0000, 0b1000_0000, Some(0b0000_0000)),
            (0b1000_0000, 0b1000_0000, Some(0b1000_0000)),
        ] {
            let mut a = base.clone();
            a.tx_modifiable = left;

            let mut b = base.clone();
            b.tx_modifiable = right;

            assert_eq!(
                a.clone()
                    .merge(b.clone())
                    .map(|global| global.tx_modifiable),
                expected
            );
            assert_eq!(b.merge(a).map(|global| global.tx_modifiable), expected);
        }
    }
}
