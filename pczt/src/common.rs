//! The common fields of a PCZT.

use alloc::{collections::BTreeMap, string::String, vec::Vec};
use core::fmt;

use getset::Getters;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::roles::combiner::merge_map;

pub(crate) const FLAG_TRANSPARENT_INPUTS_MODIFIABLE: u8 = 0b0000_0001;
pub(crate) const FLAG_TRANSPARENT_OUTPUTS_MODIFIABLE: u8 = 0b0000_0010;
pub(crate) const FLAG_HAS_SIGHASH_SINGLE: u8 = 0b0000_0100;
pub(crate) const FLAG_SHIELDED_MODIFIABLE: u8 = 0b1000_0000;

/// A placeholder anchor used internally when parsing a shielded bundle for an
/// operation that does not read the anchor's value. Zero is always a valid anchor
/// encoding for the Sapling, Orchard, and Ironwood note commitment trees.
#[cfg(any(
    feature = "io-finalizer",
    feature = "orchard",
    feature = "sapling",
    feature = "signer",
    feature = "tx-extractor"
))]
pub(crate) const PLACEHOLDER_ANCHOR: [u8; 32] = [0; 32];

/// Governs whether a non-empty shielded bundle's `anchor` must be set in order to parse
/// it into the form used by the payment protocol crates.
///
/// [ZIP 374](https://zips.z.cash/zip-0374) makes Sapling and Orchard-family bundle anchors
/// deferrable in V6 and later transactions, so operations that do not depend on the
/// anchor's value (for example computing a v6 sighash, which excludes anchors, or
/// updating unrelated fields) can proceed with it absent.
#[cfg(any(
    feature = "io-finalizer",
    feature = "orchard",
    feature = "sapling",
    feature = "signer",
    feature = "tx-extractor"
))]
#[derive(Clone, Copy, Debug)]
pub(crate) enum AnchorRequirement {
    /// The operation does not read the anchor, so an absent anchor is parsed using a
    /// placeholder value.
    ///
    /// Only constructed when the `orchard` or `sapling` feature is enabled, as those
    /// are the only operations lenient enough to use it.
    NotRequired,
    /// The operation requires the anchor's real value; parsing fails if it is absent
    /// from a non-empty bundle.
    Required,
}

#[cfg(any(
    feature = "io-finalizer",
    feature = "orchard",
    feature = "sapling",
    feature = "signer",
    feature = "tx-extractor"
))]
impl AnchorRequirement {
    /// Returns the requirement for operations that do not themselves consume the
    /// anchor, but still parse bundles through the protocol crates.
    ///
    /// V6 signatures do not commit to shielded anchors, so signing and IO
    /// finalization can proceed before anchors are set. V5 signatures do commit to
    /// anchors for Sapling spends and Orchard-protocol actions, so those bundles must
    /// keep requiring them.
    pub(crate) fn for_pre_authorization(tx_version: u32) -> Self {
        match tx_version {
            zcash_protocol::constants::V6_TX_VERSION => AnchorRequirement::NotRequired,
            #[cfg(zcash_unstable = "nutachyon")]
            zcash_protocol::constants::V7_TX_VERSION => AnchorRequirement::NotRequired,
            _ => AnchorRequirement::Required,
        }
    }

    /// Resolves a shielded bundle's wire `anchor` to the anchor that should be used
    /// when parsing it, given whether the bundle has no transaction items (no Sapling
    /// spends or outputs, or no Orchard-protocol actions).
    ///
    /// Returns `None` to mean "the anchor is absent and required"; callers should map
    /// that case to their own missing-anchor error. An absent anchor on an empty bundle
    /// resolves to [`PLACEHOLDER_ANCHOR`], since there is nothing to prove or extract.
    pub(crate) fn resolve(
        self,
        anchor: Option<[u8; 32]>,
        bundle_is_empty: bool,
    ) -> Option<[u8; 32]> {
        match (self, anchor) {
            (_, Some(anchor)) => Some(anchor),
            (AnchorRequirement::NotRequired, None) => Some(PLACEHOLDER_ANCHOR),
            (AnchorRequirement::Required, None) if bundle_is_empty => Some(PLACEHOLDER_ANCHOR),
            (AnchorRequirement::Required, None) => None,
        }
    }
}

/// Global fields that are relevant to the transaction as a whole.
#[derive(Clone, Debug, Serialize, Deserialize, Getters)]
pub struct Global {
    //
    // Transaction effecting data.
    //
    // These are required fields that are part of the final transaction, and are filled in
    // by the Creator when initializing the PCZT.
    //
    #[getset(get = "pub")]
    pub(crate) tx_version: u32,
    #[getset(get = "pub")]
    pub(crate) version_group_id: u32,

    /// The consensus branch ID for the chain in which this transaction will be mined.
    ///
    /// Non-optional because this commits to the set of consensus rules that will apply to
    /// the transaction; differences therein can affect every role.
    #[getset(get = "pub")]
    pub(crate) consensus_branch_id: u32,

    /// The transaction locktime to use if no inputs specify a required locktime.
    ///
    /// - This is set by the Creator.
    /// - If omitted, the fallback locktime is assumed to be 0.
    ///
    /// The transaction's actual lock time is given by [`determine_lock_time`], which
    /// takes the inputs' required lock times into account.
    #[getset(get = "pub")]
    pub(crate) fallback_lock_time: Option<u32>,

    #[getset(get = "pub")]
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
    #[getset(get = "pub")]
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
    ///
    /// Individual flags are also available via [`Global::inputs_modifiable`],
    /// [`Global::outputs_modifiable`], [`Global::has_sighash_single`], and
    /// [`Global::shielded_modifiable`].
    #[getset(get = "pub")]
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

/// Determines the lock time for the transaction.
///
/// Implemented following the specification in [BIP 370], with the rationale that this
/// makes integration of PCZTs simpler for codebases that already support PSBTs.
///
/// Matches the algorithm of Bitcoin Core's reference implementation
/// (`PartiallySignedTransaction::ComputeTimeLock`): an input that specifies only one
/// of the two lock time types disables the other type for the transaction, while an
/// input that specifies both (or neither) disables neither. If both types end up
/// disabled, the inputs' requirements are incompatible and `None` is returned;
/// otherwise the height lock time is preferred over the time lock time ([BIP 370]:
/// "If a PSBT has both types of locktimes possible because one or more inputs specify
/// both `required_time_locktime` and `required_height_locktime`, then a locktime
/// determined by looking at the `required_height_locktime` fields of the inputs must
/// be chosen"), and the result is the maximum of the chosen type, with a maximum of
/// zero treated as no requirement. If no input specifies a lock time,
/// `Global.fallback_lock_time` is used (0 if absent).
///
/// [BIP 370]: https://github.com/bitcoin/bips/blob/master/bip-0370.mediawiki#determining-lock-time
pub fn determine_lock_time<L: LockTimeInput>(
    global: &crate::common::Global,
    inputs: &[L],
) -> Option<u32> {
    // The nLockTime field of a transaction is determined by inspecting the
    // `Global.fallback_lock_time` and each input's `required_time_lock_time` and
    // `required_height_lock_time` fields.
    let mut time_lock: Option<u32> = Some(0);
    let mut height_lock: Option<u32> = Some(0);
    for input in inputs {
        let required_time = input.required_time_lock_time();
        let required_height = input.required_height_lock_time();
        match (required_time, required_height) {
            // This input can only take a time lock time, so the transaction can no
            // longer have a height lock time.
            (Some(_), None) => {
                height_lock = None;
                time_lock?;
            }
            // This input can only take a height lock time, so the transaction can no
            // longer have a time lock time.
            (None, Some(_)) => {
                time_lock = None;
                height_lock?;
            }
            // An input that specifies both lock time types, or neither, can take
            // both, so neither type is disabled.
            _ => {}
        }
        if let Some(t) = required_time
            && let Some(lock) = time_lock.as_mut()
        {
            *lock = (*lock).max(t);
        }
        if let Some(h) = required_height
            && let Some(lock) = height_lock.as_mut()
        {
            *lock = (*lock).max(h);
        }
    }

    if let Some(h) = height_lock
        && h > 0
    {
        return Some(h);
    }
    if let Some(t) = time_lock
        && t > 0
    {
        return Some(t);
    }
    // If none of the inputs have a `required_time_lock_time` and
    // `required_height_lock_time`, then `Global.fallback_lock_time` must be used. If
    // `Global.fallback_lock_time` is not provided, then it is assumed to be 0.
    Some(global.fallback_lock_time.unwrap_or(0))
}

pub trait LockTimeInput {
    fn required_time_lock_time(&self) -> Option<u32>;
    fn required_height_lock_time(&self) -> Option<u32>;
}

impl LockTimeInput for crate::transparent::Input {
    fn required_time_lock_time(&self) -> Option<u32> {
        self.required_time_lock_time
    }

    fn required_height_lock_time(&self) -> Option<u32> {
        self.required_height_lock_time
    }
}

#[cfg(feature = "transparent")]
impl LockTimeInput for ::transparent::pczt::Input {
    fn required_time_lock_time(&self) -> Option<u32> {
        *self.required_time_lock_time()
    }

    fn required_height_lock_time(&self) -> Option<u32> {
        *self.required_height_lock_time()
    }
}

/// The encoding of a secret key that a PCZT carries.
///
/// The bytes are erased when the value is dropped. The `Debug` output does not show
/// them, and equality comparison takes constant time. The serialized form is the same
/// as that of a `[u8; 32]`.
#[derive(Clone)]
pub struct SecretKeyBytes([u8; 32]);

impl SecretKeyBytes {
    /// Wraps the encoding of a secret key.
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the encoding of the secret key.
    pub fn expose_secret(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Drop for SecretKeyBytes {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl ZeroizeOnDrop for SecretKeyBytes {}

impl fmt::Debug for SecretKeyBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretKeyBytes(..)")
    }
}

impl PartialEq for SecretKeyBytes {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

impl Eq for SecretKeyBytes {}

impl Serialize for SecretKeyBytes {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for SecretKeyBytes {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        <[u8; 32]>::deserialize(deserializer).map(Self)
    }
}

#[cfg(test)]
mod secret_key_bytes_tests {
    use alloc::format;

    use proptest::prelude::*;

    use super::SecretKeyBytes;

    proptest! {
        #[test]
        fn serializes_as_byte_array(bytes in prop::array::uniform32(any::<u8>())) {
            let secret = SecretKeyBytes::new(bytes);
            let encoded = postcard::to_allocvec(&secret).unwrap();
            prop_assert_eq!(&encoded, &postcard::to_allocvec(&bytes).unwrap());

            let decoded: SecretKeyBytes = postcard::from_bytes(&encoded).unwrap();
            prop_assert_eq!(decoded.expose_secret(), &bytes);
        }

        #[test]
        fn debug_output_is_redacted(bytes in prop::array::uniform32(any::<u8>())) {
            let debug = format!("{:?}", SecretKeyBytes::new(bytes));
            prop_assert_eq!(debug.as_str(), "SecretKeyBytes(..)");
        }

        #[test]
        fn equality_matches_byte_equality(
            lhs in prop::array::uniform32(any::<u8>()),
            rhs in prop::array::uniform32(any::<u8>()),
        ) {
            prop_assert_eq!(SecretKeyBytes::new(lhs) == SecretKeyBytes::new(rhs), lhs == rhs);
            prop_assert!(SecretKeyBytes::new(lhs) == SecretKeyBytes::new(lhs));
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::collections::BTreeMap;

    use zcash_protocol::{
        consensus::BranchId,
        constants::{V5_TX_VERSION, V5_VERSION_GROUP_ID, mainnet},
    };

    use super::{FLAG_SHIELDED_MODIFIABLE, FLAG_TRANSPARENT_INPUTS_MODIFIABLE, Global};

    #[test]
    fn global_getters() {
        // Distinct values, so that a getter reading the wrong field is caught.
        const FALLBACK_LOCK_TIME: u32 = 1;
        const EXPIRY_HEIGHT: u32 = 2;
        const TX_MODIFIABLE: u8 = FLAG_TRANSPARENT_INPUTS_MODIFIABLE | FLAG_SHIELDED_MODIFIABLE;

        let global = Global {
            tx_version: V5_TX_VERSION,
            version_group_id: V5_VERSION_GROUP_ID,
            consensus_branch_id: BranchId::Nu6.into(),
            fallback_lock_time: Some(FALLBACK_LOCK_TIME),
            expiry_height: EXPIRY_HEIGHT,
            coin_type: mainnet::COIN_TYPE,
            tx_modifiable: TX_MODIFIABLE,
            proprietary: BTreeMap::new(),
        };

        assert_eq!(global.coin_type(), &mainnet::COIN_TYPE);
        assert_eq!(global.fallback_lock_time(), &Some(FALLBACK_LOCK_TIME));
        assert_eq!(global.tx_modifiable(), &TX_MODIFIABLE);

        // The raw bitfield agrees with the semantic flag accessors.
        assert!(global.inputs_modifiable());
        assert!(!global.outputs_modifiable());
        assert!(!global.has_sighash_single());
        assert!(global.shielded_modifiable());
    }

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

#[cfg(test)]
mod determine_lock_time_tests {
    use alloc::vec::Vec;

    use zcash_protocol::constants::{V5_TX_VERSION, V5_VERSION_GROUP_ID};

    use super::{Global, LockTimeInput, determine_lock_time};

    #[derive(Default)]
    struct TestInput {
        time: Option<u32>,
        height: Option<u32>,
    }

    impl LockTimeInput for TestInput {
        fn required_time_lock_time(&self) -> Option<u32> {
            self.time
        }

        fn required_height_lock_time(&self) -> Option<u32> {
            self.height
        }
    }

    fn global(fallback_lock_time: Option<u32>) -> Global {
        Global {
            tx_version: V5_TX_VERSION,
            version_group_id: V5_VERSION_GROUP_ID,
            consensus_branch_id: 0,
            fallback_lock_time,
            expiry_height: 0,
            coin_type: 0,
            tx_modifiable: 0,
            proprietary: Default::default(),
        }
    }

    /// The full truth table of BIP 370's lock time determination, matching Bitcoin
    /// Core's `PartiallySignedTransaction::ComputeTimeLock`. The "input specifies
    /// both" rows are the regression this guards: they used to be reported as
    /// incompatible (`None`) even though BIP 370 requires the height lock time.
    #[test]
    fn follows_bip_370() {
        let t = |time, height| TestInput { time, height };

        for (inputs, expected) in [
            // No input specifies a lock time: the fallback is used.
            (vec![t(None, None)], Some(0)),
            (vec![t(None, None)], Some(42)), // with fallback 42, below
            // Only time lock times are required: the maximum is used.
            (vec![t(Some(100), None), t(Some(200), None)], Some(200)),
            // Only height lock times are required: the maximum is used.
            (vec![t(None, Some(50)), t(None, Some(75))], Some(75)),
            // A time-only input and a height-only input are incompatible.
            (vec![t(Some(100), None), t(None, Some(50))], None),
            (vec![t(None, Some(50)), t(Some(100), None)], None),
            // An input that specifies both types can take either (BIP 370:
            // "Inputs not specifying a lock time field can take both types of
            // lock times, as can those that specify both."), so on its own the
            // height lock time is chosen (BIP 370's final rule).
            (vec![t(Some(100), Some(50))], Some(50)),
            // Both-specifying plus time-only: time is the only type supported by
            // every input.
            (vec![t(Some(100), Some(50)), t(Some(200), None)], Some(200)),
            // Both-specifying plus height-only: height is the only type supported
            // by every input.
            (vec![t(Some(100), Some(50)), t(None, Some(75))], Some(75)),
            // Both-specifying plus an input that specifies neither.
            (vec![t(Some(100), Some(50)), t(None, None)], Some(50)),
            // A zero requirement does not force a zero lock time (matching Bitcoin
            // Core, which treats a maximum of zero as no requirement).
            (vec![t(None, Some(0))], Some(0)), // fallback 0
        ] {
            // The fallback differs between the first two cases.
            let fallback = match expected {
                Some(42) => Some(42),
                _ => None,
            };
            // The zero-requirement case falls back too.
            let expected = match (inputs.as_slice(), expected) {
                (
                    [
                        TestInput {
                            height: Some(0), ..
                        },
                    ],
                    Some(0),
                ) if fallback.is_none() => {
                    // With no fallback, a zero height requirement yields 0 anyway.
                    Some(0)
                }
                (_, e) => e,
            };
            assert_eq!(
                determine_lock_time(&global(fallback), &inputs),
                expected,
                "inputs: {:?}",
                inputs
                    .iter()
                    .map(|i| (i.time, i.height))
                    .collect::<Vec<_>>()
            );
        }
    }
}
