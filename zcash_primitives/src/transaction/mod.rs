//! Structs and methods for handling Zcash transactions.
//!
//! The byte layer ([`bytes`]) is always available and does not require the
//! Sapling or Orchard protocol crates. The typed transaction types expose each
//! shielded protocol independently under its corresponding feature. The builder
//! requires `circuits`; full ZIP 248 validation requires both protocols.
#[cfg(feature = "circuits")]
pub mod builder;
pub mod bytes;
pub mod coinbase;
pub mod components;
pub mod fees;
pub mod sighash;
mod sighash_v4;
mod sighash_v5;
mod sighash_v6;
#[cfg(zcash_unstable = "nu8")]
mod sighash_v7;

pub mod txid;
pub mod util;
pub mod zip248;

#[cfg(all(
    any(test, feature = "test-dependencies"),
    feature = "sapling",
    feature = "orchard"
))]
pub mod tests;

use alloc::boxed::Box;

use crate::encoding::{ReadBytesExt, WriteBytesExt};
use corez::io::{self, Read, Write};
use zcash_protocol::consensus::BranchId;
// `valid_in_branch` matches on every branch by bare name.
use zcash_protocol::consensus::BranchId::*;

use zcash_protocol::consensus::BlockHeight;

#[allow(unused_imports)]
use ::transparent::bundle::{self as transparent, OutPoint, TxIn, TxOut};

use {
    blake2b_simd::Hash as Blake2bHash,
    core::convert::TryFrom,
    core::ops::Deref,
    zcash_protocol::value::{BalanceError, ZatBalance, Zatoshis},
};

#[cfg(all(feature = "sapling", feature = "orchard", zcash_unstable = "nu8"))]
use alloc::string::String;
#[cfg(zcash_unstable = "nu8")]
use alloc::{borrow::Cow, vec::Vec};

use self::bytes::V4SaplingBundleBytes;
#[cfg(zcash_unstable = "nu8")]
use self::bytes::transparent::TransparentBundleBytes;
#[cfg(zcash_unstable = "nu8")]
use self::bytes::{
    CoinbaseBundleBytes, V7AuthBundleBytes, V7EffectBundleBytes, V7TransactionBodyBytes,
};
#[cfg(all(feature = "sapling", zcash_unstable = "nu8"))]
use self::bytes::{V7SaplingAuthBytes, V7SaplingBundleBytes};
#[cfg(feature = "orchard")]
use self::components::orchard as orchard_serialization;
#[cfg(feature = "sapling")]
use self::{bytes::SaplingBundleBytes, components::sapling as sapling_serialization};
use self::{
    bytes::{
        LegacyTransparentBundleBytes, SproutBundleBytes, TransactionBodyBytes, TransactionBytes,
    },
    components::sprout,
    txid::{BlockTxCommitmentDigester, TxIdDigester, to_txid},
    util::sha256d::{HashReader, HashWriter},
    zip248::{BundleType, BundleVariant},
};

#[cfg(all(feature = "circuits", feature = "sapling", feature = "orchard"))]
use ::sapling::builder as sapling_builder;

use zcash_protocol::constants::{
    V3_TX_VERSION, V3_VERSION_GROUP_ID, V4_TX_VERSION, V4_VERSION_GROUP_ID, V5_TX_VERSION,
    V5_VERSION_GROUP_ID,
};

use zcash_protocol::constants::{V6_TX_VERSION, V6_VERSION_GROUP_ID};
#[cfg(zcash_unstable = "nu8")]
use zcash_protocol::constants::{V7_TX_VERSION, V7_VERSION_GROUP_ID};

pub use zcash_protocol::TxId;

/// The set of defined transaction format versions.
///
/// This is serialized in the first four or eight bytes of the transaction format, and
/// represents valid combinations of the `(overwintered, version, version_group_id)`
/// transaction fields. Note that this is not dependent on epoch, only on transaction encoding.
/// For example, if a particular epoch defines a new transaction version but also allows the
/// previous version, then only the new version would be added to this enum.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxVersion {
    /// Transaction versions allowed prior to Overwinter activation. The argument MUST be
    /// in the range `1..=0x7FFFFFFF`. Only versions 1 and 2 are defined; `3..=0x7FFFFFFF`
    /// was allowed by consensus but considered equivalent to 2. This is specified in
    /// [§ 7.1 Transaction Encoding and Consensus](https://zips.z.cash/protocol/protocol.pdf#txnencoding).
    Sprout(u32),
    /// Transaction version 3, which was introduced by the Overwinter network upgrade
    /// and allowed until Sapling activation. It is specified in
    /// [§ 7.1 Transaction Encoding and Consensus](https://zips.z.cash/protocol/protocol.pdf#txnencoding).
    V3,
    /// Transaction version 4, which was introduced by the Sapling network upgrade.
    /// It is specified in [§ 7.1 Transaction Encoding and Consensus](https://zips.z.cash/protocol/protocol.pdf#txnencoding).
    V4,
    /// Transaction version 5, which was introduced by the NU5 network upgrade.
    /// It is specified in [§ 7.1 Transaction Encoding and Consensus](https://zips.z.cash/protocol/protocol.pdf#txnencoding)
    /// and [ZIP 225](https://zips.z.cash/zip-0225).
    V5,
    /// Transaction version 6, specified in [ZIP 229](https://zips.z.cash/zip-0229).
    V6,
    /// Experimental transaction version 7 for the provisional NU8 network upgrade.
    /// It is specified in [ZIP 248](https://zips.z.cash/zip-0248).
    #[cfg(zcash_unstable = "nu8")]
    V7,
}

impl TxVersion {
    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let header = reader.read_u32_le()?;
        let overwintered = (header >> 31) == 1;
        let version = header & 0x7FFFFFFF;

        if overwintered {
            match (version, reader.read_u32_le()?) {
                (V3_TX_VERSION, V3_VERSION_GROUP_ID) => Ok(TxVersion::V3),
                (V4_TX_VERSION, V4_VERSION_GROUP_ID) => Ok(TxVersion::V4),
                (V5_TX_VERSION, V5_VERSION_GROUP_ID) => Ok(TxVersion::V5),
                (V6_TX_VERSION, V6_VERSION_GROUP_ID) => Ok(TxVersion::V6),
                #[cfg(zcash_unstable = "nu8")]
                (V7_TX_VERSION, V7_VERSION_GROUP_ID) => Ok(TxVersion::V7),
                _ => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Unknown transaction format",
                )),
            }
        } else if version >= 1 {
            Ok(TxVersion::Sprout(version))
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Unknown transaction format",
            ))
        }
    }

    pub fn header(&self) -> u32 {
        // After Sprout, the overwintered bit is always set.
        let overwintered = match self {
            TxVersion::Sprout(_) => 0,
            _ => 1 << 31,
        };

        overwintered
            | match self {
                TxVersion::Sprout(v) => *v,
                TxVersion::V3 => V3_TX_VERSION,
                TxVersion::V4 => V4_TX_VERSION,
                TxVersion::V5 => V5_TX_VERSION,
                TxVersion::V6 => V6_TX_VERSION,
                #[cfg(zcash_unstable = "nu8")]
                TxVersion::V7 => V7_TX_VERSION,
            }
    }

    pub fn version_group_id(&self) -> u32 {
        match self {
            TxVersion::Sprout(_) => 0,
            TxVersion::V3 => V3_VERSION_GROUP_ID,
            TxVersion::V4 => V4_VERSION_GROUP_ID,
            TxVersion::V5 => V5_VERSION_GROUP_ID,
            TxVersion::V6 => V6_VERSION_GROUP_ID,
            #[cfg(zcash_unstable = "nu8")]
            TxVersion::V7 => V7_VERSION_GROUP_ID,
        }
    }

    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_u32_le(self.header())?;
        match self {
            TxVersion::Sprout(_) => Ok(()),
            _ => writer.write_u32_le(self.version_group_id()),
        }
    }

    /// Returns `true` if this transaction version supports the Sprout protocol.
    pub fn has_sprout(&self) -> bool {
        match self {
            TxVersion::Sprout(v) => *v >= 2u32,
            TxVersion::V3 | TxVersion::V4 => true,
            TxVersion::V5 => false,
            TxVersion::V6 => false,
            #[cfg(zcash_unstable = "nu8")]
            TxVersion::V7 => false,
        }
    }

    pub fn has_overwinter(&self) -> bool {
        !matches!(self, TxVersion::Sprout(_))
    }

    /// Returns `true` if this transaction version supports the Sapling protocol.
    pub fn has_sapling(&self) -> bool {
        match self {
            TxVersion::Sprout(_) | TxVersion::V3 => false,
            TxVersion::V4 => true,
            TxVersion::V5 => true,
            TxVersion::V6 => true,
            #[cfg(zcash_unstable = "nu8")]
            TxVersion::V7 => true,
        }
    }

    /// Returns `true` if this transaction version supports the Orchard protocol.
    pub fn has_orchard(&self) -> bool {
        match self {
            TxVersion::Sprout(_) | TxVersion::V3 | TxVersion::V4 => false,
            TxVersion::V5 => true,
            TxVersion::V6 => true,
            #[cfg(zcash_unstable = "nu8")]
            TxVersion::V7 => true,
        }
    }

    /// Returns `true` if this transaction version supports the Ironwood protocol.
    pub fn has_ironwood(&self) -> bool {
        match self {
            TxVersion::Sprout(_) | TxVersion::V3 | TxVersion::V4 | TxVersion::V5 => false,
            TxVersion::V6 => true,
            #[cfg(zcash_unstable = "nu8")]
            TxVersion::V7 => true,
        }
    }

    #[cfg(all(feature = "zip-233", zcash_unstable = "zip233"))]
    /// Returns whether this implementation supports ZIP 233 for this version and branch.
    ///
    /// No implemented format supports ZIP 233.
    pub fn has_zip233(&self, _consensus_branch_id: BranchId) -> bool {
        false
    }

    /// Suggests the transaction version that should be used in the given Zcash epoch.
    pub fn suggested_for_branch(consensus_branch_id: BranchId) -> Self {
        match consensus_branch_id {
            BranchId::Sprout => TxVersion::Sprout(2),
            BranchId::Overwinter => TxVersion::V3,
            BranchId::Sapling | BranchId::Blossom | BranchId::Heartwood | BranchId::Canopy => {
                TxVersion::V4
            }
            BranchId::Nu5 => TxVersion::V5,
            BranchId::Nu6 => TxVersion::V5,
            BranchId::Nu6_1 => TxVersion::V5,
            BranchId::Nu6_2 => TxVersion::V5,
            BranchId::Nu6_3 => TxVersion::V6,
            BranchId::Nu7 => TxVersion::V6,
            #[cfg(zcash_unstable = "nu8")]
            BranchId::Nu8 => TxVersion::V6,
            // NuTachyon follows NU8, so it also defaults to the oldest valid
            // format. V7 remains an explicit opt-in.
            #[cfg(all(zcash_unstable = "nutachyon", zcash_unstable = "nu8"))]
            BranchId::NuTachyon => TxVersion::V6,
            #[cfg(all(zcash_unstable = "nutachyon", not(zcash_unstable = "nu8")))]
            BranchId::NuTachyon => TxVersion::V6,
        }
    }

    /// Returns `true` if this transaction version is valid for us in the specified consensus
    /// branch, `false` otherwise.
    pub fn valid_in_branch(&self, consensus_branch_id: BranchId) -> bool {
        // Note: we intentionally use `match` expressions instead of the `matches!`
        // macro below because we want exhaustivity.
        match self {
            TxVersion::Sprout(_) => consensus_branch_id == Sprout,
            TxVersion::V3 => consensus_branch_id == Overwinter,
            TxVersion::V4 => match consensus_branch_id {
                Sprout | Overwinter => false,
                Sapling | Blossom | Heartwood | Canopy | Nu5 | Nu6 | Nu6_1 | Nu6_2 => true,
                Nu6_3 => true,
                Nu7 => false, // ZIP 2003
                #[cfg(zcash_unstable = "nu8")]
                Nu8 => false,
                #[cfg(zcash_unstable = "nutachyon")]
                NuTachyon => false,
            },
            TxVersion::V5 => match consensus_branch_id {
                Sprout | Overwinter | Sapling | Blossom | Heartwood | Canopy => false,
                Nu5 | Nu6 | Nu6_1 | Nu6_2 => true,
                Nu6_3 => true,
                Nu7 => true,
                #[cfg(zcash_unstable = "nu8")]
                Nu8 => true,
                #[cfg(zcash_unstable = "nutachyon")]
                NuTachyon => true,
            },
            TxVersion::V6 => match consensus_branch_id {
                Sprout | Overwinter | Sapling | Blossom | Heartwood | Canopy | Nu5 | Nu6
                | Nu6_1 | Nu6_2 => false,
                Nu6_3 => true, // Ironwood / NU6.3
                Nu7 => true,   // NU7 retains the existing v6 transaction format.
                #[cfg(zcash_unstable = "nu8")]
                Nu8 => true,
                #[cfg(zcash_unstable = "nutachyon")]
                NuTachyon => true,
            },
            // This experimental deployment places v7 at NU8 and retains it afterward.
            #[cfg(zcash_unstable = "nu8")]
            TxVersion::V7 => match consensus_branch_id {
                Sprout | Overwinter | Sapling | Blossom | Heartwood | Canopy | Nu5 | Nu6
                | Nu6_1 | Nu6_2 | Nu6_3 | Nu7 => false,
                Nu8 => true,
                #[cfg(zcash_unstable = "nutachyon")]
                NuTachyon => true,
            },
        }
    }
}

/// Authorization state for a bundle of transaction data.
///
/// Downstream implementations must enable both `sapling` and `orchard`.
/// Associated types depend on these features, which Cargo unifies across all
/// dependents; implementing this trait under a single protocol feature is not
/// supported.
pub trait Authorization {
    type TransparentAuth: transparent::Authorization;
    #[cfg(feature = "sapling")]
    type SaplingAuth: sapling::bundle::Authorization;
    #[cfg(feature = "orchard")]
    type OrchardAuth: orchard::bundle::Authorization;
}

/// [`Authorization`] marker type for fully-authorized transactions.
#[derive(Clone, Debug)]
pub struct Authorized;

impl Authorization for Authorized {
    type TransparentAuth = transparent::Authorized;
    #[cfg(feature = "sapling")]
    type SaplingAuth = sapling::bundle::Authorized;
    #[cfg(feature = "orchard")]
    type OrchardAuth = orchard::bundle::Authorized;
}

/// [`Authorization`] marker type for non-coinbase transactions without authorization data.
///
/// Currently this includes Sapling proofs because the types in this crate support v4
/// transactions, which commit to the Sapling proofs in the transaction digest.
pub struct Unauthorized;

#[cfg(all(feature = "circuits", feature = "sapling", feature = "orchard"))]
impl Authorization for Unauthorized {
    type TransparentAuth = ::transparent::builder::Unauthorized<Zatoshis>;
    #[cfg(feature = "sapling")]
    type SaplingAuth =
        sapling_builder::InProgress<sapling_builder::Proven, sapling_builder::Unsigned>;
    #[cfg(feature = "orchard")]
    type OrchardAuth =
        orchard::builder::InProgress<orchard::builder::Unproven, orchard::builder::Unauthorized>;
}

/// [`Authorization`] marker type for coinbase transactions without authorization data.
#[cfg(all(feature = "circuits", feature = "sapling", feature = "orchard"))]
struct Coinbase;

#[cfg(all(feature = "circuits", feature = "sapling", feature = "orchard"))]
impl Authorization for Coinbase {
    type TransparentAuth = coinbase::Coinbase;
    #[cfg(feature = "sapling")]
    type SaplingAuth =
        sapling_builder::InProgress<sapling_builder::Proven, sapling_builder::Unsigned>;
    #[cfg(feature = "orchard")]
    type OrchardAuth =
        orchard::builder::InProgress<orchard::builder::Unproven, orchard::builder::Unauthorized>;
}

/// A Zcash transaction.
#[derive(Debug)]
pub struct Transaction {
    txid: TxId,
    data: TransactionData<Authorized>,
}

impl Deref for Transaction {
    type Target = TransactionData<Authorized>;

    fn deref(&self) -> &TransactionData<Authorized> {
        &self.data
    }
}

impl PartialEq for Transaction {
    fn eq(&self, other: &Transaction) -> bool {
        self.txid == other.txid
    }
}

/// The information contained in a Zcash transaction.
///
/// The internal structure reflects [ZIP 248](https://zips.z.cash/zip-0248):
/// - `value_pool_deltas`: Per-bundle value contributions to the transparent transaction value pool.
/// - Per-protocol bundle fields: transparent, Sprout (pre-v5), Sapling,
///   Orchard, Ironwood, and the v7 coinbase bundle.
///
/// Fully typed conversion requires every effecting and authorizing payload to
/// be one this implementation interprets; an opaque payload prevents it. Value
/// pool delta entries carry no payload, so entries for unknown bundle types or
/// variants remain in [`zip248::ValuePoolDeltas`] when their amounts are within
/// the typed monetary range. Use the byte layer ([`TransactionBytes`]) to parse
/// and re-serialize a transaction carrying opaque payloads.
///
/// # Feature requirements
///
/// Downstream callers of the `from_parts*` constructors, `map_bundles`,
/// `try_map_bundles`, or `map_authorization` must enable both `sapling` and
/// `orchard`. Their positional parameters depend on these features, which
/// Cargo may also enable through another dependent. Single-protocol features
/// support inspecting and digesting typed transactions, not these calls.
#[derive(Debug)]
pub struct TransactionData<A: Authorization> {
    version: TxVersion,
    consensus_branch_id: BranchId,
    lock_time: u32,
    expiry_height: BlockHeight,
    value_pool_deltas: zip248::ValuePoolDeltas,
    transparent_bundle: Option<transparent::Bundle<A::TransparentAuth, Zatoshis>>,
    sprout_bundle: Option<Box<sprout::Bundle>>,
    #[cfg(feature = "sapling")]
    sapling_bundle: Option<Box<sapling::Bundle<A::SaplingAuth, ZatBalance>>>,
    #[cfg(feature = "orchard")]
    orchard_bundle: Option<Box<orchard::bundle::Bundle<A::OrchardAuth, ZatBalance>>>,
    #[cfg(feature = "orchard")]
    ironwood_bundle: Option<Box<orchard::bundle::Bundle<A::OrchardAuth, ZatBalance>>>,
    coinbase_bundle: Option<Box<zip248::CoinbaseBundle>>,
}

impl Clone for TransactionData<Authorized> {
    fn clone(&self) -> Self {
        TransactionData {
            version: self.version,
            consensus_branch_id: self.consensus_branch_id,
            lock_time: self.lock_time,
            expiry_height: self.expiry_height,
            value_pool_deltas: self.value_pool_deltas.clone(),
            transparent_bundle: self.transparent_bundle.clone(),
            sprout_bundle: self.sprout_bundle.clone(),
            #[cfg(feature = "sapling")]
            sapling_bundle: self.sapling_bundle.clone(),
            #[cfg(feature = "orchard")]
            orchard_bundle: self.orchard_bundle.clone(),
            #[cfg(feature = "orchard")]
            ironwood_bundle: self.ironwood_bundle.clone(),
            coinbase_bundle: self.coinbase_bundle.clone(),
        }
    }
}

impl Clone for Transaction {
    fn clone(&self) -> Self {
        // SAFETY: We're reconstructing the Transaction from its data.
        // The txid is deterministic from the data, so cloning data and
        // re-computing txid would be equivalent.
        Transaction {
            txid: self.txid,
            data: self.data.clone(),
        }
    }
}

impl<A: Authorization> TransactionData<A> {
    /// Returns an Orchard-protocol slot whose bundle has the wrong version for v7.
    #[cfg(all(feature = "orchard", zcash_unstable = "nu8"))]
    fn v7_bundle_version_mismatch(&self) -> Option<BundleType> {
        for (bundle_type, bundle, expected) in [
            (
                BundleType::ORCHARD,
                self.orchard_bundle.as_ref(),
                orchard::bundle::BundleVersion::orchard_v3(),
            ),
            (
                BundleType::IRONWOOD,
                self.ironwood_bundle.as_ref(),
                orchard::bundle::BundleVersion::ironwood_v3(),
            ),
        ] {
            if bundle.is_some_and(|b| b.bundle_version() != expected) {
                return Some(bundle_type);
            }
        }
        None
    }

    #[cfg(zcash_unstable = "nu8")]
    fn v7_shielded_balance_mismatch(&self) -> Option<(BundleType, ZatBalance, ZatBalance)> {
        let balances: &[(BundleType, Option<ZatBalance>)] = &[
            #[cfg(feature = "sapling")]
            (
                BundleType::SAPLING,
                self.sapling_bundle.as_ref().map(|b| *b.value_balance()),
            ),
            #[cfg(feature = "orchard")]
            (
                BundleType::ORCHARD,
                self.orchard_bundle.as_ref().map(|b| *b.value_balance()),
            ),
            #[cfg(feature = "orchard")]
            (
                BundleType::IRONWOOD,
                self.ironwood_bundle.as_ref().map(|b| *b.value_balance()),
            ),
        ];
        balances.iter().find_map(|&(bundle_type, balance)| {
            let balance = balance?;
            let delta = self
                .value_pool_deltas
                .zec_value(bundle_type)
                .unwrap_or(ZatBalance::zero());
            (balance != delta).then_some((bundle_type, balance, delta))
        })
    }

    #[cfg(zcash_unstable = "nu8")]
    fn empty_v7_effect_bundle(&self) -> Option<BundleType> {
        if self
            .transparent_bundle
            .as_ref()
            .is_some_and(|b| b.vin.is_empty() && b.vout.is_empty())
        {
            return Some(BundleType::TRANSPARENT);
        }
        #[cfg(feature = "sapling")]
        if self
            .sapling_bundle
            .as_ref()
            .is_some_and(|b| b.shielded_spends().is_empty() && b.shielded_outputs().is_empty())
        {
            return Some(BundleType::SAPLING);
        }
        #[cfg(feature = "orchard")]
        for (bundle_type, bundle) in [
            (BundleType::ORCHARD, self.orchard_bundle.as_ref()),
            (BundleType::IRONWOOD, self.ironwood_bundle.as_ref()),
        ] {
            if bundle.is_some_and(|b| b.actions().is_empty()) {
                return Some(bundle_type);
            }
        }
        None
    }

    /// Derives the shielded value pool deltas from the bundles' value
    /// balances.
    fn set_shielded_value_pool_deltas(
        value_pool_deltas: &mut zip248::ValuePoolDeltas,
        #[cfg(feature = "sapling")] sapling_bundle: Option<
            &sapling::Bundle<A::SaplingAuth, ZatBalance>,
        >,
        #[cfg(feature = "orchard")] orchard_bundle: Option<
            &orchard::Bundle<A::OrchardAuth, ZatBalance>,
        >,
    ) {
        #[cfg(not(any(feature = "sapling", feature = "orchard")))]
        let _ = value_pool_deltas;
        #[cfg(feature = "sapling")]
        if let Some(b) = sapling_bundle {
            value_pool_deltas
                .set_sapling(*b.value_balance())
                .expect("fresh value pool delta map");
        }
        #[cfg(feature = "orchard")]
        if let Some(b) = orchard_bundle {
            value_pool_deltas
                .set_orchard(*b.value_balance())
                .expect("fresh value pool delta map");
        }
    }

    /// Constructs a `TransactionData` from its constituent parts.
    ///
    /// Callers must enable both `sapling` and `orchard`; Cargo feature unification
    /// can otherwise change this constructor's positional argument list.
    #[allow(clippy::too_many_arguments)]
    pub fn from_parts(
        version: TxVersion,
        consensus_branch_id: BranchId,
        lock_time: u32,
        expiry_height: BlockHeight,
        transparent_bundle: Option<transparent::Bundle<A::TransparentAuth, Zatoshis>>,
        sprout_bundle: Option<sprout::Bundle>,
        #[cfg(feature = "sapling")] sapling_bundle: Option<
            sapling::Bundle<A::SaplingAuth, ZatBalance>,
        >,
        #[cfg(feature = "orchard")] orchard_bundle: Option<
            orchard::Bundle<A::OrchardAuth, ZatBalance>,
        >,
    ) -> Self {
        Self::from_parts_inner(
            version,
            consensus_branch_id,
            lock_time,
            expiry_height,
            Zatoshis::ZERO,
            transparent_bundle,
            sprout_bundle,
            #[cfg(feature = "sapling")]
            sapling_bundle,
            #[cfg(feature = "orchard")]
            orchard_bundle,
        )
    }

    /// Constructs a `TransactionData` containing a ZIP 233 amount from its constituent parts.
    ///
    /// Callers must enable both `sapling` and `orchard`; see [`Self::from_parts`].
    ///
    /// The amount is carried as a ZIP 248 value pool delta. No implemented format
    /// supports a nonzero amount; [`Self::freeze`] rejects it when this data is
    /// authorized. Zero preserves the ordinary transaction format.
    #[cfg(all(feature = "zip-233", zcash_unstable = "zip233"))]
    #[allow(clippy::too_many_arguments)]
    pub fn from_parts_with_zip233(
        version: TxVersion,
        consensus_branch_id: BranchId,
        lock_time: u32,
        expiry_height: BlockHeight,
        zip233_amount: Zatoshis,
        transparent_bundle: Option<transparent::Bundle<A::TransparentAuth, Zatoshis>>,
        sprout_bundle: Option<sprout::Bundle>,
        #[cfg(feature = "sapling")] sapling_bundle: Option<
            sapling::Bundle<A::SaplingAuth, ZatBalance>,
        >,
        #[cfg(feature = "orchard")] orchard_bundle: Option<
            orchard::Bundle<A::OrchardAuth, ZatBalance>,
        >,
    ) -> Self {
        Self::from_parts_inner(
            version,
            consensus_branch_id,
            lock_time,
            expiry_height,
            zip233_amount,
            transparent_bundle,
            sprout_bundle,
            #[cfg(feature = "sapling")]
            sapling_bundle,
            #[cfg(feature = "orchard")]
            orchard_bundle,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn from_parts_inner(
        version: TxVersion,
        consensus_branch_id: BranchId,
        lock_time: u32,
        expiry_height: BlockHeight,
        zip233_amount: Zatoshis,
        transparent_bundle: Option<transparent::Bundle<A::TransparentAuth, Zatoshis>>,
        sprout_bundle: Option<sprout::Bundle>,
        #[cfg(feature = "sapling")] sapling_bundle: Option<
            sapling::Bundle<A::SaplingAuth, ZatBalance>,
        >,
        #[cfg(feature = "orchard")] orchard_bundle: Option<
            orchard::Bundle<A::OrchardAuth, ZatBalance>,
        >,
    ) -> Self {
        let mut value_pool_deltas = zip248::ValuePoolDeltas::empty();
        value_pool_deltas
            .set_zip233(zip233_amount)
            .expect("fresh value pool delta map");
        Self::set_shielded_value_pool_deltas(
            &mut value_pool_deltas,
            #[cfg(feature = "sapling")]
            sapling_bundle.as_ref(),
            #[cfg(feature = "orchard")]
            orchard_bundle.as_ref(),
        );

        Self::from_parts_with_value_pool_deltas(
            version,
            consensus_branch_id,
            lock_time,
            expiry_height,
            value_pool_deltas,
            transparent_bundle,
            sprout_bundle,
            #[cfg(feature = "sapling")]
            sapling_bundle,
            #[cfg(feature = "orchard")]
            orchard_bundle,
            #[cfg(feature = "orchard")]
            None,
            None,
        )
    }

    /// Constructs a V6 [`TransactionData`] from its constituent parts,
    /// including the Ironwood bundle.
    ///
    /// Callers must enable both `sapling` and `orchard`; see [`Self::from_parts`].
    ///
    /// Both the Orchard and Ironwood bundle fields use [`orchard::Bundle`], but
    /// they are distinct V6 transaction fields with distinct bundle versions.
    /// The `orchard_bundle` argument must contain a bundle constructed for
    /// [`orchard::bundle::BundleVersion::orchard_v3`], while `ironwood_bundle`
    /// must contain a bundle constructed for
    /// [`orchard::bundle::BundleVersion::ironwood_v3`]. Supplying a bundle for
    /// the wrong field is invalid and can be rejected by later serialization or
    /// commitment construction because the bundle flags and domains are protocol
    /// specific.
    #[allow(clippy::too_many_arguments)]
    pub fn from_parts_v6(
        consensus_branch_id: BranchId,
        lock_time: u32,
        expiry_height: BlockHeight,
        transparent_bundle: Option<transparent::Bundle<A::TransparentAuth, Zatoshis>>,
        #[cfg(feature = "sapling")] sapling_bundle: Option<
            sapling::Bundle<A::SaplingAuth, ZatBalance>,
        >,
        #[cfg(feature = "orchard")] orchard_bundle: Option<
            orchard::Bundle<A::OrchardAuth, ZatBalance>,
        >,
        #[cfg(feature = "orchard")] ironwood_bundle: Option<
            orchard::Bundle<A::OrchardAuth, ZatBalance>,
        >,
    ) -> Self {
        Self::from_parts_v6_or_v7(
            TxVersion::V6,
            consensus_branch_id,
            lock_time,
            expiry_height,
            transparent_bundle,
            #[cfg(feature = "sapling")]
            sapling_bundle,
            #[cfg(feature = "orchard")]
            orchard_bundle,
            #[cfg(feature = "orchard")]
            ironwood_bundle,
        )
    }

    /// Constructs a V6 [`TransactionData`] containing a ZIP 233 amount.
    ///
    /// Callers must enable both `sapling` and `orchard`; see [`Self::from_parts`].
    ///
    /// V6 does not support ZIP 233. [`Self::freeze`] rejects nonzero amounts when
    /// this data is authorized; zero is equivalent to [`Self::from_parts_v6`].
    #[cfg(all(feature = "zip-233", zcash_unstable = "zip233"))]
    #[allow(clippy::too_many_arguments)]
    pub fn from_parts_v6_with_zip233(
        consensus_branch_id: BranchId,
        lock_time: u32,
        expiry_height: BlockHeight,
        zip233_amount: Zatoshis,
        transparent_bundle: Option<transparent::Bundle<A::TransparentAuth, Zatoshis>>,
        #[cfg(feature = "sapling")] sapling_bundle: Option<
            sapling::Bundle<A::SaplingAuth, ZatBalance>,
        >,
        #[cfg(feature = "orchard")] orchard_bundle: Option<
            orchard::Bundle<A::OrchardAuth, ZatBalance>,
        >,
        #[cfg(feature = "orchard")] ironwood_bundle: Option<
            orchard::Bundle<A::OrchardAuth, ZatBalance>,
        >,
    ) -> Self {
        Self::from_parts_v6_or_v7_inner(
            TxVersion::V6,
            consensus_branch_id,
            lock_time,
            expiry_height,
            zip233_amount,
            transparent_bundle,
            #[cfg(feature = "sapling")]
            sapling_bundle,
            #[cfg(feature = "orchard")]
            orchard_bundle,
            #[cfg(feature = "orchard")]
            ironwood_bundle,
        )
    }

    /// Constructs a V7 [`TransactionData`] from its per-protocol bundles.
    ///
    /// Callers must enable both `sapling` and `orchard`; see [`Self::from_parts`].
    #[cfg(zcash_unstable = "nu8")]
    #[allow(clippy::too_many_arguments)]
    pub fn from_parts_v7(
        consensus_branch_id: BranchId,
        lock_time: u32,
        expiry_height: BlockHeight,
        transparent_bundle: Option<transparent::Bundle<A::TransparentAuth, Zatoshis>>,
        #[cfg(feature = "sapling")] sapling_bundle: Option<
            sapling::Bundle<A::SaplingAuth, ZatBalance>,
        >,
        #[cfg(feature = "orchard")] orchard_bundle: Option<
            orchard::Bundle<A::OrchardAuth, ZatBalance>,
        >,
        #[cfg(feature = "orchard")] ironwood_bundle: Option<
            orchard::Bundle<A::OrchardAuth, ZatBalance>,
        >,
    ) -> Self {
        Self::from_parts_v6_or_v7(
            TxVersion::V7,
            consensus_branch_id,
            lock_time,
            expiry_height,
            transparent_bundle,
            #[cfg(feature = "sapling")]
            sapling_bundle,
            #[cfg(feature = "orchard")]
            orchard_bundle,
            #[cfg(feature = "orchard")]
            ironwood_bundle,
        )
    }

    /// Constructs a V7 [`TransactionData`] containing a ZIP 233 amount.
    ///
    /// Callers must enable both `sapling` and `orchard`; see [`Self::from_parts`].
    ///
    /// V7 does not support ZIP 233. Nonzero amounts are rejected by
    /// [`Self::freeze`] when this data is authorized.
    #[cfg(all(zcash_unstable = "nu8", feature = "zip-233", zcash_unstable = "zip233"))]
    #[allow(clippy::too_many_arguments)]
    pub fn from_parts_v7_with_zip233(
        consensus_branch_id: BranchId,
        lock_time: u32,
        expiry_height: BlockHeight,
        zip233_amount: Zatoshis,
        transparent_bundle: Option<transparent::Bundle<A::TransparentAuth, Zatoshis>>,
        #[cfg(feature = "sapling")] sapling_bundle: Option<
            sapling::Bundle<A::SaplingAuth, ZatBalance>,
        >,
        #[cfg(feature = "orchard")] orchard_bundle: Option<
            orchard::Bundle<A::OrchardAuth, ZatBalance>,
        >,
        #[cfg(feature = "orchard")] ironwood_bundle: Option<
            orchard::Bundle<A::OrchardAuth, ZatBalance>,
        >,
    ) -> Self {
        Self::from_parts_v6_or_v7_inner(
            TxVersion::V7,
            consensus_branch_id,
            lock_time,
            expiry_height,
            zip233_amount,
            transparent_bundle,
            #[cfg(feature = "sapling")]
            sapling_bundle,
            #[cfg(feature = "orchard")]
            orchard_bundle,
            #[cfg(feature = "orchard")]
            ironwood_bundle,
        )
    }

    /// Constructs a v7 [`TransactionData`] whose value pool deltas balance.
    ///
    /// Callers must enable both `sapling` and `orchard`; see [`Self::from_parts`].
    ///
    /// [ZIP 248] requires the sum of all value pool deltas to be zero. The
    /// shielded deltas come from the bundles' value balances, but the
    /// transparent pool's delta cannot be recovered from an authorized
    /// transparent bundle, which records no input values, so the caller
    /// supplies it; the fee delta is then whatever balances the transaction.
    ///
    /// Returns an error if the deltas overflow, or if they sum to a negative
    /// fee (which would create value).
    ///
    /// [ZIP 248]: https://zips.z.cash/zip-0248
    #[cfg(zcash_unstable = "nu8")]
    #[allow(clippy::too_many_arguments)]
    pub fn from_parts_v7_balanced(
        consensus_branch_id: BranchId,
        lock_time: u32,
        expiry_height: BlockHeight,
        transparent_value_balance: ZatBalance,
        transparent_bundle: Option<transparent::Bundle<A::TransparentAuth, Zatoshis>>,
        #[cfg(feature = "sapling")] sapling_bundle: Option<
            sapling::Bundle<A::SaplingAuth, ZatBalance>,
        >,
        #[cfg(feature = "orchard")] orchard_bundle: Option<
            orchard::Bundle<A::OrchardAuth, ZatBalance>,
        >,
        #[cfg(feature = "orchard")] ironwood_bundle: Option<
            orchard::Bundle<A::OrchardAuth, ZatBalance>,
        >,
    ) -> Result<Self, BalanceError> {
        let mut data = Self::from_parts_v6_or_v7_inner(
            TxVersion::V7,
            consensus_branch_id,
            lock_time,
            expiry_height,
            Zatoshis::ZERO,
            transparent_bundle,
            #[cfg(feature = "sapling")]
            sapling_bundle,
            #[cfg(feature = "orchard")]
            orchard_bundle,
            #[cfg(feature = "orchard")]
            ironwood_bundle,
        );
        data.value_pool_deltas
            .set_transparent(transparent_value_balance)
            .expect("fresh value pool delta map");

        let total = [
            data.value_pool_deltas.transparent_value(),
            data.value_pool_deltas.sapling_value(),
            data.value_pool_deltas.orchard_value(),
            data.value_pool_deltas.ironwood_value(),
            data.value_pool_deltas.coinbase_value(),
        ]
        .into_iter()
        .flatten()
        .sum::<Option<ZatBalance>>()
        .ok_or(BalanceError::Overflow)?;
        data.value_pool_deltas
            .set_fee(Zatoshis::try_from(total).map_err(|_| BalanceError::Underflow)?)
            .expect("fresh value pool delta map");

        Ok(data)
    }

    #[allow(clippy::too_many_arguments)]
    fn from_parts_v6_or_v7(
        version: TxVersion,
        consensus_branch_id: BranchId,
        lock_time: u32,
        expiry_height: BlockHeight,
        transparent_bundle: Option<transparent::Bundle<A::TransparentAuth, Zatoshis>>,
        #[cfg(feature = "sapling")] sapling_bundle: Option<
            sapling::Bundle<A::SaplingAuth, ZatBalance>,
        >,
        #[cfg(feature = "orchard")] orchard_bundle: Option<
            orchard::Bundle<A::OrchardAuth, ZatBalance>,
        >,
        #[cfg(feature = "orchard")] ironwood_bundle: Option<
            orchard::Bundle<A::OrchardAuth, ZatBalance>,
        >,
    ) -> Self {
        Self::from_parts_v6_or_v7_inner(
            version,
            consensus_branch_id,
            lock_time,
            expiry_height,
            Zatoshis::ZERO,
            transparent_bundle,
            #[cfg(feature = "sapling")]
            sapling_bundle,
            #[cfg(feature = "orchard")]
            orchard_bundle,
            #[cfg(feature = "orchard")]
            ironwood_bundle,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn from_parts_v6_or_v7_inner(
        version: TxVersion,
        consensus_branch_id: BranchId,
        lock_time: u32,
        expiry_height: BlockHeight,
        zip233_amount: Zatoshis,
        transparent_bundle: Option<transparent::Bundle<A::TransparentAuth, Zatoshis>>,
        #[cfg(feature = "sapling")] sapling_bundle: Option<
            sapling::Bundle<A::SaplingAuth, ZatBalance>,
        >,
        #[cfg(feature = "orchard")] orchard_bundle: Option<
            orchard::Bundle<A::OrchardAuth, ZatBalance>,
        >,
        #[cfg(feature = "orchard")] ironwood_bundle: Option<
            orchard::Bundle<A::OrchardAuth, ZatBalance>,
        >,
    ) -> Self {
        let mut value_pool_deltas = zip248::ValuePoolDeltas::empty();
        value_pool_deltas
            .set_zip233(zip233_amount)
            .expect("fresh value pool delta map");
        Self::set_shielded_value_pool_deltas(
            &mut value_pool_deltas,
            #[cfg(feature = "sapling")]
            sapling_bundle.as_ref(),
            #[cfg(feature = "orchard")]
            orchard_bundle.as_ref(),
        );
        #[cfg(feature = "orchard")]
        if let Some(b) = &ironwood_bundle {
            value_pool_deltas
                .set_ironwood(*b.value_balance())
                .expect("fresh value pool delta map");
        }

        Self::from_parts_with_value_pool_deltas(
            version,
            consensus_branch_id,
            lock_time,
            expiry_height,
            value_pool_deltas,
            transparent_bundle,
            None,
            #[cfg(feature = "sapling")]
            sapling_bundle,
            #[cfg(feature = "orchard")]
            orchard_bundle,
            #[cfg(feature = "orchard")]
            ironwood_bundle,
            None,
        )
    }

    /// Constructs a `TransactionData` from per-protocol bundles and an
    /// explicit [`ValuePoolDeltas`](zip248::ValuePoolDeltas) map.
    ///
    /// Callers must enable both `sapling` and `orchard`; see [`Self::from_parts`].
    ///
    /// This is the constructor for callers that need to preserve value pool
    /// deltas that cannot be derived from the bundles, such as the transparent
    /// pool's delta, the fee, or a coinbase bundle's contribution. The
    /// [`Self::from_parts`] and [`Self::from_parts_v6`] constructors derive the
    /// shielded deltas from the bundles' value balances.
    #[allow(clippy::too_many_arguments)]
    pub fn from_parts_with_value_pool_deltas(
        version: TxVersion,
        consensus_branch_id: BranchId,
        lock_time: u32,
        expiry_height: BlockHeight,
        value_pool_deltas: zip248::ValuePoolDeltas,
        transparent_bundle: Option<transparent::Bundle<A::TransparentAuth, Zatoshis>>,
        sprout_bundle: Option<sprout::Bundle>,
        #[cfg(feature = "sapling")] sapling_bundle: Option<
            sapling::Bundle<A::SaplingAuth, ZatBalance>,
        >,
        #[cfg(feature = "orchard")] orchard_bundle: Option<
            orchard::Bundle<A::OrchardAuth, ZatBalance>,
        >,
        #[cfg(feature = "orchard")] ironwood_bundle: Option<
            orchard::Bundle<A::OrchardAuth, ZatBalance>,
        >,
        coinbase_bundle: Option<zip248::CoinbaseBundle>,
    ) -> Self {
        TransactionData {
            version,
            consensus_branch_id,
            lock_time,
            expiry_height,
            value_pool_deltas,
            transparent_bundle,
            sprout_bundle: sprout_bundle.map(Box::new),
            #[cfg(feature = "sapling")]
            sapling_bundle: sapling_bundle.map(Box::new),
            #[cfg(feature = "orchard")]
            orchard_bundle: orchard_bundle.map(Box::new),
            #[cfg(feature = "orchard")]
            ironwood_bundle: ironwood_bundle.map(Box::new),
            coinbase_bundle: coinbase_bundle.map(Box::new),
        }
    }

    /// Returns the transaction version.
    pub fn version(&self) -> TxVersion {
        self.version
    }

    /// Returns the Zcash epoch that this transaction can be mined in.
    pub fn consensus_branch_id(&self) -> BranchId {
        self.consensus_branch_id
    }

    pub fn lock_time(&self) -> u32 {
        self.lock_time
    }

    pub fn expiry_height(&self) -> BlockHeight {
        self.expiry_height
    }

    pub fn transparent_bundle(&self) -> Option<&transparent::Bundle<A::TransparentAuth, Zatoshis>> {
        self.transparent_bundle.as_ref()
    }

    /// Returns the coinbase bundle, if any. A v7 transaction is a coinbase
    /// transaction if and only if it has one.
    /// [ZIP 248 §Coinbase Bundle](https://zips.z.cash/zip-0248#coinbase-bundle)
    pub fn coinbase_bundle(&self) -> Option<&zip248::CoinbaseBundle> {
        self.coinbase_bundle.as_deref()
    }

    pub fn sprout_bundle(&self) -> Option<&sprout::Bundle> {
        self.sprout_bundle.as_deref()
    }

    #[cfg(feature = "sapling")]
    pub fn sapling_bundle(&self) -> Option<&sapling::Bundle<A::SaplingAuth, ZatBalance>> {
        self.sapling_bundle.as_deref()
    }

    #[cfg(feature = "orchard")]
    pub fn orchard_bundle(&self) -> Option<&orchard::Bundle<A::OrchardAuth, ZatBalance>> {
        self.orchard_bundle.as_deref()
    }

    /// Returns the Ironwood bundle, if any.
    ///
    /// The Ironwood bundle acts on the *Ironwood pool* using the Orchard
    /// protocol, so it has the same type as the Orchard bundle.
    /// [ZIP 248 §Orchard Protocol Bundles](https://zips.z.cash/zip-0248#orchard-protocol-bundles)
    #[cfg(feature = "orchard")]
    pub fn ironwood_bundle(&self) -> Option<&orchard::Bundle<A::OrchardAuth, ZatBalance>> {
        self.ironwood_bundle.as_deref()
    }

    /// Returns the ZIP 248 value pool deltas.
    pub fn value_pool_deltas(&self) -> &zip248::ValuePoolDeltas {
        &self.value_pool_deltas
    }

    /// Removes and returns the Sapling bundle, if present.
    ///
    /// Lets the transaction builder move a bundle out to authorize it, rather
    /// than cloning one it is about to replace.
    #[cfg(feature = "circuits")]
    pub(crate) fn take_sapling(&mut self) -> Option<sapling::Bundle<A::SaplingAuth, ZatBalance>> {
        self.sapling_bundle.take().map(|bundle| *bundle)
    }

    /// Removes and returns the Orchard bundle, if present.
    #[cfg(feature = "circuits")]
    pub(crate) fn take_orchard(&mut self) -> Option<orchard::Bundle<A::OrchardAuth, ZatBalance>> {
        self.orchard_bundle.take().map(|bundle| *bundle)
    }

    /// Removes and returns the Ironwood bundle, if present.
    #[cfg(feature = "circuits")]
    pub(crate) fn take_ironwood(&mut self) -> Option<orchard::Bundle<A::OrchardAuth, ZatBalance>> {
        self.ironwood_bundle.take().map(|bundle| *bundle)
    }

    /// Returns the ZIP 233 NSM amount, defaulting to zero if absent.
    #[cfg(all(feature = "zip-233", zcash_unstable = "zip233"))]
    pub fn zip233_amount(&self) -> Zatoshis {
        self.value_pool_deltas
            .zip233_amount()
            .unwrap_or(Zatoshis::ZERO)
    }

    /// Returns the fee amount, if explicitly set (v7+).
    pub fn fee_amount(&self) -> Option<Zatoshis> {
        self.value_pool_deltas.fee()
    }

    /// Returns the total fees paid by the transaction, given a function that can be used to
    /// retrieve the value of previous transactions' transparent outputs that are being spent in
    /// this transaction.
    ///
    /// Returns `Ok(None)` when the fee cannot be determined: the transparent inputs of a
    /// pre-v7 transaction include one whose value the callback does not know, or the
    /// transaction is a v7 coinbase transaction, which collects fees rather than paying
    /// them.
    ///
    /// From v7 onward the fee is an explicit value pool delta, so the callback is not
    /// consulted and a missing entry reads as zero.
    ///
    /// # Errors
    ///
    /// Returns an error if pre-v7 balance arithmetic overflows or yields a negative fee,
    /// or if a non-coinbase v7 transaction has a positive fee delta. Errors from
    /// `get_prevout` are propagated.
    pub fn fee_paid<E, F>(&self, get_prevout: F) -> Result<Option<Zatoshis>, E>
    where
        E: From<BalanceError>,
        F: FnMut(&OutPoint) -> Result<Option<Zatoshis>, E>,
    {
        #[cfg(zcash_unstable = "nu8")]
        if self.version == TxVersion::V7 {
            // ZIP 2002: the fee is committed to explicitly, so it needs no
            // previous-output values. A coinbase transaction pays no fee.
            return if self.coinbase_bundle.is_some() {
                Ok(None)
            } else {
                let fee_delta = self
                    .value_pool_deltas
                    .zec_value(zip248::BundleType::FEE)
                    .unwrap_or(ZatBalance::zero());
                Zatoshis::try_from(-fee_delta).map(Some).map_err(E::from)
            };
        }

        let transparent_balance = self.transparent_bundle.as_ref().map_or_else(
            || Ok(Some(ZatBalance::zero())),
            |b| components::transparent::value_balance(b, get_prevout),
        )?;

        transparent_balance
            .map(|transparent_balance| {
                let value_balances = [
                    transparent_balance,
                    self.sprout_bundle.as_ref().map_or_else(
                        || Ok(ZatBalance::zero()),
                        |b| b.value_balance().ok_or(BalanceError::Overflow),
                    )?,
                    #[cfg(feature = "sapling")]
                    self.sapling_bundle
                        .as_ref()
                        .map_or_else(ZatBalance::zero, |b| *b.value_balance()),
                    #[cfg(feature = "orchard")]
                    self.orchard_bundle
                        .as_ref()
                        .map_or_else(ZatBalance::zero, |b| *b.value_balance()),
                    #[cfg(feature = "orchard")]
                    self.ironwood_bundle
                        .as_ref()
                        .map_or_else(ZatBalance::zero, |b| *b.value_balance()),
                    // A coinbase bundle carries the part of the block subsidy
                    // the transaction pays out, net of the lockbox deposit and
                    // the ZIP 235 NSM fee contribution, which funds its
                    // outputs. A coinbase collects fees, so its fee delta is
                    // positive and `fee_amount` (which negates) cannot be used;
                    // read the gross delta directly.
                    self.coinbase_bundle
                        .as_ref()
                        .map_or_else(ZatBalance::zero, |b| {
                            let gross_fee = self
                                .value_pool_deltas
                                .zec_value(zip248::BundleType::FEE)
                                .and_then(|delta| Zatoshis::try_from(delta).ok())
                                .unwrap_or(Zatoshis::ZERO);
                            b.value_pool_delta(gross_fee)
                        }),
                    #[cfg(all(feature = "zip-233", zcash_unstable = "zip233"))]
                    -ZatBalance::from(self.zip233_amount()),
                ];

                let overall_balance = value_balances
                    .iter()
                    .sum::<Option<_>>()
                    .ok_or(BalanceError::Overflow)?;

                Zatoshis::try_from(overall_balance).map_err(|_| BalanceError::Underflow)
            })
            .transpose()
            .map_err(E::from)
    }

    /// Computes this transaction's digests using the provided digest strategy.
    ///
    /// [`txid::TxIdDigester`] builds a complete digest tree for every version
    /// and is the strategy that [`Self::txid_digests`] uses; other digesters,
    /// such as `txid::BlockTxCommitmentDigester`, build digests of a subset of
    /// the transaction's data.
    ///
    /// V6 and later transactions include the Ironwood bundle digest as a separate
    /// Orchard-shaped digest with Ironwood personalization. Earlier transaction
    /// versions do not include Ironwood in their digest.
    pub fn digest<D: TransactionDigest<A>>(&self, digester: D) -> D::Digest {
        let version = self.version;
        let header_digest = digester.digest_header(
            version,
            self.consensus_branch_id,
            self.lock_time,
            self.expiry_height,
        );

        digester.combine(
            header_digest,
            digester.digest_transparent(self.version, self.transparent_bundle.as_ref()),
            #[cfg(feature = "sapling")]
            digester.digest_sapling(version, self.sapling_bundle.as_deref()),
            #[cfg(feature = "orchard")]
            digester.digest_orchard(version, self.orchard_bundle.as_deref()),
            #[cfg(feature = "orchard")]
            digester.digest_ironwood(version, self.ironwood_bundle.as_deref()),
            #[cfg(zcash_unstable = "nu8")]
            digester.digest_coinbase(version, self.coinbase_bundle.as_deref()),
            #[cfg(zcash_unstable = "nu8")]
            digester.digest_value_pool_deltas(version, &self.value_pool_deltas),
        )
    }

    /// Computes this transaction's txid digest tree under the rules of its
    /// version: [ZIP 248] for v7, [ZIP 244] (with the [ZIP 229] Ironwood
    /// extension for v6) otherwise.
    ///
    /// These are the digests that signature hashes must commit to. They are
    /// the same tree that [`txid::TxIdDigester`] produces, so for v7 they
    /// include the value pool delta and coinbase digests.
    ///
    /// [ZIP 229]: https://zips.z.cash/zip-0229
    /// [ZIP 244]: https://zips.z.cash/zip-0244
    /// [ZIP 248]: https://zips.z.cash/zip-0248
    pub fn txid_digests(&self) -> Zip244Digests<blake2b_simd::Hash> {
        self.digest(txid::TxIdDigester)
    }

    /// Changes the consensus branch ID stored in this transaction for pre-v5 transactions.
    ///
    /// This can be used to fix an incorrect value passed to [`Transaction::read`]. Just
    /// like that method, this method does nothing for v5+ transactions.
    #[cfg(all(feature = "sapling", feature = "orchard"))]
    pub(crate) fn fix_consensus_branch_id(mut self, consensus_branch_id: BranchId) -> Self {
        match self.version() {
            TxVersion::Sprout(_) | TxVersion::V3 | TxVersion::V4 => {
                self.consensus_branch_id = consensus_branch_id;
            }
            // All later tx versions directly commit to the consensus branch ID, so what
            // we parse is what we trust.
            _ => (),
        }
        self
    }

    /// Maps the bundles from one type to another.
    ///
    /// This shouldn't be necessary for most use cases; it is provided for handling the
    /// cross-FFI builder logic in `zcashd`.
    ///
    /// `f_orchard` is also applied to the Ironwood bundle because Ironwood is
    /// represented with the Orchard bundle type.
    /// Pre-v7 shielded deltas are derived again from the mapped bundles; v7 deltas
    /// are preserved and must remain consistent with the mapped bundles.
    pub fn map_bundles<B: Authorization>(
        self,
        f_transparent: impl FnOnce(
            Option<transparent::Bundle<A::TransparentAuth, Zatoshis>>,
        ) -> Option<transparent::Bundle<B::TransparentAuth, Zatoshis>>,
        #[cfg(feature = "sapling")] f_sapling: impl FnOnce(
            Option<sapling::Bundle<A::SaplingAuth, ZatBalance>>,
        ) -> Option<
            sapling::Bundle<B::SaplingAuth, ZatBalance>,
        >,
        #[cfg(feature = "orchard")] mut f_orchard: impl FnMut(
            Option<orchard::bundle::Bundle<A::OrchardAuth, ZatBalance>>,
        ) -> Option<
            orchard::bundle::Bundle<B::OrchardAuth, ZatBalance>,
        >,
    ) -> TransactionData<B> {
        let mut data = TransactionData {
            version: self.version,
            consensus_branch_id: self.consensus_branch_id,
            lock_time: self.lock_time,
            expiry_height: self.expiry_height,
            value_pool_deltas: self.value_pool_deltas,
            transparent_bundle: f_transparent(self.transparent_bundle),
            sprout_bundle: self.sprout_bundle,
            #[cfg(feature = "sapling")]
            sapling_bundle: f_sapling(self.sapling_bundle.map(|b| *b)).map(Box::new),
            #[cfg(feature = "orchard")]
            orchard_bundle: f_orchard(self.orchard_bundle.map(|b| *b)).map(Box::new),
            #[cfg(feature = "orchard")]
            ironwood_bundle: f_orchard(self.ironwood_bundle.map(|b| *b)).map(Box::new),
            coinbase_bundle: self.coinbase_bundle,
        };
        data.refresh_legacy_shielded_deltas();
        data
    }

    /// Maps the bundles from one type to another with fallible closures.
    ///
    /// This shouldn't be necessary for most use cases; it is provided for handling the
    /// transaction extraction logic in the `pczt` crate.
    ///
    /// `f_orchard` is also applied to the Ironwood bundle because Ironwood is
    /// represented with the Orchard bundle type.
    /// Pre-v7 shielded deltas are derived again from the mapped bundles; v7 deltas
    /// are preserved and must remain consistent with the mapped bundles.
    pub fn try_map_bundles<B: Authorization, E>(
        self,
        f_transparent: impl FnOnce(
            Option<transparent::Bundle<A::TransparentAuth, Zatoshis>>,
        ) -> Result<
            Option<transparent::Bundle<B::TransparentAuth, Zatoshis>>,
            E,
        >,
        #[cfg(feature = "sapling")] f_sapling: impl FnOnce(
            Option<sapling::Bundle<A::SaplingAuth, ZatBalance>>,
        ) -> Result<
            Option<sapling::Bundle<B::SaplingAuth, ZatBalance>>,
            E,
        >,
        #[cfg(feature = "orchard")] mut f_orchard: impl FnMut(
            Option<orchard::bundle::Bundle<A::OrchardAuth, ZatBalance>>,
        ) -> Result<
            Option<orchard::bundle::Bundle<B::OrchardAuth, ZatBalance>>,
            E,
        >,
    ) -> Result<TransactionData<B>, E> {
        let mut data = TransactionData {
            version: self.version,
            consensus_branch_id: self.consensus_branch_id,
            lock_time: self.lock_time,
            expiry_height: self.expiry_height,
            value_pool_deltas: self.value_pool_deltas,
            transparent_bundle: f_transparent(self.transparent_bundle)?,
            sprout_bundle: self.sprout_bundle,
            #[cfg(feature = "sapling")]
            sapling_bundle: f_sapling(self.sapling_bundle.map(|b| *b))?.map(Box::new),
            #[cfg(feature = "orchard")]
            orchard_bundle: f_orchard(self.orchard_bundle.map(|b| *b))?.map(Box::new),
            #[cfg(feature = "orchard")]
            ironwood_bundle: f_orchard(self.ironwood_bundle.map(|b| *b))?.map(Box::new),
            coinbase_bundle: self.coinbase_bundle,
        };
        data.refresh_legacy_shielded_deltas();
        Ok(data)
    }

    /// Replaces the bundle-derived entries without changing explicit v7 deltas.
    fn refresh_legacy_shielded_deltas(&mut self) {
        #[cfg(zcash_unstable = "nu8")]
        if self.version == TxVersion::V7 {
            return;
        }
        let balances: &[(BundleType, Option<ZatBalance>)] = &[
            #[cfg(feature = "sapling")]
            (
                BundleType::SAPLING,
                self.sapling_bundle.as_ref().map(|b| *b.value_balance()),
            ),
            #[cfg(feature = "orchard")]
            (
                BundleType::ORCHARD,
                self.orchard_bundle.as_ref().map(|b| *b.value_balance()),
            ),
            #[cfg(feature = "orchard")]
            (
                BundleType::IRONWOOD,
                self.ironwood_bundle.as_ref().map(|b| *b.value_balance()),
            ),
        ];
        for &(bundle_type, balance) in balances {
            let variant = self
                .value_pool_deltas
                .bundle_variant(bundle_type)
                .unwrap_or(BundleVariant::DEFAULT);
            self.value_pool_deltas
                .set_zec_value(
                    zip248::BundleId::new(bundle_type, variant),
                    balance.unwrap_or(ZatBalance::zero()),
                )
                .expect("known bundle types and the existing variant are valid map keys");
        }
    }

    pub fn map_authorization<B: Authorization>(
        self,
        f_transparent: impl transparent::MapAuth<A::TransparentAuth, B::TransparentAuth>,
        #[cfg(feature = "sapling")] mut f_sapling: impl sapling_serialization::MapAuth<
            A::SaplingAuth,
            B::SaplingAuth,
        >,
        #[cfg(feature = "orchard")] mut f_orchard: impl orchard_serialization::MapAuth<
            A::OrchardAuth,
            B::OrchardAuth,
        >,
    ) -> TransactionData<B> {
        #[cfg(feature = "sapling")]
        let mut map_sapling = |sb: Option<sapling::Bundle<A::SaplingAuth, ZatBalance>>| {
            sb.map(|b| {
                Box::new(b.map_authorization(
                    &mut f_sapling,
                    |f, p| f.map_spend_proof(p),
                    |f, p| f.map_output_proof(p),
                    |f, s| f.map_auth_sig(s),
                    |f, a| f.map_authorization(a),
                ))
            })
        };
        // Applied to the Orchard bundle and then to the Ironwood bundle: both
        // are Orchard protocol bundles.
        #[cfg(feature = "orchard")]
        let mut map_orchard = |ob: Option<orchard::Bundle<A::OrchardAuth, ZatBalance>>| {
            ob.map(|b| {
                Box::new(b.map_authorization(
                    &mut f_orchard,
                    |f, _, s| f.map_spend_auth(s),
                    |f, a| f.map_authorization(a),
                ))
            })
        };

        TransactionData {
            version: self.version,
            consensus_branch_id: self.consensus_branch_id,
            lock_time: self.lock_time,
            expiry_height: self.expiry_height,
            value_pool_deltas: self.value_pool_deltas,
            transparent_bundle: self
                .transparent_bundle
                .map(|b| b.map_authorization(f_transparent)),
            sprout_bundle: self.sprout_bundle,
            #[cfg(feature = "sapling")]
            sapling_bundle: map_sapling(self.sapling_bundle.map(|bundle| *bundle)),
            #[cfg(feature = "orchard")]
            orchard_bundle: map_orchard(self.orchard_bundle.map(|bundle| *bundle)),
            #[cfg(feature = "orchard")]
            ironwood_bundle: map_orchard(self.ironwood_bundle.map(|bundle| *bundle)),
            coinbase_bundle: self.coinbase_bundle,
        }
    }
}

#[cfg(feature = "sapling")]
impl<A: Authorization> TransactionData<A> {
    pub fn sapling_value_balance(&self) -> ZatBalance {
        self.sapling_bundle
            .as_ref()
            .map_or(ZatBalance::zero(), |b| *b.value_balance())
    }
}

impl TransactionData<Authorized> {
    /// Checks that the version-dependent fields this data carries can be
    /// represented by `body_version`.
    ///
    /// A coinbase bundle requires version 7. A value pool delta entry is only
    /// accepted for a pre-v7 format when it is the default variant of the
    /// Sapling, Orchard, or Ironwood bundle, that protocol is supported by
    /// `body_version`, the corresponding typed bundle is present, and the delta
    /// equals the bundle's value balance. Entries for transparent, fee,
    /// coinbase, ZIP 233, and unknown bundle types are rejected, as are
    /// non-default variants, absent bundles, and mismatched values. Absence of a
    /// derivable entry remains valid for pre-v7 formats. For version 7, each
    /// present shielded bundle's balance must equal its map entry, with an
    /// absent entry interpreted as zero.
    ///
    /// `body_version` is the format being written, which the `write_v*` methods
    /// select independently of the stored version header.
    ///
    /// # Errors
    ///
    /// Returns [`io::ErrorKind::InvalidInput`] if the data cannot be represented
    /// by `body_version`, or if it carries a value pool delta for a bundle type
    /// that no implemented consensus branch activates.
    fn validate_version_consistency(&self, body_version: TxVersion) -> io::Result<()> {
        let unsupported_bundle = self.sprout_bundle.is_some() && !body_version.has_sprout();
        #[cfg(feature = "sapling")]
        let unsupported_bundle =
            unsupported_bundle || (self.sapling_bundle.is_some() && !body_version.has_sapling());
        #[cfg(feature = "orchard")]
        let unsupported_bundle = unsupported_bundle
            || (self.orchard_bundle.is_some() && !body_version.has_orchard())
            || (self.ironwood_bundle.is_some() && !body_version.has_ironwood());
        if unsupported_bundle {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "a bundle is not supported by the transaction body version",
            ));
        }

        // Activation is separate from registration and, unlike the ZIP 233
        // construction feature, is always known: a delta left over from
        // parsing must be rejected whatever features are enabled.
        for (&bundle_type, &(_, value)) in self.value_pool_deltas.iter() {
            if !zip248::bundle_activated(bundle_type) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    alloc::format!(
                        "value pool delta for bundleType {} (value {}) is not activated by any implemented consensus branch",
                        bundle_type.to_u64(),
                        i64::from(value)
                    ),
                ));
            }
        }

        #[cfg(zcash_unstable = "nu8")]
        if body_version == TxVersion::V7 {
            bytes::validate_v7_branch_id(Some(self.consensus_branch_id.into()))?;
            if let Some((bundle_type, _, _)) = self.v7_shielded_balance_mismatch() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    alloc::format!(
                        "value pool delta for bundleType {} differs from its bundle's value balance",
                        bundle_type.to_u64()
                    ),
                ));
            }
            return Ok(());
        }

        if self.coinbase_bundle.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "a coinbase bundle requires the version 7 transaction format",
            ));
        }

        for (&bundle_type, &(bundle_variant, value)) in self.value_pool_deltas.iter() {
            if bundle_variant != BundleVariant::DEFAULT {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "a legacy transaction format only supports the default bundle variant",
                ));
            }
            let supported = match bundle_type {
                BundleType::SAPLING => body_version.has_sapling(),
                BundleType::ORCHARD => body_version.has_orchard(),
                BundleType::IRONWOOD => body_version.has_ironwood(),
                _ => false,
            };
            if !supported {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    alloc::format!(
                        "a value pool delta for bundleType {} cannot be represented by a legacy transaction format",
                        bundle_type.to_u64()
                    ),
                ));
            }
            let expected: Option<ZatBalance> = match bundle_type {
                BundleType::SAPLING => {
                    #[cfg(feature = "sapling")]
                    {
                        self.sapling_bundle.as_ref().map(|b| *b.value_balance())
                    }
                    #[cfg(not(feature = "sapling"))]
                    {
                        None
                    }
                }
                BundleType::ORCHARD => {
                    #[cfg(feature = "orchard")]
                    {
                        self.orchard_bundle.as_ref().map(|b| *b.value_balance())
                    }
                    #[cfg(not(feature = "orchard"))]
                    {
                        None
                    }
                }
                BundleType::IRONWOOD => {
                    #[cfg(feature = "orchard")]
                    {
                        self.ironwood_bundle.as_ref().map(|b| *b.value_balance())
                    }
                    #[cfg(not(feature = "orchard"))]
                    {
                        None
                    }
                }
                _ => None,
            };
            match expected {
                Some(expected) if expected == value => {}
                Some(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        alloc::format!(
                            "value pool delta for bundleType {} differs from its bundle's value balance",
                            bundle_type.to_u64()
                        ),
                    ));
                }
                None => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        alloc::format!(
                            "value pool delta for bundleType {} has no corresponding bundle or its protocol support is disabled",
                            bundle_type.to_u64()
                        ),
                    ));
                }
            }
        }

        Ok(())
    }

    /// Builds the version 7 (ZIP 248) body of this transaction.
    ///
    /// ZIP 248 omits an empty effecting bundle, but the typed representation
    /// can hold one, so each present bundle must be non-empty. Bundle slots
    /// also fix their bundle version.
    ///
    /// # Errors
    ///
    /// Returns [`io::ErrorKind::InvalidInput`] for an empty effecting bundle, a
    /// bundle whose version does not match its slot, or a body the byte layer
    /// rejects.
    #[cfg(zcash_unstable = "nu8")]
    fn v7_body(&self) -> io::Result<V7TransactionBodyBytes> {
        #[cfg(feature = "orchard")]
        if let Some(bundle_type) = self.v7_bundle_version_mismatch() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                alloc::format!(
                    "bundleType {} has the wrong bundle version for its version 7 slot",
                    bundle_type.to_u64()
                ),
            ));
        }
        if let Some(bundle_type) = self.empty_v7_effect_bundle() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                alloc::format!(
                    "empty effecting bundleType {} must be omitted from a version 7 transaction",
                    bundle_type.to_u64()
                ),
            ));
        }
        let value_pool_deltas = self.value_pool_deltas.to_wire_entries();
        let mut effect_bundles = Vec::new();
        let mut auth_bundles = Vec::new();
        if let Some(bundle) = &self.transparent_bundle {
            let bundle = TransparentBundleBytes::from(bundle);
            let (effects, auth) = (bundle.effects().clone(), bundle.auth().cloned());
            effect_bundles.push(V7EffectBundleBytes::Transparent(effects));
            if let Some(auth) = auth {
                auth_bundles.push(V7AuthBundleBytes::Transparent(auth));
            }
        }
        if let Some(bundle) = self.coinbase_bundle.as_deref() {
            effect_bundles.push(V7EffectBundleBytes::Coinbase(CoinbaseBundleBytes::from(
                bundle,
            )));
        }
        #[cfg(feature = "sapling")]
        if let Some(bundle) = &self.sapling_bundle {
            effect_bundles.push(V7EffectBundleBytes::Sapling(
                V7SaplingBundleBytes::from_bundle(bundle),
            ));
            auth_bundles.push(V7AuthBundleBytes::Sapling(V7SaplingAuthBytes::from_bundle(
                bundle,
            )?));
        }
        #[cfg(feature = "orchard")]
        if let Some(bundle) = &self.orchard_bundle {
            let (effects, auth) = orchard_serialization::v7_bundle_to_bytes(bundle)?;
            effect_bundles.push(V7EffectBundleBytes::Orchard(effects));
            auth_bundles.push(V7AuthBundleBytes::Orchard(auth));
        }
        #[cfg(feature = "orchard")]
        if let Some(bundle) = &self.ironwood_bundle {
            let (effects, auth) = orchard_serialization::v7_bundle_to_bytes(bundle)?;
            effect_bundles.push(V7EffectBundleBytes::Ironwood(effects));
            auth_bundles.push(V7AuthBundleBytes::Ironwood(auth));
        }
        V7TransactionBodyBytes::from_parts(value_pool_deltas, effect_bundles, auth_bundles)
    }

    /// Constructs an authorized transaction and computes its transaction ID.
    ///
    /// # Errors
    ///
    /// Returns an error if the transaction cannot be serialized, or if its
    /// fields cannot be represented by its version: a nonzero ZIP 233 amount
    /// under a transaction version and consensus branch that do not support ZIP
    /// 233, a bundle unsupported by the body version, or a value pool delta
    /// entry that a pre-v7 format cannot derive from its bundles. For v7, each
    /// present shielded bundle's balance must equal its map entry (absent means
    /// zero), the consensus branch ID must be nonzero, and empty effecting
    /// bundles must be omitted.
    pub fn freeze(self) -> io::Result<Transaction> {
        self.validate_version_consistency(self.version)?;

        // A v7 body has additional structural invariants, such as one variant
        // per bundle type and the omission of empty effecting bundles. Build it
        // before the identifier is computed from the typed data, so that a
        // frozen transaction is always serializable as it stands.
        #[cfg(zcash_unstable = "nu8")]
        if self.version == TxVersion::V7 {
            self.v7_body()?;
        }

        Transaction::from_data(self)
    }
}

#[cfg(any(not(feature = "sapling"), not(feature = "orchard")))]
fn disabled_protocol(protocol: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        alloc::format!("{protocol} support is disabled; use TransactionBytes"),
    )
}

/// Borrows an effecting entry or removes it from an owned conversion source.
#[cfg(zcash_unstable = "nu8")]
fn v7_effect_for_conversion<'a>(
    body: &mut Cow<'a, V7TransactionBodyBytes>,
    bundle_type: BundleType,
) -> Option<Cow<'a, V7EffectBundleBytes>> {
    match body {
        Cow::Borrowed(body) => (*body).effect_bundle(bundle_type).map(Cow::Borrowed),
        Cow::Owned(body) => body.take_effect_bundle(bundle_type).map(Cow::Owned),
    }
}

/// Borrows an authorizing entry or removes it from an owned conversion source.
#[cfg(zcash_unstable = "nu8")]
fn v7_auth_for_conversion<'a>(
    body: &mut Cow<'a, V7TransactionBodyBytes>,
    bundle_type: BundleType,
) -> Option<Cow<'a, V7AuthBundleBytes>> {
    match body {
        Cow::Borrowed(body) => (*body).auth_bundle(bundle_type).map(Cow::Borrowed),
        Cow::Owned(body) => body.take_auth_bundle(bundle_type).map(Cow::Owned),
    }
}

impl Transaction {
    fn from_data(data: TransactionData<Authorized>) -> io::Result<Self> {
        match data.version {
            TxVersion::Sprout(_) | TxVersion::V3 | TxVersion::V4 => Self::from_data_v4(data),
            TxVersion::V5 => Ok(Self::from_data_v5(data)),
            TxVersion::V6 => Ok(Self::from_data_v6(data)),
            // v7 is the ZIP 248 extensible format, not v6's flat layout.
            #[cfg(zcash_unstable = "nu8")]
            TxVersion::V7 => Ok(Self::from_data_v7(data)),
        }
    }

    fn from_data_v4(data: TransactionData<Authorized>) -> io::Result<Self> {
        let mut tx = Transaction {
            txid: TxId::from_bytes([0; 32]),
            data,
        };
        let mut writer = HashWriter::default();
        tx.write(&mut writer)?;
        tx.txid = TxId::from_bytes(writer.into_hash().into());
        Ok(tx)
    }

    fn from_data_v5(data: TransactionData<Authorized>) -> Self {
        assert_eq!(data.version, TxVersion::V5);

        let txid = to_txid(
            data.version,
            data.consensus_branch_id,
            &data.digest(TxIdDigester),
        )
        .expect("is v5 tx");

        Transaction { txid, data }
    }

    fn from_data_v6(data: TransactionData<Authorized>) -> Self {
        assert_eq!(data.version, TxVersion::V6);

        let txid = to_txid(
            data.version,
            data.consensus_branch_id,
            &data.digest(TxIdDigester),
        )
        .expect("is v6 tx");

        Transaction { txid, data }
    }

    #[cfg(zcash_unstable = "nu8")]
    fn from_data_v7(data: TransactionData<Authorized>) -> Self {
        assert_eq!(data.version, TxVersion::V7);

        let txid = to_txid(
            data.version,
            data.consensus_branch_id,
            &data.digest(TxIdDigester),
        )
        .expect("is v7 tx");

        Transaction { txid, data }
    }

    pub fn into_data(self) -> TransactionData<Authorized> {
        self.data
    }

    pub fn txid(&self) -> TxId {
        self.txid
    }

    /// Reads a transaction from its wire encoding.
    ///
    /// This is the fully-typed compatibility path. It parses the wire bytes
    /// with [`TransactionBytes::read`], interprets each known bundle, and
    /// computes the transaction identifier. It does **not** perform the
    /// transaction-local consensus checks; use `Transaction::read_and_validate_v7`
    /// for a version 7 transaction that must be validated.
    ///
    /// For version 7, returns an error if the transaction contains an opaque
    /// effecting or authorizing payload whose bundle type or variant this
    /// implementation does not interpret. Value-pool-only entries for unknown
    /// identifiers are retained in the typed map when their amounts are within
    /// the monetary range, except for bundle types not activated by any
    /// implemented branch. Use [`TransactionBytes::read`] and supply the bundle
    /// digests to compute the identifier of a transaction carrying opaque
    /// payloads.
    pub fn read<R: Read>(reader: R, consensus_branch_id: BranchId) -> io::Result<Self> {
        let mut reader = HashReader::new(reader);
        let version = TxVersion::read(&mut reader)?;
        let (bytes, legacy_hash) = match version {
            TxVersion::Sprout(_) | TxVersion::V3 | TxVersion::V4 => {
                let bytes = TransactionBytes::read_after_version(&mut reader, version)?;
                (bytes, reader.into_hash().into())
            }
            _ => (
                TransactionBytes::read_after_version(reader.into_base_reader(), version)?,
                [0; 32],
            ),
        };
        Self::from_bytes(bytes, consensus_branch_id, legacy_hash)
    }

    /// Reads and fully validates a version 7 transaction from its wire
    /// encoding.
    ///
    /// Parses with [`TransactionBytes::read`] and applies
    /// [`TransactionBytes::validate_v7`]. That method documents the enforced
    /// [ZIP 248] rules and the block- and UTXO-context checks left to the consumer.
    ///
    /// # Errors
    ///
    /// Returns [`V7ValidationError::InvalidEncoding`] if the bytes are not a
    /// well-formed transaction, [`V7ValidationError::NotV7`] if the encoding is
    /// not version 7, and the other [`V7ValidationError`] variants for the
    /// rules listed above.
    ///
    /// [ZIP 248]: https://zips.z.cash/zip-0248
    #[cfg(all(feature = "sapling", feature = "orchard", zcash_unstable = "nu8"))]
    pub fn read_and_validate_v7<R: Read>(reader: R) -> Result<Self, V7ValidationError> {
        let bytes =
            TransactionBytes::read(reader).map_err(|error| V7ValidationError::InvalidEncoding {
                message: alloc::format!("{error}"),
            })?;
        bytes.validate_v7()
    }

    /// Interprets a byte-layer transaction as a fully-typed transaction.
    ///
    /// `legacy_hash` is the double-SHA256 of the wire bytes, used as the
    /// transaction identifier for versions 1 through 4. It is ignored for
    /// later versions, whose identifiers are computed from their digests.
    fn from_bytes(
        bytes: TransactionBytes,
        consensus_branch_id: BranchId,
        legacy_hash: [u8; 32],
    ) -> io::Result<Self> {
        let version = bytes.version();
        let lock_time = bytes.lock_time();
        let expiry_height = bytes.expiry_height();
        // Versions 5 and later encode `nConsensusBranchId` as a raw `uint32`;
        // interpreting it as a typed branch ID is a conversion-time check, not
        // a parsing requirement.
        let wire_branch_id = bytes.try_consensus_branch_id()?;

        match bytes.into_body() {
            TransactionBodyBytes::Legacy(body) => {
                let (transparent, sapling, sprout, binding_sig) = body.into_parts();
                let transparent_bundle = transparent.into_authorized()?;
                let sprout_bundle = sprout.map(SproutBundleBytes::into_bundle).transpose()?;
                #[cfg(feature = "sapling")]
                let sapling_bundle = match sapling {
                    Some(sapling) => sapling.to_authorized(binding_sig)?,
                    None => None,
                };
                #[cfg(not(feature = "sapling"))]
                {
                    let _ = binding_sig;
                    if sapling
                        .is_some_and(|bundle| !bundle.is_empty() || bundle.value_balance() != 0)
                    {
                        return Err(disabled_protocol("Sapling"));
                    }
                }

                Ok(Transaction {
                    txid: TxId::from_bytes(legacy_hash),
                    data: TransactionData::from_parts(
                        version,
                        consensus_branch_id,
                        lock_time,
                        expiry_height,
                        transparent_bundle,
                        sprout_bundle,
                        #[cfg(feature = "sapling")]
                        sapling_bundle,
                        #[cfg(feature = "orchard")]
                        None,
                    ),
                })
            }
            TransactionBodyBytes::V5(body) => {
                let consensus_branch_id = wire_branch_id.expect("v5 encodes a consensus branch ID");
                let (transparent, sapling, orchard) = body.into_parts();
                let transparent_bundle = transparent.into_authorized()?;
                #[cfg(feature = "sapling")]
                let sapling_bundle = sapling
                    .as_ref()
                    .map(SaplingBundleBytes::to_authorized)
                    .transpose()?;
                #[cfg(not(feature = "sapling"))]
                if sapling.is_some() {
                    return Err(disabled_protocol("Sapling"));
                }
                #[cfg(feature = "orchard")]
                let orchard_bundle = orchard
                    .map(|bundle| {
                        bundle.into_authorized(orchard_serialization::bundle_version_for_branch(
                            consensus_branch_id,
                            orchard::ValuePool::Orchard,
                        ))
                    })
                    .transpose()?;
                #[cfg(not(feature = "orchard"))]
                if orchard.is_some() {
                    return Err(disabled_protocol("Orchard"));
                }

                let data = TransactionData::from_parts(
                    version,
                    consensus_branch_id,
                    lock_time,
                    expiry_height,
                    transparent_bundle,
                    None,
                    #[cfg(feature = "sapling")]
                    sapling_bundle,
                    #[cfg(feature = "orchard")]
                    orchard_bundle,
                );
                Ok(Self::from_data_v5(data))
            }
            TransactionBodyBytes::V6(body) => {
                let consensus_branch_id = wire_branch_id.expect("v6 encodes a consensus branch ID");
                let (transparent, sapling, orchard, ironwood) = body.into_parts();
                let transparent_bundle = transparent.into_authorized()?;
                #[cfg(feature = "sapling")]
                let sapling_bundle = sapling
                    .as_ref()
                    .map(SaplingBundleBytes::to_authorized)
                    .transpose()?;
                #[cfg(not(feature = "sapling"))]
                if sapling.is_some() {
                    return Err(disabled_protocol("Sapling"));
                }
                #[cfg(feature = "orchard")]
                let orchard_bundle = orchard
                    .map(|bundle| {
                        bundle.into_authorized(orchard_serialization::bundle_version_for_branch(
                            consensus_branch_id,
                            orchard::ValuePool::Orchard,
                        ))
                    })
                    .transpose()?;
                #[cfg(feature = "orchard")]
                let ironwood_bundle = ironwood
                    .map(|bundle| {
                        bundle.into_authorized(orchard_serialization::bundle_version_for_branch(
                            consensus_branch_id,
                            orchard::ValuePool::Ironwood,
                        ))
                    })
                    .transpose()?;
                #[cfg(not(feature = "orchard"))]
                if orchard.is_some() || ironwood.is_some() {
                    return Err(disabled_protocol("Orchard or Ironwood"));
                }

                let data = TransactionData::from_parts_v6(
                    consensus_branch_id,
                    lock_time,
                    expiry_height,
                    transparent_bundle,
                    #[cfg(feature = "sapling")]
                    sapling_bundle,
                    #[cfg(feature = "orchard")]
                    orchard_bundle,
                    #[cfg(feature = "orchard")]
                    ironwood_bundle,
                );
                Ok(Self::from_data_v6(data))
            }
            #[cfg(zcash_unstable = "nu8")]
            TransactionBodyBytes::V7(body) => {
                let consensus_branch_id = wire_branch_id.expect("v7 encodes a consensus branch ID");
                Self::from_v7_body(
                    Cow::Owned(body),
                    consensus_branch_id,
                    lock_time,
                    expiry_height,
                )
            }
        }
    }

    /// Interprets a version 7 body as a fully-typed transaction.
    ///
    /// Every effecting and authorizing bundle must be one this implementation
    /// interprets, and none may carry data the typed representation cannot
    /// hold. Callers that accept such bundles must reject them first. Value
    /// pool delta entries are interpreted separately and may retain unknown
    /// identifiers when their amounts are within the typed monetary range.
    #[cfg(all(feature = "sapling", feature = "orchard", zcash_unstable = "nu8"))]
    fn from_v7_body_ref(
        body: &V7TransactionBodyBytes,
        consensus_branch_id: BranchId,
        lock_time: u32,
        expiry_height: BlockHeight,
    ) -> io::Result<Self> {
        Self::from_v7_body(
            Cow::Borrowed(body),
            consensus_branch_id,
            lock_time,
            expiry_height,
        )
    }

    /// Interprets a v7 body, moving owned scripts and proof buffers into typed bundles.
    #[cfg(zcash_unstable = "nu8")]
    fn from_v7_body(
        mut body: Cow<'_, V7TransactionBodyBytes>,
        consensus_branch_id: BranchId,
        lock_time: u32,
        expiry_height: BlockHeight,
    ) -> io::Result<Self> {
        let opaque_key = body
            .opaque_effect_bundles()
            .map(|bundle| bundle.id())
            .chain(body.opaque_auth_bundles().map(|bundle| bundle.id()))
            .next();
        if let Some(key) = opaque_key {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                alloc::format!(
                    "v7 transaction contains an opaque effecting or authorizing payload \
                     (bundleType {}, bundleVariant {}); \
                     parse it with TransactionBytes and supply its digests",
                    key.bundle_type().to_u64(),
                    key.bundle_variant().to_u64(),
                ),
            ));
        }
        #[cfg(not(feature = "sapling"))]
        if body.sapling().is_some() || body.sapling_auth().is_some() {
            return Err(disabled_protocol("Sapling"));
        }
        #[cfg(not(feature = "orchard"))]
        if body.orchard().is_some()
            || body.orchard_auth().is_some()
            || body.ironwood().is_some()
            || body.ironwood_auth().is_some()
        {
            return Err(disabled_protocol("Orchard or Ironwood"));
        }
        let value_pool_deltas = body.to_value_pool_deltas()?;
        let transparent_bundle = v7_effect_for_conversion(&mut body, BundleType::TRANSPARENT)
            .map(|effects| {
                let effects = match effects {
                    Cow::Borrowed(V7EffectBundleBytes::Transparent(effects)) => effects.clone(),
                    Cow::Owned(V7EffectBundleBytes::Transparent(effects)) => effects,
                    _ => unreachable!("opaque effects were rejected"),
                };
                let auth =
                    v7_auth_for_conversion(&mut body, BundleType::TRANSPARENT).map(
                        |auth| match auth {
                            Cow::Borrowed(V7AuthBundleBytes::Transparent(auth)) => auth.clone(),
                            Cow::Owned(V7AuthBundleBytes::Transparent(auth)) => auth,
                            _ => unreachable!("opaque authorizing data was rejected"),
                        },
                    );
                TransparentBundleBytes::from_parts(effects, auth)?.into_authorized()
            })
            .transpose()?
            .flatten();
        let coinbase_bundle = body
            .coinbase()
            .map(CoinbaseBundleBytes::to_coinbase_bundle)
            .transpose()?;
        #[cfg(feature = "sapling")]
        let sapling_bundle = v7_effect_for_conversion(&mut body, BundleType::SAPLING)
            .map(|effects| {
                let V7EffectBundleBytes::Sapling(effects) = effects.as_ref() else {
                    unreachable!("opaque effects were rejected");
                };
                let auth =
                    v7_auth_for_conversion(&mut body, BundleType::SAPLING).ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            "v7 Sapling effecting data has no authorizing data",
                        )
                    })?;
                let V7AuthBundleBytes::Sapling(auth) = auth.as_ref() else {
                    unreachable!("opaque authorizing data was rejected");
                };
                auth.to_authorized(
                    effects,
                    value_pool_deltas
                        .sapling_value()
                        .unwrap_or(ZatBalance::zero()),
                )
            })
            .transpose()?;
        #[cfg(feature = "orchard")]
        let orchard_bundle = v7_effect_for_conversion(&mut body, BundleType::ORCHARD)
            .map(|effects| {
                let V7EffectBundleBytes::Orchard(effects) = effects.as_ref() else {
                    unreachable!("opaque effects were rejected");
                };
                let auth =
                    v7_auth_for_conversion(&mut body, BundleType::ORCHARD).ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            "v7 Orchard effecting data has no authorizing data",
                        )
                    })?;
                let value_balance = value_pool_deltas
                    .orchard_value()
                    .unwrap_or(ZatBalance::zero());
                let version = orchard_serialization::bundle_version_for_branch(
                    consensus_branch_id,
                    orchard::ValuePool::Orchard,
                );
                match auth {
                    Cow::Borrowed(V7AuthBundleBytes::Orchard(auth)) => {
                        auth.to_authorized(effects, value_balance, version)
                    }
                    Cow::Owned(V7AuthBundleBytes::Orchard(auth)) => {
                        auth.into_authorized(effects, value_balance, version)
                    }
                    _ => unreachable!("opaque authorizing data was rejected"),
                }
            })
            .transpose()?;
        #[cfg(feature = "orchard")]
        let ironwood_bundle = v7_effect_for_conversion(&mut body, BundleType::IRONWOOD)
            .map(|effects| {
                let V7EffectBundleBytes::Ironwood(effects) = effects.as_ref() else {
                    unreachable!("opaque effects were rejected");
                };
                let auth =
                    v7_auth_for_conversion(&mut body, BundleType::IRONWOOD).ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            "v7 Ironwood effecting data has no authorizing data",
                        )
                    })?;
                let value_balance = value_pool_deltas
                    .ironwood_value()
                    .unwrap_or(ZatBalance::zero());
                let version = orchard_serialization::bundle_version_for_branch(
                    consensus_branch_id,
                    orchard::ValuePool::Ironwood,
                );
                match auth {
                    Cow::Borrowed(V7AuthBundleBytes::Ironwood(auth)) => {
                        auth.to_authorized(effects, value_balance, version)
                    }
                    Cow::Owned(V7AuthBundleBytes::Ironwood(auth)) => {
                        auth.into_authorized(effects, value_balance, version)
                    }
                    _ => unreachable!("opaque authorizing data was rejected"),
                }
            })
            .transpose()?;

        let data = TransactionData::from_parts_with_value_pool_deltas(
            TxVersion::V7,
            consensus_branch_id,
            lock_time,
            expiry_height,
            value_pool_deltas,
            transparent_bundle,
            None,
            #[cfg(feature = "sapling")]
            sapling_bundle,
            #[cfg(feature = "orchard")]
            orchard_bundle,
            #[cfg(feature = "orchard")]
            ironwood_bundle,
            coinbase_bundle,
        );
        data.validate_version_consistency(TxVersion::V7)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        Ok(Self::from_data_v7(data))
    }

    /// Converts this authorized transaction to its canonical wire representation.
    ///
    /// `body_version` selects the format of the body independently of the
    /// version header, as required by the version-specific `write_v*` methods.
    fn to_bytes(&self, body_version: TxVersion) -> io::Result<TransactionBytes> {
        self.validate_version_consistency(body_version)?;
        let transparent = || {
            self.transparent_bundle.as_ref().map_or_else(
                LegacyTransparentBundleBytes::default,
                LegacyTransparentBundleBytes::from,
            )
        };
        let consensus_branch_id = match body_version {
            TxVersion::Sprout(_) | TxVersion::V3 | TxVersion::V4 => None,
            TxVersion::V5 | TxVersion::V6 => Some(u32::from(self.consensus_branch_id)),
            #[cfg(zcash_unstable = "nu8")]
            TxVersion::V7 => Some(u32::from(self.consensus_branch_id)),
        };
        let body = match body_version {
            TxVersion::Sprout(_) | TxVersion::V3 | TxVersion::V4 => {
                #[cfg(feature = "sapling")]
                let sapling = match &self.sapling_bundle {
                    Some(bundle) if self.version.has_sapling() => {
                        Some(V4SaplingBundleBytes::from_bundle(bundle))
                    }
                    Some(_) => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "Sapling components may not be present if Sapling is not active.",
                        ));
                    }
                    None if self.version.has_sapling() => {
                        Some(V4SaplingBundleBytes::from_parts(0, vec![], vec![]))
                    }
                    None => None,
                };
                #[cfg(not(feature = "sapling"))]
                let sapling = if self.version.has_sapling() {
                    Some(V4SaplingBundleBytes::from_parts(0, vec![], vec![]))
                } else {
                    None
                };
                let sprout = self
                    .sprout_bundle
                    .as_deref()
                    .map(sprout::Bundle::to_bytes)
                    .transpose()?;
                #[cfg(feature = "sapling")]
                let sapling_binding_sig = self
                    .sapling_bundle
                    .as_ref()
                    .map(|bundle| <[u8; 64]>::from(bundle.authorization().binding_sig));
                #[cfg(not(feature = "sapling"))]
                let sapling_binding_sig = None;
                TransactionBodyBytes::Legacy(bytes::LegacyTransactionBodyBytes::from_parts(
                    transparent(),
                    sapling,
                    sprout,
                    sapling_binding_sig,
                )?)
            }
            TxVersion::V5 => {
                #[cfg(feature = "sapling")]
                let sapling = self
                    .sapling_bundle
                    .as_deref()
                    .map(SaplingBundleBytes::from_bundle);
                #[cfg(not(feature = "sapling"))]
                let sapling = None;
                #[cfg(feature = "orchard")]
                let orchard = self
                    .orchard_bundle
                    .as_deref()
                    .map(orchard_serialization::bundle_to_bytes)
                    .transpose()?;
                #[cfg(not(feature = "orchard"))]
                let orchard = None;
                TransactionBodyBytes::V5(bytes::V5TransactionBodyBytes::from_parts(
                    transparent(),
                    sapling,
                    orchard,
                ))
            }
            TxVersion::V6 => {
                #[cfg(feature = "orchard")]
                if let Some(bundle) = &self.orchard_bundle {
                    orchard_serialization::check_v6_bundle_version(bundle.bundle_version())?;
                }
                #[cfg(feature = "orchard")]
                if let Some(bundle) = &self.ironwood_bundle {
                    orchard_serialization::check_v6_bundle_version(bundle.bundle_version())?;
                }
                #[cfg(feature = "sapling")]
                let sapling = self
                    .sapling_bundle
                    .as_deref()
                    .map(SaplingBundleBytes::from_bundle);
                #[cfg(not(feature = "sapling"))]
                let sapling = None;
                #[cfg(feature = "orchard")]
                let orchard = self
                    .orchard_bundle
                    .as_deref()
                    .map(orchard_serialization::bundle_to_bytes)
                    .transpose()?;
                #[cfg(not(feature = "orchard"))]
                let orchard = None;
                #[cfg(feature = "orchard")]
                let ironwood = self
                    .ironwood_bundle
                    .as_deref()
                    .map(orchard_serialization::bundle_to_bytes)
                    .transpose()?;
                #[cfg(not(feature = "orchard"))]
                let ironwood = None;
                TransactionBodyBytes::V6(bytes::V6TransactionBodyBytes::from_parts(
                    transparent(),
                    sapling,
                    orchard,
                    ironwood,
                ))
            }
            #[cfg(zcash_unstable = "nu8")]
            TxVersion::V7 => TransactionBodyBytes::V7(self.v7_body()?),
        };

        Ok(TransactionBytes::from_parts_unchecked(
            self.version,
            consensus_branch_id,
            self.lock_time,
            self.expiry_height,
            body,
        ))
    }

    #[cfg(all(feature = "sapling", feature = "temporary-zcashd"))]
    pub fn temporary_zcashd_read_v5_sapling<R: Read>(
        reader: R,
    ) -> io::Result<Option<sapling::Bundle<sapling::bundle::Authorized, ZatBalance>>> {
        sapling_serialization::read_v5_bundle(reader)
    }

    pub fn write<W: Write>(&self, writer: W) -> io::Result<()> {
        match self.version {
            TxVersion::Sprout(_) | TxVersion::V3 | TxVersion::V4 => self.write_v4(writer),
            TxVersion::V5 => self.write_v5(writer),
            TxVersion::V6 => self.write_v6(writer),
            #[cfg(zcash_unstable = "nu8")]
            TxVersion::V7 => self.write_v7(writer),
        }
    }

    pub fn write_v4<W: Write>(&self, writer: W) -> io::Result<()> {
        #[cfg(feature = "orchard")]
        if self.orchard_bundle.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Orchard components cannot be present when serializing to the V4 transaction format.",
            ));
        }

        self.to_bytes(TxVersion::V4)?.write(writer)
    }

    pub fn write_transparent<W: Write>(&self, writer: W) -> io::Result<()> {
        let mut writer = writer;
        let (vin, vout) = self
            .transparent_bundle
            .as_ref()
            .map_or((&[][..], &[][..]), |bundle| {
                (&bundle.vin[..], &bundle.vout[..])
            });
        zcash_encoding::Vector::write(&mut writer, vin, |w, input| {
            components::transparent::write_txin(w, input)
        })?;
        zcash_encoding::Vector::write(&mut writer, vout, |w, output| {
            components::transparent::write_txout(w, output)
        })
    }

    pub fn write_v5<W: Write>(&self, writer: W) -> io::Result<()> {
        if self.sprout_bundle.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Sprout components cannot be present when serializing to the V5 transaction format.",
            ));
        }
        self.write_v5_or_v6(writer, TxVersion::V5)
    }

    pub fn write_v6<W: Write>(&self, writer: W) -> io::Result<()> {
        if self.sprout_bundle.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Sprout components cannot be present when serializing to V6 or later transaction formats.",
            ));
        }
        self.write_v5_or_v6(writer, TxVersion::V6)
    }

    /// Streams legacy contiguous bundles through the byte layer's field encoders.
    fn write_v5_or_v6<W: Write>(&self, mut writer: W, body_version: TxVersion) -> io::Result<()> {
        self.validate_version_consistency(body_version)?;
        #[cfg(feature = "orchard")]
        if body_version == TxVersion::V6 {
            for bundle in [
                self.orchard_bundle.as_deref(),
                self.ironwood_bundle.as_deref(),
            ]
            .into_iter()
            .flatten()
            {
                orchard_serialization::check_v6_bundle_version(bundle.bundle_version())?;
            }
        }
        self.write_v5_header(&mut writer)?;
        let sapling = |w: &mut W| {
            #[cfg(feature = "sapling")]
            {
                sapling_serialization::write_v5_bundle(w, self.sapling_bundle.as_deref())
            }
            #[cfg(not(feature = "sapling"))]
            bytes::SaplingBundleBytes::write_opt(w, None)
        };
        let orchard = |w: &mut W| {
            #[cfg(feature = "orchard")]
            {
                orchard_serialization::write_v5_bundle(self.orchard_bundle.as_deref(), w)
            }
            #[cfg(not(feature = "orchard"))]
            bytes::OrchardBundleBytes::write_opt(w, None)
        };
        if body_version == TxVersion::V5 {
            bytes::V5TransactionBodyBytes::write_components(
                &mut writer,
                |w| self.write_transparent(w),
                sapling,
                orchard,
            )
        } else {
            bytes::V6TransactionBodyBytes::write_components(
                &mut writer,
                |w| self.write_transparent(w),
                sapling,
                orchard,
                |w| {
                    #[cfg(feature = "orchard")]
                    {
                        orchard_serialization::write_v6_bundle(self.ironwood_bundle.as_deref(), w)
                    }
                    #[cfg(not(feature = "orchard"))]
                    bytes::OrchardBundleBytes::write_opt(w, None)
                },
            )
        }
    }

    /// Serializes this transaction in v7 (ZIP 248) wire format.
    ///
    /// [ZIP 248 §Transaction Format](https://zips.z.cash/zip-0248#transaction-format)
    #[cfg(zcash_unstable = "nu8")]
    pub fn write_v7<W: Write>(&self, writer: W) -> io::Result<()> {
        if self.sprout_bundle.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Sprout components cannot be present when serializing to the v7 transaction format.",
            ));
        }

        self.to_bytes(TxVersion::V7)?.write(writer)
    }

    pub fn write_v5_header<W: Write>(&self, mut writer: W) -> io::Result<()> {
        self.version.write(&mut writer)?;
        bytes::write_header_fragment(
            writer,
            Some(u32::from(self.consensus_branch_id)),
            self.lock_time,
            self.expiry_height,
        )
    }

    pub fn write_v6_header<W: Write>(&self, writer: W) -> io::Result<()> {
        self.write_v5_header(writer)
    }

    /// Writes the v7 (ZIP 248) common transaction header: header, nVersionGroupId,
    /// nConsensusBranchId, lock_time, nExpiryHeight (5 × u32). The ZIP 233 NSM
    /// amount is not included here; it lives in `mValuePoolDeltas` under
    /// `bundleType = 6`.
    #[cfg(zcash_unstable = "nu8")]
    pub fn write_v7_header<W: Write>(&self, writer: W) -> io::Result<()> {
        self.write_v5_header(writer)
    }

    #[cfg(all(feature = "sapling", feature = "temporary-zcashd"))]
    pub fn temporary_zcashd_write_v5_sapling<W: Write>(
        sapling_bundle: Option<&sapling::Bundle<sapling::bundle::Authorized, ZatBalance>>,
        writer: W,
    ) -> io::Result<()> {
        sapling_serialization::write_v5_bundle(writer, sapling_bundle)
    }

    #[cfg(feature = "sapling")]
    pub fn write_v5_sapling<W: Write>(&self, writer: W) -> io::Result<()> {
        sapling_serialization::write_v5_bundle(writer, self.sapling_bundle.as_deref())
    }

    /// Computes the authorizing-data commitment of this transaction.
    ///
    /// For version 7 this is the [ZIP 248] authorizing-data commitment; for
    /// earlier versions it is the [ZIP 244] or [ZIP 229] witness commitment.
    ///
    /// [ZIP 229]: https://zips.z.cash/zip-0229
    /// [ZIP 244]: https://zips.z.cash/zip-0244
    /// [ZIP 248]: https://zips.z.cash/zip-0248
    // TODO: should this be moved to `from_data` and stored?
    pub fn auth_commitment(&self) -> Blake2bHash {
        self.data.digest(BlockTxCommitmentDigester)
    }
}

/// Digests of the prevouts, sequence numbers, and outputs of a transparent bundle.
///
/// The personalization of each digest is that of the digest scheme that contains it:
/// [ZIP 143] in `Zip143Digests`, and [ZIP 244] in [`Zip244Digests`].
///
/// [ZIP 143]: https://zips.z.cash/zip-0143
/// [ZIP 244]: https://zips.z.cash/zip-0244
#[derive(Clone, Debug)]
pub struct TransparentDigests<A> {
    pub prevouts_digest: A,
    pub sequence_digest: A,
    pub outputs_digest: A,
}

/// Digests of the effecting data of a transaction, computed with the digest scheme that the
/// transaction's version uses for its signature hashes.
#[derive(Clone, Debug)]
pub enum TxDigests<A> {
    /// The digests that [ZIP 143] and [ZIP 243] signature hashes commit to, for
    /// transactions of version 4 and earlier.
    ///
    /// [ZIP 143]: https://zips.z.cash/zip-0143
    /// [ZIP 243]: https://zips.z.cash/zip-0243
    Zip143(Zip143Digests<A>),
    /// The digests that make up a [ZIP 244] transaction ID for v5 transactions, or
    /// (despite the `Zip244` name) a [ZIP 229] transaction ID for v6 transactions or a
    /// [ZIP 248] transaction ID for v7 transactions.
    ///
    /// [ZIP 244]: https://zips.z.cash/zip-0244
    /// [ZIP 229]: https://zips.z.cash/zip-0229#transactionidentifiersauthdigestsandsignaturedigests
    /// [ZIP 248]: https://zips.z.cash/zip-0248
    Zip244(Zip244Digests<A>),
}

/// The digests of a transaction that [ZIP 143] and [ZIP 243] signature hashes commit to.
///
/// [ZIP 143]: https://zips.z.cash/zip-0143
/// [ZIP 243]: https://zips.z.cash/zip-0243
#[derive(Clone, Debug)]
pub struct Zip143Digests<A> {
    /// The digests of the transparent inputs and outputs. A transaction without a
    /// transparent bundle has the digests of empty input and output lists.
    pub(crate) transparent: TransparentDigests<A>,
    /// The digest of the JoinSplits, or `None` if the transaction has none.
    pub(crate) joinsplits: Option<A>,
    /// The digest of the Sapling spends, or `None` if the transaction has none.
    pub(crate) sapling_spends: Option<A>,
    /// The digest of the Sapling outputs, or `None` if the transaction has none.
    pub(crate) sapling_outputs: Option<A>,
}

/// The digests that make up a [ZIP 244] or [ZIP 229] transaction ID, or (with the v7
/// fields populated) a [ZIP 248] transaction ID.
///
/// [ZIP 244]: https://zips.z.cash/zip-0244
/// [ZIP 229]: https://zips.z.cash/zip-0229#transactionidentifiersauthdigestsandsignaturedigests
/// [ZIP 248]: https://zips.z.cash/zip-0248
#[derive(Clone, Debug)]
pub struct Zip244Digests<A> {
    pub(crate) header_digest: A,
    pub(crate) transparent_digests: Option<TransparentDigests<A>>,
    pub(crate) sapling_digest: Option<A>,
    pub(crate) orchard_digest: Option<A>,
    /// Digest of the Ironwood bundle's effecting data. Present from v6
    /// (ZIP 229) onward; under v7 it is carried as a ZIP 248 bundle digest.
    pub(crate) ironwood_digest: Option<A>,
    /// v7 (ZIP 248): digest of the coinbase bundle's effecting data. Present
    /// only for coinbase transactions.
    #[cfg(zcash_unstable = "nu8")]
    pub(crate) coinbase_digest: Option<A>,
    /// v7 (ZIP 248): digest of the value pool deltas map.
    #[cfg(zcash_unstable = "nu8")]
    pub(crate) value_pool_deltas_digest: Option<A>,
    /// v7 (ZIP 248): per-bundle effect-data digests for unknown bundle types,
    /// in `(bundleType, bundleVariant)` order. These are folded into
    /// `effects_bundles_digest` alongside the transparent/sapling/orchard digests.
    #[cfg(zcash_unstable = "nu8")]
    pub(crate) unknown_effect_digests: alloc::vec::Vec<(zip248::BundleId, A)>,
}

impl<A> Zip244Digests<A> {
    /// Returns the digest of the transaction header.
    pub fn header_digest(&self) -> &A {
        &self.header_digest
    }

    /// Returns the digests of the transparent bundle, or `None` if the transaction has no
    /// transparent bundle.
    pub fn transparent_digests(&self) -> Option<&TransparentDigests<A>> {
        self.transparent_digests.as_ref()
    }

    /// Returns the digest of the Sapling bundle, or `None` if the transaction has no
    /// Sapling bundle.
    pub fn sapling_digest(&self) -> Option<&A> {
        self.sapling_digest.as_ref()
    }

    /// Returns the digest of the Orchard bundle, or `None` if the transaction has no
    /// Orchard bundle.
    pub fn orchard_digest(&self) -> Option<&A> {
        self.orchard_digest.as_ref()
    }

    /// Returns the digest of the Ironwood bundle of a version 6 or later
    /// transaction, or `None` if the transaction has no Ironwood bundle.
    ///
    /// When a version 6 transaction ID is derived from these digests, `None` is combined as
    /// the empty Ironwood bundle digest using the Ironwood bundle personalization. Version 7
    /// transaction IDs and authorizing-data commitments omit an absent Ironwood bundle.
    pub fn ironwood_digest(&self) -> Option<&A> {
        self.ironwood_digest.as_ref()
    }
}

/// A strategy for computing transaction digests.
///
/// Downstream implementations and direct callers of `combine` must enable
/// both `sapling` and `orchard`. Associated types, methods, and positional
/// parameters depend on these features, which Cargo unifies across all
/// dependents; single-protocol implementations are not supported.
pub trait TransactionDigest<A: Authorization> {
    type HeaderDigest;
    type TransparentDigest;
    #[cfg(feature = "sapling")]
    type SaplingDigest;
    #[cfg(feature = "orchard")]
    type OrchardDigest;
    /// The digest type produced for the Ironwood bundle in version 6 and later
    /// transactions.
    #[cfg(feature = "orchard")]
    type IronwoodDigest;
    /// The digest type produced for a version 7 coinbase bundle.
    #[cfg(zcash_unstable = "nu8")]
    type CoinbaseDigest;
    /// The digest type produced for a version 7 value pool delta map.
    #[cfg(zcash_unstable = "nu8")]
    type ValuePoolDeltasDigest;

    type Digest;

    /// Digests the canonical version, version-group ID, branch ID, lock time, and expiry
    /// height. ZIP 233 is not a header field in any implemented transaction format.
    fn digest_header(
        &self,
        version: TxVersion,
        consensus_branch_id: BranchId,
        lock_time: u32,
        expiry_height: BlockHeight,
    ) -> Self::HeaderDigest;

    fn digest_transparent(
        &self,
        version: TxVersion,
        transparent_bundle: Option<&transparent::Bundle<A::TransparentAuth, Zatoshis>>,
    ) -> Self::TransparentDigest;

    #[cfg(feature = "sapling")]
    fn digest_sapling(
        &self,
        version: TxVersion,
        sapling_bundle: Option<&sapling::Bundle<A::SaplingAuth, ZatBalance>>,
    ) -> Self::SaplingDigest;

    #[cfg(feature = "orchard")]
    fn digest_orchard(
        &self,
        version: TxVersion,
        orchard_bundle: Option<&orchard::Bundle<A::OrchardAuth, ZatBalance>>,
    ) -> Self::OrchardDigest;

    /// Computes the digest for the Ironwood bundle.
    ///
    /// Ironwood bundles are Orchard-shaped, but they use a distinct bundle personalization.
    /// Transaction ID digesters should return `None` when no Ironwood bundle is present;
    /// version 6 transaction ID combination substitutes the empty Ironwood bundle digest for
    /// `None`, while version 7 omits the entry. Transaction commitment digesters may instead
    /// return an empty authorizing data digest when no Ironwood bundle is present, and may use
    /// a different anchor commitment policy than transaction ID digesters.
    #[cfg(feature = "orchard")]
    fn digest_ironwood(
        &self,
        version: TxVersion,
        ironwood_bundle: Option<&orchard::Bundle<A::OrchardAuth, ZatBalance>>,
    ) -> Self::IronwoodDigest;

    /// Computes the digest for a version 7 coinbase bundle.
    ///
    /// Transaction ID digesters return the bundle's effecting data digest, or
    /// `None` when the transaction has no coinbase bundle. Digesters that do
    /// not build a version 7 tree may use a unit type.
    #[cfg(zcash_unstable = "nu8")]
    fn digest_coinbase(
        &self,
        version: TxVersion,
        coinbase_bundle: Option<&zip248::CoinbaseBundle>,
    ) -> Self::CoinbaseDigest;

    /// Computes the digest for a version 7 value pool delta map.
    ///
    /// Transaction ID digesters return the map's digest for version 7
    /// transactions and `None` otherwise. Digesters that do not build a
    /// version 7 tree may use a unit type.
    #[cfg(zcash_unstable = "nu8")]
    fn digest_value_pool_deltas(
        &self,
        version: TxVersion,
        value_pool_deltas: &zip248::ValuePoolDeltas,
    ) -> Self::ValuePoolDeltasDigest;

    #[allow(clippy::too_many_arguments)]
    fn combine(
        &self,
        header_digest: Self::HeaderDigest,
        transparent_digest: Self::TransparentDigest,
        #[cfg(feature = "sapling")] sapling_digest: Self::SaplingDigest,
        #[cfg(feature = "orchard")] orchard_digest: Self::OrchardDigest,
        #[cfg(feature = "orchard")] ironwood_digest: Self::IronwoodDigest,
        #[cfg(zcash_unstable = "nu8")] coinbase_digest: Self::CoinbaseDigest,
        #[cfg(zcash_unstable = "nu8")] value_pool_deltas_digest: Self::ValuePoolDeltasDigest,
    ) -> Self::Digest;
}

pub enum DigestError {
    NotSigned,
}

/// A V7 transaction map whose registry column is being checked.
#[cfg(all(feature = "sapling", feature = "orchard", zcash_unstable = "nu8"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum V7BundleMap {
    /// `mValuePoolDeltas`.
    ValuePoolDeltas,
    /// `mEffectBundles`.
    EffectBundles,
    /// `mAuthBundles`.
    AuthBundles,
}

#[cfg(all(feature = "sapling", feature = "orchard", zcash_unstable = "nu8"))]
impl core::fmt::Display for V7BundleMap {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::ValuePoolDeltas => f.write_str("mValuePoolDeltas"),
            Self::EffectBundles => f.write_str("mEffectBundles"),
            Self::AuthBundles => f.write_str("mAuthBundles"),
        }
    }
}

/// Errors that can be returned by [`TransactionBytes::validate_v7`] and
/// [`Transaction::read_and_validate_v7`].
///
/// The variants cover the byte-level registry and map rules, the conversion of
/// each known bundle to its typed representation, and the transaction-local
/// consensus rules in [`V7ConsensusError`].
///
/// [`TransactionBytes::validate_v7`]: crate::transaction::bytes::TransactionBytes::validate_v7
#[cfg(all(feature = "sapling", feature = "orchard", zcash_unstable = "nu8"))]
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum V7ValidationError {
    /// The wire encoding could not be parsed.
    InvalidEncoding {
        /// The parser's error message.
        message: String,
    },
    /// The transaction is not a version 7 transaction.
    NotV7,
    /// The encoded consensus branch ID is not a recognized [`BranchId`].
    UnrecognizedBranchId {
        /// The raw `nConsensusBranchId` value.
        branch_id: u32,
    },
    /// The transaction's consensus branch ID does not activate version 7.
    NotActivated {
        /// The branch ID encoded in the transaction.
        branch_id: BranchId,
    },
    /// `nExpiryHeight` is outside the range permitted by ZIP 248.
    InvalidExpiryHeight {
        /// The encoded expiry height.
        expiry_height: u32,
    },
    /// A bundle type is not registered for version 7.
    UnknownBundleType {
        /// The raw `bundleType`.
        bundle_type: u64,
    },
    /// A bundle variant is not registered for its bundle type.
    UnknownBundleVariant {
        /// The raw `bundleType`.
        bundle_type: u64,
        /// The raw `bundleVariant`.
        bundle_variant: u64,
    },
    /// A reserved bundle type appears in a map.
    ReservedBundleType {
        /// The raw `bundleType`.
        bundle_type: u64,
    },
    /// A bundle type appears in a map whose registry column is prohibited.
    ProhibitedBundleEntry {
        /// The raw `bundleType`.
        bundle_type: u64,
        /// The map containing the prohibited entry.
        map: V7BundleMap,
    },
    /// A registered bundle type is not activated under the transaction's
    /// consensus branch.
    BundleNotActivated {
        /// The raw `bundleType`.
        bundle_type: u64,
    },
    /// A value pool delta entry has no corresponding effecting bundle.
    MissingEffectBundle {
        /// The raw `bundleType`.
        bundle_type: u64,
    },
    /// A transparent effecting bundle with inputs has no authorizing data.
    MissingTransparentAuth {
        /// The number of transparent inputs.
        tx_in_count: usize,
    },
    /// A shielded effecting bundle has no authorizing data.
    MissingShieldedAuth {
        /// The raw `bundleType`.
        bundle_type: u64,
    },
    /// A bundle's payload could not be interpreted as its registered type.
    InvalidBundle {
        /// The conversion error message.
        message: String,
    },
    /// A transaction-local consensus rule was violated.
    Consensus(V7ConsensusError),
}

#[cfg(all(feature = "sapling", feature = "orchard", zcash_unstable = "nu8"))]
impl core::fmt::Display for V7ValidationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidEncoding { message } => {
                write!(f, "invalid v7 transaction encoding: {message}")
            }
            Self::NotV7 => f.write_str("transaction is not a version 7 transaction"),
            Self::UnrecognizedBranchId { branch_id } => {
                write!(f, "unrecognized consensus branch ID {branch_id:#010x}")
            }
            Self::NotActivated { branch_id } => {
                write!(f, "version 7 is not activated under {branch_id:?}")
            }
            Self::InvalidExpiryHeight { expiry_height } => write!(
                f,
                "nExpiryHeight {expiry_height} is outside the ZIP 248 range"
            ),
            Self::UnknownBundleType { bundle_type } => {
                write!(
                    f,
                    "bundleType {bundle_type} is not registered for version 7"
                )
            }
            Self::UnknownBundleVariant {
                bundle_type,
                bundle_variant,
            } => write!(
                f,
                "bundleVariant {bundle_variant} is not registered for bundleType {bundle_type}"
            ),
            Self::ReservedBundleType { bundle_type } => {
                write!(f, "bundleType {bundle_type} is reserved")
            }
            Self::ProhibitedBundleEntry { bundle_type, map } => {
                write!(f, "bundleType {bundle_type} must not appear in {map}")
            }
            Self::BundleNotActivated { bundle_type } => write!(
                f,
                "bundleType {bundle_type} is not activated under the transaction's consensus branch"
            ),
            Self::MissingEffectBundle { bundle_type } => write!(
                f,
                "value pool delta for bundleType {bundle_type} has no effecting bundle"
            ),
            Self::MissingTransparentAuth { tx_in_count } => write!(
                f,
                "transparent bundle with {tx_in_count} input(s) has no authorizing data"
            ),
            Self::MissingShieldedAuth { bundle_type } => write!(
                f,
                "shielded bundleType {bundle_type} has no authorizing data"
            ),
            Self::InvalidBundle { message } => {
                write!(f, "invalid v7 bundle: {message}")
            }
            Self::Consensus(error) => write!(f, "{error}"),
        }
    }
}

#[cfg(all(
    feature = "sapling",
    feature = "orchard",
    zcash_unstable = "nu8",
    feature = "std"
))]
impl std::error::Error for V7ValidationError {}

/// Errors that can be returned by [`TransactionData::check_v7_consensus_rules`].
///
/// Each variant corresponds to a transaction-local consensus rule from the
/// "Consensus Rules" section of [ZIP 248]. Rules that require block or UTXO
/// context are not checked by this method and must be enforced by the consumer
/// when validating a block or resolving transparent inputs.
///
/// [ZIP 248]: https://zips.z.cash/zip-0248
#[cfg(all(feature = "sapling", feature = "orchard", zcash_unstable = "nu8"))]
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum V7ConsensusError {
    /// The transaction is not a version 7 transaction.
    NotV7,
    /// The transaction's consensus branch ID does not activate version 7.
    NotActivated {
        /// The branch ID encoded in the transaction.
        branch_id: BranchId,
    },
    /// The transaction carries a Sprout bundle. ZIP 248 has no Sprout bundle
    /// type, so a v7 transaction cannot contain one.
    SproutBundlePresent,
    /// An Orchard-protocol bundle has the wrong version for its slot.
    ///
    /// The Orchard slot requires `orchard_v3`; Ironwood requires `ironwood_v3`.
    InvalidBundleVersion {
        /// The slot containing the incompatible bundle.
        bundle_type: BundleType,
    },
    /// A present effecting bundle contains no inputs, outputs, or actions.
    EmptyEffectBundle {
        /// The bundle that must be omitted.
        bundle_type: BundleType,
    },
    /// A shielded bundle's balance differs from its value pool delta.
    ShieldedValueBalanceMismatch {
        /// The shielded bundle.
        bundle_type: BundleType,
        /// The bundle's typed balance.
        balance: ZatBalance,
        /// The map entry, or zero when absent.
        delta: ZatBalance,
    },
    /// `nExpiryHeight` is outside the range permitted by ZIP 248.
    InvalidExpiryHeight {
        /// The encoded expiry height.
        expiry_height: u32,
    },
    /// A value pool delta entry names a bundle type that is not registered for
    /// version 7.
    UnregisteredBundleType {
        /// The raw `bundleType`.
        bundle_type: u64,
    },
    /// A value pool delta entry names a bundle variant that is not registered
    /// for its bundle type.
    UnregisteredBundleVariant {
        /// The raw `bundleType`.
        bundle_type: u64,
        /// The raw `bundleVariant`.
        bundle_variant: u64,
    },
    /// A registered bundle type is not activated under the transaction's
    /// consensus branch.
    BundleNotActivated {
        /// The raw `bundleType`.
        bundle_type: u64,
    },
    /// A value pool delta entry has no corresponding effecting bundle.
    MissingEffectBundle {
        /// The raw `bundleType`.
        bundle_type: u64,
    },
    /// A coinbase transaction has the `enableSpends` bit of `flagsOrchard`
    /// set in an Orchard protocol bundle. (Bundle-local rule.)
    CoinbaseEnableSpendsOrchardSet,
    /// An Orchard bundle has the `enableCrossAddress` bit of `flagsOrchard`
    /// set. (Bundle-local rule; the bit is unrestricted in an Ironwood
    /// bundle.)
    OrchardEnableCrossAddressSet,
    /// The Orchard pool balance is negative. (Shielded balance range rule:
    /// from NU6.3 onward, `vOrchardPoolBalance` must be nonnegative. V7 is
    /// only active from NU8, so the rule always applies. The Sapling and
    /// Ironwood pool balances are unrestricted.)
    OrchardPoolBalanceNegative { value: ZatBalance },
    /// A coinbase transaction spends a transparent output. (Bundle-local
    /// rule: the transparent bundle of a coinbase transaction must have
    /// `tx_in_count = 0`.)
    CoinbaseTransparentInputs { tx_in_count: usize },
    /// A coinbase transaction has Sapling spends. (Bundle-local rule:
    /// `nSpendsSapling` must be 0 for coinbase transactions.)
    CoinbaseSaplingSpends { spend_count: usize },
    /// The coinbase bundle's value pool delta does not equal
    /// `blockSubsidy - lockboxValue - NSMFeeContribution`, where the
    /// contribution is `floor(6 * TransactionFees / 10)` from the fee delta.
    /// (Cross-bundle rule.)
    CoinbaseValueDeltaMismatch {
        /// The expected delta, which may lie outside the `ZatBalance` range.
        expected: i64,
        /// The delta encoded in `mValuePoolDeltas`.
        actual: ZatBalance,
    },
    /// A coinbase transaction has a negative fee delta in
    /// `mValuePoolDeltas[FeeBundleId]`. The coinbase fee delta
    /// represents fees collected from other transactions in the block and
    /// must be nonnegative.
    CoinbaseFeeDeltaNegative { value: ZatBalance },
    /// A non-coinbase transaction has a positive fee delta in
    /// `mValuePoolDeltas[FeeBundleId]`. Fees paid are encoded as
    /// negative deltas (value removed from the transparent transaction
    /// value pool), so the fee delta must be nonpositive.
    NonCoinbaseFeeDeltaPositive { value: ZatBalance },
    /// The ZIP 233 NSM value pool delta is positive. The amount removed from
    /// circulation is encoded as a nonpositive delta.
    Zip233DeltaPositive { value: ZatBalance },
    /// The sum of all entries in `mValuePoolDeltas` must be zero for every
    /// transaction, coinbase included. The sum is accumulated in a wider signed
    /// type, so intermediate values outside the `ZatBalance` range do not cause
    /// a spurious failure; only the final sum is required to be zero. This
    /// variant is returned when that final sum is nonzero, indicating that
    /// value would be created or destroyed by the transaction.
    ValueImbalance {
        /// The final sum, which may lie outside the `ZatBalance` range.
        sum: i128,
    },
    /// The transaction satisfies none of the ZIP 248 input-side conditions.
    MissingInputSideCondition,
    /// The transaction satisfies none of the ZIP 248 output-side conditions.
    MissingOutputSideCondition,
}

#[cfg(all(feature = "sapling", feature = "orchard", zcash_unstable = "nu8"))]
impl core::fmt::Display for V7ConsensusError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            V7ConsensusError::NotV7 => f.write_str("transaction is not a version 7 transaction"),
            V7ConsensusError::NotActivated { branch_id } => {
                write!(f, "version 7 is not activated under {branch_id:?}")
            }
            V7ConsensusError::SproutBundlePresent => {
                write!(f, "version 7 transactions cannot contain a Sprout bundle")
            }
            V7ConsensusError::InvalidBundleVersion { bundle_type } => write!(
                f,
                "bundleType {} has the wrong bundle version for its version 7 slot",
                bundle_type.to_u64()
            ),
            V7ConsensusError::EmptyEffectBundle { bundle_type } => write!(
                f,
                "empty effecting bundleType {} must be omitted",
                bundle_type.to_u64()
            ),
            V7ConsensusError::ShieldedValueBalanceMismatch {
                bundle_type,
                balance,
                delta,
            } => write!(
                f,
                "bundleType {} balance {} differs from its value pool delta {}",
                bundle_type.to_u64(),
                i64::from(*balance),
                i64::from(*delta)
            ),
            V7ConsensusError::InvalidExpiryHeight { expiry_height } => write!(
                f,
                "nExpiryHeight {expiry_height} is outside the ZIP 248 range"
            ),
            V7ConsensusError::UnregisteredBundleType { bundle_type } => write!(
                f,
                "bundleType {bundle_type} is not registered for version 7"
            ),
            V7ConsensusError::UnregisteredBundleVariant {
                bundle_type,
                bundle_variant,
            } => write!(
                f,
                "bundleVariant {bundle_variant} is not registered for bundleType {bundle_type}"
            ),
            V7ConsensusError::MissingEffectBundle { bundle_type } => write!(
                f,
                "value pool delta for bundleType {bundle_type} has no effecting bundle"
            ),
            V7ConsensusError::BundleNotActivated { bundle_type } => write!(
                f,
                "bundleType {bundle_type} is not activated under the transaction's consensus branch"
            ),
            V7ConsensusError::CoinbaseEnableSpendsOrchardSet => write!(
                f,
                "coinbase transaction has enableSpends set in an Orchard protocol bundle"
            ),
            V7ConsensusError::OrchardEnableCrossAddressSet => {
                write!(f, "Orchard bundle has enableCrossAddress set")
            }
            V7ConsensusError::OrchardPoolBalanceNegative { value } => write!(
                f,
                "Orchard pool balance is negative ({})",
                i64::from(*value)
            ),
            V7ConsensusError::CoinbaseTransparentInputs { tx_in_count } => write!(
                f,
                "coinbase transaction spends {} transparent output(s)",
                tx_in_count
            ),
            V7ConsensusError::CoinbaseSaplingSpends { spend_count } => write!(
                f,
                "coinbase transaction has {} Sapling spend(s)",
                spend_count
            ),
            V7ConsensusError::CoinbaseValueDeltaMismatch { expected, actual } => write!(
                f,
                "coinbase bundle value pool delta is {}, but blockSubsidy - lockboxValue - NSMFeeContribution is {}",
                i64::from(*actual),
                expected
            ),
            V7ConsensusError::CoinbaseFeeDeltaNegative { value } => write!(
                f,
                "coinbase fee bundle value pool delta is negative ({})",
                i64::from(*value)
            ),
            V7ConsensusError::NonCoinbaseFeeDeltaPositive { value } => write!(
                f,
                "non-coinbase fee bundle value pool delta is positive ({}); fees are encoded as negative deltas",
                i64::from(*value)
            ),
            V7ConsensusError::Zip233DeltaPositive { value } => write!(
                f,
                "ZIP 233 NSM value pool delta is positive ({})",
                i64::from(*value)
            ),
            V7ConsensusError::ValueImbalance { sum } => {
                write!(f, "value pool deltas do not sum to zero: sum={sum}")
            }
            V7ConsensusError::MissingInputSideCondition => write!(
                f,
                "transaction satisfies none of the ZIP 248 input-side conditions"
            ),
            V7ConsensusError::MissingOutputSideCondition => write!(
                f,
                "transaction satisfies none of the ZIP 248 output-side conditions"
            ),
        }
    }
}

#[cfg(all(
    feature = "sapling",
    feature = "orchard",
    zcash_unstable = "nu8",
    feature = "std"
))]
impl std::error::Error for V7ConsensusError {}

#[cfg(all(feature = "sapling", feature = "orchard", zcash_unstable = "nu8"))]
impl<A: Authorization> TransactionData<A> {
    /// Checks the transaction-local consensus rules from
    /// [ZIP 248 §Consensus Rules](https://zips.z.cash/zip-0248#consensus-rules).
    ///
    /// Returns `Ok(())` if all transaction-local rules are satisfied,
    /// otherwise returns the first violation found.
    ///
    /// Whether the transaction is a coinbase transaction is determined by the
    /// presence of its coinbase bundle, as ZIP 248 defines it.
    ///
    /// Each present shielded bundle's balance must equal its value pool delta,
    /// with an absent entry interpreted as zero. Orchard and Ironwood slots require
    /// `orchard_v3` and `ironwood_v3` bundles, respectively. Block- and UTXO-context checks
    /// remain the consumer's responsibility; see [`TransactionBytes::validate_v7`].
    pub fn check_v7_consensus_rules(&self) -> Result<(), V7ConsensusError> {
        if self.version != TxVersion::V7 {
            return Err(V7ConsensusError::NotV7);
        }
        if !TxVersion::V7.valid_in_branch(self.consensus_branch_id) {
            return Err(V7ConsensusError::NotActivated {
                branch_id: self.consensus_branch_id,
            });
        }
        // ZIP 248 defines no Sprout bundle type, so serialization would drop it.
        if self.sprout_bundle.is_some() {
            return Err(V7ConsensusError::SproutBundlePresent);
        }
        if let Some(bundle_type) = self.v7_bundle_version_mismatch() {
            return Err(V7ConsensusError::InvalidBundleVersion { bundle_type });
        }
        if let Some(bundle_type) = self.empty_v7_effect_bundle() {
            return Err(V7ConsensusError::EmptyEffectBundle { bundle_type });
        }
        if let Some((bundle_type, balance, delta)) = self.v7_shielded_balance_mismatch() {
            return Err(V7ConsensusError::ShieldedValueBalanceMismatch {
                bundle_type,
                balance,
                delta,
            });
        }
        let expiry_height = u32::from(self.expiry_height);
        if expiry_height > zip248::MAX_EXPIRY_HEIGHT {
            return Err(V7ConsensusError::InvalidExpiryHeight { expiry_height });
        }

        let coinbase_bundle = self.coinbase_bundle.as_deref();
        let is_coinbase = coinbase_bundle.is_some();

        // [ZIP 248 §Bundle availability]: every value pool delta entry must
        // name a registered bundle type and variant. The byte validator also
        // checks the effect and auth maps, which a typed transaction cannot
        // represent for unregistered types.
        for (&bundle_type, (bundle_variant, _)) in self.value_pool_deltas.iter() {
            if !bundle_type.is_known() {
                return Err(V7ConsensusError::UnregisteredBundleType {
                    bundle_type: bundle_type.to_u64(),
                });
            }
            if !bundle_variant.is_known() {
                return Err(V7ConsensusError::UnregisteredBundleVariant {
                    bundle_type: bundle_type.to_u64(),
                    bundle_variant: bundle_variant.to_u64(),
                });
            }
            if !zip248::bundle_activated(bundle_type) {
                return Err(V7ConsensusError::BundleNotActivated {
                    bundle_type: bundle_type.to_u64(),
                });
            }
            if zip248::bundle_registry_row(bundle_type).is_none_or(|row| !row.value_pool_deltas) {
                return Err(V7ConsensusError::UnregisteredBundleType {
                    bundle_type: bundle_type.to_u64(),
                });
            }
        }

        // [ZIP 248 §Bundle-local rules]: each value pool delta entry for a
        // bundle type with effecting data must have a corresponding effecting
        // bundle.
        for (&bundle_type, _) in self.value_pool_deltas.iter() {
            let present = match bundle_type {
                zip248::BundleType::TRANSPARENT => self.transparent_bundle.is_some(),
                zip248::BundleType::COINBASE => self.coinbase_bundle.is_some(),
                zip248::BundleType::SAPLING => self.sapling_bundle.is_some(),
                zip248::BundleType::ORCHARD => self.orchard_bundle.is_some(),
                zip248::BundleType::IRONWOOD => self.ironwood_bundle.is_some(),
                _ => true,
            };
            if !present {
                return Err(V7ConsensusError::MissingEffectBundle {
                    bundle_type: bundle_type.to_u64(),
                });
            }
        }

        // [ZIP 248 §Shielded balance ranges]: from NU6.3 onward, the Orchard
        // pool balance must be nonnegative. V7 is only active from NU8, so the
        // rule always applies. The Sapling and Ironwood pool balances are
        // unrestricted.
        if let Some(orchard_value) = self.value_pool_deltas.orchard_value()
            && i64::from(orchard_value) < 0
        {
            return Err(V7ConsensusError::OrchardPoolBalanceNegative {
                value: orchard_value,
            });
        }

        if is_coinbase {
            // [ZIP 248 §Bundle-local rules]: a coinbase transaction must not
            // spend any transparent output. The coinbase bundle replaces the
            // unspendable input that carried the block height in earlier
            // transaction versions.
            if let Some(transparent_bundle) = self.transparent_bundle.as_ref()
                && !transparent_bundle.vin.is_empty()
            {
                return Err(V7ConsensusError::CoinbaseTransparentInputs {
                    tx_in_count: transparent_bundle.vin.len(),
                });
            }

            // [ZIP 248 §Bundle-local rules]: a coinbase transaction must not
            // spend shielded notes either.
            if let Some(sapling_bundle) = self.sapling_bundle.as_ref()
                && !sapling_bundle.shielded_spends().is_empty()
            {
                return Err(V7ConsensusError::CoinbaseSaplingSpends {
                    spend_count: sapling_bundle.shielded_spends().len(),
                });
            }

            // [ZIP 248 §Bundle-local rules]: `enableSpends` must be 0 in every
            // Orchard protocol bundle of a coinbase transaction. (Coinbase
            // outputs are unspendable until maturity, and enabling spends
            // would allow circumventing the maturity rule.)
            for orchard_protocol_bundle in
                [self.orchard_bundle.as_ref(), self.ironwood_bundle.as_ref()]
                    .into_iter()
                    .flatten()
            {
                if orchard_protocol_bundle.flags().spends_enabled() {
                    return Err(V7ConsensusError::CoinbaseEnableSpendsOrchardSet);
                }
            }
        }

        // [ZIP 248 §Bundle-local rules]: `enableCrossAddress` must be 0 in an
        // Orchard bundle. It is unrestricted in an Ironwood bundle. Typed
        // conversion already rejects an Orchard bundle carrying the bit, so
        // this check is a backstop for directly constructed transaction data.
        if let Some(orchard_bundle) = self.orchard_bundle.as_ref()
            && orchard_bundle.flags().cross_address_enabled()
        {
            return Err(V7ConsensusError::OrchardEnableCrossAddressSet);
        }

        // [ZIP 248 §Cross-bundle and chain-context rules]: fee delta sign.
        // Coinbase collects fees (delta >= 0), non-coinbase pays fees
        // (delta <= 0). A positive non-coinbase fee would create value from
        // nothing.
        let fee_delta = self
            .value_pool_deltas
            .zec_value(zip248::BundleType::FEE)
            .unwrap_or(ZatBalance::zero());
        if is_coinbase {
            if i64::from(fee_delta) < 0 {
                return Err(V7ConsensusError::CoinbaseFeeDeltaNegative { value: fee_delta });
            }
        } else if i64::from(fee_delta) > 0 {
            return Err(V7ConsensusError::NonCoinbaseFeeDeltaPositive { value: fee_delta });
        }

        // [ZIP 233]: the NSM amount is encoded as a nonpositive delta.
        if let Some(nsm_delta) = self
            .value_pool_deltas
            .zec_value(zip248::BundleType::ZIP233_NSM)
            && i64::from(nsm_delta) > 0
        {
            return Err(V7ConsensusError::Zip233DeltaPositive { value: nsm_delta });
        }

        // [ZIP 248 §Cross-bundle and chain-context rules]: the coinbase
        // bundle's value pool delta is the block subsidy less the lockbox
        // deposit and the ZIP 235 NSM fee contribution
        // `floor(6 * TransactionFees / 10)`. The subsidy and lockbox are in
        // the bundle's effecting data; the contribution is derived from the
        // fee delta, which was required to be nonnegative above. Whether the
        // fee delta equals the block's total fees needs block context and is
        // the consumer's responsibility.
        if let Some(coinbase_bundle) = coinbase_bundle {
            // The fee delta sign was checked above, so it is convertible.
            let transaction_fees = Zatoshis::try_from(fee_delta).unwrap_or(Zatoshis::ZERO);
            let expected = i64::from(coinbase_bundle.value_pool_delta(transaction_fees));
            let actual = self
                .value_pool_deltas
                .coinbase_value()
                .unwrap_or(ZatBalance::zero());
            if i64::from(actual) != expected {
                return Err(V7ConsensusError::CoinbaseValueDeltaMismatch { expected, actual });
            }
        }

        // [ZIP 248 §Cross-bundle and chain-context rules]: value conservation.
        // The sum of all VP deltas must be zero, i.e. no value is created or
        // destroyed. This holds for coinbase transactions too: the part of the
        // block subsidy that the transaction pays out enters the transparent
        // transaction value pool as the coinbase bundle's delta, and the fees
        // collected enter it as the fee bundle's delta.
        //
        // Sum ALL entries, including unknown bundle types. Individual entries
        // are bounded by `ZatBalance`; the accumulation is widened so that an
        // intermediate sum outside that range does not fail a transaction
        // whose mathematical total is zero.
        let mut sum: i128 = 0;
        for (_, &(_, value)) in self.value_pool_deltas.iter() {
            sum += i128::from(i64::from(value));
        }
        if sum != 0 {
            return Err(V7ConsensusError::ValueImbalance { sum });
        }

        // [ZIP 248 §Cross-bundle and chain-context rules]: input-side and
        // output-side conditions. Counts and flags are zero for an absent
        // bundle.
        let tx_in_count = self
            .transparent_bundle
            .as_ref()
            .map_or(0, |bundle| bundle.vin.len());
        let tx_out_count = self
            .transparent_bundle
            .as_ref()
            .map_or(0, |bundle| bundle.vout.len());
        let n_spends_sapling = self
            .sapling_bundle
            .as_ref()
            .map_or(0, |bundle| bundle.shielded_spends().len());
        let n_outputs_sapling = self
            .sapling_bundle
            .as_ref()
            .map_or(0, |bundle| bundle.shielded_outputs().len());
        let (n_actions_orchard, enable_spends_orchard, enable_outputs_orchard) = self
            .orchard_bundle
            .as_ref()
            .map_or((0, false, false), |bundle| {
                (
                    bundle.actions().len(),
                    bundle.flags().spends_enabled(),
                    bundle.flags().outputs_enabled(),
                )
            });
        let (n_actions_ironwood, enable_spends_ironwood, enable_outputs_ironwood) = self
            .ironwood_bundle
            .as_ref()
            .map_or((0, false, false), |bundle| {
                (
                    bundle.actions().len(),
                    bundle.flags().spends_enabled(),
                    bundle.flags().outputs_enabled(),
                )
            });
        let zip233_amount = self
            .value_pool_deltas
            .zip233_amount()
            .unwrap_or(Zatoshis::ZERO);

        let has_input_side = is_coinbase
            || tx_in_count > 0
            || n_spends_sapling > 0
            || (n_actions_orchard > 0 && enable_spends_orchard)
            || (n_actions_ironwood > 0 && enable_spends_ironwood);
        if !has_input_side {
            return Err(V7ConsensusError::MissingInputSideCondition);
        }

        let has_output_side = tx_out_count > 0
            || n_outputs_sapling > 0
            || (n_actions_orchard > 0 && enable_outputs_orchard)
            || (n_actions_ironwood > 0 && enable_outputs_ironwood)
            || zip233_amount > Zatoshis::ZERO;
        if !has_output_side {
            return Err(V7ConsensusError::MissingOutputSideCondition);
        }

        Ok(())
    }
}

#[cfg(all(test, not(feature = "sapling")))]
mod disabled_sapling_tests {
    use super::{
        BlockHeight, BranchId, Transaction, TransactionBodyBytes, TransactionBytes, TxVersion,
        V4SaplingBundleBytes, bytes::LegacyTransactionBodyBytes,
        bytes::LegacyTransparentBundleBytes,
    };
    use alloc::{vec, vec::Vec};
    use corez::io;
    use zcash_protocol::value::MAX_BALANCE;

    #[test]
    fn v4_empty_sapling_balance_without_protocol_support() {
        /// Smallest nonzero balance and distance past the monetary range.
        const NONZERO_BALANCE: i64 = 1;
        let out_of_range = MAX_BALANCE + NONZERO_BALANCE;
        for balance in [
            0,
            NONZERO_BALANCE,
            -NONZERO_BALANCE,
            out_of_range,
            -out_of_range,
        ] {
            let raw = TransactionBytes::from_parts(
                TxVersion::V4,
                None,
                0,
                BlockHeight::from_u32(0),
                TransactionBodyBytes::Legacy(
                    LegacyTransactionBodyBytes::from_parts(
                        LegacyTransparentBundleBytes::default(),
                        Some(V4SaplingBundleBytes::from_parts(balance, vec![], vec![])),
                        None,
                        None,
                    )
                    .unwrap(),
                ),
            )
            .unwrap();
            let mut wire = Vec::new();
            raw.write(&mut wire).unwrap();
            let typed = Transaction::read(&wire[..], BranchId::Sapling);
            if balance == 0 {
                let mut written = Vec::new();
                typed.unwrap().write(&mut written).unwrap();
                assert_eq!(written, wire);
            } else {
                assert_eq!(typed.unwrap_err().kind(), io::ErrorKind::InvalidData);
            }
        }
    }
}

#[cfg(all(
    any(test, feature = "test-dependencies"),
    feature = "sapling",
    feature = "orchard"
))]
pub mod testing {
    use proptest::prelude::*;

    use ::transparent::bundle::testing::{self as transparent};
    use zcash_protocol::{consensus::BranchId, value::testing::arb_zatoshis};

    use super::{
        Authorized, Transaction, TransactionData, TxId, TxVersion,
        components::{
            orchard::testing::{self as orchard},
            sapling::testing::{self as sapling},
        },
    };

    #[cfg(all(feature = "zip-233", zcash_unstable = "zip233"))]
    use zcash_protocol::value::{MAX_MONEY, Zatoshis};

    pub fn arb_txid() -> impl Strategy<Value = TxId> {
        prop::array::uniform32(any::<u8>()).prop_map(TxId::from_bytes)
    }

    pub fn arb_tx_version(branch_id: BranchId) -> impl Strategy<Value = TxVersion> {
        match branch_id {
            BranchId::Sprout => (1..=2u32).prop_map(TxVersion::Sprout).boxed(),
            BranchId::Overwinter => Just(TxVersion::V3).boxed(),
            BranchId::Sapling | BranchId::Blossom | BranchId::Heartwood | BranchId::Canopy => {
                Just(TxVersion::V4).boxed()
            }
            BranchId::Nu5 => Just(TxVersion::V5).boxed(),
            BranchId::Nu6 => Just(TxVersion::V5).boxed(),
            BranchId::Nu6_1 => Just(TxVersion::V5).boxed(),
            BranchId::Nu6_2 => Just(TxVersion::V5).boxed(),
            BranchId::Nu6_3 => Just(TxVersion::V6).boxed(),
            BranchId::Nu7 => Just(TxVersion::V6).boxed(),
            #[cfg(zcash_unstable = "nu8")]
            BranchId::Nu8 => Just(TxVersion::V7).boxed(),
            #[cfg(all(zcash_unstable = "nutachyon", zcash_unstable = "nu8"))]
            BranchId::NuTachyon => Just(TxVersion::V7).boxed(),
            #[cfg(all(zcash_unstable = "nutachyon", not(zcash_unstable = "nu8")))]
            BranchId::NuTachyon => Just(TxVersion::V6).boxed(),
        }
    }

    #[cfg(not(all(feature = "zip-233", zcash_unstable = "zip233")))]
    prop_compose! {
        pub fn arb_txdata(consensus_branch_id: BranchId)(
            version in arb_tx_version(consensus_branch_id)
        )(
            lock_time in any::<u32>(),
            expiry_height in any::<u32>(),
            transparent_bundle in transparent::arb_bundle(arb_zatoshis()),
            sapling_bundle in sapling::arb_bundle_for_version(version),
            orchard_bundle in orchard::arb_bundle_for_version(version),
            ironwood_bundle in orchard::arb_ironwood_bundle_for_version(version),
            version in Just(version),
        ) -> TransactionData<Authorized> {
            TransactionData::from_parts_v6_or_v7(
                version,
                consensus_branch_id,
                lock_time,
                expiry_height.into(),
                transparent_bundle,
                #[cfg(feature = "sapling")]
            sapling_bundle,
                #[cfg(feature = "orchard")]
            orchard_bundle,
                #[cfg(feature = "orchard")]
            ironwood_bundle,
            )
        }
    }

    #[cfg(all(feature = "zip-233", zcash_unstable = "zip233"))]
    prop_compose! {
        pub fn arb_txdata(consensus_branch_id: BranchId)(
            version in arb_tx_version(consensus_branch_id)
        )(
            lock_time in any::<u32>(),
            expiry_height in any::<u32>(),
            zip233_amount in 0..=MAX_MONEY,
            transparent_bundle in transparent::arb_bundle(arb_zatoshis()),
            sapling_bundle in sapling::arb_bundle_for_version(version),
            orchard_bundle in orchard::arb_bundle_for_version(version),
            ironwood_bundle in orchard::arb_ironwood_bundle_for_version(version),
            version in Just(version),
        ) -> TransactionData<Authorized> {
            TransactionData::from_parts_v6_or_v7_inner(
                version,
                consensus_branch_id,
                lock_time,
                expiry_height.into(),
                if version.has_zip233(consensus_branch_id) {
                    Zatoshis::from_u64(zip233_amount).unwrap()
                } else {
                    Zatoshis::ZERO
                },
                transparent_bundle,
                #[cfg(feature = "sapling")]
            sapling_bundle,
                #[cfg(feature = "orchard")]
            orchard_bundle,
                #[cfg(feature = "orchard")]
            ironwood_bundle,
            )
        }
    }

    prop_compose! {
        pub fn arb_tx(branch_id: BranchId)(tx_data in arb_txdata(branch_id)) -> Transaction {
            Transaction::from_data(tx_data).unwrap()
        }
    }
}
