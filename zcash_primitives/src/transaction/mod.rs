//! Structs and methods for handling Zcash transactions.
//!
//! The byte layer ([`bytes`]) is always available and does not require the
//! Sapling or Orchard protocol crates. The typed transaction types
//! (`Transaction`, `TransactionData`, the builder, and signature hashing)
//! require both the `sapling` and `orchard` features, because a typed
//! transaction interprets every bundle it can carry. A build with only one
//! shielded protocol feature can still parse all wire data as bytes and
//! convert the enabled protocol's bundles through the byte layer's
//! per-protocol conversions.
#[cfg(all(feature = "sapling", feature = "orchard"))]
pub mod builder;
pub mod bytes;
pub mod components;
pub mod fees;
#[cfg(all(feature = "sapling", feature = "orchard"))]
pub mod sighash;
#[cfg(all(feature = "sapling", feature = "orchard"))]
mod sighash_v4;
#[cfg(all(feature = "sapling", feature = "orchard"))]
mod sighash_v5;
#[cfg(all(feature = "sapling", feature = "orchard"))]
mod sighash_v6;
#[cfg(all(feature = "sapling", feature = "orchard", zcash_unstable = "nu8"))]
mod sighash_v7;

pub mod txid;
pub mod zip248;

#[cfg(all(
    any(test, feature = "test-dependencies"),
    feature = "sapling",
    feature = "orchard"
))]
pub mod tests;

use crate::encoding::{ReadBytesExt, WriteBytesExt};
use corez::io::{self, Read, Write};
use zcash_protocol::consensus::BranchId;
// `valid_in_branch` matches on every branch by bare name.
use zcash_protocol::consensus::BranchId::*;

#[cfg(all(feature = "sapling", feature = "orchard"))]
use zcash_protocol::consensus::BlockHeight;

#[cfg(all(feature = "sapling", feature = "orchard"))]
#[allow(unused_imports)]
use ::transparent::bundle::{self as transparent, OutPoint, TxIn, TxOut};

#[cfg(all(feature = "sapling", feature = "orchard"))]
use {
    ::transparent::util::sha256d::{HashReader, HashWriter},
    blake2b_simd::Hash as Blake2bHash,
    core::convert::TryFrom,
    core::ops::Deref,
    zcash_encoding::{CompactSize, Vector},
    zcash_protocol::value::{BalanceError, Zatoshis},
};

#[cfg(all(feature = "sapling", feature = "orchard", zcash_unstable = "nu8"))]
use alloc::{collections::BTreeMap, string::String, vec::Vec};

#[cfg(any(
    all(feature = "sapling", feature = "temporary-zcashd"),
    feature = "orchard"
))]
use zcash_protocol::value::ZatBalance;

#[cfg(all(feature = "sapling", feature = "orchard", zcash_unstable = "nu8"))]
use self::{
    bytes::{CoinbaseBundleBytes, V7TransactionBodyBytes},
    components::transparent::TransparentBundleBytes,
    zip248::{BundleType, BundleVariant},
};
#[cfg(all(feature = "sapling", feature = "orchard"))]
use self::{
    bytes::{SaplingBundleBytes, SproutBundleBytes, TransactionBodyBytes, TransactionBytes},
    components::{orchard as orchard_serialization, sapling as sapling_serialization, sprout},
    txid::{BlockTxCommitmentDigester, TxIdDigester, to_txid},
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
    /// Transaction version 7, introduced by the NU8 network upgrade.
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
            BranchId::Nu8 => TxVersion::V7,
            // NuTachyon follows NU8, so it keeps v7 whenever this build has it.
            #[cfg(all(zcash_unstable = "nutachyon", zcash_unstable = "nu8"))]
            BranchId::NuTachyon => TxVersion::V7,
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
            // v7 is deployed by NU8 and retained by the upgrades after it.
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
#[cfg(all(feature = "sapling", feature = "orchard"))]
pub trait Authorization {
    type TransparentAuth: transparent::Authorization;
    type SaplingAuth: sapling::bundle::Authorization;
    type OrchardAuth: orchard::bundle::Authorization;
}

/// [`Authorization`] marker type for fully-authorized transactions.
#[cfg(all(feature = "sapling", feature = "orchard"))]
#[derive(Clone, Debug)]
pub struct Authorized;

#[cfg(all(feature = "sapling", feature = "orchard"))]
impl Authorization for Authorized {
    type TransparentAuth = transparent::Authorized;
    type SaplingAuth = sapling::bundle::Authorized;
    type OrchardAuth = orchard::bundle::Authorized;
}

/// [`Authorization`] marker type for non-coinbase transactions without authorization data.
///
/// Currently this includes Sapling proofs because the types in this crate support v4
/// transactions, which commit to the Sapling proofs in the transaction digest.
#[cfg(all(feature = "sapling", feature = "orchard"))]
pub struct Unauthorized;

#[cfg(all(feature = "circuits", feature = "sapling", feature = "orchard"))]
impl Authorization for Unauthorized {
    type TransparentAuth = ::transparent::builder::Unauthorized;
    type SaplingAuth =
        sapling_builder::InProgress<sapling_builder::Proven, sapling_builder::Unsigned>;
    type OrchardAuth =
        orchard::builder::InProgress<orchard::builder::Unproven, orchard::builder::Unauthorized>;
}

/// [`Authorization`] marker type for coinbase transactions without authorization data.
#[cfg(all(feature = "circuits", feature = "sapling", feature = "orchard"))]
struct Coinbase;

#[cfg(all(feature = "circuits", feature = "sapling", feature = "orchard"))]
impl Authorization for Coinbase {
    type TransparentAuth = ::transparent::builder::Coinbase;
    type SaplingAuth =
        sapling_builder::InProgress<sapling_builder::Proven, sapling_builder::Unsigned>;
    type OrchardAuth =
        orchard::builder::InProgress<orchard::builder::Unproven, orchard::builder::Unauthorized>;
}

/// A Zcash transaction.
#[cfg(all(feature = "sapling", feature = "orchard"))]
#[derive(Debug)]
pub struct Transaction {
    txid: TxId,
    data: TransactionData<Authorized>,
}

#[cfg(all(feature = "sapling", feature = "orchard"))]
impl Deref for Transaction {
    type Target = TransactionData<Authorized>;

    fn deref(&self) -> &TransactionData<Authorized> {
        &self.data
    }
}

#[cfg(all(feature = "sapling", feature = "orchard"))]
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
/// A typed transaction contains only bundles this implementation interprets.
/// A transaction carrying an unknown bundle type or variant has no typed
/// representation; use the byte layer
/// ([`TransactionBytes`]) to parse and re-serialize it.
#[cfg(all(feature = "sapling", feature = "orchard"))]
#[derive(Debug)]
pub struct TransactionData<A: Authorization> {
    version: TxVersion,
    consensus_branch_id: BranchId,
    lock_time: u32,
    expiry_height: BlockHeight,
    value_pool_deltas: zip248::ValuePoolDeltas,
    transparent_bundle: Option<transparent::Bundle<A::TransparentAuth>>,
    sprout_bundle: Option<sprout::Bundle>,
    sapling_bundle: Option<sapling::Bundle<A::SaplingAuth, ZatBalance>>,
    orchard_bundle: Option<orchard::Bundle<A::OrchardAuth, ZatBalance>>,
    ironwood_bundle: Option<orchard::Bundle<A::OrchardAuth, ZatBalance>>,
    coinbase_bundle: Option<zip248::CoinbaseBundle>,
}

#[cfg(all(feature = "sapling", feature = "orchard"))]
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
            sapling_bundle: self.sapling_bundle.clone(),
            orchard_bundle: self.orchard_bundle.clone(),
            ironwood_bundle: self.ironwood_bundle.clone(),
            coinbase_bundle: self.coinbase_bundle.clone(),
        }
    }
}

#[cfg(all(feature = "sapling", feature = "orchard"))]
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

#[cfg(all(feature = "sapling", feature = "orchard"))]
impl<A: Authorization> TransactionData<A> {
    /// Derives the shielded value pool deltas from the bundles' value
    /// balances.
    fn set_shielded_value_pool_deltas(
        value_pool_deltas: &mut zip248::ValuePoolDeltas,
        sapling_bundle: Option<&sapling::Bundle<A::SaplingAuth, ZatBalance>>,
        orchard_bundle: Option<&orchard::Bundle<A::OrchardAuth, ZatBalance>>,
    ) {
        if let Some(b) = sapling_bundle {
            value_pool_deltas
                .set_sapling(*b.value_balance())
                .expect("fresh value pool delta map");
        }
        if let Some(b) = orchard_bundle {
            value_pool_deltas
                .set_orchard(*b.value_balance())
                .expect("fresh value pool delta map");
        }
    }

    /// Constructs a `TransactionData` from its constituent parts.
    #[allow(clippy::too_many_arguments)]
    pub fn from_parts(
        version: TxVersion,
        consensus_branch_id: BranchId,
        lock_time: u32,
        expiry_height: BlockHeight,
        transparent_bundle: Option<transparent::Bundle<A::TransparentAuth>>,
        sprout_bundle: Option<sprout::Bundle>,
        sapling_bundle: Option<sapling::Bundle<A::SaplingAuth, ZatBalance>>,
        orchard_bundle: Option<orchard::Bundle<A::OrchardAuth, ZatBalance>>,
    ) -> Self {
        Self::from_parts_inner(
            version,
            consensus_branch_id,
            lock_time,
            expiry_height,
            Zatoshis::ZERO,
            transparent_bundle,
            sprout_bundle,
            sapling_bundle,
            orchard_bundle,
        )
    }

    /// Constructs a `TransactionData` containing a ZIP 233 amount from its constituent parts.
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
        transparent_bundle: Option<transparent::Bundle<A::TransparentAuth>>,
        sprout_bundle: Option<sprout::Bundle>,
        sapling_bundle: Option<sapling::Bundle<A::SaplingAuth, ZatBalance>>,
        orchard_bundle: Option<orchard::Bundle<A::OrchardAuth, ZatBalance>>,
    ) -> Self {
        Self::from_parts_inner(
            version,
            consensus_branch_id,
            lock_time,
            expiry_height,
            zip233_amount,
            transparent_bundle,
            sprout_bundle,
            sapling_bundle,
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
        transparent_bundle: Option<transparent::Bundle<A::TransparentAuth>>,
        sprout_bundle: Option<sprout::Bundle>,
        sapling_bundle: Option<sapling::Bundle<A::SaplingAuth, ZatBalance>>,
        orchard_bundle: Option<orchard::Bundle<A::OrchardAuth, ZatBalance>>,
    ) -> Self {
        let mut value_pool_deltas = zip248::ValuePoolDeltas::empty();
        value_pool_deltas
            .set_zip233(zip233_amount)
            .expect("fresh value pool delta map");
        Self::set_shielded_value_pool_deltas(
            &mut value_pool_deltas,
            sapling_bundle.as_ref(),
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
            sapling_bundle,
            orchard_bundle,
            None,
            None,
        )
    }

    /// Constructs a V6 [`TransactionData`] from its constituent parts,
    /// including the Ironwood bundle.
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
        transparent_bundle: Option<transparent::Bundle<A::TransparentAuth>>,
        sapling_bundle: Option<sapling::Bundle<A::SaplingAuth, ZatBalance>>,
        orchard_bundle: Option<orchard::Bundle<A::OrchardAuth, ZatBalance>>,
        ironwood_bundle: Option<orchard::Bundle<A::OrchardAuth, ZatBalance>>,
    ) -> Self {
        Self::from_parts_v6_or_v7(
            TxVersion::V6,
            consensus_branch_id,
            lock_time,
            expiry_height,
            transparent_bundle,
            sapling_bundle,
            orchard_bundle,
            ironwood_bundle,
        )
    }

    /// Constructs a V6 [`TransactionData`] containing a ZIP 233 amount.
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
        transparent_bundle: Option<transparent::Bundle<A::TransparentAuth>>,
        sapling_bundle: Option<sapling::Bundle<A::SaplingAuth, ZatBalance>>,
        orchard_bundle: Option<orchard::Bundle<A::OrchardAuth, ZatBalance>>,
        ironwood_bundle: Option<orchard::Bundle<A::OrchardAuth, ZatBalance>>,
    ) -> Self {
        Self::from_parts_v6_or_v7_inner(
            TxVersion::V6,
            consensus_branch_id,
            lock_time,
            expiry_height,
            zip233_amount,
            transparent_bundle,
            sapling_bundle,
            orchard_bundle,
            ironwood_bundle,
        )
    }

    /// Constructs a V7 [`TransactionData`] from its per-protocol bundles.
    #[cfg(zcash_unstable = "nu8")]
    #[allow(clippy::too_many_arguments)]
    pub fn from_parts_v7(
        consensus_branch_id: BranchId,
        lock_time: u32,
        expiry_height: BlockHeight,
        transparent_bundle: Option<transparent::Bundle<A::TransparentAuth>>,
        sapling_bundle: Option<sapling::Bundle<A::SaplingAuth, ZatBalance>>,
        orchard_bundle: Option<orchard::Bundle<A::OrchardAuth, ZatBalance>>,
        ironwood_bundle: Option<orchard::Bundle<A::OrchardAuth, ZatBalance>>,
    ) -> Self {
        Self::from_parts_v6_or_v7(
            TxVersion::V7,
            consensus_branch_id,
            lock_time,
            expiry_height,
            transparent_bundle,
            sapling_bundle,
            orchard_bundle,
            ironwood_bundle,
        )
    }

    /// Constructs a V7 [`TransactionData`] containing a ZIP 233 amount.
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
        transparent_bundle: Option<transparent::Bundle<A::TransparentAuth>>,
        sapling_bundle: Option<sapling::Bundle<A::SaplingAuth, ZatBalance>>,
        orchard_bundle: Option<orchard::Bundle<A::OrchardAuth, ZatBalance>>,
        ironwood_bundle: Option<orchard::Bundle<A::OrchardAuth, ZatBalance>>,
    ) -> Self {
        Self::from_parts_v6_or_v7_inner(
            TxVersion::V7,
            consensus_branch_id,
            lock_time,
            expiry_height,
            zip233_amount,
            transparent_bundle,
            sapling_bundle,
            orchard_bundle,
            ironwood_bundle,
        )
    }

    /// Constructs a v7 [`TransactionData`] whose value pool deltas balance.
    ///
    /// [ZIP 248] requires the deltas for each asset to sum to zero. The
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
        transparent_bundle: Option<transparent::Bundle<A::TransparentAuth>>,
        sapling_bundle: Option<sapling::Bundle<A::SaplingAuth, ZatBalance>>,
        orchard_bundle: Option<orchard::Bundle<A::OrchardAuth, ZatBalance>>,
        ironwood_bundle: Option<orchard::Bundle<A::OrchardAuth, ZatBalance>>,
    ) -> Result<Self, BalanceError> {
        let mut data = Self::from_parts_v6_or_v7_inner(
            TxVersion::V7,
            consensus_branch_id,
            lock_time,
            expiry_height,
            Zatoshis::ZERO,
            transparent_bundle,
            sapling_bundle,
            orchard_bundle,
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
        transparent_bundle: Option<transparent::Bundle<A::TransparentAuth>>,
        sapling_bundle: Option<sapling::Bundle<A::SaplingAuth, ZatBalance>>,
        orchard_bundle: Option<orchard::Bundle<A::OrchardAuth, ZatBalance>>,
        ironwood_bundle: Option<orchard::Bundle<A::OrchardAuth, ZatBalance>>,
    ) -> Self {
        Self::from_parts_v6_or_v7_inner(
            version,
            consensus_branch_id,
            lock_time,
            expiry_height,
            Zatoshis::ZERO,
            transparent_bundle,
            sapling_bundle,
            orchard_bundle,
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
        transparent_bundle: Option<transparent::Bundle<A::TransparentAuth>>,
        sapling_bundle: Option<sapling::Bundle<A::SaplingAuth, ZatBalance>>,
        orchard_bundle: Option<orchard::Bundle<A::OrchardAuth, ZatBalance>>,
        ironwood_bundle: Option<orchard::Bundle<A::OrchardAuth, ZatBalance>>,
    ) -> Self {
        let mut value_pool_deltas = zip248::ValuePoolDeltas::empty();
        value_pool_deltas
            .set_zip233(zip233_amount)
            .expect("fresh value pool delta map");
        Self::set_shielded_value_pool_deltas(
            &mut value_pool_deltas,
            sapling_bundle.as_ref(),
            orchard_bundle.as_ref(),
        );
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
            sapling_bundle,
            orchard_bundle,
            ironwood_bundle,
            None,
        )
    }

    /// Constructs a `TransactionData` from per-protocol bundles and an
    /// explicit [`ValuePoolDeltas`](zip248::ValuePoolDeltas) map.
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
        transparent_bundle: Option<transparent::Bundle<A::TransparentAuth>>,
        sprout_bundle: Option<sprout::Bundle>,
        sapling_bundle: Option<sapling::Bundle<A::SaplingAuth, ZatBalance>>,
        orchard_bundle: Option<orchard::Bundle<A::OrchardAuth, ZatBalance>>,
        ironwood_bundle: Option<orchard::Bundle<A::OrchardAuth, ZatBalance>>,
        coinbase_bundle: Option<zip248::CoinbaseBundle>,
    ) -> Self {
        TransactionData {
            version,
            consensus_branch_id,
            lock_time,
            expiry_height,
            value_pool_deltas,
            transparent_bundle,
            sprout_bundle,
            sapling_bundle,
            orchard_bundle,
            ironwood_bundle,
            coinbase_bundle,
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

    pub fn transparent_bundle(&self) -> Option<&transparent::Bundle<A::TransparentAuth>> {
        self.transparent_bundle.as_ref()
    }

    /// Returns the coinbase bundle, if any. A v7 transaction is a coinbase
    /// transaction if and only if it has one.
    /// [ZIP 248 §Coinbase Bundle](https://zips.z.cash/zip-0248#coinbase-bundle)
    pub fn coinbase_bundle(&self) -> Option<&zip248::CoinbaseBundle> {
        self.coinbase_bundle.as_ref()
    }

    pub fn sprout_bundle(&self) -> Option<&sprout::Bundle> {
        self.sprout_bundle.as_ref()
    }

    pub fn sapling_bundle(&self) -> Option<&sapling::Bundle<A::SaplingAuth, ZatBalance>> {
        self.sapling_bundle.as_ref()
    }

    pub fn orchard_bundle(&self) -> Option<&orchard::Bundle<A::OrchardAuth, ZatBalance>> {
        self.orchard_bundle.as_ref()
    }

    /// Returns the Ironwood bundle, if any.
    ///
    /// The Ironwood bundle acts on the *Ironwood pool* using the Orchard
    /// protocol, so it has the same type as the Orchard bundle.
    /// [ZIP 248 §Orchard Protocol Bundles](https://zips.z.cash/zip-0248#orchard-protocol-bundles)
    pub fn ironwood_bundle(&self) -> Option<&orchard::Bundle<A::OrchardAuth, ZatBalance>> {
        self.ironwood_bundle.as_ref()
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
        self.sapling_bundle.take()
    }

    /// Removes and returns the Orchard bundle, if present.
    #[cfg(feature = "circuits")]
    pub(crate) fn take_orchard(&mut self) -> Option<orchard::Bundle<A::OrchardAuth, ZatBalance>> {
        self.orchard_bundle.take()
    }

    /// Removes and returns the Ironwood bundle, if present.
    #[cfg(feature = "circuits")]
    pub(crate) fn take_ironwood(&mut self) -> Option<orchard::Bundle<A::OrchardAuth, ZatBalance>> {
        self.ironwood_bundle.take()
    }

    /// The transparent bundle, if it carries authorizing data.
    ///
    /// Only inputs are authorized, so a transparent bundle holding outputs
    /// alone contributes no `mAuthBundles` entry. The serializer, the parser
    /// and the authorizing data commitment must agree on this, or a
    /// transaction's commitment covers an entry that is not on the wire.
    #[cfg(zcash_unstable = "nu8")]
    pub(crate) fn v7_transparent_auth(&self) -> Option<&transparent::Bundle<A::TransparentAuth>> {
        self.transparent_bundle
            .as_ref()
            .filter(|tb| !tb.vin.is_empty())
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
    pub fn fee_paid<E, F>(&self, get_prevout: F) -> Result<Option<Zatoshis>, E>
    where
        E: From<BalanceError>,
        F: FnMut(&OutPoint) -> Result<Option<Zatoshis>, E>,
    {
        let transparent_balance = self.transparent_bundle.as_ref().map_or_else(
            || Ok(Some(ZatBalance::zero())),
            |b| b.value_balance(get_prevout),
        )?;

        transparent_balance
            .map(|transparent_balance| {
                let value_balances = [
                    transparent_balance,
                    self.sprout_bundle.as_ref().map_or_else(
                        || Ok(ZatBalance::zero()),
                        |b| b.value_balance().ok_or(BalanceError::Overflow),
                    )?,
                    self.sapling_bundle
                        .as_ref()
                        .map_or_else(ZatBalance::zero, |b| *b.value_balance()),
                    self.orchard_bundle
                        .as_ref()
                        .map_or_else(ZatBalance::zero, |b| *b.value_balance()),
                    self.ironwood_bundle
                        .as_ref()
                        .map_or_else(ZatBalance::zero, |b| *b.value_balance()),
                    // A coinbase bundle carries the part of the block subsidy
                    // the transaction pays out, which funds its outputs.
                    self.coinbase_bundle
                        .as_ref()
                        .map_or_else(ZatBalance::zero, |b| b.value_pool_delta()),
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
    /// V6 and later transactions include the Ironwood bundle digest as a separate
    /// Orchard-shaped digest with Ironwood personalization. Earlier transaction
    /// versions do not include Ironwood in their digest.
    pub fn digest<D: TransactionDigest<A>>(&self, digester: D) -> D::Digest {
        let header_digest = digester.digest_header(
            self.version,
            self.consensus_branch_id,
            self.lock_time,
            self.expiry_height,
        );

        digester.combine(
            header_digest,
            digester.digest_transparent(self.transparent_bundle.as_ref()),
            digester.digest_sapling(self.version, self.sapling_bundle.as_ref()),
            digester.digest_orchard(self.version, self.orchard_bundle.as_ref()),
            digester.digest_ironwood(self.ironwood_bundle.as_ref()),
        )
    }

    /// Computes this transaction's txid digest tree under the rules of its
    /// version: [ZIP 248] for v7, [ZIP 244] (with the [ZIP 229] Ironwood
    /// extension for v6) otherwise.
    ///
    /// These are the digests that signature hashes must commit to.
    ///
    /// [ZIP 229]: https://zips.z.cash/zip-0229
    /// [ZIP 244]: https://zips.z.cash/zip-0244
    /// [ZIP 248]: https://zips.z.cash/zip-0248
    pub fn txid_digests(&self) -> Zip244Digests<blake2b_simd::Hash> {
        match self.version {
            #[cfg(zcash_unstable = "nu8")]
            TxVersion::V7 => self.digest_v7(),
            _ => self.digest(txid::TxIdDigester),
        }
    }

    /// Produces v7 transaction digests per
    /// [ZIP 248 §TxId Digest](https://zips.z.cash/zip-0248#txid-digest).
    ///
    /// The leaves are the header, the transparent effect sub-tree (itself the
    /// ZIP 244 structure), the coinbase, Sapling, Orchard and Ironwood
    /// effecting digests, and the value pool deltas map. Authorizing data is
    /// digested separately, by `Transaction::auth_commitment`.
    ///
    /// A typed transaction contains only bundles this implementation
    /// interprets, so the unknown-bundle digest list is always empty. The byte
    /// layer computes digests for transactions carrying opaque bundles.
    #[cfg(zcash_unstable = "nu8")]
    pub fn digest_v7(&self) -> Zip244Digests<blake2b_simd::Hash> {
        use txid::{
            TxIdDigester, hash_v7_coinbase_effects, hash_v7_header, hash_v7_ironwood_effects,
            hash_v7_orchard_effects, hash_v7_sapling_effects, hash_v7_value_pool_deltas,
        };

        let digester = TxIdDigester;

        Zip244Digests {
            // Leaf 1: header fields (no auth data involved).
            header_digest: hash_v7_header(
                self.version,
                self.consensus_branch_id,
                self.lock_time,
                self.expiry_height,
            ),
            // Leaf 2: transparent effect digests (prevouts, sequences, outputs).
            // Reuses the v5/ZIP 244 sub-tree structure.
            transparent_digests: <TxIdDigester as TransactionDigest<A>>::digest_transparent(
                &digester,
                self.transparent_bundle.as_ref(),
            ),
            // Leaf 3: the coinbase bundle's effecting data, for coinbase
            // transactions only.
            coinbase_digest: self.coinbase_bundle.as_ref().map(hash_v7_coinbase_effects),
            // Leaf 4: sapling effects only (spends, outputs).
            sapling_digest: self.sapling_bundle.as_ref().map(hash_v7_sapling_effects),
            // Leaf 5: orchard effects only (actions, flags).
            orchard_digest: self.orchard_bundle.as_ref().map(hash_v7_orchard_effects),
            // Leaf 6: the same, for the Orchard protocol bundle acting on the
            // *Ironwood pool*.
            ironwood_digest: self.ironwood_bundle.as_ref().map(hash_v7_ironwood_effects),
            // Leaf 7: the serialized VP deltas map.
            value_pool_deltas_digest: Some(hash_v7_value_pool_deltas(&self.value_pool_deltas)),
            // A typed transaction has no opaque bundles.
            unknown_effect_digests: Vec::new(),
        }
    }

    /// Changes the consensus branch ID stored in this transaction for pre-v5 transactions.
    ///
    /// This can be used to fix an incorrect value passed to [`Transaction::read`]. Just
    /// like that method, this method does nothing for v5+ transactions.
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
    pub fn map_bundles<B: Authorization>(
        self,
        f_transparent: impl FnOnce(
            Option<transparent::Bundle<A::TransparentAuth>>,
        ) -> Option<transparent::Bundle<B::TransparentAuth>>,
        f_sapling: impl FnOnce(
            Option<sapling::Bundle<A::SaplingAuth, ZatBalance>>,
        ) -> Option<sapling::Bundle<B::SaplingAuth, ZatBalance>>,
        mut f_orchard: impl FnMut(
            Option<orchard::bundle::Bundle<A::OrchardAuth, ZatBalance>>,
        )
            -> Option<orchard::bundle::Bundle<B::OrchardAuth, ZatBalance>>,
    ) -> TransactionData<B> {
        TransactionData {
            version: self.version,
            consensus_branch_id: self.consensus_branch_id,
            lock_time: self.lock_time,
            expiry_height: self.expiry_height,
            value_pool_deltas: self.value_pool_deltas,
            transparent_bundle: f_transparent(self.transparent_bundle),
            sprout_bundle: self.sprout_bundle,
            sapling_bundle: f_sapling(self.sapling_bundle),
            orchard_bundle: f_orchard(self.orchard_bundle),
            ironwood_bundle: f_orchard(self.ironwood_bundle),
            coinbase_bundle: self.coinbase_bundle,
        }
    }

    /// Maps the bundles from one type to another with fallible closures.
    ///
    /// This shouldn't be necessary for most use cases; it is provided for handling the
    /// transaction extraction logic in the `pczt` crate.
    ///
    /// `f_orchard` is also applied to the Ironwood bundle because Ironwood is
    /// represented with the Orchard bundle type.
    pub fn try_map_bundles<B: Authorization, E>(
        self,
        f_transparent: impl FnOnce(
            Option<transparent::Bundle<A::TransparentAuth>>,
        )
            -> Result<Option<transparent::Bundle<B::TransparentAuth>>, E>,
        f_sapling: impl FnOnce(
            Option<sapling::Bundle<A::SaplingAuth, ZatBalance>>,
        )
            -> Result<Option<sapling::Bundle<B::SaplingAuth, ZatBalance>>, E>,
        mut f_orchard: impl FnMut(
            Option<orchard::bundle::Bundle<A::OrchardAuth, ZatBalance>>,
        ) -> Result<
            Option<orchard::bundle::Bundle<B::OrchardAuth, ZatBalance>>,
            E,
        >,
    ) -> Result<TransactionData<B>, E> {
        Ok(TransactionData {
            version: self.version,
            consensus_branch_id: self.consensus_branch_id,
            lock_time: self.lock_time,
            expiry_height: self.expiry_height,
            value_pool_deltas: self.value_pool_deltas,
            transparent_bundle: f_transparent(self.transparent_bundle)?,
            sprout_bundle: self.sprout_bundle,
            sapling_bundle: f_sapling(self.sapling_bundle)?,
            orchard_bundle: f_orchard(self.orchard_bundle)?,
            ironwood_bundle: f_orchard(self.ironwood_bundle)?,
            coinbase_bundle: self.coinbase_bundle,
        })
    }

    pub fn map_authorization<B: Authorization>(
        self,
        f_transparent: impl transparent::MapAuth<A::TransparentAuth, B::TransparentAuth>,
        mut f_sapling: impl sapling_serialization::MapAuth<A::SaplingAuth, B::SaplingAuth>,
        mut f_orchard: impl orchard_serialization::MapAuth<A::OrchardAuth, B::OrchardAuth>,
    ) -> TransactionData<B> {
        let mut map_sapling = |sb: Option<sapling::Bundle<A::SaplingAuth, ZatBalance>>| {
            sb.map(|b| {
                b.map_authorization(
                    &mut f_sapling,
                    |f, p| f.map_spend_proof(p),
                    |f, p| f.map_output_proof(p),
                    |f, s| f.map_auth_sig(s),
                    |f, a| f.map_authorization(a),
                )
            })
        };
        // Applied to the Orchard bundle and then to the Ironwood bundle: both
        // are Orchard protocol bundles.
        let mut map_orchard = |ob: Option<orchard::Bundle<A::OrchardAuth, ZatBalance>>| {
            ob.map(|b| {
                b.map_authorization(
                    &mut f_orchard,
                    |f, _, s| f.map_spend_auth(s),
                    |f, a| f.map_authorization(a),
                )
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
            sapling_bundle: map_sapling(self.sapling_bundle),
            orchard_bundle: map_orchard(self.orchard_bundle),
            ironwood_bundle: map_orchard(self.ironwood_bundle),
            coinbase_bundle: self.coinbase_bundle,
        }
    }
}

#[cfg(all(feature = "sapling", feature = "orchard"))]
impl<A: Authorization> TransactionData<A> {
    pub fn sapling_value_balance(&self) -> ZatBalance {
        self.sapling_bundle
            .as_ref()
            .map_or(ZatBalance::zero(), |b| *b.value_balance())
    }
}

#[cfg(all(feature = "sapling", feature = "orchard"))]
impl TransactionData<Authorized> {
    /// Constructs an authorized transaction and computes its transaction ID.
    ///
    /// # Errors
    ///
    /// Returns an error if the transaction cannot be serialized, or if it contains a
    /// nonzero ZIP 233 amount under a transaction version and consensus branch that do
    /// not support ZIP 233.
    pub fn freeze(self) -> io::Result<Transaction> {
        #[cfg(all(feature = "zip-233", zcash_unstable = "zip233"))]
        if self.zip233_amount() != Zatoshis::ZERO
            && !self.version.has_zip233(self.consensus_branch_id)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "nonzero ZIP 233 amount is not supported by the transaction version and consensus branch",
            ));
        }

        Transaction::from_data(self)
    }
}

/// Reads a little-endian `i64` value balance.
#[cfg(any(
    all(feature = "sapling", feature = "temporary-zcashd"),
    feature = "orchard"
))]
pub(crate) fn read_amount<R: Read>(mut reader: R) -> io::Result<ZatBalance> {
    let mut tmp = [0; 8];
    reader.read_exact(&mut tmp)?;
    ZatBalance::from_i64_le_bytes(tmp)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "valueBalance out of range"))
}

#[cfg(all(feature = "sapling", feature = "orchard"))]
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

        let txid =
            to_txid(data.version, data.consensus_branch_id, &data.digest_v7()).expect("is v7 tx");

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
    /// For version 7, returns an error if the transaction contains a bundle
    /// type or variant this implementation does not interpret. Use
    /// [`TransactionBytes::read`] and supply the bundle digests to compute
    /// such a transaction's identifier.
    pub fn read<R: Read>(reader: R, consensus_branch_id: BranchId) -> io::Result<Self> {
        let mut reader = HashReader::new(reader);
        let bytes = TransactionBytes::read(&mut reader)?;
        let legacy_hash = reader.into_hash();
        Self::from_bytes(bytes, consensus_branch_id, legacy_hash.into())
    }

    /// Reads and fully validates a version 7 transaction from its wire
    /// encoding.
    ///
    /// Parses the bytes with [`TransactionBytes::read`], applies the
    /// transaction-local consensus rules from [ZIP 248], and returns the typed
    /// transaction. The byte parser enforces the ZIP 248 parsing rules; this
    /// method additionally enforces bundle availability, registry map
    /// prohibitions, required effect and authorizing entries, ZEC-only fee and
    /// coinbase value pool deltas, coinbase restrictions, the Orchard
    /// cross-address restriction, fee delta signs, the coinbase value pool
    /// delta relation, per-asset conservation, and the input- and output-side
    /// conditions.
    ///
    /// Rules that require block or UTXO context are not checked: the per-block
    /// fee sum, the ZIP 235 NSM fee contribution and the resulting miner fee
    /// available to the coinbase transaction, exactly one coinbase transaction
    /// first in the block, the coinbase bundle's `blockHeight`, `blockSubsidy`
    /// and `lockboxValue` matching the block and issuance schedule, and the
    /// transparent bundle's value pool delta matching its input and output
    /// values.
    ///
    /// # Errors
    ///
    /// Returns [`V7ValidationError::InvalidEncoding`] if the bytes are not a
    /// well-formed transaction, [`V7ValidationError::NotV7`] if the encoding is
    /// not version 7, and the other [`V7ValidationError`] variants for the
    /// rules listed above.
    ///
    /// [ZIP 248]: https://zips.z.cash/zip-0248
    #[cfg(zcash_unstable = "nu8")]
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
                let transparent_bundle = body.transparent().to_authorized()?;
                let sprout_bundle = body
                    .sprout()
                    .map(SproutBundleBytes::to_bundle)
                    .transpose()?;
                let sapling_bundle = match body.sapling() {
                    Some(sapling) => sapling.to_authorized(body.sapling_binding_sig().copied())?,
                    None => None,
                };

                Ok(Transaction {
                    txid: TxId::from_bytes(legacy_hash),
                    data: TransactionData::from_parts(
                        version,
                        consensus_branch_id,
                        lock_time,
                        expiry_height,
                        transparent_bundle,
                        sprout_bundle,
                        sapling_bundle,
                        None,
                    ),
                })
            }
            TransactionBodyBytes::V5(body) => {
                let consensus_branch_id = wire_branch_id.expect("v5 encodes a consensus branch ID");
                let transparent_bundle = body.transparent().to_authorized()?;
                let sapling_bundle = body
                    .sapling()
                    .map(SaplingBundleBytes::to_authorized)
                    .transpose()?;
                let orchard_bundle = body
                    .orchard()
                    .map(|bundle| {
                        bundle.to_authorized(orchard_serialization::bundle_version_for_branch(
                            consensus_branch_id,
                            orchard::ValuePool::Orchard,
                        ))
                    })
                    .transpose()?;

                let data = TransactionData::from_parts(
                    version,
                    consensus_branch_id,
                    lock_time,
                    expiry_height,
                    transparent_bundle,
                    None,
                    sapling_bundle,
                    orchard_bundle,
                );
                Ok(Self::from_data_v5(data))
            }
            TransactionBodyBytes::V6(body) => {
                let consensus_branch_id = wire_branch_id.expect("v6 encodes a consensus branch ID");
                let transparent_bundle = body.transparent().to_authorized()?;
                let sapling_bundle = body
                    .sapling()
                    .map(SaplingBundleBytes::to_authorized)
                    .transpose()?;
                let orchard_bundle = body
                    .orchard()
                    .map(|bundle| {
                        bundle.to_authorized(orchard_serialization::bundle_version_for_branch(
                            consensus_branch_id,
                            orchard::ValuePool::Orchard,
                        ))
                    })
                    .transpose()?;
                let ironwood_bundle = body
                    .ironwood()
                    .map(|bundle| {
                        bundle.to_authorized(orchard_serialization::bundle_version_for_branch(
                            consensus_branch_id,
                            orchard::ValuePool::Ironwood,
                        ))
                    })
                    .transpose()?;

                let data = TransactionData::from_parts_v6(
                    consensus_branch_id,
                    lock_time,
                    expiry_height,
                    transparent_bundle,
                    sapling_bundle,
                    orchard_bundle,
                    ironwood_bundle,
                );
                Ok(Self::from_data_v6(data))
            }
            #[cfg(zcash_unstable = "nu8")]
            TransactionBodyBytes::V7(body) => {
                let consensus_branch_id = wire_branch_id.expect("v7 encodes a consensus branch ID");

                if let Some(opaque) = body.opaque_bundles().next() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        alloc::format!(
                            "v7 transaction contains an unsupported bundle \
                             (bundleType {}, bundleVariant {}); \
                             parse it with TransactionBytes and supply its digests",
                            opaque.bundle_type().to_u64(),
                            opaque.bundle_variant().to_u64(),
                        ),
                    ));
                }

                Self::from_v7_body_ref(&body, consensus_branch_id, lock_time, expiry_height)
            }
        }
    }

    /// Interprets a version 7 body as a fully-typed transaction.
    ///
    /// Every bundle must be one this implementation interprets, and no bundle
    /// may carry data the typed representation cannot hold. Callers that accept
    /// such bundles must reject them first.
    #[cfg(all(feature = "sapling", feature = "orchard", zcash_unstable = "nu8"))]
    fn from_v7_body_ref(
        body: &V7TransactionBodyBytes,
        consensus_branch_id: BranchId,
        lock_time: u32,
        expiry_height: BlockHeight,
    ) -> io::Result<Self> {
        if body
            .bundles()
            .iter()
            .any(|bundle| bundle.coinbase_auth().is_some())
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "v7 transaction contains a prohibited coinbase authorizing payload; \
                 parse it with TransactionBytes",
            ));
        }

        let value_pool_deltas = body.to_value_pool_deltas()?;
        let transparent_bundle = body
            .transparent()
            .map(TransparentBundleBytes::to_authorized)
            .transpose()?
            .flatten();
        let coinbase_bundle = body
            .coinbase()
            .map(CoinbaseBundleBytes::to_coinbase_bundle)
            .transpose()?;
        let sapling_bundle = body
            .sapling()
            .map(|bundle| {
                bundle.to_authorized(
                    value_pool_deltas
                        .sapling_value()
                        .unwrap_or(ZatBalance::zero()),
                )
            })
            .transpose()?;
        let orchard_bundle = body
            .orchard()
            .map(|bundle| {
                bundle.to_authorized(
                    value_pool_deltas
                        .orchard_value()
                        .unwrap_or(ZatBalance::zero()),
                    orchard_serialization::bundle_version_for_branch(
                        consensus_branch_id,
                        orchard::ValuePool::Orchard,
                    ),
                )
            })
            .transpose()?;
        let ironwood_bundle = body
            .ironwood()
            .map(|bundle| {
                bundle.to_authorized(
                    value_pool_deltas
                        .ironwood_value()
                        .unwrap_or(ZatBalance::zero()),
                    orchard_serialization::bundle_version_for_branch(
                        consensus_branch_id,
                        orchard::ValuePool::Ironwood,
                    ),
                )
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
            sapling_bundle,
            orchard_bundle,
            ironwood_bundle,
            coinbase_bundle,
        );
        Ok(Self::from_data_v7(data))
    }

    /// Buffers one bundle's payload and tags it with its ZIP 248 registry key.
    ///
    /// The TLV framing needs the payload's length before the payload reaches
    /// the writer, so each bundle is serialized into a `Vec<u8>` first.
    #[cfg(zcash_unstable = "nu8")]
    fn tag_v7_bundle<F>(id: zip248::BundleId, write: F) -> io::Result<(u64, u64, Vec<u8>)>
    where
        F: FnOnce(&mut Vec<u8>) -> io::Result<()>,
    {
        let mut data = Vec::new();
        write(&mut data)?;
        let (bundle_type, bundle_variant) = id.wire_key();
        Ok((bundle_type, bundle_variant, data))
    }

    #[cfg(feature = "temporary-zcashd")]
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

    pub fn write_v4<W: Write>(&self, mut writer: W) -> io::Result<()> {
        if self.orchard_bundle.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Orchard components cannot be present when serializing to the V4 transaction format.",
            ));
        }

        self.version.write(&mut writer)?;

        self.write_transparent(&mut writer)?;
        writer.write_u32_le(self.lock_time)?;
        if self.version.has_overwinter() {
            writer.write_u32_le(u32::from(self.expiry_height))?;
        }

        sapling_serialization::write_v4_components(
            &mut writer,
            self.sapling_bundle.as_ref(),
            self.version.has_sapling(),
        )?;

        if self.version.has_sprout() {
            if let Some(bundle) = self.sprout_bundle.as_ref() {
                Vector::write(&mut writer, &bundle.joinsplits, |w, e| e.write(w))?;
                writer.write_all(&bundle.joinsplit_pubkey)?;
                writer.write_all(&bundle.joinsplit_sig)?;
            } else {
                CompactSize::write(&mut writer, 0)?;
            }
        }

        if self.version.has_sapling()
            && let Some(bundle) = self.sapling_bundle.as_ref()
        {
            writer.write_all(&<[u8; 64]>::from(bundle.authorization().binding_sig))?;
        }

        Ok(())
    }

    pub fn write_transparent<W: Write>(&self, mut writer: W) -> io::Result<()> {
        if let Some(bundle) = self.transparent_bundle.as_ref() {
            Vector::write(&mut writer, &bundle.vin, |w, e| e.write(w))?;
            Vector::write(&mut writer, &bundle.vout, |w, e| e.write(w))?;
        } else {
            CompactSize::write(&mut writer, 0)?;
            CompactSize::write(&mut writer, 0)?;
        }

        Ok(())
    }

    pub fn write_v5<W: Write>(&self, mut writer: W) -> io::Result<()> {
        if self.sprout_bundle.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Sprout components cannot be present when serializing to the V5 transaction format.",
            ));
        }
        self.write_v5_header(&mut writer)?;
        self.write_transparent(&mut writer)?;
        self.write_v5_sapling(&mut writer)?;
        orchard_serialization::write_v5_bundle(self.orchard_bundle.as_ref(), &mut writer)?;

        Ok(())
    }

    pub fn write_v6<W: Write>(&self, mut writer: W) -> io::Result<()> {
        if self.sprout_bundle.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Sprout components cannot be present when serializing to V6 or later transaction formats.",
            ));
        }
        self.write_v6_header(&mut writer)?;

        self.write_transparent(&mut writer)?;
        self.write_v5_sapling(&mut writer)?;
        orchard_serialization::write_v6_bundle(self.orchard_bundle.as_ref(), &mut writer)?;
        orchard_serialization::write_v6_bundle(self.ironwood_bundle.as_ref(), &mut writer)?;

        Ok(())
    }

    /// Serializes this transaction in v7 (ZIP 248) wire format.
    ///
    /// [ZIP 248 §Transaction Format](https://zips.z.cash/zip-0248#transaction-format)
    ///
    /// The value pool deltas come from `to_wire_entries`, which merges the
    /// typed and opaque entries into the one sorted sequence the spec requires;
    /// the two bundle maps are assembled per bundle and written by
    /// `zip248::write_bundle_data_map`.
    #[cfg(zcash_unstable = "nu8")]
    pub fn write_v7<W: Write>(&self, mut writer: W) -> io::Result<()> {
        if self.sprout_bundle.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Sprout components cannot be present when serializing to the v7 transaction format.",
            ));
        }

        // 1. Header (5 × u32): version, versionGroupId, consensusBranchId, lockTime, expiryHeight
        self.write_v7_header(&mut writer)?;

        // 2. Value pool deltas map -- to_wire_entries() merges known + unknown
        // entries in canonical (bundleType, assetClass, assetUuid) order.
        let vp_entries = self.value_pool_deltas.to_wire_entries();
        CompactSize::write(&mut writer, vp_entries.len())?;
        for entry in &vp_entries {
            entry.write(&mut writer)?;
        }

        // 3. Effect bundles map.
        let mut effect_bundles: Vec<(u64, u64, Vec<u8>)> = Vec::new();
        if let Some(tb) = self.transparent_bundle.as_ref() {
            effect_bundles.push(Self::tag_v7_bundle(
                zip248::BundleId::new(BundleType::TRANSPARENT, BundleVariant::DEFAULT),
                |buf| zip248::write_v7_transparent_effects(buf, tb),
            )?);
        }
        if let Some(cb) = self.coinbase_bundle.as_ref() {
            effect_bundles.push(Self::tag_v7_bundle(
                zip248::BundleId::new(BundleType::COINBASE, BundleVariant::DEFAULT),
                |buf| cb.write(buf),
            )?);
        }
        if let Some(sb) = self.sapling_bundle.as_ref() {
            effect_bundles.push(Self::tag_v7_bundle(
                zip248::BundleId::new(BundleType::SAPLING, BundleVariant::DEFAULT),
                |buf| sapling_serialization::write_v7_effects(buf, sb),
            )?);
        }
        if let Some(ob) = self.orchard_bundle.as_ref() {
            effect_bundles.push(Self::tag_v7_bundle(
                zip248::BundleId::new(BundleType::ORCHARD, BundleVariant::DEFAULT),
                |buf| orchard_serialization::write_v7_effects(buf, ob),
            )?);
        }
        if let Some(ib) = self.ironwood_bundle.as_ref() {
            effect_bundles.push(Self::tag_v7_bundle(
                zip248::BundleId::new(BundleType::IRONWOOD, BundleVariant::DEFAULT),
                |buf| orchard_serialization::write_v7_effects(buf, ib),
            )?);
        }
        zip248::write_bundle_data_map(&mut writer, effect_bundles)?;

        // 4. Auth bundles map. A bundle appears here only if it has
        // authorizing data; see `v7_transparent_auth`.
        let mut auth_bundles: Vec<(u64, u64, Vec<u8>)> = Vec::new();
        if let Some(tb) = self.v7_transparent_auth() {
            auth_bundles.push(Self::tag_v7_bundle(
                zip248::BundleId::new(BundleType::TRANSPARENT, BundleVariant::DEFAULT),
                |buf| zip248::write_v7_transparent_auth(buf, tb),
            )?);
        }
        if let Some(sb) = self.sapling_bundle.as_ref() {
            auth_bundles.push(Self::tag_v7_bundle(
                zip248::BundleId::new(BundleType::SAPLING, BundleVariant::DEFAULT),
                |buf| sapling_serialization::write_v7_auth(buf, sb),
            )?);
        }
        if let Some(ob) = self.orchard_bundle.as_ref() {
            auth_bundles.push(Self::tag_v7_bundle(
                zip248::BundleId::new(BundleType::ORCHARD, BundleVariant::DEFAULT),
                |buf| orchard_serialization::write_v7_auth(buf, ob),
            )?);
        }
        if let Some(ib) = self.ironwood_bundle.as_ref() {
            auth_bundles.push(Self::tag_v7_bundle(
                zip248::BundleId::new(BundleType::IRONWOOD, BundleVariant::DEFAULT),
                |buf| orchard_serialization::write_v7_auth(buf, ib),
            )?);
        }
        zip248::write_bundle_data_map(&mut writer, auth_bundles)?;

        Ok(())
    }

    pub fn write_v5_header<W: Write>(&self, mut writer: W) -> io::Result<()> {
        self.version.write(&mut writer)?;
        writer.write_u32_le(u32::from(self.consensus_branch_id))?;
        writer.write_u32_le(self.lock_time)?;
        writer.write_u32_le(u32::from(self.expiry_height))?;
        Ok(())
    }

    pub fn write_v6_header<W: Write>(&self, mut writer: W) -> io::Result<()> {
        self.version.write(&mut writer)?;
        writer.write_u32_le(u32::from(self.consensus_branch_id))?;
        writer.write_u32_le(self.lock_time)?;
        writer.write_u32_le(u32::from(self.expiry_height))?;

        Ok(())
    }

    /// Writes the v7 (ZIP 248) common transaction header: header, nVersionGroupId,
    /// nConsensusBranchId, lock_time, nExpiryHeight (5 × u32). The ZIP 233 NSM
    /// amount is not included here; it lives in `mValuePoolDeltas` under
    /// `bundleType = 6`.
    #[cfg(zcash_unstable = "nu8")]
    pub fn write_v7_header<W: Write>(&self, mut writer: W) -> io::Result<()> {
        self.version.write(&mut writer)?;
        writer.write_u32_le(u32::from(self.consensus_branch_id))?;
        writer.write_u32_le(self.lock_time)?;
        writer.write_u32_le(u32::from(self.expiry_height))?;
        Ok(())
    }

    #[cfg(feature = "temporary-zcashd")]
    pub fn temporary_zcashd_write_v5_sapling<W: Write>(
        sapling_bundle: Option<&sapling::Bundle<sapling::bundle::Authorized, ZatBalance>>,
        writer: W,
    ) -> io::Result<()> {
        sapling_serialization::write_v5_bundle(writer, sapling_bundle)
    }

    pub fn write_v5_sapling<W: Write>(&self, writer: W) -> io::Result<()> {
        sapling_serialization::write_v5_bundle(writer, self.sapling_bundle.as_ref())
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
        match self.data.version {
            #[cfg(zcash_unstable = "nu8")]
            TxVersion::V7 => self.auth_commitment_v7(),
            _ => self.data.digest(BlockTxCommitmentDigester),
        }
    }

    /// Computes the v7 authorizing data commitment per
    /// [ZIP 248 §Authorizing Data Commitment](https://zips.z.cash/zip-0248#authorizing-data-commitment).
    ///
    /// The auth commitment is structurally parallel to the txid digest but
    /// covers only the witness / authorization data (scriptSig, spend auth
    /// sigs, binding sig, Orchard proof, etc.). It is used by miners and
    /// validators to commit to the authorization without affecting the txid.
    ///
    /// Structure: `BLAKE2b-256(auth_bundles_digest)` with a personalization
    /// tag that embeds the consensus branch ID.
    #[cfg(zcash_unstable = "nu8")]
    fn auth_commitment_v7(&self) -> Blake2bHash {
        use txid::{
            hash_v7_auth_bundles, hash_v7_ironwood_auth, hash_v7_orchard_auth,
            hash_v7_sapling_auth, hash_v7_transparent_auth, v7_bundle_digest_entries,
        };

        // Per-protocol auth digests. Each covers the bundle's witness data
        // (scriptSig for transparent, spend/binding sigs for shielded).
        let transparent_auth_digest: Option<Blake2bHash> = self
            .data
            .v7_transparent_auth()
            .map(Some)
            .map(hash_v7_transparent_auth);
        let sapling_auth_digest: Option<Blake2bHash> = self
            .data
            .sapling_bundle
            .as_ref()
            .map(Some)
            .map(hash_v7_sapling_auth);
        let orchard_auth_digest: Option<Blake2bHash> = self
            .data
            .orchard_bundle
            .as_ref()
            .map(Some)
            .map(hash_v7_orchard_auth);
        let ironwood_auth_digest: Option<Blake2bHash> = self
            .data
            .ironwood_bundle
            .as_ref()
            .map(Some)
            .map(hash_v7_ironwood_auth);

        // A typed transaction has no opaque bundles, so there are no
        // unknown-bundle authorizing-data digests to merge in.
        let auth_bundles_digest = hash_v7_auth_bundles(v7_bundle_digest_entries(
            transparent_auth_digest.as_ref(),
            // The coinbase bundle has no authorizing data.
            None,
            sapling_auth_digest.as_ref(),
            orchard_auth_digest.as_ref(),
            ironwood_auth_digest.as_ref(),
            &[],
        ));

        // Final commitment: BLAKE2b-256 of auth_bundles_digest, personalized
        // with the consensus branch ID to domain-separate across network upgrades.
        let mut personal = [0; 16];
        personal[..12].copy_from_slice(txid::ZCASH_AUTH_PERSONALIZATION_PREFIX);
        (&mut personal[12..])
            .write_u32_le(self.data.consensus_branch_id.into())
            .unwrap();

        let mut h = txid::hasher(&personal);
        h.write_all(auth_bundles_digest.as_bytes()).unwrap();
        h.finalize()
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
#[cfg(all(feature = "sapling", feature = "orchard"))]
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
#[cfg(all(feature = "sapling", feature = "orchard"))]
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

    /// Returns the digest of the Ironwood bundle of a version 6 transaction, or `None` if
    /// the transaction has no Ironwood bundle.
    ///
    /// When a version 6 transaction ID is derived from these digests, `None` is combined as
    /// the empty Ironwood bundle digest using the Ironwood bundle personalization.
    pub fn ironwood_digest(&self) -> Option<&A> {
        self.ironwood_digest.as_ref()
    }
}

#[cfg(all(feature = "sapling", feature = "orchard"))]
pub trait TransactionDigest<A: Authorization> {
    type HeaderDigest;
    type TransparentDigest;
    type SaplingDigest;
    type OrchardDigest;
    /// The digest type produced for the Ironwood bundle in version 6 transactions.
    type IronwoodDigest;

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
        transparent_bundle: Option<&transparent::Bundle<A::TransparentAuth>>,
    ) -> Self::TransparentDigest;

    fn digest_sapling(
        &self,
        version: TxVersion,
        sapling_bundle: Option<&sapling::Bundle<A::SaplingAuth, ZatBalance>>,
    ) -> Self::SaplingDigest;

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
    /// `None`. Transaction commitment digesters may instead return an empty authorizing data
    /// digest when no Ironwood bundle is present, and may use a different anchor commitment
    /// policy than transaction ID digesters.
    fn digest_ironwood(
        &self,
        ironwood_bundle: Option<&orchard::Bundle<A::OrchardAuth, ZatBalance>>,
    ) -> Self::IronwoodDigest;

    fn combine(
        &self,
        header_digest: Self::HeaderDigest,
        transparent_digest: Self::TransparentDigest,
        sapling_digest: Self::SaplingDigest,
        orchard_digest: Self::OrchardDigest,
        ironwood_digest: Self::IronwoodDigest,
    ) -> Self::Digest;
}

#[cfg(all(feature = "sapling", feature = "orchard"))]
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
    /// A value pool delta entry has no corresponding effecting bundle.
    MissingEffectBundle {
        /// The raw `bundleType`.
        bundle_type: u64,
    },
    /// `mValuePoolDeltas` contains an entry with `bundleType = FeeBundleId`
    /// and a non-ZEC `assetClass`. (Bundle-local rule: fee amounts are
    /// denominated in ZEC and no other asset.)
    FeeAssetClassNotZec { asset_class: u8 },
    /// `mValuePoolDeltas` contains an entry with
    /// `bundleType = CoinbaseBundleId` and a non-ZEC `assetClass`.
    /// (Bundle-local rule: the block subsidy is denominated in ZEC and no
    /// other asset.)
    CoinbaseAssetClassNotZec { asset_class: u8 },
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
    /// `blockSubsidy - lockboxValue`. (Cross-bundle rule.)
    CoinbaseValueDeltaMismatch {
        /// The expected delta, which may lie outside the `ZatBalance` range.
        expected: i64,
        /// The delta encoded in `mValuePoolDeltas`.
        actual: ZatBalance,
    },
    /// A coinbase transaction has a negative fee delta in
    /// `mValuePoolDeltas[(FeeBundleId, Zec)]`. The coinbase fee delta
    /// represents fees collected from other transactions in the block and
    /// must be nonnegative.
    CoinbaseFeeDeltaNegative { value: ZatBalance },
    /// A non-coinbase transaction has a positive fee delta in
    /// `mValuePoolDeltas[(FeeBundleId, Zec)]`. Fees paid are encoded as
    /// negative deltas (value removed from the transparent transaction
    /// value pool), so the fee delta must be nonpositive.
    NonCoinbaseFeeDeltaPositive { value: ZatBalance },
    /// The ZIP 233 NSM value pool delta is positive. The amount removed from
    /// circulation is encoded as a nonpositive delta.
    Zip233DeltaPositive { value: ZatBalance },
    /// The per-asset sum of all entries in `mValuePoolDeltas` must be zero
    /// for every transaction, coinbase included. The sum is accumulated in a
    /// wider signed type, so intermediate values outside the `ZatBalance`
    /// range do not cause a spurious failure; only the final sum is required
    /// to be zero. This variant is returned when that final sum is nonzero,
    /// indicating that value would be created or destroyed by the
    /// transaction.
    ValueImbalance {
        bundle_type_for_asset: u64,
        asset_class: u8,
        /// The final per-asset sum, which may lie outside the `ZatBalance`
        /// range.
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
            V7ConsensusError::FeeAssetClassNotZec { asset_class } => write!(
                f,
                "fee bundle value pool delta has non-ZEC assetClass {:#x}",
                asset_class
            ),
            V7ConsensusError::CoinbaseAssetClassNotZec { asset_class } => write!(
                f,
                "coinbase bundle value pool delta has non-ZEC assetClass {:#x}",
                asset_class
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
                "coinbase bundle value pool delta is {}, but blockSubsidy - lockboxValue is {}",
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
            V7ConsensusError::ValueImbalance {
                bundle_type_for_asset,
                asset_class,
                sum,
            } => write!(
                f,
                "value pool deltas do not sum to zero for assetClass={:#x} (any-bundleType={}): sum={}",
                asset_class, bundle_type_for_asset, sum
            ),
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
    /// Rules that require block or UTXO context are *not* checked here and
    /// must be enforced by the consumer: the per-block sum of fee bundle
    /// values, the ZIP 235 NSM fee contribution and the resulting miner fee
    /// available to the coinbase transaction, exactly one coinbase transaction
    /// first in the block, the coinbase bundle's `blockHeight`, `blockSubsidy`
    /// and `lockboxValue` matching the block and issuance schedule, and the
    /// transparent bundle's value pool delta matching the sum of its input
    /// values less its output values.
    pub fn check_v7_consensus_rules(&self) -> Result<(), V7ConsensusError> {
        if self.version != TxVersion::V7 {
            return Err(V7ConsensusError::NotV7);
        }
        if !TxVersion::V7.valid_in_branch(self.consensus_branch_id) {
            return Err(V7ConsensusError::NotActivated {
                branch_id: self.consensus_branch_id,
            });
        }
        let expiry_height = u32::from(self.expiry_height);
        if expiry_height > zip248::MAX_EXPIRY_HEIGHT {
            return Err(V7ConsensusError::InvalidExpiryHeight { expiry_height });
        }

        let coinbase_bundle = self.coinbase_bundle.as_ref();
        let is_coinbase = coinbase_bundle.is_some();

        // [ZIP 248 §Bundle availability]: every value pool delta entry must
        // name a registered bundle type and variant. The byte validator also
        // checks the effect and auth maps, which a typed transaction cannot
        // represent for unregistered types.
        for (key, (bundle_variant, _)) in self.value_pool_deltas.iter() {
            let bundle_type = key.bundle_type();
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
            if zip248::bundle_registry_row(bundle_type).is_none_or(|row| !row.value_pool_deltas) {
                return Err(V7ConsensusError::UnregisteredBundleType {
                    bundle_type: bundle_type.to_u64(),
                });
            }
        }

        // [ZIP 248 §Bundle-local rules]: each value pool delta entry for a
        // bundle type with effecting data must have a corresponding effecting
        // bundle.
        for (key, _) in self.value_pool_deltas.iter() {
            let present = match key.bundle_type() {
                zip248::BundleType::TRANSPARENT => self.transparent_bundle.is_some(),
                zip248::BundleType::COINBASE => self.coinbase_bundle.is_some(),
                zip248::BundleType::SAPLING => self.sapling_bundle.is_some(),
                zip248::BundleType::ORCHARD => self.orchard_bundle.is_some(),
                zip248::BundleType::IRONWOOD => self.ironwood_bundle.is_some(),
                _ => true,
            };
            if !present {
                return Err(V7ConsensusError::MissingEffectBundle {
                    bundle_type: key.bundle_type().to_u64(),
                });
            }
        }

        // [ZIP 248 §Bundle-local rules]: fee and coinbase value pool delta
        // entries are denominated in ZEC. Other bundle types may carry
        // per-asset deltas; per-asset conservation below applies to them.
        for (key, _) in self.value_pool_deltas.iter() {
            if key.asset_class() != zip248::ASSET_CLASS_ZEC {
                match key.bundle_type() {
                    zip248::BundleType::FEE => {
                        return Err(V7ConsensusError::FeeAssetClassNotZec {
                            asset_class: key.asset_class(),
                        });
                    }
                    zip248::BundleType::COINBASE => {
                        return Err(V7ConsensusError::CoinbaseAssetClassNotZec {
                            asset_class: key.asset_class(),
                        });
                    }
                    _ => {}
                }
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
            .iter()
            .find_map(|(key, &(_, value))| {
                (key.bundle_type() == zip248::BundleType::FEE
                    && key.asset_class() == zip248::ASSET_CLASS_ZEC)
                    .then_some(value)
            })
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
            .iter()
            .find_map(|(key, &(_, value))| {
                (key.bundle_type() == zip248::BundleType::ZIP233_NSM
                    && key.asset_class() == zip248::ASSET_CLASS_ZEC)
                    .then_some(value)
            })
            && i64::from(nsm_delta) > 0
        {
            return Err(V7ConsensusError::Zip233DeltaPositive { value: nsm_delta });
        }

        // [ZIP 248 §Cross-bundle and chain-context rules]: the coinbase
        // bundle's value pool delta is the block subsidy less the lockbox
        // deposit. Both components are in the bundle's effecting data. ZIP 235
        // reduces the miner fee available to the coinbase transaction; it does
        // not change this relation.
        if let Some(coinbase_bundle) = coinbase_bundle {
            let expected = i64::from(coinbase_bundle.value_pool_delta());
            let actual = self
                .value_pool_deltas
                .coinbase_value()
                .unwrap_or(ZatBalance::zero());
            if i64::from(actual) != expected {
                return Err(V7ConsensusError::CoinbaseValueDeltaMismatch { expected, actual });
            }
        }

        // [ZIP 248 §Cross-bundle and chain-context rules]: per-asset
        // conservation. The sum of all VP deltas for each
        // (assetClass, assetUuid) must be zero, i.e. no value is created or
        // destroyed. This holds for coinbase transactions too: the part of
        // the block subsidy that the transaction pays out enters the
        // transparent transaction value pool as the coinbase bundle's delta,
        // and the fees collected enter it as the fee bundle's delta.
        //
        // Group ALL entries (known + unknown) by (assetClass, assetUuid) and
        // verify the sum is zero for each asset. Individual entries are
        // bounded by `ZatBalance`; the accumulation is widened so that an
        // intermediate sum outside that range does not fail a transaction
        // whose mathematical total is zero.
        let mut by_asset: BTreeMap<(u8, [u8; 64]), (BundleType, i128)> = BTreeMap::new();
        for entry in self.value_pool_deltas.to_wire_entries() {
            let asset_key = (
                entry.asset_class(),
                entry.asset_uuid().copied().unwrap_or([0u8; 64]),
            );
            let acc = by_asset
                .entry(asset_key)
                .or_insert((entry.bundle_type(), 0));
            acc.1 += i128::from(i64::from(entry.value()));
        }
        for ((asset_class, _), (any_bundle_type, sum)) in by_asset {
            if sum != 0 {
                return Err(V7ConsensusError::ValueImbalance {
                    bundle_type_for_asset: any_bundle_type.to_u64(),
                    asset_class,
                    sum,
                });
            }
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

#[cfg(all(
    any(test, feature = "test-dependencies"),
    feature = "sapling",
    feature = "orchard"
))]
pub mod testing {
    use proptest::prelude::*;

    use ::transparent::bundle::testing::{self as transparent};
    use zcash_protocol::consensus::BranchId;

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
            transparent_bundle in transparent::arb_bundle(),
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
                sapling_bundle,
                orchard_bundle,
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
            transparent_bundle in transparent::arb_bundle(),
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
                Zatoshis::from_u64(zip233_amount).unwrap(),
                transparent_bundle,
                sapling_bundle,
                orchard_bundle,
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
