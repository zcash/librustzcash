//! Structs and methods for handling Zcash transactions.
pub mod builder;
pub mod components;
pub mod fees;
pub mod sighash;
mod sighash_v4;
mod sighash_v5;
mod sighash_v6;

pub mod txid;
pub mod zip248;

#[cfg(any(test, feature = "test-dependencies"))]
pub mod tests;

use crate::encoding::{ReadBytesExt, WriteBytesExt};
use alloc::vec::Vec;
use blake2b_simd::Hash as Blake2bHash;
use core::convert::TryFrom;
use core::fmt::Debug;
use core::ops::Deref;
use corez::io::{self, Read, Write};

use ::transparent::bundle::{self as transparent, OutPoint, TxIn, TxOut};
use zcash_encoding::{CompactSize, Vector};
use zcash_protocol::{
    consensus::{BlockHeight, BranchId},
    value::{BalanceError, ZatBalance, Zatoshis},
};
// `valid_in_branch` matches on every branch by bare name.
use zcash_protocol::consensus::BranchId::*;

use self::{
    components::{
        orchard as orchard_serialization, sapling as sapling_serialization,
        sprout::{self, JsDescription},
    },
    txid::{BlockTxCommitmentDigester, TxIdDigester, to_txid},
};
use ::transparent::util::sha256d::{HashReader, HashWriter};

#[cfg(feature = "circuits")]
use ::sapling::builder as sapling_builder;

use zcash_protocol::constants::{
    V3_TX_VERSION, V3_VERSION_GROUP_ID, V4_TX_VERSION, V4_VERSION_GROUP_ID, V5_TX_VERSION,
    V5_VERSION_GROUP_ID,
};

use zcash_protocol::constants::{V6_TX_VERSION, V6_VERSION_GROUP_ID};
#[cfg(zcash_unstable = "nutachyon")]
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
    /// Transaction version 7, introduced by the NuTachyon network upgrade.
    ///
    /// V7 initially has the same fields and digest structure as V6.
    #[cfg(zcash_unstable = "nutachyon")]
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
                #[cfg(zcash_unstable = "nutachyon")]
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
                #[cfg(zcash_unstable = "nutachyon")]
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
            #[cfg(zcash_unstable = "nutachyon")]
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
            #[cfg(zcash_unstable = "nutachyon")]
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
            #[cfg(zcash_unstable = "nutachyon")]
            TxVersion::V7 => true,
        }
    }

    /// Returns `true` if this transaction version supports the Orchard protocol.
    pub fn has_orchard(&self) -> bool {
        match self {
            TxVersion::Sprout(_) | TxVersion::V3 | TxVersion::V4 => false,
            TxVersion::V5 => true,
            TxVersion::V6 => true,
            #[cfg(zcash_unstable = "nutachyon")]
            TxVersion::V7 => true,
        }
    }

    /// Returns `true` if this transaction version supports the Ironwood protocol.
    pub fn has_ironwood(&self) -> bool {
        match self {
            TxVersion::Sprout(_) | TxVersion::V3 | TxVersion::V4 | TxVersion::V5 => false,
            TxVersion::V6 => true,
            #[cfg(zcash_unstable = "nutachyon")]
            TxVersion::V7 => true,
        }
    }

    #[cfg(all(feature = "zip-233", zcash_unstable = "zip233"))]
    /// Returns whether this implementation supports ZIP 233 for this version and branch.
    ///
    /// No implemented format supports ZIP 233. In particular, NU7 preserves the v5/v6
    /// formats, and the experimental V7 scaffold does not implement ZIP 248 value-pool deltas.
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
            #[cfg(zcash_unstable = "nutachyon")]
            BranchId::NuTachyon => TxVersion::V7,
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
                #[cfg(zcash_unstable = "nutachyon")]
                NuTachyon => false,
            },
            TxVersion::V5 => match consensus_branch_id {
                Sprout | Overwinter | Sapling | Blossom | Heartwood | Canopy => false,
                Nu5 | Nu6 | Nu6_1 | Nu6_2 => true,
                Nu6_3 => true,
                Nu7 => true,
                #[cfg(zcash_unstable = "nutachyon")]
                NuTachyon => true,
            },
            TxVersion::V6 => match consensus_branch_id {
                Sprout | Overwinter | Sapling | Blossom | Heartwood | Canopy | Nu5 | Nu6
                | Nu6_1 | Nu6_2 => false,
                Nu6_3 => true, // Ironwood / NU6.3
                Nu7 => true,   // NU7 retains the existing v6 transaction format.
                #[cfg(zcash_unstable = "nutachyon")]
                NuTachyon => true,
            },
            #[cfg(zcash_unstable = "nutachyon")]
            TxVersion::V7 => consensus_branch_id == NuTachyon,
        }
    }
}

/// Authorization state for a bundle of transaction data.
pub trait Authorization {
    type TransparentAuth: transparent::Authorization;
    type SaplingAuth: sapling::bundle::Authorization;
    type OrchardAuth: orchard::bundle::Authorization;
}

/// [`Authorization`] marker type for fully-authorized transactions.
#[derive(Clone, Debug)]
pub struct Authorized;

impl Authorization for Authorized {
    type TransparentAuth = transparent::Authorized;
    type SaplingAuth = sapling::bundle::Authorized;
    type OrchardAuth = orchard::bundle::Authorized;
}

/// [`Authorization`] marker type for non-coinbase transactions without authorization data.
///
/// Currently this includes Sapling proofs because the types in this crate support v4
/// transactions, which commit to the Sapling proofs in the transaction digest.
pub struct Unauthorized;

#[cfg(feature = "circuits")]
impl Authorization for Unauthorized {
    type TransparentAuth = ::transparent::builder::Unauthorized;
    type SaplingAuth =
        sapling_builder::InProgress<sapling_builder::Proven, sapling_builder::Unsigned>;
    type OrchardAuth =
        orchard::builder::InProgress<orchard::builder::Unproven, orchard::builder::Unauthorized>;
}

/// [`Authorization`] marker type for coinbase transactions without authorization data.
#[cfg(feature = "circuits")]
struct Coinbase;

#[cfg(feature = "circuits")]
impl Authorization for Coinbase {
    type TransparentAuth = ::transparent::builder::Coinbase;
    type SaplingAuth =
        sapling_builder::InProgress<sapling_builder::Proven, sapling_builder::Unsigned>;
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
/// - `bundles`: An ordered map of protocol bundles keyed by `(bundleType, bundleVariant)`.
#[derive(Debug)]
pub struct TransactionData<A: Authorization> {
    version: TxVersion,
    consensus_branch_id: BranchId,
    lock_time: u32,
    expiry_height: BlockHeight,
    value_pool_deltas: zip248::ValuePoolDeltas,
    ironwood_bundle: Option<orchard::bundle::Bundle<A::OrchardAuth, ZatBalance>>,
    bundles: zip248::BundleMap<A>,
}

impl Clone for TransactionData<Authorized> {
    fn clone(&self) -> Self {
        TransactionData {
            version: self.version,
            consensus_branch_id: self.consensus_branch_id,
            lock_time: self.lock_time,
            expiry_height: self.expiry_height,
            value_pool_deltas: self.value_pool_deltas.clone(),
            ironwood_bundle: self.ironwood_bundle.clone(),
            bundles: self.bundles.clone(),
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
    /// Derives value pool deltas from the shielded bundle value balances and
    /// collects the supplied bundles into a [`BundleMap`](zip248::BundleMap).
    fn build_bundle_map(
        value_pool_deltas: &mut zip248::ValuePoolDeltas,
        transparent_bundle: Option<transparent::Bundle<A::TransparentAuth>>,
        sprout_bundle: Option<sprout::Bundle>,
        sapling_bundle: Option<sapling::Bundle<A::SaplingAuth, ZatBalance>>,
        orchard_bundle: Option<orchard::Bundle<A::OrchardAuth, ZatBalance>>,
    ) -> zip248::BundleMap<A> {
        if let Some(ref b) = sapling_bundle {
            value_pool_deltas.set_sapling(*b.value_balance());
        }
        if let Some(ref b) = orchard_bundle {
            value_pool_deltas.set_orchard(*b.value_balance());
        }

        let mut bundles = zip248::BundleMap::new();
        if let Some(b) = transparent_bundle {
            bundles.insert_transparent(b);
        }
        if let Some(b) = sprout_bundle {
            bundles.insert_sprout(b);
        }
        if let Some(b) = sapling_bundle {
            bundles.insert_sapling(b);
        }
        if let Some(b) = orchard_bundle {
            bundles.insert_orchard(b);
        }
        bundles
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
        value_pool_deltas.set_zip233(zip233_amount);

        let bundles = Self::build_bundle_map(
            &mut value_pool_deltas,
            transparent_bundle,
            sprout_bundle,
            sapling_bundle,
            orchard_bundle,
        );
        Self::from_parts_with_bundles(
            version,
            consensus_branch_id,
            lock_time,
            expiry_height,
            value_pool_deltas,
            bundles,
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
        Self::from_parts_v6_or_v7_with_zip233(
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

    /// Constructs a V7 [`TransactionData`] from the fields it currently shares with V6.
    #[cfg(zcash_unstable = "nutachyon")]
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
    /// The V7 scaffold does not implement ZIP 248 value-pool deltas. Nonzero amounts
    /// are rejected by [`Self::freeze`] when this data is authorized.
    #[cfg(all(
        zcash_unstable = "nutachyon",
        feature = "zip-233",
        zcash_unstable = "zip233"
    ))]
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
        Self::from_parts_v6_or_v7_with_zip233(
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

    #[cfg(all(feature = "zip-233", zcash_unstable = "zip233"))]
    #[allow(clippy::too_many_arguments)]
    fn from_parts_v6_or_v7_with_zip233(
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
        Self::from_parts_v6_or_v7_inner(
            version,
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
        debug_assert!(match version {
            TxVersion::V6 => true,
            #[cfg(zcash_unstable = "nutachyon")]
            TxVersion::V7 => true,
            _ => false,
        });

        let mut value_pool_deltas = zip248::ValuePoolDeltas::empty();
        value_pool_deltas.set_zip233(zip233_amount);

        let bundles = Self::build_bundle_map(
            &mut value_pool_deltas,
            transparent_bundle,
            None,
            sapling_bundle,
            orchard_bundle,
        );

        TransactionData {
            version,
            consensus_branch_id,
            lock_time,
            expiry_height,
            value_pool_deltas,
            ironwood_bundle,
            bundles,
        }
    }

    /// Constructs a `TransactionData` directly from a [`BundleMap`] and [`ValuePoolDeltas`].
    pub fn from_parts_with_bundles(
        version: TxVersion,
        consensus_branch_id: BranchId,
        lock_time: u32,
        expiry_height: BlockHeight,
        value_pool_deltas: zip248::ValuePoolDeltas,
        bundles: zip248::BundleMap<A>,
    ) -> Self {
        TransactionData {
            version,
            consensus_branch_id,
            lock_time,
            expiry_height,
            value_pool_deltas,
            ironwood_bundle: None,
            bundles,
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
        self.bundles.transparent()
    }

    pub fn sprout_bundle(&self) -> Option<&sprout::Bundle> {
        self.bundles.sprout()
    }

    pub fn sapling_bundle(&self) -> Option<&sapling::Bundle<A::SaplingAuth, ZatBalance>> {
        self.bundles.sapling()
    }

    pub fn orchard_bundle(&self) -> Option<&orchard::Bundle<A::OrchardAuth, ZatBalance>> {
        self.bundles.orchard()
    }

    /// Returns the ZIP 248 value pool deltas.
    pub fn value_pool_deltas(&self) -> &zip248::ValuePoolDeltas {
        &self.value_pool_deltas
    }

    /// Returns the ZIP 248 bundle map.
    pub fn bundles(&self) -> &zip248::BundleMap<A> {
        &self.bundles
    }

    pub fn ironwood_bundle(&self) -> Option<&orchard::Bundle<A::OrchardAuth, ZatBalance>> {
        self.ironwood_bundle.as_ref()
    }

    /// Returns the configured experimental ZIP 233 amount, in zatoshis.
    ///
    /// No implemented transaction format supports a nonzero amount; [`Self::freeze`]
    /// rejects it when this data is authorized.
    #[cfg(all(feature = "zip-233", zcash_unstable = "zip233"))]
    pub fn zip233_amount(&self) -> Zatoshis {
        self.value_pool_deltas
            .zip233_amount()
            .unwrap_or(Zatoshis::ZERO)
    }

    /// Returns the fee amount, if explicitly set (V6+).
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
        let transparent_balance = self.bundles.transparent().map_or_else(
            || Ok(Some(ZatBalance::zero())),
            |b| b.value_balance(get_prevout),
        )?;

        transparent_balance
            .map(|transparent_balance| {
                let value_balances = [
                    transparent_balance,
                    self.bundles.sprout().map_or_else(
                        || Ok(ZatBalance::zero()),
                        |b| b.value_balance().ok_or(BalanceError::Overflow),
                    )?,
                    self.bundles
                        .sapling()
                        .map_or_else(ZatBalance::zero, |b| *b.value_balance()),
                    self.bundles
                        .orchard()
                        .map_or_else(ZatBalance::zero, |b| *b.value_balance()),
                    self.ironwood_bundle
                        .as_ref()
                        .map_or_else(ZatBalance::zero, |b| *b.value_balance()),
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
            digester.digest_transparent(self.bundles.transparent()),
            digester.digest_sapling(self.version, self.bundles.sapling()),
            digester.digest_orchard(self.version, self.bundles.orchard()),
            digester.digest_ironwood(self.ironwood_bundle.as_ref()),
        )
    }

    /// Produces V6 (ZIP 248) transaction digests using the TxIdDigester.
    pub fn digest_v6(&self) -> Zip244Digests<blake2b_simd::Hash> {
        use txid::{
            TxIdDigester, hash_v6_header, hash_v6_orchard_effects,
            hash_v6_sapling_effects, hash_v6_value_pool_deltas,
        };

        let digester = TxIdDigester;

        // Per-unknown-bundle effect and auth digests, in (bundleType, bundleVariant)
        // order. `BundleMap.unknown_bundles()` already iterates in BTreeMap key
        // order. The digests are taken from the `UnknownBundle` itself; the
        // caller is required to have supplied them at construction time, since
        // for unknown bundle types we don't have the bundle's digest algorithm.
        let unknown_effect_digests: Vec<(zip248::BundleId, blake2b_simd::Hash)> = self
            .bundles
            .unknown_bundles()
            .map(|(id, ub)| (*id, ub.effect_digest))
            .collect();
        let unknown_auth_digests: Vec<(zip248::BundleId, blake2b_simd::Hash)> = self
            .bundles
            .unknown_bundles()
            .filter_map(|(id, ub)| ub.auth_digest.map(|digest| (*id, digest)))
            .collect();

        Zip244Digests {
            header_digest: hash_v6_header(
                self.version,
                self.consensus_branch_id,
                self.lock_time,
                self.expiry_height,
            ),
            transparent_digests:
                <TxIdDigester as TransactionDigest<A>>::digest_transparent(
                    &digester,
                    self.bundles.transparent(),
                ),
            sapling_digest: self.bundles.sapling().map(hash_v6_sapling_effects),
            orchard_digest: self.bundles.orchard().map(hash_v6_orchard_effects),
            ironwood_digest: None,
            value_pool_deltas_digest: Some(hash_v6_value_pool_deltas(&self.value_pool_deltas)),
            unknown_effect_digests,
            unknown_auth_digests,
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
            bundles: self
                .bundles
                .map_authorization(f_transparent, f_sapling, |b| f_orchard(b)),
            ironwood_bundle: self.ironwood_bundle.and_then(|b| f_orchard(Some(b))),
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
            bundles: self
                .bundles
                .try_map_authorization(f_transparent, f_sapling, |b| f_orchard(b))?,
            ironwood_bundle: match self.ironwood_bundle {
                Some(b) => f_orchard(Some(b))?,
                None => None,
            },
        })
    }

    pub fn map_authorization<B: Authorization>(
        self,
        f_transparent: impl transparent::MapAuth<A::TransparentAuth, B::TransparentAuth>,
        mut f_sapling: impl sapling_serialization::MapAuth<A::SaplingAuth, B::SaplingAuth>,
        mut f_orchard: impl orchard_serialization::MapAuth<A::OrchardAuth, B::OrchardAuth>,
    ) -> TransactionData<B> {
        TransactionData {
            version: self.version,
            consensus_branch_id: self.consensus_branch_id,
            lock_time: self.lock_time,
            expiry_height: self.expiry_height,
            value_pool_deltas: self.value_pool_deltas,
            bundles: self.bundles.map_authorization(
                |tb| tb.map(|b| b.map_authorization(f_transparent)),
                |sb| {
                    sb.map(|b| {
                        b.map_authorization(
                            &mut f_sapling,
                            |f, p| f.map_spend_proof(p),
                            |f, p| f.map_output_proof(p),
                            |f, s| f.map_auth_sig(s),
                            |f, a| f.map_authorization(a),
                        )
                    })
                },
                |ob| {
                    ob.map(|b| {
                        b.map_authorization(
                            &mut f_orchard,
                            |f, _, s| f.map_spend_auth(s),
                            |f, a| f.map_authorization(a),
                        )
                    })
                },
            ),
            ironwood_bundle: self.ironwood_bundle.map(|b| {
                b.map_authorization(
                    &mut f_orchard,
                    |f, _, s| f.map_spend_auth(s),
                    |f, a| f.map_authorization(a),
                )
            }),
        }
    }
}

impl<A: Authorization> TransactionData<A> {
    pub fn sapling_value_balance(&self) -> ZatBalance {
        self.bundles
            .sapling()
            .map_or(ZatBalance::zero(), |b| *b.value_balance())
    }
}

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
        if self.zip233_amount != Zatoshis::ZERO
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

struct V6HeaderFragment {
    consensus_branch_id: BranchId,
    lock_time: u32,
    expiry_height: BlockHeight,
}

impl Transaction {
    fn from_data(data: TransactionData<Authorized>) -> io::Result<Self> {
        match data.version {
            TxVersion::Sprout(_) | TxVersion::V3 | TxVersion::V4 => Self::from_data_v4(data),
            TxVersion::V5 => Ok(Self::from_data_v5(data)),
            TxVersion::V6 => Ok(Self::from_data_v6(data)),
            #[cfg(zcash_unstable = "nutachyon")]
            TxVersion::V7 => Ok(Self::from_data_v6(data)),
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
        #[cfg(not(zcash_unstable = "nutachyon"))]
        assert_eq!(data.version, TxVersion::V6);
        #[cfg(zcash_unstable = "nutachyon")]
        assert!(matches!(data.version, TxVersion::V6 | TxVersion::V7));

        let txid = to_txid(
            data.version,
            data.consensus_branch_id,
            &data.digest_v6(),
        )
        .expect("is v6 tx");

        Transaction { txid, data }
    }

    pub fn into_data(self) -> TransactionData<Authorized> {
        self.data
    }

    pub fn txid(&self) -> TxId {
        self.txid
    }

    pub fn read<R: Read>(reader: R, consensus_branch_id: BranchId) -> io::Result<Self> {
        let mut reader = HashReader::new(reader);

        let version = TxVersion::read(&mut reader)?;
        match version {
            TxVersion::Sprout(_) | TxVersion::V3 | TxVersion::V4 => {
                Self::read_v4(reader, version, consensus_branch_id)
            }
            TxVersion::V5 => Self::read_v5(reader.into_base_reader(), version),
            TxVersion::V6 => Self::read_v6(reader.into_base_reader(), version),
            #[cfg(zcash_unstable = "nutachyon")]
            TxVersion::V7 => Self::read_v6(reader.into_base_reader(), version),
        }
    }

    #[allow(clippy::redundant_closure)]
    fn read_v4<R: Read>(
        mut reader: HashReader<R>,
        version: TxVersion,
        consensus_branch_id: BranchId,
    ) -> io::Result<Self> {
        let transparent_bundle = Self::read_transparent(&mut reader)?;

        let lock_time = reader.read_u32_le()?;
        let expiry_height: BlockHeight = if version.has_overwinter() {
            reader.read_u32_le()?.into()
        } else {
            0u32.into()
        };

        let (value_balance, shielded_spends, shielded_outputs) =
            sapling_serialization::read_v4_components(&mut reader, version.has_sapling())?;

        let sprout_bundle = if version.has_sprout() {
            let joinsplits = Vector::read(&mut reader, |r| {
                JsDescription::read(r, version.has_sapling())
            })?;

            if !joinsplits.is_empty() {
                let mut bundle = sprout::Bundle {
                    joinsplits,
                    joinsplit_pubkey: [0; 32],
                    joinsplit_sig: [0; 64],
                };
                reader.read_exact(&mut bundle.joinsplit_pubkey)?;
                reader.read_exact(&mut bundle.joinsplit_sig)?;
                Some(bundle)
            } else {
                None
            }
        } else {
            None
        };

        let binding_sig = if version.has_sapling()
            && !(shielded_spends.is_empty() && shielded_outputs.is_empty())
        {
            let mut sig = [0; 64];
            reader.read_exact(&mut sig)?;
            Some(redjubjub::Signature::from(sig))
        } else {
            None
        };

        let mut txid = [0; 32];
        let hash_bytes = reader.into_hash();
        txid.copy_from_slice(&hash_bytes);

        let sapling_bundle = binding_sig.and_then(|binding_sig| {
            sapling::Bundle::from_parts(
                shielded_spends,
                shielded_outputs,
                value_balance,
                sapling::bundle::Authorized { binding_sig },
            )
        });

        let mut bundles = zip248::BundleMap::new();
        if let Some(b) = transparent_bundle {
            bundles.insert_transparent(b);
        }
        if let Some(b) = sprout_bundle {
            bundles.insert_sprout(b);
        }
        let mut vp = zip248::ValuePoolDeltas::empty();
        if let Some(ref b) = sapling_bundle {
            vp.set_sapling(*b.value_balance());
        }
        if let Some(b) = sapling_bundle {
            bundles.insert_sapling(b);
        }

        Ok(Transaction {
            txid: TxId::from_bytes(txid),
            data: TransactionData {
                version,
                consensus_branch_id,
                lock_time,
                expiry_height,
                value_pool_deltas: vp,
                bundles,
                ironwood_bundle: None,
            },
        })
    }

    fn read_transparent<R: Read>(
        mut reader: R,
    ) -> io::Result<Option<transparent::Bundle<transparent::Authorized>>> {
        let vin = Vector::read(&mut reader, TxIn::read)?;
        let vout = Vector::read(&mut reader, TxOut::read)?;
        Ok(if vin.is_empty() && vout.is_empty() {
            None
        } else {
            Some(transparent::Bundle {
                vin,
                vout,
                authorization: transparent::Authorized,
            })
        })
    }

    fn read_amount<R: Read>(mut reader: R) -> io::Result<ZatBalance> {
        let mut tmp = [0; 8];
        reader.read_exact(&mut tmp)?;
        ZatBalance::from_i64_le_bytes(tmp)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "valueBalance out of range"))
    }

    fn read_v5<R: Read>(mut reader: R, version: TxVersion) -> io::Result<Self> {
        let (consensus_branch_id, lock_time, expiry_height) =
            Self::read_header_fragment(&mut reader)?;

        let transparent_bundle = Self::read_transparent(&mut reader)?;
        let sapling_bundle = sapling_serialization::read_v5_bundle(&mut reader)?;
        let orchard_bundle =
            orchard_serialization::read_v5_bundle(&mut reader, consensus_branch_id)?;

        let mut bundles = zip248::BundleMap::new();
        let mut vp = zip248::ValuePoolDeltas::empty();
        if let Some(b) = transparent_bundle {
            bundles.insert_transparent(b);
        }
        if let Some(ref b) = sapling_bundle {
            vp.set_sapling(*b.value_balance());
        }
        if let Some(b) = sapling_bundle {
            bundles.insert_sapling(b);
        }
        if let Some(ref b) = orchard_bundle {
            vp.set_orchard(*b.value_balance());
        }
        if let Some(b) = orchard_bundle {
            bundles.insert_orchard(b);
        }

        let data = TransactionData {
            version,
            consensus_branch_id,
            lock_time,
            expiry_height,
            value_pool_deltas: vp,
            bundles,
            ironwood_bundle: None,
        };

        Ok(Self::from_data_v5(data))
    }

    fn read_v6<R: Read>(mut reader: R, version: TxVersion) -> io::Result<Self> {
        // 1. Header (5 × u32)
        let V6HeaderFragment {
            consensus_branch_id,
            lock_time,
            expiry_height,
        } = Self::read_v6_header_fragment(&mut reader)?;

        // 2. Value pool deltas map
        let n_vp_deltas = CompactSize::read_t::<_, usize>(&mut reader)?;
        let mut vp = zip248::ValuePoolDeltas::empty();
        for _ in 0..n_vp_deltas {
            let entry = zip248::ValuePoolDeltaEntry::read(&mut reader)?;
            let key = zip248::ValuePoolDeltaKey {
                bundle_type: entry.bundle_type,
                asset_class: entry.asset_class,
                asset_uuid: entry.asset_uuid.unwrap_or([0u8; 64]),
            };
            vp.insert_raw(key, entry.bundle_variant, entry.value);
        }

        // 3. Effect bundles map
        let n_effect_bundles = CompactSize::read_t::<_, usize>(&mut reader)?;
        let bundles = zip248::BundleMap::new();
        let mut sapling_effect_data: Option<Vec<u8>> = None;
        let mut orchard_effect_data: Option<Vec<u8>> = None;
        let mut transparent_effect_data: Option<Vec<u8>> = None;

        for _ in 0..n_effect_bundles {
            let (id, data) = zip248::read_bundle_data_framing(&mut reader)?;
            match id.bundle_type {
                zip248::BUNDLE_TYPE_TRANSPARENT => {
                    transparent_effect_data = Some(data);
                }
                zip248::BUNDLE_TYPE_SAPLING => {
                    sapling_effect_data = Some(data);
                }
                zip248::BUNDLE_TYPE_ORCHARD => {
                    orchard_effect_data = Some(data);
                }
                _ => {
                    // ZIP 248 §"Implications for Wallets" requires the
                    // bundle_effects_digest to be supplied externally for
                    // unknown bundle types; we cannot derive it from the
                    // opaque bytes alone, so without a digest registry
                    // callback we cannot safely accept unknown bundles
                    // here. Refuse the transaction. A future revision of
                    // this reader that takes a `BundleId -> digest`
                    // registry from the caller can lift this restriction.
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "V6 transaction contains an unknown effect bundle type \
                         and no digest registry was supplied",
                    ));
                }
            }
        }

        // 4. Auth bundles map
        let n_auth_bundles = CompactSize::read_t::<_, usize>(&mut reader)?;
        let mut transparent_auth_data: Option<Vec<u8>> = None;
        let mut sapling_auth_data: Option<Vec<u8>> = None;
        let mut orchard_auth_data: Option<Vec<u8>> = None;

        for _ in 0..n_auth_bundles {
            let (id, data) = zip248::read_bundle_data_framing(&mut reader)?;
            match id.bundle_type {
                zip248::BUNDLE_TYPE_TRANSPARENT => {
                    transparent_auth_data = Some(data);
                }
                zip248::BUNDLE_TYPE_SAPLING => {
                    sapling_auth_data = Some(data);
                }
                zip248::BUNDLE_TYPE_ORCHARD => {
                    orchard_auth_data = Some(data);
                }
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "V6 transaction contains an unknown auth bundle type \
                         and no digest registry was supplied",
                    ));
                }
            }
        }

        // 5. Reconstruct typed bundles from effect + auth data
        // TODO: Parse transparent, sapling, orchard from their effect+auth byte vectors.
        // For now, this is a stub that leaves the bundles empty.
        // Full parsing will require reading from Cursor over the byte vectors.
        let _ = (transparent_effect_data, transparent_auth_data);
        let _ = (sapling_effect_data, sapling_auth_data);
        let _ = (orchard_effect_data, orchard_auth_data);

        let data = TransactionData {
            version,
            consensus_branch_id,
            lock_time,
            expiry_height: expiry_height.into(),
            value_pool_deltas: vp,
            bundles,
            ironwood_bundle: None,
        };

        Ok(Self::from_data_v6(data))
    }

    /// Utility function for reading header data common to v5 and later transactions.
    fn read_header_fragment<R: Read>(mut reader: R) -> io::Result<(BranchId, u32, BlockHeight)> {
        let consensus_branch_id = reader.read_u32_le().and_then(|value| {
            BranchId::try_from(value).map_err(|_e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    #[cfg(not(feature = "std"))]
                    "invalid consensus branch id",
                    #[cfg(feature = "std")]
                    format!(
                        "invalid consensus branch id 0x{}",
                        hex::encode(value.to_be_bytes())
                    ),
                )
            })
        })?;
        let lock_time = reader.read_u32_le()?;
        let expiry_height: BlockHeight = reader.read_u32_le()?.into();
        Ok((consensus_branch_id, lock_time, expiry_height))
    }

    /// Reads the V6 (ZIP 248) common transaction header fields after the
    /// 4-byte `header` and `nVersionGroupId` (which are read by the caller).
    /// V6 has no `zip233_amount` field in the header; ZIP 233 NSM lives in
    /// `mValuePoolDeltas`.
    fn read_v6_header_fragment<R: Read>(mut reader: R) -> io::Result<V6HeaderFragment> {
        let (consensus_branch_id, lock_time, expiry_height) =
            Self::read_header_fragment(&mut reader)?;

        Ok(V6HeaderFragment {
            consensus_branch_id,
            lock_time,
            expiry_height,
        })
    }

    #[cfg(feature = "temporary-zcashd")]
    pub fn temporary_zcashd_read_v5_sapling<R: Read>(
        reader: R,
    ) -> io::Result<Option<sapling::Bundle<sapling::bundle::Authorized, ZatBalance>>> {
        sapling_serialization::read_v5_bundle(reader)
    }

    #[cfg(zcash_unstable = "zfuture")]
    fn read_tze<R: Read>(mut reader: &mut R) -> io::Result<Option<tze::Bundle<tze::Authorized>>> {
        let vin = Vector::read(&mut reader, TzeIn::read)?;
        let vout = Vector::read(&mut reader, TzeOut::read)?;
        Ok(if vin.is_empty() && vout.is_empty() {
            None
        } else {
            Some(tze::Bundle {
                vin,
                vout,
                authorization: tze::Authorized,
            })
        })
    }

    pub fn write<W: Write>(&self, writer: W) -> io::Result<()> {
        match self.version {
            TxVersion::Sprout(_) | TxVersion::V3 | TxVersion::V4 => self.write_v4(writer),
            TxVersion::V5 => self.write_v5(writer),
            TxVersion::V6 => self.write_v6(writer),
            #[cfg(zcash_unstable = "nutachyon")]
            TxVersion::V7 => self.write_v6(writer),
        }
    }

    pub fn write_v4<W: Write>(&self, mut writer: W) -> io::Result<()> {
        if self.bundles.orchard().is_some() {
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
            self.bundles.sapling(),
            self.version.has_sapling(),
        )?;

        if self.version.has_sprout() {
            if let Some(bundle) = self.bundles.sprout() {
                Vector::write(&mut writer, &bundle.joinsplits, |w, e| e.write(w))?;
                writer.write_all(&bundle.joinsplit_pubkey)?;
                writer.write_all(&bundle.joinsplit_sig)?;
            } else {
                CompactSize::write(&mut writer, 0)?;
            }
        }

        if self.version.has_sapling()
            && let Some(bundle) = self.bundles.sapling()
        {
            writer.write_all(&<[u8; 64]>::from(bundle.authorization().binding_sig))?;
        }

        Ok(())
    }

    pub fn write_transparent<W: Write>(&self, mut writer: W) -> io::Result<()> {
        if let Some(bundle) = self.bundles.transparent() {
            Vector::write(&mut writer, &bundle.vin, |w, e| e.write(w))?;
            Vector::write(&mut writer, &bundle.vout, |w, e| e.write(w))?;
        } else {
            CompactSize::write(&mut writer, 0)?;
            CompactSize::write(&mut writer, 0)?;
        }

        Ok(())
    }

    pub fn write_v5<W: Write>(&self, mut writer: W) -> io::Result<()> {
        if self.bundles.sprout().is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Sprout components cannot be present when serializing to the V5 transaction format.",
            ));
        }
        self.write_v5_header(&mut writer)?;
        self.write_transparent(&mut writer)?;
        self.write_v5_sapling(&mut writer)?;
        orchard_serialization::write_v5_bundle(self.bundles.orchard(), &mut writer)?;

        Ok(())
    }

    pub fn write_v6<W: Write>(&self, mut writer: W) -> io::Result<()> {
        if self.bundles.sprout().is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Sprout components cannot be present when serializing to V6 or later transaction formats.",
            ));
        }
        #[cfg(zcash_unstable = "zfuture")]
        if self.bundles.tze().is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "TZE components cannot be present when serializing to the V6 transaction format \
                 until a bundleType is registered for them in ZIP 248.",
            ));
        }

        // 1. Header (5 × u32): version, versionGroupId, consensusBranchId, lockTime, expiryHeight
        self.write_v6_header(&mut writer)?;

        // 2. Value pool deltas map
        let vp_entries: Vec<_> = self.value_pool_deltas.iter().map(|(k, &v)| {
            zip248::ValuePoolDeltaEntry {
                bundle_type: k.bundle_type,
                bundle_variant: self.value_pool_deltas.bundle_variant(k.bundle_type)
                    .unwrap_or(zip248::BUNDLE_VARIANT_DEFAULT),
                asset_class: k.asset_class,
                asset_uuid: if k.asset_class == zip248::ASSET_CLASS_ZEC {
                    None
                } else {
                    Some(k.asset_uuid)
                },
                value: v,
            }
        }).collect();
        CompactSize::write(&mut writer, vp_entries.len())?;
        for entry in &vp_entries {
            entry.write(&mut writer)?;
        }

        // 3. Effect bundles map
        // Count bundles that have effect data (exclude value-only types 4, 5)
        let mut effect_bundles: Vec<(zip248::BundleId, Vec<u8>)> = Vec::new();

        if let Some(tb) = self.bundles.transparent() {
            let mut buf = Vec::new();
            zip248::write_v6_transparent_effects(&mut buf, tb)?;
            effect_bundles.push((zip248::BundleId::TRANSPARENT, buf));
        }
        if let Some(sb) = self.bundles.sapling() {
            let mut buf = Vec::new();
            sapling_serialization::write_v6_effects(&mut buf, sb)?;
            effect_bundles.push((zip248::BundleId::SAPLING, buf));
        }
        if let Some(ob) = self.bundles.orchard() {
            let mut buf = Vec::new();
            orchard_serialization::write_v6_effects(&mut buf, ob)?;
            effect_bundles.push((zip248::BundleId::ORCHARD, buf));
        }
        // Unknown bundles with effect data
        for (id, ub) in self.bundles.unknown_bundles() {
            effect_bundles.push((*id, ub.effect_data.clone()));
        }
        // Sort by bundle type (BTreeMap already gives us sorted order from iter())
        effect_bundles.sort_by_key(|(id, _)| *id);

        CompactSize::write(&mut writer, effect_bundles.len())?;
        for (id, data) in &effect_bundles {
            zip248::write_bundle_data_framing(&mut writer, id, data)?;
        }

        // 4. Auth bundles map
        let mut auth_bundles: Vec<(zip248::BundleId, Vec<u8>)> = Vec::new();

        if let Some(tb) = self.bundles.transparent() {
            if !tb.vin.is_empty() {
                let mut buf = Vec::new();
                zip248::write_v6_transparent_auth(&mut buf, tb)?;
                auth_bundles.push((zip248::BundleId::TRANSPARENT, buf));
            }
        }
        if let Some(sb) = self.bundles.sapling() {
            let mut buf = Vec::new();
            sapling_serialization::write_v6_auth(&mut buf, sb)?;
            auth_bundles.push((zip248::BundleId::SAPLING, buf));
        }
        if let Some(ob) = self.bundles.orchard() {
            let mut buf = Vec::new();
            orchard_serialization::write_v6_auth(&mut buf, ob)?;
            auth_bundles.push((zip248::BundleId::ORCHARD, buf));
        }
        // Unknown bundles with auth data
        for (id, ub) in self.bundles.unknown_bundles() {
            if let Some(ref auth_data) = ub.auth_data {
                auth_bundles.push((*id, auth_data.clone()));
            }
        }
        auth_bundles.sort_by_key(|(id, _)| *id);

        CompactSize::write(&mut writer, auth_bundles.len())?;
        for (id, data) in &auth_bundles {
            zip248::write_bundle_data_framing(&mut writer, id, data)?;
        }

        Ok(())
    }

    pub fn write_v5_header<W: Write>(&self, mut writer: W) -> io::Result<()> {
        self.version.write(&mut writer)?;
        writer.write_u32_le(u32::from(self.consensus_branch_id))?;
        writer.write_u32_le(self.lock_time)?;
        writer.write_u32_le(u32::from(self.expiry_height))?;
        Ok(())
    }

    /// Writes the V6 (ZIP 248) common transaction header: header, nVersionGroupId,
    /// nConsensusBranchId, lock_time, nExpiryHeight (5 × u32). The ZIP 233 NSM
    /// amount is not included here; it lives in `mValuePoolDeltas` under
    /// `bundleType = 5`.
    pub fn write_v6_header<W: Write>(&self, mut writer: W) -> io::Result<()> {
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
        sapling_serialization::write_v5_bundle(writer, self.bundles.sapling())
    }

    // TODO: should this be moved to `from_data` and stored?
    pub fn auth_commitment(&self) -> Blake2bHash {
        match self.data.version {
            #[cfg(zcash_unstable = "nu7")]
            TxVersion::V6 => self.auth_commitment_v6(),
            _ => self.data.digest(BlockTxCommitmentDigester),
        }
    }

    /// V6 auth commitment using the ZIP 248 tagged auth_bundles_digest structure.
    #[cfg(any(zcash_unstable = "nu7", zcash_unstable = "zfuture"))]
    fn auth_commitment_v6(&self) -> Blake2bHash {
        use txid::{
            hash_v6_auth_bundles, hash_v6_orchard_auth, hash_v6_sapling_auth,
            hash_v6_transparent_auth, v6_auth_digest_entries,
        };

        let transparent_auth_digest: Option<Blake2bHash> = self
            .data
            .bundles
            .transparent()
            .map(Some)
            .map(hash_v6_transparent_auth);
        let sapling_auth_digest: Option<Blake2bHash> = self
            .data
            .bundles
            .sapling()
            .map(Some)
            .map(hash_v6_sapling_auth);
        let orchard_auth_digest: Option<Blake2bHash> = self
            .data
            .bundles
            .orchard()
            .map(Some)
            .map(hash_v6_orchard_auth);

        let unknown_auth_digests: Vec<(zip248::BundleId, Blake2bHash)> = self
            .data
            .bundles
            .unknown_bundles()
            .filter_map(|(id, ub)| ub.auth_digest.map(|digest| (*id, digest)))
            .collect();

        let auth_bundles_digest = hash_v6_auth_bundles(v6_auth_digest_entries(
            transparent_auth_digest.as_ref(),
            sapling_auth_digest.as_ref(),
            orchard_auth_digest.as_ref(),
            &unknown_auth_digests,
        ));

        let mut personal = [0; 16];
        personal[..12].copy_from_slice(b"ZTxAuthHash_");
        use crate::encoding::WriteBytesExt;
        (&mut personal[12..])
            .write_u32_le(self.data.consensus_branch_id.into())
            .unwrap();

        let mut h = blake2b_simd::Params::new()
            .hash_length(32)
            .personal(&personal)
            .to_state();
        h.update(auth_bundles_digest.as_bytes());
        h.finalize()
    }
}

/// Digests of the prevouts, sequence numbers, and outputs of a transparent bundle.
///
/// The personalization of each digest is that of the digest scheme that contains it:
/// [ZIP 143] in [`Zip143Digests`], and [ZIP 244] in [`Zip244Digests`].
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
    /// (despite the `Zip244` name) a [ZIP 229] transaction ID for v6 transactions.
    ///
    /// [ZIP 244]: https://zips.z.cash/zip-0244
    /// [ZIP 229]: https://zips.z.cash/zip-0229#transactionidentifiersauthdigestsandsignaturedigests
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

/// The digests that make up a [ZIP 244] or [ZIP 229] transaction ID.
///
/// [ZIP 244]: https://zips.z.cash/zip-0244
/// [ZIP 229]: https://zips.z.cash/zip-0229#transactionidentifiersauthdigestsandsignaturedigests
#[derive(Clone, Debug)]
pub struct Zip244Digests<A> {
    pub(crate) header_digest: A,
    pub(crate) transparent_digests: Option<TransparentDigests<A>>,
    pub(crate) sapling_digest: Option<A>,
    pub(crate) orchard_digest: Option<A>,
    pub(crate) ironwood_digest: Option<A>,
    /// V6 (ZIP 248): digest of the value pool deltas map.
    pub(crate) value_pool_deltas_digest: Option<A>,
    /// Per-unknown-bundle effect digests, in `(bundleType, bundleVariant)` order.
    pub(crate) unknown_effect_digests: Vec<(zip248::BundleId, A)>,
    /// Per-unknown-bundle authorizing data digests, in `(bundleType, bundleVariant)` order.
    pub(crate) unknown_auth_digests: Vec<(zip248::BundleId, A)>,
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

pub enum DigestError {
    NotSigned,
}

#[cfg(any(test, feature = "test-dependencies"))]
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
            #[cfg(zcash_unstable = "nutachyon")]
            BranchId::NuTachyon => Just(TxVersion::V7).boxed(),
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
            let mut value_pool_deltas = super::zip248::ValuePoolDeltas::empty();
            let bundles = TransactionData::<Authorized>::build_bundle_map(
                &mut value_pool_deltas,
                transparent_bundle,
                None,
                sapling_bundle,
                orchard_bundle,
            );
            TransactionData {
                version,
                consensus_branch_id,
                lock_time,
                expiry_height: expiry_height.into(),
                value_pool_deltas,
                ironwood_bundle,
                bundles,
            }
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
            let mut value_pool_deltas = super::zip248::ValuePoolDeltas::empty();
            value_pool_deltas.set_zip233(if version.has_zip233(consensus_branch_id) {
                Zatoshis::from_u64(zip233_amount).unwrap()
            } else {
                Zatoshis::ZERO
            });
            let bundles = TransactionData::<Authorized>::build_bundle_map(
                &mut value_pool_deltas,
                transparent_bundle,
                None,
                sapling_bundle,
                orchard_bundle,
            );
            TransactionData {
                version,
                consensus_branch_id,
                lock_time,
                expiry_height: expiry_height.into(),
                value_pool_deltas,
                ironwood_bundle,
                bundles,
            }
        }
    }

    prop_compose! {
        pub fn arb_tx(branch_id: BranchId)(tx_data in arb_txdata(branch_id)) -> Transaction {
            Transaction::from_data(tx_data).unwrap()
        }
    }
}
