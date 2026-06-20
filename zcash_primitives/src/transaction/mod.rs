//! Structs and methods for handling Zcash transactions.
pub mod builder;
pub mod components;
pub mod fees;
pub mod sighash;
pub mod sighash_v4;
pub mod sighash_v5;
#[cfg(any(zcash_unstable = "nu6.3", zcash_unstable = "nu7"))]
pub mod sighash_v6;

pub mod txid;

#[cfg(any(test, feature = "test-dependencies"))]
pub mod tests;

use crate::encoding::{ReadBytesExt, WriteBytesExt};
use blake2b_simd::Hash as Blake2bHash;
use core::convert::TryFrom;
use core::fmt::Debug;
use core::ops::Deref;
use corez::io::{self, Read, Write};

use ::transparent::bundle::{self as transparent, OutPoint, TxIn, TxOut};
use orchard::bundle::ProofSizeEnforcement;
use zcash_encoding::{CompactSize, Vector};
use zcash_protocol::{
    consensus::{BlockHeight, BranchId},
    value::{BalanceError, ZatBalance, Zatoshis},
};

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

#[cfg(any(zcash_unstable = "nu6.3", zcash_unstable = "nu7"))]
use zcash_protocol::constants::{V6_TX_VERSION, V6_VERSION_GROUP_ID};

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
    /// Transaction version 6, specified in [ZIP 230](https://zips.z.cash/zip-0230).
    #[cfg(any(zcash_unstable = "nu6.3", zcash_unstable = "nu7"))]
    V6,
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
                #[cfg(any(zcash_unstable = "nu6.3", zcash_unstable = "nu7"))]
                (V6_TX_VERSION, V6_VERSION_GROUP_ID) => Ok(TxVersion::V6),
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
                #[cfg(any(zcash_unstable = "nu6.3", zcash_unstable = "nu7"))]
                TxVersion::V6 => V6_TX_VERSION,
            }
    }

    pub fn version_group_id(&self) -> u32 {
        match self {
            TxVersion::Sprout(_) => 0,
            TxVersion::V3 => V3_VERSION_GROUP_ID,
            TxVersion::V4 => V4_VERSION_GROUP_ID,
            TxVersion::V5 => V5_VERSION_GROUP_ID,
            #[cfg(any(zcash_unstable = "nu6.3", zcash_unstable = "nu7"))]
            TxVersion::V6 => V6_VERSION_GROUP_ID,
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
            #[cfg(any(zcash_unstable = "nu6.3", zcash_unstable = "nu7"))]
            TxVersion::V6 => false,
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
            #[cfg(any(zcash_unstable = "nu6.3", zcash_unstable = "nu7"))]
            TxVersion::V6 => true,
        }
    }

    /// Returns `true` if this transaction version supports the Orchard protocol.
    pub fn has_orchard(&self) -> bool {
        match self {
            TxVersion::Sprout(_) | TxVersion::V3 | TxVersion::V4 => false,
            TxVersion::V5 => true,
            #[cfg(any(zcash_unstable = "nu6.3", zcash_unstable = "nu7"))]
            TxVersion::V6 => true,
        }
    }

    /// Returns `true` if this transaction version supports the Ironwood protocol.
    #[cfg(zcash_unstable = "nu6.3")]
    pub fn has_ironwood(&self) -> bool {
        matches!(self, TxVersion::V6)
    }

    #[cfg(all(zcash_unstable = "nu7", feature = "zip-233"))]
    pub fn has_zip233(&self) -> bool {
        match self {
            TxVersion::Sprout(_) | TxVersion::V3 | TxVersion::V4 | TxVersion::V5 => false,
            #[cfg(any(zcash_unstable = "nu6.3", zcash_unstable = "nu7"))]
            TxVersion::V6 => true,
        }
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
            #[cfg(zcash_unstable = "nu6.3")]
            BranchId::Nu6_3 => TxVersion::V6,
            #[cfg(zcash_unstable = "nu7")]
            BranchId::Nu7 => TxVersion::V6,
        }
    }

    /// Returns `true` if this transaction version is valid for us in the specified consensus
    /// branch, `false` otherwise.
    pub fn valid_in_branch(&self, consensus_branch_id: BranchId) -> bool {
        use BranchId::*;
        // Note: we intentionally use `match` expressions instead of the `matches!`
        // macro below because we want exhaustivity.
        match self {
            TxVersion::Sprout(_) => consensus_branch_id == Sprout,
            TxVersion::V3 => consensus_branch_id == Overwinter,
            TxVersion::V4 => match consensus_branch_id {
                Sprout | Overwinter => false,
                Sapling | Blossom | Heartwood | Canopy | Nu5 | Nu6 | Nu6_1 | Nu6_2 => true,
                #[cfg(zcash_unstable = "nu6.3")]
                Nu6_3 => true,
                #[cfg(zcash_unstable = "nu7")]
                Nu7 => false, // ZIP 2003
            },
            TxVersion::V5 => match consensus_branch_id {
                Sprout | Overwinter | Sapling | Blossom | Heartwood | Canopy => false,
                Nu5 | Nu6 | Nu6_1 | Nu6_2 => true,
                #[cfg(zcash_unstable = "nu6.3")]
                Nu6_3 => true,
                #[cfg(zcash_unstable = "nu7")]
                Nu7 => true,
            },
            #[cfg(any(zcash_unstable = "nu6.3", zcash_unstable = "nu7"))]
            TxVersion::V6 => match consensus_branch_id {
                Sprout | Overwinter | Sapling | Blossom | Heartwood | Canopy | Nu5 | Nu6
                | Nu6_1 | Nu6_2 => false,
                #[cfg(zcash_unstable = "nu6.3")]
                Nu6_3 => true, // Ironwood / NU6.3
                #[cfg(zcash_unstable = "nu7")]
                Nu7 => true, // ZIP 230 or ZIP 248, whichever is chosen for activation
            },
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
#[derive(Debug)]
pub struct TransactionData<A: Authorization> {
    version: TxVersion,
    consensus_branch_id: BranchId,
    lock_time: u32,
    expiry_height: BlockHeight,
    #[cfg(all(zcash_unstable = "nu7", feature = "zip-233"))]
    zip233_amount: Zatoshis,
    transparent_bundle: Option<transparent::Bundle<A::TransparentAuth>>,
    sprout_bundle: Option<sprout::Bundle>,
    sapling_bundle: Option<sapling::Bundle<A::SaplingAuth, ZatBalance>>,
    orchard_bundle: Option<orchard::bundle::Bundle<A::OrchardAuth, ZatBalance>>,
    #[cfg(zcash_unstable = "nu6.3")]
    ironwood_bundle: Option<orchard::bundle::Bundle<A::OrchardAuth, ZatBalance>>,
}

impl Clone for TransactionData<Authorized> {
    fn clone(&self) -> Self {
        TransactionData {
            version: self.version,
            consensus_branch_id: self.consensus_branch_id,
            lock_time: self.lock_time,
            expiry_height: self.expiry_height,
            #[cfg(all(zcash_unstable = "nu7", feature = "zip-233"))]
            zip233_amount: self.zip233_amount,
            transparent_bundle: self.transparent_bundle.clone(),
            sprout_bundle: self.sprout_bundle.clone(),
            sapling_bundle: self.sapling_bundle.clone(),
            orchard_bundle: self.orchard_bundle.clone(),
            #[cfg(zcash_unstable = "nu6.3")]
            ironwood_bundle: self.ironwood_bundle.clone(),
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
    /// Constructs a `TransactionData` from its constituent parts.
    #[allow(clippy::too_many_arguments)]
    pub fn from_parts(
        version: TxVersion,
        consensus_branch_id: BranchId,
        lock_time: u32,
        expiry_height: BlockHeight,
        #[cfg(all(zcash_unstable = "nu7", feature = "zip-233"))] zip233_amount: Zatoshis,
        transparent_bundle: Option<transparent::Bundle<A::TransparentAuth>>,
        sprout_bundle: Option<sprout::Bundle>,
        sapling_bundle: Option<sapling::Bundle<A::SaplingAuth, ZatBalance>>,
        orchard_bundle: Option<orchard::Bundle<A::OrchardAuth, ZatBalance>>,
    ) -> Self {
        TransactionData {
            version,
            consensus_branch_id,
            lock_time,
            expiry_height,
            #[cfg(all(zcash_unstable = "nu7", feature = "zip-233"))]
            zip233_amount,
            transparent_bundle,
            sprout_bundle,
            sapling_bundle,
            orchard_bundle,
            #[cfg(zcash_unstable = "nu6.3")]
            ironwood_bundle: None,
        }
    }

    /// Constructs a V6 [`TransactionData`] from its constituent parts,
    /// including the Ironwood bundle.
    ///
    /// Both the Orchard and Ironwood bundle fields use [`orchard::Bundle`], but
    /// they are distinct V6 transaction fields with distinct bundle protocols.
    /// The `orchard_bundle` argument must contain a bundle constructed for
    /// [`orchard::BundleProtocol::OrchardPostNu6_3`], while `ironwood_bundle`
    /// must contain a bundle constructed for
    /// [`orchard::BundleProtocol::IronwoodPostNu6_3`]. Supplying a bundle for
    /// the wrong field is invalid and can be rejected by later serialization or
    /// commitment construction because the bundle flags and domains are protocol
    /// specific.
    #[cfg(zcash_unstable = "nu6.3")]
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
        TransactionData {
            version: TxVersion::V6,
            consensus_branch_id,
            lock_time,
            expiry_height,
            transparent_bundle,
            sprout_bundle: None,
            sapling_bundle,
            orchard_bundle,
            ironwood_bundle,
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

    pub fn sprout_bundle(&self) -> Option<&sprout::Bundle> {
        self.sprout_bundle.as_ref()
    }

    pub fn sapling_bundle(&self) -> Option<&sapling::Bundle<A::SaplingAuth, ZatBalance>> {
        self.sapling_bundle.as_ref()
    }

    pub fn orchard_bundle(&self) -> Option<&orchard::Bundle<A::OrchardAuth, ZatBalance>> {
        self.orchard_bundle.as_ref()
    }

    #[cfg(zcash_unstable = "nu6.3")]
    pub fn ironwood_bundle(&self) -> Option<&orchard::Bundle<A::OrchardAuth, ZatBalance>> {
        self.ironwood_bundle.as_ref()
    }

    #[cfg(all(zcash_unstable = "nu7", feature = "zip-233"))]
    pub fn zip233_amount(&self) -> Zatoshis {
        self.zip233_amount
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
                    #[cfg(zcash_unstable = "nu6.3")]
                    self.ironwood_bundle
                        .as_ref()
                        .map_or_else(ZatBalance::zero, |b| *b.value_balance()),
                    #[cfg(all(zcash_unstable = "nu7", feature = "zip-233"))]
                    -ZatBalance::from(self.zip233_amount),
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

    /// Computes this transaction's digest using the provided digest strategy.
    ///
    /// When `zcash_unstable = "nu6.3"` is enabled, version 6 transactions include the Ironwood
    /// bundle digest as a separate Orchard-shaped digest with Ironwood personalization. Earlier
    /// transaction versions do not include Ironwood in their digest.
    pub fn digest<D: TransactionDigest<A>>(&self, digester: D) -> D::Digest {
        digester.combine(
            digester.digest_header(
                self.version,
                self.consensus_branch_id,
                self.lock_time,
                self.expiry_height,
                #[cfg(all(zcash_unstable = "nu7", feature = "zip-233"))]
                &self.zip233_amount,
            ),
            digester.digest_transparent(self.transparent_bundle.as_ref()),
            digester.digest_sapling(self.version, self.sapling_bundle.as_ref()),
            digester.digest_orchard(self.version, self.orchard_bundle.as_ref()),
            #[cfg(zcash_unstable = "nu6.3")]
            digester.digest_ironwood(self.version, self.ironwood_bundle.as_ref()),
        )
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
    /// Under `zcash_unstable="nu6.3"`, `f_orchard` is also applied to the
    /// Ironwood bundle because Ironwood is represented with the Orchard bundle type.
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
        ) -> Option<orchard::bundle::Bundle<B::OrchardAuth, ZatBalance>>,
    ) -> TransactionData<B> {
        TransactionData {
            version: self.version,
            consensus_branch_id: self.consensus_branch_id,
            lock_time: self.lock_time,
            expiry_height: self.expiry_height,
            #[cfg(all(zcash_unstable = "nu7", feature = "zip-233"))]
            zip233_amount: self.zip233_amount,
            transparent_bundle: f_transparent(self.transparent_bundle),
            sprout_bundle: self.sprout_bundle,
            sapling_bundle: f_sapling(self.sapling_bundle),
            orchard_bundle: f_orchard(self.orchard_bundle),
            #[cfg(zcash_unstable = "nu6.3")]
            ironwood_bundle: f_orchard(self.ironwood_bundle),
        }
    }

    /// Maps the bundles from one type to another with fallible closures.
    ///
    /// This shouldn't be necessary for most use cases; it is provided for handling the
    /// transaction extraction logic in the `pczt` crate.
    ///
    /// Under `zcash_unstable="nu6.3"`, `f_orchard` is also applied to the
    /// Ironwood bundle because Ironwood is represented with the Orchard bundle type.
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
        )
            -> Result<Option<orchard::bundle::Bundle<B::OrchardAuth, ZatBalance>>, E>,
    ) -> Result<TransactionData<B>, E> {
        Ok(TransactionData {
            version: self.version,
            consensus_branch_id: self.consensus_branch_id,
            lock_time: self.lock_time,
            expiry_height: self.expiry_height,
            #[cfg(all(zcash_unstable = "nu7", feature = "zip-233"))]
            zip233_amount: self.zip233_amount,
            transparent_bundle: f_transparent(self.transparent_bundle)?,
            sprout_bundle: self.sprout_bundle,
            sapling_bundle: f_sapling(self.sapling_bundle)?,
            orchard_bundle: f_orchard(self.orchard_bundle)?,
            #[cfg(zcash_unstable = "nu6.3")]
            ironwood_bundle: f_orchard(self.ironwood_bundle)?,
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
            #[cfg(all(zcash_unstable = "nu7", feature = "zip-233"))]
            zip233_amount: self.zip233_amount,
            transparent_bundle: self
                .transparent_bundle
                .map(|b| b.map_authorization(f_transparent)),
            sprout_bundle: self.sprout_bundle,
            sapling_bundle: self.sapling_bundle.map(|b| {
                b.map_authorization(
                    &mut f_sapling,
                    |f, p| f.map_spend_proof(p),
                    |f, p| f.map_output_proof(p),
                    |f, s| f.map_auth_sig(s),
                    |f, a| f.map_authorization(a),
                )
            }),
            orchard_bundle: self.orchard_bundle.map(|b| {
                b.map_authorization(
                    &mut f_orchard,
                    |f, _, s| f.map_spend_auth(s),
                    |f, a| f.map_authorization(a),
                )
            }),
            #[cfg(zcash_unstable = "nu6.3")]
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
        self.sapling_bundle
            .as_ref()
            .map_or(ZatBalance::zero(), |b| *b.value_balance())
    }
}

impl TransactionData<Authorized> {
    pub fn freeze(self) -> io::Result<Transaction> {
        Transaction::from_data(self)
    }
}

#[cfg(any(zcash_unstable = "nu6.3", zcash_unstable = "nu7"))]
struct V6HeaderFragment {
    consensus_branch_id: BranchId,
    lock_time: u32,
    expiry_height: BlockHeight,
    #[cfg(all(zcash_unstable = "nu7", feature = "zip-233"))]
    zip233_amount: Zatoshis,
}

impl Transaction {
    fn from_data(data: TransactionData<Authorized>) -> io::Result<Self> {
        match data.version {
            TxVersion::Sprout(_) | TxVersion::V3 | TxVersion::V4 => Self::from_data_v4(data),
            TxVersion::V5 => Ok(Self::from_data_v5(data)),
            #[cfg(any(zcash_unstable = "nu6.3", zcash_unstable = "nu7"))]
            TxVersion::V6 => Ok(Self::from_data_v6(data)),
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
        let txid = to_txid(
            data.version,
            data.consensus_branch_id,
            &data.digest(TxIdDigester),
        );

        Transaction { txid, data }
    }

    #[cfg(any(zcash_unstable = "nu6.3", zcash_unstable = "nu7"))]
    fn from_data_v6(data: TransactionData<Authorized>) -> Self {
        let txid = to_txid(
            data.version,
            data.consensus_branch_id,
            &data.digest(TxIdDigester),
        );

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
            #[cfg(any(zcash_unstable = "nu6.3", zcash_unstable = "nu7"))]
            TxVersion::V6 => Self::read_v6(reader.into_base_reader(), version),
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

        Ok(Transaction {
            txid: TxId::from_bytes(txid),
            data: TransactionData {
                version,
                consensus_branch_id,
                lock_time,
                expiry_height,
                #[cfg(all(zcash_unstable = "nu7", feature = "zip-233"))]
                zip233_amount: Zatoshis::ZERO,
                transparent_bundle,
                sprout_bundle,
                sapling_bundle: binding_sig.and_then(|binding_sig| {
                    sapling::Bundle::from_parts(
                        shielded_spends,
                        shielded_outputs,
                        value_balance,
                        sapling::bundle::Authorized { binding_sig },
                    )
                }),
                orchard_bundle: None,
                #[cfg(zcash_unstable = "nu6.3")]
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

        #[cfg(all(zcash_unstable = "nu7", feature = "zip-233"))]
        let zip233_amount = Zatoshis::ZERO;

        let transparent_bundle = Self::read_transparent(&mut reader)?;
        let sapling_bundle = sapling_serialization::read_v5_bundle(&mut reader)?;
        let orchard_bundle = orchard_serialization::read_v5_bundle(
            &mut reader,
            match consensus_branch_id {
                BranchId::Sprout
                | BranchId::Overwinter
                | BranchId::Sapling
                | BranchId::Blossom
                | BranchId::Heartwood
                | BranchId::Canopy
                | BranchId::Nu5
                | BranchId::Nu6
                | BranchId::Nu6_1 => ProofSizeEnforcement::Unenforced,
                BranchId::Nu6_2 => ProofSizeEnforcement::Strict,
                #[cfg(zcash_unstable = "nu6.3")]
                BranchId::Nu6_3 => ProofSizeEnforcement::Strict,
                #[cfg(zcash_unstable = "nu7")]
                BranchId::Nu7 => ProofSizeEnforcement::Strict,
            },
        )?;

        let data = TransactionData {
            version,
            consensus_branch_id,
            lock_time,
            expiry_height,
            #[cfg(all(zcash_unstable = "nu7", feature = "zip-233"))]
            zip233_amount,
            transparent_bundle,
            sprout_bundle: None,
            sapling_bundle,
            orchard_bundle,
            #[cfg(zcash_unstable = "nu6.3")]
            ironwood_bundle: None,
        };

        Ok(Self::from_data_v5(data))
    }

    #[cfg(any(zcash_unstable = "nu6.3", zcash_unstable = "nu7"))]
    fn read_v6<R: Read>(mut reader: R, version: TxVersion) -> io::Result<Self> {
        let header_fragment = Self::read_v6_header_fragment(&mut reader)?;

        let transparent_bundle = Self::read_transparent(&mut reader)?;
        let sapling_bundle = sapling_serialization::read_v5_bundle(&mut reader)?;
        let orchard_bundle = orchard_serialization::read_v6_bundle(&mut reader)?;
        #[cfg(zcash_unstable = "nu6.3")]
        let ironwood_bundle = orchard_serialization::read_v6_bundle(&mut reader)?;

        let data = TransactionData {
            version,
            consensus_branch_id: header_fragment.consensus_branch_id,
            lock_time: header_fragment.lock_time,
            expiry_height: header_fragment.expiry_height,
            #[cfg(all(zcash_unstable = "nu7", feature = "zip-233"))]
            zip233_amount: header_fragment.zip233_amount,
            transparent_bundle,
            sprout_bundle: None,
            sapling_bundle,
            orchard_bundle,
            #[cfg(zcash_unstable = "nu6.3")]
            ironwood_bundle,
        };

        Ok(Self::from_data_v5(data))
    }

    /// Utility function for reading header data common to v5 and v6 transactions.
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

    #[cfg(any(zcash_unstable = "nu6.3", zcash_unstable = "nu7"))]
    fn read_v6_header_fragment<R: Read>(mut reader: R) -> io::Result<V6HeaderFragment> {
        let (consensus_branch_id, lock_time, expiry_height) =
            Self::read_header_fragment(&mut reader)?;

        Ok(V6HeaderFragment {
            consensus_branch_id,
            lock_time,
            expiry_height,
            #[cfg(all(zcash_unstable = "nu7", feature = "zip-233"))]
            zip233_amount: Self::read_zip233_amount(&mut reader)?,
        })
    }

    #[cfg(feature = "temporary-zcashd")]
    pub fn temporary_zcashd_read_v5_sapling<R: Read>(
        reader: R,
    ) -> io::Result<Option<sapling::Bundle<sapling::bundle::Authorized, ZatBalance>>> {
        sapling_serialization::read_v5_bundle(reader)
    }

    #[cfg(all(zcash_unstable = "nu7", feature = "zip-233"))]
    fn read_zip233_amount<R: Read>(mut reader: R) -> io::Result<Zatoshis> {
        Zatoshis::from_u64(reader.read_u64_le()?)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "zip233Amount out of range"))
    }

    pub fn write<W: Write>(&self, writer: W) -> io::Result<()> {
        match self.version {
            TxVersion::Sprout(_) | TxVersion::V3 | TxVersion::V4 => self.write_v4(writer),
            TxVersion::V5 => self.write_v5(writer),
            #[cfg(any(zcash_unstable = "nu6.3", zcash_unstable = "nu7"))]
            TxVersion::V6 => self.write_v6(writer),
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

        if self.version.has_sapling() {
            if let Some(bundle) = self.sapling_bundle.as_ref() {
                writer.write_all(&<[u8; 64]>::from(bundle.authorization().binding_sig))?;
            }
        }

        Ok(())
    }

    pub fn write_transparent<W: Write>(&self, mut writer: W) -> io::Result<()> {
        if let Some(bundle) = &self.transparent_bundle {
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

    #[cfg(any(zcash_unstable = "nu6.3", zcash_unstable = "nu7"))]
    pub fn write_v6<W: Write>(&self, mut writer: W) -> io::Result<()> {
        if self.sprout_bundle.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Sprout components cannot be present when serializing to the V6 transaction format.",
            ));
        }
        self.write_v6_header(&mut writer)?;

        self.write_transparent(&mut writer)?;
        self.write_v5_sapling(&mut writer)?;
        orchard_serialization::write_v6_bundle(self.orchard_bundle.as_ref(), &mut writer)?;
        #[cfg(zcash_unstable = "nu6.3")]
        orchard_serialization::write_v6_bundle(self.ironwood_bundle.as_ref(), &mut writer)?;

        Ok(())
    }

    pub fn write_v5_header<W: Write>(&self, mut writer: W) -> io::Result<()> {
        self.version.write(&mut writer)?;
        writer.write_u32_le(u32::from(self.consensus_branch_id))?;
        writer.write_u32_le(self.lock_time)?;
        writer.write_u32_le(u32::from(self.expiry_height))?;
        Ok(())
    }

    #[cfg(any(zcash_unstable = "nu6.3", zcash_unstable = "nu7"))]
    pub fn write_v6_header<W: Write>(&self, mut writer: W) -> io::Result<()> {
        self.version.write(&mut writer)?;
        writer.write_u32_le(u32::from(self.consensus_branch_id))?;
        writer.write_u32_le(self.lock_time)?;
        writer.write_u32_le(u32::from(self.expiry_height))?;

        #[cfg(all(zcash_unstable = "nu7", feature = "zip-233"))]
        writer.write_u64_le(self.zip233_amount.into())?;
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

    // TODO: should this be moved to `from_data` and stored?
    pub fn auth_commitment(&self) -> Blake2bHash {
        self.data.digest(BlockTxCommitmentDigester)
    }
}

#[derive(Clone, Debug)]
pub struct TransparentDigests<A> {
    pub prevouts_digest: A,
    pub sequence_digest: A,
    pub outputs_digest: A,
}

#[derive(Clone, Debug)]
pub struct TxDigests<A> {
    pub header_digest: A,
    pub transparent_digests: Option<TransparentDigests<A>>,
    pub sapling_digest: Option<A>,
    pub orchard_digest: Option<A>,
    /// The digest of the Ironwood bundle used by version 6 transactions.
    ///
    /// This is `None` when the transaction has no Ironwood bundle. When a version 6 transaction
    /// ID is derived from these digests, `None` is combined as the empty Ironwood bundle digest
    /// using the Ironwood bundle personalization.
    #[cfg(zcash_unstable = "nu6.3")]
    pub ironwood_digest: Option<A>,
}

pub trait TransactionDigest<A: Authorization> {
    type HeaderDigest;
    type TransparentDigest;
    type SaplingDigest;
    type OrchardDigest;
    /// The digest type produced for the Ironwood bundle in version 6 transactions.
    #[cfg(zcash_unstable = "nu6.3")]
    type IronwoodDigest;

    type Digest;

    fn digest_header(
        &self,
        version: TxVersion,
        consensus_branch_id: BranchId,
        lock_time: u32,
        expiry_height: BlockHeight,
        #[cfg(all(zcash_unstable = "nu7", feature = "zip-233"))] zip233_amount: &Zatoshis,
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
    #[cfg(zcash_unstable = "nu6.3")]
    fn digest_ironwood(
        &self,
        version: TxVersion,
        ironwood_bundle: Option<&orchard::Bundle<A::OrchardAuth, ZatBalance>>,
    ) -> Self::IronwoodDigest;

    fn combine(
        &self,
        header_digest: Self::HeaderDigest,
        transparent_digest: Self::TransparentDigest,
        sapling_digest: Self::SaplingDigest,
        orchard_digest: Self::OrchardDigest,
        #[cfg(zcash_unstable = "nu6.3")] ironwood_digest: Self::IronwoodDigest,
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

    #[cfg(all(zcash_unstable = "nu7", feature = "zip-233"))]
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
            #[cfg(zcash_unstable = "nu6.3")]
            BranchId::Nu6_3 => Just(TxVersion::V6).boxed(),
            #[cfg(zcash_unstable = "nu7")]
            BranchId::Nu7 => Just(TxVersion::V6).boxed(),
        }
    }

    #[cfg(all(not(zcash_unstable = "nu7"), not(zcash_unstable = "nu6.3")))]
    prop_compose! {
        pub fn arb_txdata(consensus_branch_id: BranchId)(
            version in arb_tx_version(consensus_branch_id),
        )(
            lock_time in any::<u32>(),
            expiry_height in any::<u32>(),
            transparent_bundle in transparent::arb_bundle(),
            sapling_bundle in sapling::arb_bundle_for_version(version),
            orchard_bundle in orchard::arb_bundle_for_version(version),
            version in Just(version),
        ) -> TransactionData<Authorized> {
            TransactionData {
                version,
                consensus_branch_id,
                lock_time,
                expiry_height: expiry_height.into(),
                transparent_bundle,
                sprout_bundle: None,
                sapling_bundle,
                orchard_bundle,
            }
        }
    }

    #[cfg(all(zcash_unstable = "nu7", not(feature = "zip-233")))]
    prop_compose! {
        pub fn arb_txdata(consensus_branch_id: BranchId)(
            version in arb_tx_version(consensus_branch_id)
        )(
            lock_time in any::<u32>(),
            expiry_height in any::<u32>(),
            transparent_bundle in transparent::arb_bundle(),
            sapling_bundle in sapling::arb_bundle_for_version(version),
            orchard_bundle in orchard::arb_bundle_for_version(version),
            version in Just(version),
        ) -> TransactionData<Authorized> {
            TransactionData {
                version,
                consensus_branch_id,
                lock_time,
                expiry_height: expiry_height.into(),
                transparent_bundle,
                sprout_bundle: None,
                sapling_bundle,
                orchard_bundle,
            }
        }
    }

    #[cfg(all(zcash_unstable = "nu7", feature = "zip-233"))]
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
            version in Just(version),
        ) -> TransactionData<Authorized> {
            TransactionData {
                version,
                consensus_branch_id,
                lock_time,
                expiry_height: expiry_height.into(),
                zip233_amount: Zatoshis::from_u64(zip233_amount).unwrap(),
                transparent_bundle,
                sprout_bundle: None,
                sapling_bundle,
                orchard_bundle,
            }
        }
    }

    #[cfg(zcash_unstable = "nu6.3")]
    prop_compose! {
        pub fn arb_txdata(consensus_branch_id: BranchId)(
            version in arb_tx_version(consensus_branch_id)
        )(
            lock_time in any::<u32>(),
            expiry_height in any::<u32>(),
            transparent_bundle in transparent::arb_bundle(),
            sapling_bundle in sapling::arb_bundle_for_version(version),
            orchard_bundle in orchard::arb_bundle_for_version(version),
            ironwood_bundle in if version.has_ironwood() {
                orchard::arb_bundle_for_version(version).boxed()
            } else {
                Just(None).boxed()
            },
            version in Just(version),
        ) -> TransactionData<Authorized> {
            TransactionData {
                version,
                consensus_branch_id,
                lock_time,
                expiry_height: expiry_height.into(),
                transparent_bundle,
                sprout_bundle: None,
                sapling_bundle,
                orchard_bundle,
                ironwood_bundle,
            }
        }
    }

    prop_compose! {
        pub fn arb_tx(branch_id: BranchId)(tx_data in arb_txdata(branch_id)) -> Transaction {
            Transaction::from_data(tx_data).unwrap()
        }
    }
}
