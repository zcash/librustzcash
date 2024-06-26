//! Structs and methods for handling Zcash transactions.
pub mod builder;
pub mod components;
pub mod fees;
pub mod sighash;
pub mod sighash_v4;
pub mod sighash_v5;
pub mod txid;
pub mod util;

#[cfg(test)]
mod tests;

use blake2b_simd::Hash as Blake2bHash;
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use memuse::DynamicUsage;
use std::convert::TryFrom;
use std::fmt;
use std::fmt::Debug;
use std::io::{self, Read, Write};
use std::ops::Deref;

use crate::{
    consensus::{BlockHeight, BranchId},
    sapling::{self, builder as sapling_builder},
};

use self::components::AuthorizedSproutPart;
use self::{
    components::{
        amount::{Amount, BalanceError},
        orchard as orchard_serialization, sapling as sapling_serialization, sprout, transparent,
        AllBundles, AuthorizedOrchardPart, AuthorizedSaplingPart, AuthorizedTransparentPart,
        Bundles, Orchard, OrchardPart, OutPoint, Sapling, SaplingPart, ShieldedBundle, Sprout,
        SproutPart, Transparent, TransparentPart,
    },
    txid::{to_txid, BlockTxCommitmentDigester, TxIdDigester},
    util::sha256d::{HashReader, HashWriter},
};

#[cfg(zcash_unstable = "zfuture")]
use self::components::{tze, AuthorizedTzePart, Tze, TzePart};

const OVERWINTER_VERSION_GROUP_ID: u32 = 0x03C48270;
const OVERWINTER_TX_VERSION: u32 = 3;
const SAPLING_VERSION_GROUP_ID: u32 = 0x892F2085;
const SAPLING_TX_VERSION: u32 = 4;

const V5_TX_VERSION: u32 = 5;
const V5_VERSION_GROUP_ID: u32 = 0x26A7270A;

/// These versions are used exclusively for in-development transaction
/// serialization, and will never be active under the consensus rules.
/// When new consensus transaction versions are added, all call sites
/// using these constants should be inspected, and use of these constants
/// should be removed as appropriate in favor of the new consensus
/// transaction version and group.
#[cfg(zcash_unstable = "zfuture")]
const ZFUTURE_VERSION_GROUP_ID: u32 = 0xFFFFFFFF;
#[cfg(zcash_unstable = "zfuture")]
const ZFUTURE_TX_VERSION: u32 = 0x0000FFFF;

/// The identifier for a Zcash transaction.
///
/// - For v1-4 transactions, this is a double-SHA-256 hash of the encoded transaction.
///   This means that it is malleable, and only a reliable identifier for transactions
///   that have been mined.
/// - For v5 transactions onwards, this identifier is derived only from "effecting" data,
///   and is non-malleable in all contexts.
#[derive(Clone, Copy, PartialOrd, Ord, PartialEq, Eq, Hash)]
pub struct TxId([u8; 32]);

memuse::impl_no_dynamic_usage!(TxId);

impl fmt::Debug for TxId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The (byte-flipped) hex string is more useful than the raw bytes, because we can
        // look that up in RPC methods and block explorers.
        let txid_str = self.to_string();
        f.debug_tuple("TxId").field(&txid_str).finish()
    }
}

impl fmt::Display for TxId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut data = self.0;
        data.reverse();
        formatter.write_str(&hex::encode(data))
    }
}

impl AsRef<[u8; 32]> for TxId {
    fn as_ref(&self) -> &[u8; 32] {
        &self.0
    }
}

impl From<TxId> for [u8; 32] {
    fn from(value: TxId) -> Self {
        value.0
    }
}

impl TxId {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        TxId(bytes)
    }

    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let mut hash = [0u8; 32];
        reader.read_exact(&mut hash)?;
        Ok(TxId::from_bytes(hash))
    }

    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_all(&self.0)?;
        Ok(())
    }
}

/// The set of defined transaction format versions.
///
/// This is serialized in the first four or eight bytes of the transaction format, and
/// represents valid combinations of the `(overwintered, version, version_group_id)`
/// transaction fields. Note that this is not dependent on epoch, only on transaction encoding.
/// For example, if a particular epoch defines a new transaction version but also allows the
/// previous version, then only the new version would be added to this enum.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxVersion {
    Sprout(u32),
    Overwinter,
    Sapling,
    Zip225,
    #[cfg(zcash_unstable = "zfuture")]
    ZFuture,
}

impl TxVersion {
    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let header = reader.read_u32::<LittleEndian>()?;
        let overwintered = (header >> 31) == 1;
        let version = header & 0x7FFFFFFF;

        if overwintered {
            match (version, reader.read_u32::<LittleEndian>()?) {
                (OVERWINTER_TX_VERSION, OVERWINTER_VERSION_GROUP_ID) => Ok(TxVersion::Overwinter),
                (SAPLING_TX_VERSION, SAPLING_VERSION_GROUP_ID) => Ok(TxVersion::Sapling),
                (V5_TX_VERSION, V5_VERSION_GROUP_ID) => Ok(TxVersion::Zip225),
                #[cfg(zcash_unstable = "zfuture")]
                (ZFUTURE_TX_VERSION, ZFUTURE_VERSION_GROUP_ID) => Ok(TxVersion::ZFuture),
                _ => Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Unknown transaction format",
                )),
            }
        } else if version >= 1 {
            Ok(TxVersion::Sprout(version))
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidInput,
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
                TxVersion::Overwinter => OVERWINTER_TX_VERSION,
                TxVersion::Sapling => SAPLING_TX_VERSION,
                TxVersion::Zip225 => V5_TX_VERSION,
                #[cfg(zcash_unstable = "zfuture")]
                TxVersion::ZFuture => ZFUTURE_TX_VERSION,
            }
    }

    pub fn version_group_id(&self) -> u32 {
        match self {
            TxVersion::Sprout(_) => 0,
            TxVersion::Overwinter => OVERWINTER_VERSION_GROUP_ID,
            TxVersion::Sapling => SAPLING_VERSION_GROUP_ID,
            TxVersion::Zip225 => V5_VERSION_GROUP_ID,
            #[cfg(zcash_unstable = "zfuture")]
            TxVersion::ZFuture => ZFUTURE_VERSION_GROUP_ID,
        }
    }

    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_u32::<LittleEndian>(self.header())?;
        match self {
            TxVersion::Sprout(_) => Ok(()),
            _ => writer.write_u32::<LittleEndian>(self.version_group_id()),
        }
    }

    /// Returns `true` if this transaction version supports the Sprout protocol.
    pub fn has_sprout(&self) -> bool {
        match self {
            TxVersion::Sprout(v) => *v >= 2u32,
            TxVersion::Overwinter | TxVersion::Sapling => true,
            TxVersion::Zip225 => false,
            #[cfg(zcash_unstable = "zfuture")]
            TxVersion::ZFuture => true,
        }
    }

    pub fn has_overwinter(&self) -> bool {
        !matches!(self, TxVersion::Sprout(_))
    }

    /// Returns `true` if this transaction version supports the Sapling protocol.
    pub fn has_sapling(&self) -> bool {
        match self {
            TxVersion::Sprout(_) | TxVersion::Overwinter => false,
            TxVersion::Sapling => true,
            TxVersion::Zip225 => true,
            #[cfg(zcash_unstable = "zfuture")]
            TxVersion::ZFuture => true,
        }
    }

    /// Returns `true` if this transaction version supports the Orchard protocol.
    pub fn has_orchard(&self) -> bool {
        match self {
            TxVersion::Sprout(_) | TxVersion::Overwinter | TxVersion::Sapling => false,
            TxVersion::Zip225 => true,
            #[cfg(zcash_unstable = "zfuture")]
            TxVersion::ZFuture => true,
        }
    }

    #[cfg(zcash_unstable = "zfuture")]
    pub fn has_tze(&self) -> bool {
        matches!(self, TxVersion::ZFuture)
    }

    /// Suggests the transaction version that should be used in the given Zcash epoch.
    pub fn suggested_for_branch(consensus_branch_id: BranchId) -> Self {
        match consensus_branch_id {
            BranchId::Sprout => TxVersion::Sprout(2),
            BranchId::Overwinter => TxVersion::Overwinter,
            BranchId::Sapling | BranchId::Blossom | BranchId::Heartwood | BranchId::Canopy => {
                TxVersion::Sapling
            }
            BranchId::Nu5 => TxVersion::Zip225,
            #[cfg(zcash_unstable = "nu6")]
            BranchId::Nu6 => TxVersion::Zip225,
            #[cfg(zcash_unstable = "zfuture")]
            BranchId::ZFuture => TxVersion::ZFuture,
        }
    }
}

/// Authorization state for a bundle of transaction data.
pub trait Authorization {
    type TransparentAuth: transparent::Authorization;
    type SaplingAuth: sapling::bundle::Authorization;
    type OrchardAuth: orchard::bundle::Authorization;

    #[cfg(zcash_unstable = "zfuture")]
    type TzeAuth: tze::Authorization;
}

/// [`Authorization`] marker type for fully-authorized transactions.
#[derive(Debug)]
pub struct Authorized;

impl Authorization for Authorized {
    type TransparentAuth = transparent::Authorized;
    type SaplingAuth = sapling::bundle::Authorized;
    type OrchardAuth = orchard::bundle::Authorized;

    #[cfg(zcash_unstable = "zfuture")]
    type TzeAuth = tze::Authorized;
}

/// [`Authorization`] marker type for transactions without authorization data.
///
/// Currently this includes Sapling proofs because the types in this crate support v4
/// transactions, which commit to the Sapling proofs in the transaction digest.
pub struct Unauthorized;

impl Authorization for Unauthorized {
    type TransparentAuth = transparent::builder::Unauthorized;
    type SaplingAuth =
        sapling_builder::InProgress<sapling_builder::Proven, sapling_builder::Unsigned>;
    type OrchardAuth =
        orchard::builder::InProgress<orchard::builder::Unproven, orchard::builder::Unauthorized>;

    #[cfg(zcash_unstable = "zfuture")]
    type TzeAuth = tze::builder::Unauthorized;
}

/// A Zcash transaction.
#[derive(Debug)]
pub struct Transaction {
    txid: TxId,
    data: TransactionData<AllBundles<Authorized>>,
}

impl Deref for Transaction {
    type Target = TransactionData<AllBundles<Authorized>>;

    fn deref(&self) -> &TransactionData<AllBundles<Authorized>> {
        &self.data
    }
}

impl PartialEq for Transaction {
    fn eq(&self, other: &Transaction) -> bool {
        self.txid == other.txid
    }
}

/// The information contained in a Zcash transaction.
pub struct TransactionData<B: Bundles> {
    version: TxVersion,
    consensus_branch_id: BranchId,
    lock_time: u32,
    expiry_height: BlockHeight,
    transparent_bundle: Option<<B::Transparent as TransparentPart>::Bundle>,
    sprout_bundle: Option<<B::Sprout as SproutPart>::Bundle>,
    sapling_bundle: Option<<B::Sapling as SaplingPart>::Bundle>,
    orchard_bundle: Option<<B::Orchard as OrchardPart>::Bundle>,
    #[cfg(zcash_unstable = "zfuture")]
    tze_bundle: Option<<B::Tze as TzePart>::Bundle>,
}

/// Trait marker for bounds that are not yet required by consensus rules.
#[cfg(not(zcash_unstable = "zfuture"))]
trait FutureDebug {}
#[cfg(not(zcash_unstable = "zfuture"))]
impl<B: Bundles> FutureDebug for B {}

#[cfg(zcash_unstable = "zfuture")]
trait FutureDebug: Bundles<Tze = Self::FutureTze> {
    type FutureTze: TzePart<Bundle = Self::FutureTzeBundle> + fmt::Debug;
    type FutureTzeBundle: fmt::Debug;
}
#[cfg(zcash_unstable = "zfuture")]
impl<B> FutureDebug for B
where
    B: Bundles,
    B::Tze: TzePart + fmt::Debug,
    <B::Tze as TzePart>::Bundle: fmt::Debug,
{
    type FutureTze = B::Tze;
    type FutureTzeBundle = <B::Tze as TzePart>::Bundle;
}

impl<B> fmt::Debug for TransactionData<B>
where
    B: Bundles + fmt::Debug + FutureDebug,
    B::Transparent: TransparentPart + fmt::Debug,
    B::Sprout: SproutPart + fmt::Debug,
    B::Sapling: SaplingPart + fmt::Debug,
    B::Orchard: OrchardPart + fmt::Debug,
    <B::Transparent as TransparentPart>::Bundle: fmt::Debug,
    <B::Sprout as SproutPart>::Bundle: fmt::Debug,
    <B::Sapling as SaplingPart>::Bundle: fmt::Debug,
    <B::Orchard as OrchardPart>::Bundle: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut s = f.debug_struct("TransactionData");
        s.field("version", &self.version)
            .field("consensus_branch_id", &self.consensus_branch_id)
            .field("lock_time", &self.lock_time)
            .field("expiry_height", &self.expiry_height)
            .field("transparent_bundle", &self.transparent_bundle)
            .field("sprout_bundle", &self.sprout_bundle)
            .field("sapling_bundle", &self.sapling_bundle)
            .field("orchard_bundle", &self.orchard_bundle);
        #[cfg(zcash_unstable = "zfuture")]
        s.field("tze_bundle", &self.tze_bundle);
        s.finish()
    }
}

impl<B: Bundles> TransactionData<B> {
    /// Constructs a `TransactionData` from its constituent parts.
    #[allow(clippy::too_many_arguments)]
    pub fn from_parts(
        version: TxVersion,
        consensus_branch_id: BranchId,
        lock_time: u32,
        expiry_height: BlockHeight,
        transparent_bundle: Option<<B::Transparent as TransparentPart>::Bundle>,
        sprout_bundle: Option<<B::Sprout as SproutPart>::Bundle>,
        sapling_bundle: Option<<B::Sapling as SaplingPart>::Bundle>,
        orchard_bundle: Option<<B::Orchard as OrchardPart>::Bundle>,
    ) -> Self {
        TransactionData {
            version,
            consensus_branch_id,
            lock_time,
            expiry_height,
            transparent_bundle,
            sprout_bundle,
            sapling_bundle,
            orchard_bundle,
            #[cfg(zcash_unstable = "zfuture")]
            tze_bundle: None,
        }
    }

    /// Constructs a `TransactionData` from its constituent parts, including speculative
    /// future parts that are not in the current Zcash consensus rules.
    #[cfg(zcash_unstable = "zfuture")]
    #[allow(clippy::too_many_arguments)]
    pub fn from_parts_zfuture(
        version: TxVersion,
        consensus_branch_id: BranchId,
        lock_time: u32,
        expiry_height: BlockHeight,
        transparent_bundle: Option<<B::Transparent as TransparentPart>::Bundle>,
        sprout_bundle: Option<<B::Sprout as SproutPart>::Bundle>,
        sapling_bundle: Option<<B::Sapling as SaplingPart>::Bundle>,
        orchard_bundle: Option<<B::Orchard as OrchardPart>::Bundle>,
        tze_bundle: Option<<B::Tze as TzePart>::Bundle>,
    ) -> Self {
        TransactionData {
            version,
            consensus_branch_id,
            lock_time,
            expiry_height,
            transparent_bundle,
            sprout_bundle,
            sapling_bundle,
            orchard_bundle,
            tze_bundle,
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
}

impl<TA: transparent::Authorization, B: Bundles<Transparent = Transparent<TA>>> TransactionData<B> {
    pub fn transparent_bundle(&self) -> Option<&transparent::Bundle<TA>> {
        self.transparent_bundle.as_ref()
    }
}

impl<B: Bundles<Sprout = Sprout>> TransactionData<B> {
    pub fn sprout_bundle(&self) -> Option<&sprout::Bundle> {
        self.sprout_bundle.as_ref()
    }
}

impl<SA: sapling::bundle::Authorization, B: Bundles<Sapling = Sapling<SA>>> TransactionData<B> {
    pub fn sapling_bundle(&self) -> Option<&sapling::Bundle<SA, Amount>> {
        self.sapling_bundle.as_ref()
    }
}

impl<OA: orchard::bundle::Authorization, B: Bundles<Orchard = Orchard<OA>>> TransactionData<B> {
    pub fn orchard_bundle(&self) -> Option<&orchard::Bundle<OA, Amount>> {
        self.orchard_bundle.as_ref()
    }
}

#[cfg(zcash_unstable = "zfuture")]
impl<TA: tze::Authorization, B: Bundles<Tze = Tze<TA>>> TransactionData<B> {
    pub fn tze_bundle(&self) -> Option<&tze::Bundle<TA>> {
        self.tze_bundle.as_ref()
    }
}

impl<B: Bundles> TransactionData<B> {
    /// Returns the total fees paid by the transaction, given a function that can be used to
    /// retrieve the value of previous transactions' transparent outputs that are being spent in
    /// this transaction.
    pub fn fee_paid<E, F>(&self, get_prevout: F) -> Result<Amount, E>
    where
        E: From<BalanceError>,
        F: FnMut(&OutPoint) -> Result<Amount, E>,
    {
        let value_balances = [
            self.transparent_bundle.as_ref().map_or_else(
                || Ok(Amount::zero()),
                |b| B::Transparent::value_balance(b, get_prevout),
            )?,
            self.sprout_bundle
                .as_ref()
                .map_or_else(Amount::zero, |b| b.value_balance()),
            self.sapling_bundle
                .as_ref()
                .map_or_else(Amount::zero, |b| b.value_balance()),
            self.orchard_bundle
                .as_ref()
                .map_or_else(Amount::zero, |b| b.value_balance()),
        ];

        value_balances
            .iter()
            .sum::<Option<_>>()
            .ok_or_else(|| BalanceError::Overflow.into())
    }

    pub fn digest<D: TransactionDigest<B>>(&self, digester: D) -> D::Digest {
        digester.combine(
            digester.digest_header(
                self.version,
                self.consensus_branch_id,
                self.lock_time,
                self.expiry_height,
            ),
            digester.digest_transparent(self.transparent_bundle.as_ref()),
            digester.digest_sapling(self.sapling_bundle.as_ref()),
            digester.digest_orchard(self.orchard_bundle.as_ref()),
            #[cfg(zcash_unstable = "zfuture")]
            digester.digest_tze(self.tze_bundle.as_ref()),
        )
    }

    /// Maps the bundles from one type to another.
    ///
    /// This shouldn't be necessary for most use cases; it is provided for handling the
    /// cross-FFI builder logic in `zcashd`.
    pub fn map_bundles<BB: Bundles>(
        self,
        f_transparent: impl FnOnce(
            Option<<B::Transparent as TransparentPart>::Bundle>,
        ) -> Option<<BB::Transparent as TransparentPart>::Bundle>,
        f_sprout: impl FnOnce(
            Option<<B::Sprout as SproutPart>::Bundle>,
        ) -> Option<<BB::Sprout as SproutPart>::Bundle>,
        f_sapling: impl FnOnce(
            Option<<B::Sapling as SaplingPart>::Bundle>,
        ) -> Option<<BB::Sapling as SaplingPart>::Bundle>,
        f_orchard: impl FnOnce(
            Option<<B::Orchard as OrchardPart>::Bundle>,
        ) -> Option<<BB::Orchard as OrchardPart>::Bundle>,
        #[cfg(zcash_unstable = "zfuture")] f_tze: impl FnOnce(
            Option<<B::Tze as TzePart>::Bundle>,
        )
            -> Option<<BB::Tze as TzePart>::Bundle>,
    ) -> TransactionData<BB> {
        TransactionData {
            version: self.version,
            consensus_branch_id: self.consensus_branch_id,
            lock_time: self.lock_time,
            expiry_height: self.expiry_height,
            transparent_bundle: f_transparent(self.transparent_bundle),
            sprout_bundle: f_sprout(self.sprout_bundle),
            sapling_bundle: f_sapling(self.sapling_bundle),
            orchard_bundle: f_orchard(self.orchard_bundle),
            #[cfg(zcash_unstable = "zfuture")]
            tze_bundle: f_tze(self.tze_bundle),
        }
    }
}

impl<A: Authorization> TransactionData<AllBundles<A>> {
    pub fn map_authorization<AB: Authorization>(
        self,
        f_transparent: impl transparent::MapAuth<A::TransparentAuth, AB::TransparentAuth>,
        mut f_sapling: impl sapling_serialization::MapAuth<A::SaplingAuth, AB::SaplingAuth>,
        mut f_orchard: impl orchard_serialization::MapAuth<A::OrchardAuth, AB::OrchardAuth>,
        #[cfg(zcash_unstable = "zfuture")] f_tze: impl tze::MapAuth<A::TzeAuth, AB::TzeAuth>,
    ) -> TransactionData<AllBundles<AB>> {
        TransactionData {
            version: self.version,
            consensus_branch_id: self.consensus_branch_id,
            lock_time: self.lock_time,
            expiry_height: self.expiry_height,
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
            #[cfg(zcash_unstable = "zfuture")]
            tze_bundle: self.tze_bundle.map(|b| b.map_authorization(f_tze)),
        }
    }
}

impl<SA: sapling::bundle::Authorization, B: Bundles<Sapling = Sapling<SA>>> TransactionData<B> {
    pub fn sapling_value_balance(&self) -> Amount {
        self.sapling_bundle
            .as_ref()
            .map_or(Amount::zero(), |b| *b.value_balance())
    }
}

impl TransactionData<AllBundles<Authorized>> {
    pub fn freeze(self) -> io::Result<Transaction> {
        Transaction::from_data(self)
    }
}

impl Transaction {
    fn from_data(data: TransactionData<AllBundles<Authorized>>) -> io::Result<Self> {
        match data.version {
            TxVersion::Sprout(_) | TxVersion::Overwinter | TxVersion::Sapling => {
                Self::from_data_v4(data)
            }
            TxVersion::Zip225 => Ok(Self::from_data_v5(data)),
            #[cfg(zcash_unstable = "zfuture")]
            TxVersion::ZFuture => Ok(Self::from_data_v5(data)),
        }
    }

    fn from_data_v4(data: TransactionData<AllBundles<Authorized>>) -> io::Result<Self> {
        let mut tx = Transaction {
            txid: TxId([0; 32]),
            data,
        };
        let mut writer = HashWriter::default();
        tx.write(&mut writer)?;
        tx.txid.0.copy_from_slice(&writer.into_hash());
        Ok(tx)
    }

    fn from_data_v5(data: TransactionData<AllBundles<Authorized>>) -> Self {
        let txid = to_txid(
            data.version,
            data.consensus_branch_id,
            &data.digest(TxIdDigester),
        );

        Transaction { txid, data }
    }

    pub fn into_data(self) -> TransactionData<AllBundles<Authorized>> {
        self.data
    }

    pub fn txid(&self) -> TxId {
        self.txid
    }

    pub fn read<R: Read>(reader: R, consensus_branch_id: BranchId) -> io::Result<Self> {
        let mut reader = HashReader::new(reader);

        let version = TxVersion::read(&mut reader)?;
        match version {
            TxVersion::Sprout(_) | TxVersion::Overwinter | TxVersion::Sapling => {
                Self::read_v4(reader, version, consensus_branch_id)
            }
            TxVersion::Zip225 => Self::read_v5(reader.into_base_reader(), version),
            #[cfg(zcash_unstable = "zfuture")]
            TxVersion::ZFuture => Self::read_v5(reader.into_base_reader(), version),
        }
    }

    #[allow(clippy::redundant_closure)]
    fn read_v4<R: Read>(
        mut reader: HashReader<R>,
        version: TxVersion,
        consensus_branch_id: BranchId,
    ) -> io::Result<Self> {
        let transparent_bundle = Transparent::read_bundle(&mut reader)?;

        let lock_time = reader.read_u32::<LittleEndian>()?;
        let expiry_height: BlockHeight = if version.has_overwinter() {
            reader.read_u32::<LittleEndian>()?.into()
        } else {
            0u32.into()
        };

        let components = Sapling::read_v4_components(&mut reader, version.has_sapling())?;

        let sprout_bundle =
            Sprout::read_v4_bundle(&mut reader, version.has_sprout(), version.has_sapling())?;

        let sapling_bundle =
            Sapling::read_v4_binding_sig(&mut reader, version.has_sapling(), components)?;

        let mut txid = [0; 32];
        let hash_bytes = reader.into_hash();
        txid.copy_from_slice(&hash_bytes);

        Ok(Transaction {
            txid: TxId(txid),
            data: TransactionData {
                version,
                consensus_branch_id,
                lock_time,
                expiry_height,
                transparent_bundle,
                sprout_bundle,
                sapling_bundle,
                orchard_bundle: None,
                #[cfg(zcash_unstable = "zfuture")]
                tze_bundle: None,
            },
        })
    }

    fn read_amount<R: Read>(mut reader: R) -> io::Result<Amount> {
        let mut tmp = [0; 8];
        reader.read_exact(&mut tmp)?;
        Amount::from_i64_le_bytes(tmp)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "valueBalance out of range"))
    }

    fn read_v5<R: Read>(mut reader: R, version: TxVersion) -> io::Result<Self> {
        let (consensus_branch_id, lock_time, expiry_height) =
            Self::read_v5_header_fragment(&mut reader)?;
        let transparent_bundle = Transparent::read_bundle(&mut reader)?;
        let sapling_bundle = Sapling::read_v5_bundle(&mut reader)?;
        let orchard_bundle = Orchard::read_v5_bundle(&mut reader)?;

        #[cfg(zcash_unstable = "zfuture")]
        let tze_bundle = Tze::read_bundle(&mut reader, version.has_tze())?;

        let data = TransactionData {
            version,
            consensus_branch_id,
            lock_time,
            expiry_height,
            transparent_bundle,
            sprout_bundle: None,
            sapling_bundle,
            orchard_bundle,
            #[cfg(zcash_unstable = "zfuture")]
            tze_bundle,
        };

        Ok(Self::from_data_v5(data))
    }

    fn read_v5_header_fragment<R: Read>(mut reader: R) -> io::Result<(BranchId, u32, BlockHeight)> {
        let consensus_branch_id = reader.read_u32::<LittleEndian>().and_then(|value| {
            BranchId::try_from(value).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "invalid consensus branch id: ".to_owned() + e,
                )
            })
        })?;
        let lock_time = reader.read_u32::<LittleEndian>()?;
        let expiry_height: BlockHeight = reader.read_u32::<LittleEndian>()?.into();
        Ok((consensus_branch_id, lock_time, expiry_height))
    }

    #[cfg(feature = "temporary-zcashd")]
    pub fn temporary_zcashd_read_v5_sapling<R: Read>(
        reader: R,
    ) -> io::Result<Option<sapling::Bundle<sapling::bundle::Authorized, Amount>>> {
        Sapling::read_v5_bundle(reader)
    }

    pub fn write<W: Write>(&self, writer: W) -> io::Result<()> {
        match self.version {
            TxVersion::Sprout(_) | TxVersion::Overwinter | TxVersion::Sapling => {
                self.write_v4(writer)
            }
            TxVersion::Zip225 => self.write_v5(writer),
            #[cfg(zcash_unstable = "zfuture")]
            TxVersion::ZFuture => self.write_v5(writer),
        }
    }

    pub fn write_v4<W: Write>(&self, mut writer: W) -> io::Result<()> {
        self.version.write(&mut writer)?;

        self.write_transparent(&mut writer)?;
        writer.write_u32::<LittleEndian>(self.lock_time)?;
        if self.version.has_overwinter() {
            writer.write_u32::<LittleEndian>(u32::from(self.expiry_height))?;
        }

        Sapling::write_v4_components(
            self.sapling_bundle.as_ref(),
            &mut writer,
            self.version.has_sapling(),
        )?;

        Sprout::write_v4_bundle(
            self.sprout_bundle.as_ref(),
            &mut writer,
            self.version.has_sprout(),
        )?;

        Sapling::write_v4_binding_sig(
            self.sapling_bundle.as_ref(),
            &mut writer,
            self.version.has_sapling(),
        )?;

        if self.orchard_bundle.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Orchard components cannot be present when serializing to the V4 transaction format."
            ));
        }

        Ok(())
    }

    pub fn write_transparent<W: Write>(&self, writer: W) -> io::Result<()> {
        Transparent::write_bundle(self.transparent_bundle.as_ref(), writer)
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
        Orchard::write_v5_bundle(self.orchard_bundle.as_ref(), &mut writer)?;
        #[cfg(zcash_unstable = "zfuture")]
        self.write_tze(&mut writer)?;
        Ok(())
    }

    pub fn write_v5_header<W: Write>(&self, mut writer: W) -> io::Result<()> {
        self.version.write(&mut writer)?;
        writer.write_u32::<LittleEndian>(u32::from(self.consensus_branch_id))?;
        writer.write_u32::<LittleEndian>(self.lock_time)?;
        writer.write_u32::<LittleEndian>(u32::from(self.expiry_height))?;
        Ok(())
    }

    #[cfg(feature = "temporary-zcashd")]
    pub fn temporary_zcashd_write_v5_sapling<W: Write>(
        sapling_bundle: Option<&sapling::Bundle<sapling::bundle::Authorized, Amount>>,
        writer: W,
    ) -> io::Result<()> {
        Sapling::write_v5_bundle(sapling_bundle, writer)
    }

    pub fn write_v5_sapling<W: Write>(&self, writer: W) -> io::Result<()> {
        Sapling::write_v5_bundle(self.sapling_bundle.as_ref(), writer)
    }

    #[cfg(zcash_unstable = "zfuture")]
    pub fn write_tze<W: Write>(&self, writer: W) -> io::Result<()> {
        Tze::write_bundle(self.tze_bundle.as_ref(), writer, self.version.has_tze())
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
pub struct TzeDigests<A> {
    pub inputs_digest: A,
    pub outputs_digest: A,
    pub per_input_digest: Option<A>,
}

#[derive(Clone, Debug)]
pub struct TxDigests<A> {
    pub header_digest: A,
    pub transparent_digests: Option<TransparentDigests<A>>,
    pub sapling_digest: Option<A>,
    pub orchard_digest: Option<A>,
    #[cfg(zcash_unstable = "zfuture")]
    pub tze_digests: Option<TzeDigests<A>>,
}

pub trait TransactionDigest<B: Bundles> {
    type HeaderDigest;
    type TransparentDigest;
    type SaplingDigest;
    type OrchardDigest;

    #[cfg(zcash_unstable = "zfuture")]
    type TzeDigest;

    type Digest;

    fn digest_header(
        &self,
        version: TxVersion,
        consensus_branch_id: BranchId,
        lock_time: u32,
        expiry_height: BlockHeight,
    ) -> Self::HeaderDigest;

    fn digest_transparent(
        &self,
        transparent_bundle: Option<&<B::Transparent as TransparentPart>::Bundle>,
    ) -> Self::TransparentDigest;

    fn digest_sapling(
        &self,
        sapling_bundle: Option<&<B::Sapling as SaplingPart>::Bundle>,
    ) -> Self::SaplingDigest;

    fn digest_orchard(
        &self,
        orchard_bundle: Option<&<B::Orchard as OrchardPart>::Bundle>,
    ) -> Self::OrchardDigest;

    #[cfg(zcash_unstable = "zfuture")]
    fn digest_tze(&self, tze_bundle: Option<&<B::Tze as TzePart>::Bundle>) -> Self::TzeDigest;

    fn combine(
        &self,
        header_digest: Self::HeaderDigest,
        transparent_digest: Self::TransparentDigest,
        sapling_digest: Self::SaplingDigest,
        orchard_digest: Self::OrchardDigest,
        #[cfg(zcash_unstable = "zfuture")] tze_digest: Self::TzeDigest,
    ) -> Self::Digest;
}

pub enum DigestError {
    NotSigned,
}

#[cfg(any(test, feature = "test-dependencies"))]
pub mod testing {
    use proptest::prelude::*;

    use crate::consensus::BranchId;

    use super::{
        components::{
            orchard::testing::{self as orchard},
            sapling::testing::{self as sapling},
            transparent::testing::{self as transparent},
            AllBundles,
        },
        Authorized, Transaction, TransactionData, TxId, TxVersion,
    };

    #[cfg(zcash_unstable = "zfuture")]
    use super::components::tze::testing::{self as tze};

    pub fn arb_txid() -> impl Strategy<Value = TxId> {
        prop::array::uniform32(any::<u8>()).prop_map(TxId::from_bytes)
    }

    pub fn arb_tx_version(branch_id: BranchId) -> impl Strategy<Value = TxVersion> {
        match branch_id {
            BranchId::Sprout => (1..=2u32).prop_map(TxVersion::Sprout).boxed(),
            BranchId::Overwinter => Just(TxVersion::Overwinter).boxed(),
            BranchId::Sapling | BranchId::Blossom | BranchId::Heartwood | BranchId::Canopy => {
                Just(TxVersion::Sapling).boxed()
            }
            BranchId::Nu5 => Just(TxVersion::Zip225).boxed(),
            #[cfg(zcash_unstable = "nu6")]
            BranchId::Nu6 => Just(TxVersion::Zip225).boxed(),
            #[cfg(zcash_unstable = "zfuture")]
            BranchId::ZFuture => Just(TxVersion::ZFuture).boxed(),
        }
    }

    #[cfg(not(zcash_unstable = "zfuture"))]
    prop_compose! {
        pub fn arb_txdata(consensus_branch_id: BranchId)(
            version in arb_tx_version(consensus_branch_id),
        )(
            lock_time in any::<u32>(),
            expiry_height in any::<u32>(),
            transparent_bundle in transparent::arb_bundle(),
            sapling_bundle in sapling::arb_bundle_for_version(version),
            orchard_bundle in orchard::arb_bundle_for_version(version),
            version in Just(version)
        ) -> TransactionData<AllBundles<Authorized>> {
            TransactionData {
                version,
                consensus_branch_id,
                lock_time,
                expiry_height: expiry_height.into(),
                transparent_bundle,
                sprout_bundle: None,
                sapling_bundle,
                orchard_bundle
            }
        }
    }

    #[cfg(zcash_unstable = "zfuture")]
    prop_compose! {
        pub fn arb_txdata(consensus_branch_id: BranchId)(
            version in arb_tx_version(consensus_branch_id),
        )(
            lock_time in any::<u32>(),
            expiry_height in any::<u32>(),
            transparent_bundle in transparent::arb_bundle(),
            sapling_bundle in sapling::arb_bundle_for_version(version),
            orchard_bundle in orchard::arb_bundle_for_version(version),
            tze_bundle in tze::arb_bundle(consensus_branch_id),
            version in Just(version)
        ) -> TransactionData<AllBundles<Authorized>> {
            TransactionData {
                version,
                consensus_branch_id,
                lock_time,
                expiry_height: expiry_height.into(),
                transparent_bundle,
                sprout_bundle: None,
                sapling_bundle,
                orchard_bundle,
                tze_bundle
            }
        }
    }

    prop_compose! {
        pub fn arb_tx(branch_id: BranchId)(tx_data in arb_txdata(branch_id)) -> Transaction {
            Transaction::from_data(tx_data).unwrap()
        }
    }
}
