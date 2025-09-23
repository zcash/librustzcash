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

use crate::encoding::{ReadBytesExt, WriteBytesExt};
use blake2b_simd::Hash as Blake2bHash;
use core::convert::TryFrom;
use core::fmt::Debug;
use core::ops::Deref;
use core2::io::{self, Read, Write};

use ::transparent::bundle::{self as transparent, OutPoint, TxIn, TxOut};
use zcash_encoding::{CompactSize, Vector};
use zcash_protocol::{
    consensus::{BlockHeight, BranchId},
    value::{BalanceError, ZatBalance},
};

use self::{
    components::{
        orchard as orchard_serialization, sapling as sapling_serialization,
        sprout::{self, JsDescription},
    },
    txid::{to_txid, BlockTxCommitmentDigester, TxIdDigester},
    util::sha256d::{HashReader, HashWriter},
};

#[cfg(feature = "circuits")]
use {::sapling::builder as sapling_builder, orchard::builder::Unproven};

#[cfg(zcash_unstable = "zfuture")]
use self::components::tze::{self, TzeIn, TzeOut};
#[cfg(zcash_unstable = "nu7")]
use crate::transaction::components::issuance;
use orchard::orchard_flavor::OrchardVanilla;
use orchard::Bundle;
#[cfg(zcash_unstable = "nu7")]
use orchard::{issuance::IssueBundle, orchard_flavor::OrchardZSA};
use zcash_protocol::constants::{
    V3_TX_VERSION, V3_VERSION_GROUP_ID, V4_TX_VERSION, V4_VERSION_GROUP_ID, V5_TX_VERSION,
    V5_VERSION_GROUP_ID,
};

#[cfg(zcash_unstable = "nu7")]
use zcash_protocol::constants::{V6_TX_VERSION, V6_VERSION_GROUP_ID};

#[cfg(zcash_unstable = "zfuture")]
use zcash_protocol::constants::{ZFUTURE_TX_VERSION, ZFUTURE_VERSION_GROUP_ID};

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
    #[cfg(zcash_unstable = "nu7")]
    V6,
    /// This version is used exclusively for in-development transaction
    /// serialization, and will never be active under the consensus rules.
    /// When new consensus transaction versions are added, all call sites
    /// using this constant should be inspected, and uses should be
    /// removed as appropriate in favor of the new transaction version.
    #[cfg(zcash_unstable = "zfuture")]
    ZFuture,
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
                #[cfg(zcash_unstable = "nu7")]
                (V6_TX_VERSION, V6_VERSION_GROUP_ID) => Ok(TxVersion::V6),
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
                TxVersion::V3 => V3_TX_VERSION,
                TxVersion::V4 => V4_TX_VERSION,
                TxVersion::V5 => V5_TX_VERSION,
                #[cfg(zcash_unstable = "nu7")]
                TxVersion::V6 => V6_TX_VERSION,
                #[cfg(zcash_unstable = "zfuture")]
                TxVersion::ZFuture => ZFUTURE_TX_VERSION,
            }
    }

    pub fn version_group_id(&self) -> u32 {
        match self {
            TxVersion::Sprout(_) => 0,
            TxVersion::V3 => V3_VERSION_GROUP_ID,
            TxVersion::V4 => V4_VERSION_GROUP_ID,
            TxVersion::V5 => V5_VERSION_GROUP_ID,
            #[cfg(zcash_unstable = "nu7")]
            TxVersion::V6 => V6_VERSION_GROUP_ID,
            #[cfg(zcash_unstable = "zfuture")]
            TxVersion::ZFuture => ZFUTURE_VERSION_GROUP_ID,
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
            #[cfg(zcash_unstable = "nu7")]
            TxVersion::V6 => false,
            #[cfg(zcash_unstable = "zfuture")]
            TxVersion::ZFuture => false,
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
            #[cfg(zcash_unstable = "nu7")]
            TxVersion::V6 => true,
            #[cfg(zcash_unstable = "zfuture")]
            TxVersion::ZFuture => true,
        }
    }

    /// Returns `true` if this transaction version supports the Orchard protocol.
    pub fn has_orchard(&self) -> bool {
        match self {
            TxVersion::Sprout(_) | TxVersion::V3 | TxVersion::V4 => false,
            TxVersion::V5 => true,
            #[cfg(zcash_unstable = "nu7")]
            TxVersion::V6 => false,
            #[cfg(zcash_unstable = "zfuture")]
            TxVersion::ZFuture => true,
        }
    }

    pub fn has_orchard_zsa(&self) -> bool {
        match self {
            #[cfg(zcash_unstable = "nu7")]
            TxVersion::V6 => true,
            _ => false,
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
            BranchId::Overwinter => TxVersion::V3,
            BranchId::Sapling | BranchId::Blossom | BranchId::Heartwood | BranchId::Canopy => {
                TxVersion::V4
            }
            BranchId::Nu5 => TxVersion::V5,
            BranchId::Nu6 => TxVersion::V5,
            #[cfg(zcash_unstable = "nu6.1")]
            BranchId::Nu6_1 => TxVersion::V5,
            #[cfg(zcash_unstable = "nu7")]
            BranchId::Nu7 => TxVersion::V6,
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

    #[cfg(zcash_unstable = "nu7")]
    type IssueAuth: orchard::issuance::IssueAuth;

    #[cfg(zcash_unstable = "zfuture")]
    type TzeAuth: tze::Authorization;
}

/// [`Authorization`] marker type for fully-authorized transactions.
#[derive(Debug, Clone)]
pub struct Authorized;

impl Authorization for Authorized {
    type TransparentAuth = transparent::Authorized;
    type SaplingAuth = sapling::bundle::Authorized;
    type OrchardAuth = orchard::bundle::Authorized;

    #[cfg(zcash_unstable = "nu7")]
    type IssueAuth = orchard::issuance::Signed;

    #[cfg(zcash_unstable = "zfuture")]
    type TzeAuth = tze::Authorized;
}

/// [`Authorization`] marker type for transactions without authorization data.
///
/// Currently this includes Sapling proofs because the types in this crate support v4
/// transactions, which commit to the Sapling proofs in the transaction digest.
pub struct Unauthorized;

#[cfg(feature = "circuits")]
impl Authorization for Unauthorized {
    type TransparentAuth = ::transparent::builder::Unauthorized;
    type SaplingAuth =
        sapling_builder::InProgress<sapling_builder::Proven, sapling_builder::Unsigned>;
    type OrchardAuth = orchard::builder::InProgress<Unproven, orchard::builder::Unauthorized>;

    #[cfg(zcash_unstable = "nu7")]
    type IssueAuth = orchard::issuance::AwaitingSighash;

    #[cfg(zcash_unstable = "zfuture")]
    type TzeAuth = tze::builder::Unauthorized;
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

#[derive(Debug, Clone)]
pub enum OrchardBundle<A: orchard::bundle::Authorization> {
    OrchardVanilla(Bundle<A, ZatBalance, OrchardVanilla>),
    #[cfg(zcash_unstable = "nu7")]
    OrchardZSA(Bundle<A, ZatBalance, OrchardZSA>),
}

impl<A: orchard::bundle::Authorization> OrchardBundle<A> {
    pub fn value_balance(&self) -> &ZatBalance {
        match self {
            OrchardBundle::OrchardVanilla(b) => b.value_balance(),
            #[cfg(zcash_unstable = "nu7")]
            OrchardBundle::OrchardZSA(b) => b.value_balance(),
        }
    }

    pub fn map_authorization<R, B: orchard::bundle::Authorization>(
        self,
        context: &mut R,
        spend_auth: impl FnMut(&mut R, &A, A::SpendAuth) -> B::SpendAuth,
        step: impl FnOnce(&mut R, A) -> B,
    ) -> OrchardBundle<B> {
        match self {
            OrchardBundle::OrchardVanilla(b) => {
                OrchardBundle::OrchardVanilla(b.map_authorization(context, spend_auth, step))
            }
            #[cfg(zcash_unstable = "nu7")]
            OrchardBundle::OrchardZSA(b) => {
                OrchardBundle::OrchardZSA(b.map_authorization(context, spend_auth, step))
            }
        }
    }

    pub fn as_vanilla_bundle(&self) -> &Bundle<A, ZatBalance, OrchardVanilla> {
        match self {
            OrchardBundle::OrchardVanilla(b) => b,
            #[cfg(zcash_unstable = "nu7")]
            OrchardBundle::OrchardZSA(_) => panic!("Wrong bundle type"),
        }
    }

    #[cfg(zcash_unstable = "nu7")]
    pub fn as_zsa_bundle(&self) -> &Bundle<A, ZatBalance, OrchardZSA> {
        match self {
            OrchardBundle::OrchardVanilla(_) => panic!("Wrong bundle type"),
            OrchardBundle::OrchardZSA(b) => b,
        }
    }
}

/// The information contained in a Zcash transaction.
#[derive(Debug)]
pub struct TransactionData<A: Authorization> {
    version: TxVersion,
    consensus_branch_id: BranchId,
    lock_time: u32,
    expiry_height: BlockHeight,
    transparent_bundle: Option<transparent::Bundle<A::TransparentAuth>>,
    sprout_bundle: Option<sprout::Bundle>,
    sapling_bundle: Option<sapling::Bundle<A::SaplingAuth, ZatBalance>>,
    orchard_bundle: Option<OrchardBundle<A::OrchardAuth>>,
    #[cfg(zcash_unstable = "nu7")]
    issue_bundle: Option<IssueBundle<A::IssueAuth>>,
    #[cfg(zcash_unstable = "zfuture")]
    tze_bundle: Option<tze::Bundle<A::TzeAuth>>,
}

impl<A: Authorization> TransactionData<A> {
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
        orchard_bundle: Option<OrchardBundle<A::OrchardAuth>>,
        #[rustfmt::skip]
        #[cfg(zcash_unstable = "nu7")]
        issue_bundle: Option<IssueBundle<A::IssueAuth>>,
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
            #[cfg(zcash_unstable = "nu7")]
            issue_bundle,
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
        transparent_bundle: Option<transparent::Bundle<A::TransparentAuth>>,
        sprout_bundle: Option<sprout::Bundle>,
        sapling_bundle: Option<sapling::Bundle<A::SaplingAuth, ZatBalance>>,
        orchard_bundle: Option<OrchardBundle<A::OrchardAuth>>,
        tze_bundle: Option<tze::Bundle<A::TzeAuth>>,
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

    pub fn transparent_bundle(&self) -> Option<&transparent::Bundle<A::TransparentAuth>> {
        self.transparent_bundle.as_ref()
    }

    pub fn sprout_bundle(&self) -> Option<&sprout::Bundle> {
        self.sprout_bundle.as_ref()
    }

    pub fn sapling_bundle(&self) -> Option<&sapling::Bundle<A::SaplingAuth, ZatBalance>> {
        self.sapling_bundle.as_ref()
    }

    pub fn orchard_bundle(&self) -> Option<&OrchardBundle<A::OrchardAuth>> {
        self.orchard_bundle.as_ref()
    }

    #[cfg(zcash_unstable = "nu7")]
    pub fn issue_bundle(&self) -> Option<&IssueBundle<A::IssueAuth>> {
        self.issue_bundle.as_ref()
    }

    #[cfg(zcash_unstable = "zfuture")]
    pub fn tze_bundle(&self) -> Option<&tze::Bundle<A::TzeAuth>> {
        self.tze_bundle.as_ref()
    }

    /// Returns the total fees paid by the transaction, given a function that can be used to
    /// retrieve the value of previous transactions' transparent outputs that are being spent in
    /// this transaction.
    pub fn fee_paid<E, F>(&self, get_prevout: F) -> Result<ZatBalance, E>
    where
        E: From<BalanceError>,
        F: FnMut(&OutPoint) -> Result<ZatBalance, E>,
    {
        let value_balances = [
            self.transparent_bundle
                .as_ref()
                .map_or_else(|| Ok(ZatBalance::zero()), |b| b.value_balance(get_prevout))?,
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
        ];

        value_balances
            .iter()
            .sum::<Option<_>>()
            .ok_or_else(|| BalanceError::Overflow.into())
    }

    pub fn digest<D: TransactionDigest<A>>(&self, digester: D) -> D::Digest {
        digester.combine(
            digester.digest_header(
                self.version,
                self.consensus_branch_id,
                self.lock_time,
                self.expiry_height,
            ),
            digester.digest_transparent(self.transparent_bundle.as_ref()),
            digester.digest_sapling(self.sapling_bundle.as_ref()),
            self.digest_orchard(&digester),
            #[cfg(zcash_unstable = "nu7")]
            digester.digest_issue(self.issue_bundle.as_ref()),
            #[cfg(zcash_unstable = "zfuture")]
            digester.digest_tze(self.tze_bundle.as_ref()),
        )
    }

    fn digest_orchard<D: TransactionDigest<A>>(&self, digester: &D) -> D::OrchardDigest {
        digester.digest_orchard(self.orchard_bundle.as_ref())
    }

    /// Maps the bundles from one type to another.
    ///
    /// This shouldn't be necessary for most use cases; it is provided for handling the
    /// cross-FFI builder logic in `zcashd`.
    pub fn map_bundles<B: Authorization>(
        self,
        f_transparent: impl FnOnce(
            Option<transparent::Bundle<A::TransparentAuth>>,
        ) -> Option<transparent::Bundle<B::TransparentAuth>>,
        f_sapling: impl FnOnce(
            Option<sapling::Bundle<A::SaplingAuth, ZatBalance>>,
        ) -> Option<sapling::Bundle<B::SaplingAuth, ZatBalance>>,
        f_orchard: impl FnOnce(
            Option<OrchardBundle<A::OrchardAuth>>,
        ) -> Option<OrchardBundle<B::OrchardAuth>>,
        #[rustfmt::skip]
        #[cfg(zcash_unstable = "nu7")]
        f_issue: impl FnOnce(
            Option<orchard::issuance::IssueBundle<A::IssueAuth>>,
        ) -> Option<orchard::issuance::IssueBundle<B::IssueAuth>>,
        #[cfg(zcash_unstable = "zfuture")] f_tze: impl FnOnce(
            Option<tze::Bundle<A::TzeAuth>>,
        )
            -> Option<tze::Bundle<B::TzeAuth>>,
    ) -> TransactionData<B> {
        TransactionData {
            version: self.version,
            consensus_branch_id: self.consensus_branch_id,
            lock_time: self.lock_time,
            expiry_height: self.expiry_height,
            transparent_bundle: f_transparent(self.transparent_bundle),
            sprout_bundle: self.sprout_bundle,
            sapling_bundle: f_sapling(self.sapling_bundle),
            orchard_bundle: f_orchard(self.orchard_bundle),
            #[cfg(zcash_unstable = "nu7")]
            issue_bundle: f_issue(self.issue_bundle),
            #[cfg(zcash_unstable = "zfuture")]
            tze_bundle: f_tze(self.tze_bundle),
        }
    }

    /// Maps the bundles from one type to another with fallible closures.
    ///
    /// This shouldn't be necessary for most use cases; it is provided for handling the
    /// transaction extraction logic in the `pczt` crate.
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
        f_orchard: impl FnOnce(
            Option<OrchardBundle<A::OrchardAuth>>,
        ) -> Result<Option<OrchardBundle<B::OrchardAuth>>, E>,
        #[rustfmt::skip]
        #[cfg(zcash_unstable = "nu7")]
        f_issue: impl FnOnce(
            Option<orchard::issuance::IssueBundle<A::IssueAuth>>,
        ) -> Option<orchard::issuance::IssueBundle<B::IssueAuth>>,
        #[cfg(zcash_unstable = "zfuture")] f_tze: impl FnOnce(
            Option<tze::Bundle<A::TzeAuth>>,
        ) -> Result<
            Option<tze::Bundle<B::TzeAuth>>,
            E,
        >,
    ) -> Result<TransactionData<B>, E> {
        Ok(TransactionData {
            version: self.version,
            consensus_branch_id: self.consensus_branch_id,
            lock_time: self.lock_time,
            expiry_height: self.expiry_height,
            transparent_bundle: f_transparent(self.transparent_bundle)?,
            sprout_bundle: self.sprout_bundle,
            sapling_bundle: f_sapling(self.sapling_bundle)?,
            orchard_bundle: f_orchard(self.orchard_bundle)?,
            #[cfg(zcash_unstable = "nu7")]
            issue_bundle: f_issue(self.issue_bundle),
            #[cfg(zcash_unstable = "zfuture")]
            tze_bundle: f_tze(self.tze_bundle)?,
        })
    }

    pub fn map_authorization<B: Authorization>(
        self,
        f_transparent: impl transparent::MapAuth<A::TransparentAuth, B::TransparentAuth>,
        mut f_sapling: impl sapling_serialization::MapAuth<A::SaplingAuth, B::SaplingAuth>,
        mut f_orchard: impl orchard_serialization::MapAuth<A::OrchardAuth, B::OrchardAuth>,
        #[rustfmt::skip]
        #[cfg(zcash_unstable = "nu7")]
        f_issue: impl issuance::MapIssueAuth<A::IssueAuth, B::IssueAuth>,
        #[cfg(zcash_unstable = "zfuture")] f_tze: impl tze::MapAuth<A::TzeAuth, B::TzeAuth>,
    ) -> TransactionData<B> {
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
            #[cfg(zcash_unstable = "nu7")]
            issue_bundle: self
                .issue_bundle
                .map(|b| b.map_authorization(|a| f_issue.map_issue_authorization(a))),
            #[cfg(zcash_unstable = "zfuture")]
            tze_bundle: self.tze_bundle.map(|b| b.map_authorization(f_tze)),
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

impl Transaction {
    fn from_data(data: TransactionData<Authorized>) -> io::Result<Self> {
        match data.version {
            TxVersion::Sprout(_) | TxVersion::V3 | TxVersion::V4 => Self::from_data_v4(data),
            TxVersion::V5 => Ok(Self::from_data_v5(data)),
            #[cfg(zcash_unstable = "nu7")]
            TxVersion::V6 => Ok(Self::from_data_v6(data)),
            #[cfg(zcash_unstable = "zfuture")]
            TxVersion::ZFuture => Ok(Self::from_data_v5(data)),
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

    #[cfg(zcash_unstable = "nu7")]
    fn from_data_v6(data: TransactionData<Authorized>) -> Self {
        // We use the same type TransactionData for both v5 and V6
        Self::from_data_v5(data)
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
            #[cfg(zcash_unstable = "nu7")]
            TxVersion::V6 => Self::read_v6(reader.into_base_reader(), version),
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
                #[cfg(zcash_unstable = "nu7")]
                issue_bundle: None,
                #[cfg(zcash_unstable = "zfuture")]
                tze_bundle: None,
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
            Self::read_v5_header_fragment(&mut reader)?;
        let transparent_bundle = Self::read_transparent(&mut reader)?;
        let sapling_bundle = sapling_serialization::read_v5_bundle(&mut reader)?;
        let orchard_bundle = orchard_serialization::read_orchard_bundle(&mut reader)?;

        #[cfg(zcash_unstable = "zfuture")]
        let tze_bundle = if version.has_tze() {
            Self::read_tze(&mut reader)?
        } else {
            None
        };

        let data = TransactionData {
            version,
            consensus_branch_id,
            lock_time,
            expiry_height,
            transparent_bundle,
            sprout_bundle: None,
            sapling_bundle,
            orchard_bundle: orchard_bundle.map(OrchardBundle::OrchardVanilla),
            #[cfg(zcash_unstable = "nu7")]
            issue_bundle: None,
            #[cfg(zcash_unstable = "zfuture")]
            tze_bundle,
        };

        Ok(Self::from_data_v5(data))
    }

    fn read_v5_header_fragment<R: Read>(mut reader: R) -> io::Result<(BranchId, u32, BlockHeight)> {
        let consensus_branch_id = reader.read_u32_le().and_then(|value| {
            BranchId::try_from(value).map_err(|_e| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
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

    #[cfg(feature = "temporary-zcashd")]
    pub fn temporary_zcashd_read_v5_sapling<R: Read>(
        reader: R,
    ) -> io::Result<Option<sapling::Bundle<sapling::bundle::Authorized, ZatBalance>>> {
        sapling_serialization::read_v5_bundle(reader)
    }

    #[cfg(zcash_unstable = "nu7")]
    fn read_v6<R: Read>(mut reader: R, version: TxVersion) -> io::Result<Self> {
        let (consensus_branch_id, lock_time, expiry_height) =
            Self::read_v5_header_fragment(&mut reader)?;
        let transparent_bundle = Self::read_transparent(&mut reader)?;
        let sapling_bundle = sapling_serialization::read_v5_bundle(&mut reader)?;
        let orchard_zsa_bundle = orchard_serialization::read_orchard_zsa_bundle(&mut reader)?;
        let issue_bundle = issuance::read_bundle(&mut reader)?;

        #[cfg(zcash_unstable = "zfuture")]
        let tze_bundle = if version.has_tze() {
            Self::read_tze(&mut reader)?
        } else {
            None
        };

        let data = TransactionData {
            version,
            consensus_branch_id,
            lock_time,
            expiry_height,
            transparent_bundle,
            sprout_bundle: None,
            sapling_bundle,
            orchard_bundle: orchard_zsa_bundle.map(OrchardBundle::OrchardZSA),
            issue_bundle,
            #[cfg(zcash_unstable = "zfuture")]
            tze_bundle,
        };

        Ok(Self::from_data_v6(data))
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
            #[cfg(zcash_unstable = "nu7")]
            TxVersion::V6 => self.write_v6(writer),
            #[cfg(zcash_unstable = "zfuture")]
            TxVersion::ZFuture => self.write_v5(writer),
        }
    }

    pub fn write_v4<W: Write>(&self, mut writer: W) -> io::Result<()> {
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

        if self.orchard_bundle.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Orchard components cannot be present when serializing to the V4 transaction format."
            ));
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
        self.write_header(&mut writer)?;
        self.write_transparent(&mut writer)?;
        self.write_sapling(&mut writer)?;
        orchard_serialization::write_orchard_bundle(&mut writer, self.orchard_bundle.as_ref())?;
        #[cfg(zcash_unstable = "zfuture")]
        self.write_tze(&mut writer)?;
        Ok(())
    }

    pub fn write_header<W: Write>(&self, mut writer: W) -> io::Result<()> {
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

    pub fn write_sapling<W: Write>(&self, writer: W) -> io::Result<()> {
        sapling_serialization::write_v5_bundle(writer, self.sapling_bundle.as_ref())
    }

    #[cfg(zcash_unstable = "nu7")]
    pub fn write_v6<W: Write>(&self, mut writer: W) -> io::Result<()> {
        if self.sprout_bundle.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Sprout components cannot be present when serializing to the V6 transaction format.",
            ));
        }
        self.write_header(&mut writer)?;
        self.write_transparent(&mut writer)?;
        self.write_sapling(&mut writer)?;
        orchard_serialization::write_orchard_bundle(&mut writer, self.orchard_bundle.as_ref())?;
        issuance::write_bundle(self.issue_bundle.as_ref(), &mut writer)?;
        #[cfg(zcash_unstable = "zfuture")]
        self.write_tze(&mut writer)?;
        Ok(())
    }

    #[cfg(zcash_unstable = "zfuture")]
    pub fn write_tze<W: Write>(&self, mut writer: W) -> io::Result<()> {
        if let Some(bundle) = &self.tze_bundle {
            Vector::write(&mut writer, &bundle.vin, |w, e| e.write(w))?;
            Vector::write(&mut writer, &bundle.vout, |w, e| e.write(w))?;
        } else {
            CompactSize::write(&mut writer, 0)?;
            CompactSize::write(&mut writer, 0)?;
        }

        Ok(())
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
    #[cfg(zcash_unstable = "nu7")]
    pub issue_digest: Option<A>,
    #[cfg(zcash_unstable = "zfuture")]
    pub tze_digests: Option<TzeDigests<A>>,
}

pub trait TransactionDigest<A: Authorization> {
    type HeaderDigest;
    type TransparentDigest;
    type SaplingDigest;
    type OrchardDigest;

    #[cfg(zcash_unstable = "nu7")]
    type IssueDigest;

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
        transparent_bundle: Option<&transparent::Bundle<A::TransparentAuth>>,
    ) -> Self::TransparentDigest;

    fn digest_sapling(
        &self,
        sapling_bundle: Option<&sapling::Bundle<A::SaplingAuth, ZatBalance>>,
    ) -> Self::SaplingDigest;

    fn digest_orchard(
        &self,
        orchard_bundle: Option<&OrchardBundle<A::OrchardAuth>>,
    ) -> Self::OrchardDigest;

    #[cfg(zcash_unstable = "nu7")]
    fn digest_issue(&self, issue_bundle: Option<&IssueBundle<A::IssueAuth>>) -> Self::IssueDigest;

    #[cfg(zcash_unstable = "zfuture")]
    fn digest_tze(&self, tze_bundle: Option<&tze::Bundle<A::TzeAuth>>) -> Self::TzeDigest;

    fn combine(
        &self,
        header_digest: Self::HeaderDigest,
        transparent_digest: Self::TransparentDigest,
        sapling_digest: Self::SaplingDigest,
        orchard_digest: Self::OrchardDigest,
        #[cfg(zcash_unstable = "nu7")] issue_digest: Self::IssueDigest,
        #[cfg(zcash_unstable = "zfuture")] tze_digest: Self::TzeDigest,
    ) -> Self::Digest;
}

pub enum DigestError {
    NotSigned,
}

#[cfg(any(test, feature = "test-dependencies"))]
pub mod testing {
    use ::transparent::bundle::testing::{self as transparent_testing};
    use ::zcash_protocol::consensus::BranchId;
    use proptest::prelude::*;

    use super::{
        components::{
            orchard::testing::{self as orchard_testing},
            sapling::testing::{self as sapling_testing},
        },
        Authorized, Transaction, TransactionData, TxId, TxVersion,
    };

    #[cfg(zcash_unstable = "zfuture")]
    use super::components::tze::testing::{self as tze};

    #[cfg(not(zcash_unstable = "zfuture"))]
    use crate::transaction::components::issuance;

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
            #[cfg(zcash_unstable = "nu6.1")]
            BranchId::Nu6_1 => Just(TxVersion::V5).boxed(),
            #[cfg(zcash_unstable = "nu7")]
            BranchId::Nu7 => Just(TxVersion::V6).boxed(),
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
            transparent_bundle in transparent_testing::arb_bundle(),
            sapling_bundle in sapling_testing::arb_bundle_for_version(version),
            orchard_bundle in orchard_testing::arb_bundle_for_version(version),
            _issue_bundle in issuance::testing::arb_bundle_for_version(version),
            version in Just(version)
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
                #[cfg(zcash_unstable = "nu7" )]
                issue_bundle: _issue_bundle,
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
            transparent_bundle in transparent_testing::arb_bundle(),
            sapling_bundle in sapling_testing::arb_bundle_for_version(version),
            orchard_bundle in orchard_testing::arb_bundle_for_version(version),
            tze_bundle in tze::arb_bundle(consensus_branch_id),
            version in Just(version)
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
