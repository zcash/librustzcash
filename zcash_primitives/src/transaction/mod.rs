//! Structs and methods for handling Zcash transactions.
pub mod builder;
pub mod components;
pub mod sighash;
pub mod sighash_v4;
pub mod sighash_v5;
pub mod txid;
pub mod util;

#[cfg(test)]
mod tests;

use blake2b_simd::Hash as Blake2bHash;
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use ff::PrimeField;
use nonempty::NonEmpty;
use std::convert::TryFrom;
use std::fmt;
use std::fmt::Debug;
use std::io::{self, Read, Write};
use std::ops::Deref;

use orchard::{self, primitives::redpallas};

use crate::{
    consensus::{BlockHeight, BranchId},
    sapling::redjubjub,
    serialize::{CompactSize, Vector},
};

use self::{
    components::{
        amount::Amount,
        orchard as orchard_serialization,
        sapling::{
            self, OutputDescription, OutputDescriptionV5, SpendDescription, SpendDescriptionV5,
        },
        sprout::{self, JsDescription},
        transparent::{self, TxIn, TxOut},
    },
    txid::{to_txid, BlockTxCommitmentDigester, TxIdDigester},
    util::sha256d::{HashReader, HashWriter},
};

#[cfg(feature = "zfuture")]
use self::components::tze::{self, TzeIn, TzeOut};

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
#[cfg(feature = "zfuture")]
const ZFUTURE_VERSION_GROUP_ID: u32 = 0xFFFFFFFF;
#[cfg(feature = "zfuture")]
const ZFUTURE_TX_VERSION: u32 = 0x0000FFFF;

#[derive(Clone, Copy, Debug, PartialOrd, Ord, PartialEq, Eq, Hash)]
pub struct TxId([u8; 32]);

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
    #[cfg(feature = "zfuture")]
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
                #[cfg(feature = "zfuture")]
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
                #[cfg(feature = "zfuture")]
                TxVersion::ZFuture => ZFUTURE_TX_VERSION,
            }
    }

    pub fn version_group_id(&self) -> u32 {
        match self {
            TxVersion::Sprout(_) => 0,
            TxVersion::Overwinter => OVERWINTER_VERSION_GROUP_ID,
            TxVersion::Sapling => SAPLING_VERSION_GROUP_ID,
            TxVersion::Zip225 => V5_VERSION_GROUP_ID,
            #[cfg(feature = "zfuture")]
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

    pub fn has_sprout(&self) -> bool {
        match self {
            TxVersion::Sprout(v) => *v >= 2u32,
            TxVersion::Overwinter | TxVersion::Sapling => true,
            TxVersion::Zip225 => false,
            #[cfg(feature = "zfuture")]
            TxVersion::ZFuture => true,
        }
    }

    pub fn has_overwinter(&self) -> bool {
        !matches!(self, TxVersion::Sprout(_))
    }

    pub fn has_sapling(&self) -> bool {
        match self {
            TxVersion::Sprout(_) | TxVersion::Overwinter => false,
            TxVersion::Sapling => true,
            TxVersion::Zip225 => true,
            #[cfg(feature = "zfuture")]
            TxVersion::ZFuture => true,
        }
    }

    pub fn has_orchard(&self) -> bool {
        match self {
            TxVersion::Sprout(_) | TxVersion::Overwinter | TxVersion::Sapling => false,
            TxVersion::Zip225 => true,
            #[cfg(feature = "zfuture")]
            TxVersion::ZFuture => true,
        }
    }

    #[cfg(feature = "zfuture")]
    pub fn has_tze(&self) -> bool {
        matches!(self, TxVersion::ZFuture)
    }

    pub fn suggested_for_branch(consensus_branch_id: BranchId) -> Self {
        match consensus_branch_id {
            BranchId::Sprout => TxVersion::Sprout(2),
            BranchId::Overwinter => TxVersion::Overwinter,
            BranchId::Sapling | BranchId::Blossom | BranchId::Heartwood | BranchId::Canopy => {
                TxVersion::Sapling
            }
            BranchId::Nu5 => TxVersion::Zip225, //TEMPORARY WORKAROUND
            #[cfg(feature = "zfuture")]
            BranchId::ZFuture => TxVersion::ZFuture,
        }
    }
}

/// Authorization state for a bundle of transaction data.
pub trait Authorization {
    type TransparentAuth: transparent::Authorization;
    type SaplingAuth: sapling::Authorization;
    type OrchardAuth: orchard::bundle::Authorization;

    #[cfg(feature = "zfuture")]
    type TzeAuth: tze::Authorization;
}

pub struct Authorized;

impl Authorization for Authorized {
    type TransparentAuth = transparent::Authorized;
    type SaplingAuth = sapling::Authorized;
    type OrchardAuth = orchard::bundle::Authorized;

    #[cfg(feature = "zfuture")]
    type TzeAuth = tze::Authorized;
}

pub struct Unauthorized;

impl Authorization for Unauthorized {
    type TransparentAuth = transparent::builder::Unauthorized;
    type SaplingAuth = sapling::Unauthorized;
    type OrchardAuth = orchard::builder::Unauthorized;

    #[cfg(feature = "zfuture")]
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

pub struct TransactionData<A: Authorization> {
    version: TxVersion,
    consensus_branch_id: BranchId,
    lock_time: u32,
    expiry_height: BlockHeight,
    transparent_bundle: Option<transparent::Bundle<A::TransparentAuth>>,
    sprout_bundle: Option<sprout::Bundle>,
    sapling_bundle: Option<sapling::Bundle<A::SaplingAuth>>,
    orchard_bundle: Option<orchard::bundle::Bundle<A::OrchardAuth, Amount>>,
    #[cfg(feature = "zfuture")]
    tze_bundle: Option<tze::Bundle<A::TzeAuth>>,
}

impl<A: Authorization> TransactionData<A> {
    #[allow(clippy::too_many_arguments)]
    pub fn from_parts(
        version: TxVersion,
        consensus_branch_id: BranchId,
        lock_time: u32,
        expiry_height: BlockHeight,
        transparent_bundle: Option<transparent::Bundle<A::TransparentAuth>>,
        sprout_bundle: Option<sprout::Bundle>,
        sapling_bundle: Option<sapling::Bundle<A::SaplingAuth>>,
        orchard_bundle: Option<orchard::Bundle<A::OrchardAuth, Amount>>,
        #[cfg(feature = "zfuture")] tze_bundle: Option<tze::Bundle<A::TzeAuth>>,
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
            #[cfg(feature = "zfuture")]
            tze_bundle,
        }
    }

    pub fn version(&self) -> TxVersion {
        self.version
    }

    pub fn consensus_branch_id(&self) -> BranchId {
        self.consensus_branch_id
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

    pub fn sapling_bundle(&self) -> Option<&sapling::Bundle<A::SaplingAuth>> {
        self.sapling_bundle.as_ref()
    }

    pub fn orchard_bundle(&self) -> Option<&orchard::Bundle<A::OrchardAuth, Amount>> {
        self.orchard_bundle.as_ref()
    }

    #[cfg(feature = "zfuture")]
    pub fn tze_bundle(&self) -> Option<&tze::Bundle<A::TzeAuth>> {
        self.tze_bundle.as_ref()
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
            digester.digest_orchard(self.orchard_bundle.as_ref()),
            #[cfg(feature = "zfuture")]
            digester.digest_tze(self.tze_bundle.as_ref()),
        )
    }
}

impl<A: Authorization> std::fmt::Debug for TransactionData<A> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(
            f,
            "TransactionData(
                version = {:?},
                consensus_branch_id = {:?},
                lock_time = {:?},
                expiry_height = {:?},
                transparent_fields = {{{}}}
                sprout = {{{}}},
                sapling = {{{}}},
                orchard = {{{}}},
                tze = {{{}}}
            )",
            self.version,
            self.consensus_branch_id,
            self.lock_time,
            self.expiry_height,
            if let Some(b) = &self.transparent_bundle {
                format!(
                    "
                    vin = {:?},
                    vout = {:?},
                    ",
                    b.vin, b.vout
                )
            } else {
                "".to_string()
            },
            if let Some(b) = &self.sprout_bundle {
                format!(
                    "
                    joinsplits = {:?},
                    joinsplit_pubkey = {:?},
                    ",
                    b.joinsplits, b.joinsplit_pubkey
                )
            } else {
                "".to_string()
            },
            if let Some(b) = &self.sapling_bundle {
                format!(
                    "
                    value_balance = {:?},
                    shielded_spends = {:?},
                    shielded_outputs = {:?},
                    binding_sig = {:?},
                    ",
                    b.value_balance, b.shielded_spends, b.shielded_outputs, b.authorization
                )
            } else {
                "".to_string()
            },
            if let Some(b) = &self.orchard_bundle {
                format!(
                    "
                    value_balance = {:?},
                    actions = {:?},
                    ",
                    b.value_balance(),
                    b.actions().len()
                )
            } else {
                "".to_string()
            },
            {
                #[cfg(feature = "zfuture")]
                if let Some(b) = &self.tze_bundle {
                    format!(
                        "
                    tze_inputs = {:?},
                    tze_outputs = {:?},
                    ",
                        b.vin, b.vout
                    )
                } else {
                    "".to_string()
                }
                #[cfg(not(feature = "zfuture"))]
                ""
            }
        )
    }
}

impl<A: Authorization> TransactionData<A> {
    pub fn sapling_value_balance(&self) -> Amount {
        self.sapling_bundle
            .as_ref()
            .map_or(Amount::zero(), |b| b.value_balance)
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
            TxVersion::Sprout(_) | TxVersion::Overwinter | TxVersion::Sapling => {
                Self::from_data_v4(data)
            }
            TxVersion::Zip225 => Ok(Self::from_data_v5(data)),
            #[cfg(feature = "zfuture")]
            TxVersion::ZFuture => Ok(Self::from_data_v5(data)),
        }
    }

    fn from_data_v4(data: TransactionData<Authorized>) -> io::Result<Self> {
        let mut tx = Transaction {
            txid: TxId([0; 32]),
            data,
        };
        let mut writer = HashWriter::default();
        tx.write(&mut writer)?;
        tx.txid.0.copy_from_slice(&writer.into_hash());
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
            #[cfg(feature = "zfuture")]
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

        let lock_time = reader.read_u32::<LittleEndian>()?;
        let expiry_height: BlockHeight = if version.has_overwinter() {
            reader.read_u32::<LittleEndian>()?.into()
        } else {
            0u32.into()
        };

        let (value_balance, shielded_spends, shielded_outputs) = if version.has_sapling() {
            let vb = Self::read_amount(&mut reader)?;
            #[allow(clippy::redundant_closure)]
            let ss: Vec<SpendDescription<sapling::Authorized>> =
                Vector::read(&mut reader, |r| SpendDescription::read(r))?;
            #[allow(clippy::redundant_closure)]
            let so: Vec<OutputDescription<sapling::Authorized>> =
                Vector::read(&mut reader, |r| OutputDescription::read(r))?;
            (vb, ss, so)
        } else {
            (Amount::zero(), vec![], vec![])
        };

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
            Some(redjubjub::Signature::read(&mut reader)?)
        } else {
            None
        };

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
                sapling_bundle: binding_sig.map(|binding_sig| sapling::Bundle {
                    value_balance,
                    shielded_spends,
                    shielded_outputs,
                    authorization: sapling::Authorized { binding_sig },
                }),
                orchard_bundle: None,
                #[cfg(feature = "zfuture")]
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

    fn read_amount<R: Read>(mut reader: R) -> io::Result<Amount> {
        let mut tmp = [0; 8];
        reader.read_exact(&mut tmp)?;
        Amount::from_i64_le_bytes(tmp)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "valueBalance out of range"))
    }

    fn read_v5<R: Read>(mut reader: R, version: TxVersion) -> io::Result<Self> {
        let (consensus_branch_id, lock_time, expiry_height) =
            Self::read_v5_header_fragment(&mut reader)?;
        let transparent_bundle = Self::read_transparent(&mut reader)?;
        let sapling_bundle = Self::read_v5_sapling(&mut reader)?;
        let orchard_bundle = Self::read_v5_orchard(&mut reader)?;

        #[cfg(feature = "zfuture")]
        let tze_bundle = Self::read_tze(&mut reader)?;

        let data = TransactionData {
            version,
            consensus_branch_id,
            lock_time,
            expiry_height,
            transparent_bundle,
            sprout_bundle: None,
            sapling_bundle,
            orchard_bundle,
            #[cfg(feature = "zfuture")]
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

    #[allow(clippy::redundant_closure)]
    fn read_v5_sapling<R: Read>(
        mut reader: R,
    ) -> io::Result<Option<sapling::Bundle<sapling::Authorized>>> {
        let n_spends = CompactSize::read(&mut reader)?;
        let sd_v5s = Vector::read_count(&mut reader, n_spends, SpendDescriptionV5::read)?;
        let n_outputs = CompactSize::read(&mut reader)?;
        let od_v5s = Vector::read_count(&mut reader, n_outputs, OutputDescriptionV5::read)?;
        let value_balance = if n_spends > 0 || n_outputs > 0 {
            Self::read_amount(&mut reader)?
        } else {
            Amount::zero()
        };

        let anchor = if n_spends > 0 {
            Some(sapling::read_base(&mut reader, "anchor")?)
        } else {
            None
        };

        let v_spend_proofs =
            Vector::read_count(&mut reader, n_spends, |r| sapling::read_zkproof(r))?;
        let v_spend_auth_sigs = Vector::read_count(&mut reader, n_spends, |r| {
            SpendDescription::read_spend_auth_sig(r)
        })?;
        let v_output_proofs =
            Vector::read_count(&mut reader, n_outputs, |r| sapling::read_zkproof(r))?;

        let binding_sig = if n_spends > 0 || n_outputs > 0 {
            Some(redjubjub::Signature::read(&mut reader)?)
        } else {
            None
        };

        let shielded_spends = sd_v5s
            .into_iter()
            .zip(
                v_spend_proofs
                    .into_iter()
                    .zip(v_spend_auth_sigs.into_iter()),
            )
            .map(|(sd_5, (zkproof, spend_auth_sig))| {
                // the following `unwrap` is safe because we know n_spends > 0.
                sd_5.into_spend_description(anchor.unwrap(), zkproof, spend_auth_sig)
            })
            .collect();

        let shielded_outputs = od_v5s
            .into_iter()
            .zip(v_output_proofs.into_iter())
            .map(|(od_5, zkproof)| od_5.into_output_description(zkproof))
            .collect();

        Ok(binding_sig.map(|binding_sig| sapling::Bundle {
            value_balance,
            shielded_spends,
            shielded_outputs,
            authorization: sapling::Authorized { binding_sig },
        }))
    }

    fn read_v5_orchard<R: Read>(
        mut reader: R,
    ) -> io::Result<Option<orchard::Bundle<orchard::bundle::Authorized, Amount>>> {
        let n_actions = CompactSize::read(&mut reader)?;
        if n_actions == 0 {
            Ok(None)
        } else {
            let actions_without_auth = Vector::read_count(&mut reader, n_actions, |r| {
                orchard_serialization::read_action_without_auth(r)
            })?;
            let flags = orchard_serialization::read_flags(&mut reader)?;
            let value_balance = Self::read_amount(&mut reader)?;
            let anchor = orchard_serialization::read_anchor(&mut reader)?;
            let proof_size = CompactSize::read(&mut reader)?;
            let mut proof_bytes = vec![0u8; proof_size];
            reader.read_exact(&mut proof_bytes)?;
            let spend_sigs = Vector::read_count(&mut reader, n_actions, |r| {
                orchard_serialization::read_signature::<_, redpallas::SpendAuth>(r)
            })?;
            let binding_signature =
                orchard_serialization::read_signature::<_, redpallas::Binding>(&mut reader)
                    .map_err(|e| {
                        io::Error::new(
                            io::ErrorKind::InvalidInput,
                            format!(
                                "An error occurred deserializing the Orchard binding signature: {}",
                                e
                            ),
                        )
                    })?;

            let actions = NonEmpty::from_vec(
                actions_without_auth
                    .into_iter()
                    .zip(spend_sigs.into_iter())
                    .map(|(act, sig)| act.map(|_| sig))
                    .collect(),
            )
            .expect("A nonzero number of actions was read from the transaction data.");

            let authorization = orchard::bundle::Authorized::from_parts(
                orchard::Proof::new(proof_bytes),
                binding_signature,
            );

            Ok(Some(orchard::Bundle::from_parts(
                actions,
                flags,
                value_balance,
                anchor,
                authorization,
            )))
        }
    }

    #[cfg(feature = "zfuture")]
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
            TxVersion::Sprout(_) | TxVersion::Overwinter | TxVersion::Sapling => {
                self.write_v4(writer)
            }
            TxVersion::Zip225 => self.write_v5(writer),
            #[cfg(feature = "zfuture")]
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

        if self.version.has_sapling() {
            writer.write_all(
                &self
                    .sapling_bundle
                    .as_ref()
                    .map_or(Amount::zero(), |b| b.value_balance)
                    .to_i64_le_bytes(),
            )?;
            Vector::write(
                &mut writer,
                self.sapling_bundle
                    .as_ref()
                    .map_or(&[], |b| &b.shielded_spends),
                |w, e| e.write_v4(w),
            )?;
            Vector::write(
                &mut writer,
                self.sapling_bundle
                    .as_ref()
                    .map_or(&[], |b| &b.shielded_outputs),
                |w, e| e.write_v4(w),
            )?;
        } else if self.sapling_bundle.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Sapling components may not be present if Sapling is not active.",
            ));
        }

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
                bundle.authorization.binding_sig.write(&mut writer)?;
            }
        }

        if self.orchard_bundle.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Orchard components may not be present when serializing to the V4 transaction format."
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
        self.write_v5_header(&mut writer)?;
        self.write_transparent(&mut writer)?;
        self.write_v5_sapling(&mut writer)?;
        self.write_v5_orchard(&mut writer)?;
        #[cfg(feature = "zfuture")]
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

    pub fn write_v5_sapling<W: Write>(&self, mut writer: W) -> io::Result<()> {
        if let Some(bundle) = &self.sapling_bundle {
            CompactSize::write(&mut writer, bundle.shielded_spends.len())?;
            Vector::write_items(&mut writer, &bundle.shielded_spends, |w, e| {
                e.write_v5_without_witness_data(w)
            })?;

            CompactSize::write(&mut writer, bundle.shielded_outputs.len())?;
            Vector::write_items(&mut writer, &bundle.shielded_outputs, |w, e| {
                e.write_v5_without_proof(w)
            })?;

            if !(bundle.shielded_spends.is_empty() && bundle.shielded_outputs.is_empty()) {
                writer.write_all(&bundle.value_balance.to_i64_le_bytes())?;
            }
            if !bundle.shielded_spends.is_empty() {
                writer.write_all(bundle.shielded_spends[0].anchor.to_repr().as_ref())?;
            }

            Vector::write_items(
                &mut writer,
                bundle.shielded_spends.iter().map(|s| s.zkproof),
                |w, e| w.write_all(e),
            )?;
            Vector::write_items(
                &mut writer,
                bundle.shielded_spends.iter().map(|s| s.spend_auth_sig),
                |w, e| e.write(w),
            )?;

            Vector::write_items(
                &mut writer,
                bundle.shielded_outputs.iter().map(|s| s.zkproof),
                |w, e| w.write_all(e),
            )?;

            if !bundle.shielded_spends.is_empty() || !bundle.shielded_outputs.is_empty() {
                bundle.authorization.binding_sig.write(&mut writer)?;
            }
        } else {
            CompactSize::write(&mut writer, 0)?;
            CompactSize::write(&mut writer, 0)?;
        }

        Ok(())
    }

    pub fn write_v5_orchard<W: Write>(&self, mut writer: W) -> io::Result<()> {
        if let Some(bundle) = &self.orchard_bundle {
            CompactSize::write(&mut writer, bundle.actions().len())?;
            Vector::write_items(&mut writer, bundle.actions().iter(), |w, a| {
                orchard_serialization::write_action_without_auth(w, a)
            })?;

            if !bundle.actions().is_empty() {
                orchard_serialization::write_flags(&mut writer, &bundle.flags())?;
                writer.write_all(&bundle.value_balance().to_i64_le_bytes())?;
                orchard_serialization::write_anchor(&mut writer, bundle.anchor())?;
                let proof_bytes: &[u8] = bundle.authorization().proof().as_ref();
                CompactSize::write(&mut writer, proof_bytes.len())?;
                writer.write_all(&proof_bytes)?;
                Vector::write_items(
                    &mut writer,
                    bundle.actions().iter().map(|a| a.authorization()),
                    |w, auth| w.write_all(&<[u8; 64]>::from(*auth)),
                )?;
                writer.write_all(&<[u8; 64]>::from(
                    bundle.authorization().binding_signature(),
                ))?;
            }
        } else {
            CompactSize::write(&mut writer, 0)?;
        }

        Ok(())
    }

    #[cfg(feature = "zfuture")]
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
    pub fn auth_commitment(&self) -> Result<Blake2bHash, DigestError> {
        Ok(self.data.digest(BlockTxCommitmentDigester))
    }
}

#[derive(Clone)]
pub struct TransparentDigests<A> {
    pub prevout_digest: A,
    pub sequence_digest: A,
    pub outputs_digest: A,
    pub per_input_digest: Option<A>,
}

#[derive(Clone)]
pub struct TzeDigests<A> {
    pub inputs_digest: A,
    pub outputs_digest: A,
    pub per_input_digest: Option<A>,
}

#[derive(Clone)]
pub struct TxDigests<A> {
    pub header_digest: A,
    pub transparent_digests: Option<TransparentDigests<A>>,
    pub sapling_digest: A,
    pub orchard_digest: A,
    #[cfg(feature = "zfuture")]
    pub tze_digests: Option<TzeDigests<A>>,
}

pub trait TransactionDigest<A: Authorization> {
    type HeaderDigest;
    type TransparentDigest;
    type SaplingDigest;
    type OrchardDigest;

    #[cfg(feature = "zfuture")]
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
        sapling_bundle: Option<&sapling::Bundle<A::SaplingAuth>>,
    ) -> Self::SaplingDigest;

    fn digest_orchard(
        &self,
        orchard_bundle: Option<&orchard::Bundle<A::OrchardAuth, Amount>>,
    ) -> Self::OrchardDigest;

    #[cfg(feature = "zfuture")]
    fn digest_tze(&self, tze_bundle: Option<&tze::Bundle<A::TzeAuth>>) -> Self::TzeDigest;

    fn combine(
        &self,
        header_digest: Self::HeaderDigest,
        transparent_digest: Self::TransparentDigest,
        sapling_digest: Self::SaplingDigest,
        orchard_digest: Self::OrchardDigest,
        #[cfg(feature = "zfuture")] tze_digest: Self::TzeDigest,
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
        },
        Authorized, Transaction, TransactionData, TxId, TxVersion,
    };

    #[cfg(feature = "zfuture")]
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
            #[cfg(feature = "zfuture")]
            BranchId::ZFuture => Just(TxVersion::ZFuture).boxed(),
        }
    }

    #[cfg(not(feature = "zfuture"))]
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
        ) -> TransactionData<Authorized> {
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

    #[cfg(feature = "zfuture")]
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
