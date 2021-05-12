//! Structs and methods for handling Zcash transactions.

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::fmt;
use std::io::{self, Read, Write};
use std::ops::Deref;

use crate::{
    consensus::{BlockHeight, BranchId},
    sapling::redjubjub,
    serialize::{CompactSize, Vector},
};

use self::{
    components::{
        amount::Amount,
        sapling::{self, OutputDescription, SpendDescription},
        sprout::{self, JsDescription},
        transparent::{self, TxIn, TxOut},
    },
    sighash_v4::{signature_hash_data, SignableInput, SIGHASH_ALL},
    util::sha256d::{HashReader, HashWriter},
};

#[cfg(feature = "zfuture")]
use self::components::tze;

pub mod builder;
pub mod components;
pub mod sighash_v4;
pub mod util;

#[cfg(test)]
mod tests;

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
    ZcashTxV5,
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
                TxVersion::ZcashTxV5 => V5_TX_VERSION,
                #[cfg(feature = "zfuture")]
                TxVersion::ZFuture => ZFUTURE_TX_VERSION,
            }
    }

    pub fn version_group_id(&self) -> u32 {
        match self {
            TxVersion::Sprout(_) => 0,
            TxVersion::Overwinter => OVERWINTER_VERSION_GROUP_ID,
            TxVersion::Sapling => SAPLING_VERSION_GROUP_ID,
            TxVersion::ZcashTxV5 => V5_VERSION_GROUP_ID,
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
            TxVersion::ZcashTxV5 => false,
            #[cfg(feature = "zfuture")]
            TxVersion::ZFuture => true,
        }
    }

    pub fn has_sapling(&self) -> bool {
        match self {
            TxVersion::Sprout(_) | TxVersion::Overwinter => false,
            TxVersion::Sapling => true,
            TxVersion::ZcashTxV5 => true,
            #[cfg(feature = "zfuture")]
            TxVersion::ZFuture => true,
        }
    }

    pub fn suggested_for_branch(consensus_branch_id: BranchId) -> Self {
        match consensus_branch_id {
            BranchId::Sprout => TxVersion::Sprout(2),
            BranchId::Overwinter => TxVersion::Overwinter,
            BranchId::Sapling | BranchId::Blossom | BranchId::Heartwood | BranchId::Canopy => {
                TxVersion::Sapling
            }
            BranchId::Nu5 => TxVersion::Sapling, //TEMPORARY WORKAROUND
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
    type TransparentAuth = transparent::Unauthorized;
    type SaplingAuth = sapling::Unauthorized;
    type OrchardAuth = orchard::builder::Unauthorized;

    #[cfg(feature = "zfuture")]
    type TzeAuth = tze::Unauthorized;
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
    pub version: TxVersion,
    pub lock_time: u32,
    pub expiry_height: BlockHeight,
    pub transparent_bundle: Option<transparent::Bundle<A::TransparentAuth>>,
    pub sprout_bundle: Option<sprout::Bundle>,
    pub sapling_bundle: Option<sapling::Bundle<A::SaplingAuth>>,
    pub orchard_bundle: Option<orchard::bundle::Bundle<A::OrchardAuth, Amount>>,
    #[cfg(feature = "zfuture")]
    pub tze_bundle: Option<tze::Bundle<A::TzeAuth>>,
}

impl<A: Authorization> std::fmt::Debug for TransactionData<A> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(
            f,
            "TransactionData(
                version = {:?},
                lock_time = {:?},
                expiry_height = {:?},
                {}{}{}{}",
            self.version,
            self.lock_time,
            self.expiry_height,
            if let Some(b) = &self.transparent_bundle {
                format!(
                    "
                vin = {:?},
                vout = {:?},",
                    b.vin, b.vout
                )
            } else {
                "".to_string()
            },
            if let Some(b) = &self.sprout_bundle {
                format!(
                    "
                joinsplits = {:?},
                joinsplit_pubkey = {:?},",
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
                binding_sig = {:?},",
                    b.value_balance, b.shielded_spends, b.shielded_outputs, b.authorization
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
                tze_outputs = {:?},",
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

impl Default for TransactionData<Unauthorized> {
    fn default() -> Self {
        Self::new()
    }
}

impl TransactionData<Unauthorized> {
    pub fn new() -> Self {
        TransactionData {
            version: TxVersion::Sapling,
            lock_time: 0,
            expiry_height: 0u32.into(),
            transparent_bundle: None,
            sprout_bundle: None,
            sapling_bundle: None,
            orchard_bundle: None,
            #[cfg(feature = "zfuture")]
            tze_bundle: None,
        }
    }

    #[cfg(feature = "zfuture")]
    pub fn zfuture() -> Self {
        TransactionData {
            version: TxVersion::ZFuture,
            lock_time: 0,
            expiry_height: 0u32.into(),
            transparent_bundle: None,
            sprout_bundle: None,
            sapling_bundle: None,
            orchard_bundle: None,
            tze_bundle: None,
        }
    }
}

impl TransactionData<Authorized> {
    pub fn freeze(self, consensus_branch_id: BranchId) -> io::Result<Transaction> {
        Transaction::from_data(self, consensus_branch_id)
    }
}

impl Transaction {
    fn from_data(
        data: TransactionData<Authorized>,
        _consensus_branch_id: BranchId,
    ) -> io::Result<Self> {
        let mut tx = Transaction {
            txid: TxId([0; 32]),
            data,
        };
        let mut writer = HashWriter::default();
        tx.write(&mut writer)?;
        tx.txid.0.copy_from_slice(&writer.into_hash());
        Ok(tx)
    }

    pub fn txid(&self) -> TxId {
        self.txid
    }

    pub fn read<R: Read>(reader: R) -> io::Result<Self> {
        let mut reader = HashReader::new(reader);

        let version = TxVersion::read(&mut reader)?;
        let is_overwinter_v3 = version == TxVersion::Overwinter;
        let is_sapling_v4 = version == TxVersion::Sapling;

        let transparent_bundle = Self::read_transparent(&mut reader)?;

        let lock_time = reader.read_u32::<LittleEndian>()?;
        let expiry_height: BlockHeight = if is_overwinter_v3 || is_sapling_v4 {
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

        let binding_sig =
            if is_sapling_v4 && !(shielded_spends.is_empty() && shielded_outputs.is_empty()) {
                Some(redjubjub::Signature::read(&mut reader)?)
            } else {
                None
            };

        let mut txid = [0; 32];
        txid.copy_from_slice(&reader.into_hash());

        Ok(Transaction {
            txid: TxId(txid),
            data: TransactionData {
                version,
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
            Some(transparent::Bundle { vin, vout })
        })
    }

    fn read_amount<R: Read>(mut reader: R) -> io::Result<Amount> {
        let mut tmp = [0; 8];
        reader.read_exact(&mut tmp)?;
        Amount::from_i64_le_bytes(tmp)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "valueBalance out of range"))
    }

    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        self.version.write(&mut writer)?;

        let is_overwinter_v3 = self.version == TxVersion::Overwinter;
        let is_sapling_v4 = self.version == TxVersion::Sapling;

        self.write_transparent(&mut writer)?;

        writer.write_u32::<LittleEndian>(self.lock_time)?;
        if is_overwinter_v3 || is_sapling_v4 {
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
                |w, e| e.write(w),
            )?;
            Vector::write(
                &mut writer,
                self.sapling_bundle
                    .as_ref()
                    .map_or(&[], |b| &b.shielded_outputs),
                |w, e| e.write(w),
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
        } else if self.sapling_bundle.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Sapling components may not be present if Sapling is not active.",
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
}

#[cfg(any(test, feature = "test-dependencies"))]
pub mod testing {
    use proptest::prelude::*;
    use proptest::sample::select;

    use crate::consensus::BranchId;

    use super::{
        components::transparent::testing as transparent, Authorized, Transaction, TransactionData,
        TxId, TxVersion,
    };

    pub fn arb_txid() -> impl Strategy<Value = TxId> {
        prop::array::uniform32(any::<u8>()).prop_map(TxId::from_bytes)
    }

    pub fn arb_branch_id() -> impl Strategy<Value = BranchId> {
        select(vec![
            BranchId::Sprout,
            BranchId::Overwinter,
            BranchId::Sapling,
            BranchId::Blossom,
            BranchId::Heartwood,
            BranchId::Canopy,
            #[cfg(feature = "zfuture")]
            BranchId::ZFuture,
        ])
    }

    pub fn arb_tx_version(branch_id: BranchId) -> impl Strategy<Value = TxVersion> {
        match branch_id {
            BranchId::Sprout => (1..=2u32).prop_map(TxVersion::Sprout).boxed(),
            BranchId::Overwinter => Just(TxVersion::Overwinter).boxed(),
            //#[cfg(feature = "zfuture")]
            //BranchId::ZFuture => Just(TxVersion::ZFuture).boxed(),
            _otherwise => Just(TxVersion::Sapling).boxed(),
        }
    }

    #[cfg(not(feature = "zfuture"))]
    prop_compose! {
        pub fn arb_txdata(branch_id: BranchId)(
            version in arb_tx_version(branch_id),
            lock_time in any::<u32>(),
            expiry_height in any::<u32>(),
            transparent_bundle in transparent::arb_bundle(),
        ) -> TransactionData<Authorized> {
            TransactionData {
                version,
                lock_time,
                expiry_height: expiry_height.into(),
                transparent_bundle,
                sprout_bundle: None,
                sapling_bundle: None, //FIXME
                orchard_bundle: None, //FIXME
            }
        }
    }

    #[cfg(feature = "zfuture")]
    prop_compose! {
        pub fn arb_txdata(branch_id: BranchId)(
            version in arb_tx_version(branch_id),
            lock_time in any::<u32>(),
            expiry_height in any::<u32>(),
            transparent_bundle in transparent::arb_bundle(),
            //tze_bundle in tze::arb_bundle(branch_id),
        ) -> TransactionData<Authorized> {
            TransactionData {
                version,
                lock_time,
                expiry_height: expiry_height.into(),
                transparent_bundle,
                sprout_bundle: None,
                sapling_bundle: None, //FIXME
                orchard_bundle: None, //FIXME
                tze_bundle: None
            }
        }
    }

    prop_compose! {
        pub fn arb_tx(branch_id: BranchId)(tx_data in arb_txdata(branch_id)) -> Transaction {
            Transaction::from_data(tx_data, branch_id).unwrap()
        }
    }
}
