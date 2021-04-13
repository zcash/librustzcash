//! Structs and methods for handling Zcash transactions.

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::fmt;
use std::io::{self, Read, Write};
use std::ops::Deref;

use orchard;

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
    sighash::{signature_hash_data, SignableInput, SIGHASH_ALL},
    util::sha256d::{HashReader, HashWriter},
};

#[cfg(feature = "zfuture")]
use self::components::{TzeIn, TzeOut};

pub mod builder;
pub mod components;
pub mod sighash;
pub mod util;

#[cfg(test)]
mod tests;

const OVERWINTER_VERSION_GROUP_ID: u32 = 0x03C48270;
const OVERWINTER_TX_VERSION: u32 = 3;
const SAPLING_VERSION_GROUP_ID: u32 = 0x892F2085;
const SAPLING_TX_VERSION: u32 = 4;

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
                #[cfg(feature = "zfuture")]
                TxVersion::ZFuture => ZFUTURE_TX_VERSION,
            }
    }

    pub fn version_group_id(&self) -> u32 {
        match self {
            TxVersion::Sprout(_) => 0,
            TxVersion::Overwinter => OVERWINTER_VERSION_GROUP_ID,
            TxVersion::Sapling => SAPLING_VERSION_GROUP_ID,
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
            #[cfg(feature = "zfuture")]
            TxVersion::ZFuture => true,
        }
    }

    pub fn has_sapling(&self) -> bool {
        match self {
            TxVersion::Sprout(_) | TxVersion::Overwinter => false,
            TxVersion::Sapling => true,
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
}

pub struct Authorized;

impl Authorization for Authorized {
    type TransparentAuth = transparent::Authorized;
    type SaplingAuth = sapling::Authorized;
    type OrchardAuth = orchard::bundle::Authorized;
}

pub struct Unauthorized;

impl Authorization for Unauthorized {
    type TransparentAuth = transparent::Unauthorized;
    type SaplingAuth = sapling::Unauthorized;
    type OrchardAuth = orchard::builder::Unauthorized;
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

impl Transaction {
    pub fn sapling_value_balance(&self) -> Amount {
        self.data
            .sapling_bundle
            .as_ref()
            .map_or(Amount::zero(), |b| b.value_balance)
    }
}

pub struct TransactionData<A: Authorization> {
    pub version: TxVersion,
    #[cfg(feature = "zfuture")]
    pub tze_inputs: Vec<TzeIn>,
    #[cfg(feature = "zfuture")]
    pub tze_outputs: Vec<TzeOut>,
    pub lock_time: u32,
    pub expiry_height: BlockHeight,
    pub transparent_bundle: Option<transparent::Bundle<A::TransparentAuth>>,
    pub sprout_bundle: Option<sprout::Bundle>,
    pub sapling_bundle: Option<sapling::Bundle<A::SaplingAuth>>,
    pub orchard_bundle: Option<orchard::Bundle<A::OrchardAuth, Amount>>,
}

impl<A: Authorization> std::fmt::Debug for TransactionData<A> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(
            f,
            "TransactionData(
                version = {:?},
                vin = {:?},
                vout = {:?},{}
                lock_time = {:?},
                expiry_height = {:?},
                value_balance = {:?},
                shielded_spends = {:?},
                shielded_outputs = {:?},
                joinsplits = {:?},
                joinsplit_pubkey = {:?},
                binding_sig = {:?})",
            self.version,
            self.transparent_bundle.as_ref().map_or(&vec![], |b| &b.vin),
            self.transparent_bundle
                .as_ref()
                .map_or(&vec![], |b| &b.vout),
            {
                #[cfg(feature = "zfuture")]
                {
                    format!(
                        "
                tze_inputs = {:?},
                tze_outputs = {:?},",
                        self.tze_inputs, self.tze_outputs
                    )
                }
                #[cfg(not(feature = "zfuture"))]
                ""
            },
            self.lock_time,
            self.expiry_height,
            self.sapling_bundle
                .as_ref()
                .map_or(Amount::zero(), |b| b.value_balance),
            self.sapling_bundle
                .as_ref()
                .map_or(&vec![], |b| &b.shielded_spends),
            self.sapling_bundle
                .as_ref()
                .map_or(&vec![], |b| &b.shielded_outputs),
            self.sprout_bundle
                .as_ref()
                .map_or(&vec![], |b| &b.joinsplits),
            self.sprout_bundle.as_ref().map(|b| &b.joinsplit_pubkey),
            self.sapling_bundle.as_ref().map(|b| &b.authorization)
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
            #[cfg(feature = "zfuture")]
            tze_inputs: vec![],
            #[cfg(feature = "zfuture")]
            tze_outputs: vec![],
            lock_time: 0,
            expiry_height: 0u32.into(),
            transparent_bundle: None,
            sprout_bundle: None,
            sapling_bundle: None,
            orchard_bundle: None,
        }
    }

    #[cfg(feature = "zfuture")]
    pub fn zfuture() -> Self {
        TransactionData {
            version: TxVersion::ZFuture,
            tze_inputs: vec![],
            tze_outputs: vec![],
            lock_time: 0,
            expiry_height: 0u32.into(),
            transparent_bundle: None,
            sprout_bundle: None,
            sapling_bundle: None,
            orchard_bundle: None,
        }
    }
}

impl TransactionData<Authorized> {
    pub fn freeze(self, _consensus_branch_id: BranchId) -> io::Result<Transaction> {
        Transaction::from_data(self)
    }
}

impl Transaction {
    fn from_data(data: TransactionData<Authorized>) -> io::Result<Self> {
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

        #[cfg(feature = "zfuture")]
        let has_tze = version == TxVersion::ZFuture;
        #[cfg(not(feature = "zfuture"))]
        let has_tze = false;

        let transparent_bundle = Self::read_transparent(&mut reader)?;

        #[cfg(feature = "zfuture")]
        let (tze_inputs, tze_outputs) = if has_tze {
            let wi = Vector::read(&mut reader, TzeIn::read)?;
            let wo = Vector::read(&mut reader, TzeOut::read)?;
            (wi, wo)
        } else {
            (vec![], vec![])
        };

        let lock_time = reader.read_u32::<LittleEndian>()?;
        let expiry_height: BlockHeight = if is_overwinter_v3 || is_sapling_v4 || has_tze {
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

        let binding_sig = if (is_sapling_v4 || has_tze)
            && !(shielded_spends.is_empty() && shielded_outputs.is_empty())
        {
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
                #[cfg(feature = "zfuture")]
                tze_inputs,
                #[cfg(feature = "zfuture")]
                tze_outputs,
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

        #[cfg(feature = "zfuture")]
        let has_tze = self.version == TxVersion::ZFuture;
        #[cfg(not(feature = "zfuture"))]
        let has_tze = false;

        self.write_transparent(&mut writer)?;

        #[cfg(feature = "zfuture")]
        if has_tze {
            Vector::write(&mut writer, &self.tze_inputs, |w, e| e.write(w))?;
            Vector::write(&mut writer, &self.tze_outputs, |w, e| e.write(w))?;
        }
        writer.write_u32::<LittleEndian>(self.lock_time)?;
        if is_overwinter_v3 || is_sapling_v4 || has_tze {
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
            Vector::write(
                &mut writer,
                self.sprout_bundle.as_ref().map_or(&[], |b| &b.joinsplits),
                |w, e| e.write(w),
            )?;
            for bundle in &self.sprout_bundle {
                writer.write_all(&bundle.joinsplit_pubkey)?;
                writer.write_all(&bundle.joinsplit_sig)?;
            }
        }

        if self.version.has_sapling() {
            if let Some(bundle) = self.sapling_bundle.as_ref() {
                bundle.authorization.binding_sig.write(&mut writer)?;
            }
        } else if self.sapling_bundle.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Binding signature should not be present",
            ));
        }

        Ok(())
    }

    pub fn write_transparent<W: Write>(&self, mut writer: W) -> io::Result<()> {
        match &self.transparent_bundle {
            Some(bundle) => {
                Vector::write(&mut writer, &bundle.vin, |w, e| e.write(w))?;
                Vector::write(&mut writer, &bundle.vout, |w, e| e.write(w))?;
            }
            None => {
                CompactSize::write(&mut writer, 0)?;
                CompactSize::write(&mut writer, 0)?;
            }
        }
        Ok(())
    }
}

#[cfg(any(test, feature = "test-dependencies"))]
pub mod testing {
    use proptest::collection::vec;
    use proptest::prelude::*;
    use proptest::sample::select;

    use crate::consensus::BranchId;

    #[cfg(feature = "zfuture")]
    use crate::extensions::transparent as tze;

    use super::{
        components::{
            amount::testing::arb_nonnegative_amount, transparent::testing as transparent,
        },
        Authorized, Transaction, TransactionData, TxId, TxVersion,
    };

    #[cfg(feature = "zfuture")]
    use super::components::{TzeIn, TzeOut, TzeOutPoint};

    pub fn arb_txid() -> impl Strategy<Value = TxId> {
        prop::array::uniform32(any::<u8>()).prop_map(TxId::from_bytes)
    }

    #[cfg(feature = "zfuture")]
    prop_compose! {
        pub fn arb_tzeoutpoint()(txid in arb_txid(), n in 1..100u32) -> TzeOutPoint {
            TzeOutPoint::new(txid, n)
        }
    }

    #[cfg(feature = "zfuture")]
    prop_compose! {
        pub fn arb_witness()(extension_id in 0..100u32, mode in 0..100u32, payload in vec(any::<u8>(), 32..256))  -> tze::Witness {
            tze::Witness { extension_id, mode, payload }
        }
    }

    #[cfg(feature = "zfuture")]
    prop_compose! {
        pub fn arb_tzein()(prevout in arb_tzeoutpoint(), witness in arb_witness()) -> TzeIn {
            TzeIn { prevout, witness }
        }
    }

    #[cfg(feature = "zfuture")]
    prop_compose! {
        pub fn arb_precondition()(extension_id in 0..100u32, mode in 0..100u32, payload in vec(any::<u8>(), 32..256))  -> tze::Precondition {
            tze::Precondition { extension_id, mode, payload }
        }
    }

    #[cfg(feature = "zfuture")]
    prop_compose! {
        fn arb_tzeout()(value in arb_nonnegative_amount(), precondition in arb_precondition()) -> TzeOut {
            TzeOut { value, precondition }
        }
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

    fn tx_versions(branch_id: BranchId) -> impl Strategy<Value = TxVersion> {
        match branch_id {
            BranchId::Sprout => (1..=2u32).prop_map(TxVersion::Sprout).boxed(),
            BranchId::Overwinter => Just(TxVersion::Overwinter).boxed(),
            #[cfg(feature = "zfuture")]
            BranchId::ZFuture => Just(TxVersion::ZFuture).boxed(),
            _otherwise => Just(TxVersion::Sapling).boxed(),
        }
    }

    #[cfg(feature = "zfuture")]
    prop_compose! {
        pub fn arb_txdata(branch_id: BranchId)(
            version in tx_versions(branch_id),
            transparent_bundle in transparent::arb_bundle(),
            tze_inputs in vec(arb_tzein(), 0..10),
            tze_outputs in vec(arb_tzeout(), 0..10),
            lock_time in any::<u32>(),
            expiry_height in any::<u32>(),
        ) -> TransactionData<Authorized> {
            TransactionData {
                version,
                tze_inputs:  if branch_id == BranchId::ZFuture { tze_inputs } else { vec![] },
                tze_outputs: if branch_id == BranchId::ZFuture { tze_outputs } else { vec![] },
                lock_time,
                expiry_height: expiry_height.into(),
                transparent_bundle,
                sprout_bundle: None,
                sapling_bundle: None, //FIXME
                orchard_bundle: None, //FIXME
            }
        }
    }

    #[cfg(not(feature = "zfuture"))]
    prop_compose! {
        pub fn arb_txdata(branch_id: BranchId)(
            version in tx_versions(branch_id),
            transparent_bundle in transparent::arb_bundle(),
            lock_time in any::<u32>(),
            expiry_height in any::<u32>(),
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

    prop_compose! {
        pub fn arb_tx(branch_id: BranchId)(tx_data in arb_txdata(branch_id)) -> Transaction {
            Transaction::from_data(tx_data).unwrap()
        }
    }
}
