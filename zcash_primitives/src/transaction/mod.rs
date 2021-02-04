//! Structs and methods for handling Zcash transactions.

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::fmt;
use std::io::{self, Read, Write};
use std::ops::Deref;

use crate::{
    consensus::BlockHeight,
    redjubjub::Signature,
    serialize::Vector,
    util::sha256d::{HashReader, HashWriter},
};

pub mod builder;
pub mod components;
mod sighash;

#[cfg(test)]
mod tests;

pub use self::sighash::{signature_hash, signature_hash_data, SignableInput, SIGHASH_ALL};

use self::components::{Amount, JSDescription, OutputDescription, SpendDescription, TxIn, TxOut};

#[cfg(feature = "zfuture")]
use self::components::{TzeIn, TzeOut};

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
pub struct TxId(pub [u8; 32]);

impl fmt::Display for TxId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut data = self.0;
        data.reverse();
        formatter.write_str(&hex::encode(data))
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

    pub fn uses_groth_proofs(&self) -> bool {
        match self {
            TxVersion::Sprout(_) | TxVersion::Overwinter => false,
            TxVersion::Sapling => true,
            #[cfg(feature = "zfuture")]
            TxVersion::ZFuture => true,
        }
    }
}

/// A Zcash transaction.
#[derive(Debug, Clone)]
pub struct Transaction {
    txid: TxId,
    data: TransactionData,
}

impl Deref for Transaction {
    type Target = TransactionData;

    fn deref(&self) -> &TransactionData {
        &self.data
    }
}

impl PartialEq for Transaction {
    fn eq(&self, other: &Transaction) -> bool {
        self.txid == other.txid
    }
}

#[derive(Clone)]
pub struct TransactionData {
    pub version: TxVersion,
    pub vin: Vec<TxIn>,
    pub vout: Vec<TxOut>,
    #[cfg(feature = "zfuture")]
    pub tze_inputs: Vec<TzeIn>,
    #[cfg(feature = "zfuture")]
    pub tze_outputs: Vec<TzeOut>,
    pub lock_time: u32,
    pub expiry_height: BlockHeight,
    pub value_balance: Amount,
    pub shielded_spends: Vec<SpendDescription>,
    pub shielded_outputs: Vec<OutputDescription>,
    pub joinsplits: Vec<JSDescription>,
    pub joinsplit_pubkey: Option<[u8; 32]>,
    pub joinsplit_sig: Option<[u8; 64]>,
    pub binding_sig: Option<Signature>,
}

impl std::fmt::Debug for TransactionData {
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
            self.vin,
            self.vout,
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
            self.value_balance,
            self.shielded_spends,
            self.shielded_outputs,
            self.joinsplits,
            self.joinsplit_pubkey,
            self.binding_sig
        )
    }
}

impl Default for TransactionData {
    fn default() -> Self {
        TransactionData::new()
    }
}

impl TransactionData {
    pub fn new() -> Self {
        TransactionData {
            version: TxVersion::Sapling,
            vin: vec![],
            vout: vec![],
            #[cfg(feature = "zfuture")]
            tze_inputs: vec![],
            #[cfg(feature = "zfuture")]
            tze_outputs: vec![],
            lock_time: 0,
            expiry_height: 0u32.into(),
            value_balance: Amount::zero(),
            shielded_spends: vec![],
            shielded_outputs: vec![],
            joinsplits: vec![],
            joinsplit_pubkey: None,
            joinsplit_sig: None,
            binding_sig: None,
        }
    }

    #[cfg(feature = "zfuture")]
    pub fn zfuture() -> Self {
        TransactionData {
            version: TxVersion::ZFuture,
            vin: vec![],
            vout: vec![],
            tze_inputs: vec![],
            tze_outputs: vec![],
            lock_time: 0,
            expiry_height: 0u32.into(),
            value_balance: Amount::zero(),
            shielded_spends: vec![],
            shielded_outputs: vec![],
            joinsplits: vec![],
            joinsplit_pubkey: None,
            joinsplit_sig: None,
            binding_sig: None,
        }
    }

    pub fn freeze(self) -> io::Result<Transaction> {
        Transaction::from_data(self)
    }
}

impl Transaction {
    fn from_data(data: TransactionData) -> io::Result<Self> {
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

        let vin = Vector::read(&mut reader, TxIn::read)?;
        let vout = Vector::read(&mut reader, TxOut::read)?;

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

        let (value_balance, shielded_spends, shielded_outputs) = if is_sapling_v4 || has_tze {
            let vb = {
                let mut tmp = [0; 8];
                reader.read_exact(&mut tmp)?;
                Amount::from_i64_le_bytes(tmp)
            }
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "valueBalance out of range"))?;
            let ss = Vector::read(&mut reader, SpendDescription::read)?;
            let so = Vector::read(&mut reader, OutputDescription::read)?;
            (vb, ss, so)
        } else {
            (Amount::zero(), vec![], vec![])
        };

        let (joinsplits, joinsplit_pubkey, joinsplit_sig) = if version.has_sprout() {
            let jss = Vector::read(&mut reader, |r| {
                JSDescription::read(r, version.uses_groth_proofs())
            })?;
            let (pubkey, sig) = if !jss.is_empty() {
                let mut joinsplit_pubkey = [0; 32];
                let mut joinsplit_sig = [0; 64];
                reader.read_exact(&mut joinsplit_pubkey)?;
                reader.read_exact(&mut joinsplit_sig)?;
                (Some(joinsplit_pubkey), Some(joinsplit_sig))
            } else {
                (None, None)
            };
            (jss, pubkey, sig)
        } else {
            (vec![], None, None)
        };

        let binding_sig = if (is_sapling_v4 || has_tze)
            && !(shielded_spends.is_empty() && shielded_outputs.is_empty())
        {
            Some(Signature::read(&mut reader)?)
        } else {
            None
        };

        let mut txid = [0; 32];
        txid.copy_from_slice(&reader.into_hash());

        Ok(Transaction {
            txid: TxId(txid),
            data: TransactionData {
                version,
                vin,
                vout,
                #[cfg(feature = "zfuture")]
                tze_inputs,
                #[cfg(feature = "zfuture")]
                tze_outputs,
                lock_time,
                expiry_height,
                value_balance,
                shielded_spends,
                shielded_outputs,
                joinsplits,
                joinsplit_pubkey,
                joinsplit_sig,
                binding_sig,
            },
        })
    }

    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        self.version.write(&mut writer)?;

        let is_overwinter_v3 = self.version == TxVersion::Overwinter;
        let is_sapling_v4 = self.version == TxVersion::Sapling;
        #[cfg(feature = "zfuture")]
        let has_tze = self.version == TxVersion::ZFuture;
        #[cfg(not(feature = "zfuture"))]
        let has_tze = false;

        Vector::write(&mut writer, &self.vin, |w, e| e.write(w))?;
        Vector::write(&mut writer, &self.vout, |w, e| e.write(w))?;
        #[cfg(feature = "zfuture")]
        if has_tze {
            Vector::write(&mut writer, &self.tze_inputs, |w, e| e.write(w))?;
            Vector::write(&mut writer, &self.tze_outputs, |w, e| e.write(w))?;
        }
        writer.write_u32::<LittleEndian>(self.lock_time)?;
        if is_overwinter_v3 || is_sapling_v4 || has_tze {
            writer.write_u32::<LittleEndian>(u32::from(self.expiry_height))?;
        }

        if is_sapling_v4 || has_tze {
            writer.write_all(&self.value_balance.to_i64_le_bytes())?;
            Vector::write(&mut writer, &self.shielded_spends, |w, e| e.write(w))?;
            Vector::write(&mut writer, &self.shielded_outputs, |w, e| e.write(w))?;
        }

        if self.version.has_sprout() {
            Vector::write(&mut writer, &self.joinsplits, |w, e| e.write(w))?;
            if !self.joinsplits.is_empty() {
                match self.joinsplit_pubkey {
                    Some(pubkey) => writer.write_all(&pubkey)?,
                    None => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "Missing JoinSplit pubkey",
                        ));
                    }
                }
                match self.joinsplit_sig {
                    Some(sig) => writer.write_all(&sig)?,
                    None => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "Missing JoinSplit signature",
                        ));
                    }
                }
            }
        }

        if !self.version.has_sprout() || self.joinsplits.is_empty() {
            if self.joinsplit_pubkey.is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "JoinSplit pubkey should not be present",
                ));
            }
            if self.joinsplit_sig.is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "JoinSplit signature should not be present",
                ));
            }
        }

        if (is_sapling_v4 || has_tze)
            && !(self.shielded_spends.is_empty() && self.shielded_outputs.is_empty())
        {
            match self.binding_sig {
                Some(sig) => sig.write(&mut writer)?,
                None => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "Missing binding signature",
                    ));
                }
            }
        } else if self.binding_sig.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Binding signature should not be present",
            ));
        }

        Ok(())
    }
}

#[cfg(any(test, feature = "test-dependencies"))]
pub mod testing {
    use proptest::collection::vec;
    use proptest::prelude::*;
    use proptest::sample::select;

    use crate::{consensus::BranchId, legacy::Script};

    #[cfg(feature = "zfuture")]
    use crate::extensions::transparent as tze;

    use super::{
        components::{amount::MAX_MONEY, Amount, OutPoint, TxIn, TxOut},
        Transaction, TransactionData, TxVersion,
    };

    #[cfg(feature = "zfuture")]
    use super::components::{TzeIn, TzeOut};

    pub const VALID_OPCODES: [u8; 8] = [
        0x00, // OP_FALSE,
        0x51, // OP_1,
        0x52, // OP_2,
        0x53, // OP_3,
        0xac, // OP_CHECKSIG,
        0x63, // OP_IF,
        0x65, // OP_VERIF,
        0x6a, // OP_RETURN,
    ];

    prop_compose! {
        pub fn arb_outpoint()(hash in prop::array::uniform32(1u8..), n in 1..100u32) -> OutPoint {
            OutPoint::new(hash, n)
        }
    }

    prop_compose! {
        pub fn arb_script()(v in vec(select(&VALID_OPCODES[..]), 1..256)) -> Script {
            Script(v)
        }
    }

    prop_compose! {
        pub fn arb_txin()(prevout in arb_outpoint(), script_sig in arb_script(), sequence in any::<u32>()) -> TxIn {
            TxIn { prevout, script_sig, sequence }
        }
    }

    prop_compose! {
        pub fn arb_amount()(value in 0..MAX_MONEY) -> Amount {
            Amount::from_i64(value).unwrap()
        }
    }

    prop_compose! {
        pub fn arb_txout()(value in arb_amount(), script_pubkey in arb_script()) -> TxOut {
            TxOut { value, script_pubkey }
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
        pub fn arb_tzein()(prevout in arb_outpoint(), witness in arb_witness()) -> TzeIn {
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
        fn arb_tzeout()(value in arb_amount(), precondition in arb_precondition()) -> TzeOut {
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
            vin in vec(arb_txin(), 0..10),
            vout in vec(arb_txout(), 0..10),
            tze_inputs in vec(arb_tzein(), 0..10),
            tze_outputs in vec(arb_tzeout(), 0..10),
            lock_time in any::<u32>(),
            expiry_height in any::<u32>(),
            value_balance in arb_amount(),
        ) -> TransactionData {
            TransactionData {
                version,
                vin, vout,
                tze_inputs:  if branch_id == BranchId::ZFuture { tze_inputs } else { vec![] },
                tze_outputs: if branch_id == BranchId::ZFuture { tze_outputs } else { vec![] },
                lock_time,
                expiry_height: expiry_height.into(),
                value_balance: match version {
                    TxVersion::Sprout(_) | TxVersion::Overwinter => Amount::zero(),
                    _ => value_balance,
                },
                shielded_spends: vec![], //FIXME
                shielded_outputs: vec![], //FIXME
                joinsplits: vec![], //FIXME
                joinsplit_pubkey: None, //FIXME
                joinsplit_sig: None, //FIXME
                binding_sig: None, //FIXME
            }
        }
    }

    #[cfg(not(feature = "zfuture"))]
    prop_compose! {
        pub fn arb_txdata(branch_id: BranchId)(
            version in tx_versions(branch_id),
            vin in vec(arb_txin(), 0..10),
            vout in vec(arb_txout(), 0..10),
            lock_time in any::<u32>(),
            expiry_height in any::<u32>(),
            value_balance in arb_amount(),
        ) -> TransactionData {
            TransactionData {
                version,
                vin, vout,
                lock_time,
                expiry_height: expiry_height.into(),
                value_balance: match version {
                    TxVersion::Sprout(_) | TxVersion::Overwinter => Amount::zero(),
                    _ => value_balance,
                },
                shielded_spends: vec![], //FIXME
                shielded_outputs: vec![], //FIXME
                joinsplits: vec![], //FIXME
                joinsplit_pubkey: None, //FIXME
                joinsplit_sig: None, //FIXME
                binding_sig: None, //FIXME
            }
        }
    }

    prop_compose! {
        pub fn arb_tx(branch_id: BranchId)(tx_data in arb_txdata(branch_id)) -> Transaction {
            Transaction::from_data(tx_data).unwrap()
        }
    }
}
