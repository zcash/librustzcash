//! Structs and methods for handling Zcash transactions.

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use hex;
use sha2::{Digest, Sha256};
use std::fmt;
use std::io::{self, Read, Write};
use std::ops::Deref;

use crate::{consensus::BlockHeight, redjubjub::Signature, serialize::Vector};

pub mod builder;
pub mod components;
mod sighash;

#[cfg(test)]
mod tests;

pub use self::sighash::{signature_hash, signature_hash_data, SignableInput, SIGHASH_ALL};

use self::components::{
    Amount, JSDescription, OutputDescription, SpendDescription, TxIn, TxOut, TzeIn, TzeOut,
};

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
const ZFUTURE_VERSION_GROUP_ID: u32 = 0xFFFFFFFF;
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
    pub overwintered: bool,
    pub version: u32,
    pub version_group_id: u32,
    pub vin: Vec<TxIn>,
    pub vout: Vec<TxOut>,
    pub tze_inputs: Vec<TzeIn>,
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
                overwintered = {:?},
                version = {:?},
                version_group_id = {:?},
                vin = {:?},
                vout = {:?},
                tze_inputs = {:?},
                tze_outputs = {:?},
                lock_time = {:?},
                expiry_height = {:?},
                value_balance = {:?},
                shielded_spends = {:?},
                shielded_outputs = {:?},
                joinsplits = {:?},
                joinsplit_pubkey = {:?},
                binding_sig = {:?})",
            self.overwintered,
            self.version,
            self.version_group_id,
            self.vin,
            self.vout,
            self.tze_inputs,
            self.tze_outputs,
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

impl TransactionData {
    pub fn new() -> Self {
        TransactionData {
            overwintered: true,
            version: SAPLING_TX_VERSION,
            version_group_id: SAPLING_VERSION_GROUP_ID,
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

    pub fn zfuture() -> Self {
        TransactionData {
            overwintered: true,
            version: ZFUTURE_TX_VERSION,
            version_group_id: ZFUTURE_VERSION_GROUP_ID,
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

    fn header(&self) -> u32 {
        let mut header = self.version;
        if self.overwintered {
            header |= 1 << 31;
        }
        header
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
        let mut raw = vec![];
        tx.write(&mut raw)?;
        tx.txid
            .0
            .copy_from_slice(&Sha256::digest(&Sha256::digest(&raw)));
        Ok(tx)
    }

    pub fn txid(&self) -> TxId {
        self.txid
    }

    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let header = reader.read_u32::<LittleEndian>()?;
        let overwintered = (header >> 31) == 1;
        let version = header & 0x7FFFFFFF;

        let version_group_id = if overwintered {
            reader.read_u32::<LittleEndian>()?
        } else {
            0
        };

        let is_overwinter_v3 = overwintered
            && version_group_id == OVERWINTER_VERSION_GROUP_ID
            && version == OVERWINTER_TX_VERSION;
        let is_sapling_v4 = overwintered
            && version_group_id == SAPLING_VERSION_GROUP_ID
            && version == SAPLING_TX_VERSION;
        let has_tze = overwintered
            && version_group_id == ZFUTURE_VERSION_GROUP_ID
            && version == ZFUTURE_TX_VERSION;

        if overwintered && !(is_overwinter_v3 || is_sapling_v4 || has_tze) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Unknown transaction format",
            ));
        }

        let vin = Vector::read(&mut reader, TxIn::read)?;
        let vout = Vector::read(&mut reader, TxOut::read)?;
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

        let (joinsplits, joinsplit_pubkey, joinsplit_sig) = if version >= 2 {
            let jss = Vector::read(&mut reader, |r| {
                JSDescription::read(r, overwintered && version >= SAPLING_TX_VERSION)
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

        Transaction::from_data(TransactionData {
            overwintered,
            version,
            version_group_id,
            vin,
            vout,
            tze_inputs,
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
        })
    }

    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_u32::<LittleEndian>(self.header())?;
        if self.overwintered {
            writer.write_u32::<LittleEndian>(self.version_group_id)?;
        }

        let is_overwinter_v3 = self.overwintered
            && self.version_group_id == OVERWINTER_VERSION_GROUP_ID
            && self.version == OVERWINTER_TX_VERSION;
        let is_sapling_v4 = self.overwintered
            && self.version_group_id == SAPLING_VERSION_GROUP_ID
            && self.version == SAPLING_TX_VERSION;
        let has_tze = self.overwintered
            && self.version_group_id == ZFUTURE_VERSION_GROUP_ID
            && self.version == ZFUTURE_TX_VERSION;

        if self.overwintered && !(is_overwinter_v3 || is_sapling_v4 || has_tze) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Unknown transaction format",
            ));
        }

        Vector::write(&mut writer, &self.vin, |w, e| e.write(w))?;
        Vector::write(&mut writer, &self.vout, |w, e| e.write(w))?;
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

        if self.version >= 2 {
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

        if self.version < 2 || self.joinsplits.is_empty() {
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
