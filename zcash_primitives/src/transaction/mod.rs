use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use sapling_crypto::redjubjub::Signature;
use std::io::{self, Read, Write};
use std::ops::Deref;

use serialize::Vector;

pub mod components;
mod sighash;

#[cfg(test)]
mod tests;

pub use self::sighash::{signature_hash, signature_hash_data, SIGHASH_ALL};

use self::components::{Amount, JSDescription, OutputDescription, SpendDescription, TxIn, TxOut};

const OVERWINTER_VERSION_GROUP_ID: u32 = 0x03C48270;
const OVERWINTER_TX_VERSION: u32 = 3;
const SAPLING_VERSION_GROUP_ID: u32 = 0x892F2085;
const SAPLING_TX_VERSION: u32 = 4;

/// A Zcash transaction.
pub struct Transaction(TransactionData);

impl Deref for Transaction {
    type Target = TransactionData;

    fn deref(&self) -> &TransactionData {
        &self.0
    }
}

pub struct TransactionData {
    pub overwintered: bool,
    pub version: u32,
    pub version_group_id: u32,
    pub vin: Vec<TxIn>,
    pub vout: Vec<TxOut>,
    pub lock_time: u32,
    pub expiry_height: u32,
    pub value_balance: Amount,
    pub shielded_spends: Vec<SpendDescription>,
    pub shielded_outputs: Vec<OutputDescription>,
    pub joinsplits: Vec<JSDescription>,
    pub joinsplit_pubkey: [u8; 32],
    pub joinsplit_sig: [u8; 64],
    pub binding_sig: Option<Signature>,
}

impl TransactionData {
    pub fn new() -> Self {
        TransactionData {
            overwintered: true,
            version: SAPLING_TX_VERSION,
            version_group_id: SAPLING_VERSION_GROUP_ID,
            vin: vec![],
            vout: vec![],
            lock_time: 0,
            expiry_height: 0,
            value_balance: Amount(0),
            shielded_spends: vec![],
            shielded_outputs: vec![],
            joinsplits: vec![],
            joinsplit_pubkey: [0u8; 32],
            joinsplit_sig: [0u8; 64],
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

    pub fn freeze(self) -> Transaction {
        Transaction(self)
    }
}

impl Transaction {
    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let header = reader.read_u32::<LittleEndian>()?;
        let overwintered = (header >> 31) == 1;
        let version = header & 0x7FFFFFFF;

        let version_group_id = match overwintered {
            true => reader.read_u32::<LittleEndian>()?,
            false => 0,
        };

        let is_overwinter_v3 = overwintered
            && version_group_id == OVERWINTER_VERSION_GROUP_ID
            && version == OVERWINTER_TX_VERSION;
        let is_sapling_v4 = overwintered
            && version_group_id == SAPLING_VERSION_GROUP_ID
            && version == SAPLING_TX_VERSION;
        if overwintered && !(is_overwinter_v3 || is_sapling_v4) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Unknown transaction format",
            ));
        }

        let vin = Vector::read(&mut reader, TxIn::read)?;
        let vout = Vector::read(&mut reader, TxOut::read)?;
        let lock_time = reader.read_u32::<LittleEndian>()?;
        let expiry_height = match is_overwinter_v3 || is_sapling_v4 {
            true => reader.read_u32::<LittleEndian>()?,
            false => 0,
        };

        let (value_balance, shielded_spends, shielded_outputs) = if is_sapling_v4 {
            let vb = Amount(reader.read_i64::<LittleEndian>()?);
            let ss = Vector::read(&mut reader, SpendDescription::read)?;
            let so = Vector::read(&mut reader, OutputDescription::read)?;
            (vb, ss, so)
        } else {
            (Amount(0), vec![], vec![])
        };

        let mut joinsplit_pubkey = [0; 32];
        let mut joinsplit_sig = [0; 64];
        let joinsplits = if version >= 2 {
            let jss = Vector::read(&mut reader, |r| {
                JSDescription::read(r, overwintered && version >= SAPLING_TX_VERSION)
            })?;
            if !jss.is_empty() {
                reader.read_exact(&mut joinsplit_pubkey)?;
                reader.read_exact(&mut joinsplit_sig)?;
            }
            jss
        } else {
            vec![]
        };

        let binding_sig =
            match is_sapling_v4 && !(shielded_spends.is_empty() && shielded_outputs.is_empty()) {
                true => Some(Signature::read(&mut reader)?),
                false => None,
            };

        Ok(Transaction(TransactionData {
            overwintered,
            version,
            version_group_id,
            vin,
            vout,
            lock_time,
            expiry_height,
            value_balance,
            shielded_spends,
            shielded_outputs,
            joinsplits,
            joinsplit_pubkey,
            joinsplit_sig,
            binding_sig,
        }))
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
        if self.overwintered && !(is_overwinter_v3 || is_sapling_v4) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Unknown transaction format",
            ));
        }

        Vector::write(&mut writer, &self.vin, |w, e| e.write(w))?;
        Vector::write(&mut writer, &self.vout, |w, e| e.write(w))?;
        writer.write_u32::<LittleEndian>(self.lock_time)?;
        if is_overwinter_v3 || is_sapling_v4 {
            writer.write_u32::<LittleEndian>(self.expiry_height)?;
        }

        if is_sapling_v4 {
            writer.write_i64::<LittleEndian>(self.value_balance.0)?;
            Vector::write(&mut writer, &self.shielded_spends, |w, e| e.write(w))?;
            Vector::write(&mut writer, &self.shielded_outputs, |w, e| e.write(w))?;
        }

        if self.version >= 2 {
            Vector::write(&mut writer, &self.joinsplits, |w, e| e.write(w))?;
            if !self.joinsplits.is_empty() {
                writer.write_all(&self.joinsplit_pubkey)?;
                writer.write_all(&self.joinsplit_sig)?;
            }
        }

        if is_sapling_v4 && !(self.shielded_spends.is_empty() && self.shielded_outputs.is_empty()) {
            match self.binding_sig {
                Some(sig) => sig.write(&mut writer)?,
                None => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "Missing binding signature",
                    ))
                }
            }
        }

        Ok(())
    }
}
