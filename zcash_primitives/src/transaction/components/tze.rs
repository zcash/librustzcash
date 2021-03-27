//! Structs representing the TZE components within Zcash transactions.
#![cfg(feature = "zfuture")]

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};

use std::io::{self, Read, Write};

use std::convert::TryFrom;

use crate::{
    extensions::transparent as tze,
    serialize::{CompactSize, Vector},
};

use super::amount::Amount;

fn to_io_error(_: std::num::TryFromIntError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "value out of range")
}

#[derive(Clone, Debug, PartialEq)]
pub struct TzeOutPoint {
    hash: [u8; 32],
    n: u32,
}

impl TzeOutPoint {
    pub fn new(hash: [u8; 32], n: u32) -> Self {
        TzeOutPoint { hash, n }
    }

    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let mut hash = [0u8; 32];
        reader.read_exact(&mut hash)?;
        let n = reader.read_u32::<LittleEndian>()?;
        Ok(TzeOutPoint { hash, n })
    }

    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_all(&self.hash)?;
        writer.write_u32::<LittleEndian>(self.n)
    }

    pub fn n(&self) -> u32 {
        self.n
    }

    pub fn hash(&self) -> &[u8; 32] {
        &self.hash
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct TzeIn {
    pub prevout: TzeOutPoint,
    pub witness: tze::Witness,
}

/// Transaction encoding and decoding functions conforming to [ZIP 222].
///
/// [ZIP 222]: https://zips.z.cash/zip-0222#encoding-in-transactions
impl TzeIn {
    /// Convenience constructor
    pub fn new(prevout: TzeOutPoint, extension_id: u32, mode: u32) -> Self {
        TzeIn {
            prevout,
            witness: tze::Witness {
                extension_id,
                mode,
                payload: vec![],
            },
        }
    }

    /// Read witness metadata & payload
    ///
    /// Used to decode the encoded form used within a serialized
    /// transaction.
    pub fn read<R: Read>(mut reader: &mut R) -> io::Result<Self> {
        let prevout = TzeOutPoint::read(&mut reader)?;

        let extension_id = CompactSize::read(&mut reader)?;
        let mode = CompactSize::read(&mut reader)?;
        let payload = Vector::read(&mut reader, |r| r.read_u8())?;

        Ok(TzeIn {
            prevout,
            witness: tze::Witness {
                extension_id: u32::try_from(extension_id).map_err(to_io_error)?,
                mode: u32::try_from(mode).map_err(to_io_error)?,
                payload,
            },
        })
    }

    /// Write without witness data (for signature hashing)
    ///
    /// This is also used as the prefix for the encoded form used
    /// within a serialized transaction.
    pub fn write_without_witness<W: Write>(&self, mut writer: W) -> io::Result<()> {
        self.prevout.write(&mut writer)?;

        CompactSize::write(
            &mut writer,
            usize::try_from(self.witness.extension_id).map_err(to_io_error)?,
        )?;

        CompactSize::write(
            &mut writer,
            usize::try_from(self.witness.mode).map_err(to_io_error)?,
        )
    }

    /// Write prevout, extension, and mode followed by witness data.
    ///
    /// This calls [`write_without_witness`] to serialize witness metadata,
    /// then appends the witness bytes themselves. This is the encoded
    /// form that is used in a serialized transaction.
    ///
    /// [`write_without_witness`]: TzeIn::write_without_witness
    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        self.write_without_witness(&mut writer)?;
        Vector::write(&mut writer, &self.witness.payload, |w, b| w.write_u8(*b))
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct TzeOut {
    pub value: Amount,
    pub precondition: tze::Precondition,
}

impl TzeOut {
    pub fn read<R: Read>(mut reader: &mut R) -> io::Result<Self> {
        let value = {
            let mut tmp = [0; 8];
            reader.read_exact(&mut tmp)?;
            Amount::from_nonnegative_i64_le_bytes(tmp)
        }
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "value out of range"))?;

        let extension_id = CompactSize::read(&mut reader)?;
        let mode = CompactSize::read(&mut reader)?;
        let payload = Vector::read(&mut reader, |r| r.read_u8())?;

        Ok(TzeOut {
            value,
            precondition: tze::Precondition {
                extension_id: u32::try_from(extension_id).map_err(to_io_error)?,
                mode: u32::try_from(mode).map_err(to_io_error)?,
                payload,
            },
        })
    }

    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_all(&self.value.to_i64_le_bytes())?;

        CompactSize::write(
            &mut writer,
            usize::try_from(self.precondition.extension_id).map_err(to_io_error)?,
        )?;
        CompactSize::write(
            &mut writer,
            usize::try_from(self.precondition.mode).map_err(to_io_error)?,
        )?;
        Vector::write(&mut writer, &self.precondition.payload, |w, b| {
            w.write_u8(*b)
        })
    }
}
