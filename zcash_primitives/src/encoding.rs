//! Utility traits for encoding and decoding using core2.io primitives.
//!
//! This module is used in lieu of the `byteorder` crate, which uses `std::io::{Read, Write}`
//! and therefore does not support `no_std` usage.
use blake2b_simd::{Hash, State};
use core2::io::{self, Read, Write};

pub(crate) trait ReadBytesExt {
    fn read_u8(self) -> io::Result<u8>;
    fn read_u32_le(self) -> io::Result<u32>;
    fn read_i32_le(self) -> io::Result<i32>;
    fn read_u64_le(self) -> io::Result<u64>;
}

impl<R: Read> ReadBytesExt for &mut R {
    fn read_u8(self) -> io::Result<u8> {
        let mut repr = [0u8; 1];
        self.read_exact(&mut repr)?;
        Ok(repr[0])
    }

    fn read_u32_le(self) -> io::Result<u32> {
        let mut repr = [0u8; 4];
        self.read_exact(&mut repr)?;
        Ok(u32::from_le_bytes(repr))
    }

    fn read_i32_le(self) -> io::Result<i32> {
        let mut repr = [0u8; 4];
        self.read_exact(&mut repr)?;
        Ok(i32::from_le_bytes(repr))
    }

    fn read_u64_le(self) -> io::Result<u64> {
        let mut repr = [0u8; 8];
        self.read_exact(&mut repr)?;
        Ok(u64::from_le_bytes(repr))
    }
}

pub(crate) trait WriteBytesExt {
    fn write_u8(self, value: u8) -> io::Result<()>;
    fn write_u32_le(self, value: u32) -> io::Result<()>;
    fn write_i32_le(self, value: i32) -> io::Result<()>;
    fn write_u64_le(self, value: u64) -> io::Result<()>;
}

impl<W: Write> WriteBytesExt for &mut W {
    fn write_u8(self, value: u8) -> io::Result<()> {
        self.write_all(&[value])
    }

    fn write_i32_le(self, value: i32) -> io::Result<()> {
        self.write_all(&value.to_le_bytes())
    }

    fn write_u32_le(self, value: u32) -> io::Result<()> {
        self.write_all(&value.to_le_bytes())
    }

    fn write_u64_le(self, value: u64) -> io::Result<()> {
        self.write_all(&value.to_le_bytes())
    }
}

pub(crate) struct StateWrite(pub(crate) State);

impl StateWrite {
    pub(crate) fn finalize(&self) -> Hash {
        self.0.finalize()
    }
}

impl Write for StateWrite {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.update(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
