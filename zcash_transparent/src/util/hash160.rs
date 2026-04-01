//! HASH160 (`RIPEMD-160(SHA-256(data))`) hashing utilities.

use core2::io::{self, Read, Write};
use ripemd::Ripemd160;
use sha2::{Digest, Sha256, digest::Output};

/// Computes `RIPEMD-160(SHA-256(input))` in one shot.
pub fn hash(input: &[u8]) -> [u8; 20] {
    let mut writer = HashWriter::default();
    writer
        .write_all(input)
        .expect("HashWriter::write is infallible");
    writer.into_hash().into()
}

/// Abstraction over a reader which HASH160-hashes the data being read.
///
/// HASH160 is defined as `RIPEMD-160(SHA-256(data))`.
pub struct HashReader<R: Read> {
    reader: R,
    hasher: Sha256,
}

impl<R: Read> HashReader<R> {
    /// Construct a new `HashReader` given an existing `reader` by value.
    pub fn new(reader: R) -> Self {
        HashReader {
            reader,
            hasher: Sha256::new(),
        }
    }

    pub fn into_base_reader(self) -> R {
        self.reader
    }

    /// Destroy this reader and return the hash of what was read.
    pub fn into_hash(self) -> Output<Ripemd160> {
        Ripemd160::digest(self.hasher.finalize())
    }
}

impl<R: Read> Read for HashReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let bytes = self.reader.read(buf)?;

        if bytes > 0 {
            self.hasher.update(&buf[0..bytes]);
        }

        Ok(bytes)
    }
}

/// Abstraction over a writer which HASH160-hashes the data being written.
///
/// HASH160 is defined as `RIPEMD-160(SHA-256(data))`.
pub struct HashWriter {
    hasher: Sha256,
}

impl Default for HashWriter {
    fn default() -> Self {
        HashWriter {
            hasher: Sha256::new(),
        }
    }
}

impl HashWriter {
    /// Destroy this writer and return the hash of what was written.
    pub fn into_hash(self) -> Output<Ripemd160> {
        Ripemd160::digest(self.hasher.finalize())
    }
}

impl Write for HashWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.hasher.update(buf);

        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
