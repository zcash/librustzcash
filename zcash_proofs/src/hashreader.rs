//! Abstraction over a reader which hashes the data being read.

use std::{
    fmt::Write,
    io::{self, Read},
};

use blake2b_simd::State;

/// Abstraction over a reader which hashes the data being read.
pub struct HashReader<R: Read> {
    reader: R,
    hasher: State,
    byte_count: u64,
}

impl<R: Read> HashReader<R> {
    /// Construct a new `HashReader` given an existing `reader` by value.
    pub fn new(reader: R) -> Self {
        HashReader {
            reader,
            hasher: State::new(),
            byte_count: 0,
        }
    }

    /// Destroy this reader and return the hash of what was read.
    pub fn into_hash(self) -> String {
        let hash = self.hasher.finalize();

        let mut s = String::new();
        for c in hash.as_bytes().iter() {
            write!(&mut s, "{c:02x}").expect("writing to a string never fails");
        }

        s
    }

    /// Return the number of bytes read so far.
    pub fn byte_count(&self) -> u64 {
        self.byte_count
    }
}

impl<R: Read> Read for HashReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let bytes = self.reader.read(buf)?;

        if bytes > 0 {
            self.hasher.update(&buf[0..bytes]);
            let byte_count = u64::try_from(bytes).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Could not fit the number of read bytes into u64.",
                )
            })?;
            self.byte_count += byte_count;
        }

        Ok(bytes)
    }
}
