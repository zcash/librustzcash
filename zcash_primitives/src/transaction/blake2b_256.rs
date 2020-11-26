use blake2b_simd::{Hash, Params, State};
use std::io::{self, Write};

/// Abstraction over a writer which BLAKE2B-256-hashes the data being read.
pub struct HashWriter {
    hasher: State,
}

impl HashWriter {
    pub fn new(personal: &[u8; 16]) -> Self {
        let hasher = Params::new().hash_length(32).personal(personal).to_state();

        HashWriter { hasher }
    }

    pub fn finalize(&self) -> Hash {
        self.hasher.finalize()
    }
}

impl Write for HashWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.hasher.update(&buf);

        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
