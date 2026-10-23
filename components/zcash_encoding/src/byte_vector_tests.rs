use alloc::{string::ToString, vec::Vec};
use corez::io::{self, Read};

use crate::{CompactSize, MAX_COMPACT_SIZE, Vector};

fn read_per_byte<R: Read>(reader: R) -> io::Result<Vec<u8>> {
    Vector::read(reader, |r| {
        let mut byte = [0];
        r.read_exact(&mut byte)?;
        Ok(byte[0])
    })
}

fn encoded_bytes(len: usize) -> Vec<u8> {
    let mut encoded = Vec::new();
    CompactSize::write(&mut encoded, len).unwrap();
    encoded.extend((0..=255).cycle().take(len));
    encoded
}

fn assert_equivalent(encoded: &[u8]) {
    let mut old_reader = encoded;
    let mut new_reader = encoded;
    assert_eq!(
        read_per_byte(&mut old_reader).map_err(|e| (e.kind(), e.to_string())),
        Vector::read_bytes(&mut new_reader).map_err(|e| (e.kind(), e.to_string())),
    );
    assert_eq!(old_reader, new_reader);
}

#[test]
fn byte_vectors_match_at_boundaries() {
    for len in [
        0,
        1,
        252,
        253,
        254,
        4095,
        4096,
        4097,
        65535,
        65536,
        usize::try_from(MAX_COMPACT_SIZE).unwrap(),
    ] {
        let mut encoded = encoded_bytes(len);
        encoded.extend_from_slice(&[0x12, 0x34]);
        assert_equivalent(&encoded);
    }
}

#[test]
fn truncated_byte_vectors_match() {
    for len in [0, 1, 252, 253, 4097, 65535, 65536] {
        let encoded = encoded_bytes(len);
        let prefix_len = CompactSize::serialized_size(len);
        // Every prefix byte, and every payload position for small vectors.
        for end in 0..encoded.len().min(prefix_len + 254) {
            assert_equivalent(&encoded[..end]);
            assert_eq!(
                Vector::read_bytes(&encoded[..end]).unwrap_err().kind(),
                io::ErrorKind::UnexpectedEof,
            );
        }
        // Both sides of a bulk-read boundary, and the last payload byte.
        for end in [prefix_len + 4095, prefix_len + 4096, encoded.len() - 1] {
            if end < encoded.len() {
                assert_equivalent(&encoded[..end]);
            }
        }
    }

    // A maximum declared length must not require a maximum-sized payload allocation.
    let mut encoded = Vec::new();
    CompactSize::write(&mut encoded, usize::try_from(MAX_COMPACT_SIZE).unwrap()).unwrap();
    for end in 0..=encoded.len() {
        assert_equivalent(&encoded[..end]);
    }
    encoded.extend_from_slice(&[1, 2, 3]);
    assert_equivalent(&encoded);

    // The nine-byte CompactSize prefix can also be truncated at every byte.
    let encoded = [255, 0, 0, 0, 0, 1, 0, 0, 0];
    for end in 0..encoded.len() {
        assert_equivalent(&encoded[..end]);
    }
}

#[test]
fn invalid_byte_vector_lengths_preserve_errors() {
    for prefix in [
        &[253, 252, 0][..],
        &[254, 255, 255, 0, 0],
        &[255, 255, 255, 255, 255, 0, 0, 0, 0],
        &[254, 1, 0, 0, 2], // MAX_COMPACT_SIZE + 1
        &[255, 0, 0, 0, 0, 1, 0, 0, 0],
        &[255, 255, 255, 255, 255, 255, 255, 255, 255],
    ] {
        let old_error = read_per_byte(prefix).unwrap_err();
        let new_error = Vector::read_bytes(prefix).unwrap_err();
        assert_eq!(new_error.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(old_error.kind(), new_error.kind());
        assert_eq!(old_error.to_string(), new_error.to_string());
        assert_equivalent(prefix);
    }
}

struct ShortReads<'a> {
    bytes: &'a [u8],
    interrupt: bool,
    final_error: Option<io::ErrorKind>,
}

impl Read for ShortReads<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.interrupt = !self.interrupt;
        if self.interrupt {
            return Err(io::ErrorKind::Interrupted.into());
        }
        if self.bytes.is_empty()
            && let Some(kind) = self.final_error
        {
            return Err(io::Error::new(kind, "reader failure"));
        }
        let limit = buf.len().min(7);
        self.bytes.read(&mut buf[..limit])
    }
}

#[test]
fn short_interrupted_and_failed_reads_match() {
    let mut encoded = encoded_bytes(8193);
    let payload_end = encoded.len();
    encoded.extend_from_slice(&[0x12, 0x34]);
    for final_error in [
        None,
        Some(io::ErrorKind::Other),
        Some(io::ErrorKind::InvalidData),
        Some(io::ErrorKind::UnexpectedEof),
    ] {
        for end in [
            0,
            1,
            2,
            3,
            4098,
            payload_end - 1,
            payload_end,
            encoded.len(),
        ] {
            let reader = || ShortReads {
                bytes: &encoded[..end],
                interrupt: false,
                final_error,
            };
            let mut old_reader = reader();
            let mut new_reader = reader();
            assert_eq!(
                read_per_byte(&mut old_reader).map_err(|e| (e.kind(), e.to_string())),
                Vector::read_bytes(&mut new_reader).map_err(|e| (e.kind(), e.to_string())),
            );
            assert_eq!(old_reader.bytes, new_reader.bytes);
        }
    }
}

#[test]
fn byte_vectors_are_read_in_bulk() {
    struct CountingReader<'a> {
        bytes: &'a [u8],
        calls: usize,
    }
    impl Read for CountingReader<'_> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.calls += 1;
            assert!(buf.len() <= 4096);
            self.bytes.read(buf)
        }
    }
    let encoded = encoded_bytes(8193);
    let mut reader = CountingReader {
        bytes: &encoded,
        calls: 0,
    };
    assert_eq!(Vector::read_bytes(&mut reader).unwrap(), encoded[3..]);
    // Two reads for the CompactSize prefix, then three bounded payload reads.
    assert_eq!(reader.calls, 5);
}
