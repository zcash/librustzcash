use alloc::{string::ToString, vec::Vec};
use corez::io::{self, Read, Write};

use crate::{BYTE_VECTOR_READ_CHUNK_LEN, CompactSize, MAX_COMPACT_SIZE, Vector};

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
    let old_result = read_per_byte(&mut old_reader).map_err(|e| (e.kind(), e.to_string()));
    let new_result = Vector::read_bytes(&mut new_reader).map_err(|e| (e.kind(), e.to_string()));
    // `Read::read_exact` does not specify how much input it consumes when it fails.
    // Thus compare the remaining input only after a successful read.
    if old_result.is_ok() {
        assert_eq!(old_reader, new_reader);
    }
    assert_eq!(old_result, new_result);
}

#[test]
fn byte_vectors_match_at_boundaries() {
    for len in [
        0,
        1,
        252,
        253,
        254,
        BYTE_VECTOR_READ_CHUNK_LEN - 1,
        BYTE_VECTOR_READ_CHUNK_LEN,
        BYTE_VECTOR_READ_CHUNK_LEN + 1,
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
    for len in [0, 1, 252, 253, BYTE_VECTOR_READ_CHUNK_LEN + 1, 65535, 65536] {
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
        for end in [
            prefix_len + BYTE_VECTOR_READ_CHUNK_LEN - 1,
            prefix_len + BYTE_VECTOR_READ_CHUNK_LEN,
            encoded.len() - 1,
        ] {
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
    let mut encoded = encoded_bytes(2 * BYTE_VECTOR_READ_CHUNK_LEN + 1);
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
            BYTE_VECTOR_READ_CHUNK_LEN + 2,
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
            assert!(buf.len() <= BYTE_VECTOR_READ_CHUNK_LEN);
            self.bytes.read(buf)
        }
    }
    let encoded = encoded_bytes(2 * BYTE_VECTOR_READ_CHUNK_LEN + 1);
    let mut reader = CountingReader {
        bytes: &encoded,
        calls: 0,
    };
    assert_eq!(Vector::read_bytes(&mut reader).unwrap(), encoded[3..]);
    // Two reads for the CompactSize prefix, then three bounded payload reads.
    assert_eq!(reader.calls, 5);
}

/// Writes a byte vector one byte at a time through [`Vector::write`].
fn write_bytes_per_byte<W: Write>(writer: W, bytes: &[u8]) -> io::Result<()> {
    Vector::write(writer, bytes, |w, b| w.write_all(&[*b]))
}

#[test]
fn write_bytes_matches_per_byte_encoding() {
    /// The largest length that has a one-byte `CompactSize` encoding.
    const MAX_ONE_BYTE_LEN: usize = 252;
    /// The largest length that has a three-byte `CompactSize` encoding.
    const MAX_THREE_BYTE_LEN: usize = 0xFFFF;
    let max_len = usize::try_from(MAX_COMPACT_SIZE).unwrap();

    for len in [
        0,
        1,
        MAX_ONE_BYTE_LEN,
        MAX_ONE_BYTE_LEN + 1,
        MAX_THREE_BYTE_LEN,
        MAX_THREE_BYTE_LEN + 1,
        max_len,
        max_len + 1,
    ] {
        let bytes: Vec<u8> = (0..=u8::MAX).cycle().take(len).collect();
        let mut expected = vec![];
        let expected_result = write_bytes_per_byte(&mut expected, &bytes).map_err(|e| e.kind());
        let mut actual = vec![];
        let actual_result = Vector::write_bytes(&mut actual, &bytes).map_err(|e| e.kind());
        assert_eq!(actual_result, expected_result);
        assert_eq!(actual, expected);
        if len > max_len {
            assert_eq!(actual_result, Err(io::ErrorKind::InvalidInput));
            assert!(actual.is_empty());
        } else {
            assert_eq!(actual.len(), Vector::serialized_size_of_u8_vec(&bytes));
        }
    }
}

#[test]
fn write_bytes_propagates_writer_errors() {
    /// A writer that accepts at most two bytes per call, and fails once its
    /// capacity is used up.
    struct FailingWriter {
        capacity: usize,
    }

    impl Write for FailingWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            /// The largest number of bytes accepted by one call.
            const MAX_WRITE_LEN: usize = 2;
            if self.capacity == 0 {
                return Err(io::ErrorKind::Other.into());
            }
            let len = bytes.len().min(MAX_WRITE_LEN).min(self.capacity);
            self.capacity -= len;
            Ok(len)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    // The writer accepts the one-byte prefix and part of the payload, then fails.
    let bytes = [0; 8];
    let mut writer = FailingWriter {
        capacity: bytes.len() / 2,
    };
    assert_eq!(
        Vector::write_bytes(&mut writer, &bytes).unwrap_err().kind(),
        io::ErrorKind::Other,
    );
}
