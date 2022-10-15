//! Handlers for structured memos.

use wasabi_leb128::{ReadLeb128, WriteLeb128};

use super::{Error, TextMemo};
use crate::sapling::PaymentAddress;

/// A payload within a [`StructuredMemo`].
#[derive(Clone, Debug, PartialEq)]
pub enum Payload {
    /// A Sapling return address.
    ReturnAddress(PaymentAddress),
    /// UTF-8 text.
    Text(TextMemo),
    /// A payload type we don't know about.
    Unknown {
        type_id: u64,
        length: u16,
        value: Vec<u8>,
    },
}

impl Payload {
    /// Parses a `Payload` from memo field bytes.
    fn parse(mut bytes: &[u8]) -> Result<(&[u8], Option<Self>), Error> {
        match bytes.read_leb128().map_err(|_| Error::InvalidEncoding)? {
            (0x00, _) => Ok((bytes, None)),
            (0x01, _) => {
                let (length, _): (u16, _) =
                    bytes.read_leb128().map_err(|_| Error::InvalidEncoding)?;
                if length != 43 || length as usize > bytes.len() {
                    return Err(Error::InvalidEncoding);
                }

                let mut pa_bytes = [0; 43];
                pa_bytes.copy_from_slice(&bytes[..43]);

                PaymentAddress::from_bytes(&pa_bytes)
                    .ok_or(Error::InvalidEncoding)
                    .map(|pa| (&bytes[43..], Some(Payload::ReturnAddress(pa))))
            }
            (0xa0, _) => {
                let (length, _): (u16, _) =
                    bytes.read_leb128().map_err(|_| Error::InvalidEncoding)?;
                if length as usize > bytes.len() {
                    return Err(Error::InvalidEncoding);
                }

                let (value, rem) = bytes.split_at(length as usize);

                // Convert to UTF8, replacing invalid sequences with the replacement
                // character U+FFFD
                Ok((
                    rem,
                    Some(Payload::Text(TextMemo(
                        String::from_utf8_lossy(value).into(),
                    ))),
                ))
            }
            (type_id, _) => {
                let (length, _): (u16, _) =
                    bytes.read_leb128().map_err(|_| Error::InvalidEncoding)?;
                if length as usize > bytes.len() {
                    return Err(Error::InvalidEncoding);
                }

                let (value, rem) = bytes.split_at(length as usize);

                Ok((
                    rem,
                    Some(Payload::Unknown {
                        type_id,
                        length,
                        value: value.into(),
                    }),
                ))
            }
        }
    }

    /// Returns the number of memo field bytes that this `Payload` will occupy.
    fn serialized_len(&self) -> usize {
        let mut buf = [0; wasabi_leb128::max_bytes::<u64>()];
        match self {
            Payload::ReturnAddress(_) => 45,
            Payload::Text(s) => {
                let length_len = (&mut buf[..])
                    .write_leb128(s.len())
                    .expect("buffer is large enough");
                1 + length_len + s.len()
            }
            Payload::Unknown {
                type_id, length, ..
            } => {
                let type_len = (&mut buf[..])
                    .write_leb128(*type_id)
                    .expect("buffer is large enough");
                let length_len = (&mut buf[..])
                    .write_leb128(*length)
                    .expect("buffer is large enough");
                type_len + length_len + *length as usize
            }
        }
    }

    /// Serializes this `Payload` into the provided buffer.
    ///
    /// Panics if `buf` is not large enough. Caller must verify that this `Payload` will
    /// fit into `buf` by checking `serialized_len`.
    fn serialize(&self, mut buf: &mut [u8]) -> usize {
        match self {
            Payload::ReturnAddress(pa) => {
                let mut written = buf.write_leb128(0x01).expect("buffer is large enough");
                written += buf.write_leb128(43).expect("buffer is large enough");
                assert_eq!(written, 2);
                buf[..43].copy_from_slice(&pa.to_bytes());
                45
            }
            Payload::Text(s) => {
                let mut written = buf.write_leb128(0xa0).expect("buffer is large enough");
                written += buf.write_leb128(s.len()).expect("buffer is large enough");
                buf[..s.len()].copy_from_slice(s.as_bytes());
                written + s.len()
            }
            Payload::Unknown {
                type_id,
                length,
                value,
            } => {
                let mut written = buf.write_leb128(*type_id).expect("buffer is large enough");
                written += buf.write_leb128(*length).expect("buffer is large enough");
                let length = *length as usize;
                buf[..length].copy_from_slice(&value[..length]);
                written + length
            }
        }
    }
}

/// A structured [`Memo`] that contains at least one [`Payload`].
///
/// [`Memo`]: crate::memo::Memo
#[derive(Clone, Debug, PartialEq)]
pub struct StructuredMemo(Vec<Payload>);

impl AsRef<[Payload]> for StructuredMemo {
    fn as_ref(&self) -> &[Payload] {
        &self.0
    }
}

impl StructuredMemo {
    /// Pack a set of [`Payload`]s into a `StructuredMemo`.
    ///
    /// Returns an error if `payloads` is empty or will not fit into a memo field.
    pub fn new(payloads: Vec<Payload>) -> Result<Self, Error> {
        if payloads.is_empty() || payloads.iter().map(|p| p.serialized_len()).sum::<usize>() > 511 {
            Err(Error::InvalidPayload)
        } else {
            Ok(StructuredMemo(payloads))
        }
    }

    /// Parses a `StructuredMemo` from the its ZIP 302 serialization.
    pub(super) fn parse(mut bytes: &[u8]) -> Result<Self, Error> {
        // Internal function, this invariant should always hold.
        assert_eq!(bytes.len(), 511);

        let mut payloads = vec![];

        loop {
            // Parse the next payload
            bytes = match Payload::parse(bytes)? {
                (c, Some(payload)) => {
                    payloads.push(payload);

                    if c.is_empty() {
                        // Finished parsing!
                        break;
                    }

                    // There may be more payloads
                    c
                }
                (c, None) => {
                    // Remainder of bytes should be padding
                    for b in c {
                        if *b != 0x00 {
                            return Err(Error::InvalidEncoding);
                        }
                    }

                    // Finished parsing!
                    break;
                }
            };
        }

        if payloads.is_empty() {
            // Non-canonical empty memo, should be using Memo::Empty
            Err(Error::InvalidEncoding)
        } else {
            Ok(StructuredMemo(payloads))
        }
    }

    /// Serializes the `StructuredMemo` per ZIP 302.
    pub(super) fn serialize(&self, mut buf: &mut [u8]) {
        // Internal function, this invariant should always hold.
        assert_eq!(buf.len(), 511);

        // A `StructuredMemo` can only be constructed such that its payloads are
        // guaranteed to fit in `buf`.
        for payload in &self.0 {
            let written = payload.serialize(buf);
            buf = &mut buf[written..];
        }

        // Ensure that remaining buffer is padding with zeroes
        for b in buf.iter_mut() {
            *b = 0;
        }
    }
}

#[cfg(test)]
mod tests {
    use wasabi_leb128::WriteLeb128;

    use super::{Payload, StructuredMemo};
    use crate::memo::Memo;

    #[test]
    fn structured_memo() {
        let mut bytes = [0; 512];
        bytes[0] = 0xF5;

        // Empty StructuredMemo is rejected
        assert!(Memo::from_bytes(&bytes).is_err());

        bytes[1] = 0x71;
        assert_eq!(
            Memo::from_bytes(&bytes),
            Ok(Memo::Structured(StructuredMemo(vec![Payload::Unknown {
                type_id: 0x71,
                length: 0,
                value: vec![]
            }])))
        );

        bytes[2] = 0x02;
        assert_eq!(
            Memo::from_bytes(&bytes),
            Ok(Memo::Structured(StructuredMemo(vec![Payload::Unknown {
                type_id: 0x71,
                length: 2,
                value: vec![0, 0]
            }])))
        );

        bytes[3] = 0x03;
        assert_eq!(
            Memo::from_bytes(&bytes),
            Ok(Memo::Structured(StructuredMemo(vec![Payload::Unknown {
                type_id: 0x71,
                length: 2,
                value: vec![3, 0]
            }])))
        );

        bytes[4] = 0x04;
        assert_eq!(
            Memo::from_bytes(&bytes),
            Ok(Memo::Structured(StructuredMemo(vec![Payload::Unknown {
                type_id: 0x71,
                length: 2,
                value: vec![3, 4]
            }])))
        );

        bytes[5] = 0x05;
        assert_eq!(
            Memo::from_bytes(&bytes),
            Ok(Memo::Structured(StructuredMemo(vec![
                Payload::Unknown {
                    type_id: 0x71,
                    length: 2,
                    value: vec![3, 4]
                },
                Payload::Unknown {
                    type_id: 5,
                    length: 0,
                    value: vec![]
                }
            ])))
        );

        let remaining =
            512 - (1 /* 0xF5 */ + 1 /* T1 */ + 1 /* L1 */ + 2 /* V1 */ + 1 /* T2 */ + 2/* L2 */);
        (&mut bytes[6..])
            .write_leb128(remaining)
            .expect("buffer is large enough");
        assert_eq!(
            Memo::from_bytes(&bytes),
            Ok(Memo::Structured(StructuredMemo(vec![
                Payload::Unknown {
                    type_id: 0x71,
                    length: 2,
                    value: vec![3, 4]
                },
                Payload::Unknown {
                    type_id: 5,
                    length: remaining,
                    value: vec![0; remaining as usize]
                }
            ])))
        );

        // Out-of-range length is rejected
        (&mut bytes[6..])
            .write_leb128(remaining + 1)
            .expect("buffer is large enough");
        assert!(Memo::from_bytes(&bytes).is_err());
    }
}
