//! Golden vectors for the container encodings.
//!
//! Every expected byte string here is written out from the encoding's definition, not captured
//! from a run of the code under test. That is the point: the round-trip and canonicity properties
//! in the rest of the suite are self-referential, and a change that altered the encoding
//! consistently in both directions would satisfy all of them. Only a fixed, independently
//! derived byte string catches that.
//!
//! `CompactSize` boundaries are covered explicitly because that is where the length prefix
//! changes width, and where a non-canonical encoding would be admitted if the bounds were wrong.

use zcash_encoding::{
    Decodable, Encodable,
    codec::{Unprefixed, UnprefixedArgs},
};

/// A one-byte element, so a container's own framing is the only thing under test.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Byte(u8);

impl Encodable for Byte {
    fn write<W>(&self, mut writer: W) -> corez::io::Result<()>
    where
        W: corez::io::Write,
    {
        writer.write_all(&[self.0])
    }

    fn serialized_size(&self) -> usize {
        1
    }
}

impl Decodable<()> for Byte {
    fn read<R>(mut reader: R, _args: ()) -> corez::io::Result<Self>
    where
        R: corez::io::Read,
    {
        let mut b = [0u8; 1];
        reader.read_exact(&mut b)?;
        Ok(Byte(b[0]))
    }
}

fn encode<T: Encodable>(value: &T) -> Vec<u8> {
    let mut bytes = Vec::new();
    value
        .write(&mut bytes)
        .expect("writing to a Vec cannot fail");
    assert_eq!(
        bytes.len(),
        value.serialized_size(),
        "serialized_size must agree with write"
    );
    bytes
}

/// Asserts a vector in both directions.
fn check<T, A>(value: &T, expected: &[u8], args: A)
where
    T: Encodable + Decodable<A> + PartialEq + core::fmt::Debug,
{
    assert_eq!(encode(value), expected, "encoding must match the vector");
    let decoded = T::read(expected, args).expect("the vector must decode");
    assert_eq!(&decoded, value, "the vector must decode to the value");
}

fn bytes(v: &[u8]) -> Vec<Byte> {
    v.iter().copied().map(Byte).collect()
}

#[test]
fn vec_is_compactsize_prefixed() {
    // Empty: just the zero-length prefix.
    check(&Vec::<Byte>::new(), &[0x00], ());

    // One element.
    check(&bytes(&[0xAA]), &[0x01, 0xAA], ());

    // Three elements.
    check(&bytes(&[1, 2, 3]), &[0x03, 1, 2, 3], ());
}

#[test]
fn vec_at_the_compactsize_boundaries() {
    // 252 is the largest length encodable in a single byte.
    let v = bytes(&[0x7F; 252]);
    let mut expected = vec![252u8];
    expected.extend_from_slice(&[0x7F; 252]);
    check(&v, &expected, ());

    // 253 switches to the 0xFD + u16 form. A 1-byte encoding of 253 would be non-canonical.
    let v = bytes(&[0x7F; 253]);
    let mut expected = vec![0xFD, 0xFD, 0x00];
    expected.extend_from_slice(&[0x7F; 253]);
    check(&v, &expected, ());

    // 0xFFFF is the largest length in the u16 form.
    let v = bytes(&[0u8; 0xFFFF]);
    let mut expected = vec![0xFD, 0xFF, 0xFF];
    expected.extend_from_slice(&[0u8; 0xFFFF]);
    check(&v, &expected, ());

    // 0x10000 switches to the 0xFE + u32 form.
    let v = bytes(&[0u8; 0x10000]);
    let mut expected = vec![0xFE, 0x00, 0x00, 0x01, 0x00];
    expected.extend_from_slice(&[0u8; 0x10000]);
    check(&v, &expected, ());
}

#[test]
fn option_is_a_one_byte_tag() {
    check(&None::<Byte>, &[0x00], ());
    check(&Some(Byte(0xAB)), &[0x01, 0xAB], ());
}

#[test]
fn unprefixed_has_no_length_prefix() {
    let v = Unprefixed(bytes(&[1, 2, 3]));
    check(
        &v,
        &[1, 2, 3],
        UnprefixedArgs {
            count: 3,
            element: (),
        },
    );

    let empty = Unprefixed(Vec::<Byte>::new());
    check(
        &empty,
        &[],
        UnprefixedArgs {
            count: 0,
            element: (),
        },
    );
}

#[test]
fn nonempty_matches_vec_framing() {
    let ne = nonempty::NonEmpty::from_vec(bytes(&[7, 8])).unwrap();
    assert_eq!(encode(&ne), vec![0x02, 7, 8]);
}

#[test]
fn nested_containers_compose_as_expected() {
    // Vec<Option<Byte>>: one length prefix, then a tag per element.
    let v = vec![Some(Byte(1)), None, Some(Byte(2))];
    check(&v, &[0x03, 0x01, 0x01, 0x00, 0x01, 0x02], ());

    // Option<Vec<Byte>>: the outer tag, then the inner length prefix.
    let v = Some(bytes(&[9]));
    check(&v, &[0x01, 0x01, 0x09], ());
}

/// A length prefix that could have been written in fewer bytes must be rejected, otherwise the
/// same value would have two valid encodings.
#[test]
fn non_canonical_length_prefixes_are_rejected() {
    // 1 encoded in the u16 form rather than the single-byte form.
    assert!(<Vec<Byte> as Decodable<()>>::read(&[0xFD, 0x01, 0x00, 0xAA][..], ()).is_err());

    // 253 encoded in the u32 form rather than the u16 form.
    let mut input = vec![0xFE, 0xFD, 0x00, 0x00, 0x00];
    input.extend_from_slice(&[0u8; 253]);
    assert!(<Vec<Byte> as Decodable<()>>::read(&input[..], ()).is_err());
}
