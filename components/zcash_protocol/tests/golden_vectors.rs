//! Golden vectors for `TxId` and `Zatoshis`.
//!
//! The expected bytes are written out from the encoding's definition rather than captured from a
//! run of the code under test, so that a change altering the encoding consistently in both
//! directions is still caught.

use zcash_encoding::{Decodable, Encodable};
use zcash_protocol::{
    TxId,
    value::{MAX_MONEY, Zatoshis},
};

fn check<T>(value: &T, expected: &[u8])
where
    T: Encodable + Decodable + PartialEq + core::fmt::Debug + for<'a> Decodable<Args<'a> = ()>,
{
    let mut bytes = Vec::new();
    value.write(&mut bytes).unwrap();
    assert_eq!(bytes, expected, "encoding must match the vector");
    assert_eq!(value.serialized_size(), expected.len());

    let decoded = T::read(expected, ()).expect("the vector must decode");
    assert_eq!(&decoded, value, "the vector must decode to the value");
}

/// A txid is its 32 bytes, in internal byte order, with no framing.
#[test]
fn txid_is_32_raw_bytes() {
    let mut raw = [0u8; 32];
    for (i, b) in raw.iter_mut().enumerate() {
        *b = i as u8;
    }
    check(&TxId::from_bytes(raw), &raw);

    check(&TxId::from_bytes([0u8; 32]), &[0u8; 32]);
    check(&TxId::from_bytes([0xFFu8; 32]), &[0xFFu8; 32]);
}

/// Zatoshis is an unsigned 64-bit little-endian integer.
#[test]
fn zatoshis_is_u64_little_endian() {
    check(&Zatoshis::ZERO, &[0, 0, 0, 0, 0, 0, 0, 0]);
    check(&Zatoshis::const_from_u64(1), &[1, 0, 0, 0, 0, 0, 0, 0]);

    // A value with every byte distinct, to pin the byte order rather than just the width. The
    // top byte is zero because anything larger would exceed `MAX_MONEY`.
    check(
        &Zatoshis::const_from_u64(0x0001_0203_0405_0607),
        &[0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00],
    );

    // MAX_MONEY = 21_000_000 * 10^8 = 2_100_000_000_000_000 = 0x0007_75F0_5A07_4000.
    check(
        &Zatoshis::const_from_u64(MAX_MONEY),
        &[0x00, 0x40, 0x07, 0x5A, 0xF0, 0x75, 0x07, 0x00],
    );
}

/// Values above `MAX_MONEY` are outside the type's range, so the decoder must reject them even
/// though the eight bytes are structurally well formed.
#[test]
fn zatoshis_rejects_out_of_range() {
    let too_big = (MAX_MONEY + 1).to_le_bytes();
    assert!(<Zatoshis as Decodable>::read(&too_big[..], ()).is_err());
    assert!(<Zatoshis as Decodable>::read(&u64::MAX.to_le_bytes()[..], ()).is_err());
}

/// A `Vec<TxId>` is a `CompactSize` count followed by the concatenated txids.
#[test]
fn txid_vec_framing() {
    check(&Vec::<TxId>::new(), &[0x00]);

    let a = TxId::from_bytes([0x11u8; 32]);
    let b = TxId::from_bytes([0x22u8; 32]);
    let mut expected = vec![0x02];
    expected.extend_from_slice(&[0x11u8; 32]);
    expected.extend_from_slice(&[0x22u8; 32]);
    check(&vec![a, b], &expected);
}
