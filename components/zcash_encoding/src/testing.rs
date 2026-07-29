//! Test utilities for exercising binary codecs built with this crate.
//!
//! Enabled by the `test-dependencies` feature, so a downstream crate can reuse the round-trip
//! property from its own tests instead of duplicating an ad-hoc assert per codec.

use alloc::vec::Vec;
use core::fmt::Debug;

use corez::io;

use crate::codec::{Codec, Decodable, Encodable};

/// Asserts the round-trip property for a context-free codec.
///
/// See [`check_codec_roundtrip_with`] for what is checked.
pub fn check_codec_roundtrip<T>(value: &T)
where
    T: Codec + PartialEq + Debug,
{
    check_codec_roundtrip_with(value, ());
}

/// Asserts the round-trip property for a context-parameterized codec.
///
/// Checks two things:
///
/// 1. `read(write(v)) == v`, so `write` is a section of `read` and no information is lost.
/// 2. [`Encodable::serialized_size`] agrees with what [`Encodable::write`] actually emitted.
///
/// This does **not** establish that the encoding is canonical. Re-encoding the decoded value and
/// comparing bytes would add nothing, because it follows from (1) plus `write` being a function.
/// Canonicity quantifies over arbitrary byte strings rather than over values, so it needs
/// [`check_canonical`], driven by a fuzzer or a `proptest` byte-string strategy.
pub fn check_codec_roundtrip_with<T, A>(value: &T, args: A)
where
    T: Encodable + Decodable<A> + PartialEq + Debug,
{
    let mut bytes = Vec::new();
    value
        .write(&mut bytes)
        .expect("writing to a Vec is infallible");

    assert_eq!(
        bytes.len(),
        value.serialized_size(),
        "serialized_size must agree with write"
    );

    let decoded = T::read(&bytes[..], args).expect("the bytes written by `write` must decode");
    assert_eq!(&decoded, value, "round-trip must preserve the value");
}

/// Asserts that the codec is canonical: no value has more than one valid encoding.
///
/// Feed this arbitrary byte strings, including ones `write` would never produce. Whenever `read`
/// accepts a prefix of the input, re-encoding the decoded value must reproduce exactly the bytes
/// that were consumed. Inputs that `read` rejects are ignored, so the check is vacuous for a
/// codec that rejects everything; pair it with [`check_codec_roundtrip`] on real values.
///
/// A codec that fails this is malleable: two distinct encodings decode to the same value, so a
/// value's serialization is not determined by the value. Transaction-ID malleability is exactly
/// this failure mode.
pub fn check_canonical<T, A>(bytes: &[u8], args: A)
where
    T: Encodable + Decodable<A> + Debug,
{
    let mut cursor = bytes;
    let Ok(decoded) = T::read(&mut cursor, args) else {
        // `read` rejected these bytes; nothing to check.
        return;
    };
    let consumed = bytes.len() - cursor.len();

    let mut reencoded = Vec::new();
    decoded
        .write(&mut reencoded)
        .expect("writing to a Vec is infallible");

    assert_eq!(
        reencoded,
        &bytes[..consumed],
        "non-canonical encoding: {decoded:?} decoded from bytes that it does not re-encode to"
    );
}

/// Assert that a `write`/`read` pair are exact inverses for `value`: `read(write(value))` equals
/// `value`.
///
/// `write` serializes a value into a growable buffer (writing to a `Vec` is infallible); `read`
/// deserializes it back from the produced bytes. The migration codecs pass their own
/// `Type::write` / `Type::read` through small closures.
///
/// This does **not** establish that the encoding is canonical. Re-encoding the decoded value and
/// comparing bytes would add nothing, because it follows from the round-trip assertion plus
/// `write` being a function. Canonicity quantifies over arbitrary byte strings rather than over
/// values; see [`check_canonical`], which requires the [`crate::Encodable`] /
/// [`crate::Decodable`] traits.
pub fn check_roundtrip<T, W, R>(value: &T, write: W, read: R)
where
    T: PartialEq + Debug,
    W: Fn(&T, &mut Vec<u8>) -> io::Result<()>,
    R: Fn(&[u8]) -> io::Result<T>,
{
    let mut bytes = Vec::new();
    write(value, &mut bytes).expect("writing to a Vec is infallible");

    let decoded = read(&bytes).expect("the bytes written by `write` must decode");
    assert_eq!(&decoded, value, "round-trip must preserve the value");
}
