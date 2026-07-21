//! Test utilities for exercising binary codecs built with this crate.
//!
//! Enabled by the `test-dependencies` feature, so a downstream crate can reuse the round-trip
//! property from its own tests instead of duplicating an ad-hoc assert per codec.

use alloc::vec::Vec;
use core::fmt::Debug;

use corez::io;

/// Assert that a `write`/`read` pair are exact inverses for `value`: `read(write(value))` equals
/// `value`, and the encoding is stable across a round-trip (re-encoding the decoded value yields the
/// same bytes, which catches non-canonical or lossy codecs).
///
/// `write` serializes a value into a growable buffer (writing to a `Vec` is infallible); `read`
/// deserializes it back from the produced bytes. The migration codecs pass their own
/// `Type::write` / `Type::read` through small closures.
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

    let mut reencoded = Vec::new();
    write(&decoded, &mut reencoded).expect("writing to a Vec is infallible");
    assert_eq!(
        reencoded, bytes,
        "encoding must be stable across a round-trip"
    );
}
