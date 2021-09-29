#![no_std]

use blake2b_simd::{Params as Blake2bParams, OUTBYTES};
use const_format::formatcp;
use core::cmp::min;
use core::ops::RangeInclusive;
use core::result::Result;

#[cfg(feature = "std")]
extern crate std;
#[cfg(feature = "std")]
use std::vec::Vec;

#[cfg(test)]
mod test_vectors;
#[cfg(test)]
mod test_vectors_long;

pub const VALID_LENGTH: RangeInclusive<usize> = 48..=4194368;
const INVALID_LENGTH_ERROR_MESSAGE: &'static str = formatcp!(
    "Message length must be in interval ({}..={})",
    *VALID_LENGTH.start(),
    *VALID_LENGTH.end()
);
//more andvanced formatcp! only in nightly Rust

macro_rules! H_PERS {
    ( $i:expr ) => {
        [
            85, 65, 95, 70, 52, 74, 117, 109, 98, 108, 101, 95, 72, $i, 0, 0,
        ]
    };
}

macro_rules! G_PERS {
    ( $i:expr, $j:expr ) => {
        [
            85,
            65,
            95,
            70,
            52,
            74,
            117,
            109,
            98,
            108,
            101,
            95,
            71,
            $i,
            ($j & 0xFF) as u8,
            ($j >> 8) as u8,
        ]
    };
}

struct State<'a> {
    left: &'a mut [u8],
    right: &'a mut [u8],
}

impl<'a> State<'a> {
    fn new(message: &'a mut [u8]) -> Self {
        let left_length = min(OUTBYTES, message.len() / 2);
        let (left, right) = message.split_at_mut(left_length);
        State { left, right }
    }

    fn h_round(&mut self, i: u8) {
        let hash = Blake2bParams::new()
            .hash_length(self.left.len())
            .personal(&H_PERS!(i))
            .hash(&self.right);
        xor(self.left, hash.as_bytes())
    }

    fn g_round(&mut self, i: u8) {
        for j in 0..ceildiv(self.right.len(), OUTBYTES) {
            let hash = Blake2bParams::new()
                .hash_length(OUTBYTES)
                .personal(&G_PERS!(i, j as u16))
                .hash(&self.left);
            xor(&mut self.right[j * OUTBYTES..], hash.as_bytes());
        }
    }

    fn apply_f4jumble(&mut self) {
        self.g_round(0);
        self.h_round(0);
        self.g_round(1);
        self.h_round(1);
    }

    fn apply_f4jumble_inv(&mut self) {
        self.h_round(1);
        self.g_round(1);
        self.h_round(0);
        self.g_round(0);
    }
}

// xor bytes of the `source` to bytes of the `target`
fn xor(target: &mut [u8], source: &[u8]) {
    for i in 0..min(source.len(), target.len()) {
        target[i] ^= source[i];
    }
}

fn ceildiv(num: usize, den: usize) -> usize {
    (num + den - 1) / den
}

pub fn f4jumble_mut(message: &mut [u8]) -> Result<(), &str> {
    if VALID_LENGTH.contains(&message.len()) {
        State::new(message).apply_f4jumble();
        Ok(())
    } else {
        Err(INVALID_LENGTH_ERROR_MESSAGE)
    }
}

pub fn f4jumble_inv_mut(message: &mut [u8]) -> Result<(), &str> {
    if VALID_LENGTH.contains(&message.len()) {
        State::new(message).apply_f4jumble_inv();
        Ok(())
    } else {
        Err(INVALID_LENGTH_ERROR_MESSAGE)
    }
}

#[cfg(feature = "std")]
pub fn f4jumble(message: &[u8]) -> Option<Vec<u8>> {
    let mut result = message.to_vec();
    let res = f4jumble_mut(&mut result);
    if res.is_ok() {
        Some(Vec::from(result))
    } else {
        None
    }
}

#[cfg(feature = "std")]
pub fn f4jumble_inv(message: &[u8]) -> Option<Vec<u8>> {
    let mut result = message.to_vec();
    let res = f4jumble_inv_mut(&mut result);
    if res.is_ok() {
        Some(Vec::from(result))
    } else {
        None
    }
}

#[cfg(feature = "std")]
#[cfg(test)]
mod tests {
    use blake2b_simd::blake2b;
    use proptest::collection::vec;
    use proptest::prelude::*;
    use std::format;
    use std::vec::Vec;

    use super::{
        f4jumble, f4jumble_inv, test_vectors::test_vectors, test_vectors_long, VALID_LENGTH,
    };

    #[test]
    fn h_pers() {
        assert_eq!(&H_PERS!(7), b"UA_F4Jumble_H\x07\x00\x00");
    }

    #[test]
    fn g_pers() {
        assert_eq!(&G_PERS!(7, 13), b"UA_F4Jumble_G\x07\x0d\x00");
        assert_eq!(&G_PERS!(7, 65535), b"UA_F4Jumble_G\x07\xff\xff");
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(5))]

        #[test]
        fn f4jumble_roundtrip(msg in vec(any::<u8>(), VALID_LENGTH)) {
            let jumbled = f4jumble(&msg).unwrap();
            let jumbled_len = jumbled.len();
            prop_assert_eq!(
                msg.len(), jumbled_len,
                "Jumbled length {} was not equal to message length {}",
                jumbled_len, msg.len()
            );

            let unjumbled = f4jumble_inv(&jumbled).unwrap();
            prop_assert_eq!(
                jumbled_len, unjumbled.len(),
                "Unjumbled length {} was not equal to jumbled length {}",
                unjumbled.len(), jumbled_len
            );

            prop_assert_eq!(msg, unjumbled, "Unjumbled message did not match original message.");
        }
    }

    #[test]
    fn f4jumble_check_vectors() {
        for v in test_vectors() {
            let jumbled = f4jumble(&v.normal).unwrap();
            assert_eq!(jumbled, v.jumbled);
            let unjumbled = f4jumble_inv(&v.jumbled).unwrap();
            assert_eq!(unjumbled, v.normal);
        }
    }

    #[test]
    fn f4jumble_check_vectors_long() {
        for v in test_vectors_long::TEST_VECTORS {
            let normal: Vec<u8> = (0..v.length).map(|i| i as u8).collect();
            let jumbled = f4jumble(&normal).unwrap();
            assert_eq!(blake2b(&jumbled).as_bytes(), v.jumbled_hash);
            let unjumbled = f4jumble_inv(&jumbled).unwrap();
            assert_eq!(unjumbled, normal);
        }
    }
}
