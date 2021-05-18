use blake2b_simd::{Params as Blake2bParams, OUTBYTES};
use std::cmp::min;

macro_rules! H_PERS {
    ( $i:expr ) => {
        [85, 65, 95, 70, 52, 74, 117, 109, 98, 108, 101, 95, 72, 95, $i, 0]
    }
}

macro_rules! G_PERS {
    ( $i:expr, $j:expr ) => {
        [85, 65, 95, 70, 52, 74, 117, 109, 98, 108, 101, 95, 71, 95, $i, $j]
    }
}

struct Hashes {
    l_l: usize,
    l_r: usize,
}

impl Hashes {
    fn new(message_length: usize) -> Self {
        let l_l = min(OUTBYTES, message_length / 2);
        let l_r = message_length - l_l;
        Hashes { l_l, l_r }
    }

    fn h(&self, i: u8, u: &[u8]) -> Vec<u8> {
        Blake2bParams::new()
            .hash_length(self.l_l)
            .personal(&H_PERS!(i))
            .hash(&u)
            .as_ref()
            .to_vec()
    }

    fn g(&self, i: u8, u: &[u8]) -> Vec<u8> {
        (0..ceildiv(self.l_r, OUTBYTES)).flat_map(|j| {
            Blake2bParams::new()
                .hash_length(OUTBYTES)
                .personal(&G_PERS!(i, j as u8))
                .hash(u)
                .as_ref()
                .to_vec()
                .into_iter()
        })
        .take(self.l_r)
        .collect()
    }
}

fn xor(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b.iter()).map(|(a0, b0)| a0 ^ b0).collect()
}

fn ceildiv(num: usize, den: usize) -> usize {
    (num + den - 1) / den
}

#[allow(clippy::many_single_char_names)]
pub fn f4jumble(mut a: Vec<u8>) -> Option<Vec<u8>> {
    if a.len() >= 48 && a.len() <= 16448 {
        Some({
            let hashes = Hashes::new(a.len());
            let b = a.split_off(hashes.l_l);

            let x = xor(&b, &hashes.g(0, &a));
            let y = xor(&a, &hashes.h(0, &x));
            let d = xor(&x, &hashes.g(1, &y));
            let mut c = xor(&y, &hashes.h(1, &d));

            c.extend(d);
            c
        })
    } else {
        None
    }
}

#[allow(clippy::many_single_char_names)]
pub fn f4jumble_inv(mut c: Vec<u8>) -> Option<Vec<u8>> {
    if c.len() >= 48 && c.len() <= 16448 {
        Some({
            let hashes = Hashes::new(c.len());
            let d = c.split_off(hashes.l_l);

            let y = xor(&c, &hashes.h(1, &d));
            let x = xor(&d, &hashes.g(1, &y));
            let mut a = xor(&y, &hashes.h(0, &x));
            let b = xor(&x, &hashes.g(0, &a));

            a.extend(b);
            a
        })
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use proptest::collection::vec;
    use proptest::prelude::*;

    use super::{f4jumble, f4jumble_inv};
    
    #[test]
    fn h_pers() {
        assert_eq!(&H_PERS!(7), b"UA_F4Jumble_H_\x07\x00");
    }
    
    #[test]
    fn g_pers() {
        assert_eq!(&G_PERS!(7, 13), b"UA_F4Jumble_G_\x07\x0d");
    }

    proptest! {
        #[test]
        fn f4jumble_roundtrip(msg in vec(any::<u8>(), 48..16448)) {
            let jumbled = f4jumble(msg.clone()).unwrap();
            let jumbled_len = jumbled.len();
            prop_assert_eq!(
                msg.len(), jumbled_len,
                "Jumbled length {} was not equal to message length {}",
                jumbled_len, msg.len()
            );

            let unjumbled = f4jumble_inv(jumbled).unwrap();
            prop_assert_eq!(
                jumbled_len, unjumbled.len(),
                "Unjumbled length {} was not equal to jumbled length {}",
                unjumbled.len(), jumbled_len
            );

            prop_assert_eq!(msg, unjumbled, "Unjumbled message did not match original message.");
        }
    }
}
