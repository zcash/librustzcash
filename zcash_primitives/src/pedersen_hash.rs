use crate::jubjub::*;
use ff::{Field, PrimeField, PrimeFieldRepr};

#[derive(Copy, Clone)]
pub enum Personalization {
    NoteCommitment,
    MerkleTree(usize),
}

impl Personalization {
    pub fn get_bits(&self) -> Vec<bool> {
        match *self {
            Personalization::NoteCommitment => vec![true, true, true, true, true, true],
            Personalization::MerkleTree(num) => {
                assert!(num < 63);

                (0..6).map(|i| (num >> i) & 1 == 1).collect()
            }
        }
    }
}

pub fn pedersen_hash<E, I>(
    personalization: Personalization,
    bits: I,
    params: &E::Params,
) -> edwards::Point<E, PrimeOrder>
where
    I: IntoIterator<Item = bool>,
    E: JubjubEngine,
{
    let mut bits = personalization
        .get_bits()
        .into_iter()
        .chain(bits.into_iter());

    let mut result = edwards::Point::zero();
    let mut generators = params.pedersen_hash_exp_table().iter();

    loop {
        let mut acc = E::Fs::zero();
        let mut cur = E::Fs::one();
        let mut chunks_remaining = params.pedersen_hash_chunks_per_generator();
        let mut encountered_bits = false;

        // Grab three bits from the input
        while let Some(a) = bits.next() {
            encountered_bits = true;

            let b = bits.next().unwrap_or(false);
            let c = bits.next().unwrap_or(false);

            // Start computing this portion of the scalar
            let mut tmp = cur;
            if a {
                tmp.add_assign(&cur);
            }
            cur.double(); // 2^1 * cur
            if b {
                tmp.add_assign(&cur);
            }

            // conditionally negate
            if c {
                tmp.negate();
            }

            acc.add_assign(&tmp);

            chunks_remaining -= 1;

            if chunks_remaining == 0 {
                break;
            } else {
                cur.double(); // 2^2 * cur
                cur.double(); // 2^3 * cur
                cur.double(); // 2^4 * cur
            }
        }

        if !encountered_bits {
            break;
        }

        let mut table: &[Vec<edwards::Point<E, _>>] =
            &generators.next().expect("we don't have enough generators");
        let window = JubjubBls12::pedersen_hash_exp_window_size();
        let window_mask = (1 << window) - 1;

        let mut acc = acc.into_repr();

        let mut tmp = edwards::Point::zero();

        while !acc.is_zero() {
            let i = (acc.as_ref()[0] & window_mask) as usize;

            tmp = tmp.add(&table[0][i], params);

            acc.shr(window);
            table = &table[1..];
        }

        result = result.add(&tmp, params);
    }

    result
}

#[cfg(test)]
mod test {

    use pairing::bls12_381::{Bls12, Fr};
    use super::*;

    #[test]
    fn test_pedersen_hash_points() {

        let params = &JubjubBls12::new();
        let bytes = b"Salut monde!";
        let num_bits = bytes.len() * 8;
        let bits: Vec<bool> = (0..num_bits).map(
            |i| ((bytes[i / 8] >> (7 - (i % 8))) & 1) == 1
        ).collect();

        let xy = pedersen_hash::<Bls12, _>(
            Personalization::NoteCommitment,
            bits.clone().into_iter(),
            params,
        ).into_xy();

        println!("bytes = {:?}", bytes);
        let bits_int: Vec<u8> = bits.iter().map(|&i| i as u8).collect();
        println!("bits = {:?}", bits_int);
        println!("x = {}", xy.0);
        println!("y = {}", xy.1);

        // For bits=[]
        //assert_eq!(xy.0.to_string(), "Fr(0x06b1187c11ca4fb4383b2e0d0dbbde3ad3617338b5029187ec65a5eaed5e4d0b)");
        //assert_eq!(xy.1.to_string(), "Fr(0x3ce70f536652f0dea496393a1e55c4e08b9d55508e16d11e5db40d4810cbc982)");

        // For bits=[0]
        // assert_eq!(xy.0.to_string(), "Fr(0x2fc3bc454c337f71d4f04f86304262fcbfc9ecd808716b92fc42cbe6827f7f1a)");
        // assert_eq!(xy.1.to_string(), "Fr(0x46d0d25bf1a654eedc6a9b1e5af398925113959feac31b7a2c036ff9b9ec0638)");

        // For bits = "Salut monde!" in ASCII
        assert_eq!(xy.0.to_string(), "Fr(0x676f78fa89da7c64502f790a99dfe177756867006809a6f174dcb427b345cd7c)");
        assert_eq!(xy.1.to_string(), "Fr(0x1a6994a999a0abf83afc6ec5fe0ee8c8336a171653218cbfdf269689d5cfd3aa)");

    }
}