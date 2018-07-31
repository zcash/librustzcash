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

    use super::*;
    use pairing::bls12_381::Bls12;

    #[test]
    fn test_pedersen_hash_points() {
        // Test vectors from https://github.com/zcash-hackworks/zcash-test-vectors/blob/master/sapling_pedersen.py
        struct TestVector<'a> {
            personalization: Personalization,
            input_bits: Vec<u8>,
            hash_x: &'a str,
            hash_y: &'a str,
        }

        let test_vectors = vec![
            TestVector {
                personalization: Personalization::NoteCommitment,
                input_bits: vec![1, 1, 1, 1, 1, 1],
                hash_x: "Fr(0x06b1187c11ca4fb4383b2e0d0dbbde3ad3617338b5029187ec65a5eaed5e4d0b)",
                hash_y: "Fr(0x3ce70f536652f0dea496393a1e55c4e08b9d55508e16d11e5db40d4810cbc982)",
            },
            TestVector {
                personalization: Personalization::NoteCommitment,
                input_bits: vec![1, 1, 1, 1, 1, 1, 0],
                hash_x: "Fr(0x2fc3bc454c337f71d4f04f86304262fcbfc9ecd808716b92fc42cbe6827f7f1a)",
                hash_y: "Fr(0x46d0d25bf1a654eedc6a9b1e5af398925113959feac31b7a2c036ff9b9ec0638)",
            },
            TestVector {
                personalization: Personalization::NoteCommitment,
                input_bits: vec![1, 1, 1, 1, 1, 1, 1],
                hash_x: "Fr(0x4f8ce0e0a9e674b3ab9606a7d7aefba386e81583d81918127814cde41d209d97)",
                hash_y: "Fr(0x312b5ab93b14c9b9af334fe1fe3c50fffb53fbd074fa40ca600febde7c97e346)",
            },
            TestVector {
                personalization: Personalization::NoteCommitment,
                input_bits: vec![1, 1, 1, 1, 1, 1, 0, 0],
                hash_x: "Fr(0x2fc3bc454c337f71d4f04f86304262fcbfc9ecd808716b92fc42cbe6827f7f1a)",
                hash_y: "Fr(0x46d0d25bf1a654eedc6a9b1e5af398925113959feac31b7a2c036ff9b9ec0638)",
            },
            TestVector {
                personalization: Personalization::NoteCommitment,
                input_bits: vec![1, 1, 1, 1, 1, 1, 0, 1],
                hash_x: "Fr(0x21746acd049f2c54579d5bb9c106083b4bb48c8910a06565d1e39e46939ca497)",
                hash_y: "Fr(0x2cb69ae2615cd02c6ad2d6e06c1a0c15d49d71051d2d702155fca07bbf2d574c)",
            },
            TestVector {
                personalization: Personalization::NoteCommitment,
                input_bits: vec![1, 1, 1, 1, 1, 1, 1, 0],
                hash_x: "Fr(0x4f8ce0e0a9e674b3ab9606a7d7aefba386e81583d81918127814cde41d209d97)",
                hash_y: "Fr(0x312b5ab93b14c9b9af334fe1fe3c50fffb53fbd074fa40ca600febde7c97e346)",
            },
            TestVector {
                personalization: Personalization::NoteCommitment,
                input_bits: vec![1, 1, 1, 1, 1, 1, 1, 1],
                hash_x: "Fr(0x3e09bdeea175dd4acd2e106caf4a5194200af53ee3a5a71338c083093d83eba5)",
                hash_y: "Fr(0x579f6f15508af07d0f1beb117beaffe99e115a7ee859d81ddaa91d1096a103df)",
            },
            TestVector {
                personalization: Personalization::NoteCommitment,
                input_bits: vec![1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                hash_x: "Fr(0x208d2e11ee496eb3b37257d1b4a77907e4b21d6c46d5487fb52d5a5239587ea0)",
                hash_y: "Fr(0x1eeeb47b858257b9b69d009779e38c63332e20220eb474ef9af868274132181f)",
            },
            TestVector {
                personalization: Personalization::NoteCommitment,
                input_bits: vec![1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1],
                hash_x: "Fr(0x683ffae48988d517301ba81fb2c294c16a35ed1bba6411bd17312294843f37e0)",
                hash_y: "Fr(0x40f7897b86747a5a857c8bd434ce3c1079efac22ed650d7345e5da31addacaff)",
            },
            TestVector {
                personalization: Personalization::NoteCommitment,
                input_bits: vec![
                    1, 1, 1, 1, 1, 1, 0, 1, 0, 1, 0, 0, 1, 1, 0, 1, 1, 0, 0, 0, 0, 1, 0, 1, 1, 0,
                    1, 1, 0, 0, 0, 1, 1, 1, 0, 1, 0, 1, 0, 1, 1, 1, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0,
                    0, 0, 0, 1, 1, 0, 1, 1, 0, 1, 0, 1, 1, 0, 1, 1, 1, 1, 0, 1, 1, 0, 1, 1, 1, 0,
                    0, 1, 1, 0, 0, 1, 0, 0, 0, 1, 1, 0, 0, 1, 0, 1, 0, 0, 1, 0, 0, 0, 0, 1,
                ],
                hash_x: "Fr(0x676f78fa89da7c64502f790a99dfe177756867006809a6f174dcb427b345cd7c)",
                hash_y: "Fr(0x1a6994a999a0abf83afc6ec5fe0ee8c8336a171653218cbfdf269689d5cfd3aa)",
            },
            TestVector {
                personalization: Personalization::MerkleTree(34),
                input_bits: vec![0, 1, 0, 0, 0, 1],
                hash_x: "Fr(0x61f8e2cb8e945631677b450d5e5669bc6b5f2ec69b321ac550dbe74525d7ac9a)",
                hash_y: "Fr(0x4e11951ab9c9400ee38a18bd98cdb9453f1f67141ee9d9bf0c1c157d4fb34f9a)",
            },
            TestVector {
                personalization: Personalization::MerkleTree(34),
                input_bits: vec![0, 1, 0, 0, 0, 1, 0],
                hash_x: "Fr(0x27fa1e296c37dde8448483ce5485c2604d1d830e53812246299773a02ecd519c)",
                hash_y: "Fr(0x08e499113675202cb42b4b681a31430814edebd72c5bb3bc3bfedf91fb0605df)",
            },
            TestVector {
                personalization: Personalization::MerkleTree(34),
                input_bits: vec![0, 1, 0, 0, 0, 1, 1],
                hash_x: "Fr(0x52112dd7a4293d049bb011683244a0f957e6ba95e1d1cf2fb6654d449a6d3fbc)",
                hash_y: "Fr(0x2ae14ecd81bb5b4489d2d64b5d2eb92a684087b28dd9a4950ecdb78c014e178c)",
            },
            TestVector {
                personalization: Personalization::MerkleTree(34),
                input_bits: vec![0, 1, 0, 0, 0, 1, 0, 0],
                hash_x: "Fr(0x27fa1e296c37dde8448483ce5485c2604d1d830e53812246299773a02ecd519c)",
                hash_y: "Fr(0x08e499113675202cb42b4b681a31430814edebd72c5bb3bc3bfedf91fb0605df)",
            },
            TestVector {
                personalization: Personalization::MerkleTree(34),
                input_bits: vec![0, 1, 0, 0, 0, 1, 0, 1],
                hash_x: "Fr(0x5b4032d49431e7bfa085e2bb49bfc060909272a66287b063784f1d11b28a60e9)",
                hash_y: "Fr(0x4627da49652efea2637595426add6ad682a0c8821d423f04c26ef5788d35f7e3)",
            },
            TestVector {
                personalization: Personalization::MerkleTree(34),
                input_bits: vec![0, 1, 0, 0, 0, 1, 1, 0],
                hash_x: "Fr(0x52112dd7a4293d049bb011683244a0f957e6ba95e1d1cf2fb6654d449a6d3fbc)",
                hash_y: "Fr(0x2ae14ecd81bb5b4489d2d64b5d2eb92a684087b28dd9a4950ecdb78c014e178c)",
            },
            TestVector {
                personalization: Personalization::MerkleTree(34),
                input_bits: vec![0, 1, 0, 0, 0, 1, 1, 1],
                hash_x: "Fr(0x099e74a82c9c1858ac40db1a85959b1362d82fdd6efb99a443829f83003b0190)",
                hash_y: "Fr(0x0f76f53d026574ad77ab4c6cd2428b9d94d158a9fc0469aae47c7535ff107881)",
            },
            TestVector {
                personalization: Personalization::MerkleTree(34),
                input_bits: vec![0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                hash_x: "Fr(0x240da48e40637664bcf3582708491d19e28a50787ea40b0a336d61735782d10a)",
                hash_y: "Fr(0x6e630ddf6e43ad5568c925a4935e8e099230af4b2e19fab7d92b7e953b4986c3)",
            },
            TestVector {
                personalization: Personalization::MerkleTree(34),
                input_bits: vec![0, 1, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1],
                hash_x: "Fr(0x06a477addbbfdf2934e34bdf6e071cd1276beaed801cd1b660ddcceb161ca8c7)",
                hash_y: "Fr(0x355d39425378e57f393b30423cbde3ff69198ebac2ccbbafb92e25613352b0e8)",
            },
            TestVector {
                personalization: Personalization::MerkleTree(34),
                input_bits: vec![
                    0, 1, 0, 0, 0, 1, 0, 1, 0, 1, 0, 0, 1, 1, 0, 1, 1, 0, 0, 0, 0, 1, 0, 1, 1, 0,
                    1, 1, 0, 0, 0, 1, 1, 1, 0, 1, 0, 1, 0, 1, 1, 1, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0,
                    0, 0, 0, 1, 1, 0, 1, 1, 0, 1, 0, 1, 1, 0, 1, 1, 1, 1, 0, 1, 1, 0, 1, 1, 1, 0,
                    0, 1, 1, 0, 0, 1, 0, 0, 0, 1, 1, 0, 0, 1, 0, 1, 0, 0, 1, 0, 0, 0, 0, 1,
                ],
                hash_x: "Fr(0x094a624c5aac3569ad85428bb939d391bb5766ff87c389eb4d84d42aeaabb906)",
                hash_y: "Fr(0x2cf51a8699edc64b73aa962464d4eadf038821900f9409350dc3ea2ccf12e054)",
            },
        ];
        // End test vectors

        let params = &JubjubBls12::new();

        let v = &test_vectors[0];
        let input_bools: Vec<bool> = v.input_bits.iter().map(|&i| i == 1).collect();

        // The 6 bits prefix is handled separately
        assert_eq!(v.personalization.get_bits(), &input_bools[..6]);

        let (x, y) =
            pedersen_hash::<Bls12, _>(v.personalization, input_bools.into_iter().skip(6), params)
                .to_xy();

        assert_eq!(x.to_string(), v.hash_x);
        assert_eq!(y.to_string(), v.hash_y);
    }
}
