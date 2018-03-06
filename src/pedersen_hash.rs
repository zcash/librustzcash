use jubjub::*;
use pairing::*;

pub enum Personalization {
    NoteCommitment,
    MerkleTree(usize)
}

impl Personalization {
    pub fn get_bits(&self) -> Vec<bool> {
        match *self {
            Personalization::NoteCommitment =>
                vec![true, true, true, true, true, true],
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
    params: &E::Params
) -> edwards::Point<E, PrimeOrder>
    where I: IntoIterator<Item=bool>,
          E: JubjubEngine
{
    let mut bits = personalization.get_bits().into_iter().chain(bits.into_iter());

    let mut result = edwards::Point::zero();
    let mut generators = params.pedersen_hash_generators().iter();

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

        let mut tmp = generators.next().expect("we don't have enough generators").clone();
        tmp = tmp.mul(acc, params);
        result = result.add(&tmp, params);
    }

    result
}
