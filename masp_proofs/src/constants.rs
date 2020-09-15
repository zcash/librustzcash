//! Various constants used for the Zcash proofs.

use bls12_381::Scalar;
use group::{Curve, Group};
use lazy_static::lazy_static;
use masp_primitives::constants::PEDERSEN_HASH_GENERATORS;
use zcash_primitives::constants::PEDERSEN_HASH_CHUNKS_PER_GENERATOR;
use zcash_proofs::constants::{FixedGeneratorOwned, to_montgomery_coords};

/// The number of chunks needed to represent a full scalar during fixed-base
/// exponentiation.
const FIXED_BASE_CHUNKS_PER_GENERATOR: usize = 84;

lazy_static! {
    pub static ref PROOF_GENERATION_KEY_GENERATOR: FixedGeneratorOwned =
        generate_circuit_generator(masp_primitives::constants::PROOF_GENERATION_KEY_GENERATOR);

    pub static ref NOTE_COMMITMENT_RANDOMNESS_GENERATOR: FixedGeneratorOwned =
        generate_circuit_generator(masp_primitives::constants::NOTE_COMMITMENT_RANDOMNESS_GENERATOR);

    pub static ref NULLIFIER_POSITION_GENERATOR: FixedGeneratorOwned =
        generate_circuit_generator(masp_primitives::constants::NULLIFIER_POSITION_GENERATOR);

    pub static ref VALUE_COMMITMENT_RANDOMNESS_GENERATOR: FixedGeneratorOwned =
        generate_circuit_generator(masp_primitives::constants::VALUE_COMMITMENT_RANDOMNESS_GENERATOR);

    pub static ref SPENDING_KEY_GENERATOR: FixedGeneratorOwned =
        generate_circuit_generator(masp_primitives::constants::SPENDING_KEY_GENERATOR);

    /// The pre-computed window tables `[-4, 3, 2, 1, 1, 2, 3, 4]` of different magnitudes
    /// of the Pedersen hash segment generators.
    pub static ref PEDERSEN_CIRCUIT_GENERATORS: Vec<Vec<Vec<(Scalar, Scalar)>>> =
        generate_pedersen_circuit_generators();
}

/// Creates the 3-bit window table `[0, 1, ..., 8]` for different magnitudes of a fixed
/// generator.
fn generate_circuit_generator(mut gen: jubjub::SubgroupPoint) -> FixedGeneratorOwned {
    let mut windows = vec![];

    for _ in 0..FIXED_BASE_CHUNKS_PER_GENERATOR {
        let mut coeffs = vec![(Scalar::zero(), Scalar::one())];
        let mut g = gen.clone();
        for _ in 0..7 {
            let g_affine = jubjub::ExtendedPoint::from(g).to_affine();
            coeffs.push((g_affine.get_u(), g_affine.get_v()));
            g += gen;
        }
        windows.push(coeffs);

        // gen = gen * 8
        gen = g;
    }

    windows
}

/// Creates the 2-bit window table lookups for each 4-bit "chunk" in each segment of the
/// Pedersen hash.
fn generate_pedersen_circuit_generators() -> Vec<Vec<Vec<(Scalar, Scalar)>>> {
    // Process each segment
    PEDERSEN_HASH_GENERATORS
        .iter()
        .cloned()
        .map(|mut gen| {
            let mut windows = vec![];

            for _ in 0..PEDERSEN_HASH_CHUNKS_PER_GENERATOR {
                // Create (x, y) coeffs for this chunk
                let mut coeffs = vec![];
                let mut g = gen.clone();

                // coeffs = g, g*2, g*3, g*4
                for _ in 0..4 {
                    coeffs.push(
                        to_montgomery_coords(g.into())
                            .expect("we never encounter the point at infinity"),
                    );
                    g += gen;
                }
                windows.push(coeffs);

                // Our chunks are separated by 2 bits to prevent overlap.
                for _ in 0..4 {
                    gen = gen.double();
                }
            }

            windows
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use ff::PrimeField;
    use zcash_proofs::constants::{EDWARDS_D, MONTGOMERY_A, MONTGOMERY_SCALE};

    use super::*;

    #[test]
    fn edwards_d() {
        // d = -(10240/10241)
        assert_eq!(
            -Scalar::from_str("10240").unwrap()
                * Scalar::from_str("10241").unwrap().invert().unwrap(),
            EDWARDS_D
        );
    }

    #[test]
    fn montgomery_a() {
        assert_eq!(Scalar::from_str("40962").unwrap(), MONTGOMERY_A);
    }

    #[test]
    fn montgomery_scale() {
        // scaling factor = sqrt(4 / (a - d))
        assert_eq!(
            MONTGOMERY_SCALE.square() * (-Scalar::one() - EDWARDS_D),
            Scalar::from(4),
        );
    }
}
