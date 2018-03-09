//! Jubjub is a twisted Edwards curve defined over the BLS12-381 scalar
//! field, Fr. It takes the form `-x^2 + y^2 = 1 + dx^2y^2` with
//! `d = -(10240/10241)`. It is birationally equivalent to a Montgomery
//! curve of the form `y^2 = x^3 + Ax^2 + x` with `A = 40962`. This
//! value `A` is the smallest integer choice such that:
//!
//! * `(A - 2) / 4` is a small integer (`10240`).
//! * `A^2 - 4` is quadratic nonresidue.
//! * The group order of the curve and its quadratic twist has a large
//!   prime factor.
//!
//! Jubjub has `s = 0x0e7db4ea6533afa906673b0101343b00a6682093ccc81082d0970e5ed6f72cb7`
//! as the prime subgroup order, with cofactor 8. (The twist has
//! cofactor 4.)
//!
//! It is a complete twisted Edwards curve, so the equivalence with
//! the Montgomery curve forms a group isomorphism, allowing points
//! to be freely converted between the two forms.

use pairing::{
    Engine,
    Field,
    PrimeField,
    SqrtField
};

use group_hash::group_hash;

use constants;

use pairing::bls12_381::{
    Bls12,
    Fr
};

/// This is an implementation of the twisted Edwards Jubjub curve.
pub mod edwards;

/// This is an implementation of the birationally equivalent
/// Montgomery curve.
pub mod montgomery;

/// This is an implementation of the scalar field for Jubjub.
pub mod fs;

#[cfg(test)]
pub mod tests;

/// Point of unknown order.
pub enum Unknown { }

/// Point of prime order.
pub enum PrimeOrder { }

/// Fixed generators of the Jubjub curve of unknown
/// exponent.
#[derive(Copy, Clone)]
pub enum FixedGenerators {
    /// The prover will demonstrate knowledge of discrete log
    /// with respect to this base when they are constructing
    /// a proof, in order to authorize proof construction.
    ProofGenerationKey = 0,

    /// The note commitment is randomized over this generator.
    NoteCommitmentRandomness = 1,

    /// The node commitment is randomized again by the position
    /// in order to supply the nullifier computation with a
    /// unique input w.r.t. the note being spent, to prevent
    /// Faerie gold attacks.
    NullifierPosition = 2,

    /// The value commitment is used to check balance between
    /// inputs and outputs. The value is placed over this
    /// generator.
    ValueCommitmentValue = 3,
    /// The value commitment is randomized over this generator,
    /// for privacy.
    ValueCommitmentRandomness = 4,

    /// The spender proves discrete log with respect to this
    /// base at spend time.
    SpendingKeyGenerator = 5,

    Max = 6
}

/// This is an extension to the pairing Engine trait which
/// offers a scalar field for the embedded curve (Jubjub)
/// and some pre-computed parameters.
pub trait JubjubEngine: Engine {
    /// The scalar field of the Jubjub curve
    type Fs: PrimeField + SqrtField;
    /// The parameters of Jubjub and the Sapling protocol
    type Params: JubjubParams<Self>;
}

/// The pre-computed parameters for Jubjub, including curve
/// constants and various limits and window tables.
pub trait JubjubParams<E: JubjubEngine>: Sized {
    /// The `d` constant of the twisted Edwards curve.
    fn edwards_d(&self) -> &E::Fr;
    /// The `A` constant of the birationally equivalent Montgomery curve.
    fn montgomery_a(&self) -> &E::Fr;
    /// The `A` constant, doubled.
    fn montgomery_2a(&self) -> &E::Fr;
    /// The scaling factor used for conversion from the Montgomery form.
    fn scale(&self) -> &E::Fr;
    /// Returns the generators (for each segment) used in all Pedersen commitments.
    fn pedersen_hash_generators(&self) -> &[edwards::Point<E, PrimeOrder>];
    /// Returns the maximum number of chunks per segment of the Pedersen hash.
    fn pedersen_hash_chunks_per_generator(&self) -> usize;
    /// Returns the pre-computed window tables [-4, 3, 2, 1, 1, 2, 3, 4] of different
    /// magnitudes of the Pedersen hash segment generators.
    fn pedersen_circuit_generators(&self) -> &[Vec<Vec<(E::Fr, E::Fr)>>];

    /// Returns the number of chunks needed to represent a full scalar during fixed-base
    /// exponentiation.
    fn fixed_base_chunks_per_generator(&self) -> usize;
    /// Returns a fixed generator.
    fn generator(&self, base: FixedGenerators) -> &edwards::Point<E, PrimeOrder>;
    /// Returns a window table [0, 1, ..., 8] for different magntitudes of some
    /// fixed generator.
    fn circuit_generators(&self, FixedGenerators) -> &[Vec<(E::Fr, E::Fr)>];
}

impl JubjubEngine for Bls12 {
    type Fs = self::fs::Fs;
    type Params = JubjubBls12;
}

pub struct JubjubBls12 {
    edwards_d: Fr,
    montgomery_a: Fr,
    montgomery_2a: Fr,
    scale: Fr,

    pedersen_hash_generators: Vec<edwards::Point<Bls12, PrimeOrder>>,
    pedersen_circuit_generators: Vec<Vec<Vec<(Fr, Fr)>>>,

    fixed_base_generators: Vec<edwards::Point<Bls12, PrimeOrder>>,
    fixed_base_circuit_generators: Vec<Vec<Vec<(Fr, Fr)>>>,
}

impl JubjubParams<Bls12> for JubjubBls12 {
    fn edwards_d(&self) -> &Fr { &self.edwards_d }
    fn montgomery_a(&self) -> &Fr { &self.montgomery_a }
    fn montgomery_2a(&self) -> &Fr { &self.montgomery_2a }
    fn scale(&self) -> &Fr { &self.scale }
    fn pedersen_hash_generators(&self) -> &[edwards::Point<Bls12, PrimeOrder>] {
        &self.pedersen_hash_generators
    }
    fn pedersen_hash_chunks_per_generator(&self) -> usize {
        63
    }
    fn fixed_base_chunks_per_generator(&self) -> usize {
        84
    }
    fn pedersen_circuit_generators(&self) -> &[Vec<Vec<(Fr, Fr)>>] {
        &self.pedersen_circuit_generators
    }
    fn generator(&self, base: FixedGenerators) -> &edwards::Point<Bls12, PrimeOrder>
    {
        &self.fixed_base_generators[base as usize]
    }
    fn circuit_generators(&self, base: FixedGenerators) -> &[Vec<(Fr, Fr)>]
    {
        &self.fixed_base_circuit_generators[base as usize][..]
    }
}

impl JubjubBls12 {
    pub fn new() -> Self {
        let montgomery_a = Fr::from_str("40962").unwrap();
        let mut montgomery_2a = montgomery_a;
        montgomery_2a.double();

        let mut tmp_params = JubjubBls12 {
            // d = -(10240/10241)
            edwards_d: Fr::from_str("19257038036680949359750312669786877991949435402254120286184196891950884077233").unwrap(),
            // A = 40962
            montgomery_a: montgomery_a,
            // 2A = 2.A
            montgomery_2a: montgomery_2a,
            // scaling factor = sqrt(4 / (a - d))
            scale: Fr::from_str("17814886934372412843466061268024708274627479829237077604635722030778476050649").unwrap(),

            // We'll initialize these below
            pedersen_hash_generators: vec![],
            pedersen_circuit_generators: vec![],
            fixed_base_generators: vec![],
            fixed_base_circuit_generators: vec![],
        };

        // Create the bases for the Pedersen hashes
        {
            // TODO: This currently does not match the specification
            let mut cur = 0;
            let mut pedersen_hash_generators = vec![];

            // TODO: This generates more bases for the Pedersen hashes
            // than necessary, which is just a performance issue in
            // practice.
            while pedersen_hash_generators.len() < 5 {
                let gh = group_hash(&[cur], constants::PEDERSEN_HASH_GENERATORS_PERSONALIZATION, &tmp_params);
                // We don't want to overflow and start reusing generators
                assert!(cur != u8::max_value());
                cur += 1;

                if let Some(gh) = gh {
                    pedersen_hash_generators.push(gh);
                }
            }

            // Check for duplicates, far worse than spec inconsistencies!
            for (i, p1) in pedersen_hash_generators.iter().enumerate() {
                if p1 == &edwards::Point::zero() {
                    panic!("Neutral element!");
                }

                for p2 in pedersen_hash_generators.iter().skip(i+1) {
                    if p1 == p2 {
                        panic!("Duplicate generator!");
                    }
                }
            }

            tmp_params.pedersen_hash_generators = pedersen_hash_generators;
        }

        // Create the bases for other parts of the protocol
        {
            let mut fixed_base_generators = vec![edwards::Point::zero(); FixedGenerators::Max as usize];

            {
                // Each generator is found by invoking the group hash
                // on tag 0x00, 0x01, ... until we find a valid result.
                let find_first_gh = |personalization| {
                    let mut cur = 0u8;

                    loop {
                        let gh = group_hash::<Bls12>(&[cur], personalization, &tmp_params);
                        // We don't want to overflow.
                        assert!(cur != u8::max_value());
                        cur += 1;

                        if let Some(gh) = gh {
                            break gh;
                        }
                    }
                };

                // Written this way for exhaustion (double entendre). There's no
                // way to iterate over the variants of an enum, so it's hideous.
                for c in 0..(FixedGenerators::Max as usize) {
                    let p = match c {
                        c if c == (FixedGenerators::ProofGenerationKey as usize) => {
                            constants::PROOF_GENERATION_KEY_BASE_GENERATOR_PERSONALIZATION
                        },
                        c if c == (FixedGenerators::NoteCommitmentRandomness as usize) => {
                            constants::NOTE_COMMITMENT_RANDOMNESS_GENERATOR_PERSONALIZATION
                        },
                        c if c == (FixedGenerators::NullifierPosition as usize) => {
                            constants::NULLIFIER_POSITION_IN_TREE_GENERATOR_PERSONALIZATION
                        },
                        c if c == (FixedGenerators::ValueCommitmentValue as usize) => {
                            constants::VALUE_COMMITMENT_VALUE_GENERATOR_PERSONALIZATION
                        },
                        c if c == (FixedGenerators::ValueCommitmentRandomness as usize) => {
                            constants::VALUE_COMMITMENT_RANDOMNESS_GENERATOR_PERSONALIZATION
                        },
                        c if c == (FixedGenerators::SpendingKeyGenerator as usize) => {
                            constants::SPENDING_KEY_GENERATOR_PERSONALIZATION
                        },
                        _ => unreachable!()
                    };

                    fixed_base_generators[c] = find_first_gh(p);
                }
            }

            // Check for duplicates, far worse than spec inconsistencies!
            for (i, p1) in fixed_base_generators.iter().enumerate() {
                if p1 == &edwards::Point::zero() {
                    panic!("Neutral element!");
                }

                for p2 in fixed_base_generators.iter().skip(i+1) {
                    if p1 == p2 {
                        panic!("Duplicate generator!");
                    }
                }
            }

            tmp_params.fixed_base_generators = fixed_base_generators;
        }

        // Create the 2-bit window table lookups for each 4-bit
        // "chunk" in each segment of the Pedersen hash
        {
            let mut pedersen_circuit_generators = vec![];

            // Process each segment
            for mut gen in tmp_params.pedersen_hash_generators.iter().cloned() {
                let mut gen = montgomery::Point::from_edwards(&gen, &tmp_params);
                let mut windows = vec![];
                for _ in 0..tmp_params.pedersen_hash_chunks_per_generator() {
                    // Create (x, y) coeffs for this chunk
                    let mut coeffs = vec![];
                    let mut g = gen.clone();

                    // coeffs = g, g*2, g*3, g*4
                    for _ in 0..4 {
                        coeffs.push(g.into_xy().expect("cannot produce O"));
                        g = g.add(&gen, &tmp_params);
                    }
                    windows.push(coeffs);

                    // Our chunks are separated by 2 bits to prevent overlap.
                    for _ in 0..4 {
                        gen = gen.double(&tmp_params);
                    }
                }
                pedersen_circuit_generators.push(windows);
            }

            tmp_params.pedersen_circuit_generators = pedersen_circuit_generators;
        }

        // Create the 3-bit window table lookups for fixed-base
        // exp of each base in the protocol.
        {
            let mut fixed_base_circuit_generators = vec![];

            for mut gen in tmp_params.fixed_base_generators.iter().cloned() {
                let mut windows = vec![];
                for _ in 0..tmp_params.fixed_base_chunks_per_generator() {
                    let mut coeffs = vec![(Fr::zero(), Fr::one())];
                    let mut g = gen.clone();
                    for _ in 0..7 {
                        coeffs.push(g.into_xy());
                        g = g.add(&gen, &tmp_params);
                    }
                    windows.push(coeffs);

                    // gen = gen * 8
                    gen = g;
                }
                fixed_base_circuit_generators.push(windows);
            }

            tmp_params.fixed_base_circuit_generators = fixed_base_circuit_generators;
        }

        tmp_params
    }
}

#[test]
fn test_jubjub_bls12() {
    let params = JubjubBls12::new();

    tests::test_suite::<Bls12>(&params);

    let test_repr = hex!("b9481dd1103b7d1f8578078eb429d3c476472f53e88c0eaefdf51334c7c8b98c");
    let p = edwards::Point::<Bls12, _>::read(&test_repr[..], &params).unwrap();
    let q = edwards::Point::<Bls12, _>::get_for_y(
        Fr::from_str("22440861827555040311190986994816762244378363690614952020532787748720529117853").unwrap(),
        false,
        &params
    ).unwrap();

    assert!(p == q);
}
