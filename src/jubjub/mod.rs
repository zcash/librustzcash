//! Jubjub is an elliptic curve defined over the BLS12-381 scalar field, Fr.
//! It is a Montgomery curve that takes the form `y^2 = x^3 + Ax^2 + x` where
//! `A = 40962`. This is the smallest integer choice of A such that:
//!
//! * `(A - 2) / 4` is a small integer (`10240`).
//! * `A^2 - 4` is quadratic residue.
//! * The group order of the curve and its quadratic twist has a large prime factor.
//!
//! Jubjub has `s = 0x0e7db4ea6533afa906673b0101343b00a6682093ccc81082d0970e5ed6f72cb7`
//! as the prime subgroup order, with cofactor 8. (The twist has cofactor 4.)
//!
//! This curve is birationally equivalent to a twisted Edwards curve of the
//! form `-x^2 + y^2 = 1 + dx^2y^2` with `d = -(10240/10241)`. In fact, this equivalence
//! forms a group isomorphism, so points can be freely converted between the Montgomery
//! and twisted Edwards forms.

use pairing::{
    Engine,
    Field,
    PrimeField,
    SqrtField
};

use super::group_hash::group_hash;

use pairing::bls12_381::{
    Bls12,
    Fr
};

pub mod edwards;
pub mod montgomery;

#[cfg(test)]
pub mod tests;

pub trait JubjubEngine: Engine {
    type Fs: PrimeField + SqrtField;
    type Params: JubjubParams<Self>;
}

pub trait JubjubParams<E: JubjubEngine>: Sized {
    fn edwards_d(&self) -> &E::Fr;
    fn montgomery_a(&self) -> &E::Fr;
    fn montgomery_2a(&self) -> &E::Fr;
    fn scale(&self) -> &E::Fr;
    fn pedersen_hash_generators(&self) -> &[edwards::Point<E, PrimeOrder>];
    fn pedersen_hash_chunks_per_generator(&self) -> usize;
    fn pedersen_circuit_generators(&self) -> &[Vec<Vec<(E::Fr, E::Fr)>>];
}

pub enum Unknown { }
pub enum PrimeOrder { }

pub mod fs;

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
    pedersen_circuit_generators: Vec<Vec<Vec<(Fr, Fr)>>>
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
        62
    }
    fn pedersen_circuit_generators(&self) -> &[Vec<Vec<(Fr, Fr)>>] {
        &self.pedersen_circuit_generators
    }
}

impl JubjubBls12 {
    pub fn new() -> Self {
        let montgomery_a = Fr::from_str("40962").unwrap();
        let mut montgomery_2a = montgomery_a;
        montgomery_2a.double();

        let mut tmp = JubjubBls12 {
            // d = -(10240/10241)
            edwards_d: Fr::from_str("19257038036680949359750312669786877991949435402254120286184196891950884077233").unwrap(),
            // A = 40962
            montgomery_a: montgomery_a,
            // 2A = 2.A
            montgomery_2a: montgomery_2a,
            // scaling factor = sqrt(4 / (a - d))
            scale: Fr::from_str("17814886934372412843466061268024708274627479829237077604635722030778476050649").unwrap(),

            pedersen_hash_generators: vec![],
            pedersen_circuit_generators: vec![]
        };

        {
            let mut cur = 0;
            let mut pedersen_hash_generators = vec![];

            while pedersen_hash_generators.len() < 10 {
                let gh = group_hash(&[cur], &tmp);
                // We don't want to overflow and start reusing generators
                assert!(cur != u8::max_value());
                cur += 1;

                if let Some(gh) = gh {
                    pedersen_hash_generators.push(gh);
                }
            }

            tmp.pedersen_hash_generators = pedersen_hash_generators;
        }

        {
            let mut pedersen_circuit_generators = vec![];

            for mut gen in tmp.pedersen_hash_generators.iter().cloned() {
                let mut gen = montgomery::Point::from_edwards(&gen, &tmp);
                let mut windows = vec![];
                for _ in 0..tmp.pedersen_hash_chunks_per_generator() {
                    let mut coeffs = vec![];
                    let mut g = gen.clone();
                    for _ in 0..4 {
                        coeffs.push(g.into_xy().expect("cannot produce O"));
                        g = g.add(&gen, &tmp);
                    }
                    windows.push(coeffs);

                    for _ in 0..4 {
                        gen = gen.double(&tmp);
                    }
                }
                pedersen_circuit_generators.push(windows);
            }

            tmp.pedersen_circuit_generators = pedersen_circuit_generators;
        }

        tmp
    }
}

#[test]
fn test_jubjub_bls12() {
    let params = JubjubBls12::new();

    tests::test_suite::<Bls12>(&params);
}
