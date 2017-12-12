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
    PrimeField,
    SqrtField
};

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
    fn scale(&self) -> &E::Fr;
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
    scale: Fr
}

impl JubjubParams<Bls12> for JubjubBls12 {
    fn edwards_d(&self) -> &Fr { &self.edwards_d }
    fn montgomery_a(&self) -> &Fr { &self.montgomery_a }
    fn scale(&self) -> &Fr { &self.scale }
}

impl JubjubBls12 {
    pub fn new() -> Self {
        JubjubBls12 {
            // d = -(10240/10241)
            edwards_d: Fr::from_str("19257038036680949359750312669786877991949435402254120286184196891950884077233").unwrap(),
            // A = 40962
            montgomery_a: Fr::from_str("40962").unwrap(),
            // scaling factor = sqrt(4 / (a - d))
            scale: Fr::from_str("17814886934372412843466061268024708274627479829237077604635722030778476050649").unwrap()
        }
    }
}

#[test]
fn test_jubjub_bls12() {
    let params = JubjubBls12::new();

    tests::test_suite::<Bls12>(&params);
}
