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
    PrimeField
};

use pairing::bls12_381::{
    Bls12,
    Fr
};

mod fs;

pub use self::fs::{Fs, FsRepr};

pub mod edwards;
pub mod montgomery;

/// These are the pre-computed parameters of the Jubjub
/// curve.
pub struct JubjubParams<E: Engine> {
    edwards_d: E::Fr,
    montgomery_a: E::Fr,

    scale: E::Fr
}

pub enum Unknown { }
pub enum PrimeOrder { }

impl JubjubParams<Bls12> {
    pub fn new() -> Self {
        JubjubParams {
            // d = -(10240/10241)
            edwards_d: Fr::from_str("19257038036680949359750312669786877991949435402254120286184196891950884077233").unwrap(),
            // A = 40962
            montgomery_a: Fr::from_str("40962").unwrap(),
            // scaling factor = sqrt(4 / (a - d))
            scale: Fr::from_str("17814886934372412843466061268024708274627479829237077604635722030778476050649").unwrap()
        }
    }
}

#[cfg(test)]
mod test {
    use pairing::{Field, SqrtField, LegendreSymbol, PrimeField};
    use pairing::bls12_381::{Fr};
    use super::JubjubParams;

    #[test]
    fn test_params() {
        let params = JubjubParams::new();

        // a = -1
        let mut a = Fr::one();
        a.negate();

        {
            // The twisted Edwards addition law is complete when d is nonsquare
            // and a is square.

            assert!(params.edwards_d.legendre() == LegendreSymbol::QuadraticNonResidue);
            assert!(a.legendre() == LegendreSymbol::QuadraticResidue);
        }

        {
            // Check that A^2 - 4 is nonsquare:
            let mut tmp = params.montgomery_a;
            tmp.square();
            tmp.sub_assign(&Fr::from_str("4").unwrap());
            assert!(tmp.legendre() == LegendreSymbol::QuadraticNonResidue);
        }

        {
            // Check that A - 2 is nonsquare:
            let mut tmp = params.montgomery_a;
            tmp.sub_assign(&Fr::from_str("2").unwrap());
            assert!(tmp.legendre() == LegendreSymbol::QuadraticNonResidue);
        }

        {
            // Check the validity of the scaling factor
            let mut tmp = a;
            tmp.sub_assign(&params.edwards_d);
            tmp = tmp.inverse().unwrap();
            tmp.mul_assign(&Fr::from_str("4").unwrap());
            tmp = tmp.sqrt().unwrap();
            assert_eq!(tmp, params.scale);
        }
    }
}
