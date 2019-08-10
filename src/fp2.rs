//! This module implements arithmetic over the quadratic extension field Fp2.

use crate::fp::Fp;

#[derive(Copy, Clone, Debug)]
pub struct Fp2 {
    pub c0: Fp,
    pub c1: Fp,
}
