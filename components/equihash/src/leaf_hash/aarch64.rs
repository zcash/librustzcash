//! NEON leaf-hash lanes.
//!
//! Each type carries two vectors of two lanes, so independent instructions
//! cover NEON latency. The SHA3 extension's `XAR` fuses each XOR and rotation.
#![allow(unsafe_code)]

use core::arch::aarch64::*;

use super::{Digest, Lanes, MAX_LANES, Midstate};

pub(super) fn has_sha3() -> bool {
    #[cfg(feature = "std")]
    {
        std::arch::is_aarch64_feature_detected!("sha3")
    }
    #[cfg(not(feature = "std"))]
    {
        cfg!(target_feature = "sha3")
    }
}

const ROTR24: [u8; 16] = [3, 4, 5, 6, 7, 0, 1, 2, 11, 12, 13, 14, 15, 8, 9, 10];
const ROTR16: [u8; 16] = [2, 3, 4, 5, 6, 7, 0, 1, 10, 11, 12, 13, 14, 15, 8, 9];

macro_rules! neon_lanes {
    (
        $name:ident, |$x:ident, $y:ident|
        rotr32: $rotr32:expr, rotr24: $rotr24:expr, rotr16: $rotr16:expr, rotr63: $rotr63:expr $(,)?
    ) => {
        #[derive(Clone, Copy)]
        struct $name([uint64x2_t; 2]);

        impl Lanes for $name {
            const LANES: usize = 4;

            #[inline(always)]
            unsafe fn splat(x: u64) -> Self {
                unsafe { Self([vdupq_n_u64(x); 2]) }
            }
            #[inline(always)]
            unsafe fn load(words: &[u64; MAX_LANES]) -> Self {
                unsafe { Self([vld1q_u64(words.as_ptr()), vld1q_u64(words[2..].as_ptr())]) }
            }
            #[inline(always)]
            unsafe fn store(self, words: &mut [u64; MAX_LANES]) {
                unsafe {
                    vst1q_u64(words.as_mut_ptr(), self.0[0]);
                    vst1q_u64(words[2..].as_mut_ptr(), self.0[1]);
                }
            }
            #[inline(always)]
            unsafe fn add(self, other: Self) -> Self {
                unsafe {
                    Self([
                        vaddq_u64(self.0[0], other.0[0]),
                        vaddq_u64(self.0[1], other.0[1]),
                    ])
                }
            }
            #[inline(always)]
            unsafe fn xor(self, other: Self) -> Self {
                unsafe {
                    Self([
                        veorq_u64(self.0[0], other.0[0]),
                        veorq_u64(self.0[1], other.0[1]),
                    ])
                }
            }
            #[inline(always)]
            unsafe fn xor_rotr32(self, other: Self) -> Self {
                unsafe {
                    Self([
                        {
                            let ($x, $y) = (self.0[0], other.0[0]);
                            $rotr32
                        },
                        {
                            let ($x, $y) = (self.0[1], other.0[1]);
                            $rotr32
                        },
                    ])
                }
            }
            #[inline(always)]
            unsafe fn xor_rotr24(self, other: Self) -> Self {
                unsafe {
                    Self([
                        {
                            let ($x, $y) = (self.0[0], other.0[0]);
                            $rotr24
                        },
                        {
                            let ($x, $y) = (self.0[1], other.0[1]);
                            $rotr24
                        },
                    ])
                }
            }
            #[inline(always)]
            unsafe fn xor_rotr16(self, other: Self) -> Self {
                unsafe {
                    Self([
                        {
                            let ($x, $y) = (self.0[0], other.0[0]);
                            $rotr16
                        },
                        {
                            let ($x, $y) = (self.0[1], other.0[1]);
                            $rotr16
                        },
                    ])
                }
            }
            #[inline(always)]
            unsafe fn xor_rotr63(self, other: Self) -> Self {
                unsafe {
                    Self([
                        {
                            let ($x, $y) = (self.0[0], other.0[0]);
                            $rotr63
                        },
                        {
                            let ($x, $y) = (self.0[1], other.0[1]);
                            $rotr63
                        },
                    ])
                }
            }
        }
    };
}

neon_lanes!(
    NeonLanes, |a, b|
    rotr32: {
        let x = veorq_u64(a, b);
        vreinterpretq_u64_u32(vrev64q_u32(vreinterpretq_u32_u64(x)))
    },
    rotr24: {
        let x = vreinterpretq_u8_u64(veorq_u64(a, b));
        vreinterpretq_u64_u8(vqtbl1q_u8(x, vld1q_u8(ROTR24.as_ptr())))
    },
    rotr16: {
        let x = vreinterpretq_u8_u64(veorq_u64(a, b));
        vreinterpretq_u64_u8(vqtbl1q_u8(x, vld1q_u8(ROTR16.as_ptr())))
    },
    rotr63: {
        let x = veorq_u64(a, b);
        vsriq_n_u64::<63>(vaddq_u64(x, x), x)
    },
);

neon_lanes!(
    NeonSha3Lanes, |a, b|
    rotr32: vxarq_u64::<32>(a, b),
    rotr24: vxarq_u64::<24>(a, b),
    rotr16: vxarq_u64::<16>(a, b),
    rotr63: vxarq_u64::<63>(a, b),
);

/// # Safety
///
/// `blocks` and `out` must hold four entries.
#[target_feature(enable = "neon")]
pub(super) unsafe fn compress_neon(midstate: &Midstate, blocks: &[u32], out: &mut [Digest]) {
    unsafe { midstate.compress::<NeonLanes>(blocks, out) }
}

/// # Safety
///
/// The CPU must support the SHA3 extension, and `blocks` and `out` must hold
/// four entries.
#[target_feature(enable = "neon,sha3")]
pub(super) unsafe fn compress_neon_sha3(midstate: &Midstate, blocks: &[u32], out: &mut [Digest]) {
    unsafe { midstate.compress::<NeonSha3Lanes>(blocks, out) }
}
