//! AVX2 leaf-hash lanes.
//!
//! Verification deliberately has no AVX-512 kernel, so it never risks the
//! frequency drop that 512-bit instructions cause on some x86 CPUs.
#![allow(unsafe_code)]

use core::arch::x86_64::*;

use super::{Digest, Lanes, MAX_LANES, Midstate};

pub(super) fn has_avx2() -> bool {
    #[cfg(feature = "std")]
    {
        std::is_x86_feature_detected!("avx2")
    }
    #[cfg(not(feature = "std"))]
    {
        cfg!(target_feature = "avx2")
    }
}

impl Lanes for __m256i {
    const LANES: usize = 4;

    #[inline(always)]
    unsafe fn splat(x: u64) -> Self {
        unsafe { _mm256_set1_epi64x(x as i64) }
    }
    #[inline(always)]
    unsafe fn load(words: &[u64; MAX_LANES]) -> Self {
        unsafe { _mm256_loadu_si256(words.as_ptr().cast()) }
    }
    #[inline(always)]
    unsafe fn store(self, words: &mut [u64; MAX_LANES]) {
        unsafe { _mm256_storeu_si256(words.as_mut_ptr().cast(), self) }
    }
    #[inline(always)]
    unsafe fn add(self, other: Self) -> Self {
        unsafe { _mm256_add_epi64(self, other) }
    }
    #[inline(always)]
    unsafe fn xor(self, other: Self) -> Self {
        unsafe { _mm256_xor_si256(self, other) }
    }
    #[inline(always)]
    unsafe fn xor_rotr32(self, other: Self) -> Self {
        unsafe { _mm256_shuffle_epi32::<0b10_11_00_01>(self.xor(other)) }
    }
    #[inline(always)]
    unsafe fn xor_rotr24(self, other: Self) -> Self {
        unsafe {
            let bytes = _mm256_setr_epi8(
                3, 4, 5, 6, 7, 0, 1, 2, 11, 12, 13, 14, 15, 8, 9, 10, 3, 4, 5, 6, 7, 0, 1, 2, 11,
                12, 13, 14, 15, 8, 9, 10,
            );
            _mm256_shuffle_epi8(self.xor(other), bytes)
        }
    }
    #[inline(always)]
    unsafe fn xor_rotr16(self, other: Self) -> Self {
        unsafe {
            let bytes = _mm256_setr_epi8(
                2, 3, 4, 5, 6, 7, 0, 1, 10, 11, 12, 13, 14, 15, 8, 9, 2, 3, 4, 5, 6, 7, 0, 1, 10,
                11, 12, 13, 14, 15, 8, 9,
            );
            _mm256_shuffle_epi8(self.xor(other), bytes)
        }
    }
    #[inline(always)]
    unsafe fn xor_rotr63(self, other: Self) -> Self {
        unsafe {
            let x = self.xor(other);
            _mm256_or_si256(_mm256_srli_epi64::<63>(x), _mm256_add_epi64(x, x))
        }
    }
}

/// # Safety
///
/// The CPU must support AVX2, and `blocks` and `out` must hold four entries.
#[target_feature(enable = "avx2")]
pub(super) unsafe fn compress_avx2(midstate: &Midstate, blocks: &[u32], out: &mut [Digest]) {
    unsafe { midstate.compress::<__m256i>(blocks, out) }
}
