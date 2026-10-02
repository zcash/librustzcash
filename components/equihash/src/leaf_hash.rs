//! Scalar BLAKE2b leaf hashing for Equihash verification.
//!
//! Every leaf of an Equihash solution hashes the same personalized
//! `input || nonce` prefix followed by a little-endian block index. For the
//! Zcash block-header layout (a 108-byte header and a 32-byte nonce), the
//! final BLAKE2b block holds only the last 12 prefix bytes and the index, so
//! message words 2 through 15 are zero. This module caches the prefix
//! midstate and compresses final blocks with those zero words folded away.
//!
//! Reference: <https://www.rfc-editor.org/rfc/rfc7693#section-3.2>.

use blake2b_simd::BLOCKBYTES;

use crate::params::Params;

/// A BLAKE2b digest of up to 64 bytes. Bytes past the digest length are zero.
pub(crate) type Digest = [u8; 64];

const PERSONALIZATION_PREFIX: [u8; 8] = *b"ZcashPoW";

const IV: [u64; 8] = [
    0x6A09E667F3BCC908,
    0xBB67AE8584CAA73B,
    0x3C6EF372FE94F82B,
    0xA54FF53A5F1D36F1,
    0x510E527FADE682D1,
    0x9B05688C2B3E6C1F,
    0x1F83D9ABFB41BD6B,
    0x5BE0CD19137E2179,
];

const SIGMA: [[usize; 16]; 12] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
];

/// Length of a Zcash block header without its nonce and solution.
pub(crate) const HEADER_BYTES: usize = 108;

/// Length of a Zcash block header nonce.
pub(crate) const NONCE_BYTES: usize = 32;

/// Prefix bytes left in the final block for the Zcash header layout.
const TAIL_BYTES: usize = (HEADER_BYTES + NONCE_BYTES) % BLOCKBYTES;

/// The only lane count supported by the scalar backend.
const MAX_LANES: usize = 1;

/// Independent BLAKE2b state words, one per lane.
trait Lanes: Copy {
    const LANES: usize;

    fn splat(x: u64) -> Self;
    fn load(words: &[u64; MAX_LANES]) -> Self;
    fn store(self, words: &mut [u64; MAX_LANES]);
    fn add(self, other: Self) -> Self;
    fn xor(self, other: Self) -> Self;
    /// Returns `(self ^ other).rotate_right(32)`, and similarly below.
    fn xor_rotr32(self, other: Self) -> Self;
    fn xor_rotr24(self, other: Self) -> Self;
    fn xor_rotr16(self, other: Self) -> Self;
    fn xor_rotr63(self, other: Self) -> Self;
}

impl Lanes for u64 {
    const LANES: usize = 1;

    #[inline(always)]
    fn splat(x: u64) -> Self {
        x
    }

    #[inline(always)]
    fn load(words: &[u64; MAX_LANES]) -> Self {
        words[0]
    }

    #[inline(always)]
    fn store(self, words: &mut [u64; MAX_LANES]) {
        words[0] = self;
    }

    #[inline(always)]
    fn add(self, other: Self) -> Self {
        self.wrapping_add(other)
    }

    #[inline(always)]
    fn xor(self, other: Self) -> Self {
        self ^ other
    }

    #[inline(always)]
    fn xor_rotr32(self, other: Self) -> Self {
        (self ^ other).rotate_right(32)
    }

    #[inline(always)]
    fn xor_rotr24(self, other: Self) -> Self {
        (self ^ other).rotate_right(24)
    }

    #[inline(always)]
    fn xor_rotr16(self, other: Self) -> Self {
        (self ^ other).rotate_right(16)
    }

    #[inline(always)]
    fn xor_rotr63(self, other: Self) -> Self {
        (self ^ other).rotate_right(63)
    }
}

#[inline(always)]
fn g<L: Lanes>(v: &mut [L; 16], a: usize, b: usize, c: usize, d: usize, x: L, y: L) {
    v[a] = v[a].add(v[b]).add(x);
    v[d] = v[d].xor_rotr32(v[a]);
    v[c] = v[c].add(v[d]);
    v[b] = v[b].xor_rotr24(v[c]);
    v[a] = v[a].add(v[b]).add(y);
    v[d] = v[d].xor_rotr16(v[a]);
    v[c] = v[c].add(v[d]);
    v[b] = v[b].xor_rotr63(v[c]);
}

// Expands each round with constant message-word selections, so words known to
// be zero fold away in the final-block kernel.
macro_rules! rounds {
    ($v:ident, $word:ident; $($r:literal)*) => {$({
        const S: [usize; 16] = SIGMA[$r];
        g(&mut $v, 0, 4, 8, 12, $word(S[0]), $word(S[1]));
        g(&mut $v, 1, 5, 9, 13, $word(S[2]), $word(S[3]));
        g(&mut $v, 2, 6, 10, 14, $word(S[4]), $word(S[5]));
        g(&mut $v, 3, 7, 11, 15, $word(S[6]), $word(S[7]));
        g(&mut $v, 0, 5, 10, 15, $word(S[8]), $word(S[9]));
        g(&mut $v, 1, 6, 11, 12, $word(S[10]), $word(S[11]));
        g(&mut $v, 2, 7, 8, 13, $word(S[12]), $word(S[13]));
        g(&mut $v, 3, 4, 9, 14, $word(S[14]), $word(S[15]));
    })*};
}

/// Compresses one non-final prefix block into `h`.
fn compress_prefix_block(h: &mut [u64; 8], block: &[u8; BLOCKBYTES], count: u64) {
    let m: [u64; 16] =
        core::array::from_fn(|i| u64::from_le_bytes(block[8 * i..8 * i + 8].try_into().unwrap()));
    let word = |i: usize| m[i];
    let mut v = [0u64; 16];
    v[..8].copy_from_slice(h);
    v[8..].copy_from_slice(&IV);
    v[12] ^= count;
    rounds!(v, word; 0 1 2 3 4 5 6 7 8 9 10 11);
    for i in 0..8 {
        h[i] ^= v[i] ^ v[i + 8];
    }
}

/// The prefix state shared by every leaf of one solution.
#[derive(Clone, Copy)]
struct Midstate {
    h: [u64; 8],
    /// Message word 0 of the final block: prefix tail bytes 0..8.
    m0: u64,
    /// Message word 1 before inserting the index: prefix tail bytes 8..12.
    m1_low: u64,
    /// Total hashed bytes, including the index.
    count: u64,
}

impl Midstate {
    /// Returns `None` unless `input || nonce` has the length of a Zcash
    /// header and nonce, which leaves [`TAIL_BYTES`] in the final block and
    /// places the index in the high half of message word 1.
    fn new(p: &Params, input: &[u8], nonce: &[u8]) -> Option<Self> {
        if input.len().checked_add(nonce.len())? != HEADER_BYTES + NONCE_BYTES {
            return None;
        }
        let count = (HEADER_BYTES + NONCE_BYTES + 4) as u64;

        let mut h = IV;
        h[0] ^= 0x0101_0000 | u64::from(p.hash_output());
        h[6] ^= u64::from_le_bytes(PERSONALIZATION_PREFIX);
        h[7] ^= u64::from(p.n) | (u64::from(p.k) << 32);

        let mut block = [0u8; BLOCKBYTES];
        let mut filled = 0;
        let mut compressed = 0u64;
        for mut part in [input, nonce] {
            while !part.is_empty() {
                // Keep the tail in `block`: BLAKE2b compresses a block as
                // non-final only once more input follows it.
                if filled == BLOCKBYTES {
                    compressed += BLOCKBYTES as u64;
                    compress_prefix_block(&mut h, &block, compressed);
                    filled = 0;
                }
                let take = part.len().min(BLOCKBYTES - filled);
                block[filled..filled + take].copy_from_slice(&part[..take]);
                filled += take;
                part = &part[take..];
            }
        }
        debug_assert_eq!(filled, TAIL_BYTES);

        Some(Self {
            h,
            m0: u64::from_le_bytes(block[..8].try_into().unwrap()),
            m1_low: u64::from(u32::from_le_bytes(block[8..12].try_into().unwrap())),
            count,
        })
    }

    /// Hashes `L::LANES` block indices. `blocks` and `out` must each hold
    /// exactly that many entries.
    #[inline(always)]
    fn compress<L: Lanes>(&self, blocks: &[u32], out: &mut [Digest]) {
        debug_assert_eq!(blocks.len(), L::LANES);
        debug_assert_eq!(out.len(), L::LANES);
        let mut words = [0u64; MAX_LANES];
        for (word, block) in words.iter_mut().zip(blocks) {
            *word = self.m1_low | (u64::from(*block) << 32);
        }
        let zero = L::splat(0);
        let m0 = L::splat(self.m0);
        let m1 = L::load(&words);
        let word = |i: usize| match i {
            0 => m0,
            1 => m1,
            _ => zero,
        };

        let mut v = [zero; 16];
        for i in 0..8 {
            v[i] = L::splat(self.h[i]);
            v[8 + i] = L::splat(IV[i]);
        }
        v[12] = L::splat(IV[4] ^ self.count);
        // Final-block flag.
        v[14] = L::splat(!IV[6]);
        rounds!(v, word; 0 1 2 3 4 5 6 7 8 9 10 11);

        for i in 0..8 {
            L::splat(self.h[i])
                .xor(v[i].xor(v[i + 8]))
                .store(&mut words);
            for (digest, word) in out.iter_mut().zip(&words) {
                digest[8 * i..8 * i + 8].copy_from_slice(&word.to_le_bytes());
            }
        }
    }

    fn compress_portable(&self, blocks: &[u32], out: &mut [Digest]) {
        for (block, digest) in blocks.iter().zip(out) {
            self.compress::<u64>(core::slice::from_ref(block), core::slice::from_mut(digest));
        }
    }
}

/// A leaf-hashing backend.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kernel {
    Portable,
}

impl Kernel {
    /// Every kernel supported by this implementation.
    pub(crate) fn supported() -> impl Iterator<Item = Kernel> {
        [Kernel::Portable].into_iter()
    }

    fn detect() -> Self {
        Self::supported().next().unwrap_or(Kernel::Portable)
    }

    fn lanes(self) -> usize {
        match self {
            Kernel::Portable => 1,
        }
    }
}

/// Hashes Equihash block indices under one Zcash `header || nonce` prefix.
pub(crate) struct LeafHasher {
    midstate: Midstate,
    kernel: Kernel,
    hash_len: usize,
}

impl LeafHasher {
    /// Returns `None` unless `input || nonce` is a Zcash header and nonce.
    pub(crate) fn new(p: &Params, input: &[u8], nonce: &[u8]) -> Option<Self> {
        Self::with_kernel(p, input, nonce, Kernel::detect())
    }

    /// Uses `kernel`, if the prefix has the required length.
    pub(crate) fn with_kernel(
        p: &Params,
        input: &[u8],
        nonce: &[u8],
        kernel: Kernel,
    ) -> Option<Self> {
        if !Kernel::supported().any(|supported| supported == kernel) {
            return None;
        }
        Some(Self {
            midstate: Midstate::new(p, input, nonce)?,
            kernel,
            hash_len: usize::from(p.hash_output()),
        })
    }

    /// Writes the digest of each block index in `blocks` to the matching
    /// entry of `out`.
    pub(crate) fn hash(&self, blocks: &[u32], out: &mut [Digest]) {
        assert_eq!(blocks.len(), out.len());
        let lanes = self.kernel.lanes();
        for (blocks, out) in blocks.chunks_exact(lanes).zip(out.chunks_exact_mut(lanes)) {
            match self.kernel {
                Kernel::Portable => self.midstate.compress_portable(blocks, out),
            }
        }
        // The kernel writes all eight state words; keep the documented zero
        // bytes past the digest length.
        for digest in out {
            digest[self.hash_len..].fill(0);
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use super::{Digest, HEADER_BYTES, Kernel, LeafHasher, NONCE_BYTES};
    use crate::{params::Params, verify::initialise_state};

    fn reference(p: &Params, input: &[u8], nonce: &[u8], block: u32) -> Digest {
        let mut state = initialise_state(p.n, p.k, p.hash_output());
        state.update(input);
        state.update(nonce);
        state.update(&block.to_le_bytes());
        let mut digest = [0; 64];
        let hash = state.finalize();
        digest[..hash.as_bytes().len()].copy_from_slice(hash.as_bytes());
        digest
    }

    #[test]
    fn kernels_match_blake2b_simd() {
        let blocks: Vec<u32> = (0..67u32)
            .map(|i| i.wrapping_mul(0x9e37_79b9))
            .chain([0, 1, u32::MAX, u32::MAX - 1])
            .collect();
        let prefix: Vec<u8> = (0..HEADER_BYTES + NONCE_BYTES)
            .map(|i| (i * 31 + 7) as u8)
            .collect();
        // Zcash mainnet and regtest, plus other valid parameters accepted by
        // this crate.
        for (n, k) in [(200, 9), (48, 5), (96, 5), (144, 5), (96, 3)] {
            let p = Params::new(n, k).unwrap();
            // Only the combined prefix length is fixed.
            for split in [HEADER_BYTES, 0, 128, HEADER_BYTES + NONCE_BYTES] {
                let (input, nonce) = prefix.split_at(split);
                for kernel in Kernel::supported() {
                    let hasher = LeafHasher::with_kernel(&p, input, nonce, kernel).unwrap();
                    let mut out = vec![[0xa5; 64]; blocks.len()];
                    hasher.hash(&blocks, &mut out);
                    for (block, digest) in blocks.iter().zip(&out) {
                        assert_eq!(
                            digest[..],
                            reference(&p, input, nonce, *block)[..],
                            "{kernel:?} ({n}, {k}) split {split} block {block}",
                        );
                    }
                }
            }
        }
    }

    /// Compares every kernel with `blake2b_simd` on every block index a
    /// Zcash solution can reach: indices have `collision_bit_length + 1`
    /// bits, and each block covers `indices_per_hash_output` of them.
    #[test]
    #[ignore = "exhaustive; about 2^20 hashes per kernel"]
    fn kernels_match_blake2b_simd_on_every_reachable_block() {
        let prefix: Vec<u8> = (0..HEADER_BYTES + NONCE_BYTES)
            .map(|i| (i * 131 + 89) as u8)
            .collect();
        let (input, nonce) = prefix.split_at(HEADER_BYTES);
        for (n, k) in [(200, 9), (48, 5)] {
            let p = Params::new(n, k).unwrap();
            let max_index = (1u32 << (p.collision_bit_length() + 1)) - 1;
            let blocks: Vec<u32> = (0..=max_index / p.indices_per_hash_output()).collect();
            let expected: Vec<Digest> = blocks
                .iter()
                .map(|block| reference(&p, input, nonce, *block))
                .collect();
            for kernel in Kernel::supported() {
                let hasher = LeafHasher::with_kernel(&p, input, nonce, kernel).unwrap();
                let mut out = vec![[0; 64]; blocks.len()];
                hasher.hash(&blocks, &mut out);
                for (block, (digest, expected)) in out.iter().zip(&expected).enumerate() {
                    assert_eq!(
                        digest[..],
                        expected[..],
                        "{kernel:?} ({n}, {k}) block {block}"
                    );
                }
            }
        }
    }

    #[test]
    fn rejects_other_prefix_lengths() {
        let p = Params::new(200, 9).unwrap();
        for len in [0, 12, 107, 139, 141, 268] {
            assert!(LeafHasher::new(&p, &vec![0; len], &[]).is_none(), "{len}");
        }
        assert!(LeafHasher::new(&p, &[0; HEADER_BYTES], &[0; NONCE_BYTES]).is_some());
    }
}
