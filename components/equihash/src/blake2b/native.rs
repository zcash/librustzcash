//! Solver-only BLAKE2b compression for independent block indices.
//!
//! Cache the common header and nonce, then compress four final blocks together.
//! The digest, counter, and rounds follow RFC 7693. Inputs whose index crosses a
//! block boundary use the ordinary `blake2b_simd` state instead.
//!
//! Reference: <https://www.rfc-editor.org/rfc/rfc7693#section-3.2>.
// Copyright (c) 2026 The Zakura developers
// Distributed under the MIT software license, see the accompanying COPYING.
#![allow(unsafe_code)]

use core::arch::x86_64::*;

use blake2b_simd::{BLOCKBYTES, OUTBYTES};

const INDEX_BYTES: usize = core::mem::size_of::<u32>();
const GENERAL_INDEX_WORD: usize = BLOCKBYTES / core::mem::size_of::<u64>();
const GENERAL_INDEX_SHIFT: u32 = u64::BITS;
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
const SIGMA: [[u8; 16]; 12] = [
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

pub(super) struct Context {
    words: [u64; 8],
    message: [u64; 16],
    count: u128,
    index_word: usize,
    index_shift: u32,
    hash_len: usize,
}

#[inline(always)]
fn g(v: &mut [u64; 16], a: usize, b: usize, c: usize, d: usize, x: u64, y: u64) {
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
    v[d] = (v[d] ^ v[a]).rotate_right(32);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(24);
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(63);
}

fn compress_prefix(words: &mut [u64; 8], block: &[u8], count: u128) {
    let m: [u64; 16] =
        std::array::from_fn(|i| u64::from_le_bytes(block[8 * i..8 * i + 8].try_into().unwrap()));
    let mut v = [0u64; 16];
    v[..8].copy_from_slice(words);
    v[8..].copy_from_slice(&IV);
    v[12] ^= count as u64;
    v[13] ^= (count >> 64) as u64;
    for s in SIGMA {
        let s = s.map(usize::from);
        g(&mut v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
        g(&mut v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
        g(&mut v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
        g(&mut v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
        g(&mut v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
        g(&mut v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
        g(&mut v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
        g(&mut v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
    }
    for i in 0..8 {
        words[i] ^= v[i] ^ v[i + 8];
    }
}

impl Context {
    pub(super) fn new(input: &[u8], nonce: &[u8], n: u32, k: u32, hash_len: usize) -> Option<Self> {
        // Rehashing a short shared prefix costs little compared to a solver run.
        // Keep arbitrary large caller inputs on the existing incremental path.
        const MAX_PREFIX_BYTES: usize = 16 * BLOCKBYTES;
        let prefix_len = input.len().checked_add(nonce.len())?;
        if !std::is_x86_feature_detected!("avx2")
            || prefix_len > MAX_PREFIX_BYTES
            || prefix_len % BLOCKBYTES > BLOCKBYTES - INDEX_BYTES
            || !(1..=OUTBYTES).contains(&hash_len)
        {
            return None;
        }
        let mut words = IV;
        words[0] ^= 0x0101_0000 | hash_len as u64;
        words[6] ^= u64::from_le_bytes(PERSONALIZATION_PREFIX);
        words[7] ^= n as u64 | ((k as u64) << 32);
        let mut count = 0u128;
        let mut block = [0u8; BLOCKBYTES];
        let mut filled = 0;
        for mut part in [input, nonce] {
            while !part.is_empty() {
                let take = part.len().min(BLOCKBYTES - filled);
                block[filled..filled + take].copy_from_slice(&part[..take]);
                filled += take;
                part = &part[take..];
                if filled == BLOCKBYTES {
                    count += BLOCKBYTES as u128;
                    compress_prefix(&mut words, &block, count);
                    block.fill(0);
                    filled = 0;
                }
            }
        }
        let message = std::array::from_fn(|i| {
            u64::from_le_bytes(block[8 * i..8 * i + 8].try_into().unwrap())
        });
        Some(Self {
            words,
            message,
            count: count + filled as u128 + INDEX_BYTES as u128,
            index_word: filled / 8,
            index_shift: (filled % 8 * 8) as u32,
            hash_len,
        })
    }

    pub(super) fn generate(&self, first: u32, output: &mut [u8]) {
        debug_assert_eq!(output.len() % self.hash_len, 0);
        // SAFETY: construction checks AVX2 support and the final block bounds.
        // Unaligned stores write to a local array of exactly the vector width.
        unsafe {
            // Fixed index-word positions avoid spilling the entire message
            // array when inserting each lane's index.
            match (self.index_word, self.index_shift) {
                (1, 32) => self.generate_avx2::<1, 32>(first, output),
                (13, 0) => self.generate_avx2::<13, 0>(first, output),
                (1, _) => self.generate_avx2::<1, GENERAL_INDEX_SHIFT>(first, output),
                (13, _) => self.generate_avx2::<13, GENERAL_INDEX_SHIFT>(first, output),
                _ => self.generate_avx2::<GENERAL_INDEX_WORD, GENERAL_INDEX_SHIFT>(first, output),
            }
        }
    }

    #[target_feature(enable = "avx2")]
    unsafe fn generate_avx2<const INDEX_WORD: usize, const INDEX_SHIFT: u32>(
        &self,
        first: u32,
        output: &mut [u8],
    ) {
        // GENERAL_INDEX_WORD selects arbitrary index placement at runtime.
        let index_word = if INDEX_WORD == GENERAL_INDEX_WORD {
            self.index_word
        } else {
            INDEX_WORD
        };
        let index_shift = if INDEX_SHIFT == GENERAL_INDEX_SHIFT {
            self.index_shift
        } else {
            INDEX_SHIFT
        };
        unsafe {
            let base_m: [__m256i; 16] = std::array::from_fn(|i| {
                // A twelve-byte final prefix and its four-byte index leave
                // every later message word zero, regardless of the header.
                if INDEX_WORD == 1 && INDEX_SHIFT == 32 && i > INDEX_WORD {
                    _mm256_setzero_si256()
                } else {
                    _mm256_set1_epi64x(self.message[i] as i64)
                }
            });
            let h: [__m256i; 8] = std::array::from_fn(|i| _mm256_set1_epi64x(self.words[i] as i64));
            for (batch, output) in output.chunks_mut(4 * self.hash_len).enumerate() {
                let start = first.wrapping_add((batch * 4) as u32);
                let index = _mm256_setr_epi64x(
                    start as i64,
                    start.wrapping_add(1) as i64,
                    start.wrapping_add(2) as i64,
                    start.wrapping_add(3) as i64,
                );
                let mut m = base_m;
                m[index_word] = _mm256_or_si256(
                    m[index_word],
                    _mm256_sll_epi64(index, _mm_cvtsi64_si128(index_shift as i64)),
                );
                if index_shift > 32 {
                    m[index_word + 1] = _mm256_or_si256(
                        m[index_word + 1],
                        _mm256_srl_epi64(index, _mm_cvtsi64_si128((64 - index_shift) as i64)),
                    );
                }
                let mut v = [_mm256_setzero_si256(); 16];
                v[..8].copy_from_slice(&h);
                for i in 0..8 {
                    v[8 + i] = _mm256_set1_epi64x(IV[i] as i64);
                }
                v[12] = _mm256_xor_si256(v[12], _mm256_set1_epi64x(self.count as i64));
                v[13] = _mm256_xor_si256(v[13], _mm256_set1_epi64x((self.count >> 64) as i64));
                v[14] = _mm256_xor_si256(v[14], _mm256_set1_epi64x(-1));
                round4(&mut v, &m, &SIGMA[0]);
                round4(&mut v, &m, &SIGMA[1]);
                round4(&mut v, &m, &SIGMA[2]);
                round4(&mut v, &m, &SIGMA[3]);
                round4(&mut v, &m, &SIGMA[4]);
                round4(&mut v, &m, &SIGMA[5]);
                round4(&mut v, &m, &SIGMA[6]);
                round4(&mut v, &m, &SIGMA[7]);
                round4(&mut v, &m, &SIGMA[8]);
                round4(&mut v, &m, &SIGMA[9]);
                round4(&mut v, &m, &SIGMA[10]);
                round4(&mut v, &m, &SIGMA[11]);
                let hashes: [__m256i; 8] = std::array::from_fn(|i| {
                    _mm256_xor_si256(h[i], _mm256_xor_si256(v[i], v[i + 8]))
                });
                for (word, hash) in hashes.iter().enumerate().take(self.hash_len.div_ceil(8)) {
                    let mut lanes = [0u64; 4];
                    _mm256_storeu_si256(lanes.as_mut_ptr().cast(), *hash);
                    for (lane, out) in output.chunks_exact_mut(self.hash_len).enumerate() {
                        let start = word * 8;
                        let end = (start + 8).min(self.hash_len);
                        out[start..end].copy_from_slice(&lanes[lane].to_le_bytes()[..end - start]);
                    }
                }
            }
        }
    }
}

#[inline(always)]
unsafe fn vg(
    v: &mut [__m256i; 16],
    a: usize,
    b: usize,
    c: usize,
    d: usize,
    x: __m256i,
    y: __m256i,
) {
    unsafe {
        let mut va = v[a];
        let mut vb = v[b];
        let mut vc = v[c];
        let mut vd = v[d];
        va = _mm256_add_epi64(_mm256_add_epi64(va, vb), x);
        vd = _mm256_shuffle_epi32::<0xb1>(_mm256_xor_si256(vd, va));
        vc = _mm256_add_epi64(vc, vd);
        vb = _mm256_shuffle_epi8(
            _mm256_xor_si256(vb, vc),
            _mm256_setr_epi8(
                3, 4, 5, 6, 7, 0, 1, 2, 11, 12, 13, 14, 15, 8, 9, 10, 3, 4, 5, 6, 7, 0, 1, 2, 11,
                12, 13, 14, 15, 8, 9, 10,
            ),
        );
        va = _mm256_add_epi64(_mm256_add_epi64(va, vb), y);
        vd = _mm256_shuffle_epi8(
            _mm256_xor_si256(vd, va),
            _mm256_setr_epi8(
                2, 3, 4, 5, 6, 7, 0, 1, 10, 11, 12, 13, 14, 15, 8, 9, 2, 3, 4, 5, 6, 7, 0, 1, 10,
                11, 12, 13, 14, 15, 8, 9,
            ),
        );
        vc = _mm256_add_epi64(vc, vd);
        vb = _mm256_xor_si256(vb, vc);
        vb = _mm256_or_si256(_mm256_add_epi64(vb, vb), _mm256_srli_epi64::<63>(vb));
        v[a] = va;
        v[b] = vb;
        v[c] = vc;
        v[d] = vd;
    }
}

#[inline(always)]
unsafe fn round4(v: &mut [__m256i; 16], m: &[__m256i; 16], s: &[u8; 16]) {
    unsafe {
        let s = s.map(usize::from);
        vg(v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
        vg(v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
        vg(v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
        vg(v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
        vg(v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
        vg(v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
        vg(v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
        vg(v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_batches_match_reference() {
        if !std::is_x86_feature_detected!("avx2") {
            return;
        }
        let n = 200u32;
        let k = 9u32;
        for len in 0..=384 {
            let prefix: std::vec::Vec<u8> = (0..len).map(|i| (i * 197) as u8).collect();
            for hash_len in [1, 32, 50, 64] {
                let Some(ctx) =
                    Context::new(&prefix[..len / 2], &prefix[len / 2..], n, k, hash_len)
                else {
                    continue;
                };
                let mut personal = [0u8; 16];
                personal[..8].copy_from_slice(&PERSONALIZATION_PREFIX);
                personal[8..12].copy_from_slice(&n.to_le_bytes());
                personal[12..].copy_from_slice(&k.to_le_bytes());
                let mut state = blake2b_simd::Params::new()
                    .hash_length(hash_len)
                    .personal(&personal)
                    .to_state();
                state.update(&prefix);
                for (first, count) in [
                    (0, 1),
                    (3, 2),
                    (17, 3),
                    (100, 4),
                    (65534, 7),
                    (123456, 8),
                    (200000, 9),
                    (1048512, 64),
                    (u32::MAX - 3, 4),
                ] {
                    let mut out = std::vec![0u8; count * hash_len];
                    ctx.generate(first, &mut out);
                    let mut general = std::vec![0u8; count * hash_len];
                    // SAFETY: the test's feature check establishes AVX2 support.
                    unsafe {
                        ctx.generate_avx2::<GENERAL_INDEX_WORD, GENERAL_INDEX_SHIFT>(
                            first,
                            &mut general,
                        );
                    }
                    assert_eq!(out, general);
                    // Exercise each specialized AVX2 layout selected by the
                    // automatic dispatch.
                    let mut specialized = std::vec![0u8; count * hash_len];
                    // SAFETY: the test's feature check establishes AVX2 support;
                    // each selected index word matches the constructed context.
                    unsafe {
                        match (ctx.index_word, ctx.index_shift) {
                            (1, 32) => ctx.generate_avx2::<1, 32>(first, &mut specialized),
                            (13, 0) => ctx.generate_avx2::<13, 0>(first, &mut specialized),
                            (1, _) => {
                                ctx.generate_avx2::<1, GENERAL_INDEX_SHIFT>(first, &mut specialized)
                            }
                            (13, _) => ctx
                                .generate_avx2::<13, GENERAL_INDEX_SHIFT>(first, &mut specialized),
                            _ => ctx.generate_avx2::<GENERAL_INDEX_WORD, GENERAL_INDEX_SHIFT>(
                                first,
                                &mut specialized,
                            ),
                        }
                    }
                    assert_eq!(out, specialized);
                    for (offset, chunk) in out.chunks_exact(hash_len).enumerate() {
                        let mut expected = state.clone();
                        expected.update(&(first + offset as u32).to_le_bytes());
                        assert_eq!(
                            chunk,
                            expected.finalize().as_bytes(),
                            "len={len},hash_len={hash_len},first={first},offset={offset}"
                        );
                    }
                }
            }
        }
    }
}
