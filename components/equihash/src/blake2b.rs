// Copyright (c) 2020-2022 The Zcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

// BLAKE2b batches used by the Rust Tromp solver.

use blake2b_simd::State;

use crate::params::Params;

/// Owns the reference state used to generate solver hash batches.
pub(super) struct SolverHashState {
    reference: State,
    hash_len: usize,
}

impl SolverHashState {
    /// The owned state must already include `input` and `nonce` with `params`.
    pub(super) fn new(reference: State, input: &[u8], nonce: &[u8], params: Params) -> Self {
        let _ = (input, nonce);
        Self {
            reference,
            hash_len: params.hash_output() as usize,
        }
    }

    /// Tries to generate complete eight-lane batches of digest words.
    ///
    /// The native word-oriented backend is not included in the safe solver, so
    /// this always returns `false` without modifying `output`. `WORDS` must
    /// match the configured digest length rounded to whole words. The last
    /// block index must fit in [`u32`].
    pub(super) fn try_generate_words<const WORDS: usize>(
        &self,
        first_index: u32,
        output: &mut [[[u64; 8]; WORDS]],
    ) -> bool {
        const LANES: usize = 8;
        const WORD_BYTES: usize = core::mem::size_of::<u64>();
        assert_eq!(WORDS, self.hash_len.div_ceil(WORD_BYTES));
        let count = output.len().checked_mul(LANES).unwrap();
        assert!(
            count == 0
                || first_index
                    .checked_add(u32::try_from(count - 1).unwrap())
                    .is_some()
        );
        false
    }

    /// Generates consecutive block hashes without modifying the cached state.
    ///
    /// `output` must hold a whole number of digests. The last block index must
    /// fit in [`u32`].
    pub(super) fn generate(&self, first_index: u32, output: &mut [u8]) {
        assert_eq!(output.len() % self.hash_len, 0);
        let count = output.len() / self.hash_len;
        assert!(
            count == 0
                || first_index
                    .checked_add(u32::try_from(count - 1).unwrap())
                    .is_some()
        );
        for (offset, output) in output.chunks_exact_mut(self.hash_len).enumerate() {
            let mut hash_state = self.reference.clone();
            hash_state.update(&(first_index + offset as u32).to_le_bytes());
            output.copy_from_slice(hash_state.finalize().as_bytes());
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use super::SolverHashState;
    use crate::{params::Params, verify::initialise_state};

    const PARAMS: Params = Params { n: 200, k: 9 };

    #[test]
    fn generated_hashes_match_reference() {
        let hash_len = PARAMS.hash_output();
        let mut state = initialise_state(PARAMS.n, PARAMS.k, hash_len);
        let header: Vec<_> = (0..108).map(|i| i as u8).collect();
        state.update(&header);
        state.update(&[0x5a; 32]);
        let original_digest = state.finalize();
        let states = [
            SolverHashState {
                reference: state.clone(),
                hash_len: hash_len as usize,
            },
            SolverHashState::new(state, &header, &[0x5a; 32], PARAMS),
        ];

        // Include a batch spanning more than one solver buffer and an empty
        // batch. Guard bytes check that the method respects the buffer size.
        for state in states {
            for (first_index, count, expected) in REFERENCE_BATCHES {
                let mut output = vec![0xa5; count as usize * hash_len as usize + 2];
                let end = output.len() - 1;
                state.generate(first_index, &mut output[1..end]);
                assert_eq!(output[0], 0xa5);
                assert_eq!(*output.last().unwrap(), 0xa5);
                assert_eq!(state.reference.finalize(), original_digest);
                assert_eq!(
                    hex::encode(blake2b_simd::blake2b(&output[1..output.len() - 1]).as_bytes()),
                    expected,
                );
            }
        }
    }

    #[test]
    fn boundary_prefixes_match_reference() {
        let params = PARAMS;
        for prefix_len in [124, 125, 126, 127, 128, 2048, 2049] {
            let prefix: Vec<_> = (0..prefix_len).map(|i| (i * 197) as u8).collect();
            let split = prefix_len / 2;
            let mut reference = initialise_state(params.n, params.k, params.hash_output());
            reference.update(&prefix);
            let state = SolverHashState::new(
                reference.clone(),
                &prefix[..split],
                &prefix[split..],
                params,
            );
            let mut output = vec![0; 7 * params.hash_output() as usize];
            state.generate(65534, &mut output);
            for (offset, digest) in output
                .chunks_exact(params.hash_output() as usize)
                .enumerate()
            {
                let mut expected = reference.clone();
                expected.update(&(65534 + offset as u32).to_le_bytes());
                assert_eq!(digest, expected.finalize().as_bytes());
            }
        }
    }

    #[test]
    fn word_batches_use_reference_fallback_and_preserve_guards() {
        const LANES: usize = 8;
        const WORD_BYTES: usize = core::mem::size_of::<u64>();
        const HASH_BITS: usize = blake2b_simd::OUTBYTES * u8::BITS as usize;
        const WORDS: usize = (HASH_BITS / PARAMS.n as usize * PARAMS.n as usize
            / u8::BITS as usize)
            .div_ceil(WORD_BYTES);
        for prefix_len in [0, 104, 124, 125, 128, 140, 2048, 2049] {
            let prefix: Vec<_> = (0..prefix_len).map(|i| (i * 197) as u8).collect();
            let mut reference = initialise_state(PARAMS.n, PARAMS.k, PARAMS.hash_output());
            reference.update(&prefix);
            let split = prefix_len / 2;
            let state = SolverHashState::new(
                reference.clone(),
                &prefix[..split],
                &prefix[split..],
                PARAMS,
            );
            for blocks in [0, 1, 2, 8] {
                for first in [0, 65530, u32::MAX - 63] {
                    let guard = [[0xfeed_face_cafe_beef; LANES]; WORDS];
                    let mut output = vec![guard; blocks + 2];
                    let generated = state.try_generate_words(first, &mut output[1..blocks + 1]);
                    assert!(!generated);
                    assert!(output.iter().all(|&batch| batch == guard));
                    let mut compact = vec![0; blocks * LANES * state.hash_len];
                    state.generate(first, &mut compact);
                    for (offset, digest) in compact.chunks_exact(state.hash_len).enumerate() {
                        let mut expected = reference.clone();
                        expected.update(&(first + offset as u32).to_le_bytes());
                        assert_eq!(digest, expected.finalize().as_bytes());
                    }
                    assert_eq!(state.reference.finalize(), reference.finalize());
                }
            }
        }
    }

    // Computed independently with Python hashlib.blake2b: each personalized
    // 50-byte digest hashes header || nonce || little-endian block index;
    // expected is the unpersonalized BLAKE2b-512 of all concatenated digests.
    const REFERENCE_BATCHES: [(u32, u32, &str); 4] = [
        (
            0,
            0,
            "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce",
        ),
        (
            0,
            1,
            "d9357728d3b5b2def8d93d65f5f1e2abc0c3f750f938420cafaf33cc52bb02085b4d59b86e053253f919926e255c3b31a3dce8b05aa16eb9eead70958ec260ee",
        ),
        (
            63,
            67,
            "1e1404082f43cb2f355e29e8c8380ed61d241dba4b97dac5449104e7965d91c6bfbec08b65c05d9f829ff873f24220b11849b130129822453452d98d6d1e930f",
        ),
        (
            4294967293,
            3,
            "98e65ac93b4fc20b2f5cdc3ee39220a6762fc565bbf2568f06d75c9e2ef759f8e1e12b51c758a1844c54efde55a131f6468340c2708556e8dbcbc74b945c98a7",
        ),
    ];
}
