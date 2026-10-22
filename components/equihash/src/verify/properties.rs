//! Property tests for the verifier, derived from the algebra of Equihash proofs.
//!
//! A proof for `(n, k)` is a tuple of `2^k` indices read as the leaves of a
//! perfect binary tree of height `k`. Each internal node must satisfy three
//! predicates on its two subtrees: their XOR-ed hashes collide on the next
//! digit, the left subtree's first index is smaller than the right one's,
//! and the two subtrees share no index. The root's XOR must also be zero.
//!
//! Collision is symmetric and XOR is commutative and associative, so
//! swapping the two children of any internal node preserves every collision
//! and the root. Those swaps generate the automorphism group of the tree, the
//! `k`-fold iterated wreath product of `Z/2`, of order `2^(2^k - 1)`. Only
//! the ordering predicate can tell elements of one orbit apart, and with
//! distinct leaves it accepts exactly one of them: the ordering check selects
//! a canonical representative of each orbit. [`automorphisms_are_rejected`]
//! tests this as a law.
//!
//! The other properties compare the single-pass verifier with the original
//! recursive verifier, which is kept as the oracle, and check that the
//! minimal encoding is a bijection on its domain.

use alloc::vec::Vec;

use proptest::prelude::*;

use super::{
    Error, Kind,
    compatibility::{TestVector, test_vectors},
    is_valid_solution, is_valid_solution_recursive,
};
use crate::{
    leaf_hash::{HEADER_BYTES, LeafHasher, NONCE_BYTES},
    minimal::{indices_from_minimal, minimal_from_indices},
    params::Params,
    verify::initialise_state,
};

/// Digit sizes the verifier supports without panicking; outside this range
/// the minimal encoding's bit packing asserts.
const MIN_DIGIT_BITS: u32 = 8;
const MAX_DIGIT_BITS: u32 = 24;

/// Bounds the proof size to `2^MAX_K` leaves so the properties stay fast.
const MIN_K: u32 = 3;
const MAX_K: u32 = 10;

/// The widest `n` the parameter matrix explores; one BLAKE2b output is 512
/// bits, so wider leaves are unsupported.
const MAX_N: u32 = 512;

/// Prefix lengths reach past one BLAKE2b block on both sides of the
/// 140-byte Zcash layout that takes the specialized hashing path.
const MAX_PREFIX_BYTES: usize = 300;

/// Every `(n, k)` the properties use: valid, with a supported digit size,
/// and with at most `2^MAX_K` leaves.
fn supported_params() -> Vec<Params> {
    (u8::BITS..=MAX_N)
        .step_by(u8::BITS as usize)
        .flat_map(|n| (MIN_K..=MAX_K).map(move |k| (n, k)))
        .filter_map(|(n, k)| Params::new(n, k))
        .filter(|p| {
            (MIN_DIGIT_BITS as usize..=MAX_DIGIT_BITS as usize).contains(&p.collision_bit_length())
        })
        .collect()
}

fn arb_params() -> impl Strategy<Value = Params> {
    prop::sample::select(supported_params())
}

/// The bits in one encoded index.
fn index_bits(p: &Params) -> usize {
    p.collision_bit_length() + 1
}

/// `2^k` indices, each in the encodable range `[0, 2^(c + 1))`.
fn arb_indices(p: Params) -> impl Strategy<Value = Vec<u32>> {
    let leaves = p.solution_indices().unwrap();
    prop::collection::vec(0..(1u32 << index_bits(&p)), leaves)
}

fn arb_params_and_indices() -> impl Strategy<Value = (Params, Vec<u32>)> {
    arb_params().prop_flat_map(|p| (Just(p), arb_indices(p)))
}

/// An arbitrary `input || nonce` prefix with an arbitrary split point.
fn arb_prefix() -> impl Strategy<Value = (Vec<u8>, usize)> {
    prop_oneof![
        // The Zcash header layout, which takes the specialized hashing path.
        prop::collection::vec(any::<u8>(), HEADER_BYTES + NONCE_BYTES),
        // Any other length, which takes the generic path.
        prop::collection::vec(any::<u8>(), 0..MAX_PREFIX_BYTES),
    ]
    .prop_flat_map(|prefix| {
        let len = prefix.len();
        (Just(prefix), 0..=len)
    })
}

/// A valid proof from the fixed corpus.
fn arb_valid_vector() -> impl Strategy<Value = TestVector> {
    let valid: Vec<usize> = test_vectors()
        .iter()
        .enumerate()
        .filter(|(_, vector)| vector.valid)
        .map(|(i, _)| i)
        .collect();
    prop::sample::select(valid).prop_map(|i| test_vectors().swap_remove(i))
}

/// One flag per internal node of a tree with `2^k` leaves, in heap order:
/// a tree automorphism, which is the identity iff no flag is set.
fn arb_automorphism(k: u32) -> impl Strategy<Value = Vec<bool>> {
    prop::collection::vec(any::<bool>(), (1usize << k) - 1)
}

/// Applies the automorphism `flips` to `leaves`, top-down from heap node
/// `node`.
fn apply_automorphism(leaves: &mut [u32], flips: &[bool], node: usize) {
    if leaves.len() < 2 {
        return;
    }
    let half = leaves.len() / 2;
    let (left, right) = leaves.split_at_mut(half);
    if flips[node] {
        left.swap_with_slice(right);
    }
    apply_automorphism(left, flips, 2 * node + 1);
    apply_automorphism(right, flips, 2 * node + 2);
}

/// A local edit of a proof. Positions are reduced modulo the proof size.
#[derive(Clone, Debug)]
enum Mutation {
    /// Replaces one leaf with an arbitrary encodable index.
    SetLeaf { position: usize, value: u32 },
    /// Copies one leaf over another, which can duplicate an index.
    CopyLeaf { from: usize, to: usize },
    /// Copies an aligned subtree over its right sibling.
    CopySubtree { height: u32, pair: usize },
}

fn arb_mutation() -> impl Strategy<Value = Mutation> {
    prop_oneof![
        (any::<usize>(), any::<u32>())
            .prop_map(|(position, value)| Mutation::SetLeaf { position, value }),
        (any::<usize>(), any::<usize>()).prop_map(|(from, to)| Mutation::CopyLeaf { from, to }),
        (any::<u32>(), any::<usize>())
            .prop_map(|(height, pair)| Mutation::CopySubtree { height, pair }),
    ]
}

impl Mutation {
    fn apply(&self, leaves: &mut [u32], k: u32, index_bits: usize) {
        let len = leaves.len();
        match *self {
            Mutation::SetLeaf { position, value } => {
                leaves[position % len] = value & ((1 << index_bits) - 1);
            }
            Mutation::CopyLeaf { from, to } => leaves[to % len] = leaves[from % len],
            Mutation::CopySubtree { height, pair } => {
                let width = 1usize << (height % k);
                let start = (pair % (len / (2 * width))) * 2 * width;
                leaves.copy_within(start..start + width, start + width);
            }
        }
    }
}

/// The verdict of the public verifier on `indices`.
fn verdict(p: Params, input: &[u8], nonce: &[u8], indices: &[u32]) -> Result<(), Kind> {
    is_valid_solution(p.n, p.k, input, nonce, &minimal_from_indices(p, indices)).map_err(kind)
}

/// The verdict of the original recursive verifier on `indices`.
fn oracle(p: Params, input: &[u8], nonce: &[u8], indices: &[u32]) -> Result<(), Kind> {
    is_valid_solution_recursive(p, input, nonce, indices).map_err(kind)
}

fn kind(error: Error) -> Kind {
    error.0
}

fn vector_params(vector: &TestVector) -> Params {
    Params::new(vector.n, vector.k).unwrap()
}

proptest! {
    // The default config (256 cases) reads `PROPTEST_CASES`; an explicit
    // `with_cases` would silently override it.
    #![proptest_config(ProptestConfig::default())]

    /// `indices_from_minimal` is a left inverse of `minimal_from_indices` on
    /// encodable indices.
    #[test]
    fn minimal_encoding_round_trips_indices((p, indices) in arb_params_and_indices()) {
        let encoded = minimal_from_indices(p, &indices);
        prop_assert_eq!(Some(encoded.len()), p.solution_bytes());
        prop_assert_eq!(indices_from_minimal(p, &encoded), Some(indices));
    }

    /// Every byte string of the solution length decodes, and re-encodes to
    /// itself, so together with the round trip above the encoding is a
    /// bijection between `[0, 2^(c + 1))^(2^k)` and those byte strings.
    #[test]
    fn minimal_encoding_round_trips_bytes(
        (p, bytes) in arb_params().prop_flat_map(|p| {
            let len = p.solution_bytes().unwrap();
            (Just(p), prop::collection::vec(any::<u8>(), len))
        })
    ) {
        let indices = indices_from_minimal(p, &bytes).unwrap();
        prop_assert!(indices.iter().all(|i| *i < 1 << index_bits(&p)));
        prop_assert_eq!(minimal_from_indices(p, &indices), bytes);
    }

    /// Decoding accepts exactly the solution length.
    #[test]
    fn minimal_encoding_rejects_other_lengths(
        p in arb_params(),
        len in 0usize..4096,
    ) {
        let expected = p.solution_bytes().unwrap();
        prop_assert_eq!(indices_from_minimal(p, &vec![0; len]).is_some(), len == expected);
    }

    /// The single-pass verifier agrees with the recursive oracle, error kind
    /// included, on arbitrary indices and prefixes, through both the
    /// specialized and the generic leaf hashing paths.
    #[test]
    fn verifier_matches_oracle_on_arbitrary_indices(
        (p, indices) in arb_params_and_indices(),
        (prefix, split) in arb_prefix(),
    ) {
        let (input, nonce) = prefix.split_at(split);
        prop_assert_eq!(verdict(p, input, nonce, &indices), oracle(p, input, nonce, &indices));
    }

    /// The canonical-representative law: a tree automorphism of a valid proof
    /// is accepted iff it is the identity, and is otherwise rejected only for
    /// its order, because collisions and the root are invariant.
    #[test]
    fn automorphisms_are_rejected(
        (vector, flips) in arb_valid_vector()
            .prop_flat_map(|vector| {
                let k = vector.k;
                (Just(vector), arb_automorphism(k))
            })
    ) {
        let p = vector_params(&vector);
        let mut indices = vector.indices();
        apply_automorphism(&mut indices, &flips, 0);
        let identity = !flips.iter().any(|flip| *flip);
        let expected = || if identity { Ok(()) } else { Err(Kind::OutOfOrder) };
        prop_assert_eq!(verdict(p, &vector.input, &vector.nonce, &indices), expected());
        prop_assert_eq!(oracle(p, &vector.input, &vector.nonce, &indices), expected());
    }

    /// The verifier agrees with the oracle on valid proofs after a sequence of
    /// local edits, which reach the duplicate-index and collision checks deep
    /// in the tree rather than only at the first leaf pair.
    #[test]
    fn verifier_matches_oracle_on_mutated_proofs(
        vector in arb_valid_vector(),
        mutations in prop::collection::vec(arb_mutation(), 0..4),
    ) {
        let p = vector_params(&vector);
        let mut indices = vector.indices();
        for mutation in &mutations {
            mutation.apply(&mut indices, vector.k, vector.index_bits());
        }
        prop_assert_eq!(
            verdict(p, &vector.input, &vector.nonce, &indices),
            oracle(p, &vector.input, &vector.nonce, &indices)
        );
        // The corpus encoder is independent of the crate's bit packing.
        prop_assert_eq!(vector.encode(&indices), minimal_from_indices(p, &indices));
    }

    /// The verdict depends only on `input || nonce`, not on the split point.
    #[test]
    fn verdict_depends_only_on_concatenated_prefix(
        vector in arb_valid_vector(),
        split in 0usize..=HEADER_BYTES + NONCE_BYTES,
    ) {
        let prefix = [&vector.input[..], &vector.nonce[..]].concat();
        let (input, nonce) = prefix.split_at(split);
        prop_assert_eq!(
            is_valid_solution(vector.n, vector.k, input, nonce, &vector.solution).map_err(kind),
            Ok(())
        );
    }

    /// The specialized leaf hasher computes personalized BLAKE2b, for every
    /// supported parameter set, prefix, split and block index.
    #[test]
    fn leaf_hasher_matches_blake2b(
        p in arb_params(),
        prefix in prop::collection::vec(any::<u8>(), HEADER_BYTES + NONCE_BYTES),
        split in 0usize..=HEADER_BYTES + NONCE_BYTES,
        blocks in prop::collection::vec(any::<u32>(), 1..8),
    ) {
        let (input, nonce) = prefix.split_at(split);
        let hasher = LeafHasher::new(&p, input, nonce).unwrap();
        let mut digests = vec![[0xa5; 64]; blocks.len()];
        hasher.hash(&blocks, &mut digests);
        for (block, digest) in blocks.iter().zip(&digests) {
            let mut state = initialise_state(p.n, p.k, p.hash_output());
            state.update(input);
            state.update(nonce);
            state.update(&block.to_le_bytes());
            let expected = state.finalize();
            let len = expected.as_bytes().len();
            prop_assert_eq!(&digest[..len], expected.as_bytes());
            prop_assert!(digest[len..].iter().all(|b| *b == 0));
        }
    }

    /// The public verifier is total on supported parameters: arbitrary bytes
    /// of any length produce a verdict, never a panic.
    #[test]
    fn verifier_is_total_on_supported_params(
        p in arb_params(),
        (prefix, split) in arb_prefix(),
        solution in prop::collection::vec(any::<u8>(), 0..2048),
    ) {
        let (input, nonce) = prefix.split_at(split);
        let _verdict = is_valid_solution(p.n, p.k, input, nonce, &solution);
    }
}

/// Sets `width` bits of `buf` starting at bit `offset`, big-endian, to the low
/// bits of `value`.
fn set_bits(buf: &mut [u8], offset: usize, width: usize, value: u32) {
    for bit in 0..width {
        let position = offset + bit;
        let set = (value >> (width - 1 - bit)) & 1 == 1;
        let mask = 1 << (7 - position % 8);
        if set {
            buf[position / 8] |= mask;
        } else {
            buf[position / 8] &= !mask;
        }
    }
}

/// `(params, leaf, digit, value)`: one digit of one leaf to make nonzero.
fn arb_single_digit() -> impl Strategy<Value = (Params, usize, u32, u32)> {
    arb_params().prop_flat_map(|p| {
        let leaves = p.solution_indices().unwrap();
        let digit_bits = p.collision_bit_length() as u32;
        (Just(p), 0..leaves, 0..=p.k, 0..(1u32 << digit_bits))
    })
}

proptest! {
    // The default config (256 cases) reads `PROPTEST_CASES`; an explicit
    // `with_cases` would silently override it.
    #![proptest_config(ProptestConfig::default())]

    /// The tree walk against the specification itself, with a synthetic leaf
    /// hash: every leaf hashes to zero except digit `digit` of leaf `leaf`,
    /// which is `value`. Every check before height `digit + 1` then passes,
    /// the merge at that height sees `value` on one side only, and the root
    /// holds the last digit. So the verdict is `Ok` iff `value` is zero, and
    /// otherwise a collision failure, or a nonzero root when `digit = k`.
    #[test]
    fn tree_walk_checks_every_digit_of_every_leaf(
        (p, leaf, digit, value) in arb_single_digit()
    ) {
        let leaves = p.solution_indices().unwrap();
        let per_hash = p.indices_per_hash_output() as usize;
        let leaf_bytes = p.n as usize / 8;
        let digit_bits = p.collision_bit_length();
        // Leaf `i` is index `i`: distinct and canonically ordered.
        let indices: Vec<u32> = (0..leaves as u32).collect();
        let verdict = super::tree::validate_tree(&p, &indices, |blocks, digests| {
            for (block, digest) in blocks.iter().zip(digests.iter_mut()) {
                digest.fill(0);
                for slot in 0..per_hash {
                    if *block as usize * per_hash + slot == leaf {
                        let start = slot * leaf_bytes;
                        let leaf_hash = &mut digest[start..start + leaf_bytes];
                        set_bits(leaf_hash, digit as usize * digit_bits, digit_bits, value);
                    }
                }
            }
        });
        let expected = if value == 0 {
            Ok(())
        } else if digit < p.k {
            Err(Kind::Collision)
        } else {
            Err(Kind::NonZeroRootHash)
        };
        prop_assert_eq!(verdict, expected);
    }
}

/// Every valid `(n, k)` whose solution size overflows `usize` on this target
/// is rejected as invalid through the public API, for any solution length,
/// instead of panicking on the overflowing shift or multiplication.
#[test]
fn overflowing_params_are_rejected() {
    /// Reaches `k >= usize::BITS` (the shift overflows) and the `k` just
    /// below it (the multiplication overflows) for 64-bit targets.
    const MAX_SWEEP_N: u32 = 1024;
    const MAX_SWEEP_K: u32 = 2 * usize::BITS;
    const SOLUTION_LENGTHS: [usize; 4] = [0, 1, 64, 1344];
    let mut overflowing = 0;
    for n in (u8::BITS..=MAX_SWEEP_N).step_by(u8::BITS as usize) {
        for k in MIN_K..MAX_SWEEP_K.min(n) {
            let Some(p) = Params::new(n, k) else {
                continue;
            };
            if p.solution_bytes().is_some() {
                continue;
            }
            overflowing += 1;
            for len in SOLUTION_LENGTHS {
                assert_eq!(
                    is_valid_solution(n, k, &[0; HEADER_BYTES], &[0; NONCE_BYTES], &vec![0; len])
                        .map_err(kind),
                    Err(Kind::InvalidParams),
                    "({n}, {k}) with a {len}-byte solution",
                );
            }
        }
    }
    // Both overflow kinds occur: k = usize::BITS - 1 (multiplication) and
    // k >= usize::BITS (shift).
    assert!(overflowing > 0);
    assert!(Params::new(64, 63).unwrap().solution_bytes().is_none());
    assert!(Params::new(136, 67).unwrap().solution_bytes().is_none());
}

#[cfg(feature = "solver")]
mod solver {
    use proptest::prelude::*;

    use super::Params;
    use crate::{is_valid_solution, minimal::indices_from_minimal, tromp::solve_200_9};

    /// Each solver run hashes `2^20` blocks, so keep the case count small.
    const SOLVER_CASES: u32 = 4;
    const SOLVER_N: u32 = 200;
    const SOLVER_K: u32 = 9;
    /// The solver keeps at most this many solutions per nonce.
    const MAX_SOLUTIONS: usize = 8;
    const NONCE_BYTES: usize = 32;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(SOLVER_CASES))]

        /// The solver is sound: every returned proof verifies, has distinct
        /// indices, and the result is sorted, deduplicated and capped.
        #[test]
        fn solver_returns_valid_canonical_proofs(
            input in prop::collection::vec(any::<u8>(), 0..200),
            nonce in any::<[u8; NONCE_BYTES]>(),
        ) {
            let mut once = Some(nonce);
            let solutions = solve_200_9(&input, || once.take());
            prop_assert!(solutions.len() <= MAX_SOLUTIONS);
            prop_assert!(solutions.windows(2).all(|w| w[0] < w[1]));
            let p = Params::new(SOLVER_N, SOLVER_K).unwrap();
            for solution in &solutions {
                prop_assert!(is_valid_solution(SOLVER_N, SOLVER_K, &input, &nonce, solution).is_ok());
                let mut indices = indices_from_minimal(p, solution).unwrap();
                indices.sort_unstable();
                prop_assert!(indices.windows(2).all(|w| w[0] < w[1]));
            }
        }
    }
}
