//! Regenerate the random Equihash compatibility fixtures.
//!
//! Run `cargo test --release -p equihash --features solver
//! test_vectors::generate::generate_equihash_compatibility -- --ignored --exact
//! --nocapture` to print the corpus. Test harness output must be excluded when
//! saving the fixture rows to `src/test_vectors/random.txt`.

use alloc::{string::ToString, vec::Vec};
use std::{eprintln, println};

use rand::{RngCore, SeedableRng, rngs::StdRng};

use crate::{minimal, params, verify};

const HEADER_BYTES: usize = 108;
const NONCE_BYTES: usize = 32;
const SEED: u64 = 0x514_1191;
const MAINNET_PARAMS: (u32, u32) = (200, 9);
const REGTEST_PARAMS: (u32, u32) = (48, 5);

struct Row {
    hash: Vec<u8>,
    indices: Vec<u32>,
}

/// A small independent Wagner solver for the byte-aligned Regtest parameters.
fn regtest_rows(input: &[u8], nonce: &[u8]) -> Vec<Row> {
    let (n, k) = REGTEST_PARAMS;
    let collision_bits = n / (k + 1);
    assert_eq!(collision_bits, u8::BITS);
    let leaf_bytes = usize::try_from(n / u8::BITS).unwrap();
    let per_hash = 512 / n;
    let mut personalization = [0; 16];
    personalization[..8].copy_from_slice(b"ZcashPoW");
    personalization[8..12].copy_from_slice(&n.to_le_bytes());
    personalization[12..].copy_from_slice(&k.to_le_bytes());
    let mut state = blake2b_simd::Params::new()
        .hash_length(usize::try_from(per_hash).unwrap() * leaf_bytes)
        .personal(&personalization)
        .to_state();
    state.update(input);
    state.update(nonce);

    let mut rows = Vec::new();
    for index in 0..1u32 << (collision_bits + 1) {
        let mut leaf_state = state.clone();
        leaf_state.update(&(index / per_hash).to_le_bytes());
        let digest = leaf_state.finalize();
        let start = usize::try_from(index % per_hash).unwrap() * leaf_bytes;
        rows.push(Row {
            hash: digest.as_bytes()[start..start + leaf_bytes].to_vec(),
            indices: vec![index],
        });
    }
    for _ in 0..k {
        let mut buckets: [Vec<Row>; 256] = std::array::from_fn(|_| Vec::new());
        for row in rows {
            buckets[usize::from(row.hash[0])].push(row);
        }
        rows = Vec::new();
        for bucket in buckets {
            for (i, a) in bucket.iter().enumerate() {
                for b in &bucket[i + 1..] {
                    if a.indices.iter().any(|index| b.indices.contains(index)) {
                        continue;
                    }
                    let (left, right) = if a.indices[0] < b.indices[0] {
                        (a, b)
                    } else {
                        (b, a)
                    };
                    rows.push(Row {
                        hash: left.hash[1..]
                            .iter()
                            .zip(&right.hash[1..])
                            .map(|(a, b)| a ^ b)
                            .collect(),
                        indices: left.indices.iter().chain(&right.indices).copied().collect(),
                    });
                }
            }
        }
    }
    rows
}

fn encode_indices(indices: &[u32], bits: u32) -> Vec<u8> {
    let mut bytes = vec![0; indices.len() * usize::try_from(bits).unwrap() / 8];
    let mut offset = 0;
    for index in indices {
        for bit in (0..bits).rev() {
            let value = u8::try_from((index >> bit) & 1).unwrap();
            bytes[offset / 8] |= value << (7 - offset % 8);
            offset += 1;
        }
    }
    bytes
}

fn emit(params: (u32, u32), input: &[u8], nonce: &[u8], proof: &[u8], valid: bool) {
    let (n, k) = params;
    let params = params::Params::new(n, k).unwrap();
    let indices = minimal::indices_from_minimal(params, proof).unwrap();
    let reference = verify::is_valid_solution_recursive(params, input, nonce, &indices);
    assert_eq!(reference.is_ok(), valid);
    if !valid {
        assert_eq!(
            reference.unwrap_err().to_string(),
            "Invalid solution: root hash of tree is non-zero"
        );
    }
    println!(
        "{n} {k} {} {} {} {}",
        if valid { "valid" } else { "nonzero-root" },
        hex::encode(input),
        hex::encode(nonce),
        hex::encode(proof),
    );
}

#[test]
#[ignore = "regenerates the compatibility fixture corpus"]
fn generate_equihash_compatibility() {
    let mut rng = StdRng::seed_from_u64(SEED);
    println!("# Seed: {SEED:#x}; rand 0.8 StdRng; 8 Mainnet and 32 Regtest inputs.");
    println!("# Regenerate with the test_vectors::generate::generate_equihash_compatibility test.");
    println!("# n k verdict header-prefix-hex nonce-hex solution-hex");
    for case in 0..8 {
        let mut input = [0; HEADER_BYTES];
        rng.fill_bytes(&mut input);
        let mut nonce = [0; NONCE_BYTES];
        let proofs = crate::tromp::solve_200_9(&input, || {
            rng.fill_bytes(&mut nonce);
            Some(nonce)
        });
        emit(MAINNET_PARAMS, &input, &nonce, &proofs[0], true);
        eprintln!("generated Mainnet input {case}");
    }
    for case in 0..32 {
        let mut input = [0; HEADER_BYTES];
        rng.fill_bytes(&mut input);
        let (nonce, rows) = loop {
            let mut nonce = [0; NONCE_BYTES];
            rng.fill_bytes(&mut nonce);
            let rows = regtest_rows(&input, &nonce);
            if rows.iter().any(|row| row.hash == [0]) && rows.iter().any(|row| row.hash != [0]) {
                break (nonce, rows);
            }
        };
        for valid in [true, false] {
            let row = rows.iter().find(|row| (row.hash == [0]) == valid).unwrap();
            let (n, k) = REGTEST_PARAMS;
            let proof = encode_indices(&row.indices, n / (k + 1) + 1);
            emit(REGTEST_PARAMS, &input, &nonce, &proof, valid);
        }
        eprintln!("generated Regtest input {case}");
    }
}
