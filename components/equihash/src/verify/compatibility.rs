//! Differential coverage for the public verifier against the original recursive verifier.
//!
//! The fixed random inputs contain valid proofs and real proofs whose final
//! root is nonzero. Regenerate them with the ignored
//! `test_vectors::generate::generate_equihash_compatibility` test. It uses the Mainnet solver
//! and an independent Wagner solver for Regtest, and checks every fixture
//! against the original recursive verifier before emitting it.
//!
//! Each randomized test uses a fresh mutation seed and reports it on failure.
//! Set `EQUIHASH_MUTATION_SEED` to a decimal or `0x`-prefixed seed to replay it.

use alloc::{
    borrow::ToOwned,
    string::{String, ToString},
    vec::Vec,
};
use std::{collections::BTreeSet, env, process::Command};

use rand::{Rng, RngCore, SeedableRng, rngs::StdRng};

use crate::{minimal::indices_from_minimal, params::Params};

use super::{Error, Kind, is_valid_solution_recursive};

const HEADER_BYTES: usize = 108;
const NONCE_BYTES: usize = 32;
const MUTATION_SEED_ENV: &str = "EQUIHASH_MUTATION_SEED";
const RANDOM_CASES_PER_INPUT: usize = 128;
const INVALID_PARAMS: &str = "Invalid solution: invalid parameters";

struct MutationRun {
    seed: u64,
    rng: StdRng,
}

impl MutationRun {
    fn new() -> Self {
        let seed = match env::var(MUTATION_SEED_ENV) {
            Ok(value) => {
                let parsed = if let Some(hex) = value.strip_prefix("0x") {
                    u64::from_str_radix(hex, 16)
                } else {
                    value.parse()
                };
                parsed.expect("EQUIHASH_MUTATION_SEED must be a decimal or 0x-prefixed u64")
            }
            Err(env::VarError::NotPresent) => rand::random(),
            Err(error) => panic!("invalid {MUTATION_SEED_ENV}: {error}"),
        };
        Self {
            seed,
            rng: StdRng::seed_from_u64(seed),
        }
    }
}

impl Drop for MutationRun {
    fn drop(&mut self) {
        if std::thread::panicking() {
            std::eprintln!(
                "Equihash mutation seed: {:#018x}\n\
                 Replay with {MUTATION_SEED_ENV}={:#018x} cargo test \
                 -p equihash --all-features --locked verify::compatibility",
                self.seed,
                self.seed,
            );
        }
    }
}

struct TestVector {
    n: u32,
    k: u32,
    valid: bool,
    input: Vec<u8>,
    nonce: Vec<u8>,
    solution: Vec<u8>,
}

fn test_vectors() -> Vec<TestVector> {
    include_str!("../test_vectors/random.txt")
        .lines()
        .filter(|line| !line.starts_with('#') && !line.is_empty())
        .map(|line| {
            let fields: Vec<_> = line.split_ascii_whitespace().collect();
            assert_eq!(fields.len(), 6);
            assert!(matches!(fields[2], "valid" | "nonzero-root"));
            let vector = TestVector {
                n: fields[0].parse().unwrap(),
                k: fields[1].parse().unwrap(),
                valid: fields[2] == "valid",
                input: hex::decode(fields[3]).unwrap(),
                nonce: hex::decode(fields[4]).unwrap(),
                solution: hex::decode(fields[5]).unwrap(),
            };
            assert_eq!(vector.input.len(), HEADER_BYTES);
            assert_eq!(vector.nonce.len(), NONCE_BYTES);
            vector
        })
        .collect()
}

impl TestVector {
    fn compare(&self, input: &[u8], nonce: &[u8], solution: &[u8]) -> Result<(), String> {
        let expected = Params::new(self.n, self.k)
            .and_then(|params| {
                indices_from_minimal(params, solution).map(|indices| (params, indices))
            })
            .ok_or(Error(Kind::InvalidParams))
            .and_then(|(params, indices)| {
                is_valid_solution_recursive(params, input, nonce, &indices)
            })
            .map_err(|error| error.to_string());
        let actual = super::is_valid_solution(self.n, self.k, input, nonce, solution)
            .map_err(|error| error.to_string());
        assert_eq!(
            actual,
            expected,
            "({}, {}) input={} nonce={} solution={}",
            self.n,
            self.k,
            hex::encode(input),
            hex::encode(nonce),
            hex::encode(solution),
        );
        expected
    }

    fn index_bits(&self) -> usize {
        usize::try_from(self.n / (self.k + 1) + 1).unwrap()
    }

    // Read and write individual bits instead of copying either verifier's
    // accumulator-based minimal-encoding implementation.
    fn indices(&self) -> Vec<u32> {
        self.solution
            .iter()
            .flat_map(|byte| (0..8).rev().map(move |bit| u32::from((byte >> bit) & 1)))
            .collect::<Vec<_>>()
            .chunks_exact(self.index_bits())
            .map(|bits| bits.iter().fold(0, |index, bit| (index << 1) | bit))
            .collect()
    }

    fn encode(&self, indices: &[u32]) -> Vec<u8> {
        let bits = self.index_bits();
        let mut encoded = vec![0; indices.len() * bits / 8];
        for (i, index) in indices.iter().enumerate() {
            for bit in 0..bits {
                let offset = i * bits + bit;
                let value = u8::try_from((index >> (bits - bit - 1)) & 1).unwrap();
                encoded[offset / 8] |= value << (7 - offset % 8);
            }
        }
        encoded
    }
}

#[test]
fn random_solved_headers_match_upstream() {
    let vectors = test_vectors();
    assert_eq!(vectors.iter().filter(|vector| vector.valid).count(), 40);
    assert_eq!(vectors.iter().filter(|vector| !vector.valid).count(), 32);
    for vector in vectors {
        let result = vector.compare(&vector.input, &vector.nonce, &vector.solution);
        if vector.valid {
            result.expect("the generator verified this proof with upstream");
        } else {
            assert_eq!(
                result.unwrap_err(),
                "Invalid solution: root hash of tree is non-zero"
            );
        }
        assert_eq!(vector.encode(&vector.indices()), vector.solution);
    }
}

#[test]
fn random_proof_mutations_match_upstream() {
    let mut run = MutationRun::new();
    let rng = &mut run.rng;
    let mut verdicts = BTreeSet::new();
    for vector in test_vectors().into_iter().filter(|vector| vector.valid) {
        let indices = vector.indices();

        // Reach every tree height and every aligned sibling pair, including
        // merges across the verifier's leaf-hashing batch boundaries.
        for height in 0..vector.k {
            let width = 1usize << height;
            for start in (0..indices.len()).step_by(2 * width) {
                let mut swapped = indices.clone();
                let (left, right) = swapped[start..start + 2 * width].split_at_mut(width);
                left.swap_with_slice(right);
                verdicts.insert(vector.compare(
                    &vector.input,
                    &vector.nonce,
                    &vector.encode(&swapped),
                ));

                let mut duplicated = indices.clone();
                duplicated.copy_within(start..start + width, start + width);
                verdicts.insert(vector.compare(
                    &vector.input,
                    &vector.nonce,
                    &vector.encode(&duplicated),
                ));
            }
        }

        // Mutate every encoded byte, rotating through all eight bit positions.
        for byte in 0..vector.solution.len() {
            let mut solution = vector.solution.clone();
            solution[byte] ^= 1 << (byte % 8);
            verdicts.insert(vector.compare(&vector.input, &vector.nonce, &solution));
        }
        for _ in 0..RANDOM_CASES_PER_INPUT {
            let mut input = vector.input.clone();
            let mut nonce = vector.nonce.clone();
            let mut solution = vector.solution.clone();
            let mut mutated = indices.clone();
            let (a, b) = (
                rng.gen_range(0..indices.len()),
                rng.gen_range(0..indices.len()),
            );
            match rng.gen_range(0..7) {
                0 => mutated.swap(a, b),
                1 => mutated[b] = mutated[a],
                2 => mutated[a] = rng.gen_range(0..1u32 << vector.index_bits()),
                3 => mutated[a] = (1u32 << vector.index_bits()) - 1,
                4 => rng.fill_bytes(&mut solution),
                5 => rng.fill_bytes(&mut input),
                _ => rng.fill_bytes(&mut nonce),
            }
            if mutated != indices {
                solution = vector.encode(&mutated);
            }
            verdicts.insert(vector.compare(&input, &nonce, &solution));
        }
    }
    // The cases must exercise the duplicate fallback and ordering check as
    // well as the all-distinct fast path, rather than only early collisions.
    for message in [
        "Invalid solution: invalid collision length between StepRows",
        "Invalid solution: Index tree incorrectly ordered",
        "Invalid solution: duplicate indices",
    ] {
        assert!(verdicts.contains(&Err(message.to_owned())), "{message}");
    }
}

#[test]
fn random_prefix_mutations_and_splits_match_upstream() {
    for vector in test_vectors().into_iter().filter(|vector| vector.valid) {
        let prefix = [&vector.input[..], &vector.nonce[..]].concat();
        // All splits retain the 140-byte prefix, including both sides of
        // BLAKE2b's block boundary and empty input/nonce slices.
        for split in 0..=prefix.len() {
            vector
                .compare(&prefix[..split], &prefix[split..], &vector.solution)
                .expect("changing only the split preserves the hashed bytes");
        }
        for byte in 0..prefix.len() {
            let mut mutated = prefix.clone();
            mutated[byte] ^= 1 << (byte % 8);
            vector
                .compare(
                    &mutated[..HEADER_BYTES],
                    &mutated[HEADER_BYTES..],
                    &vector.solution,
                )
                .expect_err("changing a prefix byte invalidates its proof");
        }
    }
}

#[test]
fn bounded_parameter_matrix_matches_upstream() {
    let mut run = MutationRun::new();
    let rng = &mut run.rng;
    for n in (8..=512).step_by(8) {
        // Bound proof sizes to 4096 leaves so the sweep is safe to run in CI.
        for k in 3..=12 {
            if k >= n || n % (k + 1) != 0 || !(8..=24).contains(&(n / (k + 1))) {
                continue;
            }
            let params = Params::new(n, k).unwrap();
            for _ in 0..16 {
                let mut vector = TestVector {
                    n,
                    k,
                    valid: false,
                    input: vec![0; HEADER_BYTES],
                    nonce: vec![0; NONCE_BYTES],
                    solution: vec![0; params.solution_bytes().unwrap()],
                };
                rng.fill_bytes(&mut vector.input);
                rng.fill_bytes(&mut vector.nonce);
                rng.fill_bytes(&mut vector.solution);
                let _verdict = vector.compare(&vector.input, &vector.nonce, &vector.solution);
            }
        }
    }
}

#[test]
fn mutation_seed_is_reported_on_failure() {
    const CHILD_ENV: &str = "EQUIHASH_TEST_SEED_FAILURE_CHILD";
    const SEED: &str = "0x0514c0de0514c0de";
    if env::var_os(CHILD_ENV).is_some() {
        let _run = MutationRun::new();
        panic!("intentional failure to check mutation seed reporting");
    }

    let output = Command::new(env::current_exe().unwrap())
        .args([
            "--exact",
            "verify::compatibility::mutation_seed_is_reported_on_failure",
            "--nocapture",
        ])
        .env(CHILD_ENV, "1")
        .env(MUTATION_SEED_ENV, SEED)
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains(&format!("Equihash mutation seed: {SEED}")));
    assert!(stderr.contains(&format!("{MUTATION_SEED_ENV}={SEED} cargo test")));
}

#[test]
fn malformed_encodings_match_upstream() {
    for vector in test_vectors().into_iter().filter(|vector| vector.valid) {
        for len in [0, 1, vector.solution.len() - 1, vector.solution.len() + 1] {
            let mut solution = vector.solution.clone();
            solution.resize(len, 0);
            assert_eq!(
                vector.compare(&vector.input, &vector.nonce, &solution),
                Err(INVALID_PARAMS.to_owned())
            );
        }
    }
}
