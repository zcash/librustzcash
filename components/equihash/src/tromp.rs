//! Tromp's Equihash solver implemented in Rust.

use std::vec::Vec;

use crate::{blake2b::SolverHashState, minimal::minimal_from_indices, params::Params, verify};

mod solver;

const SOLVER_PARAMS: Params = Params { n: 200, k: 9 };

/// Runs the solver until the nonce source ends or a nonce produces solutions.
fn solve_200_9_uncompressed<const N: usize>(
    input: &[u8],
    mut next_nonce: impl FnMut() -> Option<[u8; N]>,
) -> Vec<Vec<u32>> {
    let p = SOLVER_PARAMS;
    let mut state = verify::initialise_state(p.n, p.k, p.hash_output());
    state.update(input);
    let mut solver = solver::Solver::new();

    while let Some(nonce) = next_nonce() {
        let mut curr_state = state.clone();
        curr_state.update(&nonce);
        let curr_state = SolverHashState::new(curr_state, input, &nonce, p);
        let solutions = solver.run(&curr_state);
        if !solutions.is_empty() {
            return solutions;
        }
    }
    Vec::new()
}

/// Performs multiple Equihash solver runs with parameters `200, 9`,
/// initializing the hash with the supplied partial `input`. Between each run,
/// generates a new nonce of length `N` using `next_nonce`.
///
/// Returns zero or more unique compressed solutions.
///
/// The solver accepts any `input` and nonce length.
pub fn solve_200_9<const N: usize>(
    input: &[u8],
    next_nonce: impl FnMut() -> Option<[u8; N]>,
) -> Vec<Vec<u8>> {
    let solutions = solve_200_9_uncompressed(input, next_nonce);
    let mut solutions: Vec<Vec<u8>> = solutions
        .iter()
        .map(|solution| minimal_from_indices(SOLVER_PARAMS, solution))
        .collect();
    solutions.sort();
    solutions.dedup();
    solutions
}

#[cfg(test)]
mod tests {
    use std::println;

    use super::solve_200_9;

    #[test]
    fn fixed_nonce_solutions_match_c_solver() {
        let input = b"Equihash is an asymmetric PoW based on the Generalised Birthday problem.";
        // These counts and BLAKE2b-512 fingerprints were recorded from the C
        // solver before this port. Fingerprints include sorted compressed
        // proofs, so this checks both the returned set and canonical ordering.
        let expected = [
            (
                0,
                "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce",
            ),
            (
                3,
                "b0a21dbaf77016d42e955c7306b2bc3e7856d16b85eca54df3fea09b7d3544ac4314793d465a16cee7cd168b23a60b9eac4dc5b696a1e67b9f984f04ba5f50e9",
            ),
            (
                2,
                "c255f85d1b9f08a44ac6e2600dcf4627fbbd2f934173b39c68399f4e94b8fb0601b69f8690fc71b980e3c1413ca3d41c5d45160ff898a0afa1ea5e7403819596",
            ),
            (
                0,
                "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce",
            ),
        ];
        for (index, (count, fingerprint)) in expected.into_iter().enumerate() {
            let mut nonce = [0; 32];
            nonce[..4].copy_from_slice(&(index as u32).to_le_bytes());
            let mut next_nonce = Some(nonce);
            let solutions = solve_200_9(input, || next_nonce.take());
            assert_eq!(solutions.len(), count);
            let mut hash = blake2b_simd::State::new();
            for solution in solutions {
                crate::is_valid_solution(200, 9, input, &nonce, &solution).unwrap();
                hash.update(&solution);
            }
            assert_eq!(hex::encode(hash.finalize().as_bytes()), fingerprint);
        }
    }

    #[test]
    #[allow(clippy::print_stdout)]
    fn run_solver() {
        let input = b"Equihash is an asymmetric PoW based on the Generalised Birthday problem.";
        let mut nonce: [u8; 32] = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ];
        let mut nonces = 0..=32_u32;
        let nonce_count = nonces.clone().count();

        let solutions = solve_200_9(input, || {
            let variable_nonce = nonces.next()?;
            println!("Using variable nonce [0..4] of {variable_nonce}");

            let variable_nonce = variable_nonce.to_le_bytes();
            nonce[0] = variable_nonce[0];
            nonce[1] = variable_nonce[1];
            nonce[2] = variable_nonce[2];
            nonce[3] = variable_nonce[3];

            Some(nonce)
        });

        if solutions.is_empty() {
            // Expected solution rate is documented at:
            // https://github.com/tromp/equihash/blob/master/README.md
            panic!("Found no solutions after {nonce_count} runs, expected 1.88 solutions per run",);
        } else {
            println!("Found {} solutions:", solutions.len());
            for (sol_num, solution) in solutions.iter().enumerate() {
                println!("Validating solution {sol_num}:-\n{}", hex::encode(solution));
                crate::is_valid_solution(200, 9, input, &nonce, solution).unwrap_or_else(|error| {
                    panic!(
                        "unexpected invalid equihash 200, 9 solution:\n\
                         error: {error:?}\n\
                         input: {input:?}\n\
                         nonce: {nonce:?}\n\
                         solution: {solution:?}"
                    )
                });
                println!("Solution {sol_num} is valid!\n");
            }
        }
    }
}
