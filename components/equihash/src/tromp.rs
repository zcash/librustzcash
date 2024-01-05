//! Rust interface to the tromp equihash solver.

use std::marker::{PhantomData, PhantomPinned};
use std::slice;

use blake2b_simd::State;

use crate::{blake2b, verify};

#[repr(C)]
struct CEqui {
    _f: [u8; 0],
    _m: PhantomData<(*mut u8, PhantomPinned)>,
}

#[link(name = "equitromp")]
extern "C" {
    #[allow(improper_ctypes)]
    fn equi_new(
        n_threads: u32,
        blake2b_clone: extern "C" fn(state: *const State) -> *mut State,
        blake2b_free: extern "C" fn(state: *mut State),
        blake2b_update: extern "C" fn(state: *mut State, input: *const u8, input_len: usize),
        blake2b_finalize: extern "C" fn(state: *mut State, output: *mut u8, output_len: usize),
    ) -> *mut CEqui;
    fn equi_free(eq: *mut CEqui);
    #[allow(improper_ctypes)]
    fn equi_setstate(eq: *mut CEqui, ctx: *const State);
    fn equi_clearslots(eq: *mut CEqui);
    fn equi_digit0(eq: *mut CEqui, id: u32);
    fn equi_digitodd(eq: *mut CEqui, r: u32, id: u32);
    fn equi_digiteven(eq: *mut CEqui, r: u32, id: u32);
    fn equi_digitK(eq: *mut CEqui, id: u32);
    fn equi_nsols(eq: *const CEqui) -> usize;
    fn equi_sols(eq: *const CEqui) -> *const *const u32;
}

/// Performs a single equihash solver run with equihash parameters `p` and hash state `curr_state`.
/// Returns zero or more solutions.
///
/// # SAFETY
///
/// The parameters to this function must match the hard-coded parameters in the C++ code.
///
/// This function uses unsafe code for FFI into the tromp solver.
#[allow(unsafe_code)]
unsafe fn worker(p: verify::Params, curr_state: &State) -> Vec<Vec<u32>> {
    // Create solver and initialize it.
    let eq = equi_new(
        1,
        blake2b::blake2b_clone,
        blake2b::blake2b_free,
        blake2b::blake2b_update,
        blake2b::blake2b_finalize,
    );
    equi_setstate(eq, curr_state);

    // Initialization done, start algo driver.
    equi_digit0(eq, 0);
    equi_clearslots(eq);
    for r in 1..p.k {
        if (r & 1) != 0 {
            equi_digitodd(eq, r, 0)
        } else {
            equi_digiteven(eq, r, 0)
        };
        equi_clearslots(eq);
    }
    // Review Note: nsols is increased here, but only if the solution passes the strictly ordered check.
    // With 256 nonces, we get to around 6/9 digits strictly ordered.
    equi_digitK(eq, 0);

    let solutions = {
        let nsols = equi_nsols(eq);
        let sols = equi_sols(eq);
        let solutions = slice::from_raw_parts(sols, nsols);
        let solution_len = 1 << p.k;

        solutions
            .iter()
            .map(|solution| slice::from_raw_parts(*solution, solution_len).to_vec())
            .collect::<Vec<_>>()
    };

    equi_free(eq);

    solutions
}

/// Performs multiple equihash solver runs with equihash parameters `200, 9`, initialising the hash with
/// the supplied partial `input`. Between each run, generates a new nonce of length `N` using the
/// `next_nonce` function.
///
/// Returns zero or more solutions.
pub fn solve_200_9<const N: usize>(
    input: &[u8],
    mut next_nonce: impl FnMut() -> Option<[u8; N]>,
) -> Vec<Vec<u32>> {
    let p = verify::Params::new(200, 9).expect("should be valid");
    let mut state = verify::initialise_state(p.n, p.k, p.hash_output());
    state.update(input);

    loop {
        let nonce = match next_nonce() {
            Some(nonce) => nonce,
            None => break vec![],
        };

        let mut curr_state = state.clone();
        curr_state.update(&nonce);

        // SAFETY: the parameters 200,9 match the hard-coded parameters in the C++ code.
        #[allow(unsafe_code)]
        let solutions = unsafe { worker(p, &curr_state) };
        if !solutions.is_empty() {
            break solutions;
        }
    }
}

/// Performs multiple equihash solver runs with equihash parameters `200, 9`, initialising the hash with
/// the supplied partial `input`. Between each run, generates a new nonce of length `N` using the
/// `next_nonce` function.
///
/// Returns zero or more compressed solutions.
pub fn solve_200_9_compressed<const N: usize>(
    input: &[u8],
    next_nonce: impl FnMut() -> Option<[u8; N]>,
) -> Vec<Vec<u8>> {
    // https://github.com/zcash/zcash/blob/6fdd9f1b81d3b228326c9826fa10696fc516444b/src/pow/tromp/equi.h#L34
    const DIGIT_BITS: usize = 200 / (9 + 1);
    let solutions = solve_200_9(input, next_nonce);

    solutions
        .iter()
        .map(|solution| get_minimal_from_indices(solution, DIGIT_BITS))
        .collect()
}

// Rough translation of GetMinimalFromIndices() from:
// https://github.com/zcash/zcash/blob/6fdd9f1b81d3b228326c9826fa10696fc516444b/src/crypto/equihash.cpp#L130-L145
fn get_minimal_from_indices(indices: &[u32], digit_bits: usize) -> Vec<u8> {
    let index_bytes = (u32::BITS / 8) as usize;
    let digit_bytes = ((digit_bits + 1) + 7) / 8;
    assert!(digit_bytes <= index_bytes);

    let len_indices = indices.len() * index_bytes;
    let min_len = (digit_bits + 1) * len_indices / (8 * index_bytes);
    let byte_pad = index_bytes - digit_bytes;

    // Rough translation of EhIndexToArray(index, array_pointer) from:
    // https://github.com/zcash/zcash/blob/6fdd9f1b81d3b228326c9826fa10696fc516444b/src/crypto/equihash.cpp#L123-L128
    //
    // Big-endian so that lexicographic array comparison is equivalent to integer comparison.
    let array: Vec<u8> = indices
        .iter()
        .flat_map(|index| index.to_be_bytes())
        .collect();
    assert_eq!(array.len(), len_indices);

    compress_array(array, min_len, digit_bits + 1, byte_pad)
}

// Rough translation of CompressArray() from:
// https://github.com/zcash/zcash/blob/6fdd9f1b81d3b228326c9826fa10696fc516444b/src/crypto/equihash.cpp#L39-L76
fn compress_array(array: Vec<u8>, out_len: usize, bit_len: usize, byte_pad: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(out_len);

    let index_bytes = (u32::BITS / 8) as usize;
    assert!(bit_len >= 8);
    assert!(8 * index_bytes >= 7 + bit_len);

    let in_width: usize = (bit_len + 7) / 8 + byte_pad;
    assert!(out_len == bit_len * array.len() / (8 * in_width));

    let bit_len_mask: u32 = (1 << (bit_len as u32)) - 1;

    // The acc_bits least-significant bits of acc_value represent a bit sequence
    // in big-endian order.
    let mut acc_bits: usize = 0;
    let mut acc_value: u32 = 0;

    let mut j: usize = 0;
    for _i in 0..out_len {
        // When we have fewer than 8 bits left in the accumulator, read the next
        // input element.
        if acc_bits < 8 {
            acc_value <<= bit_len;
            for x in byte_pad..in_width {
                acc_value = acc_value
                    | ((
                        // Apply bit_len_mask across byte boundaries
                        array[j + x] & (bit_len_mask >> (8 * (in_width - x - 1))) as u8
                    ) << (8 * (in_width - x - 1))) as u32; // Big-endian
            }
            j += in_width;
            acc_bits += bit_len;
        }

        acc_bits -= 8;
        out.push((acc_value >> acc_bits) as u8);
    }

    out
}

#[cfg(test)]
mod tests {
    use super::solve_200_9_compressed;

    #[test]
    #[allow(clippy::print_stdout)]
    fn run_solver() {
        let input = b"Equihash is an asymmetric PoW based on the Generalised Birthday problem.";
        let mut nonce: [u8; 32] = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ];
        let mut nonces = 0..=u16::MAX;

        let solutions = solve_200_9_compressed(input, || {
            let variable_nonce = nonces.next()?;
            println!("Using variable nonce [0..2] of {}", variable_nonce);

            let variable_nonce = variable_nonce.to_be_bytes();
            nonce[0] = variable_nonce[0];
            nonce[1] = variable_nonce[1];

            Some(nonce)
        });

        if solutions.is_empty() {
            println!("Found no solutions");
        } else {
            println!("Found {} solutions:", solutions.len());
            for solution in solutions {
                println!("- {:?}", solution);
                crate::is_valid_solution(200, 9, input, &nonce, &solution).unwrap_or_else(
                    |error| {
                        panic!(
                            "unexpected invalid equihash 200, 9 solution:\n\
                             error: {error:?}\n\
                             input: {input:?}\n\
                             nonce: {nonce:?}\n\
                             solution: {solution:?}"
                        )
                    },
                );
            }
        }
    }
}
