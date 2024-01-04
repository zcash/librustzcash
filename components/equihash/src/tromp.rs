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

        let solutions = unsafe { worker(p, &curr_state) };
        if !solutions.is_empty() {
            break solutions;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::solve_200_9;

    #[test]
    fn run_solver() {
        let input = b"Equihash is an asymmetric PoW based on the Generalised Birthday problem.";
        let mut nonce = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ];

        let solutions = solve_200_9(input, || {
            nonce[0] += 1;
            if nonce[0] == 0 {
                None
            } else {
                Some(nonce)
            }
        });

        if solutions.is_empty() {
            println!("Found no solutions");
        } else {
            println!("Found {} solutions:", solutions.len());
            for solution in solutions {
                println!("- {:?}", solution);
            }
        }
    }
}
