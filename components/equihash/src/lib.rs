//! The Equihash Proof-of-Work function.

mod verify;

pub use verify::{
    is_valid_solution, is_valid_solution_iterative, is_valid_solution_recursive, Error,
};
