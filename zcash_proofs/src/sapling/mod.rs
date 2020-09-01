//! Helpers for creating Sapling proofs.

use zcash_primitives::{
    constants::VALUE_COMMITMENT_VALUE_GENERATOR, transaction::components::Amount,
};

mod prover;
mod verifier;

pub use self::prover::SaplingProvingContext;
pub use self::verifier::SaplingVerificationContext;

// This function computes `value` in the exponent of the value commitment base
fn compute_value_balance(value: Amount) -> Option<jubjub::ExtendedPoint> {
    // Compute the absolute value (failing if -i64::MAX is
    // the value)
    let abs = match i64::from(value).checked_abs() {
        Some(a) => a as u64,
        None => return None,
    };

    // Is it negative? We'll have to negate later if so.
    let is_negative = value.is_negative();

    // Compute it in the exponent
    let mut value_balance = VALUE_COMMITMENT_VALUE_GENERATOR * jubjub::Fr::from(abs);

    // Negate if necessary
    if is_negative {
        value_balance = -value_balance;
    }

    // Convert to unknown order point
    Some(value_balance.into())
}
