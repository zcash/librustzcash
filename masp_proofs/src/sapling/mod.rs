//! Helpers for creating Sapling proofs.

use masp_primitives::asset_type::AssetType;

mod prover;
mod verifier;

pub use self::prover::SaplingProvingContext;
pub use self::verifier::SaplingVerificationContext;

// This function computes `value` in the exponent of the value commitment base
fn masp_compute_value_balance(asset_type: AssetType, value: i64) -> Option<jubjub::ExtendedPoint> {
    // Compute the absolute value (failing if -i64::MAX is
    // the value)
    let abs = match value.checked_abs() {
        Some(a) => a as u64,
        None => return None,
    };

    // Is it negative? We'll have to negate later if so.
    let is_negative = value.is_negative();

    // Compute it in the exponent
    let mut value_balance = asset_type.value_commitment_generator() * jubjub::Fr::from(abs);

    // Negate if necessary
    if is_negative {
        value_balance = -value_balance;
    }

    // Convert to unknown order point
    Some(value_balance.into())
}
