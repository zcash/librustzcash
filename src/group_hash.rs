use jubjub::*;
use pairing::*;
use blake2::{Blake2s};
use digest::{FixedOutput, Input};

/// Produces an (x, y) pair (Montgomery) for a
/// random point in the Jubjub curve. The point
/// is guaranteed to be prime order and not the
/// identity.
pub fn group_hash<E: JubjubEngine>(
    tag: &[u8],
    params: &E::Params
) -> Option<edwards::Point<E, PrimeOrder>>
{
    // Check to see that scalar field is 255 bits
    assert!(E::Fr::NUM_BITS == 255);

    let mut h = Blake2s::new_keyed(&[], 32);
    h.process(tag);
    let mut h = h.fixed_result().to_vec();
    assert!(h.len() == 32);

    // Take first/unset first bit of hash
    let s = h[0] >> 7 == 1; // get s
    h[0] &= 0b0111_1111; // unset s from h

    // cast to prime field representation
    let mut y0 = <E::Fr as PrimeField>::Repr::default();
    y0.read_be(&h[..]).expect("hash is sufficiently large");

    if let Ok(y0) = E::Fr::from_repr(y0) {
        if let Some(p) = edwards::Point::<E, _>::get_for_y(y0, s, params) {
            // Enter into the prime order subgroup
            let p = p.mul_by_cofactor(params);

            if p != edwards::Point::zero() {
                Some(p)
            } else {
                None
            }
        } else {
            None
        }
    } else {
        None
    }
}
