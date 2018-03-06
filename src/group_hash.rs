use jubjub::*;
use pairing::*;
use blake2_rfc::blake2s::Blake2s;

/// This is chosen to be some random string that we couldn't have anticipated when we designed
/// the algorithm, for rigidity purposes.
pub const FIRST_BLOCK: &'static [u8; 64] = b"0000000000000000002ffe76b973aabaff1d1557d79acf2c3795809c83caf580";

/// Produces an (x, y) pair (Montgomery) for a
/// random point in the Jubjub curve. The point
/// is guaranteed to be prime order and not the
/// identity.
pub fn group_hash<E: JubjubEngine>(
    tag: &[u8],
    personalization: &[u8],
    params: &E::Params
) -> Option<edwards::Point<E, PrimeOrder>>
{
    assert_eq!(personalization.len(), 8);

    // Check to see that scalar field is 255 bits
    assert!(E::Fr::NUM_BITS == 255);

    let mut h = Blake2s::with_params(32, &[], &[], personalization);
    h.update(FIRST_BLOCK);
    h.update(tag);
    let mut h = h.finalize().as_ref().to_vec();
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
