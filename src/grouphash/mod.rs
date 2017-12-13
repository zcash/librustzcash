// 64 zeros, substitute with random future determined string like a blockhash, or randomness beacom
const U: [u8; 64] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

// option to return None or point
fn grouphash<E: JubjubEngine>(tag: &[u8], params: &E::Params) -> Option<montgomery::Point<E, PrimeOrder>> {
    // Check to see that scalar field is 255 bits
    assert! (E::Fr::NUM_BITS == 255);

    // Perform hash, get random 32-byte string
    let mut h = Blake2s::new_keyed(&[], 32);
    h.process(&U);
    h.process(tag);
    let h = h.fixed_result();

    // Take first unset first bit of hash
    let sign = (h[0] >> 7) == 1;
    h[0] &= 0b01111111;

    // cast to prime field representation
    let mut x0 = <E::Fr as PrimeField>::Repr::default();
    x0.read_be(&h[..]).unwrap();

    match E::Fr::from_repr(x0) {
        Ok(x0) => {
            let tmp = montgomery::Point::get_for_x(x0, sign, params).mul_by_cofactor(params);
            if tmp == mongomery::Point.zero() { None } else { Some(tmp) };
        }
        Err(_) => None
    }
}
