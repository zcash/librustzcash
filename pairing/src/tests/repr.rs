use ff::PrimeField;
use rand_core::SeedableRng;
use rand_xorshift::XorShiftRng;

pub fn random_repr_tests<P: PrimeField>() {
    random_encoding_tests::<P>();
    random_shr_tests::<P>();
}

fn random_encoding_tests<P: PrimeField>() {
    let mut rng = XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);

    for _ in 0..1000 {
        let r = P::random(&mut rng);

        let v = r.into_repr();
        let rdecoded = P::from_repr(v).unwrap();

        assert_eq!(r, rdecoded);
    }
}

fn random_shr_tests<P: PrimeField>() {
    let mut rng = XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);

    for _ in 0..100 {
        let r = P::random(&mut rng);

        for shift in 0..P::NUM_BITS {
            let r1 = r >> shift;

            // Doubling the shifted element inserts zeros on the right; re-shifting should
            // undo the doubling.
            let mut r2 = r1;
            for _ in 0..shift {
                r2 = r2.double();
            }
            r2 = r2 >> shift;

            assert_eq!(r1, r2);
        }

        assert_eq!(r >> P::NUM_BITS, P::zero());
    }
}
