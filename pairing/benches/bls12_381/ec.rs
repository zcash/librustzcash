pub(crate) mod g1 {
    use criterion::{criterion_group, Criterion};
    use rand_core::SeedableRng;
    use rand_xorshift::XorShiftRng;
    use std::ops::AddAssign;

    use ff::Field;
    use group::CurveProjective;
    use pairing::bls12_381::*;

    fn bench_g1_mul_assign(c: &mut Criterion) {
        const SAMPLES: usize = 1000;

        let mut rng = XorShiftRng::from_seed([
            0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06,
            0xbc, 0xe5,
        ]);

        let v: Vec<(G1, Fr)> = (0..SAMPLES)
            .map(|_| (G1::random(&mut rng), Fr::random(&mut rng)))
            .collect();

        let mut count = 0;
        c.bench_function("G1::mul_assign", |b| {
            b.iter(|| {
                let mut tmp = v[count].0;
                tmp.mul_assign(v[count].1);
                count = (count + 1) % SAMPLES;
                tmp
            })
        });
    }

    fn bench_g1_add_assign(c: &mut Criterion) {
        const SAMPLES: usize = 1000;

        let mut rng = XorShiftRng::from_seed([
            0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06,
            0xbc, 0xe5,
        ]);

        let v: Vec<(G1, G1)> = (0..SAMPLES)
            .map(|_| (G1::random(&mut rng), G1::random(&mut rng)))
            .collect();

        let mut count = 0;
        c.bench_function("G1::add_assign", |b| {
            b.iter(|| {
                let mut tmp = v[count].0;
                tmp.add_assign(&v[count].1);
                count = (count + 1) % SAMPLES;
                tmp
            })
        });
    }

    fn bench_g1_add_assign_mixed(c: &mut Criterion) {
        const SAMPLES: usize = 1000;

        let mut rng = XorShiftRng::from_seed([
            0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06,
            0xbc, 0xe5,
        ]);

        let v: Vec<(G1, G1Affine)> = (0..SAMPLES)
            .map(|_| (G1::random(&mut rng), G1::random(&mut rng).into()))
            .collect();

        let mut count = 0;
        c.bench_function("G1::add_assign_mixed", |b| {
            b.iter(|| {
                let mut tmp = v[count].0;
                tmp.add_assign(&v[count].1);
                count = (count + 1) % SAMPLES;
                tmp
            })
        });
    }

    criterion_group!(
        benches,
        bench_g1_add_assign,
        bench_g1_add_assign_mixed,
        bench_g1_mul_assign,
    );
}

pub(crate) mod g2 {
    use criterion::{criterion_group, Criterion};
    use rand_core::SeedableRng;
    use rand_xorshift::XorShiftRng;
    use std::ops::AddAssign;

    use ff::Field;
    use group::CurveProjective;
    use pairing::bls12_381::*;

    fn bench_g2_mul_assign(c: &mut Criterion) {
        const SAMPLES: usize = 1000;

        let mut rng = XorShiftRng::from_seed([
            0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06,
            0xbc, 0xe5,
        ]);

        let v: Vec<(G2, Fr)> = (0..SAMPLES)
            .map(|_| (G2::random(&mut rng), Fr::random(&mut rng)))
            .collect();

        let mut count = 0;
        c.bench_function("G2::mul_assign", |b| {
            b.iter(|| {
                let mut tmp = v[count].0;
                tmp.mul_assign(v[count].1);
                count = (count + 1) % SAMPLES;
                tmp
            })
        });
    }

    fn bench_g2_add_assign(c: &mut Criterion) {
        const SAMPLES: usize = 1000;

        let mut rng = XorShiftRng::from_seed([
            0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06,
            0xbc, 0xe5,
        ]);

        let v: Vec<(G2, G2)> = (0..SAMPLES)
            .map(|_| (G2::random(&mut rng), G2::random(&mut rng)))
            .collect();

        let mut count = 0;
        c.bench_function("G2::add_assign", |b| {
            b.iter(|| {
                let mut tmp = v[count].0;
                tmp.add_assign(&v[count].1);
                count = (count + 1) % SAMPLES;
                tmp
            })
        });
    }

    fn bench_g2_add_assign_mixed(c: &mut Criterion) {
        const SAMPLES: usize = 1000;

        let mut rng = XorShiftRng::from_seed([
            0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06,
            0xbc, 0xe5,
        ]);

        let v: Vec<(G2, G2Affine)> = (0..SAMPLES)
            .map(|_| (G2::random(&mut rng), G2::random(&mut rng).into()))
            .collect();

        let mut count = 0;
        c.bench_function("G2::add_assign_mixed", |b| {
            b.iter(|| {
                let mut tmp = v[count].0;
                tmp.add_assign(&v[count].1);
                count = (count + 1) % SAMPLES;
                tmp
            })
        });
    }

    criterion_group!(
        benches,
        bench_g2_add_assign,
        bench_g2_add_assign_mixed,
        bench_g2_mul_assign,
    );
}
