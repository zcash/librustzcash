pub(crate) mod ec;
pub(crate) mod fq;
pub(crate) mod fq12;
pub(crate) mod fq2;
pub(crate) mod fr;

use criterion::{criterion_group, Criterion};
use rand_core::SeedableRng;
use rand_xorshift::XorShiftRng;

use group::CurveProjective;
use pairing::bls12_381::*;
use pairing::{Engine, PairingCurveAffine};

fn bench_pairing_g1_preparation(c: &mut Criterion) {
    const SAMPLES: usize = 1000;

    let mut rng = XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);

    let v: Vec<G1> = (0..SAMPLES).map(|_| G1::random(&mut rng)).collect();

    let mut count = 0;
    c.bench_function("G1 preparation", |b| {
        b.iter(|| {
            let tmp = G1Affine::from(v[count]).prepare();
            count = (count + 1) % SAMPLES;
            tmp
        })
    });
}

fn bench_pairing_g2_preparation(c: &mut Criterion) {
    const SAMPLES: usize = 1000;

    let mut rng = XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);

    let v: Vec<G2> = (0..SAMPLES).map(|_| G2::random(&mut rng)).collect();

    let mut count = 0;
    c.bench_function("G2 preparation", |b| {
        b.iter(|| {
            let tmp = G2Affine::from(v[count]).prepare();
            count = (count + 1) % SAMPLES;
            tmp
        })
    });
}

fn bench_pairing_miller_loop(c: &mut Criterion) {
    const SAMPLES: usize = 1000;

    let mut rng = XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);

    let v: Vec<(G1Prepared, G2Prepared)> = (0..SAMPLES)
        .map(|_| {
            (
                G1Affine::from(G1::random(&mut rng)).prepare(),
                G2Affine::from(G2::random(&mut rng)).prepare(),
            )
        })
        .collect();

    let mut count = 0;
    c.bench_function("Miller loop", |b| {
        b.iter(|| {
            let tmp = Bls12::miller_loop(&[(&v[count].0, &v[count].1)]);
            count = (count + 1) % SAMPLES;
            tmp
        })
    });
}

fn bench_pairing_final_exponentiation(c: &mut Criterion) {
    const SAMPLES: usize = 1000;

    let mut rng = XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);

    let v: Vec<Fq12> = (0..SAMPLES)
        .map(|_| {
            (
                G1Affine::from(G1::random(&mut rng)).prepare(),
                G2Affine::from(G2::random(&mut rng)).prepare(),
            )
        })
        .map(|(ref p, ref q)| Bls12::miller_loop(&[(p, q)]))
        .collect();

    let mut count = 0;
    c.bench_function("Final exponentiation", |b| {
        b.iter(|| {
            let tmp = Bls12::final_exponentiation(&v[count]);
            count = (count + 1) % SAMPLES;
            tmp
        })
    });
}

fn bench_pairing_full(c: &mut Criterion) {
    const SAMPLES: usize = 1000;

    let mut rng = XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);

    let v: Vec<(G1, G2)> = (0..SAMPLES)
        .map(|_| (G1::random(&mut rng), G2::random(&mut rng)))
        .collect();

    let mut count = 0;
    c.bench_function("Full pairing", |b| {
        b.iter(|| {
            let tmp = Bls12::pairing(v[count].0, v[count].1);
            count = (count + 1) % SAMPLES;
            tmp
        })
    });
}

criterion_group!(
    benches,
    bench_pairing_g1_preparation,
    bench_pairing_g2_preparation,
    bench_pairing_miller_loop,
    bench_pairing_final_exponentiation,
    bench_pairing_full,
);
