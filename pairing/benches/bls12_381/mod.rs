pub(crate) mod ec;
pub(crate) mod fq;
pub(crate) mod fq12;
pub(crate) mod fq2;
pub(crate) mod fr;

use criterion::{criterion_group, Criterion};
use rand_core::SeedableRng;
use rand_xorshift::XorShiftRng;

use group::Group;
use pairing::bls12_381::*;
use pairing::{Engine, MillerLoopResult, MultiMillerLoop, PairingCurveAffine};

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
            let tmp = G2Prepared::from(G2Affine::from(v[count]));
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

    let v: Vec<(G1Affine, G2Prepared)> = (0..SAMPLES)
        .map(|_| {
            (
                G1Affine::from(G1::random(&mut rng)),
                G2Affine::from(G2::random(&mut rng)).into(),
            )
        })
        .collect();

    let mut count = 0;
    c.bench_function("Miller loop", |b| {
        b.iter(|| {
            let tmp = Bls12::multi_miller_loop(&[(&v[count].0, &v[count].1)]);
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
                G1Affine::from(G1::random(&mut rng)),
                G2Affine::from(G2::random(&mut rng)).into(),
            )
        })
        .map(|(ref p, ref q)| Bls12::multi_miller_loop(&[(p, q)]))
        .collect();

    let mut count = 0;
    c.bench_function("Final exponentiation", |b| {
        b.iter(|| {
            let tmp = v[count].final_exponentiation();
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

    let v: Vec<(G1Affine, G2Affine)> = (0..SAMPLES)
        .map(|_| (G1::random(&mut rng).into(), G2::random(&mut rng).into()))
        .collect();

    let mut count = 0;
    c.bench_function("Full pairing", |b| {
        b.iter(|| {
            let tmp = Bls12::pairing(&v[count].0, &v[count].1);
            count = (count + 1) % SAMPLES;
            tmp
        })
    });
}

criterion_group!(
    benches,
    bench_pairing_g2_preparation,
    bench_pairing_miller_loop,
    bench_pairing_final_exponentiation,
    bench_pairing_full,
);
