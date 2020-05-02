use criterion::{criterion_group, Criterion};
use rand_core::SeedableRng;
use rand_xorshift::XorShiftRng;
use std::ops::{AddAssign, MulAssign, Neg, SubAssign};

use ff::{Field, PrimeField};
use pairing::bls12_381::*;

fn bench_fr_add_assign(c: &mut Criterion) {
    const SAMPLES: usize = 1000;

    let mut rng = XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);

    let v: Vec<(Fr, Fr)> = (0..SAMPLES)
        .map(|_| (Fr::random(&mut rng), Fr::random(&mut rng)))
        .collect();

    let mut count = 0;
    c.bench_function("Fr::add_assign", |b| {
        b.iter(|| {
            let mut tmp = v[count].0;
            tmp.add_assign(&v[count].1);
            count = (count + 1) % SAMPLES;
            tmp
        })
    });
}

fn bench_fr_sub_assign(c: &mut Criterion) {
    const SAMPLES: usize = 1000;

    let mut rng = XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);

    let v: Vec<(Fr, Fr)> = (0..SAMPLES)
        .map(|_| (Fr::random(&mut rng), Fr::random(&mut rng)))
        .collect();

    let mut count = 0;
    c.bench_function("Fr::sub_assign", |b| {
        b.iter(|| {
            let mut tmp = v[count].0;
            tmp.sub_assign(&v[count].1);
            count = (count + 1) % SAMPLES;
            tmp
        })
    });
}

fn bench_fr_mul_assign(c: &mut Criterion) {
    const SAMPLES: usize = 1000;

    let mut rng = XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);

    let v: Vec<(Fr, Fr)> = (0..SAMPLES)
        .map(|_| (Fr::random(&mut rng), Fr::random(&mut rng)))
        .collect();

    let mut count = 0;
    c.bench_function("Fr::mul_assign", |b| {
        b.iter(|| {
            let mut tmp = v[count].0;
            tmp.mul_assign(&v[count].1);
            count = (count + 1) % SAMPLES;
            tmp
        })
    });
}

fn bench_fr_square(c: &mut Criterion) {
    const SAMPLES: usize = 1000;

    let mut rng = XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);

    let v: Vec<Fr> = (0..SAMPLES).map(|_| Fr::random(&mut rng)).collect();

    let mut count = 0;
    c.bench_function("Fr::square", |b| {
        b.iter(|| {
            let tmp = v[count].square();
            count = (count + 1) % SAMPLES;
            tmp
        })
    });
}

fn bench_fr_invert(c: &mut Criterion) {
    const SAMPLES: usize = 1000;

    let mut rng = XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);

    let v: Vec<Fr> = (0..SAMPLES).map(|_| Fr::random(&mut rng)).collect();

    let mut count = 0;
    c.bench_function("Fr::invert", |b| {
        b.iter(|| {
            count = (count + 1) % SAMPLES;
            v[count].invert()
        })
    });
}

fn bench_fr_neg(c: &mut Criterion) {
    const SAMPLES: usize = 1000;

    let mut rng = XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);

    let v: Vec<Fr> = (0..SAMPLES).map(|_| Fr::random(&mut rng)).collect();

    let mut count = 0;
    c.bench_function("Fr::neg", |b| {
        b.iter(|| {
            let tmp = v[count].neg();
            count = (count + 1) % SAMPLES;
            tmp
        })
    });
}

fn bench_fr_sqrt(c: &mut Criterion) {
    const SAMPLES: usize = 1000;

    let mut rng = XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);

    let v: Vec<Fr> = (0..SAMPLES)
        .map(|_| Fr::random(&mut rng).square())
        .collect();

    let mut count = 0;
    c.bench_function("Fr::sqrt", |b| {
        b.iter(|| {
            count = (count + 1) % SAMPLES;
            v[count].sqrt()
        })
    });
}

fn bench_fr_to_repr(c: &mut Criterion) {
    const SAMPLES: usize = 1000;

    let mut rng = XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);

    let v: Vec<Fr> = (0..SAMPLES).map(|_| Fr::random(&mut rng)).collect();

    let mut count = 0;
    c.bench_function("Fr::to_repr", |b| {
        b.iter(|| {
            count = (count + 1) % SAMPLES;
            v[count].to_repr()
        })
    });
}

fn bench_fr_from_repr(c: &mut Criterion) {
    const SAMPLES: usize = 1000;

    let mut rng = XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);

    let v: Vec<FrRepr> = (0..SAMPLES)
        .map(|_| Fr::random(&mut rng).to_repr())
        .collect();

    let mut count = 0;
    c.bench_function("Fr::from_repr", |b| {
        b.iter(|| {
            count = (count + 1) % SAMPLES;
            Fr::from_repr(v[count])
        })
    });
}

criterion_group!(
    benches,
    bench_fr_add_assign,
    bench_fr_sub_assign,
    bench_fr_mul_assign,
    bench_fr_square,
    bench_fr_invert,
    bench_fr_neg,
    bench_fr_sqrt,
    bench_fr_to_repr,
    bench_fr_from_repr,
);
