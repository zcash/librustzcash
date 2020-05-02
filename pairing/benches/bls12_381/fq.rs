use criterion::{criterion_group, Criterion};
use rand_core::SeedableRng;
use rand_xorshift::XorShiftRng;
use std::ops::{AddAssign, MulAssign, Neg, SubAssign};

use ff::{Field, PrimeField};
use pairing::bls12_381::*;

fn bench_fq_add_assign(c: &mut Criterion) {
    const SAMPLES: usize = 1000;

    let mut rng = XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);

    let v: Vec<(Fq, Fq)> = (0..SAMPLES)
        .map(|_| (Fq::random(&mut rng), Fq::random(&mut rng)))
        .collect();

    let mut count = 0;
    c.bench_function("Fq::add_assign", |b| {
        b.iter(|| {
            let mut tmp = v[count].0;
            tmp.add_assign(&v[count].1);
            count = (count + 1) % SAMPLES;
            tmp
        })
    });
}

fn bench_fq_sub_assign(c: &mut Criterion) {
    const SAMPLES: usize = 1000;

    let mut rng = XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);

    let v: Vec<(Fq, Fq)> = (0..SAMPLES)
        .map(|_| (Fq::random(&mut rng), Fq::random(&mut rng)))
        .collect();

    let mut count = 0;
    c.bench_function("Fq::sub_assign", |b| {
        b.iter(|| {
            let mut tmp = v[count].0;
            tmp.sub_assign(&v[count].1);
            count = (count + 1) % SAMPLES;
            tmp
        })
    });
}

fn bench_fq_mul_assign(c: &mut Criterion) {
    const SAMPLES: usize = 1000;

    let mut rng = XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);

    let v: Vec<(Fq, Fq)> = (0..SAMPLES)
        .map(|_| (Fq::random(&mut rng), Fq::random(&mut rng)))
        .collect();

    let mut count = 0;
    c.bench_function("Fq::mul_assign", |b| {
        b.iter(|| {
            let mut tmp = v[count].0;
            tmp.mul_assign(&v[count].1);
            count = (count + 1) % SAMPLES;
            tmp
        })
    });
}

fn bench_fq_square(c: &mut Criterion) {
    const SAMPLES: usize = 1000;

    let mut rng = XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);

    let v: Vec<Fq> = (0..SAMPLES).map(|_| Fq::random(&mut rng)).collect();

    let mut count = 0;
    c.bench_function("Fq::square", |b| {
        b.iter(|| {
            let tmp = v[count].square();
            count = (count + 1) % SAMPLES;
            tmp
        })
    });
}

fn bench_fq_invert(c: &mut Criterion) {
    const SAMPLES: usize = 1000;

    let mut rng = XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);

    let v: Vec<Fq> = (0..SAMPLES).map(|_| Fq::random(&mut rng)).collect();

    let mut count = 0;
    c.bench_function("Fq::invert", |b| {
        b.iter(|| {
            count = (count + 1) % SAMPLES;
            v[count].invert()
        })
    });
}

fn bench_fq_neg(c: &mut Criterion) {
    const SAMPLES: usize = 1000;

    let mut rng = XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);

    let v: Vec<Fq> = (0..SAMPLES).map(|_| Fq::random(&mut rng)).collect();

    let mut count = 0;
    c.bench_function("Fq::neg", |b| {
        b.iter(|| {
            let tmp = v[count].neg();
            count = (count + 1) % SAMPLES;
            tmp
        })
    });
}

fn bench_fq_sqrt(c: &mut Criterion) {
    const SAMPLES: usize = 1000;

    let mut rng = XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);

    let v: Vec<Fq> = (0..SAMPLES)
        .map(|_| Fq::random(&mut rng).square())
        .collect();

    let mut count = 0;
    c.bench_function("Fq::sqrt", |b| {
        b.iter(|| {
            count = (count + 1) % SAMPLES;
            v[count].sqrt()
        })
    });
}

fn bench_fq_to_repr(c: &mut Criterion) {
    const SAMPLES: usize = 1000;

    let mut rng = XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);

    let v: Vec<Fq> = (0..SAMPLES).map(|_| Fq::random(&mut rng)).collect();

    let mut count = 0;
    c.bench_function("Fq::to_repr", |b| {
        b.iter(|| {
            count = (count + 1) % SAMPLES;
            v[count].to_repr()
        })
    });
}

fn bench_fq_from_repr(c: &mut Criterion) {
    const SAMPLES: usize = 1000;

    let mut rng = XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);

    let v: Vec<FqRepr> = (0..SAMPLES)
        .map(|_| Fq::random(&mut rng).to_repr())
        .collect();

    let mut count = 0;
    c.bench_function("Fq::from_repr", |b| {
        b.iter(|| {
            count = (count + 1) % SAMPLES;
            Fq::from_repr(v[count])
        })
    });
}

criterion_group!(
    benches,
    bench_fq_add_assign,
    bench_fq_sub_assign,
    bench_fq_mul_assign,
    bench_fq_square,
    bench_fq_invert,
    bench_fq_neg,
    bench_fq_sqrt,
    bench_fq_to_repr,
    bench_fq_from_repr,
);
