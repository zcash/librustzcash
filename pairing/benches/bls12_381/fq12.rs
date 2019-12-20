use criterion::{criterion_group, Criterion};
use rand_core::SeedableRng;
use rand_xorshift::XorShiftRng;
use std::ops::{AddAssign, MulAssign, SubAssign};

use ff::Field;
use pairing::bls12_381::*;

fn bench_fq12_add_assign(c: &mut Criterion) {
    const SAMPLES: usize = 1000;

    let mut rng = XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);

    let v: Vec<(Fq12, Fq12)> = (0..SAMPLES)
        .map(|_| (Fq12::random(&mut rng), Fq12::random(&mut rng)))
        .collect();

    let mut count = 0;
    c.bench_function("Fq12::add_assign", |b| {
        b.iter(|| {
            let mut tmp = v[count].0;
            tmp.add_assign(&v[count].1);
            count = (count + 1) % SAMPLES;
            tmp
        })
    });
}

fn bench_fq12_sub_assign(c: &mut Criterion) {
    const SAMPLES: usize = 1000;

    let mut rng = XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);

    let v: Vec<(Fq12, Fq12)> = (0..SAMPLES)
        .map(|_| (Fq12::random(&mut rng), Fq12::random(&mut rng)))
        .collect();

    let mut count = 0;
    c.bench_function("Fq12::sub_assign", |b| {
        b.iter(|| {
            let mut tmp = v[count].0;
            tmp.sub_assign(&v[count].1);
            count = (count + 1) % SAMPLES;
            tmp
        })
    });
}

fn bench_fq12_mul_assign(c: &mut Criterion) {
    const SAMPLES: usize = 1000;

    let mut rng = XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);

    let v: Vec<(Fq12, Fq12)> = (0..SAMPLES)
        .map(|_| (Fq12::random(&mut rng), Fq12::random(&mut rng)))
        .collect();

    let mut count = 0;
    c.bench_function("Fq12::mul_assign", |b| {
        b.iter(|| {
            let mut tmp = v[count].0;
            tmp.mul_assign(&v[count].1);
            count = (count + 1) % SAMPLES;
            tmp
        })
    });
}

fn bench_fq12_squaring(c: &mut Criterion) {
    const SAMPLES: usize = 1000;

    let mut rng = XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);

    let v: Vec<Fq12> = (0..SAMPLES).map(|_| Fq12::random(&mut rng)).collect();

    let mut count = 0;
    c.bench_function("Fq12::square", |b| {
        b.iter(|| {
            let tmp = v[count].square();
            count = (count + 1) % SAMPLES;
            tmp
        })
    });
}

fn bench_fq12_invert(c: &mut Criterion) {
    const SAMPLES: usize = 1000;

    let mut rng = XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);

    let v: Vec<Fq12> = (0..SAMPLES).map(|_| Fq12::random(&mut rng)).collect();

    let mut count = 0;
    c.bench_function("Fq12::invert", |b| {
        b.iter(|| {
            let tmp = v[count].invert();
            count = (count + 1) % SAMPLES;
            tmp
        })
    });
}

criterion_group!(
    benches,
    bench_fq12_add_assign,
    bench_fq12_sub_assign,
    bench_fq12_mul_assign,
    bench_fq12_squaring,
    bench_fq12_invert,
);
