use criterion::{criterion_group, Criterion};
use rand_core::SeedableRng;
use rand_xorshift::XorShiftRng;
use std::ops::{AddAssign, MulAssign, Neg, SubAssign};

use ff::{Field, PrimeField, PrimeFieldRepr, SqrtField};
use pairing::bls12_381::*;

fn bench_fr_repr_add_nocarry(c: &mut Criterion) {
    const SAMPLES: usize = 1000;

    let mut rng = XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);

    let v: Vec<(FrRepr, FrRepr)> = (0..SAMPLES)
        .map(|_| {
            let mut tmp1 = Fr::random(&mut rng).into_repr();
            let mut tmp2 = Fr::random(&mut rng).into_repr();
            // Shave a few bits off to avoid overflow.
            for _ in 0..3 {
                tmp1.div2();
                tmp2.div2();
            }
            (tmp1, tmp2)
        })
        .collect();

    let mut count = 0;
    c.bench_function("FrRepr::add_nocarry", |b| {
        b.iter(|| {
            let mut tmp = v[count].0;
            tmp.add_nocarry(&v[count].1);
            count = (count + 1) % SAMPLES;
            tmp
        })
    });
}

fn bench_fr_repr_sub_noborrow(c: &mut Criterion) {
    const SAMPLES: usize = 1000;

    let mut rng = XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);

    let v: Vec<(FrRepr, FrRepr)> = (0..SAMPLES)
        .map(|_| {
            let tmp1 = Fr::random(&mut rng).into_repr();
            let mut tmp2 = tmp1;
            // Ensure tmp2 is smaller than tmp1.
            for _ in 0..10 {
                tmp2.div2();
            }
            (tmp1, tmp2)
        })
        .collect();

    let mut count = 0;
    c.bench_function("FrRepr::sub_noborrow", |b| {
        b.iter(|| {
            let mut tmp = v[count].0;
            tmp.sub_noborrow(&v[count].1);
            count = (count + 1) % SAMPLES;
            tmp
        })
    });
}

fn bench_fr_repr_num_bits(c: &mut Criterion) {
    const SAMPLES: usize = 1000;

    let mut rng = XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);

    let v: Vec<FrRepr> = (0..SAMPLES)
        .map(|_| Fr::random(&mut rng).into_repr())
        .collect();

    let mut count = 0;
    c.bench_function("FrRepr::num_bits", |b| {
        b.iter(|| {
            let tmp = v[count].num_bits();
            count = (count + 1) % SAMPLES;
            tmp
        })
    });
}

fn bench_fr_repr_mul2(c: &mut Criterion) {
    const SAMPLES: usize = 1000;

    let mut rng = XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);

    let v: Vec<FrRepr> = (0..SAMPLES)
        .map(|_| Fr::random(&mut rng).into_repr())
        .collect();

    let mut count = 0;
    c.bench_function("FrRepr::mul2", |b| {
        b.iter(|| {
            let mut tmp = v[count];
            tmp.mul2();
            count = (count + 1) % SAMPLES;
            tmp
        })
    });
}

fn bench_fr_repr_div2(c: &mut Criterion) {
    const SAMPLES: usize = 1000;

    let mut rng = XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);

    let v: Vec<FrRepr> = (0..SAMPLES)
        .map(|_| Fr::random(&mut rng).into_repr())
        .collect();

    let mut count = 0;
    c.bench_function("FrRepr::div2", |b| {
        b.iter(|| {
            let mut tmp = v[count];
            tmp.div2();
            count = (count + 1) % SAMPLES;
            tmp
        })
    });
}

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

fn bench_fr_into_repr(c: &mut Criterion) {
    const SAMPLES: usize = 1000;

    let mut rng = XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);

    let v: Vec<Fr> = (0..SAMPLES).map(|_| Fr::random(&mut rng)).collect();

    let mut count = 0;
    c.bench_function("Fr::into_repr", |b| {
        b.iter(|| {
            count = (count + 1) % SAMPLES;
            v[count].into_repr()
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
        .map(|_| Fr::random(&mut rng).into_repr())
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
    bench_fr_repr_add_nocarry,
    bench_fr_repr_sub_noborrow,
    bench_fr_repr_num_bits,
    bench_fr_repr_mul2,
    bench_fr_repr_div2,
    bench_fr_add_assign,
    bench_fr_sub_assign,
    bench_fr_mul_assign,
    bench_fr_square,
    bench_fr_invert,
    bench_fr_neg,
    bench_fr_sqrt,
    bench_fr_into_repr,
    bench_fr_from_repr,
);
