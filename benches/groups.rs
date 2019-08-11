#[macro_use]
extern crate criterion;

extern crate bls12_381;
use bls12_381::*;

use criterion::{black_box, Criterion};

fn criterion_benchmark(c: &mut Criterion) {
    // G1Affine
    {
        let name = "G1Affine";
        let a = G1Affine::generator();
        c.bench_function(&format!("{} check on curve", name), move |b| {
            b.iter(|| black_box(a).is_on_curve())
        });
    }

    // G1Projective
    {
        let name = "G1Projective";
        let a = G1Projective::generator();
        c.bench_function(&format!("{} check on curve", name), move |b| {
            b.iter(|| black_box(a).is_on_curve())
        });
    }

    // G2Affine
    {
        let name = "G2Affine";
        let a = G2Affine::generator();
        c.bench_function(&format!("{} check on curve", name), move |b| {
            b.iter(|| black_box(a).is_on_curve())
        });
    }

    // G2Projective
    {
        let name = "G2Projective";
        let a = G2Projective::generator();
        c.bench_function(&format!("{} check on curve", name), move |b| {
            b.iter(|| black_box(a).is_on_curve())
        });
    }
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
