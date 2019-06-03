#![feature(test)]

extern crate test;

use jubjub::*;
use test::Bencher;

#[bench]
fn bench_mul_assign(bencher: &mut Bencher) {
    let mut n = Fr::one();
    let b = -Fr::one();
    bencher.iter(move || {
        n *= &b;
    });
}

#[bench]
fn bench_sub_assign(bencher: &mut Bencher) {
    let mut n = Fr::one();
    let b = -Fr::one();
    bencher.iter(move || {
        n -= &b;
    });
}

#[bench]
fn bench_add_assign(bencher: &mut Bencher) {
    let mut n = Fr::one();
    let b = -Fr::one();
    bencher.iter(move || {
        n += &b;
    });
}

#[bench]
fn bench_square_assign(bencher: &mut Bencher) {
    let n = Fr::one();
    bencher.iter(move || n.square());
}

#[bench]
fn bench_invert(bencher: &mut Bencher) {
    let n = Fr::one();
    bencher.iter(move || n.invert());
}

#[bench]
fn bench_sqrt(bencher: &mut Bencher) {
    let n = Fr::one().double().double();
    bencher.iter(move || n.sqrt());
}
