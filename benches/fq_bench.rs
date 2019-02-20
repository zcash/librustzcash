#![feature(test)]

extern crate test;

use jubjub::*;
use test::Bencher;

#[bench]
fn bench_mul_assign(bencher: &mut Bencher) {
    let mut n = Fq::one();
    let b = -Fq::one();
    bencher.iter(move || {
        n *= &b;
    });
}

#[bench]
fn bench_sub_assign(bencher: &mut Bencher) {
    let mut n = Fq::one();
    let b = -Fq::one();
    bencher.iter(move || {
        n -= &b;
    });
}

#[bench]
fn bench_add_assign(bencher: &mut Bencher) {
    let mut n = Fq::one();
    let b = -Fq::one();
    bencher.iter(move || {
        n += &b;
    });
}

#[bench]
fn bench_square_assign(bencher: &mut Bencher) {
    let n = Fq::one();
    bencher.iter(move || n.square());
}

#[bench]
fn bench_invert_nonzero(bencher: &mut Bencher) {
    let n = Fq::one();
    bencher.iter(move || n.invert_nonzero());
}

#[bench]
fn bench_sqrt_vartime(bencher: &mut Bencher) {
    let n = Fq::one().double().double();
    bencher.iter(move || n.sqrt_vartime());
}
