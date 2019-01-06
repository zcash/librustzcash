#![feature(test)]

extern crate jubjub;
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
fn bench_pow_q_minus_2(bencher: &mut Bencher) {
    let n = Fq::one();
    bencher.iter(move || n.pow_q_minus_2());
}
