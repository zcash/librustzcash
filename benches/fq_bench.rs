#![feature(test)]

extern crate test;
extern crate jubjub;

use std::ops::MulAssign;
use test::Bencher;
use jubjub::Fq;

#[bench]
fn bench_mul_assign(bencher: &mut Bencher) {
    let mut n = Fq::new([2, 2, 2, 2]);
    bencher.iter(move || {
        let tmp = n;
        n.mul_assign(&tmp);
    });
}

#[bench]
fn bench_square_assign(bencher: &mut Bencher) {
    let mut n = Fq::new([2, 2, 2, 2]);
    bencher.iter(move || {
        n.square_assign();
    });
}
