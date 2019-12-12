#![feature(test)]

extern crate test;

use jubjub::*;
use test::Bencher;

// Non-Niels

#[bench]
fn bench_point_doubling(bencher: &mut Bencher) {
    let a = ExtendedPoint::identity();
    bencher.iter(move || a.double());
}

#[bench]
fn bench_point_addition(bencher: &mut Bencher) {
    let a = ExtendedPoint::identity();
    let b = -ExtendedPoint::identity();
    bencher.iter(move || a + b);
}

#[bench]
fn bench_point_subtraction(bencher: &mut Bencher) {
    let a = ExtendedPoint::identity();
    let b = -ExtendedPoint::identity();
    bencher.iter(move || a + b);
}

// Niels

#[bench]
fn bench_cached_point_addition(bencher: &mut Bencher) {
    let a = ExtendedPoint::identity();
    let b = ExtendedPoint::identity().to_niels();
    bencher.iter(move || &a + &b);
}

#[bench]
fn bench_cached_affine_point_subtraction(bencher: &mut Bencher) {
    let a = ExtendedPoint::identity();
    let b = AffinePoint::identity().to_niels();
    bencher.iter(move || &a + &b);
}

#[bench]
fn bench_cached_point_subtraction(bencher: &mut Bencher) {
    let a = ExtendedPoint::identity();
    let b = ExtendedPoint::identity().to_niels();
    bencher.iter(move || &a + &b);
}

#[bench]
fn bench_cached_affine_point_addition(bencher: &mut Bencher) {
    let a = ExtendedPoint::identity();
    let b = AffinePoint::identity().to_niels();
    bencher.iter(move || &a + &b);
}
