use criterion::criterion_main;
mod bls12_381;

criterion_main!(
    bls12_381::benches,
    bls12_381::ec::g1::benches,
    bls12_381::ec::g2::benches,
    bls12_381::fq::benches,
    bls12_381::fq12::benches,
    bls12_381::fq2::benches,
    bls12_381::fr::benches,
);
