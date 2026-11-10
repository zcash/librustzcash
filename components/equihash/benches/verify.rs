//! Measures `is_valid_solution` on a Zcash mainnet block header.
//!
//! Run with `cargo bench -p equihash --bench verify`.

use criterion::{Criterion, Throughput, black_box, criterion_group, criterion_main};

// The vector file also holds a Regtest header this benchmark does not use.
#[allow(dead_code)]
mod vectors {
    include!("../src/test_vectors/zcash.rs");
}
use vectors::{MAINNET_415000_HEADER, MAINNET_415000_NONCE, MAINNET_415000_SOLUTION};

fn bench_verify(c: &mut Criterion) {
    let header = hex::decode(MAINNET_415000_HEADER).unwrap();
    let nonce = hex::decode(MAINNET_415000_NONCE).unwrap();
    let solution = hex::decode(MAINNET_415000_SOLUTION).unwrap();
    let mut invalid = solution.clone();
    // Changes one index, so an early collision check fails.
    invalid[700] ^= 1;

    equihash::is_valid_solution(200, 9, &header, &nonce, &solution).expect("block 415000 is valid");
    equihash::is_valid_solution(200, 9, &header, &nonce, &invalid)
        .expect_err("mutated solution is invalid");

    let mut group = c.benchmark_group("equihash-verification");
    group.throughput(Throughput::Elements(1));
    for (case, solution) in [("valid", &solution), ("invalid", &invalid)] {
        group.bench_function(case, |b| {
            b.iter(|| {
                equihash::is_valid_solution(
                    200,
                    9,
                    black_box(&header),
                    black_box(&nonce),
                    black_box(solution),
                )
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_verify);
criterion_main!(benches);
