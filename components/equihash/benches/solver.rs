//! Measures complete CPU solver runs for four fixed nonces.
//!
//! Run with `cargo bench -p equihash --features solver --bench solver`.
//! Construction, solving, compression, and cleanup are timed.

use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};

const INPUT: &[u8] = b"Equihash is an asymmetric PoW based on the Generalised Birthday problem.";

fn bench_solver(c: &mut Criterion) {
    let mut group = c.benchmark_group("equihash-solver");
    group.throughput(Throughput::Elements(1));
    // Each iteration performs a full memory-intensive solver run.
    group.sample_size(10);
    for nonce_index in 0..4u32 {
        let mut nonce = [0u8; 32];
        nonce[..4].copy_from_slice(&nonce_index.to_le_bytes());
        group.bench_with_input(
            BenchmarkId::from_parameter(nonce_index),
            &nonce,
            |b, nonce| {
                b.iter(|| {
                    let mut next_nonce = Some(*black_box(nonce));
                    equihash::tromp::solve_200_9(black_box(INPUT), || next_nonce.take());
                });
            },
        );
    }
    group.finish();
}

criterion_group!(benches, bench_solver);
criterion_main!(benches);
