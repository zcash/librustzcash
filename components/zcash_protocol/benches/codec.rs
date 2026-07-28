//! Compares the `Encodable`/`Decodable` trait path against the existing closure-passing
//! `Vector` combinators, on identical data producing identical bytes.
//!
//! Both paths are fully monomorphized static dispatch with no boxing, so the expectation is
//! parity. The benchmark exists to hold that expectation to account rather than assume it.

use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};

use zcash_encoding::{Decodable, Encodable, Vector};
use zcash_protocol::TxId;

fn sample(n: usize) -> Vec<TxId> {
    (0..n)
        .map(|i| {
            let mut b = [0u8; 32];
            b[0] = i as u8;
            b[1] = (i >> 8) as u8;
            TxId::from_bytes(b)
        })
        .collect()
}

fn bench_write(c: &mut Criterion) {
    let mut group = c.benchmark_group("write_vec_txid");
    for n in [1usize, 16, 256, 4096] {
        let items = sample(n);
        group.throughput(Throughput::Elements(n as u64));

        group.bench_with_input(BenchmarkId::new("combinator", n), &items, |b, items| {
            b.iter(|| {
                let mut out = Vec::with_capacity(items.len() * 32 + 9);
                Vector::write(&mut out, black_box(items), |w, e| TxId::write(e, w)).unwrap();
                black_box(out)
            })
        });

        group.bench_with_input(BenchmarkId::new("trait", n), &items, |b, items| {
            b.iter(|| {
                let mut out = Vec::with_capacity(items.len() * 32 + 9);
                Encodable::write(black_box(items), &mut out).unwrap();
                black_box(out)
            })
        });
    }
    group.finish();
}

fn bench_read(c: &mut Criterion) {
    let mut group = c.benchmark_group("read_vec_txid");
    for n in [1usize, 16, 256, 4096] {
        let items = sample(n);
        let mut bytes = Vec::new();
        Encodable::write(&items, &mut bytes).unwrap();
        group.throughput(Throughput::Elements(n as u64));

        group.bench_with_input(BenchmarkId::new("combinator", n), &bytes, |b, bytes| {
            b.iter(|| {
                let v: Vec<TxId> = Vector::read(black_box(&bytes[..]), |r| TxId::read(r)).unwrap();
                black_box(v)
            })
        });

        group.bench_with_input(BenchmarkId::new("trait", n), &bytes, |b, bytes| {
            b.iter(|| {
                let v = <Vec<TxId> as Decodable>::read(black_box(&bytes[..]), ()).unwrap();
                black_box(v)
            })
        });
    }
    group.finish();
}

/// `serialized_size` has a closed-form override for `Vec<T>`; check it is not accidentally
/// falling back to the byte-counting default, which would encode the whole value to measure it.
fn bench_serialized_size(c: &mut Criterion) {
    let mut group = c.benchmark_group("serialized_size_vec_txid");
    for n in [16usize, 4096] {
        let items = sample(n);
        group.bench_with_input(BenchmarkId::new("trait", n), &items, |b, items| {
            b.iter(|| black_box(Encodable::serialized_size(black_box(items))))
        });
    }
    group.finish();
}

criterion_group!(benches, bench_write, bench_read, bench_serialized_size);
criterion_main!(benches);
