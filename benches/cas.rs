// Benchmarks for CAS operations (TODO.complete/41).
//
// Measures save/list/load/contains throughput on LocalCas with
// varying blob counts. Run with: cargo bench --bench cas.

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use enprot::cas::{CasStore, LocalCas};
use enprot::crypto::CryptoPolicyDefault;
use tempfile::TempDir;

fn save_blobs(
    store: &LocalCas,
    n: usize,
    policy: &dyn enprot::crypto::CryptoPolicy,
) -> Vec<String> {
    let mut hashes = Vec::with_capacity(n);
    for i in 0..n {
        let blob = format!("blob content {i}").into_bytes();
        let h = store.save(&blob, policy).unwrap();
        hashes.push(h);
    }
    hashes
}

fn bench_cas_save(c: &mut Criterion) {
    let policy = CryptoPolicyDefault {};
    let mut group = c.benchmark_group("cas_save");
    for n in [100, 500, 1000] {
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &n| {
            b.iter_batched(
                || {
                    let dir = TempDir::new().unwrap();
                    let store = LocalCas::new(dir.path().to_path_buf());
                    (store, dir)
                },
                |(store, _dir)| {
                    save_blobs(&store, n, &policy);
                },
                criterion::BatchSize::LargeInput,
            );
        });
    }
    group.finish();
}

fn bench_cas_list(c: &mut Criterion) {
    let policy = CryptoPolicyDefault {};
    let mut group = c.benchmark_group("cas_list");
    for n in [100, 500, 1000] {
        let dir = TempDir::new().unwrap();
        let store = LocalCas::new(dir.path().to_path_buf());
        save_blobs(&store, n, &policy);
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, _| {
            b.iter(|| store.list().unwrap());
        });
    }
    group.finish();
}

fn bench_cas_load(c: &mut Criterion) {
    let policy = CryptoPolicyDefault {};
    let dir = TempDir::new().unwrap();
    let store = LocalCas::new(dir.path().to_path_buf());
    let hashes = save_blobs(&store, 1000, &policy);

    c.bench_function("cas_load_single", |b| {
        b.iter(|| store.load(&hashes[500], &policy).unwrap());
    });
}

fn bench_cas_contains(c: &mut Criterion) {
    let policy = CryptoPolicyDefault {};
    let dir = TempDir::new().unwrap();
    let store = LocalCas::new(dir.path().to_path_buf());
    let hashes = save_blobs(&store, 1000, &policy);

    c.bench_function("cas_contains_single", |b| {
        b.iter(|| store.contains(&hashes[500], &policy).unwrap());
    });
}

fn bench_compress(c: &mut Criterion) {
    let input = b"Hello, World! This is a test of compression. ".repeat(50);

    c.bench_function("compress_2kb", |b| {
        b.iter(|| enprot::compress::compress(&input).unwrap());
    });

    let compressed = enprot::compress::compress(&input).unwrap().0;
    c.bench_function("decompress_2kb", |b| {
        b.iter(|| enprot::compress::decompress(&compressed).unwrap());
    });
}

criterion_group!(
    benches,
    bench_cas_save,
    bench_cas_list,
    bench_cas_load,
    bench_cas_contains,
    bench_compress
);
criterion_main!(benches);
