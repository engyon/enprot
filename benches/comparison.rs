//! Performance comparison: enprot vs plausible alternatives.
//!
//! Run: `cargo bench --bench comparison`
//!
//! This benchmark doesn't actually invoke the external tools (git-crypt,
//! sops, age) — they have different process-launch overhead and bring
//! in setup complexity that obscures the enprot-side measurement.
//! Instead it measures the relevant enprot primitives on representative
//! payload sizes, with the parameter ranges that match the
//! alternatives' common use cases.
//!
//! For a fair A/B comparison vs another tool, see `bench/compare.sh`
//! (TODO.completion/23) which shells out to each tool with the same
//! input.

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use enprot::cas::CasStore;
use enprot::crypto;
use enprot::etree::ParseOps;
use enprot::prot;

fn encrypt_1mb(c: &mut Criterion) {
    let mut group = c.benchmark_group("encrypt_1mb");
    group.throughput(Throughput::Bytes(1024 * 1024));
    let payload = vec![0x42u8; 1024 * 1024];

    let mut paops = ParseOps::new(Box::new(crypto::CryptoPolicyDefault {})).unwrap();
    paops
        .passwords
        .insert("bench".to_string(), "bench-password".to_string());
    paops.crypto.cipheropts.alg = "aes-256-siv".to_string();

    group.bench_function(BenchmarkId::new("aes-256-siv", "1mb"), |b| {
        b.iter(|| {
            let _ = prot::encrypt(
                payload.clone(),
                "bench-password",
                &mut paops.crypto.rng,
                &paops.crypto.pbkdfopts,
                &paops.crypto.cipheropts,
                &mut paops.crypto.pbkdf_cache,
                &*paops.crypto.policy,
            )
            .unwrap();
        });
    });

    paops.crypto.cipheropts.alg = "aes-256-gcm".to_string();
    group.bench_function(BenchmarkId::new("aes-256-gcm", "1mb"), |b| {
        b.iter(|| {
            let _ = prot::encrypt(
                payload.clone(),
                "bench-password",
                &mut paops.crypto.rng,
                &paops.crypto.pbkdfopts,
                &paops.crypto.cipheropts,
                &mut paops.crypto.pbkdf_cache,
                &*paops.crypto.policy,
            )
            .unwrap();
        });
    });

    paops.crypto.cipheropts.alg = "aes-256-gcm-siv".to_string();
    group.bench_function(BenchmarkId::new("aes-256-gcm-siv", "1mb"), |b| {
        b.iter(|| {
            let _ = prot::encrypt(
                payload.clone(),
                "bench-password",
                &mut paops.crypto.rng,
                &paops.crypto.pbkdfopts,
                &paops.crypto.cipheropts,
                &mut paops.crypto.pbkdf_cache,
                &*paops.crypto.policy,
            )
            .unwrap();
        });
    });

    group.finish();
}

fn cas_save_varying_sizes(c: &mut Criterion) {
    let mut group = c.benchmark_group("cas_save");
    let policy = crypto::default_policy();
    let dir = std::env::temp_dir().join(format!(
        "enprot-bench-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let store = enprot::cas::LocalCas::new(dir.clone());

    for size in [1, 1024, 64 * 1024, 1024 * 1024] {
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &size| {
            let blob = vec![0xABu8; size];
            b.iter(|| {
                let _ = store.save(&blob, &*policy).unwrap();
            });
        });
    }

    group.finish();
    let _ = std::fs::remove_dir_all(&dir);
}

criterion_group!(benches, encrypt_1mb, cas_save_varying_sizes);
criterion_main!(benches);
