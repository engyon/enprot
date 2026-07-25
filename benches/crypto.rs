// Benchmarks for the crypto primitives (TODO.roadmap/05).
//
// Compares Ed25519 vs ML-DSA on keygen/sign/verify and ML-KEM on
// encapsulate/decapsulate. Run with: cargo bench --bench crypto.

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use enprot::pki::{self, KemAlgKind, SigAlgKind};

fn bench_keygen(c: &mut Criterion) {
    let mut group = c.benchmark_group("keygen");
    for alg in SigAlgKind::ALL {
        group.bench_function(alg.name(), |b| {
            b.iter(|| {
                let mut rng = botan::RandomNumberGenerator::new_system().unwrap();
                pki::keygen(*alg, &mut rng).unwrap()
            })
        });
    }
    group.finish();
}

fn bench_sign(c: &mut Criterion) {
    let msg = b"benchmark message for signing";
    let mut group = c.benchmark_group("sign");
    for alg in SigAlgKind::ALL {
        let mut rng = botan::RandomNumberGenerator::new_system().unwrap();
        let (priv_pem, _) = pki::keygen(*alg, &mut rng).unwrap();
        group.bench_function(alg.name(), |b| {
            b.iter(|| {
                let mut rng = botan::RandomNumberGenerator::new_system().unwrap();
                pki::sign(*alg, &priv_pem, msg, &mut rng).unwrap()
            })
        });
    }
    group.finish();
}

fn bench_verify(c: &mut Criterion) {
    let msg = b"benchmark message for signing";
    let mut group = c.benchmark_group("verify");
    for alg in SigAlgKind::ALL {
        let mut rng = botan::RandomNumberGenerator::new_system().unwrap();
        let (priv_pem, pub_pem) = pki::keygen(*alg, &mut rng).unwrap();
        let sig = pki::sign(*alg, &priv_pem, msg, &mut rng).unwrap();
        group.bench_function(alg.name(), |b| {
            b.iter(|| pki::verify(*alg, &pub_pem, msg, &sig).unwrap())
        });
    }
    group.finish();
}

fn bench_kem(c: &mut Criterion) {
    let mut group = c.benchmark_group("kem");
    let mut rng = botan::RandomNumberGenerator::new_system().unwrap();
    let (priv_pem, pub_pem) = pki::kem_keygen(KemAlgKind::MlKem, &mut rng).unwrap();

    group.bench_function("mlkem_encapsulate", |b| {
        b.iter(|| {
            let mut rng = botan::RandomNumberGenerator::new_system().unwrap();
            pki::kem_encapsulate(&pub_pem, 32, &mut rng).unwrap()
        })
    });

    let (_, ct) = pki::kem_encapsulate(&pub_pem, 32, &mut rng).unwrap();
    group.bench_function("mlkem_decapsulate", |b| {
        b.iter(|| pki::kem_decapsulate(&priv_pem, &ct, 32).unwrap())
    });

    group.finish();
}

fn bench_sign_message_sizes(c: &mut Criterion) {
    // Sign + verify cost as a function of message length for Ed25519.
    let mut group = c.benchmark_group("sign_by_size_ed25519");
    for size in [64, 1024, 8192, 65536].iter() {
        let msg = vec![0u8; *size];
        let mut rng = botan::RandomNumberGenerator::new_system().unwrap();
        let (priv_pem, pub_pem) = pki::keygen(SigAlgKind::Ed25519, &mut rng).unwrap();
        let sig = pki::sign(SigAlgKind::Ed25519, &priv_pem, &msg, &mut rng).unwrap();
        group.bench_with_input(BenchmarkId::from_parameter(size), &msg, |b, m| {
            b.iter(|| {
                let mut rng = botan::RandomNumberGenerator::new_system().unwrap();
                pki::sign(SigAlgKind::Ed25519, &priv_pem, m, &mut rng).unwrap()
            })
        });
        group.bench_with_input(BenchmarkId::new("verify", size), &msg, |b, m| {
            b.iter(|| pki::verify(SigAlgKind::Ed25519, &pub_pem, m, &sig).unwrap())
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_keygen,
    bench_sign,
    bench_verify,
    bench_kem,
    bench_sign_message_sizes,
);
criterion_main!(benches);
