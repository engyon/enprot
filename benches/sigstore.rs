// Sigstore keyless sign/verify benchmarks (TODO.complete/41).
//
// Measures the full ephemeral-key lifecycle that a CI pipeline
// signing every artifact pays: Ed25519 keygen + sign per call, and
// the matching verify. Entirely offline — `KeylessSigner::sign`
// generates an ephemeral keypair and produces a self-contained
// signature (local-trust mode, `log_index == 0`), so no Fulcio or
// Rekor network I/O is involved.
//
// Run with: cargo bench --bench sigstore

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use enprot::sigstore::{KeylessSigner, VerifyPolicy};

const PAYLOAD: &[u8] =
    b"enprot sigstore bench payload: the quick brown fox jumps over the lazy dog x12";

fn policy() -> VerifyPolicy {
    VerifyPolicy {
        issuer: String::new(),
        identity_regex: regex::Regex::new("").expect("empty regex"),
        fulcio_roots: Vec::new(),
        rekor_public_key: Vec::new(),
    }
}

fn bench_sign(c: &mut Criterion) {
    let signer = KeylessSigner::default();
    let mut group = c.benchmark_group("sigstore");
    group.bench_function(
        BenchmarkId::new("sign_ed25519_ephemeral", PAYLOAD.len()),
        |b| b.iter(|| signer.sign(PAYLOAD).expect("sign")),
    );
    group.finish();
}

fn bench_verify(c: &mut Criterion) {
    let signer = KeylessSigner::default();
    let sig = signer.sign(PAYLOAD).expect("sign");
    let policy = policy();
    let mut group = c.benchmark_group("sigstore");
    group.bench_function(BenchmarkId::new("verify_ed25519", PAYLOAD.len()), |b| {
        b.iter(|| enprot::sigstore::verify(PAYLOAD, &sig, &policy).expect("verify"))
    });
    group.finish();
}

criterion_group!(benches, bench_sign, bench_verify);
criterion_main!(benches);
