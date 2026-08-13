// Benchmarks for the EPT parser + writer + transform (TODO.roadmap/05).
//
// Parse and tree_write throughput over files containing many WORD
// segments. The transform pass measures encrypt+decrypt round-trip
// cost on a representative tree. Run with: cargo bench --bench parser.
//
// NOTE: parser scaling is currently superlinear (4096 segments ≈
// 600 ms; 32768 segments ≈ 41 s). The largest size below is capped
// at 4096 so the suite finishes in seconds — extend the range once
// the parser is O(N).

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use enprot::crypto::CryptoPolicyDefault;
use enprot::etree::{self, ParseOps};
use std::io::Cursor;

fn make_ept(n: usize) -> String {
    let mut s = String::new();
    for i in 0..n {
        s.push_str(&format!("// <( BEGIN WORD_{i} )>\n"));
        s.push_str(&format!("content line for segment {i}\n"));
        s.push_str(&format!("// <( END WORD_{i} )>\n"));
    }
    s
}

fn paops() -> ParseOps {
    ParseOps::new(Box::new(CryptoPolicyDefault {})).unwrap()
}

fn bench_parse(c: &mut Criterion) {
    let mut group = c.benchmark_group("parse");
    for n in [64, 512, 4096].iter() {
        let src = make_ept(*n);
        group.bench_with_input(BenchmarkId::from_parameter(n), &src, |b, s| {
            b.iter(|| {
                let mut p = paops();
                etree::parse(Cursor::new(s.as_bytes()), &mut p).unwrap()
            })
        });
    }
    group.finish();
}

fn bench_tree_write(c: &mut Criterion) {
    let mut group = c.benchmark_group("tree_write");
    for n in [64, 512, 4096].iter() {
        let src = make_ept(*n);
        let mut p = paops();
        let tree = etree::parse(Cursor::new(src.as_bytes()), &mut p).unwrap();
        group.bench_with_input(BenchmarkId::from_parameter(n), &tree, |b, t| {
            b.iter(|| {
                let mut p = paops();
                let mut out: Vec<u8> = Vec::with_capacity(src.len());
                etree::tree_write(&mut out, t, &mut p).unwrap();
                out
            })
        });
    }
    group.finish();
}

fn bench_passthrough(c: &mut Criterion) {
    let mut group = c.benchmark_group("parse_plus_write");
    for n in [64, 512, 4096].iter() {
        let src = make_ept(*n);
        group.bench_with_input(BenchmarkId::from_parameter(n), &src, |b, s| {
            b.iter(|| {
                let mut p = paops();
                let tree = etree::parse(Cursor::new(s.as_bytes()), &mut p).unwrap();
                let mut out: Vec<u8> = Vec::with_capacity(s.len());
                etree::tree_write(&mut out, &tree, &mut p).unwrap();
                out
            })
        });
    }
    group.finish();
}

/// End-to-end encrypt pipeline: parse → transform(encrypt) → write.
/// This is the canonical hot path for `enprot encrypt` and the bench
/// that catches cross-cutting regressions (parse + crypto + write
/// combined). Each segment's WORD is added to `transforms.encrypt`
/// with a shared password. (TODO.complete/41.)
///
/// Range is capped at 64 segments because each encrypt transform
/// runs the configured PBKDF — by design expensive. Larger ranges
/// make the bench take minutes; the scaling shape is visible enough
/// at 1/8/64.
fn bench_encrypt_pipeline(c: &mut Criterion) {
    let mut group = c.benchmark_group("encrypt_pipeline");
    for n in [1, 8, 64].iter() {
        let src = make_ept(*n);
        group.bench_with_input(BenchmarkId::from_parameter(n), &src, |b, s| {
            b.iter(|| {
                let mut p = paops();
                for i in 0..*n {
                    let word = format!("WORD_{i}");
                    p.transforms.encrypt.insert(word.clone());
                    p.passwords.insert(word, "bench-password".to_string());
                }
                let tree = etree::parse(Cursor::new(s.as_bytes()), &mut p).unwrap();
                let tree = etree::transform(&tree, &mut p).unwrap();
                let mut out: Vec<u8> = Vec::with_capacity(s.len());
                etree::tree_write(&mut out, &tree, &mut p).unwrap();
                out
            })
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_parse,
    bench_tree_write,
    bench_passthrough,
    bench_encrypt_pipeline
);
criterion_main!(benches);
