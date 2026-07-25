// Benchmarks for the Merkle tree primitives (TODO.roadmap/05).
//
// Tree construction cost over a range of leaf counts; proof generation
// and verification cost (both should be O(log N)). Run with:
// cargo bench --bench merkle.

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use enprot::merkle::{self, MerkleTree};

fn bench_tree_construction(c: &mut Criterion) {
    let mut group = c.benchmark_group("merkle_from_leaves");
    for n in [16, 256, 1024, 8192, 65536].iter() {
        let leaves: Vec<Vec<u8>> = (0..*n).map(|i| format!("leaf-{i}").into_bytes()).collect();
        group.bench_with_input(BenchmarkId::from_parameter(n), &leaves, |b, l| {
            b.iter(|| MerkleTree::from_leaves(l).unwrap())
        });
    }
    group.finish();
}

fn bench_proof_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("merkle_proof_gen");
    for n in [16, 256, 1024, 8192, 65536].iter() {
        let leaves: Vec<Vec<u8>> = (0..*n).map(|i| format!("leaf-{i}").into_bytes()).collect();
        let tree = MerkleTree::from_leaves(&leaves).unwrap();
        let idx = n / 2;
        group.bench_with_input(BenchmarkId::from_parameter(n), &idx, |b, &i| {
            b.iter(|| tree.proof(i).unwrap())
        });
    }
    group.finish();
}

fn bench_proof_verification(c: &mut Criterion) {
    let mut group = c.benchmark_group("merkle_proof_verify");
    for n in [16, 256, 1024, 8192, 65536].iter() {
        let leaves: Vec<Vec<u8>> = (0..*n).map(|i| format!("leaf-{i}").into_bytes()).collect();
        let tree = MerkleTree::from_leaves(&leaves).unwrap();
        let root = tree.root().unwrap();
        let proof = tree.proof(n / 2).unwrap();
        group.bench_with_input(BenchmarkId::from_parameter(n), &proof, |b, p| {
            b.iter(|| merkle::verify_proof(&root, p).unwrap())
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_tree_construction,
    bench_proof_generation,
    bench_proof_verification,
);
criterion_main!(benches);
