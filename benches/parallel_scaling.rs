// Parallel scaling benchmarks (TODO.complete/41).
//
// Drives the real `--jobs` path (`cli::pipeline::run`) over a
// multi-file workload on disk, at 1/2/4/8 threads. Each thread
// builds its own `ParseOps` from the same `RunConfig`; PBKDF
// derivation is capped at 1 msec so the measurement reflects
// parse + transform + write scaling rather than KDF cost.
//
// Absolute speedups depend on core count — run locally for real
// numbers; CI only smoke-checks execution (`--quick`). Inline DATA
// output is used so iterations don't contend on a shared CAS dir.
//
// Run with: cargo bench --bench parallel_scaling

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use enprot::cli::pipeline::{self, RunConfig};
use enprot::cli::{CommonArgs, EncryptOpts, Operation, OutputArgs};
use std::path::PathBuf;

/// One workload = N files × M WORD segments each.
const FILES: usize = 16;
const SEGMENTS: usize = 16;

fn make_ept(segments: usize, salt: usize) -> String {
    let mut s = String::new();
    for i in 0..segments {
        s.push_str(&format!("// <( BEGIN WORD_{i} )>\n"));
        // ~1 KB of host-language text per segment: representative
        // source-file shape, big enough that parse+write dominate
        // fixed per-file setup.
        for j in 0..32 {
            s.push_str(&format!(
                "host line {salt}-{i}-{j}: lorem ipsum dolor sit amet\n"
            ));
        }
        s.push_str(&format!("// <( END WORD_{i} )>\n"));
    }
    s
}

fn run_config(files: Vec<PathBuf>, jobs: usize) -> RunConfig {
    let mut common = CommonArgs::for_filter(None);
    common.jobs = jobs;
    common.quiet = true;
    common.inline = true;
    for i in 0..SEGMENTS {
        common
            .password
            .push((format!("WORD_{i}"), "bench-password".to_string()));
    }
    RunConfig {
        common,
        output: OutputArgs {
            word: (0..SEGMENTS).map(|i| format!("WORD_{i}")).collect(),
            output: Vec::new(),
            prefix: String::new(),
            output_dir: None,
            files: files
                .into_iter()
                .map(|p| p.to_string_lossy().into_owned())
                .collect(),
        },
        op: Some((
            EncryptOpts {
                pbkdf_msec: Some(1),
                ..Default::default()
            },
            Operation::Encrypt,
        )),
        recipient_pubs: Vec::new(),
        recovery_pubs: Vec::new(),
        pgp_pubs: Vec::new(),
        recipient_privs: Vec::new(),
    }
}

fn bench_parallel(c: &mut Criterion) {
    let dir = tempfile::tempdir().expect("tempdir");
    let files: Vec<PathBuf> = (0..FILES)
        .map(|i| {
            let p = dir.path().join(format!("f{i}.txt"));
            std::fs::write(&p, make_ept(SEGMENTS, i)).expect("write fixture");
            p
        })
        .collect();

    let mut group = c.benchmark_group("parallel_scaling");
    for jobs in [1usize, 2, 4, 8] {
        let cfg = run_config(files.clone(), jobs);
        group.bench_with_input(
            BenchmarkId::new("encrypt", format!("jobs{jobs}_{FILES}files")),
            &cfg,
            |b, cfg| b.iter(|| pipeline::run(cfg.clone()).expect("pipeline run")),
        );
    }
    group.finish();
}

criterion_group!(benches, bench_parallel);
criterion_main!(benches);
