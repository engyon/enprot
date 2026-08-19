// Peak-heap benchmark (TODO.complete/41).
//
// Reports the high-water heap allocation of the non-streaming
// parse → transform → write pipeline over a synthetic EPT input.
// Uses `dhat` as the global allocator; the peak is the allocator
// high-water mark (heap, not RSS — page-level RSS additionally
// includes allocator slack and code pages).
//
// One size per invocation, because dhat's HeapStats is a process-
// global cumulative counter that cannot be reset:
//
//     cargo bench --bench memory -- 10        # 10 MB input
//     cargo bench --bench memory -- 1 10 100  # runs each, peaks are cumulative
//
// The peak tracks input size at roughly 3x (tree + ciphertext
// buffers + output); CI smoke uses 10 MB. dhat writes its analysis
// file (dhat-heap.json) into the working directory — gitignored.

use std::hint::black_box;
use std::io::Cursor;

#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

fn synthetic_ept(target_bytes: usize) -> String {
    // Segment skeleton is ~1 KB; repeat until the target size is
    // reached so the input is representative (many WORD blocks,
    // host text between them), not one giant blob.
    let mut s = String::with_capacity(target_bytes + 2048);
    let mut i = 0usize;
    while s.len() < target_bytes {
        s.push_str("// <( BEGIN WORD )>\n");
        for j in 0..31 {
            s.push_str(&format!(
                "host line {i}-{j}: lorem ipsum dolor sit amet, consectetur adipiscing elit\n"
            ));
        }
        s.push_str("// <( END WORD )>\n");
        i += 1;
    }
    s
}

fn main() {
    // Tolerant parsing: `cargo bench` may inject its own flags into
    // argv; keep only bare integers (the requested sizes).
    let sizes_mb: Vec<usize> = std::env::args()
        .skip(1)
        .filter_map(|a| a.parse().ok())
        .collect();
    let sizes_mb = if sizes_mb.is_empty() {
        vec![10]
    } else {
        sizes_mb
    };

    let _profiler = dhat::Profiler::builder().build();

    for mb in sizes_mb {
        let input = synthetic_ept(mb * 1_000_000);
        let peak_before = dhat::HeapStats::get().max_bytes;
        let mut paops =
            enprot::etree::ParseOps::new(Box::new(enprot::crypto::CryptoPolicyDefault {}))
                .expect("ParseOps");
        paops.transforms.encrypt.insert("WORD".to_string());
        paops
            .passwords
            .insert("WORD".to_string(), "bench-password".to_string());
        paops.crypto.pbkdfopts.msec = Some(1);

        let tree = enprot::etree::parse(Cursor::new(input.as_bytes()), &mut paops).expect("parse");
        let tree = enprot::etree::transform(&tree, &mut paops).expect("transform");
        let mut out = Vec::new();
        enprot::etree::tree_write(&mut out, &tree, &mut paops).expect("write");
        black_box(&out);

        let stats = dhat::HeapStats::get();
        let peak = stats.max_bytes - peak_before;
        println!(
            "input {:>4} MB → output {:>4} MB | peak heap this phase: {:>6.1} MB | process high-water: {:>6.1} MB",
            mb,
            out.len() as f64 / 1_000_000.0,
            peak as f64 / 1_000_000.0,
            stats.max_bytes as f64 / 1_000_000.0,
        );
    }
}
