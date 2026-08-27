// Copyright (c) 2018-2026 [Ribose Inc](https://www.ribose.com).
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
// 1. Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

//! `enprot cas` subcommand — CAS integrity operations.
//!
//! Implements TODO.complete/67 (verify) and TODO.complete/66 (gc).
//!
//! `enprot cas verify` walks the input file(s), collects every CAS
//! hash reference (STORED, INCLUDE, MUTED, KEY, CERT), and verifies
//! each resolves to a CAS blob whose SHA3-256 matches the declared
//! hash. This is the end-to-end integrity check that complements
//! `enprot verify` (which checks markup structure + extfields but
//! does not confirm every CAS reference resolves).
//!
//! `enprot cas gc` walks the CAS directory, identifies blobs still
//! referenced by the root file(s), and deletes the rest. Use the
//! global `--dry-run` flag to preview without deleting. `--min-age`
//! protects young blobs from concurrent-process races.
//!
//! Both commands share the `collect_refs` tree walker and the
//! `collect_all_refs` file-reading helper — DRY: the hash-collection
//! logic lives in exactly one place.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::time::SystemTime;

use clap::{Args, Subcommand};
use serde::Serialize;

use crate::error::{Error, Result};
use crate::etree::{self, ParseOps, TextNode};
use crate::output;

use super::{CommonArgs, common::apply_common, common::resolve_policy};

/// `enprot cas` subcommand wrapper.
#[derive(Args, Debug, Clone)]
pub struct CasArgs {
    #[command(subcommand)]
    pub command: CasSubcmd,
}

/// `enprot cas` subcommand actions.
#[derive(Subcommand, Debug, Clone)]
pub enum CasSubcmd {
    /// Verify that every CAS hash referenced by the input file(s)
    /// resolves to a blob whose SHA3-256 matches the declared hash.
    /// Exits non-zero on any failure (CI-friendly).
    Verify(CasVerifyArgs),

    /// Delete CAS blobs not referenced by any root file. Use the
    /// global `--dry-run` flag to preview deletions without executing.
    Gc(CasGcArgs),

    /// List all blob hashes in the CAS store. Useful for inventory
    /// and scripting. One hash per line (text) or JSON array.
    List,

    /// Show CAS statistics: blob count, total disk usage, size range.
    Stats,
}

#[derive(Args, Debug, Clone)]
pub struct CasVerifyArgs {
    /// Input file(s). "-" means stdin. At least one file is required;
    /// pass "-" explicitly for stdin.
    #[arg(value_name = "FILE", default_value = "-")]
    pub files: Vec<String>,
}

#[derive(Args, Debug, Clone)]
pub struct CasGcArgs {
    /// Root EPT file(s) whose CAS references determine which blobs
    /// are still needed. Blobs not referenced by any root file (and
    /// older than `--min-age`) are deleted. "-" means stdin.
    #[arg(value_name = "FILE", default_value = "-")]
    pub files: Vec<String>,

    /// Minimum age in seconds for a blob to be eligible for deletion.
    /// Protects against removing blobs being actively written by a
    /// concurrent process. Default: 0 (no protection).
    #[arg(long, value_name = "SECONDS", default_value_t = 0)]
    pub min_age: u64,
}

/// Entry point for `enprot cas`.
pub fn run(args: CasArgs, common: &CommonArgs) -> Result<()> {
    match args.command {
        CasSubcmd::Verify(a) => run_verify(a, common),
        CasSubcmd::Gc(a) => run_gc(a, common),
        CasSubcmd::List => run_list(common),
        CasSubcmd::Stats => run_stats(common),
    }
}

/// One CAS hash reference discovered while walking a parsed tree.
/// The `kind` is the directive keyword that carried the reference
/// (STORED, INCLUDE, MUTED, KEY, CERT), for diagnostic context.
struct HashRef {
    hash: String,
    kind: &'static str,
    label: Option<String>,
    file: String,
}

/// Outcome of checking a single hash against the CAS backend.
enum HashStatus {
    Ok { bytes: usize },
    Fail { reason: String },
}

impl HashStatus {
    fn is_ok(&self) -> bool {
        matches!(self, HashStatus::Ok { .. })
    }
}

/// Per-hash result: the hash, where it was found, and whether it
/// resolved. Used for both text and JSON output.
struct HashCheck {
    hash: String,
    kind: &'static str,
    label: Option<String>,
    file: String,
    status: HashStatus,
}

impl HashCheck {
    fn print_text(&self) {
        match &self.status {
            HashStatus::Ok { bytes } => {
                let label = super::color::green("OK");
                eprintln!(
                    "{label: <6} {} {} ({} bytes) [{}]",
                    self.hash,
                    self.kind,
                    bytes,
                    location(self.file.as_str(), self.label.as_deref()),
                );
            }
            HashStatus::Fail { reason } => {
                let label = super::color::red("FAIL");
                eprintln!(
                    "{label: <6} {} {} — {} [{}]",
                    self.hash,
                    self.kind,
                    reason,
                    location(self.file.as_str(), self.label.as_deref()),
                );
            }
        }
    }

    fn to_dto(&self) -> HashCheckDto<'_> {
        match &self.status {
            HashStatus::Ok { bytes } => HashCheckDto {
                hash: &self.hash,
                kind: self.kind,
                label: self.label.as_deref(),
                file: &self.file,
                status: "ok",
                bytes: Some(*bytes),
                reason: None,
            },
            HashStatus::Fail { reason } => HashCheckDto {
                hash: &self.hash,
                kind: self.kind,
                label: self.label.as_deref(),
                file: &self.file,
                status: "fail",
                bytes: None,
                reason: Some(reason.as_str()),
            },
        }
    }
}

fn location(file: &str, label: Option<&str>) -> String {
    match label {
        Some(l) => format!("{}:{}", file, l),
        None => file.to_string(),
    }
}

/// Open a reader for a file path, or stdin if `fname == "-"`.
fn open_reader(fname: &str) -> Result<Box<dyn BufRead>> {
    if fname == "-" {
        Ok(Box::new(BufReader::new(std::io::stdin())))
    } else {
        Ok(Box::new(BufReader::new(File::open(fname).map_err(
            |e| {
                Error::Io(std::io::Error::other(format!(
                    "Failed to open {fname}: {e}"
                )))
            },
        )?)))
    }
}

/// Parse each file, walk the resulting tree, and collect every CAS
/// hash reference. Shared between `verify` and `gc` — DRY: the
/// file-reading + parsing + ref-collection pipeline lives here.
fn collect_all_refs(files: &[String], paops: &mut ParseOps) -> Result<Vec<HashRef>> {
    let mut refs: Vec<HashRef> = Vec::new();
    for fname in files {
        let reader = open_reader(fname)?;
        paops.runtime.fname = fname.clone();
        let tree = etree::parse(reader, paops).map_err(|e| Error::Parse {
            file: fname.clone(),
            lineno: 0,
            msg: e.to_string(),
        })?;
        for node in &tree {
            collect_refs(node, fname, &mut refs);
        }
    }
    Ok(refs)
}

fn run_verify(args: CasVerifyArgs, common: &CommonArgs) -> Result<()> {
    let policy = resolve_policy(common)?;
    let mut paops = ParseOps::new(policy)?;
    apply_common(common, &mut paops);

    let refs = collect_all_refs(&args.files, &mut paops)?;

    // Deduplicate by hash: the same hash referenced from N sites
    // needs only one CAS lookup. Keep the first occurrence for
    // reporting context.
    let mut unique: BTreeMap<String, &HashRef> = BTreeMap::new();
    for r in &refs {
        unique.entry(r.hash.clone()).or_insert(r);
    }

    // Verify each unique hash via the CAS backend trait.
    let policy_ref: &dyn crate::crypto::CryptoPolicy = &*paops.crypto.policy;
    let cas_store = paops.io.cas.as_ref();

    let mut results: Vec<HashCheck> = Vec::with_capacity(unique.len());
    for (hash, r) in &unique {
        let status = match cas_store.load(hash, policy_ref) {
            Ok(blob) => HashStatus::Ok { bytes: blob.len() },
            Err(e) => HashStatus::Fail {
                reason: e.to_string(),
            },
        };
        results.push(HashCheck {
            hash: hash.clone(),
            kind: r.kind,
            label: r.label.clone(),
            file: r.file.clone(),
            status,
        });
    }

    // Sort by hash for stable output (BTreeMap already ordered, but
    // make the ordering explicit in the result list too).
    results.sort_by(|a, b| a.hash.cmp(&b.hash));

    let ok = results.iter().filter(|r| r.status.is_ok()).count();
    let fail = results.len() - ok;

    match common.format {
        output::OutputFormat::Text => {
            for r in &results {
                r.print_text();
            }
            eprintln!("---");
            eprintln!(
                "{} OK, {} FAIL ({} unique hashes checked)",
                ok,
                fail,
                results.len()
            );
            if results.is_empty() {
                eprintln!("no CAS references found in input");
            }
        }
        output::OutputFormat::Json => {
            let payload = CasVerifyOutput {
                checked: results.len(),
                ok,
                fail,
                results: results.iter().map(HashCheck::to_dto).collect(),
            };
            println!("{}", output::to_json(&payload)?);
        }
    }

    if fail > 0 {
        std::process::exit(1);
    }
    Ok(())
}

/// `enprot cas gc` — delete unreferenced CAS blobs.
///
/// Uses `CasStore::list()` to enumerate all blobs and
/// `CasStore::delete()` to remove orphans. Works with any backend
/// that implements those methods. The global `--dry-run` flag
/// suppresses deletion and prints what would be removed instead.
fn run_gc(args: CasGcArgs, common: &CommonArgs) -> Result<()> {
    let policy = resolve_policy(common)?;
    let mut paops = ParseOps::new(policy)?;
    apply_common(common, &mut paops);

    let referenced: BTreeSet<String> = collect_all_refs(&args.files, &mut paops)?
        .into_iter()
        .map(|r| r.hash)
        .collect();

    let cas_store = paops.io.cas.as_ref();
    let all_hashes = cas_store.list()?;
    let now = SystemTime::now();
    let casdir = &paops.io.casdir;

    let mut orphans: Vec<String> = Vec::new();
    let mut kept = 0usize;
    for hash in &all_hashes {
        if referenced.contains(hash.as_str()) {
            kept += 1;
            continue;
        }
        if args.min_age > 0 {
            let path = casdir.join(hash);
            if let Ok(meta) = std::fs::metadata(&path)
                && let Ok(modified) = meta.modified()
                && let Ok(elapsed) = now.duration_since(modified)
                && elapsed.as_secs() < args.min_age
            {
                kept += 1;
                continue;
            }
        }
        orphans.push(hash.clone());
    }

    let dry_run = common.dry_run;

    match common.format {
        output::OutputFormat::Text => {
            for hash in &orphans {
                if dry_run {
                    let prefix = super::color::yellow("WOULD DEL");
                    eprintln!("{prefix} {hash}");
                } else {
                    let prefix = super::color::red("DELETED  ");
                    eprintln!("{prefix} {hash}");
                }
            }
            eprintln!("---");
            eprintln!(
                "{} {}, {} kept ({} total blobs)",
                if dry_run { "would delete" } else { "deleted" },
                orphans.len(),
                kept,
                all_hashes.len(),
            );
        }
        output::OutputFormat::Json => {
            let payload = CasGcOutput {
                total: all_hashes.len(),
                kept,
                deleted: orphans.len(),
                dry_run,
                orphans: orphans.iter().map(|h| h.as_str()).collect(),
            };
            println!("{}", output::to_json(&payload)?);
        }
    }

    if !dry_run {
        for hash in &orphans {
            cas_store.delete(hash)?;
        }
    }

    Ok(())
}

/// `enprot cas list` — enumerate all blob hashes in the CAS store.
fn run_list(common: &CommonArgs) -> Result<()> {
    let policy = resolve_policy(common)?;
    let mut paops = ParseOps::new(policy)?;
    apply_common(common, &mut paops);

    let cas_store = paops.io.cas.as_ref();
    let mut hashes = cas_store.list()?;
    hashes.sort();

    match common.format {
        output::OutputFormat::Text => {
            for hash in &hashes {
                println!("{hash}");
            }
            eprintln!("{} blobs", hashes.len());
        }
        output::OutputFormat::Json => {
            let payload = CasListOutput {
                count: hashes.len(),
                blobs: hashes,
            };
            println!("{}", output::to_json(&payload)?);
        }
    }

    Ok(())
}

/// `enprot cas stats` — show CAS blob count, total disk usage, size range.
fn run_stats(common: &CommonArgs) -> Result<()> {
    let policy = resolve_policy(common)?;
    let mut paops = ParseOps::new(policy)?;
    apply_common(common, &mut paops);

    let cas_store = paops.io.cas.as_ref();
    let hashes = cas_store.list()?;
    let casdir = &paops.io.casdir;

    let mut sizes: Vec<u64> = Vec::with_capacity(hashes.len());
    for hash in &hashes {
        let path = casdir.join(hash);
        if let Ok(meta) = std::fs::metadata(&path) {
            sizes.push(meta.len());
        }
    }

    let count = sizes.len();
    let total: u64 = sizes.iter().sum();
    let min = sizes.iter().min().copied().unwrap_or(0);
    let max = sizes.iter().max().copied().unwrap_or(0);
    let avg = if count > 0 { total / count as u64 } else { 0 };

    match common.format {
        output::OutputFormat::Text => {
            eprintln!("CAS statistics:");
            eprintln!("  Blobs:     {count}");
            eprintln!("  Total:     {total} bytes");
            eprintln!("  Smallest:  {min} bytes");
            eprintln!("  Largest:   {max} bytes");
            eprintln!("  Average:   {avg} bytes");
        }
        output::OutputFormat::Json => {
            let payload = CasStatsOutput {
                blobs: count,
                total_bytes: total,
                min_bytes: min,
                max_bytes: max,
                avg_bytes: avg,
            };
            println!("{}", output::to_json(&payload)?);
        }
    }

    Ok(())
}

/// Recursively walk a parsed node, collecting every CAS hash
/// reference. References come from directives that point into the
/// CAS: STORED, INCLUDE, MUTED, KEY, CERT.
///
/// IMMUTABLE blocks carry a content hash but the content is inline
/// (not in CAS), so their hash is NOT collected here — `enprot
/// verify` already checks IMMUTABLE hashes against inline content.
/// CHAIN `payload` extfields are file-state hashes, not CAS
/// references, so they're excluded too.
fn collect_refs(node: &TextNode, file: &str, out: &mut Vec<HashRef>) {
    match node {
        TextNode::Stored { keyw, cas } => {
            out.push(HashRef {
                hash: cas.clone(),
                kind: "STORED",
                label: Some(keyw.clone()),
                file: file.to_string(),
            });
        }
        TextNode::Include { hash } => {
            out.push(HashRef {
                hash: hash.clone(),
                kind: "INCLUDE",
                label: None,
                file: file.to_string(),
            });
        }
        TextNode::Muted { name, hash, .. } => {
            out.push(HashRef {
                hash: hash.clone(),
                kind: "MUTED",
                label: Some(name.clone()),
                file: file.to_string(),
            });
        }
        TextNode::Key { name, hash, .. } => {
            out.push(HashRef {
                hash: hash.clone(),
                kind: "KEY",
                label: Some(name.clone()),
                file: file.to_string(),
            });
        }
        TextNode::Cert { name, hash, .. } => {
            out.push(HashRef {
                hash: hash.clone(),
                kind: "CERT",
                label: Some(name.clone()),
                file: file.to_string(),
            });
        }
        TextNode::Encrypted { txt, .. } | TextNode::BeginEnd { txt, .. } => {
            for child in txt {
                collect_refs(child, file, out);
            }
        }
        TextNode::Immutable { txt, .. } => {
            for child in txt {
                collect_refs(child, file, out);
            }
        }
        TextNode::Conflict { ours, theirs, .. } => {
            for child in ours {
                collect_refs(child, file, out);
            }
            for child in theirs {
                collect_refs(child, file, out);
            }
        }
        _ => {}
    }
}

// --- JSON DTO types ----------------------------------------------------

#[derive(Serialize)]
struct CasVerifyOutput<'a> {
    checked: usize,
    ok: usize,
    fail: usize,
    results: Vec<HashCheckDto<'a>>,
}

#[derive(Serialize)]
struct HashCheckDto<'a> {
    hash: &'a str,
    kind: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    label: Option<&'a str>,
    file: &'a str,
    status: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    bytes: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<&'a str>,
}

#[derive(Serialize)]
struct CasGcOutput<'a> {
    total: usize,
    kept: usize,
    deleted: usize,
    dry_run: bool,
    orphans: Vec<&'a str>,
}

#[derive(Serialize)]
struct CasListOutput {
    count: usize,
    blobs: Vec<String>,
}

#[derive(Serialize)]
struct CasStatsOutput {
    blobs: usize,
    total_bytes: u64,
    min_bytes: u64,
    max_bytes: u64,
    avg_bytes: u64,
}
