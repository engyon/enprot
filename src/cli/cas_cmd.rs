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
//! Implements TODO.complete/67.
//!
//! `enprot cas verify` walks the input file(s), collects every CAS
//! hash reference (STORED, INCLUDE, MUTED, KEY, CERT), and verifies
//! each resolves to a CAS blob whose SHA3-256 matches the declared
//! hash. This is the end-to-end integrity check that complements
//! `enprot verify` (which checks markup structure + extfields but
//! does not confirm every CAS reference resolves).
//!
//! The command dispatches through the `CasStore` trait, so it works
//! with any backend (LocalCas, MemoryCas, future S3/IPFS) — OCP: a
//! new backend needs no change here.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufRead, BufReader};

use clap::{Args, Subcommand};
use serde::Serialize;

use crate::error::{Error, Result};
use crate::etree::{self, ParseOps, TextNode};
use crate::output;

use super::{CommonArgs, apply_common, resolve_policy};

/// `enprot cas` subcommand wrapper.
#[derive(Args, Debug, Clone)]
pub struct CasArgs {
    #[command(subcommand)]
    pub command: CasSubcmd,
}

/// `enprot cas` subcommand actions. Currently only `verify`; future
/// actions (gc, repair, list) will be added here.
#[derive(Subcommand, Debug, Clone)]
pub enum CasSubcmd {
    /// Verify that every CAS hash referenced by the input file(s)
    /// resolves to a blob whose SHA3-256 matches the declared hash.
    /// Exits non-zero on any failure (CI-friendly).
    Verify(CasVerifyArgs),
}

#[derive(Args, Debug, Clone)]
pub struct CasVerifyArgs {
    /// Input file(s). "-" means stdin. At least one file is required;
    /// pass "-" explicitly for stdin.
    #[arg(value_name = "FILE", default_value = "-")]
    pub files: Vec<String>,
}

/// Entry point for `enprot cas`.
pub fn run(args: CasArgs, common: &CommonArgs) -> Result<()> {
    match args.command {
        CasSubcmd::Verify(a) => run_verify(a, common),
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
                eprintln!(
                    "OK    {} {} ({} bytes) [{}]",
                    self.hash,
                    self.kind,
                    bytes,
                    location(self.file.as_str(), self.label.as_deref()),
                );
            }
            HashStatus::Fail { reason } => {
                eprintln!(
                    "FAIL  {} {} — {} [{}]",
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

fn run_verify(args: CasVerifyArgs, common: &CommonArgs) -> Result<()> {
    let policy = resolve_policy(common)?;
    let mut paops = ParseOps::new(policy)?;
    apply_common(common, &mut paops);

    // Collect hash references across all input files.
    let mut refs: Vec<HashRef> = Vec::new();

    for fname in &args.files {
        let reader: Box<dyn BufRead> = if fname == "-" {
            Box::new(BufReader::new(std::io::stdin()))
        } else {
            Box::new(BufReader::new(File::open(fname).map_err(|e| {
                Error::Io(std::io::Error::other(format!(
                    "Failed to open {fname}: {e}"
                )))
            })?))
        };
        paops.runtime.fname = fname.clone();

        let tree = match etree::parse(reader, &mut paops) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("FAIL {}: parse error: {}", fname, e);
                return Err(Error::Cas(format!("parse error in {}: {}", fname, e)));
            }
        };

        for node in &tree {
            collect_refs(node, fname, &mut refs);
        }
    }

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
