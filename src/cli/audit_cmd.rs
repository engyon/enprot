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

//! `enprot audit` — query and verify the operational audit trail
//! (TODO.complete/63). Recording is enabled by the global
//! `--audit-log FILE` flag; this subcommand reads what it wrote.

use std::path::PathBuf;

use clap::{Args, Subcommand};

use crate::audit;
use crate::error::{Error, Result};

/// `enprot audit` top-level args: a nested subcommand dispatcher.
#[derive(Args, Debug)]
pub struct AuditArgs {
    #[command(subcommand)]
    pub cmd: AuditSubcmd,
}

/// `enprot audit` subcommand.
#[derive(Subcommand, Debug)]
pub enum AuditSubcmd {
    /// Filter the audit log and print matching records as JSON
    /// Lines (grep/jq-friendly).
    Query(QueryArgs),
    /// Verify every signature batch in the log against a trust
    /// root. Exits non-zero on any tampering or unsigned records.
    Verify(VerifyArgs),
}

#[derive(Args, Debug)]
pub struct QueryArgs {
    /// The audit log written via `--audit-log`.
    #[arg(long, value_name = "FILE")]
    pub log: PathBuf,

    /// Filter by subcommand name (e.g. `decrypt`).
    #[arg(long)]
    pub op: Option<String>,

    /// Filter by invoking user.
    #[arg(long)]
    pub user: Option<String>,

    /// Filter by WORD (`--word` value of the invocation).
    #[arg(long)]
    pub word: Option<String>,

    /// Inclusive lower bound; RFC 3339 or `YYYY-MM-DD`.
    #[arg(long)]
    pub since: Option<String>,

    /// Inclusive upper bound; RFC 3339 or `YYYY-MM-DD`.
    #[arg(long)]
    pub until: Option<String>,
}

#[derive(Args, Debug)]
pub struct VerifyArgs {
    /// The audit log written via `--audit-log`.
    #[arg(long, value_name = "FILE")]
    pub log: PathBuf,

    /// Trusted public key (PEM) the audit signatures must come from.
    #[arg(long, value_name = "PUB.pem")]
    pub trust_root: PathBuf,
}

pub fn run(a: AuditArgs) -> Result<()> {
    match a.cmd {
        AuditSubcmd::Query(q) => {
            let lines = audit::query(
                &q.log,
                &audit::AuditQuery {
                    op: q.op,
                    user: q.user,
                    word: q.word,
                    since: q.since,
                    until: q.until,
                },
            )?;
            for l in lines {
                println!("{l}");
            }
            Ok(())
        }
        AuditSubcmd::Verify(v) => {
            let pem = std::fs::read_to_string(&v.trust_root)?;
            let out = audit::verify_log(&v.log, &pem)?;
            println!("verified records: {}", out.verified);
            if out.unsigned > 0 {
                println!("unsigned records: {}", out.unsigned);
            }
            for f in &out.failures {
                eprintln!("error: {f}");
            }
            if out.ok() {
                Ok(())
            } else {
                Err(Error::VerifyFailed {
                    issues: out.failures.len() + out.unsigned,
                })
            }
        }
    }
}

/// (subcommand label, `--word` values, input files) for the audit
/// record. Words/files are captured only for subcommands that carry
/// an `OutputArgs`; the others record the operation name alone —
/// their arguments are either fixed (Capabilities) or singular
/// paths already implied by the subcommand.
pub(super) fn invocation_context(cmd: &super::Command) -> (String, Vec<String>, Vec<String>) {
    use super::Command;
    let out = |o: &super::OutputArgs| (o.word.clone(), o.files.clone());
    match cmd {
        Command::Encrypt(a) => ("encrypt".into(), out(&a.output).0, out(&a.output).1),
        Command::Decrypt(a) => ("decrypt".into(), out(&a.output).0, out(&a.output).1),
        Command::Store(a) => ("store".into(), out(&a.output).0, out(&a.output).1),
        Command::Fetch(a) => ("fetch".into(), out(&a.output).0, out(&a.output).1),
        Command::EncryptStore(a) => ("encrypt-store".into(), out(&a.output).0, out(&a.output).1),
        Command::Passthrough(a) => ("passthrough".into(), out(&a.output).0, out(&a.output).1),
        Command::Verify(a) => ("verify".into(), out(&a.output).0, out(&a.output).1),
        Command::List(a) => ("list".into(), out(&a.output).0, out(&a.output).1),
        Command::Completions { .. } => ("completions".into(), vec![], vec![]),
        Command::Sbom(_) => ("sbom".into(), vec![], vec![]),
        Command::Keygen(_) => ("keygen".into(), vec![], vec![]),
        Command::Sign(_) => ("sign".into(), vec![], vec![]),
        Command::VerifySig(_) => ("verify-sig".into(), vec![], vec![]),
        Command::Fingerprint(_) => ("fingerprint".into(), vec![], vec![]),
        Command::VerifyChain(_) => ("verify-chain".into(), vec![], vec![]),
        Command::AuditLog(_) => ("audit-log".into(), vec![], vec![]),
        Command::Snapshot(_) => ("snapshot".into(), vec![], vec![]),
        Command::Pin(_) => ("pin".into(), vec![], vec![]),
        Command::Audit(_) => ("audit".into(), vec![], vec![]),
        Command::Capabilities => ("capabilities".into(), vec![], vec![]),
        Command::Init(_) => ("init".into(), vec![], vec![]),
        Command::MergeDriver(_) => ("merge-driver".into(), vec![], vec![]),
        Command::Resolve(_) => ("resolve".into(), vec![], vec![]),
        Command::Conflicts(_) => ("conflicts".into(), vec![], vec![]),
        Command::Inspect(_) => ("inspect".into(), vec![], vec![]),
        Command::Cap(_) => ("cap".into(), vec![], vec![]),
        Command::Clean(_) => ("clean".into(), vec![], vec![]),
        Command::Smudge(_) => ("smudge".into(), vec![], vec![]),
        Command::Textconv(_) => ("textconv".into(), vec![], vec![]),
        Command::Manifest(_) => ("manifest".into(), vec![], vec![]),
        Command::Attest(_) => ("attest".into(), vec![], vec![]),
        Command::Scm(_) => ("scm".into(), vec![], vec![]),
        Command::Cas(_) => ("cas".into(), vec![], vec![]),
    }
}

/// Write the audit record for one invocation when `--audit-log` was
/// given. A write failure is surfaced on stderr but never masks the
/// command's own outcome: an audit gap is observable in the log, a
/// silently-swapped error is not.
pub(super) fn maybe_record(
    audit_log: Option<&std::path::Path>,
    signer: Option<&std::path::Path>,
    op: &str,
    words: &[String],
    files: &[String],
    started: std::time::Instant,
    result: &Result<()>,
) {
    let Some(log) = audit_log else {
        return;
    };
    let exit = if result.is_ok() { 0 } else { 1 };
    let duration = started.elapsed().as_millis() as u64;
    let signer = signer.and_then(|p| std::fs::read_to_string(p).ok());
    if let Err(e) =
        audit::record_invocation(log, op, words, files, exit, duration, signer.as_deref())
    {
        eprintln!("error writing audit log: {e}");
    }
}
