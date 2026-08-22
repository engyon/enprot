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

//! Operational audit trail (TODO.complete/63).
//!
//! Chain anchors record **content** provenance (which file state was
//! signed); this module records **operational** provenance — who ran
//! which subcommand, on which files and WORDs, when, and with what
//! outcome. Enabled per-invocation with `--audit-log FILE`.
//!
//! Format: JSON Lines, internally tagged (`type` field) so data
//! records and signature records extend without format breaks:
//!
//! ```json
//! {"type":"record","ts":"...","host":"...","user":"...","op":"decrypt",
//!  "words":["SECRET"],"files":["config.ept"],"exit":0,"duration_ms":42}
//! {"type":"signature","ts":"...","records":1,"signer":"ed25519:...",
//!  "sig":"<hex>"}
//! ```
//!
//! Guarantees:
//! - **Append-only**: enprot opens the log with `O_APPEND` and writes
//!   each line with a single `write` — concurrent invocations never
//!   interleave within a line. enprot never rewrites or truncates.
//! - **Tamper-evident**: when `--signer` is also given, the session's
//!   data lines are signed at exit (Ed25519 over the exact line
//!   bytes); `enprot audit verify --trust-root PUB.pem` walks the
//!   log and checks every batch.
//! - **Cheap**: one open-append-close per invocation (<1ms); suitable
//!   for piping into a log collector.

use std::io::Write;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::pki::{self, SigAlgKind};
use crate::utils;

/// One operational record: a single enprot invocation.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct AuditRecord {
    /// RFC 3339 UTC.
    pub ts: String,
    pub host: String,
    pub user: String,
    /// Subcommand name (`encrypt`, `decrypt`, …).
    pub op: String,
    /// `--word` values.
    #[serde(default)]
    pub words: Vec<String>,
    /// Input file paths.
    #[serde(default)]
    pub files: Vec<String>,
    /// Exit status of the invocation (0 = success).
    pub exit: i32,
    /// Wall-clock duration in milliseconds.
    pub duration_ms: u64,
}

/// Per-session signature over the exact bytes of the session's data
/// lines. Appended after the records it covers.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct SignatureRecord {
    pub ts: String,
    /// Number of data records covered by this signature.
    pub records: usize,
    /// `ed25519:<pubkey-fp-hex>` of the signing key.
    pub signer: String,
    /// Ed25519 signature (hex) over the covered lines joined with
    /// `\n`.
    pub sig: String,
}

/// One line of the audit log.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum AuditLine {
    Record(AuditRecord),
    Signature(SignatureRecord),
}

/// Append one line to the log. Single `write` under `O_APPEND`:
/// concurrent invocations never interleave within a line.
pub fn append_line(path: &Path, line: &AuditLine) -> Result<()> {
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    let mut json = serde_json::to_string(line).map_err(Error::json)?;
    json.push('\n');
    f.write_all(json.as_bytes())?;
    f.sync_data()?;
    Ok(())
}

/// Record one invocation. `exit` mirrors the command's outcome. When
/// `signer_pem` is supplied, the session's record is immediately
/// followed by a signature over its exact line bytes (a one-record
/// session — each invocation signs its own record, so any tampering
/// with or removal of any line is detectable at verify time).
pub fn record_invocation(
    log: &Path,
    op: &str,
    words: &[String],
    files: &[String],
    exit: i32,
    duration_ms: u64,
    signer_pem: Option<&str>,
) -> Result<()> {
    let rec = AuditRecord {
        ts: utils::rfc3339(None),
        // whoami 2 removed the fallible module; the infallible
        // accessors return "unknown" themselves on failure.
        host: whoami::hostname().unwrap_or_else(|_| "unknown".into()),
        user: whoami::username().unwrap_or_else(|_| "unknown".into()),
        op: op.to_string(),
        words: words.to_vec(),
        files: files.to_vec(),
        exit,
        duration_ms,
    };
    let line = AuditLine::Record(rec);
    let exact = serde_json::to_string(&line).map_err(Error::json)?;
    append_line(log, &line)?;

    if let Some(pem) = signer_pem {
        let sig = sign_session(&[exact], pem)?;
        append_line(log, &AuditLine::Signature(sig))?;
    }
    Ok(())
}

/// Sign the exact line bytes of one session's data records.
fn sign_session(lines: &[String], priv_pem: &str) -> Result<SignatureRecord> {
    let mut rng = botan::RandomNumberGenerator::new_system().map_err(Error::botan)?;
    let msg = lines.join("\n");
    let sig = pki::sign(SigAlgKind::Ed25519, priv_pem, msg.as_bytes(), &mut rng)?;
    // The signer label is derived from the pubkey, not the file name.
    let fp = signer_fingerprint(priv_pem)?;
    Ok(SignatureRecord {
        ts: utils::rfc3339(None),
        records: lines.len(),
        signer: format!("ed25519:{fp}"),
        sig: hex::encode(sig),
    })
}

/// `ed25519:<fp-hex>` label for a private PEM.
fn signer_fingerprint(priv_pem: &str) -> Result<String> {
    let botan_priv = botan::Privkey::load_pem(priv_pem).map_err(Error::botan)?;
    let pub_pem = botan_priv
        .pubkey()
        .and_then(|p| p.pem_encode())
        .map_err(Error::botan)?;
    let fp = crate::capability::KeyFp::from_pem(&pub_pem)?;
    Ok(fp.to_hex())
}

/// The outcome of verifying an entire audit log.
#[derive(Debug, Default, PartialEq)]
pub struct VerifyOutcome {
    /// Data records verified under a valid signature.
    pub verified: usize,
    /// Data records present without a covering signature.
    pub unsigned: usize,
    /// Human-readable failures (bad signature, count mismatch,
    /// unknown signer).
    pub failures: Vec<String>,
}

impl VerifyOutcome {
    pub fn ok(&self) -> bool {
        self.failures.is_empty() && self.unsigned == 0
    }
}

/// Walk the log and verify every signature batch against
/// `trust_root_pem`. The log is split into batches at signature
/// lines; each signature must cover the exact bytes of the data
/// lines since the previous signature, and the signer fingerprint
/// must match the trust root's.
pub fn verify_log(log: &Path, trust_root_pem: &str) -> Result<VerifyOutcome> {
    let text = std::fs::read_to_string(log)?;
    // The trust root is a PUBLIC key PEM; KeyFp::from_pem is defined
    // over exactly that.
    let expected_fp = crate::capability::KeyFp::from_pem(trust_root_pem)?.to_hex();

    let mut outcome = VerifyOutcome::default();
    let mut batch: Vec<String> = Vec::new();

    for (lineno, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let parsed: AuditLine = serde_json::from_str(line)
            .map_err(|e| Error::Json(format!("audit log line {}: {e}", lineno + 1)))?;
        match parsed {
            AuditLine::Record(_) => batch.push(line.to_string()),
            AuditLine::Signature(sig) => {
                if !sig.signer.ends_with(&expected_fp) {
                    outcome.failures.push(format!(
                        "line {}: signer {} is not the trust root",
                        lineno + 1,
                        sig.signer
                    ));
                }
                if sig.records != batch.len() {
                    outcome.failures.push(format!(
                        "line {}: signature covers {} records but batch has {} — records tampered",
                        lineno + 1,
                        sig.records,
                        batch.len()
                    ));
                }
                let msg = batch.join("\n");
                let sig_bytes = hex::decode(&sig.sig).map_err(Error::from)?;
                let ok = pki::verify(
                    SigAlgKind::Ed25519,
                    trust_root_pem,
                    msg.as_bytes(),
                    &sig_bytes,
                )?;
                if !ok {
                    outcome.failures.push(format!(
                        "line {}: signature does not verify — content tampered",
                        lineno + 1
                    ));
                }
                if ok && sig.records == batch.len() && sig.signer.ends_with(&expected_fp) {
                    outcome.verified += batch.len();
                }
                batch.clear();
            }
        }
    }
    outcome.unsigned = batch.len();
    Ok(outcome)
}

/// A query over the audit log. All filters are conjunctive; `None`
/// matches everything.
#[derive(Debug, Default, Clone)]
pub struct AuditQuery {
    pub op: Option<String>,
    pub user: Option<String>,
    pub word: Option<String>,
    /// Inclusive lower bound, RFC 3339 (or `YYYY-MM-DD`, normalized).
    pub since: Option<String>,
    /// Inclusive upper bound, RFC 3339 (or `YYYY-MM-DD`, normalized
    /// to end-of-day).
    pub until: Option<String>,
}

/// Normalize a user-supplied bound to canonical RFC 3339 so lexical
/// comparison against record timestamps is correct. A bare date maps
/// to `T00:00:00.000000000Z` (`since`) or `T23:59:59.999999999Z`
/// (`until`).
fn normalize_bound(s: &str, end_of_day: bool) -> String {
    if s.len() == 10 && s.as_bytes()[4] == b'-' {
        if end_of_day {
            format!("{s}T23:59:59.999999999Z")
        } else {
            format!("{s}T00:00:00.000000000Z")
        }
    } else {
        s.to_string()
    }
}

/// Filter the log, returning the original JSON lines of matching
/// data records (grep-friendly: query output is itself valid input
/// to grep/jq). Signature lines are not returned; use `audit
/// verify` to check them.
pub fn query(log: &Path, q: &AuditQuery) -> Result<Vec<String>> {
    let text = std::fs::read_to_string(log)?;
    let since = q.since.as_deref().map(|s| normalize_bound(s, false));
    let until = q.until.as_deref().map(|s| normalize_bound(s, true));
    let mut out = Vec::new();
    for (lineno, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let parsed: AuditLine = serde_json::from_str(line)
            .map_err(|e| Error::Json(format!("audit log line {}: {e}", lineno + 1)))?;
        let AuditLine::Record(r) = parsed else {
            continue;
        };
        if let Some(op) = &q.op
            && &r.op != op
        {
            continue;
        }
        if let Some(user) = &q.user
            && &r.user != user
        {
            continue;
        }
        if let Some(word) = &q.word
            && !r.words.iter().any(|w| w == word)
        {
            continue;
        }
        if let Some(since) = &since
            && r.ts.as_str() < since.as_str()
        {
            continue;
        }
        if let Some(until) = &until
            && r.ts.as_str() > until.as_str()
        {
            continue;
        }
        out.push(line.to_string());
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(op: &str, user: &str, ts: &str, words: &[&str]) -> AuditLine {
        AuditLine::Record(AuditRecord {
            ts: ts.into(),
            host: "h".into(),
            user: user.into(),
            op: op.into(),
            words: words.iter().map(|s| s.to_string()).collect(),
            files: vec!["f.ept".into()],
            exit: 0,
            duration_ms: 1,
        })
    }

    #[test]
    fn record_round_trips_with_type_tag() {
        let line = rec("decrypt", "ci", "2026-08-17T00:00:00.000000000Z", &["W"]);
        let json = serde_json::to_string(&line).unwrap();
        assert!(json.starts_with(r#"{"type":"record""#), "{json}");
        let back: AuditLine = serde_json::from_str(&json).unwrap();
        assert_eq!(back, line);
    }

    #[test]
    fn append_is_exclusive_and_appends() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("a.jsonl");
        append_line(
            &log,
            &rec("encrypt", "u", "2026-08-17T00:00:00.000000000Z", &[]),
        )
        .unwrap();
        append_line(
            &log,
            &rec("decrypt", "u", "2026-08-17T00:00:01.000000000Z", &[]),
        )
        .unwrap();
        let text = std::fs::read_to_string(&log).unwrap();
        assert_eq!(text.lines().count(), 2);
    }

    #[test]
    fn concurrent_appends_do_not_interleave() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("c.jsonl");
        std::fs::write(&log, b"").unwrap();
        let n = 8;
        let per = 50;
        std::thread::scope(|s| {
            for t in 0..n {
                let log = &log;
                s.spawn(move || {
                    for i in 0..per {
                        append_line(
                            log,
                            &rec(
                                "encrypt",
                                &format!("t{t}"),
                                &format!("2026-08-17T00:00:{i:02}.000000000Z"),
                                &[],
                            ),
                        )
                        .unwrap();
                    }
                });
            }
        });
        let text = std::fs::read_to_string(&log).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), n * per, "no lines lost or merged");
        assert!(lines.iter().all(|l| l.starts_with(r#"{"type":"record""#)));
    }

    #[test]
    fn signed_session_verifies_and_tampering_is_detected() {
        let mut rng = botan::RandomNumberGenerator::new_system().unwrap();
        let (priv_pem, pub_pem) = pki::keygen(SigAlgKind::Ed25519, &mut rng).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("s.jsonl");

        record_invocation(
            &log,
            "decrypt",
            &["W".into()],
            &["f.ept".into()],
            0,
            5,
            Some(&priv_pem),
        )
        .unwrap();
        record_invocation(&log, "encrypt", &[], &["g.ept".into()], 0, 7, None).unwrap();

        // Signed record verifies; the unsigned one is reported.
        let out = verify_log(&log, &pub_pem).unwrap();
        assert_eq!(out.verified, 1);
        assert_eq!(out.unsigned, 1);
        assert!(out.failures.is_empty());

        // Tamper with the signed record's payload → count mismatch +
        // bad signature.
        let text = std::fs::read_to_string(&log).unwrap();
        let tampered = text.replace("decrypt", "DECRYPTED");
        std::fs::write(&log, tampered).unwrap();
        let out = verify_log(&log, &pub_pem).unwrap();
        assert!(!out.failures.is_empty(), "{out:?}");
    }

    #[test]
    fn query_filters() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("q.jsonl");
        append_line(
            &log,
            &rec("decrypt", "alice", "2026-08-01T10:00:00.000000000Z", &["A"]),
        )
        .unwrap();
        append_line(
            &log,
            &rec("encrypt", "bob", "2026-08-02T10:00:00.000000000Z", &["B"]),
        )
        .unwrap();
        append_line(
            &log,
            &rec("decrypt", "bob", "2026-08-03T10:00:00.000000000Z", &["A"]),
        )
        .unwrap();

        let q = |q: AuditQuery| query(&log, &q).unwrap();
        assert_eq!(
            q(AuditQuery {
                op: Some("decrypt".into()),
                ..Default::default()
            })
            .len(),
            2
        );
        assert_eq!(
            q(AuditQuery {
                user: Some("bob".into()),
                ..Default::default()
            })
            .len(),
            2
        );
        assert_eq!(
            q(AuditQuery {
                word: Some("A".into()),
                ..Default::default()
            })
            .len(),
            2
        );
        assert_eq!(
            q(AuditQuery {
                since: Some("2026-08-02".into()),
                ..Default::default()
            })
            .len(),
            2
        );
        assert_eq!(
            q(AuditQuery {
                since: Some("2026-08-02".into()),
                until: Some("2026-08-02".into()),
                ..Default::default()
            })
            .len(),
            1
        );
        // Signature lines never appear in query output even if mixed in.
        let mut rng = botan::RandomNumberGenerator::new_system().unwrap();
        let (priv_pem, _) = pki::keygen(SigAlgKind::Ed25519, &mut rng).unwrap();
        record_invocation(&log, "store", &[], &[], 0, 1, Some(&priv_pem)).unwrap();
        assert_eq!(q(AuditQuery::default()).len(), 4);
    }

    #[test]
    fn bound_normalization() {
        assert_eq!(
            normalize_bound("2026-08-01", false),
            "2026-08-01T00:00:00.000000000Z"
        );
        assert_eq!(
            normalize_bound("2026-08-01", true),
            "2026-08-01T23:59:59.999999999Z"
        );
        assert_eq!(
            normalize_bound("2026-08-01T12:00:00.000000000Z", true),
            "2026-08-01T12:00:00.000000000Z"
        );
    }
}
