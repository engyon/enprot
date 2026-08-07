# 63 — Audit trail

**Priority**: P2
**Status**: specified

## Problem

enprot's chain anchors provide **content** provenance (who signed
which file state, when). They don't provide **operational**
provenance: who ran `enprot decrypt`, on which file, from which
host, at what time. For enterprise/compliance use cases, this
operational audit trail is required:

- "Show me every decrypt of files containing WORD=PAYROLL in the
  last 30 days."
- "Who ran `enprot encrypt-store` on the config file after the
  security incident?"
- "Was the recovery key used? When? By whom?"

The chain anchor DAG is append-only and tamper-evident, but it
records *transformations* (encrypt/decrypt/store/fetch), not
*invocations* (who called the CLI, with what args, from where).

## Goals

- An optional `--audit-log <FILE>` flag that appends a structured
  record for every operation.
- Records carry: timestamp, hostname, username, subcommand, WORDs,
  files, exit status.
- The log is append-only (no rewrite/delete by enprot itself).
- The log is signed at close time with the user's key, so tampering
  is detectable.
- A `enprot audit query` command for filtering/searching the log.

## Design

### Log format

JSON Lines (`.jsonl`), one record per line:

```json
{"ts":"2026-08-07T12:00:00Z","host":"build-server-01","user":"ci","op":"decrypt","word":"SECRET","file":"config.ept","exit":0,"duration_ms":42}
{"ts":"2026-08-07T12:01:00Z","host":"build-server-01","user":"ci","op":"encrypt-store","word":"CONFIG","file":"secrets.ept","exit":0,"duration_ms":128}
```

JSON Lines is:
- Append-only-friendly (no JSON array brackets to manage).
- Line-delimited (grep-friendly).
- Streaming-parseable (no need to load the whole file).

### Audit record shape

```rust
#[derive(Serialize)]
pub struct AuditRecord {
    pub ts: String,             // RFC 3339
    pub host: String,           // hostname
    pub user: String,           // $USER or getpwuid
    pub op: String,             // subcommand name
    pub words: Vec<String>,     // --word values
    pub files: Vec<String>,     // input file paths
    pub exit: i32,              // exit code
    pub duration_ms: u64,       // wall-clock duration
    pub key_fingerprint: Option<String>,  // if --signer was used
    pub recovery_used: bool,    // if recovery key was used (TODO #59)
}
```

### Signing

When `--audit-log FILE` is passed and `--signer` is also passed,
enprot signs the session's audit records at exit time and appends a
signature record:

```json
{"ts":"...","type":"signature","records":42,"signer":"ed25519:abc...","sig":"..."}
```

A verifier reads the log, separates data records from signature
records, and checks each signature against the preceding batch.

### CLI surface

```sh
# Enable audit logging
enprot encrypt --audit-log /var/log/enprot-audit.jsonl -w WORD FILE

# Query the audit log
enprot audit query --log /var/log/enprot-audit.jsonl \
                    --since 2026-08-01 \
                    --op decrypt \
                    --user alice
```

### Performance

Writing one JSON line per invocation adds < 1ms. The file is opened
in append mode, written, and closed per operation (no long-held
locks). For high-throughput pipelines, the log can be written to a
pipe and ingested by a log collector (Fluentd, Vector).

## Implementation plan

1. Add `AuditRecord` type + serde.
2. Add `--audit-log` flag to `CommonArgs`.
3. In `app_main`, wrap the dispatch in a timer + audit-record writer.
4. Add `enprot audit query` subcommand.
5. Add signing-at-close for audit records.
6. Document the audit trail format in `docs/audit.md`.
7. Test the log is append-only across concurrent invocations.

## Test plan

- [ ] Each subcommand produces one audit record.
- [ ] Records contain correct timestamp, user, hostname.
- [ ] Concurrent invocations don't corrupt the log (no interleaved
  lines).
- [ ] `enprot audit query` filters by time/op/user correctly.
- [ ] Signature verification detects tampered records.

## Out of scope

- Remote audit log shipping ( syslog, OTLP — use a log collector).
- Real-time alerting on audit events (organisational tool).
- Encryption of the audit log at rest (use filesystem encryption).
- Tamper-evident logging beyond per-session signatures (use a Merkle
  tree or chain anchor for stronger guarantees).
