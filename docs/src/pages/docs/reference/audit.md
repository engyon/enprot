---
title: "Audit Trail"
layout: ../../../layouts/DocPage.astro
---

**Status**: living document; format versioned by the `"type"` tag.

The operational audit trail records **who ran which enprot command,
on which files and WORDs, when, and with what outcome**. This is
distinct from chain anchors (`--anchor`, `enprot audit-log`), which
record *content* provenance — signed commitments to file states.

## Enabling

```sh
enprot decrypt --audit-log /var/log/enprot-audit.jsonl -w PAYROLL payroll.ept
```

Every invocation of any subcommand with `--audit-log` set appends
exactly one record — including `enprot audit query` itself (querying
an audit log is an auditable event).

## Format

JSON Lines, internally tagged so the format extends without breaks:

```json
{"type":"record","ts":"2026-08-17T12:00:00.123456789Z","host":"build-01","user":"ci","op":"decrypt","words":["PAYROLL"],"files":["payroll.ept"],"exit":0,"duration_ms":42}
{"type":"signature","ts":"2026-08-17T12:00:00.130000000Z","records":1,"signer":"ed25519:<fp-hex>","sig":"<hex>"}
```

| Field | Meaning |
|---|---|
| `ts` | RFC 3339 UTC, nanosecond precision |
| `host` / `user` | invoking machine and OS user |
| `op` | subcommand name |
| `words` / `files` | `--word` values and input paths |
| `exit` / `duration_ms` | outcome (0 = success) and wall-clock cost |

## Guarantees

- **Append-only**: the log is opened `O_APPEND`, each line written
  with a single `write` (plus `fsync`); concurrent invocations never
  interleave within a line. enprot never rewrites or truncates the
  log.
- **Tamper-evident**: when `--signer PRIV.pem` is also passed, the
  invocation's record is immediately followed by an Ed25519 signature
  over the record's **exact line bytes**. Any edit, removal, or
  reordering of a signed line breaks its signature; a removed
  signature line surfaces as an unsigned record.
- **Cheap**: one open-append-fsync per invocation (sub-millisecond);
  suitable for piping into a log collector.

## Querying

```sh
enprot audit query --log audit.jsonl --op decrypt --word PAYROLL \
                    --since 2026-08-01 --until 2026-08-17
```

Filters combine conjunctively; `--since`/`--until` accept RFC 3339
timestamps or bare `YYYY-MM-DD` (normalized to start/end of day).
Output is the matching original JSON lines — grep/jq-friendly.

## Verifying

```sh
enprot audit verify --log audit.jsonl --trust-root pub.pem
```

Walks the log, verifies every signature batch against the trust
root, and reports: verified count, unsigned count, and per-line
failures. Exits non-zero on any failure or unsigned record.

## Relationship to chain anchors

| | Chain anchors (`--anchor`) | Audit trail (`--audit-log`) |
|---|---|---|
| Records | content state (what) | invocations (who/when) |
| Storage | inside the EPT file | external JSONL file |
| Signing | per-file-state | per-invocation |
| Verify | `enprot verify-chain` | `enprot audit verify` |
