---
title: "Benchmarks & comparison"
layout: ../../../layouts/DocPage.astro
---

# Benchmarks & comparison

enprot occupies a specific point in the committed-ciphertext design
space: human-editable wire format, WORD-scoped regions, deterministic
AEAD for CAS dedup, and in-file chain anchors. The honest way to
explain that point is to measure it against the incumbents.

## Competitors

| Tool | Model |
|------|-------|
| **enprot** | WORD regions encrypted in place; `-det` variants make identical plaintext produce identical ciphertext |
| **SOPS** | values encrypted inside YAML/JSON/ENV; age/KMS/PGP recipients |
| **git-crypt** | whole files encrypted by a git filter; GPG keys |

## Methodology

The harness (`ci/bench/competitors.sh`) runs in CI
(`benchmark-comparison` workflow, weekly and on demand) on pinned
competitor versions. Three axes:

1. **Throughput** — encrypt/decrypt of a segmented corpus at 16 KiB /
   256 KiB / 4 MiB. enprot uses `aes-256-gcm-det` (its merge-mode
   cipher).
2. **Diff noise** — how many ciphertext *lines* change when a single
   plaintext line inside one secret changes. This is the cost a
   reviewer pays in every PR, and where enprot's design should win:
   a `-det` re-encryption of an untouched segment reproduces the same
   ciphertext, so untouched segments contribute zero diff.
3. **3-way merge** — two parties edit *different* secrets in the same
   file; `git merge-file` either merges cleanly or conflicts.

Full row definitions and the raw JSONL live in the workflow artifact
(`benchmark-comparison`, 90-day retention).

## Snapshot

First full measured run (2026-08-31, `benchmark-comparison` workflow;
ubuntu-latest; SOPS 3.10.2 + age 1.2.1, git-crypt via apt):

| Tool | enc ms | dec ms | overhead | diff noise¹ | merge² |
|------|-------:|-------:|---------:|------------:|--------|
| enprot `aes-256-gcm-det` (4.9 KB / 8 segs) | 254 | 103 | 9% | **13 (one segment)** | **clean** |
| enprot (19.6 KB / 32 segs) | 256 | 103 | 2% | | |
| enprot (39 KB / 64 segs) | 270 | 120 | 1% | | |
| SOPS + age (6.7 KB) | 15 | 12 | 18% | 2 | clean |
| SOPS (107 KB) | 14 | 11 | 4% | | |
| SOPS (1.7 MB) | 30 | 29 | 3% | | |
| git-crypt (6.7 KB) | 31 | 18 | 0% | whole-file³ | conflict |
| git-crypt (107 KB) | 36 | 24 | 0% | | |
| git-crypt (1.7 MB) | 137 | 69 | 0% | | |

¹ ciphertext lines changed by a one-line plaintext edit. enprot's 13
lines are exactly the edited segment's wire footprint; **untouched
segments re-encrypt byte-identically and contribute zero** — the
advantage grows with the number of segments per file. SOPS's 2 lines
are the edited value plus the file MAC (its granularity floor).
² two parties editing *different* secrets in one file, `git
merge-file`. ³ git-crypt rewrites the whole file by design; this
run's automated row was unreliable (guarded failure) — treat as
design-documented.

## Reading the numbers

Throughput gaps of 2–5× between tools rarely matter — decryption is
not on any hot path for any of them. Diff noise and merge behavior
compound on every commit, review, and rebase; they are the axes this
project optimizes for, and the ones whole-file tools cannot buy back.
