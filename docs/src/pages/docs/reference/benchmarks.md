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

Numbers from the latest scheduled run are appended to that run's job
summary; the table below is refreshed when results materially change.

| Metric | enprot | SOPS | git-crypt |
|--------|--------|------|-----------|
| diff noise (1-line plaintext edit) | segment-local | whole-block rewrite | whole-file rewrite |
| merge, different secrets | clean by construction | conflict-prone | conflict-prone |
| throughput / overhead | see workflow summary | | |

## Reading the numbers

Throughput gaps of 2–5× between tools rarely matter — decryption is
not on any hot path for any of them. Diff noise and merge behavior
compound on every commit, review, and rebase; they are the axes this
project optimizes for, and the ones whole-file tools cannot buy back.
