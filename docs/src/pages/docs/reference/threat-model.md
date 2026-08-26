---
title: "Threat Model"
layout: ../../../layouts/DocPage.astro
---

# enprot Threat Model

**Status**: living document; reviewed on every release.
**Last reviewed**: 2026-08-07.

This document captures what enprot protects, against whom, and how.
It is the authoritative answer to "is this a security bug?" — if a
behavior violates an **in-scope guarantee** below, it's a bug. If it
falls under **out-of-scope**, it's a known limitation.

## 1. Assets

enprot handles the following sensitive data:

| Asset | Where it lives | Sensitivity |
|---|---|---|
| Plaintext WORD segments | In-memory tree; CAS blobs (when store op used) | High |
| Passwords | In-memory `paops.passwords`; TTY prompt input | High |
| Private keys (signing) | `--signer <PRIV.pem>` file; in-memory during sign | Critical |
| Private keys (recipient) | `--key-file <PRIV.pem>` for KEM decrypt | Critical |
| PBKDF-derived key material | In-memory `cache` | High |
| Ciphertext (post-encrypt) | Output file / CAS blobs | Low (encrypted) |
| Chain anchor signatures | Output file | Public |
| CAS content hashes | Output file / CAS filenames | Public |

The most valuable assets are the **plaintext**, **passwords**, and
**private keys**. Everything else is derived or public.

## 2. Adversaries

### In scope

| Adversary | Capabilities | What we defend against |
|---|---|---|
| Network observer | Read/MITM traffic to GitHub Releases, crates.io | Signature verification of release artifacts (#45) |
| Disk-only adversary | Steals laptop / disk image; reads `.ept` files | Ciphertext confidentiality (AES-256-SIV); CAS content addressing |
| Same-user process | Reads `~/.enprot/`, env vars, `ps` output | No plaintext in env vars; passwords via TTY prompt (no echo); 0600 perms on key files |
| Cryptanalytic adversary (current) | Knows the cipher algorithm; tries to break it | Policy-approved ciphers only (AES-256-SIV, AES-256-GCM-SIV); constant-time comparison where applicable |
| Quantum adversary (signatures, future) | Harvests anchors today; forges Ed25519 chain signatures once a CRQC exists | ML-DSA + composite signature algorithms (`keygen`, chain anchors); `migrate-keys` for per-anchor rollout ([pq-migration.md](pq-migration.md)) |
| Compromised dependency | A crate in the dep tree is malicious | `cargo audit` + `cargo deny` in CI; reproducible builds (#45) |
| Supply-chain CI attacker | Modifies a GHA workflow to inject code | Tag-protected workflow changes; signed releases |

### Out of scope

| Adversary | Why out of scope |
|---|---|
| Root/admin on the host | Can read process memory, swap, etc. — beyond enprot's threat model |
| Hardware side-channel (Spectre, etc.) | OS/hardware concern; use full mitigations at OS level |
| Quantum adversary (symmetric, current) | AES-256 and SHA3-256 have comfortable margins against Grover; nothing to do at current sizes |
| Coercion ("rubber-hose") | Out of scope; use a real password manager + deniable encryption if needed |

## 3. Attack surface

| Surface | Risk | Mitigation |
|---|---|---|
| CLI arguments | Visible via `ps` on multi-user systems | Acceptable; document the risk; `ENPROPT_KEY=WORD=password` is the env-var alternative |
| Environment variables | Visible via `/proc/<pid>/environ` to same-user | Documented; user's choice |
| stdin/stdout pipes | Same-user process can read | Acceptable; pipe to a file with 0600 perms |
| CAS directory | File permissions are user-controlled; default 0644 on blobs | Document `umask 077` recommendation; consider enforcing 0600 in a future release |
| Config files (`.enprot.toml`) | Same-user readable | 0600 by default via `enprot init` |
| Build dependencies (Botan, rnp-rs, etc.) | A backdoor in a dep ships to users | `cargo audit` + `cargo deny` + reproducible builds (#45) |
| GitHub Actions CI | Compromised secret, malicious PR merged | Tag-protected workflows; signed release artifacts (#45) |
| Language bindings (Python/Node/Go/Ruby) | Bindings are a thin wrapper around the FFI | FFI is `unsafe`-audited; bindings do no crypto themselves |

## 4. In-scope guarantees

These are the security properties enprot commits to. Violations are
bugs.

| # | Guarantee | Verified by |
|---|---|---|
| G1 | Ciphertext confidentiality: AES-256-SIV/GCM-SIV under a strong password resists offline attack | `proptest_roundtrip.rs`; cipher tests with known-answer vectors |
| G2 | Password hardening: PBKDF2 ≥ 1000 iters, scrypt N≥2¹⁴, Argon2id with policy-approved cost | `tests/policy.rs::pbkdf_below_floor_rejected` |
| G3 | Tamper detection: any change to a CHAIN anchor's payload invalidates every subsequent anchor | `verify-chain` end-to-end tests |
| G4 | CAS content addressing: the CAS filename equals SHA3-256(content); a mismatch is detected on load | `proptest_invariants.rs::cas_dedup` |
| G5 | Signature non-repudiation: a CHAIN anchor signature is verifiable by anyone holding the pubkey | `tests/cli/issue_15.rs` + signature round-trip tests |
| G6 | Forward secrecy of keyless signatures (log_index=0 local verify only — NOT a substitute for real Fulcio+Rekor) | `sigstore.rs::verify_rejects_wrong_payload` |
| G7 | FIPS mode (`--fips`) restricts to NIST-approved algorithms only | `tests/policy.rs::fips_forces_nist` |
| G8 | Private key files are written with 0600 perms on Unix | `write_key_or_stdout` code path; manual verification |

## 5. Out-of-scope (non-guarantees)

These are NOT security properties enprot provides. Documenting them
prevents false confidence.

| # | Non-guarantee | Why | What to do instead |
|---|---|---|---|
| N1 | Side-channel resistance of Botan primitives | Botan's responsibility | Use a hardware crypto accelerator if you need SCA resistance |
| N2 | Resistance to root-level adversaries | Root can `ptrace` enprot, dump memory, etc. | Use full-disk encryption; run enprot in a sandboxed container |
| N3 | Constant-time comparison of passwords | enprot uses a real password prompt, not constant-time compare | Use a password manager; never type passwords where they could be keylogged |
| N4 | Protection against compromised build toolchain | Compiler/rustc could inject backdoors | Use reproducible builds (#45) + a trusted builder |
| N5 | Quantum-safe encryption | PQC algorithms (ML-KEM, ML-DSA) are on the roadmap but not the default | If PQC is required today, layer enprot on top of a PQC tunnel |
| N6 | Zeroization of in-memory secrets on drop | Rust doesn't guarantee zeroization; `Drop` may not run | Use `zeroize` crate (planned future TODO); reboot after handling secrets |
| N7 | Constant-time PHC string comparison | PHC strings are not secret (they're stored alongside ciphertext) | N/A |
| N8 | mlock() of crypto buffers | Not currently called; buffers may swap | Disable swap, or wait for future TODO |

## 6. Mitigations

Specific defenses enprot implements:

- **0600 perms on private keys** — `write_key_or_stdout` in `pki_cmd.rs`.
- **TTY-aware password prompt** — `password::read_password` uses `rpassword`
  with echo suppression; piped input skips repeat-verification.
- **No plaintext in env vars** — `ENPROPT_KEY=WORD=password` is supported
  but documented as visible via `/proc`.
- **CAS hash comparison is non-constant-time** — acceptable because CAS
  hashes are content-derived, not secret-derived (N7).
- **Sigstore keyless (log_index=0)** — local verification of the embedded
  pubkey; full Fulcio+Rekor integration is TODO #32.
- **Reproducible builds (TODO #45)** — every release binary should be
  byte-rebuildable from source.
- **`cargo audit` + `cargo deny`** — CI gates on dep vulnerabilities.
- **Tag-protected workflows** — release workflow only runs on tagged
  commits.

## 7. Open questions

These are unresolved; they may become in-scope guarantees or stay
non-guarantees.

- **Q1**: Should enprot `mlock()` crypto buffers to prevent swap leaks?
  Pro: defense against N8. Con: requires `setuid` or capabilities on
  Linux; may fail silently.
- **Q2**: Should we add `--paranoid` flag that double-checks every
  CAS hash, every signature, every cipher invocation? Pro: catches
  implementation bugs. Con: 2× runtime; redundant for the common case.
- **Q3**: What's the canonical way to wipe the in-memory `TextTree`
  after use? `zeroize::Zeroize` on `Vec<TextNode>`?
- **Q4**: Should we add a `--audit-log` mode that emits every
  encrypt/decrypt/sign event to an append-only log?
- **Q5**: Should the FFI expose a "scrub secrets" call that
  zeroizes all in-memory state?

## 8. Review process

This document is reviewed:

- **On every release** — by the release manager.
- **On any crypto-related PR** — by ≥1 reviewer with security context.
- **On any new dep added to Cargo.toml** — to update §3 attack surface.

Changes to the threat model are versioned: each release's threat
model is preserved in `docs/threat-model-v<version>.md` (future).

## See also

- [SECURITY.md](../SECURITY.md) — vulnerability reporting process.
- [docs/fips.md](fips.md) — FIPS mode details.
- [docs/code-signing.md](code-signing.md) — release signing.
- TODO.complete/32-sigstore-keyless-fulcro-rekor.md — full keyless signing.
- TODO.complete/45-reproducibility-verification.md — reproducible builds.
