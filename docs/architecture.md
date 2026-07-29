# Architecture

## Overview

enprot is a **document confidentiality and provenance processor**. It
parses host-language comments containing EPT (Engyon Protected Text)
directives, then applies idempotent transformations: store, fetch,
encrypt, decrypt.

The design follows three principles:

1. **Parse → transform → write** — a strict pipeline. Each phase is
   pure; side effects (file I/O, CAS writes) happen only at the
   boundaries.
2. **Model-driven** — the `TextTree` / `TextNode` IR is the single
   source of truth. Every transform operates on the tree, never on
   raw text.
3. **Open/closed** — new directives, ciphers, CAS backends, and
   signer providers are added by implementing a trait, not by
   editing switch statements in existing code.

## Module map

```
src/
├── lib.rs            — public API + app_main orchestrator
├── main.rs           — thin binary entry point (delegates to lib)
├── cli.rs            — clap CLI definition + dispatch
├── config.rs         — TOML config file parsing
├── error.rs          — thiserror Error enum (no string errors)
│
├── etree/            — the core IR + parser + writer + transforms
│   ├── mod.rs        — TextTree, TextNode, Directive, ParseOps
│   ├── parse.rs      — line-oriented parser → TextTree
│   ├── transform.rs  — store/fetch/encrypt/decrypt mutations
│   ├── write.rs      — TextTree → output (inverse of parse)
│   └── blob.rs       — CAS blob serialization helpers
│
├── crypto.rs         — hash/PBKDF wrappers over Botan
├── cipher.rs         — SymmetricCipher trait (Botan + RustCrypto)
├── pbkdf.rs          — PBKDF key derivation (legacy/timed/manual)
├── prot.rs           — high-level encrypt()/decrypt()
├── password.rs       — TTY-aware password reading
├── cas.rs            — CasStore trait + LocalCas + MemoryCas
├── kemenc.rs         — KEM-based multi-recipient encryption
│
├── pki.rs            — keygen, sign, verify (Ed25519, ML-DSA)
├── openpgp.rs        — OpenPGP via rnp-rs (librnp FFI)
├── provider.rs       — SignerProvider / KemProvider traits
├── capability.rs     — capability ledger model + provenance
│
├── policy/           — CryptoPolicy trait
│   ├── mod.rs        — trait definition + default impl
│   ├── default.rs    — permissive default policy
│   └── nist.rs       — FIPS-aligned policy (AlgKind enum)
│
├── ledger/           — chain/anchor DAG
│   ├── mod.rs        — ChainBlock, AnchorNode
│   ├── anchor.rs     — anchor construction + signing
│   └── dag.rs        — DAG traversal + verification
│
├── merge/mod.rs      — WORD-aware three-way merge driver
├── resolve/mod.rs    — conflict resolver (ours/theirs/union/manual)
├── scm/mod.rs        — Git smudge/clean filter integration
├── provenance/mod.rs — SigningProvenance (Local/Threshold/Hardware)
├── extfield.rs       — typed ExtField enums (write-side safety)
├── merkle.rs         — Merkle tree for anchor DAG
├── cappolicy.rs      — capability-based access policy
├── output.rs         — structured JSON / text output
├── consts.rs         — shared constants
└── utils.rs          — misc helpers
```

## Data flow

```
Input file
    │
    ▼
 parse()          ← etree/parse.rs — line scanner, directive dispatch
    │
    ▼
 TextTree          ← etree/mod.rs — Vec<TextNode> IR
    │
    ▼
 transform()      ← etree/transform.rs — per-node mutation
    │                 dispatches to: store, fetch, encrypt, decrypt
    │                 crypto ops via: prot.rs → cipher.rs → botan
    │                 CAS ops via: cas.rs → CasStore trait
    │
    ▼
 tree_write()     ← etree/write.rs — IR → output text
    │
    ▼
 Output file
```

## TextNode IR

Five node kinds cover the full EPT surface:

| Variant | Purpose |
|---------|---------|
| `Plain(String)` | Host text — preserved verbatim |
| `Data(Vec<u8>)` | Raw ciphertext bytes (base64 in wire form) |
| `Stored { keyw, cas }` | CAS pointer (content-addressed) |
| `BeginEnd { keyw, txt }` | BEGIN/END segment (IMMUTABLE/MUTABLE) |
| `Encrypted { keyw, txt, extfields }` | Must contain one Data or Stored child |

Plus integrity nodes: `Immutable`, `Muted`, `Key`, `Cert`, `Unkey`,
`Uncert` — these pass through transforms unchanged (they are
provenance/integrity directives, not confidentiality transforms).

## Trait extensibility points

| Trait | Implement to add |
|-------|-----------------|
| `SymmetricCipher` | New AEAD (e.g., XChaCha20-Poly1305) |
| `CasStore` | New CAS backend (S3, IPFS) |
| `SignerProvider` | Sync signing (PEM, PKCS#11) |
| `AsyncSignerProvider` | Async signing (Confium threshold, cloud KMS) |
| `KemProvider` | Key encapsulation (ML-KEM, threshold) |
| `CryptoPolicy` | Regulatory policy (FIPS, custom) |

Each trait is `Send + Sync + Debug` and returns `Result<T>` — no
panicking, no unwrapping in production paths.

## Dependency graph

```
enprot
├── botan (3.x)          — crypto primitives (AES, SHA-3, Ed25519, …)
├── aes-gcm-siv          — RFC 8452 AES-GCM-SIV (Botan doesn't implement)
├── rnp-rs (librnp)      — OpenPGP signatures (required, not optional)
├── clap (4.x)           — CLI parsing (feature-gated under "cli")
├── thiserror            — error enum derive
├── serde + serde_json   — JSON output, config parsing
├── toml                 — config file
├── phf                  — compile-time hash maps for alg lookup
├── zeroize              — zero secrets on drop
├── hex                  — hex encode/decode
└── rpassword            — password prompt (TTY-aware)
```

## CI architecture

| Workflow | Purpose |
|----------|---------|
| `tests.yml` | Matrix: {ubuntu, macOS, Windows} × {stable, beta, 1.88} |
| `deploy.yml` | Tag-driven release: cross-compile, publish to crates.io + GitHub Releases + Snap |
| `ohos.yml` | OpenHarmony cross-compile (continue-on-error — librnp upstream blocker) |
| `release.yml` | release-plz: auto-changelog + tag on push to main |
| `deploy-docs.yml` | Docs site deploy |

## Testing strategy

- **Unit tests** (`#[cfg(test)] mod tests`) — crypto KATs, parser
  edge cases, wire-format round-trips.
- **Integration tests** (`tests/cli/*.rs`) — end-to-end via
  `assert_cmd` driving the compiled binary. 33 test files.
- **Property tests** (`tests/proptest_roundtrip.rs`) — 256 random
  inputs per property; checks round-trip + determinism.
- **Fuzz targets** (`fuzz/fuzz_targets/`) — parser, extfield, merge
  driver, conflict well-formedness.
- **Benchmarks** (`benches/`) — criterion: crypto, merkle, parser,
  comparison.

No mocks. All tests use real Botan, real librnp, real files.
