# CONTEXT — enprot domain vocabulary

The shared language of this codebase. Architecture reviews, code
comments, and commit messages use these terms exactly; when a term
here is sharpened, update this file in the same change.

## The document

- **EPT (Engyon Protected Text)** — any text-based file carrying
  enprot directives. The unit of processing.
- **WORD** — the name of a protected segment (`BEGIN Agent_007`).
  The grain of confidentiality: transforms key off it; passwords
  and capability requirements are per-WORD.
- **directive** — a host-language comment line between the
  **separators** (default `// <(` … `)>`) that the parser
  recognizes: `BEGIN`, `END`, `DATA`, `STORED`, `ENCRYPTED`,
  `CHAIN`, `INCLUDE`, `CONFLICT`.
- **separator** — the left/right comment delimiters for the host
  language; presets selected by `--lang` (a programming language,
  not a locale).
- **TextTree / TextNode** — the intermediate representation: a tree
  of `Plain`, `Data`, `Stored`, `Encrypted`, `BeginEnd`, `Chain`,
  `Include`, `Conflict` nodes. Parse produces it; `tree_write`
  inverts it.
- **visitor / Control** — the single deep traversal over a
  TextTree (`etree::visitor::visit` / `visit_mut` / `visit_depth`).
  A visitor sees
  nodes pre-order (parents before children) and returns
  `Control::Continue` or `Control::Prune` (skip children, keep
  walking siblings).
- **extfield** — the `key:value` pairs on `ENCRYPTED` and `CHAIN`
  directive lines. Typed on the read side by views
  (`EncryptedExtFields`); raw string keys are private to the owning
  module (e.g. escrow's `recovery:` key).

## The pipeline

- **ParseOps** — the mutable pipeline state threaded through parse,
  transform, and write: separators, transforms, passwords, crypto
  config, runtime state, IO, anchor config. Deliberately a struct
  of inner structs (2026 audit decomposition); shared by the sync,
  streaming, and async pipeline variants.
- **transform** — the store / fetch / encrypt / decrypt mutations
  on a TextTree, keyed by WORD.
- **CAS (content-addressed storage)** — blobs named by their
  SHA3-256 hex. Backends: `LocalCas`, `MemoryCas`, S3, IPFS/Kubo,
  the Rekor transparency layer, plugin-registered schemes.
- **chain anchor** — a `CHAIN` directive recording a signed
  snapshot of file state: parents, signer, timestamp, payload hash,
  signature. Anchors form a DAG; `verify-chain` walks it.
- **escrow block** — an `ENCRYPTED` block whose payload key is a
  wrapped **CEK** (content-encryption key) reachable via the
  password *or* any recovery private key (ML-KEM). Detected only
  through `escrow::is_escrow_block`.
- **pgp recipient** — an OpenPGP public key that received the CEK of
  an escrow block (`pgp-<fp16>-wrap` extfields, added v0.5.75). The
  matching armored secret key decrypts via `--key-file`, no password.
- **rotation** — re-wrapping an escrow block's CEK under new
  password/recovery key material; the payload ciphertext is
  byte-identical.

## Trust and policy

- **policy** — the crypto gate (`default` | `nist`): which
  ciphers, hashes, and PBKDF parameters are permitted, plus
  defaults. FIPS mode forces nist.
- **capability** — what the caller may do with a WORD (viewer /
  reader / decryptor / signer / verifier tiers), evaluated by the
  cap policy.
- **signer backend** — where a signature's private key lives
  (`software` today; PKCS#11 / TPM / Secure Enclave are the
  hardware tiers behind the `Signer` trait).
- **deterministic cipher (`-det`)** — a cipher variant where the
  same (password, plaintext) yields the same ciphertext (CAS dedup);
  incompatible with escrow (the fresh CEK breaks the contract).
