# Quickstart cookbook

End-to-end recipes for getting real work done with enprot. Every
recipe is a copy-pasteable shell transcript you can run from a clone
of this repo.

For scenario-focused walkthroughs see the sibling cookbooks:
[`classified-documents.md`](classified-documents.md),
[`collaborative-editing.md`](collaborative-editing.md),
[`supply-chain.md`](supply-chain.md).

Recipes here are grouped by use case:

- [Setup](#setup)
- [Single-file workflows](#single-file-workflows)
- [Trees and CI](#trees-and-ci)
- [Git integration](#git-integration)
- [CAS-only flow](#cas-only-flow)
- [Deterministic encryption for dedup](#deterministic-encryption-for-dedup)
- [Multi-recipient PQ encryption](#multi-recipient-pq-encryption)
- [Migrating from SOPS](#migrating-from-sops)
- [Locking secrets in a Docker image](#locking-secrets-in-a-docker-image)
- [Encrypt-on-commit hook](#encrypt-on-commit-hook)
- [Key lifecycle: escrow, rotation, migration](#key-lifecycle-escrow-rotation-migration)
- [Recovery decryption without the password](#recovery-decryption-without-the-password)
- [Rotating the password or recovery keys](#rotating-the-password-or-recovery-keys)
- [Post-quantum migration](#post-quantum-migration)
- [Diagnosing the environment](#diagnosing-the-environment)
- [AI agents: MCP server](#ai-agents-mcp-server)
- [From Python](#from-python)
- [From Node.js](#from-nodejs)

---

## Setup

```sh
brew install botan rnp                       # macOS
brew link --overwrite rnp                    # if it conflicts
cargo install --locked --path . --features vendored-rnp
enprot --version
```

Linux: `./ci/install.sh` builds Botan + librnp from source.

A WORD is the secret-name you bind to a password. Every encrypted
block in a file is tagged with a WORD; only callers who hold the
matching password can decrypt it. Treat WORDs like git branch names:
short, scoped, lowercase (`secret`, `prodcreds`, `agent_007`).

---

## Single-file workflows

### Encrypt one segment, leave the rest readable

```sh
cat > app.conf <<'EOF'
# deployed config
db_host = db.example.com
db_port = 5432

# <( BEGIN SECRET )>
db_password = "hunter2"   # sensitive
# <( END SECRET )>

pool_size = 100
EOF

# Encrypt the SECRET block in place. Same password would have to
# decrypt later.
enprot encrypt -w SECRET=hunter2 app.conf

# app.conf now has:
#   # <( ENCRYPTED SECRET )>
#   # <( DATA 7Z2K... )>
#   # <( END SECRET )>
# Plaintext outside the BEGIN/END block is untouched.

enprot decrypt -w SECRET=hunter2 app.conf    # round-trip
```

### Use a different cipher per call

```sh
enprot encrypt -w SECRET=pw --cipher aes-256-gcm-siv  app.conf
enprot decrypt -w SECRET=pw                          app.conf
```

Supported ciphers: `aes-256-siv` (default), `aes-256-gcm`,
`aes-256-gcm-siv`, plus the `-det` variants for dedup-friendly output.

### Prompt for the password instead of putting it on the CLI

```sh
enprot encrypt -w SECRET app.conf         # no =VALUE → interactive prompt
```

Skips the verification echo when stdin isn't a TTY (CI-friendly).

---

## Trees and CI

### Encrypt every file matching a glob

```sh
enprot encrypt -w SECRET=pw secrets/*.toml secrets/*.yaml
```

enprot processes each file independently. A failure on file N aborts
the run; partial output is left in files 1..N-1.

### Decrypt in CI, never commit plaintext

```yaml
# .github/workflows/test.yml
- uses: engyon/enprot/action@v0.5
  with:
    operation: decrypt
    files: tests/fixtures/secrets.toml
    words: SECRET=${{ secrets.ENPROT_SECRET_WORD }}
- run: pytest                                  # plaintext lives only in CI
```

The plaintext never lands on disk in the repo. After the workflow
finishes, the GitHub Actions runner is destroyed.

### Encrypt-on-publish workflow

```yaml
on:
  push:
    branches: [release/*]
jobs:
  encrypt:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: engyon/enprot/action@v0.5
        with:
          operation: encrypt
          files: |
            config/prod.toml
            config/staging.toml
          words: |
            PROD=${{ secrets.ENPROT_PROD_WORD }},
            STAGING=${{ secrets.ENPROT_STAGING_WORD }}
      - uses: stefanzweifel/git-auto-commit-action@v5
        with:
          commit_message: "chore: encrypt PROD/STAGING blocks for release"
```

---

## Git integration

### Install the merge driver

```sh
# .gitattributes
*.ept  filter=enprot diff=enprot merge=enprot
*.toml filter=enprot diff=enprot merge=enprot

# .git/config (one-time)
git config filter.enprot.clean    "enprot encrypt-store -w SECRET=%ENPROT_WORD"
git config filter.enprot.smudge   "enprot decrypt       -w SECRET=%ENPROT_WORD"
git config diff.enprot.textconv   "enprot decrypt       -w SECRET=%ENPROT_WORD"
git config merge.enprot.driver    "enprot merge-driver %O %A %B %L %P"
```

The driver emits `CONFLICT` blocks instead of `<<<<<<<` markers, so
the merged file stays valid host-language source. Run `enprot resolve`
to clear conflict blocks.

### Mark a region IMMUTABLE so merges can't change it

```
// <( IMMUTABLE VERSION )>
v1.0.0
// <( END IMMUTABLE )>
```

Any branch that changes the body of an `IMMUTABLE` block will fail
`enprot verify` — useful for pinning audit-relevant metadata.

---

## CAS-only flow

For content you want to *delete* from the file but still reference.

### Strip a secret out of the file, leave a CAS pointer

```sh
# Before: file contains plaintext inside a BEGIN/END block.
enprot store -w SECRET=pw app.conf
# After:  file contains
#   # <( STORED SECRET key=abc123... )>
#   # <( END SECRET )>
# The plaintext is written to .cas/abc123... (named by SHA3-256 of bytes).
# Commit the file freely; the secret lives in .cas/ which is .gitignored.

enprot fetch -w SECRET=pw app.conf          # restore on demand
```

### Share CAS pointers across branches

`.cas/` is content-addressed — if two branches independently store
the same plaintext, they produce the same `key=...` hash. Merging
those branches is a no-op for the STORED block. No conflicts.

---

## Deterministic encryption for dedup

The `-det` cipher variants derive the nonce from the plaintext via
HKDF + HMAC. Same `(password, plaintext)` always produces the same
ciphertext.

```sh
# Two files with the same plaintext in SECRET blocks → identical DATA.
enprot encrypt -w SECRET=pw --cipher aes-256-gcm-siv-det a.toml b.toml

# Git diff sees no change when you encrypt then re-encrypt the same content.
```

Use this for:

- Secret rotation where you want to spot which files actually changed
- CAS-dedup of encrypted blobs
- Reproducible builds

---

## Multi-recipient PQ encryption

```sh
# Generate an ML-KEM keypair for each recipient.
enprot keygen --alg ml-kem --out-priv priv_abe.pem --out-pub pub_abe.pem
enprot keygen --alg ml-kem --out-priv priv_bea.pem --out-pub pub_bea.pem

# Encrypt so that EITHER recipient can decrypt.
enprot encrypt \
  -w SECRET=pw \
  --recipient pub_abe.pem \
  --recipient pub_bea.pem \
  app.conf

# Abe decrypts with her private key.
enprot decrypt -w SECRET=pw --recipient-priv priv_abe.pem app.conf
```

ML-KEM is the NIST FIPS 203 post-quantum KEM. Composite
Ed25519+ML-KEM constructions are also supported.

---

## Migrating from SOPS

If you have a SOPS-encrypted YAML file:

```sh
python3 tools/import-sops.py secrets.sops.yaml -o secrets.ept
```

Each encrypted value in the SOPS file becomes a `BEGIN WORD` block
tagged with the SOPS key path. After import, treat it like any other
EPT file. See [`tools/import-sops.py`](../tools/import-sops.py) for
the full README.

---

## Locking secrets in a Docker image

```dockerfile
FROM ghcr.io/engyon/enprot:latest AS encrypt
WORKDIR /work
COPY config/plaintext/ ./config/
RUN enprot encrypt -w SECRET=$ENPROT_WORD --casdir /cas config/*.toml && \
    rm -rf config/*.toml.bak

FROM app:latest
COPY --from=encrypt /work/config/   /etc/app/config/
COPY --from=encrypt /cas/           /var/lib/enprot/cas/
ENV ENPROT_CASDIR=/var/lib/enprot/cas
```

The final image contains only encrypted segments and CAS pointers.
Plaintext lives only in the build-stage layer, which Docker discards.

---

## Encrypt-on-commit hook

```sh
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/engyon/enprot
    rev: v0.5.11
    hooks:
      - id: enprot-plaintext
        name: no plaintext inside BEGIN blocks
        entry: python3 hooks/pre-commit/enprot_pre_commit.py
        language: system
        types: [text]
```

Fails the commit if a `BEGIN WORD ... END WORD` block contains
plaintext that hasn't been encrypted or CAS-stored yet. Catches the
"committed the raw password" footgun.

---

## Key lifecycle: escrow, rotation, migration

The complete enterprise key story: encrypt with a recovery path,
rotate credentials without re-encrypting, and migrate anchor
signatures to post-quantum algorithms — all without losing access.

### Escrow encryption (password + recovery key)

```sh
# Generate an ML-KEM recovery keypair (via the library or your
# organization's provisioning):
cargo test --lib -- escrow keygen  # or see bindings/python

# Encrypt so BOTH the password and the recovery key can decrypt:
enprot encrypt -w SECRET -k SECRET=password \
    --cipher aes-256-siv \
    --recovery-key recovery.pub.pem \
    config.ept
```

The block now carries `recovery:mlkem:<fp>` + `pw-wrap:` extfields.
The password path is unchanged; the recovery path is the
organization's break-glass access.

### Recovery decryption without the password

```sh
# HR needs access to a departed employee's file:
enprot decrypt -w SECRET --key-file recovery.priv.pem config.ept
```

### Rotating the password or recovery keys

```sh
# Rotate the password (payload ciphertext is BYTE-IDENTICAL —
# CAS pointers stay valid, no re-encryption cost):
enprot -k SECRET=old-password rotate \
    --new-password new-password \
    --recovery-key new-recovery.pub.pem \
    config.ept

# Or rotate when the password isn't available (unwrap via the
# current recovery key):
enprot rotate --key-file old-recovery.priv.pem \
    --new-password rotated-pw \
    --recovery-key new-recovery.pub.pem \
    config.ept
```

### Post-quantum migration

```sh
# Migrate chain anchors from Ed25519 to composite (verifies every
# old signature first; parents + payload hashes preserved):
enprot keygen composite-ed25519-mldsa \
    --out-priv new_priv.pem --out-pub new_pub.pem
enprot migrate-keys \
    --from ed25519 --to composite-ed25519-mldsa \
    --old-key old_pub.pem --new-key new_priv.pem \
    document.ept

# Verify under the new key:
enprot verify-chain --trust-root new_pub.pem document.ept
```

See [`../docs/pq-migration.md`](../docs/pq-migration.md) for the
full hybrid-period + rotation-checklist walkthrough.

## Diagnosing the environment

```sh
# One command: versions, linked libraries, resolved policy,
# CAS writability, locale, git filter wiring:
enprot doctor
```

Paste the output in bug reports; use the resolved-policy +
FIPS lines for compliance attestation; run it after install as
an onboarding sanity check.

## AI agents: MCP server

```sh
# Install the server (ships with the release):
enprot-mcp &  # stdio JSON-RPC; agents spawn it as a subprocess

# Or drive it from any MCP-aware agent (Claude Code, Cursor,
# Continue) — add to .mcp.json:
#   { "mcpServers": { "enprot": { "command": "enprot-mcp" } } }
```

Agents get 8 typed tools (`enprot_inspect`, `enprot_encrypt`,
`enprot_decrypt`, `enprot_verify`, `enprot_verify_chain`,
`enprot_snapshot`, `enprot_pin`, `enprot_cap_check`) behind a
filesystem policy gate (`.enprot/mcp-policy.toml`). See
[`../docs/mcp.md`](../docs/mcp.md).

## From Python

```python
import pyenprot

pyenprot.encrypt(
    "config.toml",
    words={"SECRET": "correct horse battery staple"},
    cipher="aes-256-siv",
    casdir=".cas",
)
```

See [`bindings/python/`](../bindings/python/) for install + full API.

---

## From Node.js

```js
const enprot = require("@engyon/enprot");

enprot.encrypt("config.toml", {
  words: { SECRET: "correct horse battery staple" },
  cipher: "aes-256-siv",
  casdir: ".cas",
});
```

See [`bindings/nodejs/`](../bindings/nodejs/) for install + full API.

---

## See also

- [README](../README.md) — overview, install, command reference
- [`classified-documents.md`](classified-documents.md) — multi-level classification in one file
- [`collaborative-editing.md`](collaborative-editing.md) — multi-author signing
- [`supply-chain.md`](supply-chain.md) — provenance manifests
- [CONTRIBUTING.md](../CONTRIBUTING.md) — dev setup
