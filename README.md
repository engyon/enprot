# Engyon: enprot

[![Build Status](https://github.com/engyon/enprot/actions/workflows/tests.yml/badge.svg)](https://github.com/engyon/enprot/actions?workflow=tests)
[![MSRV 1.85](https://img.shields.io/badge/MSRV-1.85-blue)](https://blog.rust-lang.org/2025/02/20/Rust-1.85.0.html)

Enprot is a confidentiality processor for text and source code files.
It lets you embed encrypted, stored, and authenticated segments directly
inside any text-based file — source code, documentation, configuration —
without breaking the host language's syntax.

- **Human-editable markup**: EPT directives sit inside host-language
  comments, so files stay valid C, Rust, Python, Markdown, HTML, or LaTeX.
- **Content-addressed storage (CAS)**: segments can be sanitized out of
  the document and stored by their SHA3-256 hash. Same content always
  produces the same CAS file — deterministic, dedup-friendly.
- **Authenticated encryption**: AES-256-SIV (default), AES-256-GCM, or
  AES-256-GCM-SIV. Password-derived keys via Argon2, Scrypt, or PBKDF2.
  ML-KEM-based multi-recipient encryption via `--recipient`.
- **Deterministic AEAD**: optional `aes-256-gcm-det` / `aes-256-gcm-siv-det`
  variants derive the nonce from the plaintext so identical content
  always produces identical ciphertext — enabling CAS dedup on encrypted
  segments.
- **Chain anchors**: signed `CHAIN` blocks provide tamper-evident file
  history. Multi-signer anchors require N parties to sign.
- **Merge-friendly**: WORD-region merge driver emits `CONFLICT` blocks
  that keep the file valid host-language source. `enprot resolve` clears
  them. CAS-referenced blocks deduplicate across branches.
- **Post-quantum ready**: ML-DSA signatures, ML-KEM key encapsulation,
  and composite Ed25519+ML-DSA constructions ship today.

## Installation

### From source

Enprot requires [Botan 3.x](https://github.com/randombit/botan)
(`brew install botan` on macOS; see `ci/install.sh` for Linux).

```sh
cargo install --git https://github.com/engyon/enprot
```

or build locally:

```sh
git clone https://github.com/engyon/enprot
cd enprot
cargo build --release        # binary at target/release/enprot
```

### From crates.io

```sh
cargo install enprot
```

### Shell completions

```sh
enprot completions bash  > /etc/bash_completion.d/enprot
enprot completions zsh   > ~/.zsh/completions/_enprot
enprot completions fish  > ~/.config/fish/completions/enprot.fish
```

## Quick start

```sh
mkdir cas                                               # CAS storage directory
enprot init                                             # config + cas/ + .gitattributes
enprot encrypt -w Secret -k Secret=password file.txt    # encrypt
enprot decrypt -w Secret -k Secret=password file.txt    # decrypt
enprot store  -w Secret file.txt                        # sanitize to CAS
enprot fetch  -w Secret file.txt                        # restore from CAS
enprot list   file.txt                                  # see segments
enprot inspect file.txt                                 # structure + anchors + capabilities
enprot verify file.txt                                  # check integrity
```

## EPT markup

An EPT file is a normal text file containing **directives** hidden inside
host-language comments. The default separators are `// <(` (left) and
`)>` (right), which work for C, C++, Rust, JavaScript, and other
`//`-comment languages.

A simple example (`sample/test.ept`):

```
hello, this is a test file
// <( BEGIN GEHEIM )>
Secret line 1
Secret line 2
// <( BEGIN Agent_007 )>
James Bond
// <( END Agent_007 )>
// <( END GEHEIM )>
// <( BEGIN Agent_007 )>
Super secret line 3
// <( END Agent_007 )>
```

Directive types:

| Directive | Meaning |
|-----------|---------|
| `BEGIN <WORD>` | Opens a named segment. Segments can nest. |
| `END <WORD>` | Closes the matching segment. |
| `STORED <WORD> <hash>` | A CAS pointer — content lives in the CAS file named `<hash>`. |
| `ENCRYPTED <WORD> [hash] [pbkdf:… cipher:…]` | An encrypted segment. If a hash is present, ciphertext is in CAS; otherwise inline `DATA` lines follow. |
| `DATA <base64>` | Base64-encoded ciphertext inside an `ENCRYPTED` block. |
| `CHAIN key:val …` | Signed chain anchor — tamper-evident history. |
| `INCLUDE <hash>` | Cross-file CAS reference (provenance manifests). |
| `CONFLICT <WORD>` | Merge-driver conflict marker (resolved by `enprot resolve`). |

### Host-language separators

Use `--lang` to preset separators for non-`//` languages:

| `--lang` | Left sep | Right sep |
|----------|----------|-----------|
| `raw` | `<(` | `)>` |
| `c` | `// <(` | `)>` |
| `python` | `# <(` | `)>` |
| `html` | `<!-- <(` | `)> -->` |
| `latex` | `% <(` | `)>` |

## Subcommands

### encrypt

```sh
enprot encrypt -w Agent_007 -k Agent_007=bond sample/test.ept
```

Encrypt-specific options:

| Option | Description |
|--------|-------------|
| `--cipher <ALG>` | `aes-256-siv` (default), `aes-256-gcm`, `aes-256-gcm-siv`, `-det` variants |
| `--pbkdf <ALG>` | `argon2` (default), `scrypt`, `pbkdf2-sha256`, `pbkdf2-sha512`, `legacy` |
| `--recipient <PUB.pem>` | ML-KEM multi-recipient encryption (repeatable) |
| `--inline` | Force inline `DATA` blocks instead of CAS-referenced |
| `--pbkdf-msec <N>` | KDF time budget (default 100ms) |

### decrypt

```sh
enprot decrypt -w Agent_007 -k Agent_007=bond sample/test.ept
enprot decrypt -w Agent_007 --key-file priv.pem sample/test.ept  # KEM mode
```

### store / fetch

```sh
enprot store  -w GEHEIM sample/test.ept   # sanitize to CAS
enprot fetch  -w GEHEIM sample/test.ept   # restore from CAS
```

### verify / inspect / list

```sh
enprot verify  sample/test.ept   # integrity check (exit non-zero on failure)
enprot inspect sample/test.ept   # structure + anchors + capabilities
enprot list    sample/test.ept   # segment listing
```

### keygen / sign / verify-sig

```sh
enprot keygen ed25519 --out-priv priv.pem --out-pub pub.pem
enprot sign --alg ed25519 --key-file priv.pem document.txt
enprot verify-sig --alg ed25519 --key-file pub.pem document.txt

# Multi-signer bundle (repeat --key-file):
enprot sign --alg ed25519 --key-file priv1.pem --key-file priv2.pem document.txt
```

### Chain anchors

```sh
enprot encrypt --anchor --signer priv.pem -w WORD -k WORD=pw file.ept
enprot verify-chain --trust-root pub.pem file.ept
enprot snapshot file.ept    # print chain head hash
enprot pin <hash> file.ept  # verify against published pin
```

### Merge driver + conflict resolution

```sh
enprot merge-driver %O %A %B %P    # git merge-driver contract
enprot conflicts file.ept           # list unresolved conflicts
enprot resolve --mode ours file.ept # clear conflicts
```

### Git filters

```sh
enprot init --git    # writes .gitattributes + prints .git/config snippet
enprot clean  -w WORD -k WORD=PASSWORD   # stdin plaintext → stdout ciphertext
enprot smudge -w WORD -k WORD=PASSWORD   # stdin ciphertext → stdout plaintext
```

### Provenance + supply chain

```sh
enprot manifest . --output build.ept -c cas/   # walk tree, hash each file
enprot attest --signer builder.pem build.ept   # sign the manifest
enprot verify-chain --trust-root builder.pub build.ept

enprot scm init manifest.ept
enprot scm add manifest.ept src/
enprot scm deps manifest.ept Cargo.toml
enprot scm attest --signer vendor.pem manifest.ept
enprot scm verify --trust-root vendor.pub manifest.ept
enprot scm diff old.ept new.ept
```

## Common options

These flags work with every subcommand (before or after the subcommand name):

| Flag | Description |
|------|-------------|
| `-v` / `--verbose` | Show progress on stderr |
| `-k <WORD=PASSWORD>` | Supply a password (repeatable) |
| `-c <DIR>` | CAS directory (default `./cas` if it exists) |
| `--lang <LANG>` | Preset separators: `raw`, `c`, `python`, `html`, `latex` |
| `--policy <POLICY>` | Crypto policy: `default` or `nist` |
| `--fips` | Force FIPS-compliant algorithms |
| `--format <text\|json>` | Output format for inspection subcommands |
| `--policy-file <PATH>` | Capability policy TOML file |
| `--anchor` | Append a signed chain anchor after transform |

## Configuration

`enprot init` writes `.enprot.toml`. Layered resolution:

1. Built-in defaults
2. `~/.config/enprot/config.toml` (user global)
3. `.enprot.toml` (project local, walked up from cwd)
4. `ENPROPT_*` environment variables
5. CLI flags (highest precedence)

```toml
casdir = "cas"
lang = "c"

[encrypt]
cipher = "aes-256-gcm-siv-det"
pbkdf = "argon2"

[chain]
# signer = "confium://session-id"
# auto_anchor = true
```

## Library usage

Enprot can be used as a Rust library without the CLI:

```toml
[dependencies]
enprot = { version = "0.4", default-features = false }
```

The `default-features = false` build excludes `clap` and `clap_complete`.
All library modules (crypto, parsing, capability model, chain anchors,
Merkle trees, merge driver, provenance, SCM) are available.

## Development

```sh
cp .githooks/pre-commit .git/hooks/pre-commit && chmod +x .git/hooks/pre-commit
cargo test
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings
```

Architecture docs: `CLAUDE.md`. Wire format specs: `docs/schemas/`.
Migration guide: `docs/migration-0.3-to-0.4.md`.

## License

BSD-2-Clause. See `LICENSE` file.
