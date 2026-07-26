# Engyon: enprot

[![Build Status](https://github.com/engyon/enprot/actions/workflows/tests.yml/badge.svg)](https://github.com/engyon/enprot/actions?workflow=tests)
[![MSRV 1.85](https://img.shields.io/badge/MSRV-1.85-blue)](https://blog.rust-lang.org/2025/02/20/Rust-1.85.0.html)
[![crates.io](https://img.shields.io/crates/v/enprot)](https://crates.io/crates/enprot)

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

### From crates.io

```sh
cargo install enprot
```

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

### Shell completions

After installation, generate completions for your shell:

```sh
enprot completions bash  > /etc/bash_completion.d/enprot
enprot completions zsh   > ~/.zsh/completions/_enprot
enprot completions fish  > ~/.config/fish/completions/enprot.fish
enprot completions powershell | Out-File enprot.ps1
```

## Quick start

```sh
mkdir cas                                               # CAS storage directory
enprot init                                             # config + cas/ + .gitattributes
enprot encrypt -w Secret -k Secret=password file.txt    # encrypt inline
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
| `STORED <WORD> <hash>` | A CAS pointer — the segment's content lives in the CAS file named `<hash>`. |
| `ENCRYPTED <WORD> [hash] [pbkdf:… cipher:…]` | An encrypted segment. If a hash is present, the ciphertext is in CAS; otherwise inline `DATA` lines follow. |
| `DATA <base64>` | One or more base64-encoded ciphertext lines inside an `ENCRYPTED` block. |
| `CHAIN key:val …` | Signed chain anchor — tamper-evident history. |
| `INCLUDE <hash>` | Cross-file CAS reference (provenance manifests). |
| `CONFLICT <WORD>` | Merge-driver conflict marker (resolved by `enprot resolve`). |

### Host-language separators

Use `-l`/`-r` to override the separators for non-`//` languages, or use
the `--lang` preset:

| `--lang` | Left sep | Right sep |
|----------|----------|-----------|
| `raw` | `<(` | `)>` |
| `c` | `// <(` | `)>` |
| `python` | `# <(` | `)>` |
| `html` | `<!-- <(` | `)> -->` |
| `latex` | `% <(` | `)>` |

Example: encrypt a Python file's segments with `# <(` comments:

```sh
enprot --lang python encrypt -w Secret -k Secret=pw script.py
```

## Subcommands

### encrypt

Encrypt WORD segments inline (ciphertext stays in the document):

```sh
enprot encrypt -w Agent_007 -k Agent_007=bond sample/test.ept
```

If no `-k` is given, you are prompted interactively (with repeat).

Encrypt-specific options (run `enprot encrypt --help` for the full list):

| Option | Description |
|--------|-------------|
| `--cipher <ALG>` | `aes-256-siv` (default), `aes-256-gcm`, `aes-256-gcm-siv`, `aes-256-gcm-det`, `aes-256-gcm-siv-det` |
| `--pbkdf <ALG>` | `argon2` (default), `scrypt`, `pbkdf2-sha256`, `pbkdf2-sha512`, `legacy` |
| `--pbkdf-msec <MSEC>` | Time-budget for KDF parameter tuning (default 100) |
| `--pbkdf-salt-len <N>` | Salt length in bytes (default 16) |
| `--pbkdf-params <K=V,…>` | Override KDF parameters manually (testing) |
| `--pbkdf-salt <HEX>` | Fixed salt (testing) |
| `--pbkdf-disable-cache` | Disable PBKDF cache (slower, but no shared derivation state) |
| `--cipher-iv <HEX>` | Fixed IV (testing) |
| `--recipient <PUB.pem>` | ML-KEM multi-recipient encryption (repeatable) |
| `--inline` | Force inline `DATA` blocks instead of CAS-referenced |

### decrypt

Decrypt WORD segments:

```sh
enprot decrypt -w Agent_007,GEHEIM -k Agent_007=bond -k GEHEIM=james sample/test.ept
```

Multiple WORDs are comma-separated or repeated. Multiple `-k` flags
supply passwords for different WORDs.

For KEM-mode blocks (encrypted with `--recipient`):

```sh
enprot decrypt -w Agent_007 --key-file priv.pem sample/test.ept
```

### store

Sanitize WORD segments to CAS — replace the segment content with a
`STORED <WORD> <hash>` pointer and write the original content to a file
named by its SHA3-256 hash:

```sh
enprot store -w GEHEIM sample/test.ept
```

After storing, the CAS directory contains the content:

```
$ ls cas
cea67c3ef34ff899793b557e9178c1b97bbcfe9722df2f6d35d2d0c91d2c1fe4
```

The same content always produces the same hash, so storing is
idempotent — re-storing identical content is a no-op.

### fetch

Restore WORD segments from CAS:

```sh
enprot fetch -w GEHEIM sample/test.ept
```

### encrypt-store

Encrypt and store in one step. The ciphertext goes to CAS and is
referenced by hash:

```sh
enprot encrypt-store -w Agent_007 -k Agent_007=bond sample/test.ept
```

### verify

Check file integrity without decrypting. Validates markup structure,
CAS pointer resolution (file exists + hash matches), and extfield
formatting:

```sh
enprot verify sample/test.ept
enprot verify *.ept
```

Output is `OK` or `FAIL` per file. Exits non-zero on any failure —
useful in CI pipelines.

### list

List all WORD segments in a file with their type and crypto metadata:

```sh
$ enprot list sample/test.ept
BEGIN/END  GEHEIM
  BEGIN/END  Agent_007
  ENCRYPTED Agent_007  cipher=aes-256-siv  pbkdf=legacy
BEGIN/END  Agent_007
  ENCRYPTED Agent_007  cipher=aes-256-siv  pbkdf=legacy
```

For multiple files, each is headed with `== <path> ==`.

### passthrough

Parse and re-write a file without applying any transform. Useful for
validating markup or measuring parse performance:

```sh
enprot passthrough sample/test.ept
```

### completions

Print a shell completion script:

```sh
enprot completions bash  > /etc/bash_completion.d/enprot
enprot completions zsh   > ~/.zsh/completions/_enprot
enprot completions fish  > ~/.config/fish/completions/enprot.fish
enprot completions powershell | Out-File enprot.ps1
```

### inspect

Combined diagnostic: show structure + chain anchors + conflicts + capabilities
in one pass (exit non-zero if conflicts remain):

```sh
enprot inspect sample/test.ept
```

### keygen / sign / verify-sig

Detached signatures (Ed25519, ML-DSA, and composite constructions):

```sh
# Generate a keypair (PEM, one file each).
enprot keygen ed25519 --out-priv priv.pem --out-pub pub.pem

# Sign a file → produces FILE.sig (raw 64-byte Ed25519 signature).
enprot sign --alg ed25519 --key-file priv.pem document.txt

# Verify → reads document.txt.sig by default.
enprot verify-sig --alg ed25519 --key-file pub.pem document.txt
```

Multi-signer bundles (repeat `--key-file`):

```sh
enprot sign --alg ed25519 --key-file priv1.pem --key-file priv2.pem document.txt
enprot verify-sig --alg ed25519 --key-file pub1.pem --key-file pub2.pem document.txt
```

Override the signature path with `--sig-file PATH` (verify-sig) or
`-o PATH` (sign). Both commands read stdin when no `FILE` is given.

### Chain anchors

Signed chain anchors provide tamper-evident file history:

```sh
# Produce an anchor after a transform.
enprot encrypt --anchor --signer priv.pem -w WORD -k WORD=pw file.ept

# Verify anchors against a trusted pubkey.
enprot verify-chain --trust-root pub.pem file.ept

# Print the current chain head hash (publish out-of-band).
enprot snapshot file.ept

# Verify against a published pin.
enprot pin <expected-hash> file.ept

# List unresolved conflicts (exit non-zero if any).
enprot conflicts file.ept
```

### Merge driver + conflict resolution

```sh
# Git merge-driver contract (%O=ancestor, %A=ours, %B=theirs, %P=path).
enprot merge-driver %O %A %B %P

# Resolve conflicts (one mode for all, or per-WORD overrides).
enprot resolve --mode ours file.ept
enprot resolve --word Agent_007:ours --word GEHEIM:theirs file.ept
```

### Git filters

```sh
enprot init --git    # writes .gitattributes + prints .git/config snippet

# stdin → stdout pipes for git filter/textconv integration.
enprot clean  -w WORD -k WORD=PASSWORD   # plaintext → ciphertext
enprot smudge -w WORD -k WORD=PASSWORD   # ciphertext → plaintext
```

### Provenance + supply chain

```sh
# SLSA-style provenance manifest.
enprot manifest . --output build.ept -c cas/
enprot attest --signer builder.pem build.ept
enprot verify-chain --trust-root builder.pub build.ept

# Supply-chain manifest with Cargo.toml dep parsing.
enprot scm init manifest.ept
enprot scm add manifest.ept src/
enprot scm deps manifest.ept Cargo.toml
enprot scm attest --signer vendor.pem manifest.ept
enprot scm verify --trust-root vendor.pub manifest.ept
enprot scm diff old.ept new.ept
```

## Common options

These flags work with every subcommand (before or after the subcommand
name):

| Flag | Description |
|------|-------------|
| `-v`, `--verbose` | Show parse/transform/write progress on stderr |
| `-q`, `--quiet` | Suppress non-essential output |
| `-k`, `--key <WORD=PASSWORD>` | Supply a password (repeatable; one pair per flag) |
| `-c`, `--casdir <DIR>` | CAS directory (default `./cas` if it exists, else `.`) |
| `-l`, `--left-separator <SEP>` | Left EPT separator (default `// <(`) |
| `-r`, `--right-separator <SEP>` | Right EPT separator (default `)>`) |
| `--lang <LANG>` | Preset separators: `raw`, `c`, `python`, `html`, `latex` |
| `--policy <POLICY>` | Crypto policy: `default` or `nist` |
| `--defaults <POLICY>` | Load a policy's defaults without enforcing it |
| `--fips` | Force FIPS-compliant algorithms (implies `--policy=nist`) |
| `--max-depth <N>` | Maximum nesting depth (default 100; 0 = infinite) |
| `-w`, `--word <WORD>` | WORD(s) to operate on (repeatable, also comma-separated) |
| `-o`, `--output <FILE>` | Output file for the previous input (repeatable) |
| `-p`, `--prefix <PREFIX>` | Prefix for output filenames (directory mode if ends with `/`) |
| `--output-dir <DIR>` | Write outputs into DIR by basename (conflicts with `-p`) |
| `--format <text\|json>` | Output format for inspection subcommands |
| `--policy-file <PATH>` | Capability policy TOML file |
| `--anchor` | Append a signed chain anchor after transform |
| `--inline` | Force inline DATA blocks instead of CAS-referenced |
| `--pbkdf-disable-cache` | Disable PBKDF cache |

## Deterministic encryption

By default, AES-GCM and AES-GCM-SIV use random nonces — encrypting
the same plaintext twice produces different ciphertexts. This breaks CAS
deduplication for encrypted segments.

The `-det` cipher variants derive the nonce from the plaintext via
HKDF + HMAC, making encryption fully deterministic:

| Cipher | Construction |
|--------|-------------|
| `aes-256-gcm-det` | `enc_key = HKDF(master, "enc")`, `iv = HMAC(iv_key, pt)[..12]`, then AES-256-GCM |
| `aes-256-gcm-siv-det` | Same HKDF/HMAC construction, then AES-256-GCM-SIV (misuse-resistant) |

Same `(password, plaintext)` always produces the same ciphertext, so
`encrypt-store` on identical segments deduplicates in CAS.

Usage:

```sh
enprot encrypt -w Agent_007 --cipher aes-256-gcm-det -k Agent_007=bond file.ept
```

## Multi-file processing

Process wildcards in one invocation. Passwords are prompted once:

```sh
enprot encrypt -w Secret -k Secret=pw src/*.rs
```

Output to a different file:

```sh
enprot encrypt -w Secret -k Secret=pw input.ept -o output.ept
```

Output to a directory (basename preserved):

```sh
enprot encrypt -w Secret -k Secret=pw --output-dir build/ src/*.ept
# or equivalently:
enprot encrypt -w Secret -k Secret=pw -p build/ src/*.ept
```

Plain prefix (prepended verbatim — legacy behavior):

```sh
enprot encrypt -w Secret -k Secret=pw -p build_ src/*.ept
# produces: build_src/main.ept, build_src/lib.ept, …
```

## Working on source code

EPT directives inside comments don't break compilation. Enprot's own
source has an encrypted `AUTHOR` block in `src/lib.rs`:

```
// <( ENCRYPTED AUTHOR )>
// <( DATA X417HVMRRAs6Z1xGo5yY4TxUQ2tpAHEKQ1sg9+kfku5uUikK3y2tODtsUiGqfRGW )>
// <( DATA xUCGYFu02BCdqPM7uuX5UNvbfrLvKkj6gLYwg/cr42PJmr4o5xnw1qo= )>
// <( END AUTHOR )>
```

Decrypt it:

```sh
enprot decrypt -w AUTHOR -k AUTHOR=markku src/lib.rs
```

## Crypto policies

Two built-in policies control which algorithms are permitted:

| | `default` | `nist` |
|---|-----------|--------|
| Default cipher | AES-256-SIV | AES-256-GCM |
| Default PBKDF | Argon2 | PBKDF2-SHA-512 |
| Allowed hashes | Any | SHA3-256, SHA3-512 |
| Min salt length | None | 16 bytes |
| Min iterations | None | 1000 |
| GCM IV width | Any | 96 bits |

`--fips` forces the `nist` policy. On Linux, it also auto-engages
when `/proc/sys/crypto/fips_enabled` reads `1`.

See `docs/fips.adoc` for details on what a fully FIPS-validated build
would require.

## Cross-compiling for OHOS (OpenHarmony)

enprot builds for `aarch64-unknown-linux-ohos` (HarmonyOS arm64). The cross-compile
setup is in `ci/setup-ohos-ndk.sh` (NDK download + sysroot symlink) and
`ci/build-botan-ohos.sh` (static Botan). CI runs the full pipeline in
`.github/workflows/ohos.yml` and verifies the binary in `dockerharmony`
(real OHOS userland via qemu binfmt).

Local reproduction:

```sh
sh ci/setup-ohos-ndk.sh --prefix ext/ohos
sh ci/build-botan-ohos.sh --prefix ext/ohos --botan-version 3.7.0
export PKG_CONFIG_PATH=ext/ohos/ohos-aarch64/lib/pkgconfig
export PKG_CONFIG_ALLOW_CROSS=1
export PKG_CONFIG_SYSROOT_DIR=ext/ohos/llvm-19/sysroot/aarch64-linux-ohos
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_OHOS_LINKER=ext/ohos/llvm-19/llvm/bin/aarch64-unknown-linux-ohos-clang++
cargo build --target aarch64-unknown-linux-ohos --release
```

The Rust target uses the `unknown` vendor field (`aarch64-unknown-linux-ohos`);
the NDK clang binary is named after the Rust triple, but the sysroot path
and `--target=` flag use the NDK triple (`aarch64-linux-ohos`, no vendor).
See `docs/ohos-porting-guide.md` for the full porting reference
(NDK architecture, two-sysroots problem, code signing, CI topology).

## Compatibility

Documents encrypted by enprot <=0.3.1 still decrypt. The wire format of
the `pbkdf:` and `cipher:` extended fields is unchanged:

```
// <( ENCRYPTED <keyword> [cas-hash] pbkdf:$<id>$<k=v,k=v>$<base64-salt> cipher:$<alg>$iv=<base64-iv> )>
```

When the ciphertext is in CAS rather than inline, the CAS hash replaces
the inner `DATA` lines and the `cipher:` field carries the IV.

The `legacy` PBKDF (plain SHA3-512 truncation) is retained for
decrypting old blobs; selecting it for new encryption prints a warning.

See `docs/migration-0.3-to-0.4.md` for the full migration guide
(subcommand CLI, CAS-referenced default, CONFLICT directive, chain
anchors, feature-gated library).

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

See `CONTRIBUTING.md` for the full guide. Quick reference:

```sh
cp .githooks/pre-commit .git/hooks/pre-commit && chmod +x .git/hooks/pre-commit
cargo test
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings
typos                    # spell check (cargo install typos-cli)
cargo deny check         # license + advisory check
```

Architecture docs: `CLAUDE.md`. Wire format specs: `docs/schemas/`.
Upgrade history: `TODO.upgrade/`, `TODO.audit/`, `TODO.issues/`,
`TODO.finalize/`, `TODO.roadmap/`.

## License

BSD-2-Clause. See `LICENSE` file.
