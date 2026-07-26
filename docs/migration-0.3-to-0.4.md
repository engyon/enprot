# Migration guide: 0.3.x → 0.4.x

## Breaking changes

### 1. Subcommand CLI (issue #22)

**Before** (0.3.x):
```sh
enprot -e -w Agent_007 -k Agent_007=password file.ept
enprot -d -w Agent_007 -k Agent_007=password file.ept
```

**After** (0.4.x):
```sh
enprot encrypt -w Agent_007 -k Agent_007=password file.ept
enprot decrypt -w Agent_007 -k Agent_007=password file.ept
```

Common flags (`-v`, `-k`, `-c`, `--policy`) work before or after
the subcommand name. Encrypt-specific flags (`--cipher`,
`--pbkdf`) go after `encrypt`.

### 2. CAS-referenced encrypt default (TODO.roadmap/42)

**Before** (0.3.x): `encrypt` always produced inline `DATA`
lines with base64 ciphertext.

**After** (0.4.x): `encrypt` with an explicit `-c <dir>`
produces a CAS-referenced block (hash pointer instead of inline
ciphertext). This is merge-friendly — two candidate ciphertexts
no longer produce textual conflicts.

To restore the old behavior:
```sh
enprot encrypt --inline -w WORD -k WORD=pw file.ept
```

### 3. CONFLICT directive (TODO.roadmap/43)

**New** (0.4.x): the merge driver emits `CONFLICT` / `OURS` /
`THEIRS` / `END` blocks when both sides modify the same WORD
region differently. These are valid EPT — the file remains
parseable host-language source.

To clear conflicts:
```sh
enprot resolve --mode ours file.ept
```

### 4. Chain anchors (TODO.roadmap/17)

**New** (0.4.x): `--anchor --signer priv.pem` appends a signed
CHAIN block after the transform. Verify with:
```sh
enprot verify-chain --trust-root pub.pem file.ept
```

### 5. Feature-gated library (TODO.finalize/36)

**New** (0.4.x): downstream Rust crates can depend on enprot
without clap:
```toml
[dependencies]
enprot = { version = "0.4", default-features = false }
```

## Non-breaking additions

- `enprot keygen` / `sign` / `verify-sig` — Ed25519, ML-DSA, composite
- `enprot manifest` / `attest` — SLSA-style provenance
- `enprot scm` — supply-chain manifest with Cargo.toml dep parsing
- `enprot resolve` — conflict resolver (ours/theirs/both/skip/interactive)
- `enprot clean` / `smudge` / `textconv` — git filter integration
- `enprot init` — config file + gitattributes scaffolding
- `enprot inspect` — combined diagnostic (structure + anchors + caps)
- `enprot conflicts` — list unresolved CONFLICT blocks
- `--format json` on inspection subcommands
- `--policy-file` for capability policy enforcement
- Multi-signer chain anchors and detached multi-sig bundles
- KEM-based multi-recipient encryption (`--recipient`)
- Layered TOML config (`.enprot.toml` + `~/.config/enprot/config.toml`)
