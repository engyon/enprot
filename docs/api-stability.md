# enprot API Stability Policy

**Status**: living document; reviewed on every release.
**Last reviewed**: 2026-08-07.

This document defines which parts of enprot's surface are stable,
which are beta, and which are experimental. Users can rely on stable
surfaces; experimental surfaces may break without notice.

## Why this matters

Without a stability policy, every release is a potential breaking
change. Users can't answer:

- "Is `cargo update enprot` safe?"
- "Can I depend on `enprot::etree::parse` in my crate?"
- "Will `--word` change shape between minor versions?"

This document answers those questions per surface.

## Stability tiers

| Tier | Meaning | Versioning |
|---|---|---|
| **stable** | Backward-compatible within the current major version. Breaking changes require a major bump + 1-minor deprecation cycle. | SemVer respected. |
| **beta** | Stable within the current minor version. May break between minors. | Breaking changes don't bump major, but ARE documented. |
| **experimental** | No stability guarantee. May break on any release. | Use at your own risk. |

## Surface classification

### 1. CLI surface

| Item | Tier | Since |
|---|---|---|
| Subcommand names (`encrypt`, `decrypt`, `store`, `fetch`, `encrypt-store`, `passthrough`) | stable | 0.5.0 |
| Subcommand names (`verify`, `list`, `inspect`, `verify-chain`, `audit-log`, `snapshot`, `pin`, `manifest`, `attest`, `scm`, `clean`, `smudge`, `textconv`) | beta | 0.5.0 |
| Flag `--word` / `-w` | stable | 0.5.0 |
| Flag `--password` / `-k` | stable | 0.5.0 |
| Flag `--casdir` | beta | 0.5.0 |
| Flag `--policy` | beta | 0.5.0 |
| Flag `--fips` | beta | 0.5.0 |
| Flag `--signer` | beta | 0.5.0 |
| Flag `--anchor` | beta | 0.5.0 |
| Flag `--jobs` | experimental | 0.5.13 |
| Flag `--format json` (per subcommand) | experimental | 0.5.0 |
| Flag `--otel-endpoint` | experimental | future (TODO #38) |
| Exit codes (0 = success, 1 = error, 2 = arg parse fail) | stable | 0.5.0 |
| Exit codes (specific codes per error kind) | experimental | future |
| Stdout text format | beta | 0.5.0 |
| Stdout JSON format (`--format json`) | experimental | 0.5.0 |
| Stderr (log messages) | experimental | always |

### 2. Rust library surface

| Item | Tier | Since |
|---|---|---|
| `enprot::Error` (the enum itself) | experimental | 0.5.0 (will stabilise post-#26) |
| `enprot::Error::Io`, `Botan`, `Hex`, `Cipher`, `Pbkdf`, `Policy`, `Cas` | beta | 0.5.0 |
| `enprot::Error::Parse`, `PolicyViolation`, `Phc`, `Json`, `Msg` | experimental | 0.5.0 |
| `enprot::Error::InvalidArg`, `Extfield`, `SignatureVerify`, `BlockShape`, `ConflictResolve` | experimental | 0.5.13 |
| `enprot::etree::parse`, `transform`, `tree_write` | beta | 0.5.0 |
| `enprot::etree::TextTree`, `TextNode` | beta | 0.5.0 |
| `enprot::etree::ParseOps` | experimental | 0.5.0 |
| `enprot::etree::streaming::*` | experimental | 0.5.13 |
| `enprot::prot::encrypt`, `decrypt` | beta | 0.5.0 |
| `enprot::cas::CasStore` trait | experimental | 0.5.0 (will stabilise post-#27) |
| `enprot::cas::LocalCas`, `MemoryCas` | experimental | 0.5.0 |
| `enprot::ledger::*` (Anchor, AnchorDag, etc.) | experimental | 0.5.0 |
| `enprot::pki::*` | experimental | 0.5.0 |
| `enprot::pbkdf::*` | experimental | 0.5.0 |
| `enprot::cipher::*` | experimental | 0.5.0 |
| `enprot::capability::*` | experimental | 0.5.0 |
| `enprot::sigstore::*` | experimental | 0.5.13 |
| `enprot::scm::*` | experimental | 0.5.0 |

### 3. FFI surface

| Item | Tier | Since |
|---|---|---|
| `enprot_process(config_json: *const c_char) -> EnprotResult` | experimental | 0.5.0 (will stabilise at 1.0) |
| `EnprotResult` struct layout | experimental | 0.5.0 |
| `enprot_free_result(res: *mut EnprotResult)` | experimental | 0.5.0 |
| Error code constants (`ENPROT_ERR_IO`, etc.) | beta | 0.5.0 |

### 4. EPT wire format

| Item | Tier | Since |
|---|---|---|
| `BEGIN <WORD>` / `END <WORD>` | stable | 0.1.0 |
| `// <( ... )>` default separators | stable | 0.1.0 |
| `DATA <base64>` (48 bytes per line) | stable | 0.1.0 |
| `STORED <WORD> <hash>` | stable | 0.1.0 |
| `ENCRYPTED <WORD> pbkdf:... cipher:...` extfield format | beta | 0.5.0 |
| `CHAIN signer:... payload:... sig:...` extfield format | beta | 0.5.0 |
| `IMMUTABLE <name> <hashalg>=<hash>` + `MUTABLE <name>` closer | beta | 0.5.0 |
| `MUTED <name> <hashalg>=<hash>` | beta | 0.5.0 |
| `INCLUDE <hash>` | beta | 0.5.0 |
| `CONFLICT <WORD>` + `OURS` / `THEIRS` / `END <WORD>` | beta | 0.5.0 |
| `KEY` / `UNKEY` / `CERT` / `UNCERT` directives | experimental | 0.5.0 |

### 5. Configuration files

| Item | Tier | Since |
|---|---|---|
| `.enprot.toml` schema | beta | 0.5.0 |
| `.enprot/policy.toml` (capability policy) | experimental | 0.5.0 |
| `.gitattributes` for smudge/clean | stable | 0.5.0 |

## Deprecation cycle

When a **stable** item needs to change:

1. **Minor N**: deprecate the old form
   (`#[deprecated(since = "0.5.N", note = "use new_thing instead")]`).
   Add the new form alongside. Both work; the old form emits a warning.
2. **Minor N+1**: old form still works, warning persists.
3. **Major bump**: remove the old form.

For **beta** items, breaking changes follow a shorter cycle:

1. **Minor N**: introduce the new form alongside the old.
2. **Minor N+1**: remove the old form.

For **experimental** items: no notice required.

## CI enforcement

`.github/workflows/semver.yml` runs `cargo-semver-checks` on every PR
that touches `src/` or `enprot-ffi/src/`:

```yaml
- run: cargo install cargo-semver-checks
- run: cargo semver-checks check-release
```

This catches:
- Removed public items (functions, types, variants).
- Changed signatures (added required args, type changes).
- New required trait methods.

It doesn't catch:
- Renames (Rust allows re-exports).
- Behavioral changes (only signature changes).
- CLI flag changes (no semver-checks equivalent for CLI).

## Attribute convention (future)

When the attribute macro from TODO #40 lands, every public item will
carry a stability annotation:

```rust
#[stable(since = "0.5.0")]
pub fn parse(/* ... */) -> /* ... */ { /* ... */ }

#[beta(since = "0.5.0")]
pub fn transform(/* ... */) -> /* ... */ { /* ... */ }

#[experimental(since = "0.5.0", tracking = "TODO.complete/27")]
pub trait CasStore { /* ... */ }
```

`cargo doc` will render stability badges; `scripts/api-audit.sh`
produces a report of all stable items for review on each release.

## Review process

This document is reviewed:

- **On every release** — the release manager verifies the classification
  table reflects the current code.
- **On any PR that adds a public item** — the PR author proposes a
  tier; reviewers confirm.

Items can graduate between tiers:

- **experimental → beta**: after ≥1 minor version of real use without
  breaking changes.
- **beta → stable**: after ≥2 minor versions of real use without
  breaking changes, AND a documented test that locks the behavior.

Items cannot be demoted (stable → beta) without a major version bump.

## See also

- [TODO.complete/40-api-stability-semver](../TODO.complete/40-api-stability-semver.md)
- [TODO.complete/42-migration-guide](../TODO.complete/42-migration-guide.md)
- [CHANGELOG.md](../CHANGELOG.md)
- [SECURITY.md](../SECURITY.md)
