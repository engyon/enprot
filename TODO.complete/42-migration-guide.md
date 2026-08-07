# 42 — Migration guide for breaking changes

**Priority**: P2
**Status**: specified

## Problem

enprot evolves. When a breaking change lands (CLI flag rename,
config-file schema change, removed API), users discover it via CI
failures or runtime errors. There's no structured path from "this
changed" to "here's what to do".

The codebase has `CHANGELOG.md` (release-plz generated) but it lists
commits, not migrations. Users need:

- "Flag X was renamed to Y in version Z. Update your scripts."
- "The pbkdf extfield format changed in 0.5.0. Re-encrypt files
  encrypted by older versions."

## Goals

- `docs/migrations/` directory with one file per breaking change.
- Each migration file has: version, what changed, why, before/after
  examples, automated detection script (where possible).
- `CHANGELOG.md` links to migration files.
- A `enprot doctor` command that detects deprecated configs / files
  and suggests migrations.

## Design

### Migration file shape

```
docs/migrations/
├── README.md
├── 0.5.0-cli-subcommands.md
├── 0.5.0-pbkdf-extfield-format.md
├── 0.5.11-ffi-abi-v2.md
└── ...
```

Each migration file:

```markdown
# Migration: pbkdf extfield format (0.5.0)

## What changed
The `pbkdf:` extfield in ENCRYPTED blocks now uses the PHC string
format (`$pbkdf2-sha256$i=1000$...`) instead of the legacy
`pbkdf2-sha256(1000)` format.

## Why
The PHC format is a widely-adopted standard that encodes the salt
and parameters in a self-describing string. The legacy format
required separate fields for each parameter.

## Before / after
```ept
# Before (0.4.x)
// <( ENCRYPTED WORD pbkdf=pbkdf2-sha256(1000) cipher=aes-256-gcm-siv )>

# After (0.5.0+)
// <( ENCRYPTED WORD pbkdf=$pbkdf2-sha256$i=1000$abc... cipher=aes-256-gcm-siv )>
```

## Detection
Run `enprot doctor` to scan for legacy extfields:

    $ enprot doctor path/to/files.ept
    WARN  path/to/files.ept:14  pbkdf extfield uses legacy format
    HINT  re-encrypt with `enprot encrypt -w WORD --pbkdf pbkdf2-sha256 path/to/files.ept`

## Migration
Files encrypted by older versions still decrypt correctly (the
decrypt path auto-detects the format). To upgrade:

    enprot decrypt -w WORD old.ept > plaintext
    enprot encrypt -w WORD --pbkdf pbkdf2-sha256 plaintext > new.ept
```

### `enprot doctor` command

A new subcommand that scans files + config and reports:

- Deprecated CLI flags used in scripts (if it can find them).
- Legacy extfield formats.
- Old config-file schemas.
- Stale CAS references (hashes that point to missing blobs).
- Anchor signature algorithms that are no longer recommended.

Output is human-readable by default, JSON via `--format json`.

### CHANGELOG.md integration

Release-plz generates the changelog from commit messages. Augment
with a "Migrations" section per release that links to the relevant
migration files:

```markdown
## [0.5.2] - 2026-08-15

### Breaking changes
- Renamed `--word` to `--encrypt-word` (see [migration](docs/migrations/0.5.2-word-flag-rename.md))

### Migrations
- [0.5.2 word flag rename](docs/migrations/0.5.2-word-flag-rename.md)
```

## Implementation plan

1. Create `docs/migrations/` with a README template.
2. Write retrospective migration docs for past breaking changes
   (CLI subcommand rewrite in 0.5.0, FFI split, etc.).
3. Implement `enprot doctor` subcommand in `src/cli/doctor.rs`.
4. Wire doctor checks: extfield format, anchor algorithms, CAS
   reference resolution.
5. Add a release-checklist item: "write a migration doc for any
   breaking change".
6. Document the migration workflow in CONTRIBUTING.md.

## Test plan

- [ ] `enprot doctor` detects each known legacy format.
- [ ] Each migration file has before/after examples.
- [ ] CHANGELOG links work.

## Out of scope

- An automated migration tool (e.g. `enprot migrate --auto`). Doctor
  is advisory; users run the migration manually.
- Compatibility shims for indefinitely-old versions (only N-1 supported).
