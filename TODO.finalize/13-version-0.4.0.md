# Version 0.4.0 release

## Why 0.4.0

The CLI surface has changed in breaking ways since 0.3.1:

- Subcommand-style CLI (`enprot encrypt FILE` instead of `enprot -e FILE`).
- `-w` no longer splits on commas inside passwords. Use multiple `-k`
  flags for multiple WORD=PASSWORD pairs.
- `--lang` preset flag added.
- `verify`, `list`, `completions` subcommands added.
- Botan 3 minimum (was Botan 2).
- Rust edition 2024 / rust-version 1.85 minimum (was edition 2015).

Per SemVer, breaking changes → minor bump on a 0.x project.

## Scope

1. `Cargo.toml`: `version = "0.4.0"`.
2. `CHANGELOG.md`: new `## [0.4.0] - 2026-07-24` section under
   `## [Unreleased]`, with Breaking / Added / Changed / Fixed buckets.
3. README.adoc badge / version reference (if any) updated.
4. Tag `v0.4.0` *only after* the deploy workflow is confirmed green
   on `main` post-merge. Tagging is a release action; the user does
   this, never the assistant.

## Out of scope

- Code changes beyond the version bump and changelog.
- Publishing to crates.io / Snap Store — the deploy workflow handles
  that on tag push, and only the user pushes tags.
