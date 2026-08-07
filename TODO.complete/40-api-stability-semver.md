# 40 — API stability + semver policy

**Priority**: P1
**Status**: specified

## Problem

enprot's public API has three surfaces:

1. **CLI** (subcommands, flags, exit codes) — consumed by scripts + CI.
2. **Rust library** (`enprot::*` public modules) — consumed by FFI + downstream crates.
3. **FFI** (`enprot-ffi/src/lib.rs`) — consumed by Python/Node/Go/Ruby bindings.

Each surface has a different stability expectation, but none is
documented. Users can't tell:

- Is `cargo update enprot` safe between minor versions?
- Can I depend on `enprot::etree::parse` in my crate?
- Will the CLI flag `--word` change shape?

Without a policy, every release is a potential breaking change.

## Goals

- `docs/api-stability.md` documents which surface is:
  - **stable**: backward-compatible within the current major version.
  - **beta**: stable within the current minor version; may break between minors.
  - **experimental**: no stability guarantee; may break on any release.
- A `#[stable]` / `#[beta]` / `#[experimental]` attribute (custom
  proc macro or doc comment) annotates every public item.
- CI gate: a `cargo-semver-checks` run on every PR that touches
  `src/` or `enprot-ffi/src/`.
- Breaking changes follow a deprecation cycle (≥1 minor version
  notice).

## Design

### Surface classification

| Surface | Stability | Since |
|---|---|---|
| **CLI subcommands + flags** | beta | 0.5.0 |
| **CLI exit codes** | beta | 0.5.0 |
| **CLI stdout format (text)** | beta | 0.5.0 |
| **CLI stdout format (JSON)** | experimental | 0.5.0 |
| **`enprot::Error` enum** | experimental | 0.5.0 (will stabilise post-#26) |
| **`enprot::etree::parse` / `transform` / `tree_write`** | beta | 0.5.0 |
| **`enprot::prot::encrypt` / `decrypt`** | beta | 0.5.0 |
| **`enprot::cas::CasStore` trait** | experimental | 0.5.0 |
| **`enprot::ledger::*`** | experimental | 0.5.0 |
| **`enprot::pki::*`** | experimental | 0.5.0 |
| **FFI (`enprot_process` etc.)** | experimental | 0.5.0 |

### Attribute convention

```rust
// src/lib.rs
//! # API stability
//!
//! Items marked `#[stable]` ...
//! Items marked `#[beta]` ...
//! Items marked `#[experimental]` ...

/// Stable public API.
#[stable(since = "0.5.0")]
pub fn parse(/* ... */) -> /* ... */ { /* ... */ }

/// Beta-quality API; may change between minor versions.
#[beta(since = "0.5.0")]
pub fn transform(/* ... */) -> /* ... */ { /* ... */ }

/// Experimental; no stability guarantee.
#[experimental(since = "0.5.0", issue = "TODO.complete/27")]
pub trait CasStore { /* ... */ }
```

The attributes are inert (no compile-time effect). Tooling reads them:

- `cargo doc` could render stability badges (future work).
- A `scripts/api-stability-audit.sh` greps for `#[stable]` items and
  produces a list to review on each release.

### CI gate

`.github/workflows/semver.yml`:

```yaml
jobs:
  semver-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - uses: dtolnay/rust-toolchain@stable
      - run: cargo install cargo-semver-checks
      - run: cargo semver-checks check-release
```

This catches:
- Removed public items (functions/types/variants).
- Changed signatures (added required args, changed types).
- New required trait methods.

### Deprecation cycle

When a stable item needs to change:

1. **Minor N**: deprecate the old form (`#[deprecated(since = "0.5.2")]`).
   Add the new form alongside. Both work.
2. **Minor N+1**: the old form still works but emits a warning.
3. **Major Bump**: remove the old form.

Experimental items can break without notice.

## Implementation plan

1. Write `docs/api-stability.md` with the full classification.
2. Add `#[stable]` / `#[beta]` / `#[experimental]` attributes
   (custom proc macro in a new `enprot-macros` crate, or simple
   doc comments for v1).
3. Annotate the top ~30 public items based on the classification table.
4. Add `cargo-semver-checks` to CI.
5. Document the deprecation cycle in CONTRIBUTING.md.
6. Add a `CHANGELOG.md` section template that prompts authors to
   flag breaking changes.

## Test plan

- [ ] `cargo semver-checks` passes on main.
- [ ] An intentional breaking change (e.g. rename `parse` to
  `parse_tree`) is caught by CI.
- [ ] Every annotated item has a `#[stable]` / `#[beta]` /
  `#[experimental]` line that renders in `cargo doc`.

## Out of scope

- A formal RFC process for breaking changes (organisational).
- Semver compatibility checks for the CLI (no good tool exists).
- Freezing the FFI ABI at 1.0 (deferred).
