# 48 — Static FIPS build

## Problem

enprot's `--fips` flag selects the `nist` policy and the
FIPS-compliant algorithms. But the underlying Botan library is built
with all sorts of algorithms, only some of which are FIPS-validated.
The current binary still *links* Botan's full crypto surface; we just
refuse to call the non-FIPS ones at the policy layer.

A real FIPS deployment needs the binary to *only contain* FIPS-validated
crypto. Botan's documentation mentions a "FIPS 140 build mode" that
disables builtins and wraps an OpenSSL FIPS module.

## Approach

This is almost entirely a CI / packaging concern, not a Rust code change.
`--fips` already does the right thing at the policy layer; what's missing
is a build profile that produces a binary with the right Botan.

### CI job (`.github/workflows/fips.yml`)

A new optional workflow that:

1. Builds the OpenSSL FIPS module (or pulls a prebuilt one).
2. Builds Botan with `--with-fips` (or whatever the current Botan 3 flag
   is — needs verification against `configure.py --help`).
3. Statically links enprot against that Botan.
4. Runs the test suite under `--fips` and confirms nothing leaks.
5. Optionally produces a release archive tagged `fips`.

### enprot code

Probably none. The existing `--fips` flag and the `nist` policy are
already what we'd want. If Botan's FIPS module rejects e.g. Argon2 (it
likely does — Argon2 isn't FIPS-validated), the nist policy already
forbids Argon2; that aligns.

If anything, add a `--strict-fips` mode that *additionally* refuses to
start if the running Botan reports non-FIPS algorithms available. But
Botan doesn't expose that query in the Rust crate. Probably skip.

### Realistic scope

This issue is open since 2020 with no movement because it's genuinely
hard:

- OpenSSL FIPS module builds are non-trivial across platforms.
- Botan's FIPS mode docs are sparse; need to verify the Botan side
  actually works.
- FIPS certification is per-binary, so even a "FIPS build" only counts
  if the *resulting binary* is certified. We can produce a build that
  *looks* like FIPS, but claiming compliance requires the certification
  paperwork.

What this PR can deliver: a CI job that builds enprot against a
Botan-built-with-OpenSSL-FIPS, runs the existing tests under `--fips`,
and uploads the binary. Labelling it "FIPS-mode build" not "FIPS-certified".

## Files

- `.github/workflows/fips.yml` (new)
- `ci/build-fips.sh` (new) — script that does the OpenSSL FIPS + Botan
  build, parameterised by target.
- `docs/fips.md` (new) — explains what the build does and doesn't prove.

## Verification

CI job runs green. Locally, reproduce by:

```
ci/build-fips.sh x86_64-unknown-linux-musl
```

And confirm the resulting binary still passes `cargo test` under `--fips`.

## Defer if

If OpenSSL FIPS module setup proves fragile across the matrix targets,
scope down to just linux-musl-x86_64 and document that.

## Rollback

Delete the workflow and the build script.
