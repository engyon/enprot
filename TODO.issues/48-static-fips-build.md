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

### Status (July 2026)

Resolved as **wontfix-by-doc**: the work needed to produce a genuinely
FIPS-validated binary depends on certification paperwork outside this
repo's scope. `docs/fips.adoc` captures what a real FIPS build would
require (OpenSSL 3.x FIPS provider + Botan 3 built with `--with-openssl`
+ `--enable-modules=fips` + static linking) and explains why enprot
stops at the `--fips` policy flag rather than claiming compliance.

The issue body's original ask ("build botan as an OpenSSL FIPS wrapper
and statically link that") is technically achievable but has been open
since 2020 with no movement because the value of a non-certified
"FIPS-shaped" binary is questionable. Documentation closes the loop
without pretending otherwise.

The `nist` policy (`src/policy/nist.rs`) and the deterministic AES-GCM
variants (`aes-256-gcm-det`, `aes-256-gcm-siv-det`) already enforce the
algorithm-level constraints that a FIPS module would require, so any
future certification work has the policy layer ready.
