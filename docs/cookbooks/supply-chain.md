# Supply-chain attestation with provenance manifests

Demonstrates `enprot manifest`, `enprot scm`, and `enprot attest` —
the SLSA-style provenance pipeline built into enprot. No external
attestation tooling needed; manifests are EPT files, so they
inherit all the chain-anchor, CAS, and verification machinery.

## Why this matters

SLSA / in-toto / sigstore all describe "prove how this artifact was
built." enprot's contribution: the provenance manifest is itself a
text file with cryptographic integrity — no sidecar JSON, no
detached signature blob. Verifiers read the same file distributors
ship.

## Building a manifest from a source tree

```sh
enprot manifest . --output build.ept -c cas/
```

This walks `.`, stores each source file in CAS by its SHA3-256
hash, and emits `build.ept` with an `INCLUDE <hash>` directive per
file:

```
// <( CHAIN ts:20260728T143000Z )>
# path: src/lib.rs
// <( INCLUDE 7a3c9f4b8e… )>
# path: Cargo.toml
// <( INCLUDE 2b8f1e3c4d… )>
…
```

The CHAIN anchor pins the manifest to a specific build time. The
INCLUDE directives reference CAS blobs by content hash — anyone
with the same CAS state reproduces the same manifest.

## Adding Cargo dependency attestation

```sh
enprot scm init supply-chain.ept
enprot scm add supply-chain.ept src/
enprot scm deps supply-chain.ept Cargo.toml
```

`scm deps` parses `[dependencies]`, `[dev-dependencies]`,
`[build-dependencies]`, `[target.*.dependencies]`, and
`[workspace.dependencies]` from `Cargo.toml`, resolves each dep's
current version, and emits a `# dep:` annotation in the manifest:

```
# dep: botan ^0.11 -> 0.11.1
# dep: rnp-rs ^0.1.7 -> 0.1.7
…
```

## Signing the manifest

```sh
enprot attest --signer builder-priv.pem build.ept
enprot scm attest --signer vendor-priv.pem supply-chain.ept
```

Both commands append a `CHAIN` block with `signer:`, `sig:`,
`payload:`, `parents:` extfields. The signature is over the
manifest's pre-anchor state — the file-tree hash before this
anchor was added.

## Verifying

```sh
enprot verify-chain --trust-root builder-pub.pem build.ept
enprot scm verify --trust-root vendor-pub.pem supply-chain.ept
```

Returns OK if the anchor signature is valid under the supplied
trust root AND the payload hash matches the file's current state.
Returns FAIL if either check fails.

## Diffing manifests

Two manifests from different builds/branches can be diffed to
surface dependency changes:

```sh
enprot scm diff old.ept new.ept
```

Output:

```
+ dep: foo ^1.0 -> 1.2.3       (added)
- dep: bar ^2.0 -> 2.1.0       (removed)
~ dep: baz ^0.5 -> 0.5.0       (was 0.4.2, now 0.5.0)
```

The diff is itself an EPT document — it can be signed and verified
as evidence of intentional dependency changes.

## Pinning at install time

For reproducible installs, capture the manifest head hash and
verify it on the install side:

```sh
# Distributor side
HASH=$(enprot snapshot build.ept)
echo "$HASH" > build.ept.sha256

# Installer side
enprot pin "$(cat build.ept.sha256)" build.ept
```

`enprot pin` exits non-zero if the file's current head doesn't
match the expected hash. Useful in CI:

```sh
enprot pin "$PINNED_HASH" build.ept || {
    echo "supply chain attestation failed!" >&2
    exit 1
}
```

## Composing with sigstore / cosign

enprot doesn't replace artifact signing — it complements it. The
typical composition:

```sh
# Sign the source provenance with enprot (document-level)
enprot manifest . --output build.ept -c cas/
enprot attest --signer builder-priv.pem build.ept

# Sign the built artifact with cosign (artifact-level)
cargo build --release
tar czf app.tar.gz target/release/app
cosign sign-blob --key cosign.key app.tar.gz

# Both signatures are independently verifiable
enprot verify-chain --trust-root builder-pub.pem build.ept
cosign verify-blob --key cosign.pub app.tar.gz
```

## What this demonstrates

- SLSA-style provenance is built-in, not bolt-on.
- Diff between two manifests surfaces dependency changes
  programmatically.
- Pinning gives reproducible verification at install time.
- Composes with sigstore / cosign without overlap or conflict.
