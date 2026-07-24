# Stage 5c — Source code provenance

## Why

Software supply-chain attacks (SolarWinds, codecov, etc.) exploited
the gap between "what was built" and "what was attested". SLSA /
S2C2N / NIST SSDF all call for cryptographic provenance: every build
artifact should be traceable to a specific source commit, builder,
and inputs.

Enprot's chain anchors + Merkle tree + Ed25519 sigs map directly
onto SLSA provenance: each source file is an EPT document, every
build produces a manifest EPT file that uses `INCLUDE` (TODO 25) for all
sources, the manifest is signed.

## Scope

1. `enprot provenance manifest` subcommand:
   - Walks a project tree
   - For each file: compute hash, emit `INCLUDE <hash>` in the
     manifest (after storing content in CAS)
   - At manifest close: emit chain anchor with `mutations: provenance
     build=<build-id> inputs=<file-count>`
2. `enprot provenance attest --signer <key>`: sign the manifest
3. `enprot provenance verify --policy-file <path>`: enforce
   - Trust roots (acceptable builder keys)
   - Required inputs (cannot build without these)
   - Forbidden inputs (these must NOT be in the tree)
4. CycloneDX / SLSA Provenance JSON output (`--format slsa` /
   `--format cyclonedx`)
5. CI integration: GitHub Actions example that produces provenance
   on every build

## Real-life example (docs)

```sh
# Builder identity
enprot keygen ed25519 --out-priv builder.pem --out-pub builder.pub

# Produce provenance manifest
enprot provenance manifest . --output build-$(git rev-parse HEAD).ept

# Attest
enprot provenance attest --signer builder.pem build-$(git rev-parse HEAD).ept

# Verify downstream
curl -O https://corp.example/build-abc123.ept
cat > policy.toml <<EOF
[chain]
trust_roots = ["ed25519:$(enprot fingerprint builder.pem)"]
[provenance]
required_inputs = ["src/", "Cargo.lock", "Cargo.toml"]
forbidden_inputs = ["secrets.env"]
EOF
enprot provenance verify --policy-file policy.toml build-abc123.ept
```

## Out of scope

- reproducible builds enforcement (we capture inputs, can't force
  build determinism)
- Binary transparency log (caller can append to a public log)
- SBOM enrichment (callers can layer CycloneDX on top)

## Acceptance criteria

- Manifest correctly enumerates project tree
- INCLUDE references resolve through CAS
- SLSA Provenance JSON validates against the official schema
- CI example documented in `docs/examples/provenance.md`
