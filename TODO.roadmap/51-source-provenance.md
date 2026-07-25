# 51 — Source provenance (SLSA-style)

**Priority**: P2
**Status**: specified (consolidated from TODO.finalize/29)

## CLI

```sh
# Builder identity
enprot keygen ed25519 --out-priv builder.pem --out-pub builder.pub

# Walk project tree, emit INCLUDE per source file
enprot provenance manifest . --output build-$GIT_SHA.ept

# Sign as the builder
enprot provenance attest --signer builder.pem build-$GIT_SHA.ept

# Customer verifies
enprot provenance verify --policy-file customer-policy.toml build-$GIT_SHA.ept
# → checks: anchor signed by trusted builder, required inputs present,
#   forbidden inputs absent, INCLUDE hashes resolve through CAS
```

## Dependencies

- INCLUDE directive (shipped, PR #117)
- Chain anchors (shipped)
- Capability policy (roadmap 46)
- CAS for source file storage

## Output formats

- `--format slsa` → SLSA Provenance JSON
- `--format cyclonedx` → CycloneDX SBOM

## Acceptance criteria

- [ ] Manifest correctly enumerates project tree
- [ ] INCLUDE references resolve through CAS
- [ ] SLSA JSON validates against official schema
- [ ] Docs with CI integration example
