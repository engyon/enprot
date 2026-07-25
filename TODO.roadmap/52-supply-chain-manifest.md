# 52 — Supply chain manifest

**Priority**: P2
**Status**: specified (consolidated from TODO.finalize/31)

## CLI

```sh
# Vendor side
enprot scm init
enprot scm add src/
enprot scm add Cargo.toml
enprot scm deps Cargo.toml   # adds each [dependencies] hash
enprot scm attest --signer vendor.pem
# → publishes manifest.v1.ept alongside the .crate

# Customer side
enprot scm verify --policy-file customer-policy.toml manifest.v1.ept
# → checks: vendor signature, dependency hashes, license policy,
#   forbidden deps (e.g., openssl-sys)

# Differential verification
enprot scm diff manifest.v1.ept manifest.v2.ept
# → shows added/removed deps, changed source hashes, new signers
```

## Dependencies

- INCLUDE (shipped)
- Chain anchors (shipped)
- Capability policy (roadmap 46)
- Cargo/npm/pip dependency parsing

## Acceptance criteria

- [ ] Full vendor → customer flow on a sample crate
- [ ] Differential verification produces useful change report
- [ ] Cargo, npm, pip dependency ecosystems
- [ ] Docs page with full workflow
