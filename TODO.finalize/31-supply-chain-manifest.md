# Stage 5e — Supply chain manifest

## Why

A vendor distributing software wants to attest to: which sources
were used, which dependencies (with hashes), which build commands,
which tests ran. Customers verify the manifest before installing.

Distinct from TODO 29 (provenance, which is build-time) — supply
chain manifest is **distributable**: it travels with the artifact,
customers verify it on their side.

## Scope

1. `enprot scm init`: scaffolds a `.enprot/` directory with policy,
   cas backing, key fingerprints
2. `enprot scm add <path>`: adds a file to the manifest (stores in
   CAS, emits INCLUDE)
3. `enprot scm deps <manifest>`: parses Cargo.toml / package.json /
   requirements.txt etc., adds each dependency hash to manifest
4. `enprot scm attest --signer <key>`: signs the manifest
5. `enprot scm verify --policy-file <path>`: customer-side; checks
   signatures, dependency hashes, policy
6. Differential verification: `enprot scm diff <old> <new>` shows
   what changed between two manifest versions (audit-friendly)
7. Tests: full vendor→customer flow

## Real-life example (docs)

```sh
# Vendor side
cd my-crate/
enprot scm init
enprot scm add src/
enprot scm add Cargo.toml
enprot scm deps Cargo.toml   # adds each `[dependencies]` crate hash
enprot scm attest --signer vendor.pem
# publishes manifest.v1.ept alongside the .crate file

# Customer side
curl -O https://vendor.example/my-crate-1.0.crate
curl -O https://vendor.example/manifest.v1.ept
cat > customer-policy.toml <<EOF
[chain]
trust_roots = ["ed25519:$(enprot fingerprint vendor.pub)"]
[scm]
allowed_licenses = ["MIT", "BSD-2-Clause", "Apache-2.0"]
forbidden_deps = ["openssl-sys"]   # policy: no openssl
EOF
enprot scm verify --policy-file customer-policy.toml manifest.v1.ept
```

## Out of scope

- License discovery (cargo-deny does this; we consume its output)
- Vulnerability scanning (cargo-audit; we consume)
- Runtime policy enforcement (out of scope; we verify at install)

## Acceptance criteria

- Full vendor→customer flow works on a sample crate
- Differential verification produces a useful change report
- Cargo, npm, pip ecosystems supported (parse deps files)
- Docs page with the full workflow
