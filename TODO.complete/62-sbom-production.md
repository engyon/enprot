# 62 — SBOM production (SPDX / CycloneDX)

**Priority**: P2
**Status**: specified

## Problem

A Software Bill of Materials (SBOM) lists every component in a
software product — direct deps, transitive deps, build tools.
Regulatory frameworks (US Executive Order 14028, EU Cyber Resilience
Act) increasingly require SBOMs for security-critical software.

enprot currently produces provenance manifests (`enprot manifest`,
`enprot scm deps`) that list content files + Cargo dependencies. But
these aren't in a standard SBOM format. Consumers can't feed them
into vulnerability scanners (Trivy, Grype) or compliance platforms
that expect SPDX or CycloneDX.

## Goals

- `enprot sbom --format spdx-json > enprot.spdx.json` produces a
  valid SPDX 2.3 document.
- `enprot sbom --format cyclonedx-json > enprot.cdx.json` produces a
  valid CycloneDX 1.5 document.
- The SBOM includes: Rust crate deps (from Cargo.lock), C library
  deps (Botan, librnp, json-c, zlib, bzip2), and the enprot binary
  itself as the top-level package.
- CI generates + uploads an SBOM with every release artifact.
- The SBOM can be consumed by `grype enprot.spdx.json` for
  vulnerability scanning.

## Design

### SBOM generation approach

Two options:

**A. `cargo cyclonedx`** — a Cargo plugin that reads Cargo.lock and
produces a CycloneDX document. Covers Rust deps but NOT C deps
(Botan, librnp).

**B. `enprot sbom`** — a built-in command that reads Cargo.lock +
queries the C dep versions (from build.rs or pkg-config) and
produces a unified SBOM.

Option B is more complete. It mirrors `enprot manifest` but targets
the *software's* supply chain, not the *content's*.

### `enprot sbom` command shape

```sh
enprot sbom [--format spdx-json|cyclonedx-json|spdx-tag] [--output FILE]
```

Reads `Cargo.lock` at the workspace root; queries `pkg-config` for
Botan + librnp versions; merges into one SBOM document.

### SPDX 2.3 output

```json
{
  "spdxVersion": "SPDX-2.3",
  "dataLicense": "CC0-1.0",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "enprot",
  "documentNamespace": "https://engyon.com/spdx/enprot-0.5.14-<hash>",
  "creationInfo": { "created": "...", "creators": ["Tool: enprot sbom"] },
  "packages": [
    {
      "name": "enprot",
      "SPDXID": "SPDXRef-enprot",
      "versionInfo": "0.5.14",
      "downloadLocation": "https://github.com/engyon/enprot",
      "filesAnalyzed": false,
      "licenseConcluded": "BSD-2-Clause"
    },
    {
      "name": "botan",
      "SPDXID": "SPDXRef-botan",
      "versionInfo": "3.12.0",
      "downloadLocation": "https://botan.randombit.net",
      "licenseConcluded": "BSD-2-Clause"
    },
    // ... one entry per Cargo.lock package + C dep
  ],
  "relationships": [
    { "spdxElementId": "SPDXRef-enprot", "relationshipType": "DEPENDS_ON", "relatedSpdxElement": "SPDXRef-botan" },
    // ...
  ]
}
```

### CycloneDX 1.5 output

Similar structure but with CycloneDX's `components` array.

### CI integration

```yaml
# .github/workflows/deploy.yml (extended)
- name: Generate SBOM
  run: ./target/release/enprot sbom --format spdx-json --output enprot-${{ github.ref_name }}.spdx.json
- name: Upload SBOM
  uses: actions/upload-artifact@v4
  with:
    name: sbom
    path: "*.spdx.json"
```

## Implementation plan

1. Add `spdx-rs` or hand-write the SPDX document builder.
2. Read `Cargo.lock` and enumerate packages + versions.
3. Query `pkg-config --modversion botan-3 rnp` for C dep versions.
4. Build the SPDX document with packages + DEPENDS_ON relationships.
5. Add `enprot sbom` subcommand.
6. Add CycloneDX output format.
7. Integrate into `deploy.yml`.
8. Add `grype` scan to CI as a vulnerability check.

## Test plan

- [ ] SPDX output validates against `spdx-tools` validator.
- [ ] CycloneDX output validates against CycloneDX schema.
- [ ] All Cargo.lock packages appear in the SBOM.
- [ ] C dep versions are correct (Botan, librnp).
- [ ] `grype enprot.spdx.json` runs without errors.

## Out of scope

- SBOM signing (covered by release signing + reproducible builds #45).
- Continuous SBOM monitoring (organisational tool, not enprot's job).
- SBOM for language bindings (each binding has its own SBOM).
