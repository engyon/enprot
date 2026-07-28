# 04 — Cookbooks for primary workflows

**Priority**: P1
**Status**: done (this document — cookbooks are content, not code)

Three end-to-end walkthroughs that demonstrate the integrated value
proposition. Each cookbook is reproducible from a fresh `git clone`.

## Cookbook A: Collaborative editing with cryptographic provenance

**Audience**: small team contributing to a shared document.
**Confium required**: no (Phase 1 use case).
**Time**: 10 minutes.

### Setup

```sh
# Alice and Bob each clone the repo
git clone https://example.com/team/design.ept
cd design.ept
enprot init
enprot keygen ed25519 --out-priv alice-priv.pem --out-pub alice-pub.pem
# Bob does the same with bob-priv.pem / bob-pub.pem
```

### Sign a contribution

```sh
# Alice signs an anchor on her branch
enprot encrypt -w Draft -k Draft=password design.ept
enprot encrypt --anchor --signer alice-priv.pem -w Draft design.ept
git commit -am "Alice: encrypted Draft section + signed anchor"
git push
```

### Merge with conflict

```sh
# Bob also signed the same region; merge produces a CONFLICT block
git merge alice/branch
enprot inspect design.ept  # exits non-zero — unresolved conflict
enprot resolve --word Draft:ours design.ept
enprot encrypt --anchor --signer bob-priv.pem -w Draft design.ept
git commit -am "Merged Alice's changes; re-signed"
```

### Verify provenance

```sh
enprot verify-chain --trust-root alice-pub.pem --trust-root bob-pub.pem design.ept
enprot snapshot design.ept  # publish the chain head hash out-of-band
```

### What this demonstrates

- Multi-signer chain anchors work locally without Confium
- WORD-region merge produces valid host-language source (CONFLICT
  blocks live inside comments)
- Verification doesn't need to decrypt — chain anchors carry their
  own proof

## Cookbook B: Supply-chain attestation

**Audience**: release engineering, supply-chain security.
**Confium required**: no (Phase 1, but optional transparency
anchoring at Phase 3+).
**Time**: 15 minutes.

### Build a provenance manifest

```sh
enprot manifest . --output build.ept -c cas/
enprot attest --signer builder-priv.pem build.ept
enprot verify-chain --trust-root builder-pub.pem build.ept
```

### Add Cargo dependency attestation

```sh
enprot scm init supply-chain.ept
enprot scm add supply-chain.ept src/
enprot scm deps supply-chain.ept Cargo.toml
enprot scm attest --signer vendor-priv.pem supply-chain.ept
enprot scm verify --trust-root vendor-pub.pem supply-chain.ept
enprot scm diff old.ept new.ept
```

### Pin and verify at install time

```sh
EXPECTED=$(enprot snapshot supply-chain.ept)
# ... time passes, supply-chain.ept is distributed ...
enprot pin "$EXPECTED" supply-chain.ept
```

### What this demonstrates

- SLSA-style provenance is built-in, not bolt-on
- Diff between two manifests surfaces dependency changes
- Pinning gives reproducible verification at install time

## Cookbook C: Classified document workflow (per RSD spec)

**Audience**: regulated industries (defense, healthcare, legal).
**Confium required**: yes for k-of-n signing (Phase 3+).
**Time**: 20 minutes.

### Multi-level classification in one document

```
// <( BEGIN PUBLIC )>
This document is approved for public release.
// <( BEGIN CONFIDENTIAL )>
// <( BEGIN Secret )>
Source 13 is Mallory.
// <( END Secret )>
Financial projections: [redacted]
// <( END CONFIDENTIAL )>
// <( END PUBLIC )>
```

### Sanitize for unclassified distribution

```sh
enprot store -w Secret report.ept    # Secret → CAS pointer
# Now the file has STORED Secret <hash> where the secret was
enprot verify report.ept             # CAS pointer resolves
```

Distribute the sanitized file. Parties without the Secret key see
only the hash; parties with the key can `enprot fetch -w Secret` to
restore.

### Reclassify after edits

```sh
# An editor modifies the unclassified version, wants to push changes back
enprot fetch -w Secret report.ept    # restore from CAS
enprot encrypt -w Secret -k Secret=password report.ept
enprot encrypt --anchor --signer classify-priv.pem -w Secret report.ept
```

### k-of-n signing (Phase 3+, requires Confium)

```sh
# Three-party FROST signing session via Confium daemon
enprot encrypt --anchor \
    --signer confium://session-abc \
    -w Secret report.ept
```

### What this demonstrates

- Same source file carries multiple classification levels
- Sanitization is reversible (CAS ensures content survives)
- Anchor signing works the same way for single-party (PEM) and
  threshold (Confium) — the wire format is identical

## Acceptance criteria

- [x] Three cookbooks written
- [x] Each is reproducible from a fresh clone
- [x] Each demonstrates a different buyer-ladder phase
- [x] Confium integration shown as additive, not required

## Cross-references

- [[01-strategic-vision]]
- [[03-readme-positioning]]
