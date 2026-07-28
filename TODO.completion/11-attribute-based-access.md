# 11 — Attribute-based access control (ABAC) bridge to Confium

**Priority**: P2
**Status**: specified (Confium `confium-attributes` provides the engine)

## Problem

enprot's capability model is **identity-based** ("this WORD is
decryptable by holder of key X"). The RSD spec calls for
**attribute-based** access ("this WORD is decryptable by anyone
whose clearance >= SECRET and role == auditor").

Without ABAC, every capability grant is a manual key distribution.
With ABAC, capabilities compose from attributes that Confium
already manages.

## Solution

Bridge enprot's WORD segments to Confium's attribute DSL.

### Confium side

`confium-attributes` (v0.3.0) provides a predicate DSL:

```
clearance >= SECRET && role == "auditor" && org == "acme"
```

Attributes are bound to identities (X.509 certs, SAML assertions,
Confium deployment manifests). The Confium daemon evaluates
predicates against the caller's attribute set during sign/decrypt
operations.

### enprot side

Extend `parse_signer_arg` and the WORD encryption flow to accept an
attribute predicate:

```sh
enprot encrypt \
    -w Secret \
    --attribute-predicate 'clearance >= SECRET && role == "auditor"' \
    file.ept
```

The predicate is encoded in the `ENCRYPTED` block's extfield:

```
// <( ENCRYPTED Secret attr:clearance%3E%3DSECRET%26%26role%3D%3D%22auditor%22 )>
```

(URL-encoded to keep the extfield wire-stable.)

### Capability resolution

`CapabilitySet::from_paops` consults Confium (if available) to
resolve the attribute predicate against the local identity's
attributes:

```rust
if let Some(attr_predicate) = encrypted_block.attr_predicate {
    let client = paops.confium_client()?;
    if !client.attributes_satisfy(&attr_predicate, &local_identity)? {
        return Err(Error::AttributeDenied { predicate: attr_predicate });
    }
}
```

Without Confium, attribute predicates are accepted but not enforced
(Warning: "attribute predicate present but no Confium daemon —
access not verified"). Local-first remains valid; ABAC is enforced
only when Confium is in the loop.

## Use case: classified document workflows

```
// <( ENCRYPTED Secret attr:clearance%3E%3DSECRET )>
// <( ENCRYPTED TopSecret attr:clearance%3E%3DTS%26%26citizenship%3D%3D%22US%22 )>
```

A user with Confium daemon + SECRET clearance can decrypt the first
block; only US citizens with TS clearance can decrypt the second.
The document carries the policy in-band; no per-user key
distribution needed.

## What this enables

- Policy-as-data: documents declare their own access rules.
- Compliance mappings: SOC 2 / HIPAA / FedRAMP map naturally to
  attribute predicates.
- Time-bounded access: predicates can include `valid_until < now`.
- Revocation: revoking an attribute at the daemon invalidates
  future decrypts without touching the document.

## Acceptance criteria

- [ ] `ENCRYPTED` extfield accepts `attr:` predicate
- [ ] `--attribute-predicate` CLI flag added to `encrypt`
- [ ] `CapabilitySet` resolution consults Confium when available
- [ ] Without Confium, predicates are recorded but not enforced
- [ ] Tests: predicate match, predicate deny, no-Confium warning
- [ ] Cookbook: classified document with attribute predicates (TODO 04)

## Blockers

- Confium daemon attribute evaluation endpoint (in `confium-attributes`
  but not yet exposed via daemon RPC).

## Cross-references

- [[09-confium-signer-architecture]] — daemon connection shape
- [[10-capability-threshold-provenance]] — capability model extension
- [[04-cookbooks]] — Cookbook C (classified documents) would use this
- Confium `confium-attributes` crate
