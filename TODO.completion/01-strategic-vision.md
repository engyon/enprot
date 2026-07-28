# 01 — Strategic vision: enprot + Confium integrated trust stack

**Priority**: P0
**Status**: done (this document)

## Why this document exists

enprot's value proposition has been muddied. The README positions it
as "confidentiality processor for text and source code files" — true
but undersold. The implementation has accumulated capability model,
chain anchors, ML-DSA/ML-KEM, OpenPGP via rnp-rs, CAS, merge driver,
provenance manifests, audit log — a feature surface that doesn't fit
the "encryption inside source comments" headline.

The RSD spec at `../engyon/rsd-engyon-syntax` describes the actual
intent: **a document classification system with cryptographic
enforcement**, where the same source file carries multiple
classification levels simultaneously and different parties see
different views.

With the Confium project (`../confium/confium`) reaching v0.3.0 with
real threshold crypto, hardware key custody, transparency logs, and
drop-in provider integrations, the strategic story becomes clear:
**enprot is the document interface for an organizational trust
infrastructure; Confium is the trust backend.**

## The integrated stack

| Layer | enprot | Confium | Closest competitor |
|---|---|---|---|
| Document confidentiality | EPT markup | — | git-crypt, sops, age |
| Document provenance | chain anchors | — | sigstore (artifact-level) |
| Merge-friendly signed regions | unique | — | (none) |
| Threshold signing | — | FROST Ed25519/ML-DSA/P-256, BLS, GG18, CMP20 | (none mainstream) |
| Hardware key custody | — | TPM, HSM, PKCS#11, OpenPGP card, cloud KMS | per-vendor |
| Audit transparency | — | Merkle log + OTS + ERS archival | Rekor |
| PQ migration | partial (ML-DSA/ML-KEM) | composite + threshold | (none mainstream) |
| Cross-org aggregation | — | BLS threshold | (none mainstream) |
| TLS / OpenSSL / JCE / PKCS#11 interop | — | providers | per-vendor |

No competitor covers this range. sigstore + age + sops + git-crypt
together don't equal the integrated stack.

## Buyer ladder

1. **Phase 1 (now)**: Individual + small team. enprot standalone.
   Collaborative editing with chain anchors. Local PEM keys. Audience:
   OSS maintainers, journalists, research consortia.
2. **Phase 6-12 months**: Teams + release engineering. Shared
   Confium daemon. Threshold signing (2-of-3 for release approvals).
   Local PKCS#11 for custody.
3. **Phase 12-24 months**: Enterprise. Confium stores on TPM/HSM.
   Confium attributes gate document classification to clearance level
   automatically. Transparency log anchors published quarterly.
   Audience: defense, finance, healthcare, legal.
4. **Phase 24+ months**: Cross-org. BLS threshold for M&A due
   diligence, joint ventures, regulatory filings. Public transparency
   anchoring. Compliance certifications (SOC 2, HIPAA, FedRAMP).

## Primary use case (revised)

**"Regulatory-grade document confidentiality with distributed trust."**

Standalone enprot is one tool among many. enprot + Confium is a
category. The marketing, demos, cookbooks, and TODOs should organize
around this combination rather than around standalone encryption.

## What enprot owns forever

- EPT markup grammar (text-embedded confidentiality)
- Parser, transforms, CAS, merge driver
- Document classification model per RSD spec
- Wire format for chain anchors, Encrypted blocks
- Host-language comment-aware parsing

## What Confium owns

- Threshold crypto primitives + orchestration
- Key custody (hardware + cloud)
- Transport (TCP/QUIC/WS)
- Transparency log
- Provider integrations (PKCS#11, OpenSSL, JCE, TLS)
- Identity + attributes

## Integration boundary

`SignerProvider` / `KemProvider` traits in `src/provider.rs`. Confium
implements them. Document-level operations stay in enprot; signing
and decryption dispatch through the provider trait.

This boundary is load-bearing: every architectural decision in
TODO.completion/* must preserve it. enprot must never grow threshold
crypto code; Confium must never grow document-classification code.

## Strategic principles for the TODO.completion batch

1. **Spec conformance over invention.** The RSD spec is the source
   of truth. Where enprot has drifted (e.g. BEGIN+encrypt vs spec's
   CLASSIFY/UNCLASSIFY), the spec wins. Document the deviation first;
   close it second.
2. **Confium as backend, not fork.** Don't reinvent threshold crypto
   in enprot. Wire to Confium via the provider trait.
3. **Local-first remains valid.** A single user with a PEM key must
   work end-to-end without Confium. The Confium path is additive.
4. **MECE at the trait boundary.** Document operations in enprot;
   signing operations in providers. No overlap, no gaps at the seam.
5. **Open/closed for new providers.** Adding PKCS#11, Confium,
   YubiKey, cloud KMS = adding trait impls, not editing dispatch.

## Acceptance criteria

- [x] Strategic vision document exists and is referenced from README
- [x] Confium integration architecture documented (see 08-11)
- [x] RSD spec reference added to README (see 02)
- [x] Buyer ladder articulated for marketing/sales use

## Cross-references

- [[02-rsd-spec-conformance]] — spec audit + vocabulary alignment
- [[03-readme-positioning]] — README rewrite around this vision
- [[08-async-signer-provider]] — Confium-ready trait shape
- [[09-confium-signer-architecture]] — integration plan
- Confium repo: `../confium/confium`
- RSD spec: `../engyon/rsd-engyon-syntax`
