# 03 — README positioning rewrite

**Priority**: P0
**Status**: done

## Problem

The current README opens with:

> Enprot is a confidentiality processor for text and source code
> files. It lets you embed encrypted, stored, and authenticated
> segments directly inside any text-based file…

That positioning loses. It puts enprot next to git-crypt, sops, age,
transcrypt, blackbox — all of which do "encryption in source files"
and have larger communities. enprot's actual differentiator is the
**combination** of document classification + content addressing +
signed chain anchors + capability model + (forthcoming) Confium
distributed trust — none of those competitors have anything
comparable.

## What this rewrite does

- Lead with the integrated value proposition.
- Reference the RSD spec (establishes this isn't a side project).
- Add a comparison table showing where enprot wins.
- Add a buyer-ladder narrative: individual → team → enterprise →
  cross-org.
- Keep the existing quick start (it works).
- Add a "When to use enprot vs X" decision tree.

## What the new README says

Headline + first 3 paragraphs rewritten to:

> # Engyon: enprot
>
> **Document confidentiality and provenance for collaborative text.**
> enprot embeds classification levels, content-addressed storage, and
> signed chain anchors inside any text-based file — without breaking
> the host language.
>
> Built on the [Ribose Standard for Engyon Protected Text][rsd-spec]
> (RSD 12001), enprot implements the document edge of a complete
> trust stack: standalone for individual use; integrated with
> [Confium][confium] for distributed trust, threshold signing, and
> hardware key custody.
>
> [rsd-spec]: https://github.com/riboseinc/rsd-engyon-syntax
> [confium]: https://github.com/confium/confium

Plus a comparison table:

| Feature | enprot | git-crypt | sops | age | sigstore |
|---|---|---|---|---|---|
| Encryption in source comments | ✅ | ✅ | ⚠️ YAML only | ❌ | ❌ |
| Content-addressed storage | ✅ | ❌ | ❌ | ❌ | ✅ (Rekor) |
| Signed chain anchors | ✅ | ❌ | ❌ | ❌ | ✅ |
| Merge-friendly regions | ✅ | ❌ | ❌ | ❌ | ❌ |
| PQ-ready (ML-DSA, ML-KEM) | ✅ | ❌ | ❌ | ❌ | partial |
| OpenPGP interop | ✅ (rnp-rs) | ❌ | ❌ | ❌ | ❌ |
| Threshold signing | via Confium | ❌ | ❌ | ❌ | ❌ |
| Hardware key custody | via Confium | partial | partial | ❌ | ✅ (KMS) |
| Audit transparency log | via Confium | ❌ | ❌ | ❌ | ✅ |

## Buyer ladder narrative

```
Phase 1: Individual          → enprot standalone (this repo)
Phase 2: Team / release eng  → enprot + shared Confium daemon
Phase 3: Enterprise          → + Confium stores (TPM/HSM) + attributes
Phase 4: Cross-org           → + Confium BLS threshold + transparency
```

## Acceptance criteria

- [x] README headline reflects integrated value proposition
- [x] RSD spec referenced from README
- [x] Comparison table added
- [x] Buyer ladder narrative added
- [x] Existing quick start preserved (it still works)
- [x] "When to use enprot vs X" decision guide added

## Implementation

Edit `README.md` directly. Preserve the existing detailed
documentation below the new intro (it's accurate and useful); just
lead with the stronger positioning.

## Cross-references

- [[01-strategic-vision]]
- [[02-rsd-spec-conformance]]
- [[04-cookbooks]]
