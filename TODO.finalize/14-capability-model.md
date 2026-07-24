# Capability model — formalize the four access tiers

## Why this comes first

Every subsequent stage (chain anchors, merge driver, PQC recipients,
policy language) needs a unified vocabulary for "what can the caller
do with this file?" Today the codebase expresses this implicitly:
the presence of a `-k WORD=pwd` flag means Decryptor-for-WORD; the
presence of `--key-file` means Signer; reading a `STORED` blob means
Reader. We need this explicit so that:

- `list --capabilities` can print a deterministic summary
- The merge driver can describe conflicts in capability terms
- Chain anchor verification can require specific capabilities
- Future policy work has a type to bind to

## The four tiers

| Tier | Holds | Can do |
|---|---|---|
| `Viewer` | nothing | parse, list, verify structure, walk DAG (no decryption) |
| `Reader` | CAS path | fetch `STORED` plaintext |
| `Decryptor(WORD)` | WORD password | decrypt that WORD's segments |
| `Signer` | privkey | produce chain anchors, detached signatures |
| `Verifier` | pubkey | verify signatures (read-only, no decryption) |

`Signer` and `Verifier` are dual halves of one capability; holding
the privkey implies the capability to sign, holding the pubkey implies
the capability to verify. They're listed separately because the
operations are asymmetric.

## Scope

1. New module `src/capability.rs`:
   - `enum Capability { Viewer, Reader, Decryptor(WordId), Signer(KeyFp), Verifier(KeyFp) }`
   - `CapabilitySet` newtype around `HashSet<Capability>` with set-union semantics
   - `fn from_paops(paops: &ParseOps) -> CapabilitySet` — derive from current passwords + key files
   - `fn required_for(node: &TextNode) -> CapabilitySet` — derive from a parsed block
2. `WordId` newtype around `String` (semantic alias, not raw string)
3. `KeyFp` newtype around SHA3-256 of the pubkey PEM (32 bytes, displayed hex)
4. `list --capabilities` flag: print the current `CapabilitySet`
5. Tests: round-trip derivation; set-union; tier overlap

## Non-goals

- Policy *enforcement* (Stage 4a / `TODO.finalize/26`)
- Capability *delegation* (Stage 5 / `TODO.finalize/27-30`)
- Capability revocation (key distribution problem; out of scope)

## Acceptance criteria

- `cargo test` includes ≥5 new unit tests for capability derivation
- `enprot list --capabilities FILE` outputs a stable, machine-readable
  summary
- No existing tests regress
- Documentation in `docs/` references the typed model

## Design constraints

- **MECE**: tier set is mutually exclusive (no overlap) and collectively
  exhaustive (every operation maps to exactly one tier or none)
- **OCP**: adding a new tier is one `enum` variant + one match arm per
  consumer; no core code changes
- **DRY**: capability derivation logic lives in `from_paops`, not
  duplicated across subcommands
- **Model-driven**: tiers and capabilities are typed, not stringly-typed
