# CHAIN anchor format spec (v1)

**Status**: spec
**Schema version**: v1
**Stability**: stable — additive changes only within v1.

CHAIN blocks are enprot's tamper-evident history layer. Every
transform optionally appends a CHAIN anchor that signs the new file
state. This document defines:

- Wire format (extfield names, ordering, encoding).
- Cryptographic invariants (what's signed, hash algorithm, signature scheme).
- Verification rules (how a verifier decides PASS / FAIL / INCONCLUSIVE).
- Identity model (who is the "signer"; how to map identity to a trust policy).

## Wire format

```
// <( CHAIN anchor )>
// <( index:N )>
// <( parents:HEX32[,HEX32...] )>           # omitted or empty for genesis
// <( payload:HEX32 )>                      # SHA3-256 of canonical file bytes
// <( ts:COMPACT_RFC3339 )>                 # optional
// <( mut:DESCRIPTION )>                    # optional; '+' for spaces
// <( signer:ALG:HEXFP )>                   # e.g. "ed25519:9f3a7b..."
// <( sig:HEXSIG )>
// <( [cert:PEM_B64] )>                     # sigstore-keyless only
// <( [rekor:URL] )>                        # sigstore-keyless only
// <( END anchor )>
```

`ALG` ∈ { `ed25519`, `ml-dsa-65`, `composite-ed25519-ml-dsa`, `sigstore-keyless` }.

`HEXFP` is the signer's public key fingerprint (SHA3-256 of the
DER-encoded SubjectPublicKeyInfo, hex-encoded).

## Canonical file bytes

`canonical_bytes(file)` is the file's text content with the following
transformations applied:

1. All CHAIN blocks removed (the anchor signs the file's *content*,
   not its history).
2. CRLF → LF.
3. UTF-8 normalized to NFC.
4. Trailing whitespace stripped per line.
5. A trailing LF appended if absent.

Rationale: an anchor at revision N signs what a reader sees at
revision N, independent of how the history grew. Stripping the
CHAIN blocks themselves prevents a "Russian doll" where anchors
sign earlier anchors.

## Signing payload

`signing_payload(anchor)` is a fixed-layout byte string:

```
index:u64                    # big-endian
parents_count:u8             # number of parents
parents: [parent_hash; parents_count]   # each 32 bytes
signer_alg_len:u8
signer_alg:bytes
signer_fp: [u8; 32]
ts_len:u8
ts:bytes                     # empty if no ts
payload: [u8; 32]            # canonical_bytes(file) hash
```

Hashing this with SHA3-256 yields the digest that's signed.

## Verification rules

A verifier runs these checks in order. The first failure determines
the verdict; passing all yields PASS.

1. **Parse extfields.** Required: `index`, `signer`, `payload`, `sig`.
   Missing required → FAIL with `kind=MissingFields`.
2. **Recompute `payload`.** Hash `canonical_bytes(file)` with
   SHA3-256; compare to the anchor's `payload`. Mismatch → FAIL
   with `kind=PayloadMismatch`.
3. **Recompute signing payload.** Construct per the layout above;
   hash with SHA3-256; verify signature against the signer's public
   key (or Fulcio cert for `sigstore-keyless`).
   - Invalid signature → FAIL with `kind=SignatureInvalid`.
4. **Identity policy.**
   - For `ed25519`/`ml-dsa`/composite: lookup `signer_fp` in the
     caller's trust roots. Not found → INCONCLUSIVE with
     `kind=UnknownSigner`.
   - For `sigstore-keyless`: fetch the Rekor entry, verify inclusion
     proof, validate the Fulcio cert chain, check the OIDC `sub`
     matches the configured identity policy. Mismatch → FAIL with
     `kind=IdentityMismatch`.
5. **Walk the chain.** Anchor N's `parents` must reference earlier
   anchors by their `AnchorHash` (= SHA3-256 of the anchor's
   canonical extfields). Missing parent → FAIL with
   `kind=BrokenChain`. Cycle → FAIL with `kind=CycleDetected`.
6. **Timestamp monotonicity** (optional, opt-in via policy). If
   `ts` is present and the policy requires monotonicity, the new
   anchor's `ts` must be > the latest parent's `ts`. Violation →
   FAIL with `kind=TimestampRegression`.

## Anchor hash

`AnchorHash(anchor)` = SHA3-256 of the anchor's canonical extfield
bytes. Used by child anchors' `parents` field. Computed by:

1. Sort extfields by key (BTreeMap order).
2. Serialize as `key=value\n` per line.
3. SHA3-256.

## Identity model

The signer identity is the (alg, fingerprint) pair. The verifier's
trust policy maps identities to permissions:

- **Direct trust**: list of `(alg, fp)` tuples the verifier accepts.
- **Fingerprint pinning**: same as direct, but pinned to a specific
  file or revision.
- **OIDC policy** (sigstore-keyless only): regex on the OIDC `sub`
  claim (e.g., `github.com/engyon/enprot/.github/workflows/*`).
- **Threshold** (Confium integration, future): k-of-n signers from
  a defined set.

## Forward compatibility

Unknown extfields with `x-` prefix are preserved verbatim. Unknown
extfields without `x-` prefix cause FAIL with `kind=UnknownExtfield`
— this catches typos and intentional tampering.

Adding a new extfield to the spec is an **additive v1 change**: old
verifiers that don't know about it should treat it as `x-` (preserve,
don't reject). New verifiers use it.

## Test plan

`tests/chain_anchor_spec.rs` (TODO.complete/23) asserts every rule
above with a positive and negative fixture.

## See also

- [`ept-wire-format-v1.md`](ept-wire-format-v1.md) — overall file shape.
- [`extfield-schema-v1.md`](extfield-schema-v1.md) — extfield grammar.
- `src/ledger/` — Rust implementation.
- [TODO.complete/03-sigstore-keyless-signing](../../TODO.complete/03-sigstore-keyless-signing.md) — sigstore-keyless signer kind.
