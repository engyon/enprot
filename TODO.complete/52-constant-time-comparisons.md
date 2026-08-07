# 52 — Constant-time comparisons for secret-derived data

**Priority**: P2
**Status**: specified

## Problem

Most of enprot's comparisons are not timing-sensitive (CAS hashes
are content-derived; anchor IDs are public). Two categories ARE
timing-sensitive:

1. **Password verification** — when comparing a user-supplied
   password to a stored reference (currently none, but future
   capability policy might store hashed passwords for word-level
   access control).
2. **MAC/authentication tag verification** — when comparing a
   decrypt-supplied AEAD tag to a re-computed tag. Botan handles
   this internally for AEADs (returns boolean), so enprot itself
   doesn't compare tags. But future custom MAC verification
   (e.g., HKDF-derived commitment) might.

Without constant-time comparison:
- A timing-attack adversary can recover secrets byte-by-byte.
- Side-channel resistance is required for FIPS 140-3 / Common
  Criteria EAL5+.

The current code uses `==` everywhere, which short-circuits on the
first mismatch. That's a timing leak.

## Goals

- Every comparison of secret-derived data uses the `subtle` crate's
  `ConstantTimeEq`.
- A code-review checklist documents which comparisons are
  timing-sensitive.
- A lint (custom Clippy rule or grep gate) catches new
  non-constant-time comparisons of secret types.

## Design

### The `subtle` crate

`subtle` (RustCrypto) provides `ConstantTimeEq` for `[u8]` and
other primitives:

```rust
use subtle::ConstantTimeEq;

let a: &[u8] = /* derived from secret */;
let b: &[u8] = /* expected */;

let matches: bool = a.ct_eq(b).into();
```

`ct_eq` runs in time independent of the contents (same length,
same access pattern).

### Where to apply

| Location | Current | Change |
|---|---|---|
| `cas::LocalCas::load` hash comparison | `hash != verify` | OK to leave — hash is content-derived, not secret-derived |
| `pbkdf::verify_phc` (future) | `==` on stored PHC | `ct_eq` on the re-derived key |
| `pki::verify` signature result | `Ok(bool)` from Botan | OK — Botan handles constant-time internally |
| `sigstore::verify` pubkey comparison | `==` on PEM bytes | Use `ct_eq` — pubkeys are not strictly secret but timing-attacks can fingerprint |
| Any future HMAC/HKDF tag check | `==` | `ct_eq` |

### What's NOT timing-sensitive

- WORD name comparison (not secret).
- Filename / path comparison.
- Cipher algorithm name comparison.
- Anchor index / timestamps.
- CAS hash comparison (content-derived).

The principle: **secret-derived data needs `ct_eq`; everything else
can use `==`**. Documenting this in CONTRIBUTING.md prevents
over-cautious "just use ct_eq everywhere" noise.

### Type-system enforcement (with TODO #50)

Once `Password` / `Mac` / `SignatureBytes` are newtypes:

```rust
impl PartialEq for Password {
    fn eq(&self, other: &Self) -> bool {
        self.0.as_bytes().ct_eq(other.0.as_bytes()).into()
    }
}
```

Now any `==` on a `Password` is automatically constant-time. The
type system enforces it; no per-call-site audit needed.

## Implementation plan

1. Add `subtle = "2.6"` to `[dependencies]`.
2. Audit all `==` / `!=` comparisons in `src/` for timing-sensitivity.
3. Convert the timing-sensitive ones to `ct_eq`.
4. Document the audit in `CONTRIBUTING.md` (security review section).
5. Once #50 lands, implement `PartialEq` via `ct_eq` on the newtypes.
6. Add a Clippy custom lint or grep gate that flags raw `==` on
   secret types.

## Test plan

- [ ] Audit document lists every comparison with its category.
- [ ] Timing-sensitive comparisons use `ct_eq`.
- [ ] A microbenchmark shows `ct_eq` is no slower than `==` on
  typical inputs.
- [ ] Reviewers have a checklist to consult on security-related PRs.

## Out of scope

- Constant-time memory access (cache-timing resistance). Harder;
  requires careful instruction selection. Out of scope.
- Side-channel resistance of Botan primitives (Botan's
  responsibility).
- A formal proof of constant-timeness (requires tools like
  ct-verif; out of scope).
