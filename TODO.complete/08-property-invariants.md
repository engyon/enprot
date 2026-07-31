# 08 — Property-based invariant tests

**Priority**: P1
**Status**: specified

## Problem

Existing `tests/proptest_roundtrip.rs` covers round-trip + determinism for `-det` ciphers. Missing invariants:

- **Identity**: `store(file) → fetch(file) = file` (byte-equal).
- **Commutativity**: `store_then_encrypt = encrypt_then_store` (after canonicalization).
- **Policy gating**: any operation rejected by policy fails identically across all callers.
- **CAS dedup**: identical plaintexts always produce identical CAS keys.
- **Idempotency**: `encrypt(encrypt(file)) = encrypt(file)`.

## Design

Add `tests/proptest_invariants.rs`:

```rust
proptest! {
    #[test]
    fn store_fetch_identity(file in arb_ept_file()) {
        let stored = store(&file, &mut paops)?;
        let fetched = fetch(&stored, &mut paops)?;
        prop_assert_eq!(fetched, file);
    }

    #[test]
    fn encrypt_decrypt_identity(file in arb_ept_file(), pw in arb_password()) {
        let enc = encrypt(&file, pw, &mut paops)?;
        let dec = decrypt(&enc, pw, &mut paops)?;
        prop_assert_eq!(dec, file);
    }

    #[test]
    fn cas_dedup(p1 in arb_plaintext(), p2 in arb_plaintext()) {
        let h1 = cas_save(&p1); let h2 = cas_save(&p2);
        prop_assert_eq!(p1 == p2, h1 == h2);
    }

    #[test]
    fn encrypt_idempotent(file in arb_ept_file(), pw in arb_password()) {
        let once = encrypt(&file, pw, &mut paops)?;
        let twice = encrypt(&once, pw, &mut paops)?;
        prop_assert_eq!(once, twice);
    }
}
```

256 cases per property (matches existing convention).

## Test plan

- [ ] All properties hold across the EPT file generator's corpus.
- [ ] Property failures minimized to readable counterexamples.

## Out of scope

- Differential testing against an external implementation (none exists).
- Property-based CLI fuzzing (separate fuzz/ workspace exists).
