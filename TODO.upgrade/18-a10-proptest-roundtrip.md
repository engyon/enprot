# A10 — Property-based round-trip test

## Problem

The integration tests check `encrypt ∘ decrypt = id` for a handful of
specific plaintexts (the golden `test-data/*.ept` files). A
property-based test would generate random plaintexts and assert the
property across a much larger input space.

## Approach

Add `proptest` as a dev-dependency. Add a `tests/proptest_roundtrip.rs`
that drives the public crypto layer (`prot::encrypt` +
`prot::decrypt`) with random plaintexts.

```rust
proptest! {
    #[test]
    fn round_trip_aes_256_gcm_siv_det(
        pt in prop::collection::vec(any::<u8>(), 0..4096),
        password in "[a-zA-Z0-9]{1,64}",
    ) {
        let mut rng = botan::RandomNumberGenerator::new().unwrap();
        let policy: Box<dyn CryptoPolicy> = Box::new(CryptoPolicyDefault {});
        let pbkdfopts = PBKDFOptions { alg: "pbkdf2-sha256".into(),
            saltlen: 8, salt: Some(b"01234567".to_vec()),
            msec: None, params: Some(iter::once(("i".into(), 1000)).collect()) };
        let cipheropts = CipherOptions { alg: "aes-256-gcm-siv-det".into(), iv: None };
        let mut cache = Some(Vec::new());

        let (ct, extfields) = encrypt(pt.clone(), &password, &mut Some(rng),
                                       &pbkdfopts, &cipheropts, &mut cache, &*policy)?;
        let recovered = decrypt(ct, &password, &extfields.get("pbkdf"),
                                 &extfields.get("cipher"), &mut cache, &*policy)?;
        prop_assert_eq!(recovered, pt);
    }
}
```

Deterministic mode (`-det`) is used so the property is also a CAS
deduplication check (two encrypts of the same plaintext produce the
same ciphertext).

## Files

- `Cargo.toml` — add `proptest = "1"` to `[dev-dependencies]`.
- `tests/proptest_roundtrip.rs` (new) — the property test.

## Verification

`cargo test --test proptest_roundtrip` runs ~256 random cases by
default; failures print the minimal shrinking.

## Rollback

Remove the test file and the dev-dependency.
