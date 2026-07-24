# PQC Phase 1 — Ed25519 keygen, sign, verify-sig

## Goal

Bring enprot to "latest cryptographic practice" by adding public-key
signatures alongside the existing symmetric encryption. Ed25519 is the
lowest-risk first step: it has been in Botan since 2.x, the keys are
tiny (32 B), signing is deterministic and fast, and there are no NIST
standardization loose ends.

## Why this comes first

rnp's PQC matrix (ML-DSA, SLH-DSA, ML-KEM, composites) is built on top
of Ed25519 as the "classical" leg of every hybrid. We need Ed25519 in
the codebase before any composite construction makes sense.

## Scope

1. Add `ed25519` to `ci/botan-modules`.
2. New module `src/pki.rs`:
   - `fn keygen(rng) -> (priv_pem, pub_pem)` — Botan `Privkey::create("Ed25519", …)`.
   - `fn sign(priv_pem, msg, rng) -> Vec<u8>` — Botan `PK_Signer` with
     `"Pure"` padding.
   - `fn verify(pub_pem, msg, sig) -> bool` — Botan `Pubkey::load` +
     `PK_Verifier`.
3. New CLI subcommands under a `key` group (or top-level for now):
   - `enprot keygen Ed25519 --out-priv priv.pem --out-pub pub.pem`
   - `enprot sign --key priv.pem FILE`
   - `enprot verify-sig --key pub.pem FILE.sig FILE`
   (`verify-sig` to avoid clashing with the existing `verify` which
   checks EPT markup structure.)
4. Signature file format: OpenPGP-style detached, base64-encoded, with
   a header line `-----BEGIN ENPROT SIGNATURE-----` so it is easy to
   pipe and visually distinct from PEM keys.
5. Tests:
   - keygen→sign→verify-sig round-trip (positive).
   - verify-sig with tampered message (negative).
   - verify-sig with wrong key (negative).

## Out of scope

- Key encryption (passphrase-protected PEM). Defer until PQC KEM lands.
- Keyrings / trust stores. Defer until composite signatures land.
- Inline signatures inside EPT markup. Detached only for v1.

## Botan API reference

```
privkey = botan::Privkey::create("Ed25519", "", rng)?;      // 32 B seed
signer  = botan::Signer::new(&privkey, "Pure")?;             // Ed25519ph == Pure
sig     = signer.sign(&msg, rng)?;
verifier = botan::Verifier::new(&pubkey, "Pure")?;
ok      = verifier.verify_message(&msg, &sig)?;
```

## Acceptance criteria

- `cargo test` includes ≥3 new tests, all green on Linux + macOS.
- `ci/botan-modules` lists `ed25519`.
- README.adoc gets a "Signatures" section with the three commands.
