# 39 — Deterministic AES-GCM (+AES-GCM-SIV)

## Problem

AES-GCM and AES-GCM-SIV use random nonces by default, so encrypting the
same plaintext with the same password twice produces two different
ciphertexts. That breaks the CAS deduplication property: two files with
identical `BEGIN..END` content under the same WORD get different CAS
hashes, wasting storage and losing the "content-addressable" promise for
encrypted segments.

AES-SIV doesn't have this problem — it's deterministic by construction
(IV is derived from plaintext+AD). The same is achievable for GCM by
deriving the nonce deterministically.

## Approach

The approach the issue describes is the standard one (see the
crypto.stackexchange links in the issue body):

1. PBKDF produces a master key.
2. HKDF-Expand on the master key with two different `info` strings
   produces an `enc_key` and an `iv_key`.
3. The GCM nonce is `HMAC-SHA256(iv_key, plaintext)` truncated to 96 bits
   (12 bytes — GCM's standard nonce width).

Same `(password, plaintext, AD)` ⇒ same `(enc_key, iv, ciphertext)`. CAS
hash matches.

### Cipher variants

Two new names join `consts::VALID_CIPHER_ALGS`:

- `aes-256-gcm-det` — deterministic AES-256-GCM.
- `aes-256-gcm-siv-det` — deterministic AES-256-GCM-SIV.

The `-det` suffix is the wire-format identity. Decryption sees the name
in the `cipher:` extfield and knows it needs to:

1. Recompute the IV from the (now-decrypted) plaintext? **No** — that's
   circular.
2. Store the IV in the extfield like normal GCM.

Wait. If the IV is derived from plaintext, decryption can't re-derive it
without first decrypting. So we have two options:

**Option A**: Store the derived IV in the `cipher:` extfield, exactly as
we do for random-IV GCM. Determinism is achieved at encrypt time (same
plaintext → same IV → same ciphertext); decryption is identical to
random-IV GCM.

**Option B**: Don't store the IV. Decryption tries `HMAC(iv_key,
candidate_plaintext) == stored_iv`? No, can't, see circular.

**Option A is correct.** The "deterministic" property only matters at
encrypt time — two identical plaintexts produce identical output. The
decryption path is unchanged from regular GCM.

So the only wire-format difference: cipher name is `aes-256-gcm-det`
instead of `aes-256-gcm`. The `iv=...` field is still there.

### Why two keys via HKDF?

If we used the PBKDF key directly as both the GCM key and the HMAC key,
a weakness in either could leak the other. HKDF domain-separates them.

The HKDF-Expand `info` strings: `"enprot-encrypt"` and `"enprot-iv"` —
short, constant, descriptive.

### Botan support

Botan exposes HKDF (`HKDF(MessageAuthenticationCode, Extract)` and
`HKDF_Extract`/`HKDF_Expand`) and HMAC. Use:

- `botan::Kdf::new("HKDF-Expand(SHA-256)")` or
  `botan::derive_key_from_password` with PBKDF2-HMAC-SHA-256?

Actually simpler: `botan::hkdf(...)` if the crate exposes it; otherwise
combine `botan::Mac::new("HMAC(SHA-256)")` manually.

Need to check botan 0.11 crate surface.

### Files

- `src/consts.rs` — add the two new cipher names.
- `src/cipher.rs` — `BOTAN_CIPHER_ALG_MAP` doesn't change (det variants
  still use Botan's AES-256/GCM under the hood). Dispatch in
  `encryption()`/`decryption()` recognises the `-det` suffix and strips
  it for the Botan lookup.
- `src/prot.rs::encrypt` — when cipher ends in `-det`, derive enc_key
  and IV from the PBKDF master key + plaintext.
- `src/prot.rs::decrypt` — no special path; the `cipher:` extfield's
  name tells us it's GCM underneath; IV is stored as before.
- `src/crypto.rs` — add `hkdf_expand`/`hmac` helpers.
- `tests/cli/cipher.rs` — KATs for the det variants.

## Verification

- KAT: encrypt the same plaintext twice with the same password and salt,
  assert identical ciphertext.
- Round-trip: encrypt then decrypt, recover plaintext.
- Property test: for randomly generated plaintexts, `encrypt(p) ==
  encrypt(p)` under the det variants. (Random-IV variants should fail
  this property; useful negative test.)

## Compat

Existing `aes-256-gcm` blobs still decrypt (cipher name unchanged). The
new variants are opt-in. No migration needed.

## Rollback

Remove the two new cipher names, drop the new code paths in cipher/prot.
