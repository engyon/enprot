# Default cipher → deterministic AEAD

## Why

Random-IV encryption produces different ciphertext every time even
for the same plaintext + key. That breaks:

- **Merge-friendliness**: two parties encrypting the same block
  independently produce divergent ciphertext → textual merge conflict
- **CAS dedup**: identical plaintext no longer deduplicates because
  the ciphertext (and thus the hash) differs
- **Reproducible builds**: re-running encrypt on the same input gives
  different output, breaking supply-chain provenance

Deterministic AEAD (`-det` variants, already shipped) derives the IV
from the plaintext via HKDF+HMAC. Same input → same output. Default
it.

## Scope

1. `consts::DEFAULT_CIPHER_ALG` change: `aes-256-siv` →
   `aes-256-gcm-siv-det`. (We keep `aes-256-siv` and `-gcm` as
   selectable; they're not removed, just not default.)
2. Deprecation warning when caller explicitly selects a non-det
   cipher: stderr note that the output will not be reproducible.
3. README + CHANGELOG note: deterministic is now default
4. Test: encrypt same input twice → identical output, default flags
5. Test: encryption is still semantically secure under det (we
   inherit this from the `-det` KAT tests already in place)

## Why `aes-256-gcm-siv-det` and not `aes-256-siv`

- `aes-256-siv` is itself misuse-resistant (RFC 5297) and det-ish, but
  Botan's implementation doesn't go through the HKDF+HMAC nonce
  derivation our `-det` variants use, so it doesn't share the CAS
  dedup invariant.
- `aes-256-gcm-siv-det` is the GCM-SIV variant (RFC 8452) with our
  HKDF+HMAC construction; same perf, better browser/library interop
  story (GCM hardware acceleration).

## Compatibility

- **Reading old files**: unchanged. Decrypt doesn't care which cipher
  was used; the wire format records the algorithm.
- **Writing new files**: defaults change. Callers who pin `--cipher
  aes-256-siv` keep old behavior.

## Acceptance criteria

- `cargo test` includes the "encrypt twice = same output" test
- `enprot encrypt -w X -k X=p file` (no `--cipher`) produces det
  ciphertext
- Deprecation note in `CHANGELOG.md`
