# 68 — Compression before encryption

**Priority**: P2 | **Status**: specified

## Problem
enprot encrypts plaintext as-is. For repetitive or compressible
plaintext (source code, logs, JSON), the ciphertext is larger than
necessary. Compression before encryption would reduce output size by
50–80% for typical text inputs.

## Design
- `--compress <alg>` flag on `encrypt` and `encrypt-store`. Values:
  `none` (default), `zstd`, `deflate`, `brotli`.
- The `cipher:` extfield gains a `compress:` sibling field recording
  the algorithm used. Decrypt auto-detects.
- Compression happens BEFORE encryption (standard practice —
  compressing ciphertext doesn't work).
- Compressed size is capped at plaintext size (if compression makes
  it larger, skip compression).

## Out of scope
- Streaming compression (covered by #35 streaming transform).
- Dictionary-based compression (pre-shared dictionary).
- Compression of CAS blobs (separate concern from encrypt-time).
