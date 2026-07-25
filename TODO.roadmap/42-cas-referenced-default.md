# 42 — CAS-referenced encrypted blocks as default

**Priority**: P1
**Status**: specified (consolidated from TODO.finalize/16)

## Problem

Inline DATA lines put ciphertext in the file text. Two candidate
ciphertexts become textual conflicts on merge. CAS-referenced blocks
keep only a hash pointer in the file.

## Solution

Default `encrypt` output uses `STORED ct <hash>` when CAS is available.
Inline `DATA` becomes opt-in via `--inline`.

```
// <( ENCRYPTED Agent_007 )>
// <( STORED ct 575d69f5b0034279bc3ef164e94287e6366e9df76729895a302a66a8817cf306 )>
// <( END ENCRYPTED )>
```

## Implementation

- `prot::encrypt` emits `STORED ct <hash>` when `paops.io.casdir` is set
- `--inline` flag restores old behavior
- Inline stays the default only when CAS unavailable (stdin pipeline)

## Acceptance criteria

- [ ] Default encrypt produces CAS-referenced output
- [ ] `--inline` restores old behavior
- [ ] CAS dedup: same plaintext+password reuses same CAS file
