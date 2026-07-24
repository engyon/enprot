# Default encrypted-block format → CAS-referenced

## Why

Current format embeds ciphertext inline as `DATA <base64>` lines
inside `ENCRYPTED` blocks. This means:

- The ciphertext lives in the file text
- Two candidate ciphertexts (merge conflict) become textual conflicts
- File grows with payload size, even for repeated content
- CAS dedup of ciphertext is impossible because the hash anchor isn't
  in the file

CAS-referenced format puts only a hash pointer in the file:

```
// <( ENCRYPTED Agent_007 )>
// <( STORED ct 575d69f5b0034279bc3ef164e94287e6366e9df76729895a302a66a8817cf306 )>
// <( END ENCRYPTED )>
```

(The `STORED ct <hash>` form already exists in the parser; this PR
makes it the default output of `encrypt` when CAS is available.)

## Scope

1. `prot::encrypt` always emits `STORED ct <hash>` when `paops.casdir`
   is set; inline `DATA` becomes opt-in via `--inline` flag
2. Inline remains the default only when CAS is unavailable (e.g.,
   reading from stdin with no `-c`)
3. New `--inline` flag on `encrypt`/`encrypt-store` for callers who
   want the old behavior
4. Migration path: round-trip parse→write converts old inline blocks
   to CAS-referenced on next encrypt
5. Tests: encrypt → output contains `STORED ct`, not `DATA`; decrypt
   still works; CAS dedup confirmed by hashing identical plaintext
6. README update

## Compatibility

- Reading: both formats parse transparently
- Writing: default changes
- Old files: continue to decrypt; users can `enprot encrypt` again to
  migrate to CAS-referenced form

## Why not deprecate inline entirely

- Stdin→stdout pipelines have no CAS available; inline is needed
- Embedded systems / single-file distribution may want self-contained
- Debug scenarios benefit from seeing the ciphertext

## Acceptance criteria

- Default `encrypt` produces CAS-referenced output when CAS is set
- `--inline` flag restores old behavior
- All existing decrypt tests still pass against both formats
- CAS blob dedup: encrypting the same plaintext twice under the same
  password reuses the same CAS file
