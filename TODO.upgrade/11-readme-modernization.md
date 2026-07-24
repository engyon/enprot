# 11 — README modernization

## Goal

`README.adoc` still describes Botan 2.13 and the old install story. Update
to reflect Botan 3, the dual cipher backend, and the current dependency
set.

## Files

- `README.adoc`

## Approach

- Bump the Botan version reference (2.13 → 3.x).
- Note the cipher backend split: Botan for `aes-256-siv` and `aes-256-gcm`,
  RustCrypto for `aes-256-gcm-siv` (Botan doesn't implement RFC 8452).
- Update the cryptography section to reflect the maintained PBKDF list
  and the `pbkdf:`/`cipher:` extfield format.
- Add a brief "Compatibility" note: documents produced by enprot ≤0.3.1
  still decrypt.
- Leave the tutorial section alone — the EPT markup and examples are
  unchanged.

## Verification

Visual review of rendered asciidoc.

## Rollback

Revert the file.
