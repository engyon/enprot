# 60 — Wire --recipient into encrypt/decrypt CLI

**Priority**: P0
**Status**: specified

## Problem

The `kemenc` module (TODO.roadmap/58) implements ML-KEM-based
multi-recipient encryption at the library level, but the CLI
subcommands `encrypt` and `decrypt` have no `--recipient` /
`--key-file` flags. Users cannot use pubkey-based encryption
from the command line today — only password-based (PBKDF).

This is the biggest functional gap: the capability model
promises "encrypt to a recipient's pubkey, not a shared
password" but the CLI surface doesn't deliver it.

## Solution

### Encrypt side

Add `--recipient pub.pem` (repeatable) to `EncryptSubcmd`.
When at least one recipient is supplied, the transform calls
`kemenc::encrypt` instead of `prot::encrypt`. The Encrypted
block's extfields carry `recipients:` + per-recipient KEM
ciphertext entries.

ParseOps gains a `recipient_pubkeys: Vec<String>` field so the
transform layer can dispatch without touching CLI types.

### Decrypt side

Add `--key-file priv.pem` (repeatable) to `OperationSubcmd`.
When the Encrypted block has a `recipients:` extfield, the
transform calls `kemenc::decrypt` using the matching privkey.
When it has `pbkdf:`, it falls back to `prot::decrypt` (current
behaviour).

ParseOps gains a `recipient_privkeys: HashMap<String, String>`
keyed by WORD so multiple WORDs can decrypt with different keys.

### Mixed mode

If both `--recipient pub.pem` and `-k WORD=PASSWORD` are
supplied for the same WORD, the recipient wins. This lets
callers encrypt some WORDs with pubkeys and others with
passwords in one invocation.

## Implementation

- ParseOps: add `recipient_pubkeys` and `recipient_privkeys`
  fields (or a unified `KeySource` enum per WORD).
- transform_begin_end: branch on whether recipients are set
  for this WORD.
- cli.rs: add `--recipient` to EncryptSubcmd, `--key-file` to
  OperationSubcmd (decrypt path only).

## Acceptance criteria

- [ ] `encrypt --recipient pub.pem -w WORD FILE` produces
      Encrypted blocks with `recipients:` extfields
- [ ] `decrypt --key-file priv.pem -w WORD FILE` recovers
      plaintext from KEM-mode blocks
- [ ] Password-based encrypt/decrypt round-trip unchanged
- [ ] Mixed mode (password + recipient on different WORDs) works
- [ ] Tests cover all four cases
