# 59 — Key escrow / recovery

**Priority**: P2
**Status**: specified

## Problem

enprot encrypts WORD segments with a password. If the user forgets
the password, the plaintext is unrecoverable. For enterprise
deployments, this is unacceptable — HR needs to access departed
employees' files, compliance officers need audit access, and
business continuity requires a recovery path.

Current state: no key escrow, no recovery key, no multi-recipient
encryption at the password level. The `recipient:` extfield
supports multi-pubkey encryption (KEM mode), but that's for
*intended* recipients, not for *recovery*.

## Goals

- A `--recovery-key <PUB.pem>` flag that encrypts each WORD segment
  to BOTH the password AND the recovery pubkey.
- Decrypt succeeds with EITHER the password OR the recovery privkey.
- Recovery keys are optional; default behavior is unchanged.
- A `enprot recover --key <PRIV.pem> FILE` command for recovery-time
  decryption.
- Documented key-management policy for recovery keys (who holds
  them, how they're rotated, how access is audited).

## Design

### Wire format extension

The ENCRYPTED block's extfields gain an optional `recovery:` field:

```ept
// <( ENCRYPTED SECRET
       pbkdf:$pbkdf2-sha256$i=1000$...
       cipher:aes-256-siv
       recovery:<recovery-pubkey-fp>:<base64-wrapped-key>
 )>
```

The `recovery:` field carries the content-encryption key (CEK)
wrapped with the recovery pubkey (via RSA-OAEP or ML-KEM). At
decrypt time:

1. Try password-based decrypt (existing path).
2. If that fails (wrong password), try `--key PRIV.pem` against
   the `recovery:` field.
3. If neither works, error.

### CLI surface

```sh
# Encrypt with recovery key
enprot encrypt -w WORD -k WORD=password --recovery-key recovery.pub FILE

# Normal decrypt (password)
enprot decrypt -w WORD -k WORD=password FILE

# Recovery decrypt (privkey)
enprot recover -w WORD --key recovery.priv FILE
```

### Key wrapping

The CEK is a random 256-bit key generated per encryption. It's
used as the actual cipher key (the PBKDF-derived key wraps the
CEK, not the plaintext directly). This separation means:

- Password change: re-wrap the CEK with the new PBKDF key.
  Plaintext isn't re-encrypted.
- Recovery key rotation: re-wrap the CEK with the new recovery
  pubkey. Same.
- Multiple recovery keys: multiple `recovery:` lines, each
  wrapping the same CEK with a different pubkey.

### Audit trail

Every `enprot recover` invocation should be logged (TODO #63):
who, when, which file, which WORD. This prevents silent recovery
abuse.

## Implementation plan

1. Add `recovery:` extfield parsing in `etree::parse`.
2. Modify `prot::encrypt` to accept an optional recovery pubkey.
3. Generate per-encryption CEK, wrap with recovery pubkey via KEM.
4. Modify `prot::decrypt` to try recovery unwrap on password failure.
5. Add `--recovery-key` CLI flag to `encrypt` subcommand.
6. Add `enprot recover` subcommand.
7. Document key-management policy in `docs/key-escrow.md`.
8. Add conformance fixture with recovery extfield.

## Test plan

- [ ] Encrypt with recovery key, decrypt with password succeeds.
- [ ] Encrypt with recovery key, recover with privkey succeeds.
- [ ] Decrypt with wrong password + no privkey fails gracefully.
- [ ] Recovery key rotation preserves existing encrypted content.
- [ ] Multiple recovery keys: any one privkey suffices.

## Out of scope

- Shamir secret sharing for recovery keys (organisational, not
  technical — use a separate tool).
- Hardware-backed recovery keys (covered by #56).
- Automatic key rotation (manual process; document the procedure).
- Legal compliance of key escrow (jurisdiction-dependent; consult
  legal counsel).
