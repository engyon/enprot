# Stage 5a — Audit log mode

## Why

A natural application of chain anchors: append-only audit logs where
every line is attested. `tail -f` for cryptographic logs. Useful for:

- Compliance logs (SOX, HIPAA access logs)
- Security event logs (intrusion detection, SIEM feeds)
- Operational change logs (who deployed what, when, with whose sign-off)

## Scope

1. New mode: `enprot audit-log FILE`:
   - Watches stdin (or `-w path` for file tail)
   - Each line becomes a chain anchor with `mutations: append <line-hash>`
   - Anchors signed with `--signer <key-file>`
   - Optional `--rotate <N>`: roll over to a new file every N anchors
2. `verify-chain --audit` mode: optimizes for streaming verification
   of large logs (doesn't load all anchors into memory)
3. Tamper detection: any line deletion, insertion, or modification
   breaks the chain at that point
4. Tests: append + verify; tamper detection at various points;
   rotation correctness

## Real-life example (docs)

```sh
# Set up an audit log
enprot keygen ed25519 --out-priv auditor.pem --out-pub auditor.pub

# Stream audit events
(echo "user=alice action=login ts=$(date -Iseconds)";
 echo "user=bob action=deploy ts=$(date -Iseconds)") | \
  enprot audit-log --signer auditor.pem access-log.ept

# Verify later
enprot verify-chain --trust-root $(enprot fingerprint auditor.pub) access-log.ept
```

## Out of scope

- Real-time alerting (caller pipes `verify-chain` into their alerting)
- Log shipping (caller's infra)
- Compression (caller can gzip the CAS)

## Acceptance criteria

- Audit log mode produces verifiable chain
- Tamper detection works for insert, delete, modify
- Stream verification handles 100k+ anchors in <10s
