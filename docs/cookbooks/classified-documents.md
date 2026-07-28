# Classified document workflow (per RSD spec)

Demonstrates enprot's classification model: one source file carries
multiple classification levels simultaneously, different parties see
different views. Built on the [Ribose Standard for EPT][rsd-spec]
vocabulary.

[rsd-spec]: https://github.com/riboseinc/rsd-engyon-syntax

## The model

A document has nested WORD segments at different classification
levels. Each level has its own key. The same source compiles to
different distributions: a fully-classified version for the
authoring team; a sanitized version for broader distribution with
classified segments replaced by hash references.

```
// <( BEGIN Public )>
This document is approved for public release.
// <( BEGIN Confidential )>
Internal source: [name withheld]
// <( BEGIN Secret )>
Source 13 is Mallory.
// <( END Secret )>
// <( END Confidential )>
// <( END Public )>
```

## Setting up

```sh
enprot init
# Generate three keys, one per classification level
enprot keygen ed25519 --out-priv public-priv.pem --out-pub public-pub.pem
# (Public sections aren't encrypted; the key is for chain anchor signing only)

# Set passwords (or use --pbkdf-salt to fix derivation)
export ENPROT_CONFIDENTIAL_PW="..."
export ENPROT_SECRET_PW="..."
```

## Encrypting at each level

```sh
# Encrypt the Secret segment
enprot encrypt -w Secret -k Secret="$ENPROT_SECRET_PW" report.ept

# Encrypt the Confidential segment (which now contains the
# encrypted Secret inside it)
enprot encrypt -w Confidential -k Confidential="$ENPROT_CONFIDENTIAL_PW" report.ept

# Sign the full document at the Public level
enprot encrypt --anchor --signer public-priv.pem -w Public report.ept
```

After encryption, the file looks like:

```
// <( BEGIN Public )>
This document is approved for public release.
// <( ENCRYPTED Confidential pbkdf:$argon2id$… cipher:aes-256-gcm$iv=… )>
// <( STORED ct 2b8f1e3c4d… )>
// <( END Confidential )>
// <( END Public )>
// <( CHAIN ts:… signer:ed25519:… payload:… sig:… )>
```

The original nested plaintext is gone — replaced by encrypted
blocks and CAS references.

## Sanitizing for unclassified distribution

To produce a version without the Confidential / Secret content,
store each classified segment to CAS and distribute the sanitized
file:

```sh
# Store Secret first (innermost), then Confidential
enprot store -w Secret report.ept
enprot store -w Confidential report.ept

# Now report.ept has STORED pointers where the encrypted blocks were
git add cas/  # include the CAS blobs if recipients can decrypt
```

Distribute `report.ept` plus the `cas/` directory. Recipients
without the Confidential key see only the hash; they can verify
the document's structure without seeing the content.

## Restoring classified content

After an editor modifies the unclassified version (e.g. typo fix
in the public section), restore the classified content:

```sh
enprot fetch -w Confidential report.ept
enprot fetch -w Secret report.ept
enprot encrypt -w Secret -k Secret="$ENPROT_SECRET_PW" report.ept
enprot encrypt -w Confidential -k Confidential="$ENPROT_CONFIDENTIAL_PW" report.ept
enprot encrypt --anchor --signer public-priv.pem -w Public report.ept
```

The CAS layer ensures content survives sanitization unchanged —
the same SHA3-256 hash always references the same blob.

## k-of-n signing (Confium integration, Phase 3+)

For documents requiring multi-party approval (e.g. 3-of-5 release
approvers), route signing through Confium:

```sh
# One-time setup: create a FROST session via confium-cli (when it ships)
# confium session create --threshold 3 --parties alice,bob,carol,dave,eve

# enprot delegates signing to the daemon
enprot encrypt --anchor \
    --signer confium://release-approvers \
    -w Public report.ept
```

The chain anchor's `signer:` extfield carries the threshold
metadata:

```
signer:frost-ed25519:group=…;t=3;n=5;session=…;daemon=tcp://confium:7001
```

Verifiers without Confium check the group pubkey fingerprint
against their trust root — they don't need to know it was
threshold. Verifiers with Confium can additionally query the
session log to confirm the quorum.

## Attribute-based access control (Phase 3+)

Bind classification levels to clearance attributes rather than
specific passwords:

```sh
enprot encrypt \
    -w Secret \
    --attribute-predicate 'clearance >= SECRET && citizenship == "US"' \
    report.ept
```

The predicate is encoded in the ENCRYPTED block's extfield. When
the recipient's Confium daemon evaluates the predicate against
their attribute set, access is granted or denied at decrypt time.

## What this demonstrates

- One source file carries multiple classification levels.
- Sanitization is reversible (CAS ensures content survives).
- Signing works the same way for single-party (PEM) and threshold
  (Confium) — the wire format is identical.
- Attribute-based access moves policy into the document, not the
  key distribution.

## See also

- [Collaborative editing cookbook](collaborative-editing.md)
- [Supply chain attestation cookbook](supply-chain.md)
- RSD spec: [riboseinc/rsd-engyon-syntax][rsd-spec]
