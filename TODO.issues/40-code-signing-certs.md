# 40 — Support usage with code-signing certificates

## Problem

One target user population uses individual code-signing certificates
issued by DigiCert (primarily on Windows, then macOS, then Linux).
enprot should "support this use case" — but the use case itself is
under-specified.

## Why this is deferred

The issue doesn't define:

- **What** the cert is for. Options:
  - Signing the enprot binary itself (authenticode on Windows,
    codesign on macOS, GPG elsewhere).
  - Signing the *output* files enprot produces (so recipients can verify
    provenance).
  - Using the cert's private key as (or to derive) the encryption key
    instead of (or in addition to) a password.
  - Encrypting segments *to* a certificate's public key (PKI envelope,
    like CMS / S/MIME).
- **Where** the cert lives. Windows cert store? Keychain? PEM file on
  disk? Hardware token (PIV/PKCS#11)?
- **Who** verifies. The same user? A CI pipeline? A downstream consumer
  of the encrypted file?
- **What** the integration with EPT markup looks like. A new directive
  (`<( SIGNED BY ... )>`)? A signature extfield on `ENCRYPTED`? A
  separate top-level signature over the whole document?

Each of these is a meaningfully different feature. Picking one without
the user confirming cuts off the others.

## What this codebase would need

Any of the four interpretations is a non-trivial addition:

- **Binary signing** is purely a release-engineering concern; no Rust
  code in enprot itself, just CI steps.
- **Output file signing** needs a signature format choice (CMS, JWS,
  PGP, custom), key management, and verification logic.
- **Cert-as-key** means bridging enprot's PBKDF-centric model to a
  certificate-centric one. Probably a new KDF "alg" (`x509-cert`) that
  pulls the key from a cert handle.
- **Encrypt-to-cert (PKI envelope)** is the biggest: would need CMS
  support, ASN.1, X.509 parsing, etc. Botan has these primitives but
  the wire format and UX design work is significant.

## Status (July 2026)

Resolved as **deferred-by-doc**. `docs/code-signing.adoc` captures the
four plausible interpretations of the issue (sign the binary, sign
output files, cert-as-key, encrypt-to-cert), the open questions for
each, and the suggested extension points in the codebase.

The issue stays under-specified; picking one path requires scope
discussion with the original reporter. Anyone driving the initiative
has a starting point.
