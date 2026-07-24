# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.4.x   | yes       |
| < 0.4   | no        |

## Reporting a Vulnerability

**DO NOT** open a public issue for security vulnerabilities.

Report security issues to: open.source@ribose.com

### What to Include

1. Description of the vulnerability
2. Steps to reproduce
3. Potential impact
4. Your name/handle (optional)

### Response Timeline

- **Initial response**: Within 48 hours
- **Status update**: Within 7 days
- **Resolution target**: Within 30 days (critical), 90 days (others)

## Security Considerations

### Cryptographic Primitives

Enprot uses [Botan 3](https://botan.randombit.net/) as its primary crypto backend:

- **AEAD ciphers**: AES-256-SIV (default, RFC 5297), AES-256-GCM, AES-256-GCM-SIV (RFC 8452 via RustCrypto)
- **KDF**: Argon2id (default), Scrypt, PBKDF2-SHA-256/512
- **Hashing**: SHA-3-256 for CAS, SHA-3-512 for legacy PBKDF

### FIPS Mode

The `--fips` flag selects the `nist` policy which restricts algorithms to FIPS-approved names. See `docs/fips.adoc` for details on what a fully validated FIPS build would require.

### Password Handling

- Passwords are read via `rpassword` with TTY echo suppression
- Piped passwords are accepted but repeat-verification is skipped
- Passwords are never logged or written to CAS

### Known Limitations

1. **No constant-time CAS comparison** — the CAS hash is content-derived, not secret-derived, so timing leaks are not a concern
2. **Legacy PBKDF** (plain SHA3-512 truncation) is retained for backward compatibility with old blobs; a warning is printed on encrypt

### Security Updates

Security updates will be:
- Announced on GitHub Releases
- Published to crates.io immediately
- Documented in the changelog
