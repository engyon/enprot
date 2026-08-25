<!-- Copyright (c) 2018-2026 [Ribose Inc](https://www.ribose.com). -->
<!--
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
// 1. Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
-->

# Key escrow and recovery

Password-only encryption has a failure mode enterprises can't accept:
a forgotten password, a departed employee, a compliance audit — and the
plaintext is gone. Escrow mode gives an encrypted block **two independent
decryption paths**: the user's password, and any one of a set of recovery
private keys held by the organization.

## Usage

```sh
# Encrypt to the password AND a recovery pubkey (repeatable flag)
enprot encrypt -w WORD -k WORD=password \
    --cipher aes-256-siv \
    --recovery-key recovery.pub.pem \
    FILE

# Normal decrypt — unchanged, nobody needs to know escrow exists
enprot decrypt -w WORD -k WORD=password FILE

# Recovery decrypt — no password at all
enprot decrypt -w WORD --key-file recovery.priv.pem FILE
```

Either path restores the plaintext. A wrong password fails cleanly at the
key-wrap AEAD (`AEAD decrypt failed`) — never garbage output. With neither
password nor key supplied, the error says exactly what to provide; escrow
blocks never fall back to an interactive prompt.

## How it works

The payload is encrypted under a fresh random content-encryption key
(CEK). The CEK is then wrapped once per path:

- **Password path**: `KEK = PBKDF(password, salt)` recorded in the
  usual `pbkdf:` field, CEK wrapped under the KEK with AES-256-GCM in
  `pw-wrap:`.
- **Recovery path** (per pubkey): ML-KEM encapsulation to the recovery
  pubkey; the shared secret expands via HKDF to a wrap key; the CEK
  wrapped under it, with the KEM ciphertext in
  `recovery-kem-mlkem-<fp>:` and the wrap in
  `recovery-wrap-mlkem-<fp>:`. The `recovery:` field lists every
  recovery fingerprint.

The wrap cipher is always AES-256-GCM — policy-approved under both the
default and NIST policies, and distinct from the payload cipher so wrap
and payload keys are never conflated.

This CEK indirection is what makes later operations cheap: rotating the
recovery key or the password means re-wrapping a ~64-byte key, not
re-encrypting content (the manual procedure today is decrypt + re-encrypt;
a dedicated re-wrap command is future work).

## Constraints

- **Deterministic ciphers are refused.** `--recovery-key` with any
  `-det` cipher errors out: the fresh CEK makes each encryption random,
  which silently breaks the deterministic same-input → same-output
  contract (CAS dedup). Note the default policy's default cipher
  (`aes-256-gcm-siv-det`) is deterministic — pass `--cipher aes-256-siv`
  (or run under `--fips`, whose default is `aes-256-gcm`).
- Files encrypted without `--recovery-key` are byte-identical to the
  legacy format; escrow is strictly opt-in per encryption.
- Recovery keys are ML-KEM keys. `enprot keygen` covers signature
  algorithms; KEM keys are generated through the library
  (`pki::kem_keygen`) or your organization's existing provisioning.
- Multi-sig chain anchors are unrelated to escrow; see
  [pq-migration.md](pq-migration.md) for anchor migration.

## Key-management policy (who holds recovery keys)

Escrow is only as trustworthy as the custody of the recovery private
keys. Recommended practices:

- **Split knowledge**: require k-of-n recovery keys (e.g., legal holds
  one, security holds one, both must cooperate). Today this means
  encrypting with multiple `--recovery-key` pubkeys and applying
  organisational separation; cryptographic threshold escrow is future
  work.
- **Offline storage**: recovery privkeys live in a vault or HSM, never
  on employee machines, never in the repository.
- **Rotation**: rotate recovery pubkeys on a schedule; rotation =
  re-encrypt files with the new key (documented manual procedure for
  now).
- **Audit**: run recovery decryption under `--audit-log` so every use
  is recorded (`enprot audit query` / `verify` to review). Recovery
  without a record is a policy violation, not a tooling problem.

## See also

- `docs/threat-model.md` — which adversaries escrow does and doesn't
  address (it *adds* a key-holder adversary; it doesn't remove any).
- `docs/pq-migration.md` — ML-KEM/ML-DSA key handling.
