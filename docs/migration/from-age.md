# Migrating from age

age is a modern file-encryption tool. Simple, fast, single-purpose.
enprot is broader — encryption + classification + provenance + CAS
+ chain anchors. Migration makes sense when you want enprot's
extras; otherwise stay on age.

## Vocabulary mapping

| age | enprot | Notes |
|---|---|---|
| `age -p` (passphrase) | `enprot encrypt -w WORD -k WORD=pw` | Equivalent |
| `age -r <recipient>` | `enprot encrypt -w WORD --recipient pub.pem` | enprot uses ML-KEM |
| `age -i priv.txt` | `enprot decrypt -w WORD --key-file priv.pem` | enprot uses ML-KEM |
| `age` file (whole-file) | `enprot` file with one WORD wrapping everything | Whole-file = WORD |
| Standalone `.age` file | `.ept` file with embedded ciphertext | Same idea |
| — | CAS-referenced ciphertext | enprot-only |
| — | Chain anchors (signed history) | enprot-only |
| — | Merge driver for WORD regions | enprot-only |

## When to migrate

| Want | Stay on age if… | Migrate to enprot if… |
|---|---|---|
| Simple file encryption | Yes | No |
| Encrypt parts of a source file | — | Yes |
| Multi-level classification in one file | — | Yes |
| Signed edit history | — | Yes |
| Merge-friendly encrypted regions | — | Yes |

If your use case is "encrypt a file, send to friend" — stay on age.
If it's "encrypt parts of a doc with different keys, track edits"
— migrate.

## Step-by-step

### 1. Decrypt the age file

```sh
age -d -i priv.txt secret.age > secret.txt
```

### 2. Wrap content in a WORD block

```sh
{
  echo "// <( BEGIN Secret )>"
  cat secret.txt
  echo "// <( END Secret )>"
} > secret.ept
```

### 3. Initialize enprot and encrypt

```sh
enprot init
enprot encrypt -w Secret -k Secret=password secret.ept
```

### 4. Optionally replace passphrase with ML-KEM recipient

age recipients and enprot recipients are different formats. Generate
a new ML-KEM keypair:

```sh
enprot keygen mlkem --out-priv recipient-mlkem-priv.pem \
                    --out-pub  recipient-mlkem-pub.pem

enprot encrypt -w Secret --recipient recipient-mlkem-pub.pem secret.ept
```

### 5. Add chain anchor (optional)

```sh
enprot encrypt --anchor --signer my-ed25519-priv.pem -w Secret secret.ept
```

Now the file carries a signed history of every encrypt/decrypt
operation.

## What you gain / lose

**Gain:**
- Multiple classification levels in one file
- CAS-based deduplication of identical ciphertext
- Chain anchors for tamper-evident edit history
- Merge-friendly conflict markers
- OpenPGP interop via rnp-rs
- PQ-ready signatures (ML-DSA, ML-KEM)

**Lose:**
- age's "just works" simplicity
- age's smaller binary (enprot pulls in Botan + librnp)
- age's faster cold-start (no KDF parameter tuning)

## Composition: age + enprot

You don't have to choose. Use age for whole-file encryption of
enprot output:

```sh
enprot encrypt -w Secret -k Secret=pw report.ept
age -r <recipient> -o report.ept.age report.ept
```

The recipient decrypts with age, then runs enprot decrypt on the
result. Two layers of encryption — paranoid but valid.

## See also

- [Migration from git-crypt](from-git-crypt.md)
- [Migration from sops](from-sops.md)
