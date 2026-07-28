# Migrating from sops

sops encrypts structured files (YAML, JSON, ENV) with per-key
metadata. enprot encrypts WORD segments inside any text file. The
migration requires deciding whether you want whole-file encryption
(simpler) or per-key encryption (closer to sops's per-key model).

## Vocabulary mapping

| sops | enprot | Notes |
|---|---|---|
| YAML/JSON with `sops:` metadata block | EPT file with WORD segments | sops: structured. enprot: text-region. |
| `sops --encrypt --kms arn:…` | `enprot encrypt -w WORD --recipient pub.pem` | sops: KMS. enprot: ML-KEM recipients. |
| `sops --set '["key"]=value'` for partial updates | edit + `enprot encrypt -w WORD` | sops: structured path. enprot: re-encrypt WORD. |
| `sops --rotate` re-encrypts under new keys | same — re-run encrypt with new recipients | identical pattern |
| Per-key encryption metadata in `sops:` block | per-WORD ENCRYPTED blocks | different surface, equivalent semantics |

## Step-by-step

### 1. Identify sops-encrypted files

```sh
grep -rl 'sops_version' --include='*.yaml' --include='*.json' .
```

### 2. Convert YAML/JSON to EPT format

For a sops-encrypted YAML file like:

```yaml
database_password: ENC[AES256_GCM,data:abc123,iv:…,tag:…,type:str]
api_key: ENC[AES256_GCM,data:def456,iv:…,tag:…,type:str]
public_setting: this_stays_plaintext
```

Convert to EPT with one WORD per encrypted key:

```yaml
public_setting: this_stays_plaintext
database_password: # <( ENCRYPTED DbPw pbkdf:… cipher:… )> # <( DATA … )> # <( END DbPw )>
api_key: # <( ENCRYPTED ApiKey pbkdf:… cipher:… )> # <( DATA … )> # <( END ApiKey )>
```

The `#` prefix works for YAML/Python-style comments. For other
host languages, adjust the separator via `--lang`:

```sh
enprot --lang raw encrypt -w DbPw -k DbPw=pw secrets.yaml
```

### 3. Re-encrypt under enprot keys

```sh
# Generate keys (or reuse the sops KMS key material)
enprot keygen ed25519 --out-priv ops-priv.pem --out-pub ops-pub.pem

# For each sops-encrypted value, populate its WORD with the plaintext
# (extracted from sops --decrypt), then encrypt:
enprot encrypt -w DbPw -k DbPw="$DB_PW" secrets.yaml
enprot encrypt -w ApiKey -k ApiKey="$API_KEY" secrets.yaml
```

### 4. Migrate KMS-backed encryption to ML-KEM recipients

If sops used AWS KMS / GCP KMS, replace with enprot's recipient
model (or wait for Confium cloud-store integration):

```sh
# Generate per-recipient ML-KEM keys
enprot keygen mlkem --out-priv deploy-mlkem-priv.pem --out-pub deploy-mlkem-pub.pem

enprot encrypt \
    -w DbPw \
    --recipient deploy-mlkem-pub.pem \
    secrets.yaml
```

## Caveats

### Per-key vs per-WORD granularity

sops encrypts individual values inside a YAML/JSON structure.
enprot encrypts WORD segments, which can wrap a single value OR
a multi-line block. For one-value-per-line secrets, the
`inline-form` shown above works. For larger regions (whole YAML
subtree), wrap the region:

```yaml
# <( BEGIN ProductionSecrets )>
database_password: abc123
api_key: def456
# <( END ProductionSecrets )>
```

Then `enprot encrypt -w ProductionSecrets -k ProductionSecrets=pw file.yaml`.

### YAML/JSON structure preservation

sops preserves the file's structure (you can still `yq` / `jq`
the unencrypted keys). enprot's WORD segments live in comments, so
the host structure stays valid — but the encrypted *content* is
inside comment blocks, not in the YAML/JSON tree.

For tooling that parses the YAML/JSON directly, this is a behavior
change. Workarounds:
1. Use placeholder values in the YAML/JSON; document that the real
   values live in the WORD segments.
2. Use the `clean`/`smudge` git filter to swap placeholder for
   real value at checkout.

### sops's PGP fallback path

sops supports PGP keys as a fallback when KMS is unavailable.
enprot's OpenPGP path (via rnp-rs) covers the same use case:

```sh
enprot encrypt --recipient pgp:alice@example.com -w WORD file.yaml
```

(`pgp:` URI scheme is future; for now convert PGP keys to PEM or
ML-KEM.)

## See also

- [Migration from git-crypt](from-git-crypt.md)
- [Migration from age](from-age.md)
