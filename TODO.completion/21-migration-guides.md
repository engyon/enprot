# 21 — Migration guides from git-crypt / sops / sigstore

**Priority**: P2
**Status**: specified

## Problem

enprot's target users already use one of: git-crypt, sops, age,
sigstore, gpg, transcrypt, blackbox. Switching tools has real cost
(rewriting CI, retraining team, migrating existing secrets). Without
a clear migration path, adoption stalls at "interesting but too
expensive to switch".

## Goal

Per-tool migration guide that:
1. Maps the existing tool's vocabulary to enprot's
2. Shows step-by-step conversion of a representative repo
3. Documents caveats (features that don't map cleanly)
4. Provides a migration script where possible

## git-crypt → enprot

### Vocabulary mapping

| git-crypt | enprot |
|---|---|
| `.gitattributes` pattern with `filter=git-crypt` | WORD segment in file |
| `git-crypt init` | `enprot init` |
| `git-crypt unlock keyfile` | `enprot decrypt -w WORD -k WORD=pw file` |
| GPG recipient list | `--recipient pub.pem` (or Confium session) |

### Migration steps

```sh
# 1. Identify encrypted files
git-crypt status

# 2. For each file, replace git-crypt filter with EPT markup
# (script: scan for git-crypt-encrypted files, wrap content in
# BEGIN/END WORD blocks)
./scripts/migrate-from-git-crypt.sh path/to/repo

# 3. Remove git-crypt from .gitattributes
sed -i '/git-crypt/d' .gitattributes

# 4. Initialize enprot
enprot init
enprot encrypt -w Migrated -k Migrated=<old-password> file1 file2 ...
```

### Caveats

- git-crypt encrypts whole files; enprot encrypts WORD segments.
  Whole-file encryption = wrap entire file in BEGIN/END.
- git-crypt uses GPG keyrings; enprot uses PEM (or Confium for
  multi-party). Bridge via `gpg --export` → PEM conversion.

## sops → enprot

### Vocabulary mapping

| sops | enprot |
|---|---|
| YAML/JSON file with `sops:` metadata | `.ept` file |
| `sops --encrypt --kms ...` | `enprot encrypt -w Sops --recipient pub.pem` |
| `sops --set` for partial updates | edit + `enprot encrypt -w WORD` |
| Key rotation via re-encrypt | same |

### Migration

sops has structured metadata (per-key encryption). enprot is per-WORD.
A single sops file may map to one EPT file with multiple WORDs:

```yaml
# Original sops file
database_password: ENC[AES256GCM,...]
api_key: ENC[AES256GCM,...]
```

Becomes:

```
database_password: // <( ENCRYPTED DbPw pbkdf:… cipher:… )> // <( DATA … )> // <( END DbPw )>
api_key: // <( ENCRYPTED ApiKey pbkdf:… cipher:… )> // <( DATA … )> // <( END ApiKey )>
```

Migration script: `./scripts/migrate-from-sops.sh file.yaml`.

## sigstore → enprot

sigstore is artifact-level signing (cosign). enprot is
document-level signing (chain anchors). They compose:

```sh
# Sign the source document with enprot chain anchor
enprot encrypt --anchor --signer dev-priv.pem file.ept

# Sign the built artifact with cosign
cosign sign --key dev-key blob.tar.gz
```

enprot doesn't replace cosign; it complements it. Document this.

## age → enprot

age is simpler than enprot (file-level, no chain anchors). Migration
is mostly "drop in BEGIN/END WORD around age-encrypted content" if
the user wants enprot's other features (CAS, merge).

## Acceptance criteria

- [ ] `docs/migration/from-git-crypt.md`
- [ ] `docs/migration/from-sops.md`
- [ ] `docs/migration/from-sigstore.md` (composition, not replacement)
- [ ] `docs/migration/from-age.md`
- [ ] Migration scripts where feasible
- [ ] Cookbook: end-to-end git-crypt → enprot migration

## Cross-references

- [[04-cookbooks]] — final-state workflows
- [[03-readme-positioning]] — comparison table
