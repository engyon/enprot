# Migrating from git-crypt

git-crypt encrypts whole files via GPG recipients. enprot encrypts
WORD segments via password-derived keys (or, with Confium, threshold
sessions). The migration is mechanical but lossy in one direction:
enprot can express everything git-crypt does, but git-crypt can't
express multi-level classification or merge-friendly signed regions.

## Vocabulary mapping

| git-crypt | enprot | Notes |
|---|---|---|
| `.gitattributes` pattern with `filter=git-crypt` | WORD segment in file | git-crypt: whole file. enprot: regions. |
| `git-crypt init` | `enprot init` | Both create config + CAS dir |
| `git-crypt unlock keyfile` | `enprot decrypt -w WORD -k WORD=pw file` | git-crypt: GPG keyring. enprot: PEM or password |
| `.gitattributes diff=git-crypt` (merged view) | not directly analogous | enprot always shows current ciphertext |
| GPG recipient list | `--recipient pub.pem` (ML-KEM mode) | enprot supports N recipients |
| `git-crypt export-key` | `enprot keygen` + share privkey | different model |

## Step-by-step

### 1. Inventory encrypted files

```sh
git-crypt status
# or, if git-crypt isn't installed:
grep -rl 'filter=git-crypt' .gitattributes
```

### 2. Convert each file

For each encrypted file, wrap its contents in BEGIN/END WORD blocks:

```sh
./scripts/migrate-from-git-crypt.sh path/to/file
```

Where the script does roughly:

```sh
#!/bin/sh
FILE="$1"
WORD="${FILE##*/}"           # use filename as WORD name
WORD="${WORD//[^A-Za-z0-9_]/_}"
TMP=$(mktemp)
{
  echo "// <( BEGIN $WORD )>"
  cat "$FILE"
  echo "// <( END $WORD )>"
} > "$TMP"
mv "$TMP" "$FILE"
```

### 3. Remove git-crypt configuration

```sh
sed -i '/filter=git-crypt/d' .gitattributes
git rm -rf .git-crypt 2>/dev/null || true
```

### 4. Initialize enprot and encrypt

```sh
enprot init
# Use the same password git-crypt used for this file (or pick a new one)
enprot encrypt -w "$WORD" -k "$WORD=$PASSWORD" "$FILE"
```

### 5. Replace GPG recipient lists with ML-KEM (optional)

git-crypt's "anyone with key X can decrypt" maps to enprot's
`--recipient` mode. Generate ML-KEM keypairs for each recipient:

```sh
for recipient in alice bob carol; do
    enprot keygen mlkem --out-priv "$recipient"-mlkem-priv.pem \
                        --out-pub  "$recipient"-mlkem-pub.pem
done

enprot encrypt \
    -w "$WORD" \
    --recipient alice-mlkem-pub.pem \
    --recipient bob-mlkem-pub.pem \
    --recipient carol-mlkem-pub.pem \
    "$FILE"
```

Each recipient decrypts with their private key — no shared password.

## Caveats

### Whole-file vs segment encryption

git-crypt encrypts the whole file; enprot encrypts WORD segments.
For a fully-encrypted file equivalent, wrap the entire content in
one BEGIN/END WORD block.

### GPG keyring integration

enprot doesn't read GPG keyrings directly. To reuse an existing
GPG key, export it and convert to PEM (or use the OpenPGP path
via rnp-rs for in-process signing):

```sh
gpg --export-secret-keys $KEYID | \
    paperkey --secret-key - | \
    # convert to PEM... (tooling-dependent)
```

For threshold-signing needs, consider migrating to Confium instead
of trying to reuse GPG.

### gitattributes filter

git-crypt's `filter=git-crypt` does transparent encrypt-on-commit /
decrypt-on-checkout. enprot's equivalent is `clean`/`smudge` filters:

```sh
enprot init --git   # writes .gitattributes with the right filter lines
```

But enprot's model is explicit encryption (you run `enprot encrypt`),
not transparent. This is intentional — transparent encryption
hides what's happening from the operator.

## Rolling back

If you need to revert to git-crypt mid-migration:

```sh
# Restore from backup
git checkout HEAD~N -- path/to/file

# Re-add git-crypt filter
echo "path/to/file filter=git-crypt diff=git-crypt" >> .gitattributes
git-crypt unlock
```

## See also

- [Migration from sops](from-sops.md)
- [Migration from age](from-age.md)
- [Migration from sigstore](from-sigstore.md) (composition, not replacement)
