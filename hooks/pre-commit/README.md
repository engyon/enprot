# enprot pre-commit hook

Pre-commit hook that blocks commits when a file contains plaintext
inside an enprot `BEGIN WORD` block. Catches the "committed the
secret" footgun before it reaches the remote.

## Install with pre-commit framework

Add to your project's `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/engyon/enprot
    rev: v0.5.11
    hooks:
      - id: enprot-plaintext
        name: enprot (no plaintext in BEGIN blocks)
        entry: python3 hooks/pre-commit/enprot_pre_commit.py
        language: system
        types: [text]
```

Then `pre-commit install` to wire it into `.git/hooks/pre-commit`.

## Install as a plain git hook

```sh
cp hooks/pre-commit/enprot_pre_commit.py .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```

## What it detects

A file fails when it has a block like:

```
// <( BEGIN SECRET )>
password = "hunter2"
// <( END SECRET )>
```

i.e. the body is plaintext. These pass cleanly:

```
// <( ENCRYPTED SECRET )>
// <( DATA 7Z2K... )>
// <( END SECRET )>

// <( STORED SECRET key=abc123 )>
// <( END SECRET )>
```

Encrypted ciphertext and CAS pointers are safe to commit; raw
plaintext is not.

## CLI

```sh
python3 enprot_pre_commit.py [FILES...]      # scan listed files (default)
python3 enprot_pre_commit.py                 # scan staged files (git diff --cached)
python3 enprot_pre_commit.py --all           # scan entire tracked tree
```

Exit code 0 = clean, 1 = plaintext found.
