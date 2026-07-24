# Git smudge/clean filters

## Why

Git's smudge/clean (`.gitattributes`) lets you transform a file at
checkout (smudge) and at commit (clean). For EPT files, this enables:

- **Auto-encrypt on commit**: plaintext in working tree → ciphertext
  in repo (team members only see ciphertext via `git log`)
- **Auto-decrypt on checkout**: ciphertext in repo → plaintext in
  working tree (only signers of granted capabilities see plaintext)
- **Sanitize on push, restore on pull**: STORED references in repo,
  full content in working tree

This is the "always-on encryption" workflow that fits naturally into
existing git habits.

## Scope

1. `enprot smudge` subcommand: reads ciphertext from stdin, writes
   plaintext to stdout. Requires the caller's Decryptor capability
   (password from `ENPROPT_WORD_<NAME>` env var or config).
2. `enprot clean` subcommand: reads plaintext from stdin, writes
   ciphertext to stdout. Uses deterministic AEAD (TODO 15) so the
   same plaintext produces the same ciphertext → git diffs are
   minimal.
3. `.gitattributes` snippet (in docs):
   ```
   *.ept  filter=enprot diff=enprot merge=enprot
   *.eptx filter=enprot diff=enprot merge=enprot
   ```
4. `.git/config` snippet:
   ```
   [filter "enprot"]
       clean = enprot clean
       smudge = enprot smudge
   [diff "enprot"]
       textconv = enprot textconv
   ```
5. `enprot textconv` subcommand: for `git diff` rendering. Decrypts
   to plaintext so diffs show semantic changes, not ciphertext noise.
6. `enprot init --git` flag: writes the `.gitattributes` and
   `.git/config` snippets for the current repo.
7. Tests:
   - Round-trip: clean → smudge produces identical plaintext (with
     det AEAD)
   - Diff readability: textconv output is human-readable
   - Missing capability: clean fails loudly, not silently

## Dependencies

- TODO 05 (config file): smudge/clean is non-interactive; needs
  config + env vars for keys
- TODO 15 (det AEAD default): deterministic ciphertext → reproducible
  diffs
- TODO 16 (CAS-referenced default): keeps repo size small via CAS
  dedup

## Out of scope

- Per-branch encryption policies (use separate repos)
- Auto-rotation of passwords (key distribution, out of scope)
- Conflict resolution in smudge/clean context (the merge driver TODO
  19 handles three-way merges)

## Real-life example

```sh
# Project setup
enprot init --git
git add .gitattributes
git commit -m "Configure enprot smudge/clean"

# Day-to-day
echo "// <( BEGIN Secret )>\nstuff\n// <( END Secret )>" > notes.ept
git add notes.ept          # clean → ciphertext in index
git commit -m "Add secret notes"
git push                   # ciphertext in remote

# Collaborator
git clone <repo>
# working tree shows plaintext (if they have the password)
ENPROPT_WORD_Secret=hunter2 cat notes.ept
```

## Acceptance criteria

- `clean` + `smudge` round-trips with det AEAD
- `textconv` produces readable diffs
- All tests pass; CI green
- Documentation in `docs/git-integration.md`
