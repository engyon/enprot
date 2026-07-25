# 45 — Git smudge/clean filters

**Priority**: P2
**Status**: specified (consolidated from TODO.finalize/06)

## CLI

```sh
enprot clean    # stdin plaintext → stdout ciphertext (det AEAD)
enprot smudge   # stdin ciphertext → stdout plaintext (needs Decryptor)
enprot textconv # for git diff: decrypt to plaintext for readable diffs
```

## .gitattributes + .git/config

```
*.ept filter=enprot diff=enprot merge=enprot
```

```
[filter "enprot"]
    clean = enprot clean
    smudge = enprot smudge
[diff "enprot"]
    textconv = enprot textconv
```

`enprot init --git` scaffolds the config.

## Dependencies

- TODO 40 (config file) for non-interactive key source
- TODO 42 (CAS-referenced default) for repo-size efficiency

## Acceptance criteria

- [ ] Round-trip: clean → smudge produces identical plaintext
- [ ] textconv produces readable diffs
- [ ] Missing capability: clean/smudge fails loudly
