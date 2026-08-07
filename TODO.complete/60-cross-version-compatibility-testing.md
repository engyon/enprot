# 60 — Cross-version compatibility testing

**Priority**: P1
**Status**: specified

## Problem

enprot evolves. A file encrypted by 0.4.x should decrypt in 0.5.x;
a file encrypted by 0.5.13 should decrypt in 0.5.14. But there's
no automated test that verifies this. The wire format, extfield
syntax, and cipher parameter encoding change over time.

Manual testing found issues in the past (the pbkdf extfield format
changed between 0.4 and 0.5). Without automated cross-version
testing, each release ships with an implicit "trust me" on
backwards compatibility.

## Goals

- A `tests/cross-version/` directory with fixtures encrypted by
  each released version of enprot.
- A CI job that decrypts every fixture with the current build.
- A CI job that encrypts a test payload with the current build and
  decrypts it with the previous released version.
- A version matrix documenting which versions are mutually
  compatible.

## Design

### Fixture directory

```
tests/cross-version/
├── README.md
├── v0.4.0/
│   ├── encrypt_aes256siv.ept       # encrypted with 0.4.0
│   ├── encrypt_aes256gcm.ept
│   ├── store_basic.ept
│   └── meta.toml                    # password, expected plaintext hash
├── v0.5.0/
│   ├── encrypt_aes256siv.ept
│   └── ...
├── v0.5.13/
│   ├── encrypt_aes256gcmsiv_det.ept
│   └── ...
└── current/
    └── (generated at test time by the current build)
```

Each fixture carries a `meta.toml`:

```toml
version = "0.5.13"
word = "TEST"
password = "test123"
plaintext_sha3_256 = "abcdef..."
operations = ["decrypt"]
```

### CI job

```yaml
# .github/workflows/cross-version.yml
jobs:
  backwards-compat:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - run: ./ci/install.sh
      - run: cargo build --release
      # Decrypt every historical fixture with the current build.
      - run: |
          for dir in tests/cross-version/v*/; do
            version=$(basename "$dir")
            for fixture in "$dir"*.ept; do
              password=$(toml get "$dir/meta.toml" password)
              word=$(toml get "$dir/meta.toml" word)
              ./target/release/enprot decrypt -w "$word" -k "${word}=${password}" "$fixture" > /dev/null
              echo "OK: $version $(basename $fixture)"
            done
          done
```

### Forward compatibility

For forward compat (new build → old version), CI downloads the
previous release binary, encrypts a test payload with the current
build, then decrypts it with the old binary:

```yaml
  forward-compat:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - run: cargo build --release
      # Download previous release
      - run: |
          gh release download v0.5.13 -p 'enprot-*-linux-musl' -O enprot-old
          chmod +x enprot-old
      # Encrypt with current, decrypt with old
      - run: |
          echo "test" | ./target/release/enprot encrypt -w T -k T=pw > test.ept
          ./enprot-old decrypt -w T -k T=pw test.ept
```

## Implementation plan

1. Create `tests/cross-version/` with fixtures from every released
   version (0.4.0, 0.5.0, 0.5.13).
2. Add `meta.toml` per fixture.
3. Add `cross-version.yml` CI workflow.
4. On each release: generate new fixtures and commit them.
5. Document the compatibility matrix in `docs/compatibility.md`.

## Test plan

- [ ] Every historical fixture decrypts with the current build.
- [ ] Current-build output decrypts with the previous release.
- [ ] Compatibility matrix documents known incompatibilities.
- [ ] CI fails if backwards compatibility is broken.

## Out of scope

- Forward compatibility beyond N-1 (0.5.x can't predict 0.6.x changes).
- Testing bindings (Python/Node/Go/Ruby) across versions.
- Testing against unreleased / beta builds.
