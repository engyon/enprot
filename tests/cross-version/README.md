# Cross-version compatibility fixtures (TODO.complete/60)

Every `v<version>/` directory holds fixtures produced BY that
released enprot binary, with `meta.toml` recording the word,
password, and the SHA3-256 of the original plaintext. CI
(`cross-version.yml`) decrypts every fixture with the current
build; a failure names the exact version and fixture whose
compatibility promise broke.

## Layout

```
v0.5.50/
├── meta.toml                  # word, password, plaintext hash
├── encrypt_default.ept        # default cipher (aes-256-siv), inline
├── encrypt_aes256gcm.ept      # --cipher aes-256-gcm
├── encrypt_aes256gcmsiv_det.ept  # deterministic variant
├── encrypt_compress.ept       # --compress (zlib extfield path)
├── store_basic.ept            # CAS-referenced STORED
└── cas/                       # the blobs store_basic.ept references
```

## Regenerating on each release

```
tests/cross-version/generate.sh <path-to-released-enprot> <version> \
  tests/cross-version/v<version>
git add tests/cross-version/v<version>
```

Commit the new directory with the release PR so the next cycle
covers the just-shipped version.

## History note

Fixtures begin at 0.5.50: earlier tags predate working release
binaries (the cross-compile deploy legs were broken until issue
#368 was fixed), so no authentic old-version output exists to
fixture from. Forward compatibility (current-build output
decrypted by the previous release) is covered separately by the
`forward-compat` CI job and needs no fixtures.
