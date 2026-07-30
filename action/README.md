# enprot-action

Composite GitHub Action that installs `enprot` from GitHub Releases and
runs it against files in your workflow.

[enprot]: https://github.com/engyon/enprot

## Why

Encrypt, decrypt, or sanitize secrets inside source files in CI —
without a separate "decrypt then re-encrypt" pipeline. enprot writes
its state back into the file's own comments, so CI workflows stay
deterministic and the encrypted artifact can be committed as-is.

Typical uses:

- **Encrypt-on-commit**: a workflow that encrypts `ENCRYPTED` segments
  before publishing the artifact to a release branch.
- **Decrypt-on-test**: a workflow that decrypts `ENCRYPTED` test
  fixtures using secrets from the GitHub Actions secret store, runs the
  tests, and never commits the plaintext back.
- **Store-to-CAS**: a workflow that strips secrets out of a public
  release artifact, replacing them with CAS pointers the build system
  can resolve from a private store.

## Usage

```yaml
- uses: engyon/enprot@v0.5
  with:
    operation: encrypt
    files: |
      config/secrets.toml
      tests/fixtures/creds.yaml
    words: |
      SECRET=${{ secrets.ENPROT_SECRET_WORD }}
      API=${{ secrets.ENPROT_API_WORD }}
    cipher: aes-256-siv
    casdir: .cas
```

## Inputs

| Name          | Required | Default   | Description |
|---|---|---|---|
| `version`     | no       | `latest`  | enprot release tag (e.g. `0.5.11`) |
| `operation`   | yes      | —         | Subcommand: `encrypt` / `decrypt` / `store` / `fetch` / `encrypt-store` / `passthrough` / `verify` |
| `files`       | yes      | —         | Space- or newline-separated file globs |
| `words`       | no       | —         | Comma-separated `WORD=password` pairs. Use `${{ secrets.* }}` |
| `cipher`      | no       | enprot default | `aes-256-siv`, `aes-256-gcm`, `aes-256-gcm-siv`, `-det` variants |
| `casdir`      | no       | `.cas`    | CAS directory for `store` / `fetch` / `encrypt-store` |
| `policy`      | no       | default  | `default` or `nist` (forces FIPS mode) |
| `extra-args`  | no       | —         | Additional raw CLI args appended to the invocation |

## Caching

The action downloads the binary on every run (~5 MB). For faster
workflows, cache `$HOME/.enprot-bin` with `actions/cache` keyed on the
version:

```yaml
- name: Cache enprot
  uses: actions/cache@v4
  with:
    path: ~/.enprot-bin
    key: enprot-${{ inputs.version }}-${{ runner.os }}-${{ runner.arch }}
```

## License

BSD-2-Clause.
