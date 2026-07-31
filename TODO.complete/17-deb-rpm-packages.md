# 17 — Debian `.deb` + Fedora `.rpm` packages

**Priority**: P2
**Status**: specified

## Problem

Linux distribution is currently Docker + AUR + Nix. Debian/Ubuntu and Fedora/RHEL users — the majority of Linux servers — have no native package. They have to install via cargo or extract from the release tarball manually.

## Goals

- `.deb` package built in CI from release binaries, published to GitHub Releases.
- `.rpm` package likewise.
- Optional APT and YUM repositories (separate TODO; first cut ships just the package files).

## Design

Use `cargo-deb` for `.deb` and `cargo-generate-rpm` for `.rpm`. Both produce native packages from Cargo metadata + asset list.

```toml
# Cargo.toml additions
[package.metadata.deb]
maintainer = "Engyon <open.source@ribose.com>"
copyright = "2018-2026 Ribose Inc."
license-file = ["LICENSE", "0"]
depends = "libbotan-3-dev, librnp-dev"
section = "utils"
priority = "optional"
extended-description = "".readme = "README.md"
assets = [
    ["target/release/enprot", "usr/bin/", "755"],
    ["target/release/enprot.1", "usr/share/man/man1/", "644"],
    ["target/release/completions/enprot.bash", "usr/share/bash-completion/completions/enprot", "644"],
    ["target/release/completions/_enprot", "usr/share/zsh/vendor-completions/", "644"],
    ["target/release/completions/enprot.fish", "usr/share/fish/vendor_completions.d/", "644"],
]

[package.metadata.generate-rpm]
summary = "Engyon Protected Text confidentiality processor"
license = "BSD-2-Clause"
vendor = "Ribose Inc."
url = "https://github.com/engyon/enprot"
assets = [
    { source = "target/release/enprot", dest = "/usr/bin/enprot", mode = "755" },
    # …
]
```

CI:

```yaml
# .github/workflows/deploy.yml addition
- name: Build .deb (x86_64)
  if: matrix.target == 'x86_64-unknown-linux-musl'
  run: cargo deb --target x86_64-unknown-linux-gnu --no-build

- name: Build .rpm (x86_64)
  if: matrix.target == 'x86_64-unknown-linux-musl'
  run: cargo generate-rpm --target x86_64-unknown-linux-gnu
```

## Implementation plan

1. Add `cargo-deb` + `cargo-generate-rpm` to CI deps.
2. Add `[package.metadata.deb]` + `[package.metadata.generate-rpm]` to `Cargo.toml`.
3. New jobs in `deploy.yml`: `package-deb`, `package-rpm`.
4. Upload artifacts to GitHub Releases alongside existing tarballs.
5. Cookbook entry: `apt install ./enprot_0.5.13_amd64.deb`.

## Test plan

- [ ] `.deb` installs in `ubuntu:22.04` and `debian:12` containers.
- [ ] `.rpm` installs in `fedora:39` and `rockylinux:9` containers.
- [ ] Man page + completions end up in correct locations.

## Out of scope

- APT / YUM repository hosting (needs CloudFront + signing key; separate effort).
- Signed packages (`debsign`, `rpmsign`) — needs a GPG key.
