# 19 — Packaging and distribution

**Priority**: P1
**Status**: partial (crates.io done); other channels tracked here

## Problem

enprot is on crates.io (`cargo install enprot`). That's the only
distribution channel. Users on Homebrew, apt, dnf, Docker, Nix, or
Snap have to build from source. Friction for adoption.

## Channels

### Homebrew tap (macOS)

`docs/homebrew.md` already documents the formula. Need to publish
the tap repo (`riboseinc/homebrew-enprot`) and the formula:

```ruby
class Enprot < Formula
  desc "Engyon Protected Text (EPT) — confidentiality processor"
  homepage "https://github.com/engyon/enprot"
  url "https://github.com/engyon/enprot/archive/refs/tags/v0.4.2.tar.gz"
  sha256 "<replace>"
  license "BSD-2-Clause"
  head "https://github.com/engyon/enprot.git", branch: "main"

  depends_on "rust" => :build
  depends_on "botan"
  depends_on "rnp"

  def install
    system "cargo", "install", *std_cargo_args
  end

  test do
    assert_match "Engyon Protected Text", shell_output("#{bin}/enprot --help")
  end
end
```

CI: add a job that auto-updates the tap on tag push.

### Debian/Ubuntu (apt)

Two paths:
1. **Official Debian package** — long process; takes years
2. **PPA / apt repo** — Ribose-maintained `apt.ribose.com`

For now, ship a `.deb` via `cargo-deb`:

```sh
cargo install cargo-deb
cargo deb
# produces target/debian/enprot_0.4.2_amd64.deb
```

Publish to GitHub Releases. Users install with:

```sh
wget https://github.com/engyon/enprot/releases/download/v0.4.2/enprot_0.4.2_amd64.deb
sudo dpkg -i enprot_0.4.2_amd64.deb
```

### RPM (Fedora/RHEL)

`cargo-rpm` does the equivalent. Less common in target audience;
defer until asked.

### Snap (Linux universal)

`docs/` mentions snap. Verify the existing `.github/workflows/`
snap job is functional.

### Docker image

Official image at `ghcr.io/engyon/enprot:latest`:

```dockerfile
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y \
    botan librnp0 && \
    rm -rf /var/lib/apt/lists/*
COPY enprot /usr/local/bin/
ENTRYPOINT ["enprot"]
```

CI: build image on tag push; publish to GHCR.

### Nix

Confium has `flake.nix` + `shell.nix` + `default.nix`. Mirror the
pattern:

```nix
# flake.nix
{
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  outputs = { self, nixpkgs }: {
    packages.x86_64-linux.enprot =
      nixpkgs.legacyPackages.x86_64-linux.callPackage ./default.nix {};
  };
}
```

Publish to `nixpkgs` upstream once stable.

## CI automation

Single workflow `.github/workflows/release-artifacts.yml` triggered
on tag:

```yaml
on:
  push:
    tags: ['v[0-9]+.[0-9]+.[0-9]+']

jobs:
  homebrew:
    runs-on: macos-latest
    steps:
      - run: brew tap riboseinc/enprot
      - run: brew bump-formula-pr enprot --version=$GITHUB_REF_NAME

  deb:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - run: ./ci/install.sh
      - run: cargo install cargo-deb
      - run: cargo deb
      - uses: softprops/action-gh-release@v2
        with:
          files: target/debian/*.deb

  docker:
    runs-on: ubuntu-latest
    steps:
      - uses: docker/build-push-action@v5
        with:
          push: true
          tags: ghcr.io/engyon/enprot:latest,ghcr.io/engyon/enprot:${{ github.ref_name }}
```

## Acceptance criteria

- [ ] Homebrew tap published (`brew install riboseinc/enprot/enprot`)
- [ ] `.deb` artifact in GitHub Releases
- [ ] Docker image on GHCR
- [ ] Nix flake in repo
- [ ] Snap package (if not already)
- [ ] Auto-update CI for all channels on tag push

## Cross-references

- [[20-documentation-site]] — install instructions per channel
- [[22-security-audit-prep]] — packaging affects audit scope
