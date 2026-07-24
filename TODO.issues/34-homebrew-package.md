# 34 — Homebrew package for Enprot

## Problem

`brew install enprot` should work. Today users have to build from source.

## Why this isn't a PR against this repo

Homebrew formulas for projects outside the core `homebrew-core` live in
"tap" repos: `riboseinc/homebrew-enprot`, then users run
`brew install riboseinc/enprot/enprot` (or `brew tap riboseinc/enprot`
then `brew install enprot`).

Submission to `homebrew-core` is also possible but has stricter
notability requirements and may be rejected; the tap is the reliable
path.

## What goes in the tap repo

```ruby
# Formula/enprot.rb
class Enprot < Formula
  desc "Engyon Protected Text (EPT) confidentiality processor"
  homepage "https://github.com/engyon/enprot"
  url "https://github.com/engyon/enprot/archive/refs/tags/0.4.0.tar.gz"
  sha256 "<...>"
  license "BSD-2-Clause"

  depends_on "rust" => :build
  depends_on "botan"

  def install
    system "cargo", "install", *std_cargo_args(path: "src")
  end

  test do
    assert_match "Engyon Protected Text", shell_output("#{bin}/enprot --help")
  end
end
```

The formula uses Homebrew's Botan (3.x) which has the modules enprot
needs (`aes-256-siv`, `aes-256-gcm`); AES-GCM-SIV comes from the
RustCrypto crate (pure Rust, no system dep).

## Prerequisites

- enprot needs a 0.4.0 release tag on GitHub (none exists yet — current
  `Cargo.toml` is at 0.3.1).
- The release workflow in `.github/workflows/deploy.yml` needs to produce
  a source archive the formula can `url`. The tag-triggered flow already
  does this via GitHub Releases.

## Status (July 2026)

Resolved as **deferred-by-doc**. The formula belongs in a tap repo
(`riboseinc/homebrew-enprot`), not here, and depends on a `0.4.0`
release tag that doesn't exist yet. `docs/homebrew.adoc` captures the
recipe and the prerequisites so the tap PR is mechanical when the
release happens.

No code or formula in this repo.
