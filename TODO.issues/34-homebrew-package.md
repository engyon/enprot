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

## Action items (in this repo)

None. The formula lives in `riboseinc/homebrew-enprot` (to be created).
Once the tap is published:

- Update `README.adoc` with `brew install` instructions.
- Optionally add a Homebrew badge to the README.

## Why this issue stays open

Until the tap exists and a 0.4.0 tag is cut, there's nothing actionable
in this repo. Tracking issue for the external tap PR.

## Deferred

This triage writes the README install section but does NOT create the
formula. The formula is the tap repo's first PR.
