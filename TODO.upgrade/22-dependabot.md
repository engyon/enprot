# Dependabot config

## Problem

No automated dependency-update flow. Deps drift, security fixes
languish, the next manual upgrade becomes harder. We just paid for
this directly with the Botan 3 upgrade — eight months of drift
between Botan 2 → 3.

## Approach

Add `.github/dependabot.yml` covering the ecosystems we use:

```yaml
version: 2
updates:
  - package-ecosystem: "cargo"
    directory: "/"
    schedule:
      interval: "weekly"
    open-pull-requests-limit: 5
    labels: ["dependencies"]
    groups:
      botan:
        patterns: ["botan", "botan-sys"]
      rustcrypto:
        patterns: ["aes", "aes-gcm", "aes-gcm-siv", "aead", "cipher"]
      clap:
        patterns: ["clap", "clap_builder", "clap_lex"]
      dev-deps:
        dependency-type: "development"
  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "weekly"
    labels: ["dependencies", "ci"]
```

Grouping keeps the PR count low — one PR per ecosystem family rather
than one per crate. Botan and the RustCrypto crates get their own
groups because they have ABI implications that warrant dedicated
review.

## Files

- `.github/dependabot.yml` (new)

## Verification

Push the file; Dependabot starts opening PRs within a few hours. No
local verification needed.

## Rollback

Delete the file.
