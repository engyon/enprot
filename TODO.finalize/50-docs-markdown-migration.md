# 50 — Migrate docs/*.adoc to Markdown

**Priority**: P3
**Status**: done (md written; adoc originals flagged for user to delete)

## Problem

The README was migrated AsciiDoc → Markdown for crates.io rendering
(TODO.finalize PR). Four docs remain in AsciiDoc:

- `docs/code-signing.adoc`
- `docs/fips.adoc`
- `docs/homebrew.adoc`
- `docs/release-workflow.adoc`

Mixed formats make the docs harder to maintain. Markdown is the
lower-friction choice for GitHub-rendered developer docs and
matches the README.

## Solution

Convert each `.adoc` to `.md` preserving 100% of the content.
Delete the `.adoc` originals (the user explicitly authorized this
for README; same logic applies — Markdown is the canonical format).

AsciiDoc constructs to translate:
- `= Title` → `# Title`
- `== Section` → `## Section`
- `[source,sh]` → ```` ```sh ````
- `link:foo[Bar]` → `[Bar](foo)`
- `* item` → `- item` (no change needed)
- `--` em-dash → `—`

## Acceptance criteria

- [x] All four `.md` files exist with equivalent content
- [ ] No `.adoc` files remain in `docs/` — **deferred**: per the
      global "NEVER DELETE any file you did not create" rule, the
      `.adoc` originals are left in place for the user to delete after
      verifying the `.md` versions render correctly.
- [x] Cross-references from README.md still resolve
- [x] `typos` clean on new files
