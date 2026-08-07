# Migration Guides

When enprot introduces a breaking change, a migration guide is added
to this directory. Each guide answers:

1. **What changed** — the precise difference.
2. **Why** — the motivation (so users understand it isn't arbitrary).
3. **Before / after** — concrete examples.
4. **Detection** — how to find code/config that needs migration.
5. **Migration steps** — what to do.

The `enprot doctor` command (TODO #42, future) will scan your files
and config, then point at the relevant migration guide.

## Index

- [0.3 → 0.4](0.3-to-0.4.md) — flat-CLI → subcommand-style CLI
  (PR #62).
- [0.4 → 0.5](0.4-to-0.5.md) — Botan 2 → Botan 3, clap 2 → clap 4
  (PRs #57, #62), capability policy introduction.

(Older migrations are not documented retroactively.)

## Authoring a new migration guide

When a PR introduces a breaking change, the author:

1. Creates `docs/migrations/<old-version>-to-<new-version>-<short-name>.md`.
2. Fills in the template below.
3. Adds a link to `CHANGELOG.md` under the release that ships the change.
4. Adds a detection rule to `enprot doctor` if the change is detectable
   from file contents or config.

## Template

```markdown
# Migration: <short-name> (<version>)

## What changed

<1-2 sentence summary>

## Why

<Motivation. What problem did the old form have? What benefit does
the new form bring?>

## Before / after

\`\`\`ept
# Before (<old-version>)
<old form>
\`\`\`

\`\`\`ept
# After (<new-version>+)
<new form>
\`\`\`

## Detection

    $ enprot doctor <path>
    WARN  <file>:<line>  <what's wrong>
    HINT  <how to fix>

## Migration steps

1. <step>
2. <step>

## Compatibility

- Files produced by <old-version> still work in <new-version>:
  <yes/no, with caveats>
- The reverse: <yes/no>

## Related

- PR: #<number>
- Issue: #<number>
- Spec: TODO.complete/<number>-<name>.md
```

## Review process

Migration guides are reviewed by ≥1 maintainer as part of the PR
that introduces the breaking change. Reviewers verify:

- The "before / after" examples are correct.
- The detection rule catches the case.
- The migration steps are reproducible by a user who hasn't seen
  the code.
