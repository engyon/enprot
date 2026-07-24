# A11 — README doctest (deferred)

## Problem

`README.adoc` documents CLI commands in `[source,sh]` blocks. None of
those are executed by CI, so they rot silently when the CLI shape
changes. The Botan 3 upgrade broke most of them; the subcommand
refactor (#22) rewrote them; future changes will break them again.

## Approach (deferred)

AsciiDoc doesn't have native doctest infrastructure (unlike rustdoc
` ```rust ` blocks). Two options:

1. **Custom test runner.** A `tests/readme.rs` that reads
   `README.adoc`, extracts the `enprot ...` lines from source blocks,
   and runs each against a tempdir. Stateful sequences (encrypt then
   decrypt) need to be grouped so each block is its own session.

2. **Migrate to Markdown** with `mdbook` or similar that supports
   runnable code blocks. Much bigger scope.

Option 1 is more realistic. The work is:
- A small asciidoc parser (or use `ascii_doc` crate) that finds
  `[source,sh]` blocks.
- A test harness that sets up a tempdir, copies `sample/test.ept`, and
  runs each command.
- Skipping blocks that depend on interactive input (e.g. password
  prompts without `-k`).

## Why deferred

The README has 30+ documented commands, several of which are
stateful. Wiring all of them up is a multi-day project for marginal
value — the existing `tests/cli/*.rs` integration tests already
exercise the same code paths. The README doctest would catch copy-paste
typos in the docs, but real CLI breakage would be caught by the
existing tests.

Revisit if a contributor wants to drive this, or if a doc-generation
pipeline (mdbook migration) lands.
