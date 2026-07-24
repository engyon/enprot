# `enprot resolve` — interactive conflict resolver

## Why

After `merge-driver` leaves conflict markers, the user needs a way to
walk them, understand the capability disagreement, and pick a
resolution. Plain text editing works but loses the capability framing
— `resolve` surfaces it.

## Scope

1. New subcommand `resolve`:
   - `enprot resolve [--ours | --theirs | --both | --interactive] FILE`
   - Default `--interactive` opens a TUI walk-through
   - `--ours` / `--theirs` / `--both` apply blanket resolution
2. Conflict walk:
   - Find every `CONFLICT <WORD>` block
   - For each: show both sides, the required capability for each, the
     key fingerprint of the signer (if signed)
   - Prompt: `[k]eep ours / [t]heirs / [b]oth / [r]e-encrypt under
     unified key / [s]kip`
3. Re-encrypt under unified key: caller supplies `--unify WORD=pwd`,
     both sides get re-encrypted under the new password and the
     conflict collapses to a single block
4. Capability set invariant check: after resolution, the file's
   capability set is reported; user confirms it's the intended set
5. Tests: each resolution mode applied to a fixture file

## Out of scope

- GUI resolver (caller can build on the JSON output of `list --conflicts`)
- Auto-detection of "same plaintext under different passwords" —
  decrypt-and-compare would require holding both passwords; user must
  opt in via `--unify`

## Acceptance criteria

- All four resolution modes produce valid EPT (re-parseable)
- `--interactive` is usable from a terminal (TTY check)
- Conflict markers are always removed or replaced by resolution
- README has a conflict-resolution example
