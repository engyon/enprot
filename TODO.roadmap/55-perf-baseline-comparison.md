# 55 — CI: benchmark baseline comparison

**Priority**: P2
**Status**: implemented (no committed baseline file; PR-vs-main
comparison runs in the same workflow).

## Problem

The `bench` CI job (TODO.roadmap/05) compiles the criterion suites
and runs them with `--quick` to catch build breakage. It does NOT
compare against a stored baseline, so a 10× regression in the
parser or crypto path slips through silently.

## Solution

The `bench-compare` job runs on PRs and compares the PR branch
against `origin/main` within the same workflow. The PR head is
benched first with `--save-baseline pr`; the workflow then checks
out `origin/main`, rebuilds, and re-runs the benches with
`--benchmark pr`. Criterion auto-prints the regression percentage
per bench in the workflow log.

No baseline file is committed. The two-checkout approach is more
reliable than a stored baseline (same machine, same day, same
noise floor) at the cost of running each bench twice per PR.

The threshold for failing CI is left to human review for now:
criterion's output surfaces the regression percentage clearly and
developers eyeball it. A scripted fail-on-regression > N% can be
added later if false-positive flakes become a problem.

## Acceptance criteria

- [x] PR builds run bench-compare and surface regression %s in CI logs
- [x] Both PR head and main rebuild and re-run in the same workflow
- [x] Documented in `docs/benches/README.md`

