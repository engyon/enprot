# 71 — Internationalization (i18n)

**Priority**: P3 | **Status**: specified

## Problem
Error messages, CLI help text, and documentation are English-only.
For global adoption in Japanese, Chinese, Korean, and European markets,
localized output helps non-English-speaking users.

## Design
- Use `gettext`-style message catalogs (`.po` / `.mo` files) for
  runtime messages.
- `--lang <CODE>` flag (or `$LANG` env var) selects the locale.
- Initial locales: `en` (default), `ja`, `zh-CN`, `de`, `fr`.
- CLI help text localization via clap's `about` / `long_about`
  with locale-aware strings.
- Documentation stays English-only (translation burden too high for
  docs; defer).

## Out of scope
- Right-to-left layout (not needed for current locales).
- Locale-aware date/number formatting (use RFC 3339 timestamps
  everywhere).
- Crowd-sourced translation (organisational, not technical).
