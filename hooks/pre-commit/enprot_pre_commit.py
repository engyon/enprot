"""Pre-commit hook: block plaintext secrets inside enprot BEGIN blocks.

Detects committed plaintext that should have been encrypted or
content-addressed first. A file fails this hook when it contains a
``BEGIN WORD`` segment whose body is neither:

- an ``ENCRYPTED`` block (ciphertext),
- a ``STORED`` pointer (CAS hash),
- a ``DATA`` line (base64 blob),

i.e. the body is raw plaintext that anyone reading the file can see.

Designed for the `pre-commit <https://pre-commit.com>`_ framework, but
also works as a plain git hook: drop it in ``.git/hooks/pre-commit`` and
make it executable.

Returns non-zero (blocking the commit) when any staged file carries
plaintext inside a ``BEGIN``/``END`` block. Staged-only filtering is
done by checking ``git diff --cached``; pass ``--all`` to scan the
whole tree instead.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path
from typing import Iterable

# Match a separator-prefixed directive. The default enprot separators
# are ``// <(`` and ``)>``. We allow arbitrary leading whitespace and
# either ``//`` or ``#`` as the host-language comment leader, since
# the user may have reconfigured separators.
#
# Capture group 1 = directive keyword (BEGIN/END/ENCRYPTED/STORED/DATA)
# Capture group 2 = WORD or extra args (e.g. ``key=hash`` for STORED).
_DIRECTIVE_RE = re.compile(
    r"""
    ^ \s*
    (?: // | \# | -- | /* | ; )  # host-language comment leader
    \s*
    <? \( ?                       # optional left separator chars
    \s*
    (BEGIN|END|ENCRYPTED|STORED|DATA)
    \b
    (?: \s+ ([^)>]*) )?           # rest of line, up to right separator
    """,
    re.VERBOSE,
)


def _staged_files() -> list[Path]:
    out = subprocess.run(
        ["git", "diff", "--cached", "--name-only", "--diff-filter=AM"],
        check=True,
        capture_output=True,
        text=True,
    )
    return [Path(p) for p in out.stdout.splitlines() if p]


def _all_files() -> list[Path]:
    out = subprocess.run(
        ["git", "ls-files"],
        check=True,
        capture_output=True,
        text=True,
    )
    return [Path(p) for p in out.stdout.splitlines() if p]


def _has_plaintext_in_begin(path: Path) -> tuple[str, int] | None:
    """Return (word, line_number) of the first offending BEGIN block, else None."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except (OSError, UnicodeDecodeError):
        return None

    in_begin: str | None = None
    body_is_clean: bool = True
    body_start: int = 0
    saw_any_directive: bool = False

    for lineno, line in enumerate(text.splitlines(), start=1):
        m = _DIRECTIVE_RE.match(line)
        if m:
            saw_any_directive = True
            kw = m.group(1)
            rest = (m.group(2) or "").strip()

            if kw == "BEGIN":
                in_begin = rest.split()[0] if rest else "(anon)"
                body_is_clean = False
                body_start = lineno
            elif kw == "ENCRYPTED":
                in_begin = rest.split()[0] if rest else in_begin
                body_is_clean = True
            elif kw == "STORED":
                body_is_clean = True
            elif kw == "DATA":
                body_is_clean = True
            elif kw == "END":
                if in_begin is not None and not body_is_clean:
                    return (in_begin, body_start)
                in_begin = None
                body_is_clean = True
        else:
            if in_begin is not None and line.strip() and not body_is_clean:
                # Plaintext content inside a BEGIN block.
                return (in_begin, body_start)

    if not saw_any_directive:
        return None
    if in_begin is not None and not body_is_clean:
        return (in_begin, body_start)
    return None


def _scan(files: Iterable[Path]) -> list[tuple[Path, str, int]]:
    bad: list[tuple[Path, str, int]] = []
    for f in files:
        if not f.is_file():
            continue
        hit = _has_plaintext_in_begin(f)
        if hit:
            word, lineno = hit
            bad.append((f, word, lineno))
    return bad


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument(
        "files",
        nargs="*",
        help="Files to scan (default: staged files).",
    )
    p.add_argument(
        "--all",
        action="store_true",
        help="Scan the whole tracked tree instead of staged files.",
    )
    args = p.parse_args(argv)

    if args.files:
        files = [Path(f) for f in args.files]
    elif args.all:
        files = _all_files()
    else:
        files = _staged_files()

    bad = _scan(files)
    if not bad:
        return 0

    sys.stderr.write(
        "\n\033[31menprot-pre-commit: plaintext inside BEGIN block detected.\033[0m\n"
        "Run `enprot encrypt -w WORD=PASSWORD <file>` or "
        "`enprot store <file>` before committing.\n\n"
    )
    for path, word, lineno in bad:
        sys.stderr.write(f"  {path}:{lineno}  BEGIN {word}\n")
    sys.stderr.write("\n")
    return 1


if __name__ == "__main__":
    sys.exit(main())
