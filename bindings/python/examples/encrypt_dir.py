"""Example: encrypt every EPT file in a directory with the same WORD.

Run with:

    ENPROT_LIB=target/release/libenprot.dylib \
    DYLD_LIBRARY_PATH=$(brew --prefix)/lib \
    python3 bindings/python/examples/encrypt_dir.py \
        ./secrets/ my_password

This iterates *.ept, *.txt, *.toml, *.yaml under the given directory
and encrypts every `BEGIN WORD` block using the WORD=PASSWORD pair
supplied on the command line.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pyenprot

EXTS = {".ept", ".txt", ".toml", ".yaml", ".yml", ".md", ".rs", ".py", ".go", ".ts"}


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print(f"usage: {argv[0]} <dir> <password>", file=sys.stderr)
        return 2
    directory = Path(argv[1])
    password = argv[2]
    if not directory.is_dir():
        print(f"not a directory: {directory}", file=sys.stderr)
        return 2

    print(f"enprot {pyenprot.version()}")
    casdir = directory / ".cas"
    n = 0
    for path in sorted(directory.rglob("*")):
        if path.suffix.lower() not in EXTS or not path.is_file():
            continue
        try:
            pyenprot.encrypt(path, words={"SECRET": password}, casdir=casdir)
            print(f"  encrypted: {path}")
            n += 1
        except pyenprot.EnprotError as e:
            print(f"  skip {path}: [{e.category}] {e}", file=sys.stderr)
    print(f"\n{n} file(s) processed")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
