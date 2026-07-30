#!/usr/bin/env python3
"""import-sops — convert a SOPS-encrypted file into an EPT file.

Each encrypted scalar value in a SOPS file becomes a BEGIN WORD block
in the output. The WORD is `sops:<dotted-key-path>` so the original
location is recoverable. The encrypted bytes (the SOPS ciphertext)
are preserved verbatim — import does NOT re-encrypt. Once imported,
run `enprot encrypt -w sops:database.password=PASSWORD` (or
`enprot store`) to convert the SOPS ciphertext to enprot-native
crypto.

Why import instead of just decrypting SOPS and re-encrypting?

- Keep both versions in one file: SOPS ciphertext for backward
  compat with SOPS tooling, enprot-managed WORD blocks for new
  workflow. Easy rollback.
- Convert gradually: re-encrypt WORDs one at a time without losing
  the SOPS audit trail.
- No key custody required to import: the importer doesn't need
  access to SOPS keys, it just relocates the bytes.

USAGE
    python3 tools/import-sops.py secrets.sops.yaml -o secrets.ept
    python3 tools/import-sops.py secrets.sops.json  -o secrets.ept
    python3 tools/import-sops.py secrets.sops.yaml  # prints to stdout

Requires PyYAML for YAML input (or use .json input to skip it).
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Iterator

# Heuristic for "this scalar is encrypted by SOPS":
#   ENC[<algo>,data:<base64>,iv:<base64>,tag:<base64>,...:type:<kind>]
# Multiple comma-separated key:value pairs, algo first. Match leniently
# rather than enumerating every cipher SOPS has ever supported.
_SOPS_ENC_RE = re.compile(r"^ENC\[[A-Z0-9_]+,.*\]$")

# Extract the data: portion so we can chunk it into DATA lines later.
_SOPS_DATA_RE = re.compile(r"\bdata:([0-9A-Za-z+/=]+)")

# The SOPS metadata block lives under this top-level key. We must
# skip it during traversal so we don't emit WORD blocks for it.
_SOPS_META_KEY = "sops"


def _walk(node: Any, path: tuple[str, ...]) -> Iterator[tuple[tuple[str, ...], Any]]:
    """Yield (path, scalar) for every leaf scalar in `node`."""
    if isinstance(node, dict):
        for k, v in node.items():
            if path == () and k == _SOPS_META_KEY:
                continue
            yield from _walk(v, path + (str(k),))
    elif isinstance(node, list):
        for i, v in enumerate(node):
            yield from _walk(v, path + (str(i),))
    else:
        yield path, node


def _is_encrypted(value: Any) -> bool:
    return isinstance(value, str) and bool(_SOPS_ENC_RE.match(value))


def _word_for(path: tuple[str, ...]) -> str:
    return "sops:" + ".".join(path)


def _format_data_line(value: str, indent: str) -> str:
    """Wrap the SOPS `data:` payload to 48-char DATA chunks (enprot convention)."""
    m = _SOPS_DATA_RE.search(value)
    raw = m.group(1) if m else value
    lines = []
    for i in range(0, len(raw), 48):
        lines.append(f"{indent}# <( DATA {raw[i:i + 48]} )>")
    return "\n".join(lines)


def import_sops(payload: str, ext: str) -> tuple[str, list[str]]:
    """Parse SOPS payload and emit EPT text. Returns (ept_text, warnings)."""
    if ext in {".yaml", ".yml"}:
        try:
            import yaml  # type: ignore[import-not-found]
        except ImportError as e:
            raise SystemExit(
                "YAML input requires PyYAML: `pip install pyyaml`, or pass a .json file."
            ) from e
        data = yaml.safe_load(payload)
    elif ext == ".json":
        data = json.loads(payload)
    else:
        raise SystemExit(f"unsupported input extension: {ext} (want .yaml or .json)")

    if not isinstance(data, dict):
        raise SystemExit(
            f"SOPS root must be a mapping, got {type(data).__name__}"
        )

    warnings: list[str] = []
    out: list[str] = ["# Imported from SOPS. Each block was an encrypted scalar.",
                      "# Run `enprot encrypt -w <WORD>=<PASSWORD>` to re-encrypt with enprot-native crypto.",
                      ""]

    n_encrypted = 0
    n_plain = 0
    for path, value in _walk(data, ()):
        if _is_encrypted(value):
            n_encrypted += 1
            word = _word_for(path)
            out.append(f"# {'.'.join(path)}")
            out.append(f"# <( ENCRYPTED {word} )>")
            out.append(_format_data_line(value, "    "))
            out.append(f"# <( END {word} )>")
            out.append("")
        else:
            n_plain += 1
            if value not in (None, "", [], {}):
                warnings.append(
                    f"{'.'.join(path) or '<root>'}: scalar is not SOPS-encrypted; emitting as comment"
                )
                out.append(f"# {'.'.join(path)} = {value!r}  (plaintext in source, kept for reference)")
                out.append("")

    if n_encrypted == 0:
        warnings.append("no ENC[...] values found in input — was this file actually SOPS-encrypted?")

    header = (f"# {n_encrypted} encrypted scalar(s), {n_plain} plaintext scalar(s) "
              f"skipped/annotated.\n")
    return header + "\n".join(out).rstrip() + "\n", warnings


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description=__doc__.splitlines()[0],
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="See docs/cookbooks/quickstart.md § 'Migrating from SOPS' for end-to-end usage.",
    )
    p.add_argument("input", type=Path, help="SOPS file (.yaml or .json)")
    p.add_argument("-o", "--out", type=Path, default=None,
                   help="Output path (default: stdout)")
    args = p.parse_args(argv)

    if not args.input.is_file():
        p.error(f"input not found: {args.input}")

    payload = args.input.read_text(encoding="utf-8")
    try:
        ept, warnings = import_sops(payload, args.input.suffix.lower())
    except SystemExit as e:
        print(str(e), file=sys.stderr)
        return 2

    for w in warnings:
        print(f"warning: {w}", file=sys.stderr)

    if args.out:
        args.out.write_text(ept, encoding="utf-8")
        print(f"wrote {args.out} ({len(ept)} bytes)", file=sys.stderr)
    else:
        sys.stdout.write(ept)
    return 0


if __name__ == "__main__":
    sys.exit(main())
