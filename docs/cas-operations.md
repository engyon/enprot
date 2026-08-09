# CAS Operations

**Version**: 1.0
**Status**: Normative
**Scope**: `enprot cas` subcommands — verify, gc, list

## Overview

The CAS (content-addressed storage) subsystem provides three
diagnostic subcommands for managing blob integrity and disk space.

All commands use the global `-c` / `--casdir` flag to specify the
CAS directory (default: `./cas` if it exists, else `.`).

## `enprot cas verify`

Walks the input file(s), collects every CAS hash reference (STORED,
INCLUDE, MUTED, KEY, CERT), and verifies each resolves to a CAS blob
whose SHA3-256 matches the declared hash.

### Usage

```
enprot cas verify [OPTIONS] [FILES...]
```

### Options

| Flag | Description |
|---|---|
| `-c, --casdir <DIR>` | CAS directory (global, repeatable) |
| `--format <text\|json>` | Output format (default: text) |
| `FILES...` | Input file(s); `-` means stdin |

### Text output

```
OK    <hash> STORED (42 bytes) [file.ept:WORD]
FAIL  <hash> STORED — <reason> [file.ept:WORD]
---
3 OK, 1 FAIL (4 unique hashes checked)
```

Exit code: 0 if all hashes pass, 1 if any fail.

### JSON output

```json
{
  "$schema": "enprot/v1",
  "checked": 4,
  "ok": 3,
  "fail": 1,
  "results": [
    {
      "hash": "<64-hex-chars>",
      "kind": "STORED",
      "label": "WORD",
      "file": "file.ept",
      "status": "ok",
      "bytes": 42
    },
    {
      "hash": "<64-hex-chars>",
      "kind": "INCLUDE",
      "file": "file.ept",
      "status": "fail",
      "reason": "CAS blob not found: <hash>"
    }
  ]
}
```

## `enprot cas gc`

Deletes CAS blobs not referenced by any root file. Uses the global
`--dry-run` flag to preview without deleting.

### Usage

```
enprot cas gc [OPTIONS] [FILES...]
```

### Options

| Flag | Description |
|---|---|
| `-c, --casdir <DIR>` | CAS directory (global) |
| `--dry-run` | List what would be deleted; don't delete (global) |
| `--min-age <SECONDS>` | Preserve blobs younger than this (default: 0) |
| `--format <text\|json>` | Output format (default: text) |
| `FILES...` | Root EPT file(s) whose references determine what's kept |

### Text output

```
DELETED       <hash>
WOULD DEL     <hash>
---
deleted 2, 5 kept (7 total blobs)
```

Exit code: always 0 (orphans are not errors).

### `--min-age` safety

Blobs modified within the last N seconds are preserved even if
orphaned. This prevents deleting blobs being actively written by a
concurrent process. Recommended for CI: `--min-age 300` (5 minutes).

## `enprot cas list`

Enumerates all blob hashes in the CAS store. Uses `CasStore::list()`.

### Usage

```
enprot cas list [OPTIONS]
```

### Text output

One hash per line (sorted), with count on stderr:

```
aaaa1100000000000000000000000000000000000000000000000000000000aa
bbbb2200000000000000000000000000000000000000000000000000000000bb
---
2 blobs
```

### JSON output

```json
{
  "$schema": "enprot/v1",
  "count": 2,
  "blobs": [
    "aaaa1100...",
    "bbbb2200..."
  ]
}
```

## Backend Support

All three commands dispatch through the `CasStore` trait:

| Method | verify | gc | list |
|---|---|---|---|
| `load()` | ✓ | | |
| `list()` | | ✓ | ✓ |
| `delete()` | | ✓ | |

Backends that don't support `list()` or `delete()` (e.g.,
append-only transparency logs) return `Error::CasUnsupported`.

## IMMUTABLE Blocks

IMMUTABLE blocks carry a content hash but the content is inline (not
in CAS). The hash is verified against the inline content by
`enprot verify`, NOT by `enprot cas verify`. The `cas verify`
command only checks CAS-referenced hashes (STORED, INCLUDE, MUTED,
KEY, CERT).
