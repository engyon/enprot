# EPT manifest format — `manifest/v1`

`enprot manifest` (TODO.roadmap/51) and `enprot scm` (TODO.roadmap/52)
emit and consume this format. A manifest is a regular EPT file
using the existing `INCLUDE` directive plus two informal comment
conventions that pin a label and metadata to each entry.

## Grammar (informal)

```
manifest      := header? entry*
header        := comment+
entry         := annotation* include
annotation    := "# path: " relpath newline
               | "# dep: " name "=" version tag? newline
include       := "// <( INCLUDE " hash " )>" newline
tag           := " (" source ")"
source        := "deps" | "dev-deps" | "build-deps"
               | "target " cfg-expr | "workspace"
hash          := 64 hex chars (SHA3-256 of entry content)
```

## Annotations

### `# path: <relpath>`

Records the relative path of a source file inside the project. The
path is POSIX-normalised (forward slashes, no `..`). It is relative
to the directory passed to `enprot manifest` — typically the
project root.

The annotation must immediately precede its INCLUDE line. Multiple
path annotations for the same INCLUDE are malformed.

### `# dep: <name>=<version> [(<source>)]`

Records a dependency entry. `name` is the package name; `version`
is the resolved version string (Cargo workspace-inherited deps
emit `=workspace` until the workspace root is also processed).

Optional `(source)` tag identifies which dependency table the entry
came from. Values: `deps`, `dev-deps`, `build-deps`,
`target <cfg>`, `workspace`. The tag is informational — verifiers
treat all sources as equally significant for trust purposes.

## Sort order

Entries are sorted by label, deps before paths when both are
present:

1. `# dep:` entries in lexicographic `(source, name)` order
2. `# path:` entries in lexicographic path order

Identical input trees produce byte-identical manifests. This is
required for diff-friendliness and for content-addressed caching
of the manifest itself.

## INCLUDE semantics

The INCLUDE hash is a CAS blob ID. For `# path:` entries the blob
contains the file's bytes verbatim. For `# dep:` entries the blob
contains the UTF-8 string `name=version` (no trailing newline).

Verifiers resolve INCLUDE hashes via the CAS directory
(`--casdir` or the default `./cas`). A manifest whose INCLUDE
hashes don't resolve is malformed and `enprot verify-chain` will
fail.

## Round-trip example

Input tree:

```
myproj/
├── Cargo.toml
└── src/main.rs
```

`enprot manifest myproj --output manifest.ept -c cas` produces:

```
# provenance manifest for myproj
# path: Cargo.toml
// <( INCLUDE abc123... )>
# path: src/main.rs
// <( INCLUDE def456... )>
```

`enprot verify-chain --trust-root builder.pub manifest.ept` checks
the anchor's signature, recomputes the payload hash, and resolves
each INCLUDE through the CAS — exit non-zero on any failure.

## Forward compatibility

Parsers MUST preserve unknown `# foo:` annotations verbatim.
Verifiers MAY ignore them. A future `manifest/v2` would add new
annotations without breaking `v1` consumers.

## Conflict semantics

A manifest with two INCLUDE lines for the same label (e.g., two
`# path: src/main.rs` entries) is malformed. `enprot verify-chain`
must reject it. The merge driver (TODO.roadmap/43) emits a
`CONFLICT` block instead of duplicating labels.
