# 18 — Language bindings (Python, Ruby, Node, Go)

**Priority**: P2
**Status**: specified

## Problem

enprot's wire format (EPT markup) is language-agnostic. The library
API is Rust-only. Non-Rust consumers (most of the world) have to
shell out to the CLI, which is awkward for embedding.

The RSD spec is being implemented in multiple languages eventually;
enprot should be consumable from those languages today.

## Approach: PyO3 + maturin first

Python is the largest data-science / scripting audience. Build a
Python binding via PyO3 + maturin; the pattern transfers to Ruby
(helix), Node (napi-rs), Go (CGo or cbindgen).

### Module structure

```
enprot/                 # Rust crate (existing)
enprot-python/          # new repo or workspace member
  src/
    lib.rs              # PyO3 wrappers
  Cargo.toml
  pyproject.toml        # maturin build config
```

### Public surface

```python
import enprot

# Parse a file
doc = enprot.parse("file.ept")
print(doc.segments())      # list of WORDs with metadata

# Encrypt a WORD
doc.encrypt("Secret", password="hunter2")
doc.save()

# Verify chain anchors
result = doc.verify_chain(trust_roots=["alice.pub", "bob.pub"])
if not result.ok:
    print(result.errors)

# Manifest building
manifest = enprot.manifest(".", casdir="cas/")
manifest.attest(signer="builder.pem")
```

### Build

```sh
maturin develop --release  # local install
maturin publish            # PyPI
```

PyPI package: `enprot`. Wheels for CPython 3.10+ on Linux/macOS
(x86_64 + aarch64) + Windows.

## What this enables

- Data pipelines that process EPT documents in Python
- Jupyter notebooks that decrypt + analyze
- AWS Lambda / GCP Cloud Functions that verify chain anchors
- Integration with existing Python tooling (SOPS scripts, ansible)

## Ruby binding (Phase 2)

Ribose has Ruby expertise; Confium already has Ruby bindings
(`ruby/` in confium checkout). The pattern is `helix` or `rutie`:

```ruby
require 'enprot'

doc = Enprot.parse("file.ept")
doc.encrypt("Secret", password: "hunter2")
doc.save
```

## Node binding (Phase 3)

`napi-rs` (the same project `ohos-rs` was forked from):

```javascript
const enprot = require('enprot');

const doc = enprot.parse('file.ept');
doc.encrypt('Secret', { password: 'hunter2' });
doc.save();
```

## Go binding (Phase 4)

CGo via cbindgen. Most painful due to CGo FFI overhead. Lower
priority unless enterprise Go shops ask for it.

## Acceptance criteria

- [ ] `enprot-python` package on PyPI
- [ ] Wheels for Linux + macOS + Windows
- [ ] Public API documented
- [ ] Ruby gem `enprot` published
- [ ] Node package `enprot` published
- [ ] Cookbook: Python data pipeline with EPT documents

## What this is NOT

- A reimplementation of EPT in each language. The Rust crate is
  always the backend.

## Cross-references

- [[17-editor-integrations]] — VS Code extension can use Node binding
- Confium `ruby/` — pattern reference for Ruby bindings
