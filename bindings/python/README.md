# pyenprot

Python bindings for [`enprot`][enprot] — the Engyon Protected Text
confidentiality processor.

[enprot]: https://github.com/engyon/enprot

`pyenprot` exposes enprot's four core operations — **encrypt**,
**decrypt**, **store**, **fetch** — as a small Pythonic API built on
top of the C FFI (`libenprot`). The bindings are pure Python (no
PyO3, no extension module); they load the shared library at import
time via `ctypes`.

## Install

### 1. Build the shared library

From the enprot repo root:

```sh
cargo build --release           # produces target/release/libenprot.{so,dylib,dll}
```

### 2. Install the package (dev mode)

```sh
cd bindings/python
pip install -e .
```

`pyenprot` finds `libenprot` in this order:

1. `$ENPROT_LIB` — absolute path to the shared library.
2. `target/release/` two levels up from this package.
3. `ctypes.util.find_library("enprot")` — system library search path.

## Quick start

```python
import pyenprot

print("enprot", pyenprot.version())            # '0.5.11'

pyenprot.encrypt(
    "config.toml",
    words={"SECRET": "correct horse battery staple"},
    cipher="aes-256-siv",
    casdir=".cas",
)

pyenprot.store("config.toml", words={"SECRET": "..."}, casdir=".cas")
```

## API

| Function | Description |
|---|---|
| `version()` | Return the enprot crate version string. |
| `process(config)` | Invoke `enprot_process` with a raw JSON config dict. |
| `encrypt(file, *, words, cipher=None, casdir=None, policy=None)` | Encrypt `ENCRYPTED` segments in place. |
| `decrypt(file, *, words, casdir=None, policy=None)` | Decrypt `ENCRYPTED` segments in place. |
| `store(file, *, words, casdir=None)` | Replace `STORED` segments with CAS pointers. |
| `fetch(file, *, words, casdir=None)` | Restore `STORED` segments from CAS. |

### Errors

All failures raise `pyenprot.EnprotError` with `.code` (FFI status code)
and `.category` (`"parse"`, `"crypto"`, `"io"`, `"invalid"`).

## License

BSD-2-Clause, same as the enprot Rust crate.
