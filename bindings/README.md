# Bindings & Integrations

`enprot` ships with a C FFI (`include/enprot.h`) that exposes the core
operations to any language with C-interop. The cdylib is built
automatically by `cargo build` (the `[lib] crate-type` in `Cargo.toml`
includes `cdylib`).

| Language | Package | Status |
|---|---|---|
| **Python** | [`bindings/python/`](python/) (`pyenprot`) | Beta — ctypes wrapper |
| **GitHub Actions** | [`action/`](../action/) | Beta — composite action |
| **Pre-commit hook** | [`hooks/pre-commit/`](../hooks/pre-commit/) | Beta — plaintext-leak detector |
| Node.js (napi-rs) | planned | — |
| Go (cgo) | planned | — |
| Ruby (ffi gem) | planned | — |

## Build the shared library

All bindings need `libenprot.{so,dylib,dll}`. From the repo root:

```sh
cargo build --release
# produces target/release/{libenprot.so | libenprot.dylib | enprot.dll}
```

The cdylib has the same system dependencies as the CLI binary (Botan 3,
librnp). For self-contained builds that bundle librnp + its C deps,
add `--features vendored-rnp`.

## C FFI surface

Three functions are exported (see [`include/enprot.h`](../include/enprot.h)):

```c
enprot_result_t enprot_process(const char *config_json);
const char     *enprot_version(void);
void            enprot_free_error(char *ptr);
```

`enprot_process` accepts a JSON config string mirroring the CLI:

```json
{
  "operation": "encrypt",
  "file": "/path/to/file.txt",
  "words": {"SECRET": "password"},
  "cipher": "aes-256-siv",
  "casdir": ".cas"
}
```

## Writing a new binding

1. Load `libenprot` via your language's FFI mechanism.
2. Define the `enprot_result_t` struct (`int code; char *error;`).
3. Serialize your call args to a JSON string and pass to
   `enprot_process`.
4. Free `error` with `enprot_free_error` if non-NULL.

The Python bindings (`bindings/python/pyenprot/__init__.py`) are a
~200-line reference implementation.
