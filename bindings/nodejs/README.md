# @engyon/enprot

Node.js bindings for [`enprot`][enprot] — the Engyon Protected Text
confidentiality processor.

[enprot]: https://github.com/engyon/enprot

Pure-JavaScript wrapper over the C FFI (`libenprot.{so,dylib,dll}`)
using [koffi][koffi]. No native compilation at install time; koffi
ships prebuilt binaries for linux/macos/windows × x64/arm64.

[koffi]: https://github.com/Koromix/koffi

## Install

### 1. Build the shared library

From the enprot repo root:

```sh
cargo build --release           # produces target/release/libenprot.{so,dylib,dll}
```

### 2. Install the package (dev mode)

```sh
cd bindings/nodejs
npm install
```

The bindings find `libenprot` in this order:

1. `process.env.ENPROT_LIB` — absolute path to the shared library.
2. `target/release/` two levels up from this package.
3. `target/debug/` two levels up.
4. `koffi.locate("enprot")` — system library search.

## Quick start

```js
const enprot = require("@engyon/enprot");

console.log("enprot", enprot.version()); // '0.5.11'

enprot.encrypt("config.toml", {
  words: { SECRET: "correct horse battery staple" },
  cipher: "aes-256-siv",
  casdir: ".cas",
});

enprot.store("config.toml", { words: { SECRET: "..." }, casdir: ".cas" });
```

ESM:

```js
import * as enprot from "@engyon/enprot";
enprot.encrypt("config.toml", { words: { SECRET: "pw" }, casdir: ".cas" });
```

TypeScript:

```ts
import enprot, { EnprotError } from "@engyon/enprot";
try {
  enprot.encrypt("config.toml", { words: { SECRET: "pw" } });
} catch (e) {
  if (e instanceof EnprotError) console.error(e.code, e.category, e.message);
}
```

## API

| Function | Description |
|---|---|
| `version()` | Return the enprot crate version string. |
| `process(config)` | Invoke `enprot_process` with a raw JSON config object. |
| `encrypt(file, opts)` | Encrypt `ENCRYPTED` segments in place. |
| `decrypt(file, opts)` | Decrypt `ENCRYPTED` segments in place. |
| `store(file, opts)` | Replace `STORED` segments with CAS pointers. |
| `fetch(file, opts)` | Restore `STORED` segments from CAS. |

### `OpOptions`

| Field | Type | Description |
|---|---|---|
| `words` | `Record<string, string>` | `WORD=password` pairs. |
| `cipher` | `string` | `aes-256-siv` (default), `aes-256-gcm`, `aes-256-gcm-siv`, `-det` variants. |
| `casdir` | `string` | CAS directory for store/fetch. |
| `policy` | `string` | `default` or `nist` (FIPS mode). |

### Errors

All failures throw `enprot.EnprotError` with `.code` (FFI status code)
and `.category` (`"parse"`, `"crypto"`, `"io"`, `"invalid"`).

## License

BSD-2-Clause, same as the enprot Rust crate.
