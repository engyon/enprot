# enprot (Ruby gem)

Ruby bindings for [`enprot`][enprot] — the Engyon Protected Text
confidentiality processor.

[enprot]: https://github.com/engyon/enprot

Pure-Ruby wrapper over the C FFI (`libenprot.{so,dylib,dll}`) using
the [ffi][ffi] gem. No native compilation; works on JRuby and CRuby.

[ffi]: https://github.com/ffi/ffi/wiki

## Install

### 1. Build the shared library

From the enprot repo root:

```sh
cargo build --release           # produces target/release/libenprot.{so,dylib,dll}
```

### 2. Install the gem (dev mode)

```sh
cd bindings/ruby
bundle install                  # for the test suite
gem build enprot.gemspec        # produces enprot-0.1.0.gem
gem install enprot-0.1.0.gem
```

The gem finds `libenprot` in this order:

1. `ENV["ENPROT_LIB"]` — absolute path.
2. `<repo>/target/release/` (three levels up from the gem's lib dir).
3. `<repo>/target/debug/`.
4. The system loader (`LD_LIBRARY_PATH`, `DYLD_LIBRARY_PATH`).

## Quick start

```ruby
require "enprot"

puts "enprot #{Enprot.version}"  # → "enprot 0.5.11"

Enprot.encrypt(
  "config.toml",
  words:  { "SECRET" => "correct horse battery staple" },
  cipher: "aes-256-siv",
  casdir: ".cas",
)

Enprot.decrypt("config.toml", words: { "SECRET" => "..." })
Enprot.store("config.toml",   casdir: ".cas")
Enprot.fetch("config.toml",   casdir: ".cas")
```

## API

| Method | Description |
|---|---|
| `Enprot.version` | Return the enprot crate version string. |
| `Enprot.process(config)` | Invoke `enprot_process` with a raw config Hash. |
| `Enprot.encrypt(file, words:, cipher:, casdir:, policy:)` | Encrypt `ENCRYPTED` segments in place. |
| `Enprot.decrypt(file, words:, cipher:, casdir:, policy:)` | Decrypt `ENCRYPTED` segments in place. |
| `Enprot.store(file, words:, casdir:, policy:)` | Replace `STORED` segments with CAS pointers. |
| `Enprot.fetch(file, words:, casdir:, policy:)` | Restore `STORED` segments from CAS. |

All keyword arguments except `file` are optional and default to `nil`
(meaning: use enprot's defaults).

### Errors

All failures raise `Enprot::EnprotError` with `#code` (FFI status code)
and `#category` (`"parse"`, `"crypto"`, `"io"`, `"invalid"`).

## License

BSD-2-Clause, same as the enprot Rust crate.
