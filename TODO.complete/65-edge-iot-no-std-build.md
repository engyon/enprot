# 65 — Edge / IoT build (`no_std` + reduced footprint)

**Priority**: P3
**Status**: specified

## Problem

enprot targets desktop + server: Linux, macOS, Windows on x86_64
and aarch64. Edge and IoT devices (microcontrollers, sensors,
embedded Linux with 16 MB RAM) can't run the current binary:

- The `enprot` release binary is ~15 MB stripped.
- Botan alone adds ~20 MB to the build footprint.
- The standard library (`std`) pulls in threading, filesystem,
  networking — unnecessary on bare metal.
- Memory allocation patterns assume a heap with `Vec`/`String`;
  some embedded targets have no allocator.

IoT use cases:
- Encrypt sensor data at the edge before uploading to cloud.
- Verify chain anchors on a gateway device before forwarding.
- Decrypt configuration updates received OTA.

## Goals

- A `no_std` build mode that eliminates the Rust standard library.
- A reduced-feature build that omits: the CLI (`clap`), language
  bindings, LSP server, FFI — keeping only `prot`, `etree`, `cas`,
  `pki`, `cipher`.
- A WASM-compatible build (overlaps with #14).
- Peak memory usage < 64 KB for a typical encrypt/decrypt cycle.
- Binary size < 500 KB stripped.
- Documentation for embedded consumers (which boards, which RTOS).

## Design

### Feature gate

```toml
[features]
default = ["std", "cli"]
std = []
cli = ["std", "clap", "clap_complete", "rpassword"]
no_std = []  # no std, no alloc (or alloc-only)
```

Consumers building for embedded targets:
```toml
[dependencies]
enprot = { version = "0.5", default-features = false, features = ["alloc"] }
```

### What needs to change

| Module | `std` dep | `no_std` replacement |
|---|---|---|
| `std::io::{Read, Write, BufRead}` | File, stdin/stdout | `embedded-io` crate or custom traits |
| `std::fs` | Filesystem ops | `embedded-storage` crate |
| `std::collections::{HashMap, BTreeMap}` | Heap-backed | `heapless` crate (stack-allocated, fixed-capacity) |
| `std::path::PathBuf` | OS paths | `&str` or `heapless::String<N>` |
| `std::time::SystemTime` | Wall clock | `chrono` or custom clock trait |
| `std::process::exit` | Process control | Return error, don't exit |
| `std::thread` | Threading | Remove (single-threaded) |

### Alloc-only mode

If the target has `alloc` (a global allocator) but not full `std`:

- `Vec<u8>`, `String` work (heap-backed).
- `HashMap` works (with a heap allocator).
- File I/O doesn't work — use byte buffers instead.
- The pipeline takes `&[u8]` input and `&mut Vec<u8>` output.

### `no_std` + `no-alloc` mode

For bare-metal (no heap at all):

- Fixed-size buffers: `heapless::Vec<u8, 4096>`.
- No dynamic allocation.
- Max input size is a compile-time constant.
- Tradeoff: simplicity vs. generality. Useful only for the most
  constrained devices.

### Botan on embedded

Botan is a C++ library that requires a full OS. For `no_std`:

- Use RustCrypto crates (`aes-gcm-siv`, `sha3`, `pbkdf2`, `argon2`)
  instead of Botan. They work in `no_std`.
- Replace `rnp-rs` (OpenPGP) with `rsa` or `ed25519-dalek` for
  signing.
- This is a big change — the entire crypto stack swaps.

Alternative: keep Botan but require a Linux-based embedded OS
(Raspberry Pi, OpenWrt, Yocto). This works today without `no_std`.

## Implementation plan

1. Add `no_std` feature gate + `#![cfg_attr(not(feature = "std"), no_std)]`.
2. Replace `std::io::{Read, Write}` with `embedded-io` traits in
   `etree::parse` and `tree_write`.
3. Replace `std::collections::HashMap` with `heapless::FnvIndexMap`
   in `ParseOps.passwords` (alloc-only mode).
4. Add RustCrypto backend behind a `no-botan` feature flag.
5. Add an `examples/embedded/` project targeting a Cortex-M4 (e.g.,
   STM32) or RISC-V.
6. Document footprint measurements (flash, RAM).
7. Add CI job for `cargo build --no-default-features --features alloc`.

## Test plan

- [ ] `cargo build --no-default-features` compiles (no_std + no-alloc).
- [ ] `cargo build --no-default-features --features alloc` compiles.
- [ ] `prot::encrypt` + `decrypt` round-trip works in no_std.
- [ ] Peak RAM on a test payload is < 64 KB.
- [ ] Binary size is < 500 KB stripped.
- [ ] Example embedded project builds for ≥1 real target.

## Out of scope

- A full RTOS integration (FreeRTOS, Zephyr). The embedded example
  demonstrates the API; RTOS integration is consumer-specific.
- Hardware crypto acceleration (STM32 CRYP, ESP32 AES). Use the
  RustCrypto backend; let the consumer provide accelerated impls.
- Wireless/OTA update protocol. Out of scope; enprot encrypts/verifies
  data, doesn't transmit it.
- MCU-specific binary sizes (each chip has different flash sizes).
  The 500 KB target is a guideline, not a hard limit.
