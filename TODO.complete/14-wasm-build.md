# 14 — WASM build for browser/edge

**Priority**: P2
**Status**: specified

## Problem

enprot runs as a CLI binary or via cdylib for native bindings. For browser / Cloudflare Workers / Vercel edge runtimes, neither works — those environments accept only WASM.

This unlocks:
- Client-side encrypt/decrypt in a web UI (no server round-trip).
- Edge decryption with per-request keys.
- WebAssembly-based CI step (faster cold start than Docker).

## Goals

- `enprot-wasm` crate producing `enprot.wasm`.
- JS bindings via `wasm-bindgen` for browsers and `wasi-sdk` for edge runtimes.
- Botan replaced with a RustCrypto-only crypto stack in the WASM build (Botan C++ doesn't compile to WASM easily).

## Non-goals

- Performance parity with native. 2-3× slower is acceptable.
- Confium integration. WASM build is document-edge only.

## Design

New crate `enprot-wasm/` as a workspace member. Excludes Botan-dependent code paths via feature gates:

```toml
# enprot-wasm/Cargo.toml
[features]
default = ["aes-256-siv", "aes-256-gcm"]
# Cannot support: rnp-rs (OpenPGP), botan (AES-SIV via Botan)
# Alternative: aes-siv crate (RustCrypto) for AES-SIV.
```

JS bindings:

```ts
// bindings/web/src/index.ts
import { encrypt, decrypt } from "enprot-wasm";
await encrypt(fileContent, { words: { "SECRET": "pw" } });
```

## Implementation plan

1. Add `aes-siv` RustCrypto dep as alternative AES-SIV backend.
2. Feature-gate Botan in `src/cipher.rs` behind `botan` feature.
3. Create `enprot-wasm/` workspace member.
4. Add `wasm-bindgen` + `wasm-pack` infrastructure.
5. CI workflow `.github/workflows/wasm.yml` builds and publishes to npm.
6. Cookbook entry: in-browser encryption.

## Test plan

- [ ] `wasm-pack test --headless` passes in Chrome + Firefox.
- [ ] Smoke test in Cloudflare Workers (limit: 1 MB request size).
- [ ] Bundle size < 500 KB gzipped.

## Out of scope

- WASI support (separate runtime target; revisit when WASI stabilizes).
- Hardware acceleration via WASM SIMD (some browsers; opt-in).
