# 51 — Memory zeroization (zeroize crate)

**Priority**: P1
**Status**: specified

## Problem

Secret material — passwords, PBKDF-derived keys, plaintext bytes,
private key bytes — lives in `String` / `Vec<u8>` / `[u8; N]`. When
these go out of scope, Rust drops them but **does not zero the
memory**. The bytes remain in the freed allocation until the
allocator reuses them. Adversaries with dump access (root, swap
inspection, core dumps) can recover them.

The threat model (TODO #39) documents this as N6 ("out of scope
for current versions"). With this TODO, N6 graduates to in-scope.

## Goals

- Every `String` / `Vec<u8>` / `[u8; N]` that holds secret data is
  zeroized on drop.
- The zeroization is **type-enforced**, not opt-in per call site.
  If a future PR adds a new secret field, the type system reminds
  the author to zeroize.
- Zeroization is verifiable: a test asserts that no plaintext
  bytes remain in memory after a typical encrypt/decrypt cycle.
- No measurable performance impact (zeroize is `memset(0)`, ~ns).

## Design

### Tool: `zeroize` crate

The RustCrypto `zeroize` crate is the de-facto standard. It
provides:

- `Zeroize` trait: a method that overwrites `self` with zeros.
- `ZeroizeOnDrop` derive macro: wraps the type in a `Drop` impl
  that calls `zeroize()`.
- `Zeroizing<T>` wrapper: a generic `Box<T>`-like that zeroizes
  on drop.

### Where to apply

| Location | Type | Change |
|---|---|---|
| `ParseOps.passwords: HashMap<String, String>` | HashMap of secret strings | Wrap value in `Zeroizing<String>`. Key (WORD) is not secret. |
| `pbkdf::derive_key` return | `Vec<u8>` (derived key) | Wrap in `Zeroizing<Vec<u8>>`. |
| `prot::encrypt/decrypt` intermediate | `Vec<u8>` plaintext, derived key | Same. |
| `cipher::Cipher` key field | `Vec<u8>` | Same. |
| `pki::Privkey` loaded bytes | `Vec<u8>` PEM | Same. |
| TODO #50 `Password` newtype | `String` | Derive `ZeroizeOnDrop`. |
| `TextNode::Data(Vec<u8>)` when inside ENCRYPTED block | ciphertext bytes | Tricky — ciphertext is not secret, but plaintext before encryption was. Wrap only the in-flight plaintext. |

### Pattern

Before:

```rust
pub fn derive_key(...) -> Vec<u8> {
    let mut key = vec![0u8; 32];
    // ... fill key ...
    key
}
```

After:

```rust
use zeroize::Zeroizing;

pub fn derive_key(...) -> Zeroizing<Vec<u8>> {
    let mut key = Zeroizing::new(vec![0u8; 32]);
    // ... fill key ...
    key
}
```

Callers treat the return as `&[u8]` via `Deref`; on drop, the
inner `Vec<u8>` is zeroized.

### Type-enforcement

To make this **opt-out, not opt-in**, change the type signatures:

```rust
// Before
pub fn pbkdf::derive_key(...) -> Vec<u8>;
pub fn prot::encrypt(pt: Vec<u8>, ...) -> (Vec<u8>, ...);

// After
pub fn pbkdf::derive_key(...) -> Zeroizing<Vec<u8>>;
pub fn prot::encrypt(pt: Zeroizing<Vec<u8>>, ...) -> (Zeroizing<Vec<u8>>, ...);
```

Now any caller that constructs the input must wrap it; the compiler
enforces zeroization at the call boundary.

### Where zeroization is **not** needed

- Ciphertext (output of encrypt): already scrambled; not a secret.
- Hash digests (CAS keys, payload hashes): content-derived, not
  secret-derived.
- Anchor signatures: public.
- Public keys: public.

### Verifiable test

```rust
#[test]
fn password_zeroized_after_drop() {
    let pw = Zeroizing::new("hunter2".to_string());
    let ptr = pw.as_ptr();
    let len = pw.len();
    drop(pw);
    // Read the freed memory — should be all zeros.
    // (Use std::alloc to grab the same region.)
    unsafe {
        let slice = std::slice::from_raw_parts(ptr, len);
        assert!(slice.iter().all(|&b| b == 0), "memory not zeroized");
    }
}
```

This is fragile (the allocator might not return the same region).
A more robust check: use `zeroize`'s own test utilities, or rely on
valgrind/ASan in CI.

## Implementation plan

1. Add `zeroize = "1.8"` to `[dependencies]`.
2. Add a `Zeroizing<String>` wrapper for `ParseOps.passwords` values.
3. Convert `pbkdf::derive_key` → `Zeroizing<Vec<u8>>`.
4. Convert `prot::encrypt`/`decrypt` intermediate buffers.
5. Convert `cipher::Cipher` key field.
6. Convert `pki::Privkey` PEM bytes.
7. Add unit tests asserting zeroization on drop.
8. Document the zeroization invariant in CONTRIBUTING.md.

## Test plan

- [ ] `cargo build` clean after each step.
- [ ] Unit tests assert zeroization works.
- [ ] No measurable performance regression (`cargo bench`).
- [ ] Memory inspection (valgrind/ASan) shows no plaintext bytes
  after process exit.

## Out of scope

- `mlock()` to prevent swap (TODO #39 Q1 — separate decision).
- Zeroization of compiler-internal copies (e.g., stack frames the
  compiler didn't elide). Hard to verify; out of scope.
- Constant-time zeroization (zeroization is not observable across
  process boundaries; timing isn't a leak vector here).
