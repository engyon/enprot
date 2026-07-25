# 06 — Examples directory

**Priority**: P2
**Status**: specified

## Problem

No runnable examples. Users have to read integration tests to understand
the API. parsanol-rs has 15+ examples in `examples/`.

## Solution

### `examples/` at workspace root

```
examples/
├── basic_encrypt_decrypt.rs    # simplest round-trip
├── audit_log.rs                # signed audit log via library API
├── chain_anchor.rs             # produce + verify chain anchors
├── merkle_proof.rs             # Merkle tree proof generation + verification
├── capability_check.rs         # inspect capability tiers
├── multi_word_encrypt.rs      # encrypt multiple WORD segments
├── store_fetch.rs              # CAS store/fetch cycle
└── snapshot_pin.rs             # external verifiability workflow
```

Each example is a standalone `cargo run --example <name>` binary.

### Pattern

```rust
// examples/basic_encrypt_decrypt.rs
fn main() -> enprot_core::Result<()> {
    let mut paops = enprot_core::etree::ParseOps::new(
        Box::new(enprot_core::crypto::CryptoPolicyDefault {})
    )?;
    // ... setup, parse, transform, write
    println!("Done!");
    Ok(())
}
```

## Acceptance criteria

- [ ] 8+ examples covering the main use cases
- [ ] Each example compiles with `cargo build --examples`
- [ ] README links to examples
- [ ] docs.rs shows examples inline
