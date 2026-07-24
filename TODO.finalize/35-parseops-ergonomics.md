# Refactoring: ParseOps ergonomics

## Why

`ParseOps` is a 9-field mutable struct threaded through every phase.
It mixes:
- Configuration (separators, transforms, max_depth, verbose)
- Runtime state (level, fname)
- Crypto subsystem (CryptoConfig with policy, RNG, caches)
- External services (casdir path)
- Caller-provided secrets (passwords)

That's five different concerns in one struct. Each access path is
long (`paops.crypto.policy`, `paops.separators.left`, etc.) and the
mixing makes it hard to test any single concern in isolation.

The decomposition work (TODO audit A1) extracted three inner structs;
we can go further.

## Scope

1. Extract `paops.runtime: RuntimeState { level, fname }` for the
   per-invocation mutable state
2. Extract `paops.io: IoConfig { casdir, verbose }` for IO and logging
3. Keep `passwords`, `transforms`, `separators`, `max_depth` as
   direct fields (they're "configuration")
4. `CryptoConfig` stays as-is (already decomposed)
5. Update call sites: `paops.runtime.level` instead of `paops.level`,
   `paops.io.casdir` instead of `paops.casdir`, etc.
6. Tests: same coverage; assert field access patterns are cleaner

## Out of scope

- Splitting ParseOps into multiple traits (over-abstraction)
- Builder pattern (current direct construction is fine)
- Removing `paops.casdir` (still needed as a path; just nested)

## Acceptance criteria

- Five concerns cleanly separable in the struct definition
- Field paths read naturally (`paops.runtime.level`)
- All tests still pass
- Documentation in `src/etree/mod.rs` updated
