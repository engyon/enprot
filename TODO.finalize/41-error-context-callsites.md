# 41 — Apply Error::with_context to key callsites

**Priority**: P2
**Status**: specified

Error::with_context() exists (PR #158). Apply it to the 5 most
common failure paths: key loading, CAS operations, parse errors,
chain verification, and KEM decrypt.
