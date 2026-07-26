# 39 — Zeroize secrets on drop

**Priority**: P1
**Status**: specified

Add `zeroize` crate. Implement `Drop for ParseOps` that zeros
passwords and recipient PEMs on drop. No type changes needed —
`Zeroize` trait works on `&mut String` in place.
