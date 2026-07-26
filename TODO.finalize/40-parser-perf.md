# 40 — Parser performance investigation

**Priority**: P2
**Status**: specified

The parser benchmarks show 4k segments ≈ 600ms. Profile to find
the bottleneck: likely the `std::mem::take` pattern in
parse_begin/parse_end or the `split_whitespace` allocations.
Fix should target < 100ms for 4k segments.
