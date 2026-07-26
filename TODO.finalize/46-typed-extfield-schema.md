# 46 — Typed ExtField schema

**Priority**: P3
**Status**: specified

Replace string-matching extfield parsing with a typed enum.
Centralizes schema changes in one place instead of four sites
(parser, writer, transform, verify-chain).
