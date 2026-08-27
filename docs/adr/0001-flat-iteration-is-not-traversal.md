# ADR-0001: Flat iteration over top-level nodes is not traversal

- **Status**: Accepted (2026-08-27, architecture review round 3)
- **Context**: `etree::visitor` (#438) is the single deep traversal over
  `TextTree`. Several modules (`inspect`, `list`) iterate the tree with
  `tree.iter().map(...)`, producing per-node DTOs.

## Decision

Flat per-top-level-node iteration (DTO maps over `tree.iter()`) is a
**different shape** from traversal, and does not go through
`etree::visitor`. The visitor exists for code that must descend into
`BeginEnd`/`Encrypted` children; a flat map that immediately prunes every
child would be abstraction for its own sake.

## Consequence

- New code that <em>descends</em> uses `visitor::visit` / `visit_mut`.
- New code that only maps top-level nodes (block summaries, listings)
  keeps using `tree.iter()` directly.
- Future architecture reviews do not flag flat iterations as "missed
  walker migrations" — this ADR is the reason.
