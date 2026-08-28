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

- New code that <em>descends</em> uses `visitor::visit` / `visit_mut` /
  `visit_depth` (round 8: depth-tracking renderers).
- New code that only maps top-level nodes (block summaries, listings)
  keeps using `tree.iter()` directly.
- Future architecture reviews do not flag flat iterations as "missed
  walker migrations" — this ADR is the reason.

## Annex (2026-08-28, round 8): reconstruction folds own their descent

`etree::transform` rebuilds a **new** tree per pass — a `BeginEnd`
under `encrypt -w W` becomes a structurally different `Encrypted`
node, with `Result` threading and `runtime.level` depth accounting.
That is a reconstruction fold, not a visit: the visitor's in-place,
error-free interface (`visit_mut`) would contort it, and pure
rebuilding keeps transform's fail-atomicity. `transform`'s recursion
stays hand-rolled **by decision**, and future reviews do not re-flag
it. The same reasoning covers `merge::partition` (regions taken as
opaque payloads — flat by design) and `smudge::extract_first_encrypted`
(early-exit search; `Control::Stop` remains hypothetical while it is
the lone consumer).
