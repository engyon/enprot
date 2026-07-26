# 45 — TransformContext trait for testability

**Priority**: P3
**Status**: done

Extract the transform's ParseOps dependency into a trait so
transforms can be tested in isolation without the full CLI state.
OCP-friendly; decouples parsing from CLI.
