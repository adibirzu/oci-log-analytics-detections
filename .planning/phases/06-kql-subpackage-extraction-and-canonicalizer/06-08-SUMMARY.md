# Plan 06-08 Summary — Extract `union` operator

**Status:** Complete
**Date:** 2026-05-16

- `scripts/kql/operators/union_op.py` — `convert_union(stage, ctx)` always returns Tier-3 with a structured `unsupported KQL stage: union ...` skip reason. This preserves the legacy converter's behavior (no `union` shape is currently supported) while still placing a real registered operator in `OPERATOR_REGISTRY`.
- `_legacy.py` no longer registers `union`.
- Operator tests: `test_union_always_tier3` verifies Tier-3 + non-empty skip_reasons + empty fragments.
- Gates: full regression green; promoted bodies byte-identical.
