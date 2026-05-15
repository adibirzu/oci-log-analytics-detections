# Plan 06-05 Summary — Extract `extend` operator

**Status:** Complete
**Date:** 2026-05-16

- `scripts/kql/operators/extend_op.py` — `convert_extend(stage, ctx) -> StageResult` wraps legacy `_convert_extend`. Critical: `StageResult.new_aliases` captures the column aliases the extend stage introduces (D-08) so downstream stages reference them through a fresh `ConversionContext`.
- `_legacy.py` no longer registers `extend`.
- Operator tests: `test_extend_basic_alias_propagation` asserts `IsAdmin` flows into `new_aliases` on a successful conversion.
- Gates: full regression green; promoted bodies byte-identical.
