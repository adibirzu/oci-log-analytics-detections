# Plan 06-03 Summary — Extract `summarize` operator

**Status:** Complete
**Date:** 2026-05-16

- `scripts/kql/operators/summarize_op.py` — `convert_summarize(stage, ctx) -> StageResult` wraps legacy `_convert_summarize`. Propagates `aggregate_aliases` as `StageResult.new_aliases`.
- `_legacy.py` no longer registers `summarize`.
- Operator tests: registry binding + `test_summarize_count_by_tier1`.
- Gates: full regression green; promoted bodies byte-identical.
