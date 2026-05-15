# Plan 06-07 Summary — Extract `distinct` operator

**Status:** Complete
**Date:** 2026-05-16

- `scripts/kql/operators/distinct_op.py` — `convert_distinct(stage, ctx)` wraps the legacy `_convert_fields_clause` and emits the Logan QL equivalent `stats count as Count by <fields>` (mirrors the legacy in-line distinct handling in `convert_kql_to_logan`).
- StageResult.new_aliases populates with `Count` so downstream stages know about the synthetic alias.
- `_legacy.py` no longer registers `distinct`.
- Operator tests: `test_distinct_emits_stats_count`.
- Gates: full regression green; promoted bodies byte-identical.
