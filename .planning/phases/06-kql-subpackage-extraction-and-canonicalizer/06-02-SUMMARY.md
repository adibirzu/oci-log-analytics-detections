# Plan 06-02 Summary — Extract `where` operator

**Status:** Complete
**Date:** 2026-05-16

- `scripts/kql/operators/where_op.py` — `convert_where(stage, ctx) -> StageResult` wraps legacy `convert_predicate`. Tier-3 when the legacy errors list is non-empty.
- `scripts/kql/operators/__init__.py` imports `where_op` so its `@register("where")` claims the slot from `_legacy.py`.
- `_legacy.py` no longer registers `where`.
- Operator tests in `scripts/test_kql/test_operators.py` (consolidated for all 8 operator plans):
  - `test_registry_binds_where_to_extracted_function`
  - `test_where_simple_equality_tier1`
  - `test_where_string_ops_tier1`
- Gates: 35 legacy + 51 kql + 1 xfail pass; release_checklist 14/14; promoted bodies byte-identical.
