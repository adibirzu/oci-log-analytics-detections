# Plan 06-04 Summary — Extract `project` / `fields` operator

**Status:** Complete
**Date:** 2026-05-16

- `scripts/kql/operators/project_op.py` — `convert_project(stage, ctx) -> StageResult` wraps legacy `_convert_fields_clause`. Registered three times: `project`, `project-reorder`, `fields` (all point to the same callable).
- `_legacy.py` no longer registers `project` or `fields`.
- Operator tests: `test_registry_binds_project_and_fields_to_same_function` + `test_project_basic_tier1`.
- Gates: full regression green; promoted bodies byte-identical.
