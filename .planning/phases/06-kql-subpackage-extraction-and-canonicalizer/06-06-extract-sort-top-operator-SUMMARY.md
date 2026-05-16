# Plan 06-06 Summary — Extract `sort` / `order` / `top` operators

**Status:** Complete
**Date:** 2026-05-16

- `scripts/kql/operators/sort_op.py` exposes `convert_sort` (registered as `sort` AND `order`) and `convert_top` (registered as `top`). Both wrap their respective legacy helpers (`_convert_sort`, `_convert_top`).
- `_legacy.py` no longer registers `sort`, `order`, or `top`.
- Operator tests: triple-binding regression-fence + happy-path Tier-1 for both functions.
- Gates: full regression green; promoted bodies byte-identical.
