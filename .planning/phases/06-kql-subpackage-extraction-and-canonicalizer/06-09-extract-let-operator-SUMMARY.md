# Plan 06-09 Summary — Extract `let` operator

**Status:** Complete
**Date:** 2026-05-16

- `scripts/kql/operators/let_op.py` — `convert_let(stage, ctx)` parses the right-hand side and delegates to legacy `_normalize_simple_let_expression`. Tier-1 on a scalar binding; Tier-3 (`let_unsupported_shape`) on tabular or function-shaped lets.
- Substitution semantics intentionally still flow through legacy `_preprocess_simple_lets` at the top of `convert_kql_to_logan`. Phase 7+ refactors substitution into `ConversionContext`; in PR-1 the wrapper documents the shim role explicitly.
- `_legacy.py` no longer registers `let`.
- Operator tests: `test_let_scalar_tier1` + `test_let_tabular_tier3`.
- Gates: full regression green; promoted bodies byte-identical.

## Deviation

- Wrapper initially passed the whole `let <name> = <expr>` form to `_normalize_simple_let_expression`, which expects only the expression portion. Fixed inline by splitting on the first `=` and trimming the optional trailing semicolon.
