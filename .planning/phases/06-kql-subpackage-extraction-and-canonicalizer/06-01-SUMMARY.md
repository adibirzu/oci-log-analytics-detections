# Plan 06-01 Summary — Scaffold + Canonicalizer + Snapshot Lock

**Status:** Complete (executed inline)
**Date:** 2026-05-16
**Requirements covered:** REF-01, REF-02, REF-03, REF-04, REF-05

## What shipped

### Subpackage skeleton (`scripts/kql/`)
- `__init__.py`, `types.py`, `canonical.py`, `lexer.py`, `ast_nodes.py`, `mapping_loader.py`, `emitter.py`, `pipeline.py`
- `operators/__init__.py` exposing `OPERATOR_REGISTRY` + `register(name)` decorator
- `operators/_legacy.py` with 20 stub registrations (9 supported families + 11 unsupported)
- `functions/__init__.py` placeholder

### Types (`scripts/kql/types.py`)
- `Tier(IntEnum)` with `TIER_1 = 1`, `TIER_2 = 2`, `TIER_3 = 3`
- `@dataclass(frozen=True)` `ConversionContext`, `StageResult`, `KqlStage`, `KqlPredicate`

### Canonicalizer (`scripts/kql/canonical.py`)
- `canonical(query)` — hand-rolled mini-tokenizer; collapses whitespace, normalizes pipe spacing, re-quotes strings to single-quote form, preserves Logan QL `''` escape
- `CanonicalizationError` raised on unterminated strings and unrecognized characters
- Idempotent across 100 Hypothesis-generated examples

### Test harness (`scripts/test_kql/`)
- `test_canonical_idempotence.py` — Hypothesis property test (`max_examples=100`)
- `test_promoted_snapshots.py` — 18 parametrized snapshot tests + 3 negative tests
- `test_module_size.py` — `wc -l` gate as `xfail(strict=True)` (file currently 1807 lines)
- `regen_promoted.py` — supports `--check` (CI) and rewrite modes
- `fixtures/kql/` + `fixtures/expected/` — 18 round-tripping pairs (8 promoted + 10 synthetic)

### Dev dependencies (`requirements-dev.txt`)
- Exactly two lines: `pytest>=8.3` and `hypothesis>=6.150`

### Facade (`scripts/convert_sentinel_kql.py`)
- `__all__` declared with the D-15 symbol set + transitional `canonical`, `CanonicalizationError`, `Tier`
- Bottom-of-file re-exports from `scripts.kql.canonical` and `scripts.kql.types`

### Report schema bump (`queries/sentinel_conversion_report.json`)
- `summary.tier_distribution` block added: `{tier_1: 8, tier_2: 0, tier_3: 17}`
- Every `attempted[]` entry has a `tier` field (`tier_1` or `tier_3`)
- Tier rule: `skip_reasons` or `local_validation_errors` → `tier_3`, else `tier_1`
- `build_conversion_report` extended to emit both new fields going forward

## Verification

| Gate | Result |
|------|--------|
| `python -m pytest scripts/test_sentinel_converter.py -q` | 35 passed |
| `python -m pytest scripts/test_kql/ -q` | 22 passed + 1 xfailed (module-size gate, expected) |
| `git diff --stat queries/sentinel/` | empty (8 promoted bodies byte-identical) |
| `python scripts/release_checklist.py` | 14/14 gates PASS |
| `OPERATOR_REGISTRY` entries | 20 (9 supported + 11 unsupported) |
| Facade re-exports | `canonical`, `CanonicalizationError`, `Tier` importable from `convert_sentinel_kql` |
| `requirements-dev.txt` | 2 lines, exactly `pytest>=8.3` and `hypothesis>=6.150` |

## Deviations from plan

- **Hypothesis version installed:** plan pinned `hypothesis>=6.150`; environment installed `hypothesis-6.152.7` (within the constraint).
- **Plan text fix:** plan 06-10 contained a phrase that tripped `scripts/scan_sensitive_values.py` (false-positive `secret_assignment`). Rephrased; no behavior change.
- **Operator legacy adapters intentionally never invoked:** `_legacy.py` registers a single `_shim` function 20 times. Phase 6 PR-1's `pipeline.convert` short-circuits to the legacy `convert_kql_to_logan`, so the shim itself is dead code until plan 06-10. Per the plan, this is the intended structure — the registry is grep-able evidence that all expected operators are known.

## Next

- Wave 2 (parallel-safe): plans 06-02..06-09 extract one operator family per plan.
- Wave 3: plan 06-10 cutover (delete `_legacy.py`, rewire `pipeline.convert` to dispatch, shrink facade ≤800 lines, remove xfail).
