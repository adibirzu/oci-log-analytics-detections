# Phase 6: KQL Subpackage Extraction and Canonicalizer - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-05-15
**Phase:** 6-kql-subpackage-extraction-and-canonicalizer
**Areas discussed:** Canonicalizer scope, OPERATOR_REGISTRY design, Golden fixture layout, Behavior-preservation strategy

---

## Canonicalizer scope

### Q1 — Normalization floor

| Option | Description | Selected |
|--------|-------------|----------|
| Whitespace + quoting only | Collapse runs of whitespace; normalize stage separator (' \| '); pick one quote style. Lowest risk. | ✓ |
| + literal-side reorder | Swap `<literal> == <field>` → `<field> == <literal>`. | |
| + AND-chain sort | Sort top-level AND clauses; requires filter purity analysis. | |
| + case-fold keywords | Lower-case Logan QL operators/keywords; fields preserved verbatim. | |

**User's choice:** Whitespace + quoting only.
**Notes:** Minimal floor; raises no semantic-claim risk. All other normalizations deferred (see CONTEXT.md `<deferred>`).

### Q2 — Implementation approach

| Option | Description | Selected |
|--------|-------------|----------|
| Mini-tokenizer | Hand-rolled tokenizer in `scripts/kql/canonical.py`, ~150 LoC, correct around escaped quotes. | ✓ |
| Regex with placeholder protection | Extract quoted strings as placeholders, collapse whitespace, restore. ~40 LoC; risk on `''` escape. | |
| Reuse `_strip_string_literals` helper | Wrap the legacy strip helper to produce a position map. Tightest legacy coupling. | |

**User's choice:** Mini-tokenizer.
**Notes:** Correctness on doubled-single-quote escape (`''`) was the deciding factor.

### Q3 — Safety proof

| Option | Description | Selected |
|--------|-------------|----------|
| Idempotence property + 8 promoted snapshots | Hypothesis `canonical(canonical(x)) == canonical(x)` + fixture lock; no live OCI dep. | ✓ |
| Snapshots only | 8 promoted snapshots; no hypothesis fuzzing. | |
| Snapshots + live OCI binding parity | Above plus one-time live OCI run confirming canonicalized form binds. | |

**User's choice:** Idempotence property + 8 promoted snapshots.
**Notes:** Live-OCI dependency stays a Phase 9/10 concern (deferred).

### Q4 — Error behavior

| Option | Description | Selected |
|--------|-------------|----------|
| Raise CanonicalizationError | Custom exception; refactor commits with un-canonicalizable output fail loudly. | ✓ |
| Best-effort passthrough | Return input unchanged on tokenizer failure. | |
| Raise in tests, log+passthrough in production | Mode flag via env var or fixture. | |

**User's choice:** Raise CanonicalizationError.
**Notes:** Single behavior; no mode flag. Exception named exactly `CanonicalizationError`.

---

## OPERATOR_REGISTRY design

### Q1 — Registration mechanism

| Option | Description | Selected |
|--------|-------------|----------|
| Decorator at operator module top | `@register('extend')` populates `OPERATOR_REGISTRY` at import time. Grep-able. | ✓ |
| Explicit dict in `scripts/kql/registry.py` | Central `OPERATOR_REGISTRY = {...}` dict; merge-conflict prone in Phase 9. | |
| Auto-discovery via `__init__.py` | Directory scan; magical for debugging missing operators. | |

**User's choice:** Decorator at operator module top.

### Q2 — Operator function shape

| Option | Description | Selected |
|--------|-------------|----------|
| Pure function `(stage, ctx) -> result` | Stateless; minimal ceremony; hypothesis-friendly. | ✓ |
| Class with precheck/emit/tier methods | Three lifecycle phases; no current operator needs them. | |
| Pure function returning AST node + separate emitter | Cleanest layering; forces Logan-AST design in Phase 6. | |

**User's choice:** Pure function.
**Notes:** Logan-AST emitter pass deferred. KQL-side AST scaffolding only (D-06 detail in CONTEXT.md).

### Q3 — Migration handling

| Option | Description | Selected |
|--------|-------------|----------|
| Legacy adapter in registry | Not-yet-extracted ops get adapter that calls legacy function. | ✓ |
| Fallback to inline if-chain in pipeline | Two code paths during migration; drift risk. | |
| Big-bang extraction in a single PR | One commit extracts everything; un-reviewable. | |

**User's choice:** Legacy adapter in registry.
**Notes:** Adapters live in `scripts/kql/operators/_legacy.py`; deleted by the final extraction PR.

### Q4 — ConversionContext / StageResult shape

| Option | Description | Selected |
|--------|-------------|----------|
| Frozen dataclasses, immutable context | No hidden mutation; trivially testable. | ✓ |
| Mutable context, return only fragment | Operators mutate `ctx.errors`; less ceremony, harder to test. | |
| Match legacy signature exactly | Smallest extraction diff; misses the cleanup opportunity. | |

**User's choice:** Frozen dataclasses, immutable context.

---

## Golden fixture layout

### Q1 — File layout

| Option | Description | Selected |
|--------|-------------|----------|
| Paired files: `kql/<name>.kql` + `expected/<name>.logan` | Diff-friendly; sidecar meta only when needed. | ✓ |
| Single JSON envelope per query | All metadata co-located; less diff-friendly. | |
| Subdir per query: `<name>/{input.kql,expected.logan,meta.json}` | Scales for additional artifacts; deepest tree. | |

**User's choice:** Paired files.

### Q2 — Naming convention

| Option | Description | Selected |
|--------|-------------|----------|
| Promoted slug + behavior tag | Promoted uses `queries/sentinel/*.json` slug; synthetic uses behavior tags. | ✓ |
| Stable GUID per fixture | Rename-proof; unreadable. | |
| Hierarchical by operator family | `kql/extend/iff_basic.kql`; awkward for promoted queries. | |

**User's choice:** Promoted slug + behavior tag.

### Q3 — Regeneration policy

| Option | Description | Selected |
|--------|-------------|----------|
| Regenerable for promoted; hand-edited for synthetic | `regen_promoted.py` script; CI fails on diff. | ✓ |
| Fully regenerable | Eliminates author error; kills Phase 9 TDD path. | |
| Fully hand-edited | Strong contract-first stance; typo risk on 8 long Logan strings. | |

**User's choice:** Regenerable for promoted; hand-edited for synthetic.

### Q4 — Phase 6 fixture scope

| Option | Description | Selected |
|--------|-------------|----------|
| 8 promoted + ~10 synthetic per existing operator family | ~18 total; regression anchor per extracted operator. | ✓ |
| Only the 8 promoted queries | Minimum required by exit conditions. | |
| 8 promoted + operator coverage + TIER-3 skip examples | ~25 total; pre-locks Phase 9 skip-reason contract. | |

**User's choice:** 8 promoted + ~10 synthetic per existing operator family.
**Notes:** TIER-3 skip-reason fixtures deferred to Phase 9.

---

## Behavior-preservation strategy

### Q1 — Refactor sequence

| Option | Description | Selected |
|--------|-------------|----------|
| Snapshot lock first, then iterative extraction | PR-1 scaffolds + snapshots; PR-2..N extract one operator family each. | ✓ |
| Iterative extraction only, no upfront snapshot | Each extraction PR adds its own fixture; weaker overall safety. | |
| Big-bang refactor in one PR | Single PR; ~2000 LoC; un-reviewable. | |

**User's choice:** Snapshot lock first, then iterative extraction.

### Q2 — Line-budget gate

| Option | Description | Selected |
|--------|-------------|----------|
| pytest gate in PR-1 with `xfail(strict=True)` during migration | Surfaces over-budget facade immediately; xfail removed by final PR. | ✓ |
| Final PR adds the gate | No migration friction; longer risk window. | |
| `release_checklist.py` adds line-budget gate | Project-wide policy; outside Phase 6's test surface. | |

**User's choice:** pytest gate in PR-1 with xfail during migration.

### Q3 — Facade contract

| Option | Description | Selected |
|--------|-------------|----------|
| Re-export all current names from facade | `__all__` tracks the surface; callers unchanged. | ✓ |
| Update all caller imports in the same PR | Cleaner long-term; expands PR-1 scope. | |
| Keep private functions in `convert_sentinel_kql.py` | I/O helpers stay; risks the file going just over 800 lines. | |

**User's choice:** Re-export all current names.
**Notes:** 14+ symbols captured in CONTEXT.md D-15.

### Q4 — TIER classifier integration

| Option | Description | Selected |
|--------|-------------|----------|
| Per-operator return value, aggregated per candidate | `StageResult.tier`; report gains `tier_distribution` + per-candidate `tier`. | ✓ |
| Separate classifier pass on the AST | Decoupled from operators; two passes; more code. | |
| Inferred from existing outcome counters | Lowest new code; weakest contract. | |

**User's choice:** Per-operator return value, aggregated per candidate.

---

## Claude's Discretion

Captured explicitly in `CONTEXT.md` `<decisions>` → "Claude's Discretion" subsection. Summary:
- Hypothesis fuzz generator scope: narrow predicate/field-list/stage-separator generators only in Phase 6; no `eval` / `stats` / aggregate generators.
- `Tier` enum lives in `scripts/kql/types.py` as `IntEnum`.
- Legacy adapters consolidated in `scripts/kql/operators/_legacy.py` (deleted by final PR).
- `requirements-dev.txt` is exactly two lines: `pytest>=8.3`, `hypothesis>=6.150`.
- `scripts/kql/ast_nodes.py` is created but holds KQL-side AST only — Logan-side AST deferred.

## Deferred Ideas

- Commutative reorder, AND-chain sort, keyword case-folding in canonicalizer.
- Logan-side AST + separate emitter pass.
- TIER-3 skip-reason synthetic fixtures (Phase 9 alongside the operators).
- Live OCI binding parity check (Phase 9/10).
- `release_checklist.py` line-budget gate (Phase 11).
- `coverage` / `pytest-cov` / `pytest-xdist` (revisit if Phase 9 needs them).
- AST-based code-lines measurement (replace `wc -l` only if false alarms).
