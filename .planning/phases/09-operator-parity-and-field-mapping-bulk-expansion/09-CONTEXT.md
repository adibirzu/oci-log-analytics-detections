# Phase 9: Operator Parity and Field Mapping Bulk Expansion - Context

**Gathered:** 2026-05-17
**Status:** Ready for planning
**Mode:** Auto-generated (autonomous infrastructure + live-gated promotion boundary)

<domain>
## Phase Boundary

This phase expands deterministic Sentinel KQL to Logan QL parity and MAP-05 field coverage, then uses the existing live OCI promotion gate to move promoted Sentinel content toward the roadmap target. The live-validation gate is not relaxed: new promoted JSON may only be written by the converter after passing live OCI parser validation.

</domain>

<decisions>
## Implementation Decisions

### the agent's Discretion
- Implement local converter and mapping work first, with golden/operator tests.
- Keep lossy constructs explicitly skipped with structured reasons.
- Use `queries/sentinel_backlog_priority.json` to choose Phase 9 work order.
- Treat `OCI_PROFILE=cap` as the live validation profile when the live promotion step is reached, based on prior user direction and Phase 6/7 evidence.
- Do not hand-edit `queries/sentinel/*.json`; only converter promotion may update promoted Sentinel artifacts.

</decisions>

<code_context>
## Existing Code Insights

- Whole-query conversion currently flows through `scripts/kql/_facade_impl.py` via the `scripts/convert_sentinel_kql.py` facade.
- Operator wrapper modules under `scripts/kql/operators/` call `_facade_impl` helpers, so `_facade_impl` changes must be reflected in operator-level tests.
- Phase 8 ranked 4,443 backlog candidates. Dominant blockers are `operator:let`, `operator:extend.tostring`, `operator:extend.iff`, `operator:project`, `operator:top`, `operator:countif`, `operator:column_ifexists`, `operator:bin`, and MAP-05 fields.
- `scripts/sentinel_conversion_workflow.py promote --top all` is the canonical promotion path and writes promoted JSON only after live validation.

</code_context>

<specifics>
## Specific Ideas

- First local tranche: strip KQL `set` directives; expand `extend` scalar functions; add `countif`, `bin(TimeGenerated, span)`, `column_ifexists`, `project-away`, `project`, `top`, and `distinct` coverage.
- MAP-05 tranche: add field mappings only where there is an approved OCI display field or built-in; write parser-readiness docs for fields requiring parser work.
- Live tranche: run local conversion first, then run cap profile promotion with conservative timeouts and review resulting report before committing promoted artifacts.

</specifics>

<deferred>
## Deferred Ideas

- KQL ML operators, geo functions, JSON-bag expansion, cross-table joins, and watchlists remain out of scope and must stay skipped.
- Drift and synthetic-hit enforcement belong to Phase 10.
- CI live cache/lane split belongs to Phase 11.

</deferred>

