# Phase 8: Backlog Prioritizer and Cohort Overlay - Context

**Gathered:** 2026-05-17
**Status:** Ready for planning
**Mode:** Auto-generated (infrastructure-only autonomous discuss)

<domain>
## Phase Boundary

This phase adds a deterministic Sentinel backlog prioritizer that ranks non-promoted candidates into actionable cohorts for Phase 9 and Phase 10. It does not promote new Sentinel detections, change live validation rules, or add operator translators.

</domain>

<decisions>
## Implementation Decisions

### the agent's Discretion
- Use existing `queries/sentinel_candidates.json`, `queries/sentinel_conversion_report.json`, converter classification helpers, and mapping metadata.
- Treat `scripts/sync_sentinel_kql.py --no-fetch` as the default explicit sync entry condition so local runs do not require network unless an operator requests refresh.
- Keep ranking deterministic and explainable; every ranked item must expose a primary blocker and an unblock-chain count.
- Do not mutate promoted Sentinel JSON.

</decisions>

<code_context>
## Existing Code Insights

- `scripts/sentinel_conversion_workflow.py` already classifies attempted non-promoted candidates into field/table/KQL/live buckets, but it only covers the 25 attempted candidates.
- `queries/sentinel_candidates.json` contains the full 4,452-candidate corpus and source metadata.
- `queries/sentinel_conversion_report.json` contains the current 8 promoted / 17 non-promoted attempted report with tier data.
- `scripts/release_checklist.py` owns local release-gate output and can print a non-blocking advisory after gates finish.

</code_context>

<specifics>
## Specific Ideas

- Generate `queries/sentinel_backlog_priority.json` from the full candidate corpus, excluding already promoted IDs.
- Build blocker reasons from unsupported operators/functions, unsupported tables, missing mapped fields, parser-readiness phrases, and known Phase 9 operator/MAP-05 field tokens.
- Use unblock-chain length as the count of ranked candidates sharing the same normalized primary blocker.

</specifics>

<deferred>
## Deferred Ideas

- Actual operator support and bulk field additions belong to Phase 9.
- Drift and synthetic-hit enforcement belong to Phase 10.
- CI reporting belongs to Phase 11.

</deferred>

