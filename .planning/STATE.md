---
gsd_state_version: 1.0
milestone: v3.0
milestone_name: Logan QL Conversion Workbench
status: in_progress
last_updated: "2026-06-11T09:48:00Z"
last_activity: "2026-06-11 - Completed Phase 9, Phase 11, and v3.0 local implementation; Phase 10 remains open only for DRIFT-03 live synthetic-hit evidence on the remaining promoted Sentinel artifacts"
progress:
  total_phases: 16
  completed_phases: 15
  total_plans: 70
  completed_plans: 69
  percent: 94
---

# Project State

## Project Reference

See: .planning/PROJECT.md (updated 2026-05-17)

**Core value:** Every committed detection, query, dashboard, parser mapping, and generated artifact must remain deployable and verifiable against OCI Log Analytics without leaking tenant-specific data.
**Current focus:** Close the final Phase 10 DRIFT-03 live synthetic-hit evidence gap while maintaining the integrated `webapp/` frontend for cross-QL conversion into OCI Log Analytics QL. Phase 9, Phase 11, and v3.0 producer/webapp work are locally complete; live OCI validation remains explicit and profile-driven.

## Current Position

Phase: 10 (drift-detector-and-synthetic-hit-promotion-gate) - In progress
Plan: —
Status: Local release gates pass with `scripts/sentinel_drift_check.py` wired into `scripts/release_checklist.py`. Strict `--require-synthetic-hits` mode is implemented and intentionally not default because current live evidence covers 20 / 60 promoted Sentinel artifacts; `queries/sentinel_drift.json` tracks the remaining 40 and all are now `synthetic_ready` live-validation targets.
Last activity: 2026-06-11 - Added parser schema hashes to promoted Sentinel artifacts, added drift automation and CI workflow, completed EventData parser extraction for ObjectDN/ObjectName/AttributeLDAPDisplayName, refreshed generated artifacts, and passed the full local release checklist.

## Performance Metrics

**Velocity:**

- Total plans completed: 16
- Average duration: n/a
- Total execution time: 0.0 hours

**By Phase:**

| Phase | Plans | Total | Avg/Plan |
|-------|-------|-------|----------|
| 1 | 3 | - | - |
| 2 | 3 | - | - |
| 3 | 3 | - | - |
| 4 | 4 | - | - |
| 5 | 3 | - | - |
| 6 | 10 | - | - |
| 7 | 4 | - | - |
| 8 | 3 | - | - |
| 9 | 11 | - | - |
| 10 | 3/4 | - | - |
| 11 | 6 | - | - |
| 12 | 3 | - | - |
| 13 | 3 | - | - |
| 14 | 4 | - | - |
| 15 | 3 | - | - |
| 16 | 3 | - | - |

**Recent Trend:**

- Last 5 plans: Phase 12 artifact/API contract, Phase 13 reference catalog, Phase 14 mapping patterns, Phase 15 workbench UX, Phase 16 examples/gates
- Trend: local implementation complete except Phase 10 DRIFT-03 live synthetic-hit evidence

## Accumulated Context

### Decisions

Decisions are logged in `.planning/PROJECT.md`.

- 2026-05-14: Use `.planning/` as the GSD project root for this repo.
- 2026-05-14: Keep generated artifact boundaries from `CLAUDE.md` and README as hard project constraints.
- 2026-05-14: Do not auto-commit planning docs while the worktree contains unrelated pre-existing changes.
- 2026-05-15: v2.0 milestone scoped to Sentinel KQL → Logan QL parity; phase numbering continues from v1.0 starting at Phase 6.
- 2026-05-15: Reject third-party KQL parser libraries (kusto-query-language-parser immature; pythonnet+Kusto.Language broken on macOS ARM); extend hand-rolled stage pipeline under new `scripts/kql/` subpackage.
- 2026-05-15: Add test-tier deps only (`pytest >= 8.3`, `hypothesis >= 6.150` in `requirements-dev.txt`); runtime deps in `requirements.txt` stay untouched.
- 2026-05-15: Promotion gate remains live OCI parser validation — v2.0 does not relax it; new gates (synthetic-hit, drift) sit on top.
- 2026-05-16: Sentinel synthetic readiness requires source-backed predicate fields and non-empty live Logan QL results. Do not treat parser-valid but empty results as production-ready.
- 2026-05-17: v3.0 initially scoped as a sibling frontend workbench; superseded on 2026-05-18 by the user decision to move the UI into this long-term repo.
- 2026-05-18: `webapp/` is the maintained Forge frontend source of truth; the old `LoganSecurityDashboardv0` project is historical only.
- 2026-05-17: The v3.0 OCI command menu must be generated from official Oracle Log Analytics docs with provenance instead of being hand-authored in frontend components.
- 2026-06-11: Phase 10's strict synthetic-hit gate must remain opt-in until every promoted Sentinel artifact has non-empty live synthetic-hit evidence; local drift/hash/report checks can run without live OCI access.

### Pending Todos

- Run a live synthetic upload/validation pass for the 40 `synthetic_ready` promoted Sentinel artifacts listed in `queries/sentinel_drift.json`, then rerun `scripts/sentinel_drift_check.py --require-synthetic-hits`.
- After strict synthetic hits are complete, make the strict gate the default local release behavior and mark DRIFT-03 / Phase 10 complete.
- If running `python3 scripts/release_checklist.py --include-live`, expect it to rewrite generated artifacts. Use a clean or intentionally staged worktree first.
- Keep `webapp/` docs, deploy scripts, and security controls aligned with the generated artifact contract.
- Use `docs/OKE_OBSERVABILITY_RUNBOOK.md` when deploying Forge or diagnosing OCI Kubernetes Monitoring telemetry on other OKE clusters; keep the runbook placeholder-safe and free of tenant-specific values.

### Blockers/Concerns

- Live OCI validation requires explicit profile/environment access and should not be assumed for local-only tasks. The 2026-05-17 production validation used `OCI_PROFILE=cap`.
- RESOLVED 2026-06-05: `scripts/convert_sigma.py --validate` now reports **0 warnings** over 678 queries (previously 20). The validator was hardened (escaped-quote parity, negative-paren-depth, unterminated-quote detection) and all local gates are green.
- Phase 7 strict YAML loader found no duplicate keys in the generated shard layout; future mapping edits must go through `config/mapping/` and regenerate `config/sentinel_oci_mapping.yaml`.
- The Phase 11 workflow is wired locally, but the first remote scheduled/manual live run still needs GitHub Actions execution with OCI secrets to populate the live cache.
- `docs/health/*.json` evidence is ignored by git; live evidence files exist locally for the 2026-05-16 pass but require explicit archival if they must be shared.
- v3.0 now lives in this repo. Phase work must avoid duplicating converter generation logic in `webapp/` and must keep tenant-specific values out of examples, docs, and UI output.

## Deferred Items

| Category | Item | Status | Deferred At |
|----------|------|--------|-------------|
| Automation | CI release gates for all local checks | Superseded by CI-01 (Phase 11) | Initialization |
| Coverage | Sentinel live-failure backlog reduction | Active in Phase 9 (operator + mapping bulk) | Initialization |
| Coverage | KQL ML operators (`series_*`, `autocluster`) | Out of scope v2.0 | 2026-05-15 |
| Coverage | `geo_*`, dynamic-bag expansion, cross-table `join` | Out of scope v2.0 | 2026-05-15 |
| Automation | OCI Lookups-backed watchlist replacement | Post-v2.0 epic | 2026-05-15 |

## Session Continuity

Last session: 2026-05-17T08:44:38.184Z
Stopped at: v3.0 milestone initialized and ready for Phase 12 planning
Resume file: .planning/ROADMAP.md (v3.0 Phase 12 entry point)
