---
gsd_state_version: 1.0
milestone: v3.0
milestone_name: Logan QL Conversion Workbench
status: planning
last_updated: "2026-05-17T08:44:38.184Z"
last_activity: "2026-05-17 - Milestone v3.0 planned; next step is Phase 12"
progress:
  total_phases: 5
  completed_phases: 0
  total_plans: 0
  completed_plans: 0
  percent: 0
---

# Project State

## Project Reference

See: .planning/PROJECT.md (updated 2026-05-17)

**Core value:** Every committed detection, query, dashboard, parser mapping, and generated artifact must remain deployable and verifiable against OCI Log Analytics without leaking tenant-specific data.
**Current focus:** v3.0 - Logan QL Conversion Workbench; plan a sibling frontend for cross-QL conversion into OCI Log Analytics QL while this repo generates the command catalog, mapping patterns, examples, and schemas that the frontend consumes. v2.0 Phase 9+ work remains open history and must not be treated as completed by this milestone switch.

## Current Position

Phase: 12 (frontend-boundary-and-artifact-api-contract) - Not started
Plan: —
Status: Ready to plan Phase 12
Last activity: 2026-05-17 - v3.0 milestone research, requirements, and roadmap created

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

**Recent Trend:**

- Last 5 plans: 04-03, 04-04, 05-01, 05-02, 05-03
- Trend: complete

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
- 2026-05-17: v3.0 is scoped as a sibling frontend workbench, not UI code inside this repo; this repo produces versioned conversion/reference artifacts.
- 2026-05-17: The v3.0 OCI command menu must be generated from official Oracle Log Analytics docs with provenance instead of being hand-authored in frontend components.

### Pending Todos

- Plan the remaining Phase 9 operator parity and field mapping bulk expansion work via `$gsd-plan-phase 9`; do not treat the 2026-05-17 promotion/test pass as full Phase 9 completion.
- Optional: decide whether Phase 10-style synthetic-hit promotion metadata should be backfilled for the 20 candidates that returned rows in `queries/sentinel_synthetic_live_results.json`; current canonical promotion still uses live parser validation.
- If running `python3 scripts/release_checklist.py --include-live`, expect it to rewrite generated artifacts. Use a clean or intentionally staged worktree first.
- Start v3.0 with `$gsd-plan-phase 12` to define the sibling frontend target, artifact/API schemas, and import contract.
- Before Phase 15 execution, confirm whether the workbench extends `../LoganSecurityDashboardv0` or a new sibling app.

### Blockers/Concerns

- Worktree has many generated Sentinel and inventory changes from the 2026-05-17 promotion/test pass. Future fixes must isolate changed files and avoid reverting user work.
- Live OCI validation requires explicit profile/environment access and should not be assumed for local-only tasks. The 2026-05-17 production validation used `OCI_PROFILE=cap`.
- `python3 scripts/convert_sigma.py --validate` exits 0 but still reports 20 existing warnings for known query syntax patterns; treat these as future validation-hardening work.
- Phase 7 strict YAML loader found no duplicate keys in the generated shard layout; future mapping edits must go through `config/mapping/` and regenerate `config/sentinel_oci_mapping.yaml`.
- CI secrets handling for fork PRs (Phase 11) needs a short security-review spike before the `live` job is wired.
- `docs/health/*.json` evidence is ignored by git; live evidence files exist locally for the 2026-05-16 pass but require explicit archival if they must be shared.
- v3.0 spans at least this repo and one sibling frontend repo. Phase work must avoid duplicating converter generation logic and must keep tenant-specific values out of examples.

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
