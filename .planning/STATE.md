---
gsd_state_version: 1.0
milestone: v2.0
milestone_name: Sentinel KQL Parity to Logan QL
status: Complete
stopped_at: Production validation pass completed against OCI profile cap
last_updated: "2026-05-16T17:23:47.000Z"
last_activity: 2026-05-16 — cap live validation green: 23/23 dashboards present, 351/351 widgets HIT, Sentinel dashboard 8/8 HIT, Sentinel synthetic Logan QL candidates 20/20 HIT
progress:
  total_phases: 6
  completed_phases: 1
  total_plans: 10
  completed_plans: 10
---

# Project State

## Project Reference

See: .planning/PROJECT.md (updated 2026-05-15)

**Core value:** Every committed detection, query, dashboard, parser mapping, and generated artifact must remain deployable and verifiable against OCI Log Analytics without leaking tenant-specific data.
**Current focus:** v2.0 — Sentinel KQL Parity to Logan QL; Phase 6 complete, production validation green in `cap`, Phase 7 (Mapping Config Sharding and Collision Lint) next.

## Current Position

Phase: 6 (kql-subpackage-extraction-and-canonicalizer) — Complete
Plan: all 10 plans executed in sequence (06-01 Wave 1, 06-02..06-09 Wave 2 batched, 06-10 Wave 3).
Status: Complete with one documented deferral (Plan 06-10 Task 1 — pipeline.convert registry-dispatch rewire — moved to Phase 7).
Last activity: 2026-05-16 — Production validation pass against OCI profile `cap`: log sources/parsers refreshed, Sentinel synthetic batches uploaded, Sentinel dashboard deployed, 20/20 Sentinel-derived Logan QL candidates returned rows, and all 351 deployed dashboard widgets returned HIT.

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

### Pending Todos

- Plan Phase 7 via `$gsd-plan-phase 7` for mapping config sharding and collision lint.
- Optional: promote only the additional Sentinel candidates that have both live parser validation and non-empty synthetic-hit evidence; 12 extra candidates were live-hit tested but not promoted in the 2026-05-16 pass.
- If running `python3 scripts/release_checklist.py --include-live`, expect it to rewrite generated artifacts. Use a clean or intentionally staged worktree first.

### Blockers/Concerns

- Worktree has many pre-existing modified/deleted/untracked files. Future fixes must isolate changed files and avoid reverting user work.
- Live OCI validation requires explicit profile/environment access and should not be assumed for local-only tasks. The 2026-05-16 production validation used `OCI_PROFILE=cap`.
- `python3 scripts/convert_sigma.py --validate` exits 0 but still reports 20 existing warnings for known query syntax patterns; treat these as future validation-hardening work.
- Phase 7 strict YAML loader rollout will likely surface silent overrides on the first run — treat as its own task with known-noisy outcome.
- CI secrets handling for fork PRs (Phase 11) needs a short security-review spike before the `live` job is wired.
- `docs/health/*.json` evidence is ignored by git; live evidence files exist locally for the 2026-05-16 pass but require explicit archival if they must be shared.

## Deferred Items

| Category | Item | Status | Deferred At |
|----------|------|--------|-------------|
| Automation | CI release gates for all local checks | Superseded by CI-01 (Phase 11) | Initialization |
| Coverage | Sentinel live-failure backlog reduction | Active in Phase 9 (operator + mapping bulk) | Initialization |
| Coverage | KQL ML operators (`series_*`, `autocluster`) | Out of scope v2.0 | 2026-05-15 |
| Coverage | `geo_*`, dynamic-bag expansion, cross-table `join` | Out of scope v2.0 | 2026-05-15 |
| Automation | OCI Lookups-backed watchlist replacement | Post-v2.0 epic | 2026-05-15 |

## Session Continuity

Last session: 2026-05-15T10:34:04.973Z
Stopped at: cap production validation complete
Resume file: docs/health/all-dashboard-verify-cap-20260516.json (ignored local evidence)
