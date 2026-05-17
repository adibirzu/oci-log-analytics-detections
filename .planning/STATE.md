---
gsd_state_version: 1.0
milestone: v2.0
milestone_name: Sentinel KQL Parity to Logan QL
status: In Progress
stopped_at: Phase 8 complete; Phase 9 ready for autonomous planning
last_updated: "2026-05-17T06:36:13.000Z"
last_activity: 2026-05-17 — Phase 8 local release gates green: Sentinel backlog priority generated for 4,443 candidates, top blocker field_mapping:SubjectDomainName, Sentinel strict status ok with promoted_count 8, full pytest 367 passed / 5 skipped / 2 subtests passed
progress:
  total_phases: 6
  completed_phases: 3
  total_plans: 17
  completed_plans: 17
---

# Project State

## Project Reference

See: .planning/PROJECT.md (updated 2026-05-15)

**Core value:** Every committed detection, query, dashboard, parser mapping, and generated artifact must remain deployable and verifiable against OCI Log Analytics without leaking tenant-specific data.
**Current focus:** v2.0 — Sentinel KQL Parity to Logan QL; Phase 8 complete with backlog prioritization, Phase 9 (Operator Parity and Field Mapping Bulk Expansion) next.

## Current Position

Phase: 8 (backlog-prioritizer-and-cohort-overlay) — Complete
Plan: all 3 plans executed inline (08-01 prioritizer generator, 08-02 release advisory/artifact contract, 08-03 docs/release gates).
Status: Complete; Phase 9 is the next incomplete roadmap phase.
Last activity: 2026-05-17 — Local Phase 8 verification passed: `queries/sentinel_backlog_priority.json` stable, release checklist advisory prints `Sentinel backlog: 4443 ranked; top blocker: field_mapping:SubjectDomainName`, release checklist 14/14 PASS.

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

- Plan Phase 9 via `$gsd-plan-phase 9` for operator parity and field mapping bulk expansion.
- Optional: promote only the additional Sentinel candidates that have both live parser validation and non-empty synthetic-hit evidence; 12 extra candidates were live-hit tested but not promoted in the 2026-05-16 pass.
- If running `python3 scripts/release_checklist.py --include-live`, expect it to rewrite generated artifacts. Use a clean or intentionally staged worktree first.

### Blockers/Concerns

- Worktree has many pre-existing modified/deleted/untracked files. Future fixes must isolate changed files and avoid reverting user work.
- Live OCI validation requires explicit profile/environment access and should not be assumed for local-only tasks. The 2026-05-16 production validation used `OCI_PROFILE=cap`.
- `python3 scripts/convert_sigma.py --validate` exits 0 but still reports 20 existing warnings for known query syntax patterns; treat these as future validation-hardening work.
- Phase 7 strict YAML loader found no duplicate keys in the generated shard layout; future mapping edits must go through `config/mapping/` and regenerate `config/sentinel_oci_mapping.yaml`.
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

Last session: 2026-05-17T06:36:13.000Z
Stopped at: Phase 8 complete; Phase 9 ready
Resume file: docs/health/release-checklist-2026-05-17T063613Z.json (ignored local evidence)
