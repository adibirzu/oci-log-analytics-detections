---
gsd_state_version: 1.0
milestone: v2.0
milestone_name: Sentinel KQL Parity to Logan QL
status: In Progress
stopped_at: Phase 9 production-readiness review pass complete; Phase 9 operator/mapping work remains open
last_updated: "2026-05-17T07:16:27.000Z"
last_activity: 2026-05-17 — Sentinel promotion refresh under `OCI_PROFILE=cap`: 100 candidates attempted, 60 promoted live parser-passed, strict Sentinel status ok, dashboard pre-flight passed with 640 query files, synthetic Sentinel-shaped logs uploaded to CAP and 20/20 ready Logan QL queries returned rows.
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
**Current focus:** v2.0 — Sentinel KQL Parity to Logan QL; Phase 8 complete, Phase 9 partially advanced by a live promotion/test pass (60 parser-passed promoted queries; 20 synthetic-hit queries), with remaining operator parity and bulk mapping work still open.

## Current Position

Phase: 9 (operator-parity-and-field-mapping-bulk-expansion) — In Progress
Plan: production-readiness review and live promotion/testing pass executed inline from the Phase 8 backlog output; full Phase 9 operator/mapping plan remains to be formalized before completing the phase.
Status: Partial progress; promoted Sentinel coverage now meets the Phase 9 minimum count, but remaining operator parity, MAP-05 parser-readiness docs, and regression tests are not complete.
Last activity: 2026-05-17 — `scripts/sentinel_conversion_workflow.py status --json --strict` returned ok with 60 promoted files / 60 live-passed; `scripts/sentinel_synthetic_logs.py validate-live --limit 20 --lookback 24h --timeout 60` returned 20 passed / 0 empty / 0 failed after CAP upload.

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

- Plan the remaining Phase 9 operator parity and field mapping bulk expansion work via `$gsd-plan-phase 9`; do not treat the 2026-05-17 promotion/test pass as full Phase 9 completion.
- Optional: decide whether Phase 10-style synthetic-hit promotion metadata should be backfilled for the 20 candidates that returned rows in `queries/sentinel_synthetic_live_results.json`; current canonical promotion still uses live parser validation.
- If running `python3 scripts/release_checklist.py --include-live`, expect it to rewrite generated artifacts. Use a clean or intentionally staged worktree first.

### Blockers/Concerns

- Worktree has many generated Sentinel and inventory changes from the 2026-05-17 promotion/test pass. Future fixes must isolate changed files and avoid reverting user work.
- Live OCI validation requires explicit profile/environment access and should not be assumed for local-only tasks. The 2026-05-17 production validation used `OCI_PROFILE=cap`.
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

Last session: 2026-05-17T07:16:27.000Z
Stopped at: Phase 9 production-readiness review pass complete; release gates and commit pending
Resume file: queries/sentinel_synthetic_live_results.json (tracked synthetic live-hit evidence)
