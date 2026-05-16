# Project Research Summary

**Project:** oci-log-analytics-detections
**Milestone:** v2.0 — Sentinel KQL Parity to Logan QL (continues phase numbering from v1.0; starts at Phase 6)
**Domain:** Brownfield detection-content conversion pipeline (Microsoft Sentinel KQL → OCI Log Analytics QL) with live-OCI-parser validation as the sole promotion gate
**Researched:** 2026-05-15
**Confidence:** HIGH (all four researchers converged on shared evidence: in-repo source files plus the current `queries/sentinel_conversion_report.json` blocker counter)

## Executive Summary

The v2.0 milestone closes the **conversion gap** between Microsoft Sentinel KQL and OCI Log Analytics QL so the Sentinel converter can grow from **8 promoted queries** out of **4,452 candidates** (with 25 attempted and 10 live-failed in the canonical report) toward thousands of promoted queries — without weakening the "live OCI parser validation is the only promotion gate" invariant. The conversion gap is overwhelmingly **semantic mapping** (18+ unmapped fields such as `Subject*`, `InitiatingProcess*`, `EventData`, `OfficeWorkload`, `MailboxOwnerUPN`) plus a small closed set of **operator-level expression blockers** (`iff`, `countof`, `parse_command_line`, `column_ifexists`, `let`-binding, multi-stage `extend`, `bin → timestats`, `set timeout=` directive). It is **not** a parsing problem — no KQL parser library would solve it.

The pragmatic v2.0 path is to **extend the existing 1,747-line `scripts/convert_sentinel_kql.py`** with hand-rolled per-operator translators, organised into a new `scripts/kql/` subpackage so the file stays within the project's 800-line ceiling. Add only two test-tier dependencies (`pytest`, `hypothesis`); leave runtime deps (`oci`, `PyYAML`, `python-dotenv`) untouched. Shard `config/sentinel_oci_mapping.yaml` (526 lines, conflict-magnet) by OCI data domain (`identity`, `endpoint`, `cloud_azure`, `cloud_office`, `network`). Anti-features are firm: no KQL ML, no `geo_*`, no dynamic-bag expansion (`parse_json`/`bag_unpack`), no cross-table `join`, no `_GetWatchlist`, no lossy `parse_command_line` emission, no auto-created OCI alarms.

The dominant risk is **silent semantic loss** as the converter scales — a 1-bit promotion gate (live parser binds → "passed") accepts queries that compile, return zero rows over sparse synthetic data, and ship inert detections to consumers. Mitigations must land **before** any new operator code: golden-fixture pairs + a Logan QL canonicalizer (P1), mapping-collision lint + role tagging (P2), a synthetic-hit promotion gate (P3), and a drift detector + strict YAML loader (P5). The CI workflow must split into a PR-tier dry-run lane (no live OCI calls) and a scheduled/manual live-promotion lane to contain throttling and API-budget blow-up (P6).

## Key Findings

### Recommended Stack

**Do not adopt a third-party KQL parser.** No mature pure-Python option exists (`kusto-query-language-parser` is at 0.0.2 with ~10 commits; Microsoft's authoritative `Kusto.Language` is C#-only and `pythonnet` is broken on macOS ARM + .NET 9). A full `lark`-based grammar is a 6–12 week investment for a problem that is not parsing-bound. Extend the working stage-based pipeline with hand-rolled per-operator translators instead.

**Core technologies (runtime — no change):**
- **Python 3.11+** — converter runtime; `match`-statements and frozen dataclasses simplify the new IR/registry.
- **`oci` >= 2.130.0** — live OCI Log Analytics REST validation; the sole promotion gate.
- **`PyYAML` >= 6.0** — mapping YAML ingestion; v2 must load with a duplicate-key-detecting strict loader.
- **`python-dotenv` >= 1.0.0** — OCI profile env loading; unchanged.

**Test-only additions (new `requirements-dev.txt`):**
- **`pytest` >= 8.3** — parametrized tables for each operator translator.
- **`hypothesis` >= 6.150** — property-based fuzz on predicate conversion and the canonicalizer; generators stay narrow.

**Explicitly rejected:** `kusto-query-language-parser` (immature), `pythonnet + Kusto.Language` (broken on ARM), `lark` for v2.0 (over-engineered until unsupported-feature count > ~25 shapes), `KustoPandas` (wrong primitive), `pysigma` Sentinel backend (duplicates Sigma path), regex re-implementation of `parse_command_line` (lossy → silent detection corruption).

Full detail in [STACK.md](STACK.md).

### Expected Features

**P1 — Must-have (closes the visible failure set):**
- **Mapping additions** (closes 7 of 10 current live failures): `Subject*` cluster, `InitiatingProcess*` extras, `MailboxOwnerUPN`, `OfficeWorkload`, `OrganizationName`, `ClientInfoString`, `UserType`, `ParentProcessName`, `ProcessId`, `Exe`, `LocalFile`, `ActingProcessFileInternalName`.
- **Trivial unblockers:** `Logon_Type` → `LogonType` alias; strip KQL `set timeout=...` / `set truncationmaxsize=...` directives.
- **Operator parity:** `extend` with `iff`, `tostring`, `tolower`, `toupper`, `toint`, `tolong`; single-use `let` constant inlining; `bin(TimeGenerated, span)` → `timestats span=`; `project` / `project-away` / `top N by` / `distinct`.
- **CI dry-run on every PR** running converter + catalog regen + release-checklist local gates.
- **Operator-level + field-mapping gap reports** (free given existing skip-reason inventory).

**P2 — Should-have (raises bar from converter to parity program):**
- **Conversion drift detector** — re-validates `queries/sentinel/*.json` whenever mapping/parser shifts; emits `queries/sentinel_drift.json`; CI-fails on regression.
- **MITRE coverage scoring on backlog** — orders `next-queries` by ATT&CK gap × converter difficulty.
- `column_ifexists` (gated on P1 mapping completeness).
- `countif` aggregate → `eval flag = if(...,1,0) | stats sum(flag)`.
- `matches regex` (trivial-only → `like`; true regex stays SKIPPED with structured reason).

**P3 — Defer (post-v2.0):** `parse Field with "lit" capture ...`, `parse_command_line` + array indexing, `union T1, T2`, OCI Lookups-backed watchlist replacement.

**Anti-features (hard NO):** KQL ML, `geo_*`, dynamic bag expansion (`parse_json`/`bag_unpack`), cross-table `join`, `_GetWatchlist`, `evaluate plugin()`, stored-function `invoke`, lossy `parse_command_line` emission, auto-created OCI alarms from Sentinel content, hand-edited promoted JSON.

Full detail in [FEATURES.md](FEATURES.md).

### Architecture Approach

The current converter is a working stage-based pipeline already at the 800-line ceiling (1,747 lines, 60+ functions). Any new operator code lands as a new file under `scripts/kql/`; the public entry stays as `scripts/convert_sentinel_kql.py` but becomes a thin facade. Mapping config shards by **OCI data domain** (not Sentinel solution name).

**Major components (v2 target):**
1. **`scripts/kql/` subpackage (NEW)** — `lexer.py`, `ast_nodes.py`, `pipeline.py`, `mapping_loader.py`, `operators/<op>.py`, `functions/<fn>.py`, `emitter.py`. One module per operator family, dispatched via `OPERATOR_REGISTRY`.
2. **`scripts/convert_sentinel_kql.py` (MODIFIED — facade)** — trimmed to ≤ 800 lines.
3. **`config/mapping/` shards (NEW)** — `_root.yaml` + `tables/{identity,endpoint,cloud_azure,cloud_office,network}.yaml` + `fields/{common,subject,process,office,network}.yaml`. Old `sentinel_oci_mapping.yaml` becomes generated compat re-export.
4. **`scripts/sentinel_backlog_prioritize.py` (NEW)** — writes `queries/sentinel_backlog_priority.json` (MITRE-weighted, cohort-driven).
5. **`scripts/sentinel_drift_check.py` (NEW)** — diffs current vs `main:queries/sentinel_conversion_report.json` baseline; writes `queries/sentinel_drift.json`; release-checklist gate.
6. **`.github/workflows/sentinel-converter.yml` (NEW)** — split jobs: `unit`, `integration` (dry-run, no live), `drift`, `live` (manual/scheduled, OCI-credentialed).

**CI lane split:** PR-tier runs local + drift only. Live promotion is `workflow_dispatch` or `schedule` with secrets. Fork PRs cannot reach org secrets.

Full detail in [ARCHITECTURE.md](ARCHITECTURE.md).

### Critical Pitfalls

1. **P1 — Silent semantic loss in "permissive" operator handlers.** Live parser validation is binding-level only; it accepts lossy collapses (`parse_command_line` → `tostring`, `iff` drop-else). *Addressed Phase 6: golden fixtures + canonicalizer + TIER-1/2/3 classification before any new operator code.*
2. **P2 — Mapping collisions / tautological many-to-one fan-out.** Today's YAML maps 9 user fields to `User Name` and `Computer`+`DeviceId` to `Entity`. Comparisons become always-true. *Addressed Phase 7: collision lint + role tagging + dictionary-as-oracle.*
3. **P3 — Zero-row false pass at scale.** "Binds and runs" ≠ "returns meaningful data". Empty-result population grows silently. *Addressed Phase 10: synthetic-hit promotion gate.*
4. **P5 — Promoted queries silently regressing after mapping/parser drift.** Promoted JSON is committed once; mapping moves. *Addressed Phase 10 (drift detector) + Phase 7 strict YAML loader.*
5. **P6 — Live API budget exhaustion + non-deterministic CI.** Today's `--top all --timeout 20` against 4,452 candidates blows quota. *Addressed Phase 11: PR-tier dry-run only; nightly delta-only live; throttling-aware classifier as small Phase 7 fix.*
6. **P7 — Brittle string-equality converter tests.** `assert ocl == "..."` breaks under safe refactors. *Addressed Phase 6: canonicalizer + AAA-pattern fixture harness.*
7. **P8 — Sequencing throwaway.** Operator-first AND mapping-first in isolation both leave `promoted_count` flat (blockers are conjunctive). *Addressed Phase 8: cohort-driven backlog prioritizer.*

Secondary (P4 tenancy-quirk leakage, P9 hygiene, P10 catalog drift) addressed in Phase 11.

Full detail in [PITFALLS.md](PITFALLS.md).

## Implications for Roadmap

Phase numbering continues from v1.0. Consensus sequence across all four research files; apparent "mappings-first vs operators-first" disagreement resolved by treating refactor/extraction as the structural gate.

### Phase 6 — KQL subpackage extraction + test harness foundation
**Rationale:** Current file at 800-line ceiling; golden-fixture infrastructure must exist before any new operator translator. Behavior-preserving refactor — existing tests stay green.
**Delivers:** `scripts/kql/` subpackage scaffolding; `OPERATOR_REGISTRY` dispatch; `scripts/test_kql/` mirror tree with `kql/` + `expected/` fixture dirs; Logan QL canonicalizer; TIER-1/2/3 expression classification; `pytest` + `hypothesis` wired into `requirements-dev.txt`.
**Avoids:** P1, P7.

### Phase 7 — Mapping config sharding + collision lint
**Rationale:** Monolithic YAML is conflict-magnet and silently fans many Sentinel fields onto identical Logan columns. Sharding + collision lint must land before bulk additions.
**Delivers:** `config/mapping/_root.yaml` + shards; `scripts/kql/mapping_loader.py` with strict duplicate-key detection; collision-lint emitting `lossy_mapping_collision:<a>+<b>→<col>` skip reasons; role tags (`subject | target | initiator | resource | time | hash | network`); throttling-aware classifier patch.
**Avoids:** P2, P5 partial, P4 partial.

### Phase 8 — Backlog prioritizer + cohort planning overlay
**Rationale:** Operator-first or mapping-first in isolation both produce throwaway work. Lands early so Phases 9 and 10 work against ranked cohorts.
**Delivers:** `scripts/sentinel_backlog_prioritize.py` writing `queries/sentinel_backlog_priority.json`; MITRE coverage scoring; "unblock chain length" metric; release-checklist advisory wire.
**Avoids:** P8.

### Phase 9 — Operator capabilities + field mapping bulk expansion (parallel cohort work)
**Rationale:** Phase 6 unblocks both axes; they target different blocker classes within the same cohort.
**Delivers (operator):** `extend` with scalar funcs; `let` constant inlining; `bin → timestats`; `project`/`project-away`/`top N by`/`distinct`; `countif` rewrite; `set ...` directive stripping. Each operator is its own PR.
**Delivers (mapping):** `Subject*`, `InitiatingProcess*` extras, `MailboxOwnerUPN`, `OfficeWorkload`, `OrganizationName`, `ClientInfoString`, `UserType`, `ParentProcessName`, `ProcessId`, `Exe`, `LocalFile`, `ActingProcessFileInternalName`, `Logon_Type` alias. Every addition must trace to `log_source_field_dictionary.json` or a documented parser-source contract.
**Avoids:** P1 (golden fixtures), P2 (collision lint), P4 (dictionary oracle).

### Phase 10 — Drift detector + synthetic-hit promotion gate
**Rationale:** P5 becomes acute the moment Phase 9 ships bulk additions; P3 becomes acute when `promoted_count` climbs past ~50. Both gates must exist before scaling promotion.
**Delivers:** `scripts/sentinel_drift_check.py` writing `queries/sentinel_drift.json`; `parser_schema_hash` pinned per promoted artifact; `live_synthetic_hit_count > 0` release-checklist gate; `live_validation_passed_with_rows` vs `..._zero_rows` split in report summary.
**Avoids:** P3, P5, P1 reinforcement.

### Phase 11 — CI workflow with PR-dry-run vs scheduled-live lane split
**Rationale:** Five of ten pitfalls become CI-gate problems once generators and detectors exist. PR-tier vs live split is non-negotiable for fork-PR support and API budget control.
**Delivers:** `.github/workflows/sentinel-converter.yml` with `unit`/`integration`/`drift`/`live` jobs; throttling-aware classification (429 / `RequestThrottled` → `live_environment`, not `live_validation`); live-call cache keyed on `(logan_ql_hash, parser_schema_hash, lookback)`; `scan_sensitive_values.py` extended over promoted Sentinel artifacts; `inventory drift check` extended to cover Sentinel JSON ↔ report ↔ catalog ↔ manifest; CI summary comment posting backlog-priority and drift results.
**Avoids:** P4, P6, P9, P10.

### Phase Ordering Rationale

- **Phase 6 first is structural** — line-count ceiling and golden fixtures gate everything else.
- **Phase 7 second is prerequisite-only** — small but gates Phase 9 mapping work.
- **Phase 8 third is overlay** — reframes success as "candidates promoted," not "operators implemented."
- **Phase 9 fourth runs mapping and operator work in parallel** — Features-vs-Architecture surface disagreement dissolves because Phase 6 unblocks both.
- **Phase 10 fifth gates promotion at scale** — drift + synthetic-hit must exist before `promoted_count` climbs past human-review threshold.
- **Phase 11 last because it integrates everything** — building earlier means rewriting it as new gates ship.

### Research Flags

**Needs deeper research during planning:**
- **Phase 6** — Logan QL canonicalizer design (tokenization rules, quoting normalization, `eval if` n-ary vs binary `iff` handling).
- **Phase 9 (mapping side)** — parser-side extraction scope per field (`EventData` children, `ActingProcessFileInternalName`).
- **Phase 10** — `parser_schema_hash` derivation recipe (sort order, normalization, version stamp).

**Standard patterns (skip research-phase):** Phase 7 (YAML sharding), Phase 8 (reuses existing classifier), Phase 11 (existing workflow templates).

## Confidence Assessment

| Area | Confidence | Notes |
|------|------------|-------|
| Stack | HIGH | Verified against in-repo source, OCI primary docs, Microsoft KQL reference, PyPI metadata. |
| Features | HIGH | Anchored in live `queries/sentinel_conversion_report.json` (8/4452/10/25) and 526-line mapping YAML. |
| Architecture | HIGH | Based on direct inspection of converter (1,747 lines), workflow (1,166 lines), release_checklist, drift detector, existing workflows. |
| Pitfalls | HIGH | Every pitfall grounded in observable evidence (specific `unsupported_features` entries, concrete YAML collisions, 1-bit gate documented in PROJECT.md). |

**Overall confidence:** HIGH.

### Gaps to Address

- **Parser-side extraction scope** (Phase 9) — flag mappings requiring SOC parser changes.
- **MITRE quality_score freshness** (Phase 8) — require fresh `sync_sentinel_kql.py` run as Phase 8 entry condition.
- **CI secrets handling for forks** (Phase 11) — short security-review spike needed.
- **Synthetic fixture coverage gap** (Phase 10) — audit fixtures against promoted set.
- **Strict YAML loader rollout risk** (Phase 7) — first run will surface silent overrides; treat as own task with known-noisy outcome.

## Sources

### Primary (HIGH confidence)
- `scripts/convert_sentinel_kql.py` (1,747 lines)
- `scripts/sentinel_conversion_workflow.py` (1,166 lines)
- `scripts/release_checklist.py`, `scripts/check_inventory_drift.py`
- `config/sentinel_oci_mapping.yaml` (526 lines, 161 field entries)
- `queries/sentinel_conversion_report.json` (8 promoted / 4,452 candidates / 10 live-failed / 25 attempted)
- `queries/log_source_field_dictionary.json`
- `.github/workflows/{inventory-drift.yml,validate-rules.yml}`
- OCI Log Analytics command reference (`docs.oracle.com/en-us/iaas/log-analytics/doc/`)
- Microsoft KQL reference (`learn.microsoft.com/azure/data-explorer/kusto/query/`)
- Microsoft Sentinel ASIM normalization schemas
- Azure-Sentinel GitHub corpus

### Secondary (MEDIUM confidence)
- PyPI `kusto-query-language-parser` 0.0.2 — rejected after maturity check
- `microsoft/Kusto-Query-Language` — C#/JS only
- `pythonnet` 3.0.x + issue #2514 (.NET 9 ARM regression)
- `lark` 1.3.x, `hypothesis` 6.150.x, `pytest` 8.3.x

### Tertiary (LOW confidence — validate during phase planning)
- Parser-side extraction scope per Sentinel field (Phase 9)
- `parser_schema_hash` derivation recipe (Phase 10)
- Synthetic fixture coverage gap inventory (Phase 10)
- CI secrets handling for fork PRs (Phase 11)

---
*Research completed: 2026-05-15*
*Ready for roadmap: yes*
*Phase numbering: continues from v1.0; v2.0 starts at Phase 6*
