# Architecture Research

**Domain:** Sentinel KQL → OCI Log Analytics QL converter (parity extension to existing v1 pipeline)
**Researched:** 2026-05-15
**Confidence:** HIGH (based on direct inspection of `scripts/convert_sentinel_kql.py`, `scripts/sentinel_conversion_workflow.py`, `scripts/release_checklist.py`, `scripts/check_inventory_drift.py`, `config/sentinel_oci_mapping.yaml`, and `.github/workflows/*.yml`)

## Standard Architecture

### System Overview (v2 target)

```
┌──────────────────────────────────────────────────────────────────────────┐
│                       SOURCE LAYER (unchanged)                            │
│  ┌──────────────────┐   ┌──────────────────────┐  ┌────────────────────┐ │
│  │ rules/** (Sigma) │   │ .sentinel/ clone     │  │ queries/sentinel_  │ │
│  │                  │   │ (sync_sentinel_kql)  │  │ candidates.json    │ │
│  └─────────┬────────┘   └──────────┬───────────┘  └──────────┬─────────┘ │
└────────────┼───────────────────────┼─────────────────────────┼───────────┘
             │                       │                         │
┌────────────┴───────────────────────┴─────────────────────────┴───────────┐
│                       CONVERSION LAYER                                    │
│                                                                           │
│  scripts/convert_sigma.py        scripts/sentinel_conversion_workflow.py  │
│        │                                       │                          │
│        │                                       ▼                          │
│        │                          scripts/convert_sentinel_kql.py         │
│        │                                       │                          │
│        │                                       ▼                          │
│        │                          ┌─────────────────────────────┐         │
│        │                          │  NEW: scripts/kql/           │         │
│        │                          │  ├── lexer.py                │         │
│        │                          │  ├── ast_nodes.py            │         │
│        │                          │  ├── operators/              │         │
│        │                          │  │   ├── parse.py            │         │
│        │                          │  │   ├── extend.py           │         │
│        │                          │  │   ├── summarize.py        │         │
│        │                          │  │   ├── mv_expand.py        │         │
│        │                          │  │   └── column_ifexists.py  │         │
│        │                          │  ├── functions/              │         │
│        │                          │  │   ├── iff.py              │         │
│        │                          │  │   ├── countof.py          │         │
│        │                          │  │   └── parse_command_line. │         │
│        │                          │  ├── emitter.py (Logan QL)   │         │
│        │                          │  └── mapping_loader.py        │         │
│        │                          └─────────────────────────────┘         │
└────────┼───────────────────────────────────┼──────────────────────────────┘
         │                                   │
┌────────┴───────────────────────────────────┴──────────────────────────────┐
│                       MAPPING CONFIG LAYER                                │
│                                                                           │
│  config/sentinel_oci_mapping.yaml  ──── refactor ──▶  config/mapping/    │
│  (526 lines, monolithic)                              ├── _root.yaml      │
│                                                       ├── tables/         │
│                                                       │   ├── identity.yaml│
│                                                       │   ├── endpoint.yaml│
│                                                       │   └── ...         │
│                                                       └── fields/         │
│                                                           ├── common.yaml │
│                                                           ├── subject.yaml│
│                                                           └── process.yaml│
└──────────────────────────────────┬────────────────────────────────────────┘
                                   │
┌──────────────────────────────────┴────────────────────────────────────────┐
│                       VALIDATION LAYER                                    │
│                                                                           │
│  validate_logan_query_local()   →   OCI Log Analytics REST live validate  │
│         │                                  │                              │
│         ▼                                  ▼                              │
│  local errors[]                    live_validation_status                 │
└──────────────────────────────────┬────────────────────────────────────────┘
                                   │
┌──────────────────────────────────┴────────────────────────────────────────┐
│                       ARTIFACT LAYER                                      │
│                                                                           │
│  queries/sentinel/*.json (promoted)                                       │
│  queries/sentinel_conversion_report.json                                  │
│  NEW: queries/sentinel_backlog_priority.json                              │
│  NEW: queries/sentinel_drift.json                                         │
│  queries/catalog.json   queries/dashboard_inventory.json                  │
└──────────────────────────────────┬────────────────────────────────────────┘
                                   │
┌──────────────────────────────────┴────────────────────────────────────────┐
│                       GATE LAYER                                          │
│                                                                           │
│  scripts/release_checklist.py   ←── adds: kql/ unit tests, drift check    │
│  scripts/check_inventory_drift.py (existing)                              │
│  NEW: scripts/sentinel_drift_check.py                                     │
│  NEW: scripts/sentinel_backlog_prioritize.py                              │
└──────────────────────────────────┬────────────────────────────────────────┘
                                   │
┌──────────────────────────────────┴────────────────────────────────────────┐
│                       CI LAYER (.github/workflows/)                       │
│                                                                           │
│  validate-rules.yml (existing — Sigma path, unchanged)                    │
│  inventory-drift.yml (existing — runs on every push/PR)                   │
│  NEW: sentinel-converter.yml                                              │
│        ├── job: unit (operator translators)                               │
│        ├── job: integration (dry-run full corpus)                         │
│        ├── job: drift (compare promoted vs candidates)                    │
│        └── job: live (manual / scheduled — OCI promote)                   │
└────────────────────────────────────────────────────────────────────────────┘
```

### Component Responsibilities

| Component | Responsibility | Type |
|-----------|----------------|------|
| `scripts/kql/lexer.py` | Tokenize KQL preserving string literals, comments, brackets | NEW |
| `scripts/kql/ast_nodes.py` | Frozen dataclasses for pipeline stages (Source, Where, Extend, Summarize, …) | NEW |
| `scripts/kql/operators/*.py` | One module per KQL operator family — parse stage → emit Logan QL fragment | NEW |
| `scripts/kql/functions/*.py` | One module per KQL function (`iff`, `countof`, `parse_command_line`, `column_ifexists`) | NEW |
| `scripts/kql/emitter.py` | Serialize the converted pipeline back to Logan QL string + metadata | NEW |
| `scripts/kql/mapping_loader.py` | Load + merge `config/mapping/*.yaml` shards; back-compat with monolithic file | NEW |
| `scripts/convert_sentinel_kql.py` | Stays as the public entry: orchestrates sync → tokenize → operator dispatch → emit → validate. Becomes thin facade (≤ 800 lines) | MODIFIED |
| `scripts/sentinel_conversion_workflow.py` | Stays as workflow wrapper (status, run-local, promote, backlog). Existing `build_next_query_backlog()` extracted into helper module | MODIFIED |
| `scripts/sentinel_backlog_prioritize.py` | Standalone CLI that writes `queries/sentinel_backlog_priority.json` (consumed by humans + CI summary) | NEW |
| `scripts/sentinel_drift_check.py` | Compares current promoted set against last-known-good report; detects regressions when mapping / converter changes | NEW |
| `config/mapping/_root.yaml` + shards | Table-scoped + field-domain-scoped mapping files | NEW (refactor) |
| `scripts/release_checklist.py` | Existing — add two steps: `sentinel_drift_check.py` and `sentinel_backlog_prioritize.py --validate` | MODIFIED |
| `.github/workflows/sentinel-converter.yml` | New workflow with dry-run + drift jobs on PR, live promote on schedule/manual | NEW |

## Recommended Project Structure

```
oci-log-analytics-detections/
├── scripts/
│   ├── kql/                            # NEW subpackage for KQL parity
│   │   ├── __init__.py
│   │   ├── lexer.py                    # tokenizer (string-aware, comment-stripping)
│   │   ├── ast_nodes.py                # @dataclass(frozen=True) stage nodes
│   │   ├── pipeline.py                 # stage list -> emit Logan QL
│   │   ├── mapping_loader.py           # merges config/mapping/**.yaml
│   │   ├── operators/
│   │   │   ├── __init__.py             # OPERATOR_REGISTRY: {name: convert_fn}
│   │   │   ├── where.py
│   │   │   ├── project.py
│   │   │   ├── extend.py
│   │   │   ├── summarize.py
│   │   │   ├── sort_top.py
│   │   │   ├── parse.py                # NEW capability — parse, parse-kv
│   │   │   ├── mv_expand.py            # NEW capability
│   │   │   ├── join.py                 # explicit unsupported with structured reason
│   │   │   └── let.py                  # promote `_preprocess_simple_lets`
│   │   ├── functions/
│   │   │   ├── __init__.py             # FUNCTION_REGISTRY
│   │   │   ├── iff.py                  # iff(cond, a, b) → case-when in eval
│   │   │   ├── countof.py
│   │   │   ├── parse_command_line.py
│   │   │   ├── column_ifexists.py      # → coalesce / lookup-keyed
│   │   │   ├── tostring.py
│   │   │   └── string_ops.py           # has, has_any, contains, startswith
│   │   └── emitter.py                  # Logan QL string + dashboard metadata
│   ├── convert_sentinel_kql.py         # thin facade (existing) — delegates to scripts.kql
│   ├── sentinel_conversion_workflow.py # workflow wrapper (existing)
│   ├── sentinel_backlog_prioritize.py  # NEW: writes queries/sentinel_backlog_priority.json
│   ├── sentinel_drift_check.py         # NEW: writes queries/sentinel_drift.json
│   ├── sync_sentinel_kql.py            # unchanged
│   ├── check_inventory_drift.py        # unchanged
│   ├── release_checklist.py            # MODIFIED: adds two gate steps
│   └── test_kql/                       # NEW: mirrors scripts/kql/ for unit tests
│       ├── operators/
│       │   ├── test_parse.py
│       │   ├── test_extend.py
│       │   └── test_summarize.py
│       ├── functions/
│       │   ├── test_iff.py
│       │   └── test_column_ifexists.py
│       └── fixtures/
│           ├── kql/                    # input KQL .kql snippets
│           └── expected/               # expected Logan QL .ql snippets
│   ├── test_sentinel_converter.py      # existing — keep as integration entry
│   ├── test_sentinel_drift_check.py    # NEW
│   └── test_sentinel_backlog_prioritize.py  # NEW
│
├── config/
│   ├── sentinel_oci_mapping.yaml       # KEEP as compat shim — re-exports from config/mapping/
│   └── mapping/                        # NEW: sharded mapping
│       ├── _root.yaml                  # categories, services, defaults
│       ├── tables/
│       │   ├── identity.yaml           # SigninLogs, AuditLogs, AAD*
│       │   ├── endpoint.yaml           # SecurityEvent, DeviceEvents, Sysmon
│       │   ├── cloud_azure.yaml        # AzureActivity, AzureDiagnostics
│       │   ├── cloud_office.yaml       # OfficeActivity, EmailEvents
│       │   └── network.yaml            # DeviceNetworkEvents, CommonSecurityLog
│       └── fields/
│           ├── common.yaml             # User, Time, Entity (existing)
│           ├── subject.yaml            # Subject* (gap)
│           ├── process.yaml            # InitiatingProcess*, Parent* (gap)
│           ├── office.yaml             # MailboxOwner*, OfficeWorkload (gap)
│           └── network.yaml            # SrcIp/DstIp variants
│
├── queries/
│   ├── sentinel/*.json                 # promoted (existing — 8 today)
│   ├── sentinel_conversion_report.json # existing
│   ├── sentinel_backlog_priority.json  # NEW
│   └── sentinel_drift.json             # NEW
│
└── .github/workflows/
    ├── inventory-drift.yml             # existing
    ├── validate-rules.yml              # existing — Sigma path
    └── sentinel-converter.yml          # NEW
```

### Structure Rationale

- **`scripts/kql/` as a subpackage:** `convert_sentinel_kql.py` is already 1747 lines with 60+ functions and growing pattern-list (`UNSUPPORTED_PATTERNS`, `SUPPORTED_AGGREGATIONS`). Adding 5+ new operators inline pushes it past 2500 lines and makes per-operator testing brittle. One module per operator + a `OPERATOR_REGISTRY` dispatch table mirrors the proven Sigma path organization (`rules/**` by domain) and matches the global rule `200-400 lines typical, 800 max`.
- **`config/mapping/` shards:** A single 526-line YAML with ~70 tables + ~300 field mappings makes PRs unreviewable (`fields:` block alone is ~160 lines). Splitting by domain (`subject`, `process`, `office`, `network`) lets a backlog-driven PR add `Subject*` mappings without touching `SigninLogs` rows, and lets reviewers grep for `MailboxOwner` in `fields/office.yaml` rather than scrolling. `sentinel_oci_mapping.yaml` remains as a compat re-export so `convert_sentinel_kql.py` callers do not break mid-migration.
- **`scripts/test_kql/` mirroring source tree:** Unit tests for individual operators (`parse`, `extend`, `iff`) must be findable by file name. Today's `test_sentinel_converter.py` is 774 lines with three classes — adding per-operator cases there would push it past 2000 lines. Fixtures live as plain `.kql` / `.ql` files so a contributor can add a new failing case without writing Python.
- **Backlog + drift artifacts under `queries/`:** They are generated machine-readable contracts (like `catalog.json`, `sentinel_conversion_report.json`). Putting them anywhere else breaks the CLAUDE.md invariant "`queries/catalog.json` is canonical for counts" — generated state lives in `queries/`.
- **CI workflow split:** Existing `validate-rules.yml` is Sigma-only; existing `inventory-drift.yml` is artifact-only. A new `sentinel-converter.yml` keeps the Sentinel path on its own trigger graph so churn there does not block Sigma PRs.

## Architectural Patterns

### Pattern 1: Operator Registry with one module per operator family

**What:** Each KQL operator (`parse`, `extend`, `summarize`, `mv-expand`, `column_ifexists`) lives in its own module under `scripts/kql/operators/`. A single `OPERATOR_REGISTRY` dict maps operator name → `convert(stage_text, mapping, context) -> StageResult` callable. `convert_sentinel_kql.py` dispatches by looking up the operator name from the stage's first token.

**When to use:** When the existing single-file converter has > 5 operators with non-trivial per-operator state (errors, aliases, allowed_aliases). The current implementation already hints at this via `_convert_summarize`, `_convert_sort`, `_convert_top`, `_convert_extend` — they share signature shape but live as private functions in one file.

**Trade-offs:**
- **Pro:** Each operator is independently testable and reviewable. New contributors only need to understand one file. Per-operator metrics (success/skip rate) become trivial.
- **Pro:** The registry is the single place where `unsupported KQL operator: <X>` skip-reasons are generated, so the backlog prioritizer can group by operator deterministically.
- **Con:** First migration is invasive — must move `_convert_*` private functions and their helpers (`_split_alias_expression`, `_default_aggregate_alias`) into shared `scripts/kql/utils.py`. Plan for a Phase 6 "extract without behavior change" commit + Phase 7 "add new operators" commits.

**Example:**
```python
# scripts/kql/operators/__init__.py
from .where import convert as convert_where
from .extend import convert as convert_extend
from .summarize import convert as convert_summarize
from .parse import convert as convert_parse        # NEW
from .mv_expand import convert as convert_mv_expand  # NEW

OPERATOR_REGISTRY: dict[str, OperatorConvertFn] = {
    "where":     convert_where,
    "extend":    convert_extend,
    "summarize": convert_summarize,
    "parse":     convert_parse,
    "mv-expand": convert_mv_expand,
    "mv-apply":  convert_mv_expand,
}
```

### Pattern 2: Sharded mapping config with merge loader

**What:** `config/mapping/_root.yaml` lists shard files in load order. `mapping_loader.load()` reads each shard, merges into the unified dict expected by `load_mapping_config()`, validates no duplicate keys across shards (deterministic failure on conflict). A back-compat path lets `load_mapping_config()` fall through to the monolithic `sentinel_oci_mapping.yaml` if `config/mapping/_root.yaml` is absent.

**When to use:** When a single config file > 400 lines becomes a merge-conflict magnet for parallel PRs. Today's mapping is exactly this — every backlog entry touches the `fields:` block.

**Trade-offs:**
- **Pro:** Per-domain ownership and review. `octo-apm-demo` contributors only edit `fields/office.yaml`.
- **Pro:** Test-time fixtures can pass a single-shard mapping without simulating the full file.
- **Con:** Adds one indirection. Must enforce shard-load determinism (deterministic ordering, fail on duplicate keys) or downstream behavior depends on filesystem order.

**Example:**
```yaml
# config/mapping/_root.yaml
version: 1
shards:
  - tables/identity.yaml
  - tables/endpoint.yaml
  - tables/cloud_azure.yaml
  - fields/common.yaml
  - fields/subject.yaml
  - fields/process.yaml
defaults:
  category: unknown
  service: unknown
```

### Pattern 3: Drift detector as a release-gate side-channel

**What:** `sentinel_drift_check.py` reads the current `queries/sentinel_conversion_report.json` plus the set of files in `queries/sentinel/*.json`, then compares (a) promoted set, (b) per-file live_validation_status, (c) per-file generated query body against a stored baseline (last commit's report or an explicit `--baseline`). It writes `queries/sentinel_drift.json` and exits non-zero on any regression (promoted-passed → now failing, or promoted-and-live-passed file body changed without a corresponding ranked-up score).

**When to use:** Whenever mapping / converter changes silently flip a promoted query from passing to skipping. Without this gate, a `fields/subject.yaml` edit can downgrade `SubjectAccount`-using promoted queries and the only signal is `summary.promoted_count` drift — which `check_inventory_drift.py` does not catch at field-granularity.

**Trade-offs:**
- **Pro:** Catches mapping / converter regressions before live re-validation runs (which is slow and OCI-credential-gated).
- **Pro:** Output `sentinel_drift.json` is greppable evidence for release reviewers.
- **Con:** Requires a stable baseline. Use git-tracked `queries/sentinel_conversion_report.json` as the baseline (it is already committed) and treat each PR as "current vs main".

**Example flow:**
```
release_checklist.py
  └── step "sentinel drift check"
       └── sentinel_drift_check.py
            ├── load baseline from git (main:queries/sentinel_conversion_report.json)
            ├── load current report
            ├── diff promoted_set, per-file status, query body hash
            ├── write queries/sentinel_drift.json
            └── exit 0 if no regressions else 1
```

## Data Flow

### KQL → Logan QL → Catalog → CI

```
[.sentinel/ KQL files]                                  [ config/mapping/*.yaml ]
        │                                                          │
        ▼                                                          │
[scripts/sync_sentinel_kql.py]                                     │
        │                                                          │
        ▼                                                          │
[queries/sentinel_candidates.json] ──┐                             │
                                     ▼                             ▼
                  ┌──────── scripts/convert_sentinel_kql.py ◀──────┘
                  │              │
                  │              ▼
                  │      scripts/kql/lexer.py
                  │              │
                  │              ▼  tokens
                  │      scripts/kql/pipeline.py
                  │              │  stages = [Source, Where, Extend, …]
                  │              ▼
                  │      for stage in stages:
                  │          OPERATOR_REGISTRY[stage.op](stage, mapping)
                  │              │
                  │              ▼  Logan QL fragments + errors[]
                  │      scripts/kql/emitter.py
                  │              │
                  │              ▼  Logan QL string + dashboard metadata
                  │      validate_logan_query_local()
                  │              │
                  │              ▼  (passes)
                  │      OCI Log Analytics REST live validate
                  │              │
                  │              ▼  (live_validation_status == "passed")
                  │      _write_query_payload()
                  ▼              │
[queries/sentinel/<slug>.json] ◀─┘
[queries/sentinel_conversion_report.json] ─────────┐
                                                   │
        ┌──────────────────────────────────────────┼──────────────────┐
        ▼                                          ▼                  ▼
[sentinel_backlog_prioritize.py]   [sentinel_drift_check.py]   [generate_catalog.py]
        │                                          │                  │
        ▼                                          ▼                  ▼
[queries/sentinel_backlog_priority.json]  [queries/sentinel_drift.json]  [queries/catalog.json]
        │                                          │                  │
        └──────────────────────────────────────────┴──────────────────┘
                                  │
                                  ▼
                        scripts/release_checklist.py
                                  │
                                  ▼
                  .github/workflows/sentinel-converter.yml
```

### Key Data Flows

1. **Conversion path (per-candidate):** `KQL text → tokens → stage AST list → operator dispatch → Logan QL string + errors → local validator → live validator → promoted payload`. The new `scripts/kql/` modules sit between "stage AST list" and "Logan QL string"; everything before and after stays in `convert_sentinel_kql.py`.

2. **Backlog flow (human-facing):** Non-promoted candidates from `sentinel_conversion_report.json` → `classify_next_query_candidate()` (already exists in `sentinel_conversion_workflow.py`) → priority sort by MITRE quality_score + work_type strategy → `queries/sentinel_backlog_priority.json` → consumed by humans browsing the file and by CI summary comments on PRs.

3. **Drift flow (gate-facing):** Baseline `sentinel_conversion_report.json` from `main` ↔ current `sentinel_conversion_report.json` from PR branch → diff promoted set + per-file status + query body hash → `queries/sentinel_drift.json` → `release_checklist.py` reads exit code → CI fails PR if regressions.

4. **CI flow:** PR opens → `inventory-drift.yml` (existing) checks counts → `sentinel-converter.yml` (new) runs unit tests on `scripts/kql/`, runs dry-run conversion on full candidate corpus (no live OCI calls), runs drift check against `main`, posts backlog-priority summary as comment.

## Scaling Considerations

| Scale | Architecture Adjustments |
|-------|--------------------------|
| 8 promoted (today) | Current architecture is already strained — `convert_sentinel_kql.py` at 1747 lines is at the file-size limit per coding-style. |
| 100 promoted | Operator registry + mapping shards are mandatory. Without them, every new mapping touches the same 526-line YAML and review velocity collapses. |
| 1000+ promoted | Need parallel local validation (multiprocess) inside `convert_candidates`. Live validation stays serial — OCI throttles. Add per-table candidate caches keyed on `(source_hash, mapping_hash)` so re-runs only re-convert affected rows. |
| 4452 candidates (full corpus) | Live promotion must shard across multiple CI jobs by table category (`identity`, `endpoint`, `cloud_azure`, …). Drift check must persist a per-shard baseline file (`queries/sentinel_drift/<shard>.json`). |

### Scaling Priorities

1. **First bottleneck:** `convert_sentinel_kql.py` file size + per-PR mapping merge conflicts. Fix via `scripts/kql/` extraction (Phase 6) + `config/mapping/` shards (Phase 7). This is the minimum viable refactor before any new operator code lands.
2. **Second bottleneck:** Local validation runtime. With 4452 candidates and per-candidate regex-heavy validation, `convert_candidates` becomes O(minutes). Fix via `concurrent.futures.ProcessPoolExecutor` over candidate batches once the operator code is module-isolated (subprocess-safe).
3. **Third bottleneck:** Live validation budget. Each live call hits OCI REST. Cap promotions per CI run, route the rest through scheduled (cron) jobs in `sentinel-converter.yml`.

## Anti-Patterns

### Anti-Pattern 1: Adding new operators directly to `convert_sentinel_kql.py`

**What people do:** Open the existing 1747-line file, add `_convert_parse()` next to `_convert_summarize()`, append a regex to `UNSUPPORTED_PATTERNS`, and ship.
**Why it's wrong:** The file is already at the project's documented `800 max` line ceiling and the test file (`test_sentinel_converter.py`) is at 774 lines covering three classes. Each new operator adds 40-100 lines of logic and 100+ lines of tests. After three new operators the file is unreviewable and tests fight for namespace.
**Do this instead:** Extract `scripts/kql/` first (Phase 6, behavior-preserving), then add new operator files (Phase 7+). Each operator PR touches one operator file + one test file.

### Anti-Pattern 2: Hand-editing `queries/sentinel/*.json` to fix conversion gaps

**What people do:** See a missing field in a promoted query, open the JSON, patch it.
**Why it's wrong:** Already explicitly banned by `CLAUDE.md` invariant: *"`queries/sentinel/**` contains only promoted live-validation-passed Sentinel conversions"*. Hand-edits drift on the next conversion run and silently regress.
**Do this instead:** Fix the converter or mapping shard. The drift detector exists precisely to catch hand-edits — `sentinel_drift_check.py` will flag a JSON whose body does not match the current converter output.

### Anti-Pattern 3: Splitting mapping by Sentinel solution name rather than data domain

**What people do:** Create `config/mapping/microsoft_defender_xdr.yaml`, `config/mapping/azure_sentinel_core.yaml`, etc., mirroring upstream folder names.
**Why it's wrong:** Sentinel solutions overlap heavily on fields (`SubjectAccount` appears in Defender XDR, Windows Security, and AD solutions). Sharding by solution causes duplicate field mappings and the merge loader must arbitrarily pick one — a silent correctness hazard.
**Do this instead:** Shard by OCI Log Analytics data domain (`identity`, `endpoint`, `cloud_azure`, …). Each Sentinel field has exactly one mapping home regardless of which Sentinel solution authored the rule.

### Anti-Pattern 4: Adding live OCI calls to PR CI

**What people do:** Wire `sentinel-converter.yml` to call `convert_sentinel_kql.py --validate-live` on every PR.
**Why it's wrong:** OCI credentials per PR are a secrets-management nightmare; live calls are slow (minutes per candidate) and rate-limited; PRs from forks cannot access org secrets.
**Do this instead:** PR jobs run dry-run + drift only. Live promotion runs on a `workflow_dispatch` job (manual) or a scheduled cron job (`schedule: '0 6 * * 1'`) with `OCI_*` secrets attached. Promoted artifacts from the live job land via a follow-up PR or push to a maintenance branch.

## Integration Points

### External Services

| Service | Integration Pattern | Notes |
|---------|---------------------|-------|
| OCI Log Analytics REST API | Live validate via `oci` Python SDK in `_validate_live()` (`convert_sentinel_kql.py:1352`) | Existing — do not change in v2. Credentials via `OCI_PROFILE` / `OCI_CONFIG_FILE`. |
| Azure Sentinel GitHub repo | Read-only clone via `sync_sentinel_kql.py` to `.sentinel/` cache | Existing. Commit hash recorded in `sentinel_conversion_report.json.source.commit`. |
| GitHub Actions | `validate-rules.yml`, `inventory-drift.yml`, new `sentinel-converter.yml` | Trigger paths: `scripts/kql/**`, `config/mapping/**`, `scripts/convert_sentinel_kql.py`, `scripts/sentinel_*.py`, `queries/sentinel_candidates.json`. |

### Internal Boundaries

| Boundary | Communication | Notes |
|----------|---------------|-------|
| `scripts/kql/` ↔ `convert_sentinel_kql.py` | Direct import + `OPERATOR_REGISTRY` dispatch | Keep registry as the only seam — no per-operator import in `convert_sentinel_kql.py`. |
| `scripts/kql/mapping_loader.py` ↔ `config/mapping/**` | Filesystem read at converter startup | Must validate no-duplicate-key across shards. |
| `sentinel_drift_check.py` ↔ git | `git show main:queries/sentinel_conversion_report.json` for baseline | Falls back to a committed baseline file if `main` is not available (e.g. on `main` itself). |
| `sentinel_backlog_prioritize.py` ↔ `sentinel_conversion_workflow.py` | Reuse `classify_next_query_candidate()` and `build_next_query_backlog()` | Do not duplicate classification logic. Extract into `scripts/kql/backlog.py` if a circular import risk emerges. |
| `release_checklist.py` ↔ new gates | Adds two `subprocess.run()` steps in `build_steps()` | Keep the existing ordering invariant: drift checks run AFTER generators. |
| `sentinel-converter.yml` ↔ `release_checklist.py` | CI invokes `python3 scripts/release_checklist.py --skip-tests` for dry-run job | Live job uses `--include-live`. |

## Integration Build Order (dependency-aware)

Phases must build in this order — each phase requires the prior phase's integration point to exist:

1. **Phase 6 — Operator extraction (refactor, behavior-preserving):**
   Carve `scripts/kql/` out of `convert_sentinel_kql.py` without adding new operators. Adds `scripts/test_kql/` skeleton. Existing `test_sentinel_converter.py` must stay green. *Blocks every later phase — no new operator code can land in `convert_sentinel_kql.py`.*

2. **Phase 7 — Mapping config shards (refactor, back-compat):**
   Add `scripts/kql/mapping_loader.py` and `config/mapping/_root.yaml` + initial shards. `sentinel_oci_mapping.yaml` becomes a generated compat re-export. *Blocks field-mapping expansion work.*

3. **Phase 8 — New operator capabilities:**
   `parse`, `extend` expansions (`iff`, `countof`, `parse_command_line`), `column_ifexists`, `mv-expand`. Each operator is one PR. *Requires Phase 6.*

4. **Phase 9 — Field/table mapping expansion:**
   Add `Subject*`, `InitiatingProcess*`, `MailboxOwner*`, `OfficeWorkload`, `OrganizationName` etc. to the new shards. *Requires Phase 7.*

5. **Phase 10 — Backlog prioritizer artifact:**
   `scripts/sentinel_backlog_prioritize.py` writes `queries/sentinel_backlog_priority.json`. Wire into `release_checklist.py`. *Independent — can land any time after Phase 6.*

6. **Phase 11 — Drift detector:**
   `scripts/sentinel_drift_check.py` writes `queries/sentinel_drift.json`. Wire into `release_checklist.py` AFTER existing generators (mirrors the existing ordering comment in `release_checklist.py:96-99`). *Requires Phase 8 + Phase 9 to produce a stable, expanded baseline first.*

7. **Phase 12 — CI workflow:**
   `.github/workflows/sentinel-converter.yml` with `unit`, `integration` (dry-run), `drift`, `live` (manual/scheduled) jobs. *Requires all prior phases.*

## Required Integration Tests

### (a) Operator translator unit tests (`scripts/test_kql/operators/test_*.py`)

- One test class per operator file in `scripts/kql/operators/`.
- Each operator: minimum 6 cases — happy path, every documented sub-form, every unsupported sub-form (with expected skip-reason string), aliasing collision, field mapping miss, regression case from `sentinel_conversion_report.json:unsupported_features`.
- Fixtures live as `scripts/test_kql/fixtures/kql/<op>_<case>.kql` and `scripts/test_kql/fixtures/expected/<op>_<case>.ql` so non-Python contributors can add cases.

### (b) End-to-end converter integration tests (`scripts/test_sentinel_converter.py`)

- Keep existing 774-line file as the integration entry. Do **not** delete `TestSentinelKqlConversion` — those cases prove the public `convert_kql_to_logan()` API stays stable.
- Add new class `TestSentinelKqlNewOperators` covering full pipelines that exercise `parse → extend → summarize` chains end-to-end against the actual mapping.
- Add new class `TestMappingShardLoading` to lock in the merge-loader's deterministic ordering and no-duplicate-key behavior.

### (c) Drift detector regression tests (`scripts/test_sentinel_drift_check.py`)

- Synthesize a baseline report + a current report fixture pair.
- Cover: promoted-passed → now-failed (must fail), promoted body hash unchanged (must pass), new promotion added (must pass — not a regression), promoted removed (must fail), field added to promoted query (must fail unless flagged as expected via `--allow` arg).
- Cover the `git show main:` baseline path with a temp git repo fixture so CI's actual behavior is testable offline.

### (d) Backlog prioritizer tests (`scripts/test_sentinel_backlog_prioritize.py`)

- Cover each strategy in `NEXT_QUERY_STRATEGIES` (`default`, `foundational`).
- Cover priority ties: equal `_priority` → sorted by `-quality_score` then `title`.
- Cover empty-report case and the missing-report case (raises `FileNotFoundError`, exits non-zero with a clear message).

### (e) CI workflow smoke test

- Add a job step in `sentinel-converter.yml` named `verify workflow integrity` that runs `python3 -m pytest scripts/test_kql -q` and `python3 scripts/release_checklist.py --skip-tests --skip-live` to catch wiring regressions in PRs that only touch the workflow YAML.

## Sources

- `/Users/abirzu/dev/oci-log-analytics-detections/scripts/convert_sentinel_kql.py` (1747 lines, inspected lines 1-1100)
- `/Users/abirzu/dev/oci-log-analytics-detections/scripts/sentinel_conversion_workflow.py` (1166 lines, inspected lines 1-450)
- `/Users/abirzu/dev/oci-log-analytics-detections/scripts/release_checklist.py` (full)
- `/Users/abirzu/dev/oci-log-analytics-detections/scripts/check_inventory_drift.py` (first 100 lines)
- `/Users/abirzu/dev/oci-log-analytics-detections/config/sentinel_oci_mapping.yaml` (526 lines, inspected sections)
- `/Users/abirzu/dev/oci-log-analytics-detections/queries/sentinel_conversion_report.json` (summary + first attempted entries)
- `/Users/abirzu/dev/oci-log-analytics-detections/.github/workflows/inventory-drift.yml`
- `/Users/abirzu/dev/oci-log-analytics-detections/.github/workflows/validate-rules.yml`
- `/Users/abirzu/dev/oci-log-analytics-detections/.planning/codebase/ARCHITECTURE.md`
- `/Users/abirzu/dev/oci-log-analytics-detections/.planning/PROJECT.md`
- `/Users/abirzu/dev/oci-log-analytics-detections/CLAUDE.md`

---
*Architecture research for: Sentinel KQL → OCI Log Analytics QL parity (v2.0 milestone)*
*Researched: 2026-05-15*
