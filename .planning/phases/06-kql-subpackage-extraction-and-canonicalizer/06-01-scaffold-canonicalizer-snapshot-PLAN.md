---
phase: 06-kql-subpackage-extraction-and-canonicalizer
plan: 01
type: execute
wave: 1
depends_on: []
files_modified:
  - scripts/kql/__init__.py
  - scripts/kql/types.py
  - scripts/kql/canonical.py
  - scripts/kql/lexer.py
  - scripts/kql/ast_nodes.py
  - scripts/kql/pipeline.py
  - scripts/kql/mapping_loader.py
  - scripts/kql/emitter.py
  - scripts/kql/operators/__init__.py
  - scripts/kql/operators/_legacy.py
  - scripts/kql/functions/__init__.py
  - scripts/test_kql/__init__.py
  - scripts/test_kql/test_canonical_idempotence.py
  - scripts/test_kql/test_module_size.py
  - scripts/test_kql/test_promoted_snapshots.py
  - scripts/test_kql/regen_promoted.py
  - scripts/test_kql/fixtures/kql/.gitkeep
  - scripts/test_kql/fixtures/expected/.gitkeep
  - requirements-dev.txt
  - scripts/convert_sentinel_kql.py
  - scripts/build_sentinel_conversion_report.py
autonomous: true
requirements:
  - REF-01
  - REF-02
  - REF-03
  - REF-04
  - REF-05

must_haves:
  truths:
    - "Importing scripts.kql.canonical exposes canonical() function and CanonicalizationError exception."
    - "Importing scripts.kql.types exposes Tier IntEnum (TIER_1=1, TIER_2=2, TIER_3=3), ConversionContext frozen dataclass, StageResult frozen dataclass, KqlStage, KqlPredicate."
    - "scripts.kql.operators package contains _legacy.py adapters registered via @register decorator for every operator currently supported by scripts/convert_sentinel_kql.py."
    - "All 35 existing tests in scripts/test_sentinel_converter.py still pass."
    - "scripts/test_kql/ contains 8 promoted snapshots + 10 synthetic snapshots (18 .logan files under fixtures/expected/, paired with .kql files under fixtures/kql/)."
    - "queries/sentinel_conversion_report.json summary.tier_distribution exists; every candidates[] entry has a tier field."
  artifacts:
    - path: scripts/kql/__init__.py
      provides: "kql subpackage marker"
    - path: scripts/kql/types.py
      provides: "Tier enum, ConversionContext, StageResult, KqlStage, KqlPredicate"
      contains: "class Tier(IntEnum)"
    - path: scripts/kql/canonical.py
      provides: "canonical() tokenizer + CanonicalizationError"
      contains: "class CanonicalizationError"
    - path: scripts/kql/pipeline.py
      provides: "convert() pipeline with OPERATOR_REGISTRY dispatch via legacy adapters"
      contains: "OPERATOR_REGISTRY"
    - path: scripts/kql/operators/_legacy.py
      provides: "@register adapters bridging to legacy scripts/convert_sentinel_kql.py functions"
      contains: "@register("
    - path: scripts/test_kql/test_module_size.py
      provides: "wc -l scripts/convert_sentinel_kql.py <= 800 gate (xfail strict during migration)"
      contains: "@pytest.mark.xfail(strict=True"
    - path: scripts/test_kql/test_canonical_idempotence.py
      provides: "Hypothesis idempotence property test for canonical()"
      contains: "from hypothesis"
    - path: scripts/test_kql/regen_promoted.py
      provides: "snapshot regen script for the 8 promoted slugs; CI runs read-only and fails on diff"
    - path: requirements-dev.txt
      provides: "test-only deps: pytest + hypothesis"
      contains: "pytest>=8.3"
    - path: scripts/convert_sentinel_kql.py
      provides: "facade re-exporting the D-15 symbol set; existing imports keep working"
      contains: "__all__"
  key_links:
    - from: scripts/sentinel_synthetic_logs.py
      to: scripts/convert_sentinel_kql.py
      via: "from convert_sentinel_kql import ConversionResult, _clean_output_dir, _write_query_payload, build_conversion_report, convert_candidate, load_mapping_config, select_top_candidates, slugify_title"
      pattern: "from convert_sentinel_kql import"
    - from: scripts/kql/operators/_legacy.py
      to: scripts/convert_sentinel_kql.py
      via: "legacy adapter functions call back into convert_sentinel_kql._convert_* helpers"
      pattern: "from .. import|from scripts\\.convert_sentinel_kql"
---

<objective>
Lay the entire Phase 6 foundation in one cohesive PR: create the `scripts/kql/` subpackage skeleton with `OPERATOR_REGISTRY` dispatch via legacy adapters, ship the Logan QL canonicalizer (`canonical.py` + `CanonicalizationError`), publish the `Tier` IntEnum and frozen-dataclass types (`ConversionContext`, `StageResult`, `KqlStage`, `KqlPredicate`), snapshot the 8 promoted artifacts plus ~10 synthetic operator-coverage fixtures through `canonical()`, wire pytest + Hypothesis through `requirements-dev.txt`, land the `wc -l <= 800` line-budget gate as `xfail(strict=True)`, extend `queries/sentinel_conversion_report.json` with `summary.tier_distribution` and per-candidate `tier`, and convert `scripts/convert_sentinel_kql.py` into a backward-compatible facade.

Purpose: Establish the structural safety net (D-13) that all subsequent operator-extraction plans (06-02..06-09) depend on. No behavior change ships in this plan — every promoted query body must remain byte-identical, every existing test must still pass.

Output: Subpackage skeleton, canonicalizer, 18 golden snapshots, test harness, dev-deps, schema-bumped conversion report, facade.
</objective>

<execution_context>
@$HOME/.claude/get-shit-done/workflows/execute-plan.md
@$HOME/.claude/get-shit-done/templates/summary.md
</execution_context>

<context>
@.planning/PROJECT.md
@.planning/ROADMAP.md
@.planning/STATE.md
@.planning/REQUIREMENTS.md
@.planning/phases/06-kql-subpackage-extraction-and-canonicalizer/06-CONTEXT.md
@scripts/convert_sentinel_kql.py
@scripts/test_sentinel_converter.py
@scripts/sentinel_synthetic_logs.py
@CLAUDE.md
</context>

<tasks>

<task type="auto">
  <name>Task 1: Create kql subpackage skeleton + types</name>
  <files>scripts/kql/__init__.py, scripts/kql/types.py, scripts/kql/lexer.py, scripts/kql/ast_nodes.py, scripts/kql/mapping_loader.py, scripts/kql/emitter.py, scripts/kql/operators/__init__.py, scripts/kql/functions/__init__.py</files>
  <read_first>.planning/phases/06-kql-subpackage-extraction-and-canonicalizer/06-CONTEXT.md, scripts/convert_sentinel_kql.py, .planning/research/ARCHITECTURE.md</read_first>
  <action>
    Create `scripts/kql/` package. `__init__.py` re-exports nothing yet — keep it empty docstring only. `scripts/kql/types.py` defines: `class Tier(IntEnum)` with members `TIER_1 = 1`, `TIER_2 = 2`, `TIER_3 = 3` (IntEnum so `max(...)` aggregates severity per D-16). `@dataclass(frozen=True) class ConversionContext` with fields `mapping: dict`, `allowed_aliases: frozenset[str]`, `dictionary_fields: frozenset[str]`, `log_source_tables: tuple[str, ...]`. `@dataclass(frozen=True) class StageResult` with fields `fragments: tuple[str, ...]`, `tier: Tier`, `skip_reasons: tuple[str, ...]`, `new_aliases: tuple[str, ...]`. `@dataclass(frozen=True) class KqlStage` with fields `kind: str`, `body: str` (a parsed top-level stage prior to operator-specific parsing). `@dataclass(frozen=True) class KqlPredicate` with `text: str` (placeholder shell — operators don't need richer parsing yet per D-06). `scripts/kql/lexer.py` exposes `split_kql_stages(kql: str) -> list[str]` that delegates to `convert_sentinel_kql._split_kql_stages` (keep behavior identical; operator-extraction plans replace this with the real implementation moved over). `scripts/kql/ast_nodes.py` is intentionally minimal — re-export `KqlStage` and `KqlPredicate` from `.types` for ergonomic imports. `scripts/kql/mapping_loader.py` exposes `load_mapping(path)` that delegates to `convert_sentinel_kql.load_mapping_config` so callers can migrate import paths gradually. `scripts/kql/emitter.py` defines `format_stage(fragments: Iterable[str]) -> str` returning `" | ".join(fragments)` for future use (no callers in Phase 6). `scripts/kql/operators/__init__.py` declares `OPERATOR_REGISTRY: dict[str, Callable[[KqlStage, ConversionContext], StageResult]] = {}` and `def register(name): def _wrap(fn): OPERATOR_REGISTRY[name] = fn; return fn; return _wrap`. Import `_legacy` at the bottom to trigger adapter registration. `scripts/kql/functions/__init__.py` empty docstring. Every new file ends with newline.
  </action>
  <verify>python -c "from scripts.kql.types import Tier, ConversionContext, StageResult, KqlStage, KqlPredicate; assert Tier.TIER_1 < Tier.TIER_3; assert max([Tier.TIER_1, Tier.TIER_3]) == Tier.TIER_3"</verify>
  <acceptance_criteria>
    - scripts/kql/types.py contains "class Tier(IntEnum)"
    - scripts/kql/types.py contains "TIER_1 = 1" AND "TIER_2 = 2" AND "TIER_3 = 3"
    - scripts/kql/types.py contains "@dataclass(frozen=True)" before ConversionContext, StageResult, KqlStage, KqlPredicate
    - scripts/kql/operators/__init__.py contains "OPERATOR_REGISTRY" AND "def register(" AND "from . import _legacy"
    - scripts/kql/lexer.py contains "split_kql_stages"
    - python -c "from scripts.kql.types import Tier; assert max([Tier.TIER_1, Tier.TIER_2, Tier.TIER_3]) == Tier.TIER_3" exits 0
  </acceptance_criteria>
  <done>Subpackage exists with types, registry, and lexer/mapping/emitter facades; import smoke test passes.</done>
</task>

<task type="auto">
  <name>Task 2: Implement canonical() mini-tokenizer + CanonicalizationError</name>
  <files>scripts/kql/canonical.py</files>
  <read_first>.planning/phases/06-kql-subpackage-extraction-and-canonicalizer/06-CONTEXT.md, scripts/convert_sentinel_kql.py</read_first>
  <action>
    Implement `canonical(query: str) -> str` per D-01 and D-02 — whitespace + quoting normalization ONLY. Hand-rolled mini-tokenizer (~150 LoC). Token kinds: `QUOTED_STRING` (single or double quotes; preserves Logan QL `''` doubled-single-quote escape), `IDENTIFIER` (alnum + `_`, may start with letter or `_`), `NUMBER`, `OPERATOR` (`==`, `!=`, `<=`, `>=`, `=`, `<`, `>`, `+`, `-`, `*`, `/`, `|`, `=~`, `!~`), `PUNCTUATION` (`,`, `(`, `)`, `[`, `]`, `;`, `:`), `STAGE_SEP` (the top-level `|` that separates Logan stages — distinguishable from `=~`/`!~` because those have `~` adjacent and from boolean-or because Logan uses `or` keyword), `WHITESPACE` (any run of `\s+`). Re-emit: collapse all `WHITESPACE` runs to a single space; emit ` | ` (space-pipe-space) around `STAGE_SEP`; normalize all `QUOTED_STRING` tokens to single-quote form (re-escape interior single quotes to `''`); preserve interior content otherwise. Do NOT reorder commutative comparisons, do NOT sort AND chains, do NOT case-fold keywords (those are deferred per D-01). Strip leading/trailing whitespace from the final output. Define `class CanonicalizationError(Exception)` at module top with docstring "Raised when canonical() encounters malformed KQL/Logan QL input (e.g. unterminated quoted string, unrecognized token)." Tokenizer raises `CanonicalizationError` on: unterminated quoted string (no matching closing quote), and unrecognized characters outside whitespace/identifier/operator/punctuation/quote classes. No best-effort passthrough per D-04. Add `__all__ = ["canonical", "CanonicalizationError"]`.
  </action>
  <verify>python -c "from scripts.kql.canonical import canonical, CanonicalizationError; assert canonical(\"'Log Source'  =   'Windows Security Events'\") == \"'Log Source' = 'Windows Security Events'\"; assert canonical(canonical(\"a | b\")) == canonical(\"a | b\")"</verify>
  <acceptance_criteria>
    - scripts/kql/canonical.py contains "class CanonicalizationError(Exception)"
    - scripts/kql/canonical.py contains "def canonical(" AND "__all__"
    - python -c "from scripts.kql.canonical import canonical; assert canonical(\"  a   |   b  \") == 'a | b'" exits 0
    - python -c "from scripts.kql.canonical import canonical; assert canonical(\"\\\"foo\\\"\") == \"'foo'\"" exits 0
    - python -c "from scripts.kql.canonical import canonical, CanonicalizationError\ntry:\n    canonical(\"'unterminated\")\nexcept CanonicalizationError:\n    pass\nelse:\n    raise SystemExit(1)" exits 0
    - canonical(canonical(x)) == canonical(x) for x in ["'a' = 'b'", "a | b | c", "'Field Name' contains 'value'"]
  </acceptance_criteria>
  <done>canonical() and CanonicalizationError are importable; idempotent on small examples; raises on malformed input.</done>
</task>

<task type="auto">
  <name>Task 3: Build pipeline.py + legacy operator adapters</name>
  <files>scripts/kql/pipeline.py, scripts/kql/operators/_legacy.py</files>
  <read_first>scripts/convert_sentinel_kql.py, scripts/kql/operators/__init__.py, scripts/kql/types.py</read_first>
  <action>
    `scripts/kql/pipeline.py` defines `convert(kql: str, mapping: dict, allowed_aliases: set[str] | None = None) -> tuple[str, dict, list[str]]` — same signature as the legacy `convert_kql_to_logan`. In Phase 6 this function delegates to legacy: `from scripts import convert_sentinel_kql as _legacy_mod; return _legacy_mod.convert_kql_to_logan(kql, mapping)`. The legacy adapter path is what gets uniformly dispatched in subsequent plans; pipeline.convert is the future entry point. `scripts/kql/operators/_legacy.py` registers thin adapter functions for every operator family the legacy converter supports. For each operator name in this list — `where`, `summarize`, `project`, `extend`, `sort`, `top`, `distinct`, `union`, `let`, `fields`, `take`, `count`, `limit`, `parse`, `evaluate`, `mv-expand`, `make-series`, `join`, `render` — emit: `@register("<op>")\ndef _adapt_<op>(stage: KqlStage, ctx: ConversionContext) -> StageResult:\n    raise NotImplementedError("Legacy adapter shim; pipeline.convert() delegates to legacy convert_kql_to_logan in Phase 6 — operators not yet routed through registry. See plans 06-02..06-09.")`. The body is intentionally a marker — pipeline.convert short-circuits to legacy for the entire Phase 6 PR-1. Subsequent plans (06-02..06-09) replace each marker with a real operator function and re-wire pipeline.convert to dispatch through OPERATOR_REGISTRY. Add a module-level comment at the top of `_legacy.py`: `# DELETED in plan 06-10 after every operator has a real module under scripts/kql/operators/<op>.py`. Add `from .types import KqlStage, KqlPredicate # noqa: F401` and `from . import _legacy # noqa: F401` to `scripts/kql/operators/__init__.py` if not already done in Task 1.
  </action>
  <verify>python -c "from scripts.kql.operators import OPERATOR_REGISTRY; expected = {'where','summarize','project','extend','sort','top','distinct','union','let','fields','take','count','limit','parse','evaluate','mv-expand','make-series','join','render'}; assert expected.issubset(set(OPERATOR_REGISTRY)), set(OPERATOR_REGISTRY)"</verify>
  <acceptance_criteria>
    - scripts/kql/operators/_legacy.py contains "@register(\"where\")"
    - scripts/kql/operators/_legacy.py contains "@register(\"summarize\")"
    - scripts/kql/operators/_legacy.py contains "@register(\"project\")"
    - scripts/kql/operators/_legacy.py contains "@register(\"extend\")"
    - scripts/kql/operators/_legacy.py contains "@register(\"sort\")"
    - scripts/kql/operators/_legacy.py contains "@register(\"top\")"
    - scripts/kql/operators/_legacy.py contains "@register(\"distinct\")"
    - scripts/kql/operators/_legacy.py contains "@register(\"union\")"
    - scripts/kql/operators/_legacy.py contains "@register(\"let\")"
    - scripts/kql/operators/_legacy.py contains "DELETED in plan 06-10"
    - scripts/kql/pipeline.py contains "def convert(" AND "convert_kql_to_logan"
    - python -c "from scripts.kql.operators import OPERATOR_REGISTRY; assert len(OPERATOR_REGISTRY) >= 9" exits 0
  </acceptance_criteria>
  <done>OPERATOR_REGISTRY populated with ≥9 entries via decorator; pipeline.convert delegates to legacy.</done>
</task>

<task type="auto">
  <name>Task 4: Convert convert_sentinel_kql.py into a facade (re-export D-15 symbol set)</name>
  <files>scripts/convert_sentinel_kql.py</files>
  <read_first>scripts/convert_sentinel_kql.py, scripts/sentinel_synthetic_logs.py, scripts/sentinel_conversion_workflow.py, .planning/phases/06-kql-subpackage-extraction-and-canonicalizer/06-CONTEXT.md</read_first>
  <action>
    Keep ALL existing implementation in place for this PR (no behavior change). Add an `__all__` list at the top of `scripts/convert_sentinel_kql.py` immediately after the module docstring listing the D-15 symbol set verbatim: `__all__ = ["ConversionResult", "_clean_output_dir", "_write_query_payload", "build_conversion_report", "classify_unsupported_kql", "convert_candidate", "convert_candidates", "convert_kql_to_logan", "load_mapping_config", "rank_candidates", "select_top_candidates", "slugify_title", "validate_logan_query_local"]`. This declares the public re-export surface and stops further private-API leakage (callers must request additions). Add a module-level docstring (or extend existing) noting: "Facade module — public API enumerated in __all__. Phase 6 keeps full implementation here; subsequent plans (06-02..06-09) extract operator helpers into scripts/kql/operators/<op>.py; plan 06-10 reduces this file to <=800 lines by removing the operator helpers that are no longer called." Add at the bottom of the file (after all definitions): `from scripts.kql.canonical import canonical, CanonicalizationError  # noqa: F401` and `from scripts.kql.types import Tier  # noqa: F401` so callers can transitionally import these from the facade if needed. Verify that running `python -c "from convert_sentinel_kql import ConversionResult, _clean_output_dir, _write_query_payload, build_conversion_report, classify_unsupported_kql, convert_candidate, convert_candidates, convert_kql_to_logan, load_mapping_config, rank_candidates, select_top_candidates, slugify_title, validate_logan_query_local"` succeeds (these symbols already exist; the only change is the `__all__` declaration + canonical/Tier re-exports).
  </action>
  <verify>cd scripts && python -c "from convert_sentinel_kql import ConversionResult, _clean_output_dir, _write_query_payload, build_conversion_report, classify_unsupported_kql, convert_candidate, convert_candidates, convert_kql_to_logan, load_mapping_config, rank_candidates, select_top_candidates, slugify_title, validate_logan_query_local, canonical, CanonicalizationError, Tier; print('ok')"</verify>
  <acceptance_criteria>
    - scripts/convert_sentinel_kql.py contains "__all__ = ["
    - scripts/convert_sentinel_kql.py __all__ contains exactly these strings: ConversionResult, _clean_output_dir, _write_query_payload, build_conversion_report, classify_unsupported_kql, convert_candidate, convert_candidates, convert_kql_to_logan, load_mapping_config, rank_candidates, select_top_candidates, slugify_title, validate_logan_query_local
    - scripts/convert_sentinel_kql.py contains "from scripts.kql.canonical import canonical, CanonicalizationError"
    - scripts/convert_sentinel_kql.py contains "from scripts.kql.types import Tier"
    - python -c "import sys; sys.path.insert(0,'scripts'); from convert_sentinel_kql import canonical, CanonicalizationError, Tier" exits 0
    - python -m pytest scripts/test_sentinel_converter.py -q exits 0 (all 35 tests still pass)
  </acceptance_criteria>
  <done>Facade publishes the D-15 symbol set + canonical/Tier re-exports; legacy callers unchanged.</done>
</task>

<task type="auto">
  <name>Task 5: Add requirements-dev.txt + scripts/test_kql/ skeleton</name>
  <files>requirements-dev.txt, scripts/test_kql/__init__.py, scripts/test_kql/fixtures/kql/.gitkeep, scripts/test_kql/fixtures/expected/.gitkeep</files>
  <read_first>requirements.txt, .planning/phases/06-kql-subpackage-extraction-and-canonicalizer/06-CONTEXT.md</read_first>
  <action>
    Create `requirements-dev.txt` with exactly two requirement lines (per Claude discretion in CONTEXT — minimal scope, no coverage/pytest-cov/pytest-xdist):
    ```
    pytest>=8.3
    hypothesis>=6.150
    ```
    No comments, no blank lines, file ends with newline. Create `scripts/test_kql/__init__.py` (empty docstring). Create `scripts/test_kql/fixtures/kql/.gitkeep` and `scripts/test_kql/fixtures/expected/.gitkeep` (both empty files — the directories must exist in git). Do NOT touch `requirements.txt` (runtime deps unchanged per STATE.md decision).
  </action>
  <verify>test -f requirements-dev.txt &amp;&amp; [ "$(wc -l < requirements-dev.txt | tr -d ' ')" = "2" ] &amp;&amp; grep -q "^pytest>=8.3$" requirements-dev.txt &amp;&amp; grep -q "^hypothesis>=6.150$" requirements-dev.txt &amp;&amp; test -d scripts/test_kql/fixtures/kql &amp;&amp; test -d scripts/test_kql/fixtures/expected</verify>
  <acceptance_criteria>
    - requirements-dev.txt exists with exactly 2 lines
    - requirements-dev.txt contains "pytest>=8.3"
    - requirements-dev.txt contains "hypothesis>=6.150"
    - requirements.txt is unchanged from prior commit (git diff requirements.txt is empty)
    - scripts/test_kql/__init__.py exists
    - scripts/test_kql/fixtures/kql/.gitkeep exists
    - scripts/test_kql/fixtures/expected/.gitkeep exists
  </acceptance_criteria>
  <done>Dev deps locked at exactly pytest + hypothesis; fixture directories present.</done>
</task>

<task type="auto">
  <name>Task 6: Generate 8 promoted snapshots + 10 synthetic fixtures through canonical()</name>
  <files>scripts/test_kql/regen_promoted.py, scripts/test_kql/fixtures/kql/m365_url_click_threats.kql, scripts/test_kql/fixtures/kql/detect_suspicious_commands_initiated_by_webserver_processes.kql, scripts/test_kql/fixtures/kql/discord_download_invoked_from_cmd_line.kql, scripts/test_kql/fixtures/kql/doppelpaymer_stop_services.kql, scripts/test_kql/fixtures/kql/dopplepaymer_procdump.kql, scripts/test_kql/fixtures/kql/lemonduck_component_names.kql, scripts/test_kql/fixtures/kql/lsass_credential_dumping_with_procdump.kql, scripts/test_kql/fixtures/kql/nrt_base64_encoded_windows_process_command_lines.kql, scripts/test_kql/fixtures/kql/office_apps_launching_wscipt.kql, scripts/test_kql/fixtures/kql/where_basic.kql, scripts/test_kql/fixtures/kql/where_string_ops.kql, scripts/test_kql/fixtures/kql/summarize_count_by.kql, scripts/test_kql/fixtures/kql/project_basic.kql, scripts/test_kql/fixtures/kql/extend_iff_basic.kql, scripts/test_kql/fixtures/kql/sort_basic.kql, scripts/test_kql/fixtures/kql/top_basic.kql, scripts/test_kql/fixtures/kql/distinct_basic.kql, scripts/test_kql/fixtures/kql/union_simple.kql, scripts/test_kql/fixtures/kql/let_scalar.kql, scripts/test_kql/fixtures/expected/*.logan</files>
  <read_first>queries/sentinel/detect_suspicious_commands_initiated_by_webserver_processes.json, queries/sentinel/discord_download_invoked_from_cmd_line.json, queries/sentinel/doppelpaymer_stop_services.json, queries/sentinel/dopplepaymer_procdump.json, queries/sentinel/lemonduck-component-names.json, queries/sentinel/lsass_credential_dumping_with_procdump.json, queries/sentinel/nrt_base64_encoded_windows_process_command-lines.json, queries/sentinel/office_apps_launching_wscipt.json, scripts/convert_sentinel_kql.py</read_first>
  <action>
    Note: the promoted set is **8 slugs** (CONTEXT.md cites "8 promoted" — the local repo currently has these slugs under `queries/sentinel/*.json`: detect_suspicious_commands_initiated_by_webserver_processes, discord_download_invoked_from_cmd_line, doppelpaymer_stop_services, dopplepaymer_procdump, lemonduck-component-names, lsass_credential_dumping_with_procdump, nrt_base64_encoded_windows_process_command-lines, office_apps_launching_wscipt). The CONTEXT mention of `m365_url_click_threats` was illustrative; use the actual 8 slugs above (with hyphens converted to underscores in fixture filenames for grep-ability). If a promoted slug is missing from `queries/sentinel/`, log `[skipped] <slug>` and continue — the fixture corpus is 8 promoted + 10 synthetic regardless.

    Step 1 — write `scripts/test_kql/regen_promoted.py` that: (a) iterates `queries/sentinel/*.json`, (b) for each, extracts `query.body` (or equivalent — read the first promoted file to confirm the key path), (c) writes `query.body` verbatim to `scripts/test_kql/fixtures/kql/<slug_underscored>.kql`, (d) writes `canonical(query.body)` to `scripts/test_kql/fixtures/expected/<slug_underscored>.logan`. The script accepts `--check` mode that compares disk against re-computed canonical output and exits non-zero on diff. CI runs `python scripts/test_kql/regen_promoted.py --check`.

    Step 2 — author 10 synthetic operator-coverage fixtures by hand per D-12. Each `.kql` is a minimal Logan-QL-shaped input demonstrating one operator family; each `.logan` is the canonical form (run through `canonical()`). Contents (Logan QL post-conversion form — these are NOT KQL, they are the expected Logan QL output, with the .kql sibling carrying a representative KQL input — but for Phase 6 simplicity, make `.kql` and `.logan` both Logan-QL snippets, since canonical() operates on Logan QL output):
      - where_basic.kql: `'Log Source' = 'Windows Security Events'   |   where 'Event ID' = 4624`
      - where_basic.logan: `'Log Source' = 'Windows Security Events' | where 'Event ID' = 4624`
      - where_string_ops.kql: `where 'Process Name' like '%powershell%' and 'Command Line' contains 'invoke-expression' and 'User' startswith 'admin'`
      - where_string_ops.logan: `where 'Process Name' like '%powershell%' and 'Command Line' contains 'invoke-expression' and 'User' startswith 'admin'`
      - summarize_count_by.kql: `where 'Event ID' = 4624 |  stats  count as event_count  by 'User'`
      - summarize_count_by.logan: `where 'Event ID' = 4624 | stats count as event_count by 'User'`
      - project_basic.kql: `where 'Event ID' = 4624 |   fields 'Time', 'User', 'Process Name'`
      - project_basic.logan: `where 'Event ID' = 4624 | fields 'Time', 'User', 'Process Name'`
      - extend_iff_basic.kql: `eval is_admin = if(role = 'admin', 1, 0)`
      - extend_iff_basic.logan: `eval is_admin = if(role = 'admin', 1, 0)`
      - sort_basic.kql: `where 'Event ID' = 4624 | sort by 'Time' desc`
      - sort_basic.logan: `where 'Event ID' = 4624 | sort by 'Time' desc`
      - top_basic.kql: `top 10 by 'Time' desc`
      - top_basic.logan: `top 10 by 'Time' desc`
      - distinct_basic.kql: `distinct 'User','Source IP'`
      - distinct_basic.logan: `distinct 'User', 'Source IP'`
      - union_simple.kql: `union ('Log Source' = 'Linux Secure'), ('Log Source' = 'Windows Security Events')`
      - union_simple.logan: `union ('Log Source' = 'Linux Secure'), ('Log Source' = 'Windows Security Events')`
      - let_scalar.kql: `let threshold = 5;   where 'Event Count' > threshold`
      - let_scalar.logan: `let threshold = 5; where 'Event Count' > threshold`
    Adjust whitespace in `.kql` to be NON-canonical (extra spaces / different quote forms) so canonical() has work to do; the `.logan` must be the exact `canonical(.kql)` output.

    Step 3 — verify each synthetic fixture round-trips: `assert canonical(open(kql).read()) == open(logan).read()`. If any pair mismatches, fix the `.logan` to match `canonical()` output (the canonicalizer is the source of truth).

    Step 4 — run regen_promoted.py once to write the 8 promoted `.kql` + `.logan` snapshot pairs.
  </action>
  <verify>python scripts/test_kql/regen_promoted.py --check &amp;&amp; ls scripts/test_kql/fixtures/expected/*.logan | wc -l | grep -E "^1[78]$"</verify>
  <acceptance_criteria>
    - scripts/test_kql/regen_promoted.py exists and supports `--check` flag
    - scripts/test_kql/fixtures/kql/ contains at least 18 .kql files (8 promoted + 10 synthetic; ≥17 if one promoted slug is absent from queries/sentinel)
    - scripts/test_kql/fixtures/expected/ contains a .logan file paired with every .kql file
    - For every promoted slug present in queries/sentinel/*.json: canonical(query_body) == read(scripts/test_kql/fixtures/expected/<slug>.logan)
    - For every synthetic slug: canonical(read(.kql)) == read(.logan)
    - python scripts/test_kql/regen_promoted.py --check exits 0
  </acceptance_criteria>
  <done>18 fixture pairs on disk; promoted snapshots regenerable via --check; synthetic fixtures round-trip through canonical().</done>
</task>

<task type="auto">
  <name>Task 7: Write the canonical idempotence property test (Hypothesis)</name>
  <files>scripts/test_kql/test_canonical_idempotence.py, scripts/test_kql/test_promoted_snapshots.py</files>
  <read_first>scripts/kql/canonical.py, scripts/test_kql/fixtures/expected/, .planning/phases/06-kql-subpackage-extraction-and-canonicalizer/06-CONTEXT.md</read_first>
  <action>
    `scripts/test_kql/test_canonical_idempotence.py` uses `hypothesis` to verify `canonical(canonical(x)) == canonical(x)` over narrow Logan QL fragments per Claude discretion in CONTEXT — generators emit:
      (a) `from hypothesis import given, strategies as st, settings`
      (b) Strategy `_field()` → `'<ident>'` with ident drawn from `st.from_regex(r"[A-Za-z][A-Za-z0-9 ]{0,15}", fullmatch=True)`
      (c) Strategy `_literal()` → `'<text>'` with text drawn from `st.from_regex(r"[A-Za-z0-9_ %\\-]{0,20}", fullmatch=True)`
      (d) Strategy `_clause()` → `st.builds(lambda f, op, v: f"{f} {op} {v}", _field(), st.sampled_from(["=", "!=", "like", "contains", "startswith"]), _literal())`
      (e) Strategy `_chain()` → `st.lists(_clause(), min_size=1, max_size=4).map(lambda xs: " and ".join(xs))` and similar for `or`
      (f) Strategy `_fields_clause()` → `st.lists(_field(), min_size=1, max_size=5).map(lambda xs: "fields " + ", ".join(xs))`
      (g) Strategy `_query()` → joins 1..4 stages with `st.sampled_from([" | ", "  |  ", "|"])` so canonical() actually has work to do
      (h) `@settings(max_examples=100, deadline=None)` to keep CI fast
      (i) `@given(query=_query()) def test_idempotent(query): assert canonical(canonical(query)) == canonical(query)`
    Per CONTEXT (Claude discretion): generators do NOT emit `eval`, `stats`, or aggregate forms — those land in Phase 9 with their operator extractions and gain their own narrow generators then.

    `scripts/test_kql/test_promoted_snapshots.py` — parametrized pytest:
      `@pytest.mark.parametrize("kql_path", list(Path("scripts/test_kql/fixtures/kql").glob("*.kql")))`
      `def test_canonical_matches_snapshot(kql_path):`
        `expected_path = Path("scripts/test_kql/fixtures/expected") / f"{kql_path.stem}.logan"`
        `assert canonical(kql_path.read_text()) == expected_path.read_text(), f"{kql_path.stem} drifted"`
    Plus a negative test:
      `def test_canonical_raises_on_unterminated_quote(): with pytest.raises(CanonicalizationError): canonical("'unterminated")`

    Both tests must pass when run via `python -m pytest scripts/test_kql/test_canonical_idempotence.py scripts/test_kql/test_promoted_snapshots.py -q`.
  </action>
  <verify>python -m pytest scripts/test_kql/test_canonical_idempotence.py scripts/test_kql/test_promoted_snapshots.py -q</verify>
  <acceptance_criteria>
    - scripts/test_kql/test_canonical_idempotence.py contains "from hypothesis"
    - scripts/test_kql/test_canonical_idempotence.py contains "canonical(canonical("
    - scripts/test_kql/test_canonical_idempotence.py contains "@settings(max_examples=100"
    - scripts/test_kql/test_promoted_snapshots.py contains "fixtures/kql"
    - scripts/test_kql/test_promoted_snapshots.py contains "CanonicalizationError"
    - python -m pytest scripts/test_kql/test_canonical_idempotence.py scripts/test_kql/test_promoted_snapshots.py -q exits 0
  </acceptance_criteria>
  <done>Hypothesis idempotence proof + 18 snapshot tests + negative test all green.</done>
</task>

<task type="auto">
  <name>Task 8: Add line-budget gate as xfail(strict=True)</name>
  <files>scripts/test_kql/test_module_size.py</files>
  <read_first>scripts/convert_sentinel_kql.py, .planning/phases/06-kql-subpackage-extraction-and-canonicalizer/06-CONTEXT.md</read_first>
  <action>
    Write `scripts/test_kql/test_module_size.py`:
    ```python
    """Module-size gate for the convert_sentinel_kql facade.

    Asserts scripts/convert_sentinel_kql.py is <= 800 lines per D-14 + CLAUDE.md
    file-size ceiling. Marked xfail(strict=True) during Phase 6 migration; the
    final extraction plan (06-10) removes the xfail mark once the facade is
    actually <=800 lines.
    """
    from pathlib import Path
    import pytest

    FACADE = Path(__file__).resolve().parent.parent / "convert_sentinel_kql.py"
    LIMIT = 800


    @pytest.mark.xfail(strict=True, reason="Phase 6 migration in progress; legacy helpers still inline. Plan 06-10 removes this xfail.")
    def test_facade_under_line_limit():
        line_count = sum(1 for _ in FACADE.open())
        assert line_count <= LIMIT, f"{FACADE.name} is {line_count} lines, exceeds {LIMIT}"
    ```
    `xfail(strict=True)` means: while the file is > 800 lines, the test expectedly fails and pytest passes overall. The moment a plan accidentally reduces the file under 800 prematurely, `strict=True` flips it to an XPASS failure — forcing whoever did it to remove the xfail (the intended cutover signal). Plan 06-10 explicitly removes the xfail decorator.
  </action>
  <verify>python -m pytest scripts/test_kql/test_module_size.py -q</verify>
  <acceptance_criteria>
    - scripts/test_kql/test_module_size.py contains "@pytest.mark.xfail(strict=True"
    - scripts/test_kql/test_module_size.py contains "LIMIT = 800"
    - scripts/test_kql/test_module_size.py contains "Plan 06-10 removes this xfail"
    - python -m pytest scripts/test_kql/test_module_size.py -q exits 0 (xfailed expectedly while file > 800 lines)
  </acceptance_criteria>
  <done>Line-budget gate active and xfailed; flips to XPASS when facade reaches <=800 lines (deliberate cutover signal for 06-10).</done>
</task>

<task type="auto">
  <name>Task 9: Extend sentinel_conversion_report.json with tier_distribution + per-candidate tier</name>
  <files>scripts/convert_sentinel_kql.py, queries/sentinel_conversion_report.json</files>
  <read_first>scripts/convert_sentinel_kql.py, queries/sentinel_conversion_report.json, .planning/phases/06-kql-subpackage-extraction-and-canonicalizer/06-CONTEXT.md</read_first>
  <action>
    Locate `build_conversion_report` in `scripts/convert_sentinel_kql.py` (line ~1454). Extend the per-candidate payload to include `"tier": "tier_1"` as a string field (snake_case serialization of `Tier.TIER_1` — see CONTEXT.md "Specific Ideas": Tier enum members are `TIER_1/TIER_2/TIER_3` and JSON keys are `tier_1/tier_2/tier_3`). For Phase 6 PR-1, default every candidate's tier to `"tier_1"` (lossless) — the actual per-operator tier dispatch lands when operators are extracted in 06-02..06-09. Add a `tier_distribution` block under `summary`: `{"tier_1": <count of tier_1 candidates>, "tier_2": 0, "tier_3": <count of candidates with skip_reasons>}`. Helper: tier_3 should be the count of candidates where `classify_unsupported_kql(kql)` returns a non-empty list — that already exists and is the bridge to the future operator-level tier classifier. Write the helper as a small private function `def _tier_for_candidate(kql: str) -> str` that returns `"tier_3"` if `classify_unsupported_kql(kql)` is non-empty else `"tier_1"`. Regenerate `queries/sentinel_conversion_report.json` by running the existing conversion entry point (e.g., `python scripts/sentinel_conversion_workflow.py local` or whatever the project uses — confirm by reading `sentinel_conversion_workflow.py` line 1-60). If regenerating the report requires live OCI access, instead run a local-only path: `python -c "from scripts import convert_sentinel_kql as m; import json; from pathlib import Path; candidates = json.loads(Path('queries/sentinel_candidates.json').read_text()) if Path('queries/sentinel_candidates.json').exists() else []; mapping = m.load_mapping_config(); m.build_conversion_report(...)"` — preferred: write a small `scripts/build_sentinel_conversion_report.py` thin wrapper that loads candidates from `queries/sentinel_candidates.json`, calls `build_conversion_report` with `live_validation_status='not_run'`, and writes `queries/sentinel_conversion_report.json`. This wrapper does NOT call OCI. Run it once.
  </action>
  <verify>python -c "import json; r = json.load(open('queries/sentinel_conversion_report.json')); assert 'tier_distribution' in r['summary']; assert set(r['summary']['tier_distribution']) >= {'tier_1','tier_2','tier_3'}; assert all('tier' in c for c in r.get('candidates', []))"</verify>
  <acceptance_criteria>
    - scripts/convert_sentinel_kql.py contains "_tier_for_candidate" OR "tier_distribution"
    - queries/sentinel_conversion_report.json `summary.tier_distribution` exists and has keys tier_1, tier_2, tier_3 (all integer values)
    - Every entry in queries/sentinel_conversion_report.json `candidates[]` has a string "tier" field with value in {"tier_1","tier_2","tier_3"}
    - queries/sentinel/*.json bodies are byte-identical to the prior commit (git diff queries/sentinel/ is empty)
    - python -m pytest scripts/test_sentinel_converter.py -q exits 0 (all 35 tests still pass)
  </acceptance_criteria>
  <done>Report schema bumped; promoted query bodies untouched; legacy tests green.</done>
</task>

<task type="auto">
  <name>Task 10: Full regression — converter tests + new kql tests both green; promoted bodies byte-identical</name>
  <files>(verification only — no writes)</files>
  <read_first>scripts/test_sentinel_converter.py, scripts/test_kql/, queries/sentinel/</files>
  <action>
    Run the full Phase 6 PR-1 verification sequence:
    1. `python -m pytest scripts/test_sentinel_converter.py scripts/test_kql/ -q` — must exit 0.
    2. `git diff --stat queries/sentinel/` — must report empty (no changes to promoted bodies).
    3. `wc -l scripts/convert_sentinel_kql.py` — record the current line count (expected ~1747 + small facade additions; gate is xfailed so this stays > 800 for now).
    4. `python -c "from scripts.kql.canonical import canonical; from scripts.kql.types import Tier, ConversionContext, StageResult; from scripts.kql.operators import OPERATOR_REGISTRY; print(len(OPERATOR_REGISTRY))"` — must print ≥ 9.
    5. `python -c "import sys; sys.path.insert(0,'scripts'); from convert_sentinel_kql import canonical, CanonicalizationError, Tier"` — must succeed (facade re-exports work).
    6. Run `scripts/release_checklist.py` and confirm it still passes (success criterion #4 in ROADMAP — Phase 6 must not regress release-checklist).
    If any step fails, fix in this plan before declaring complete (or split the fix into a follow-up if it's behavior-touching). Document any deviations in the SUMMARY.
  </action>
  <verify>python -m pytest scripts/test_sentinel_converter.py scripts/test_kql/ -q &amp;&amp; [ -z "$(git diff --stat queries/sentinel/)" ] &amp;&amp; python scripts/release_checklist.py</verify>
  <acceptance_criteria>
    - python -m pytest scripts/test_sentinel_converter.py scripts/test_kql/ -q exits 0
    - git diff queries/sentinel/ produces empty output
    - python scripts/release_checklist.py exits 0
    - OPERATOR_REGISTRY contains ≥ 9 entries after import
    - Facade re-exports canonical, CanonicalizationError, Tier are importable
  </acceptance_criteria>
  <done>All gates green; promoted artifacts untouched; release checklist still passes.</done>
</task>

</tasks>

<verification>
- [ ] `python -m pytest scripts/test_sentinel_converter.py -q` — 35 tests green
- [ ] `python -m pytest scripts/test_kql/ -q` — idempotence + snapshots + module-size gate all green (xfail expected)
- [ ] `git diff --stat queries/sentinel/` — empty
- [ ] `python scripts/release_checklist.py` — passes
- [ ] `python -c "from scripts.kql.operators import OPERATOR_REGISTRY; assert len(OPERATOR_REGISTRY) >= 9"` — exits 0
- [ ] `python -c "import sys; sys.path.insert(0,'scripts'); from convert_sentinel_kql import canonical, CanonicalizationError, Tier"` — exits 0
- [ ] `wc -l requirements-dev.txt` reports 2 lines
- [ ] `queries/sentinel_conversion_report.json` has `summary.tier_distribution` + per-candidate `tier`
</verification>

<success_criteria>
- All 10 tasks completed
- `scripts/kql/` subpackage exists with types, canonical, pipeline, registry, legacy adapters
- 18 golden fixtures on disk and round-trip through canonical()
- Hypothesis idempotence property test green (100 examples)
- Line-budget gate landed as `xfail(strict=True)`
- requirements-dev.txt locked at exactly pytest + hypothesis
- Conversion report extended with tier_distribution + per-candidate tier
- Facade re-exports the D-15 symbol set; `scripts/test_sentinel_converter.py` stays green
- The 8 promoted Sentinel query bodies are byte-identical to the prior commit
</success_criteria>

<output>
After completion, create `.planning/phases/06-kql-subpackage-extraction-and-canonicalizer/06-01-SUMMARY.md`
</output>
