# Phase 6: KQL Subpackage Extraction and Canonicalizer - Context

**Gathered:** 2026-05-15
**Status:** Ready for planning

<domain>
## Phase Boundary

Behavior-preserving structural refactor of the Sentinel→Logan QL converter. Split the 1747-line `scripts/convert_sentinel_kql.py` into a `scripts/kql/` subpackage (≤800 lines facade), introduce an `OPERATOR_REGISTRY` dispatch, add a Logan QL canonicalizer that lets converter tests assert on canonical form rather than exact strings, and classify every KQL expression as TIER-1 / TIER-2 / TIER-3. **No operator or mapping changes ship in this phase** — those belong in Phases 7 (mapping shards) and 9 (operator parity / field expansion). The 8 promoted Sentinel artifacts must remain byte-identical after canonical normalization; the existing `scripts/test_sentinel_converter.py` suite must stay green throughout the refactor; the live OCI parser validation promotion gate is not relaxed.

</domain>

<decisions>
## Implementation Decisions

### Canonicalizer (`scripts/kql/canonical.py`)

- **D-01 — Normalization floor:** `canonical()` normalizes **whitespace + quoting only**. Collapse runs of whitespace, normalize stage separator to ` | `, pick one quote style (single-quotes for both Logan field names with spaces and string literals, matching current promoted output). Commutative reorder, AND-chain sort, and keyword case-folding are **deferred** — they raise semantic-claim risk and Phase 6 must stay minimal.
- **D-02 — Implementation strategy:** **Mini-tokenizer** in `scripts/kql/canonical.py`. Hand-rolled tokens for quoted-string / identifier / operator / punctuation / whitespace, then re-emit with normalized spacing. ~150 LoC. Must handle Logan QL doubled-single-quote (`''`) escape correctly. Regex-with-placeholder and reuse of `_strip_string_literals` were rejected — escape handling and coupling risk.
- **D-03 — Proof / safety harness:** **Idempotence property test + 8 promoted snapshots.** Hypothesis property: `canonical(canonical(x)) == canonical(x)` over randomly generated Logan QL fragments (narrow generators — see Hypothesis scope below). Plus a fixture lock: canonical form of each of the 8 promoted query bodies stored under `scripts/test_kql/fixtures/expected/<slug>.logan`; CI fails on drift. No live OCI dependency in Phase 6.
- **D-04 — Error behavior:** `canonical()` **raises `CanonicalizationError`** (new custom exception in `scripts/kql/canonical.py`) when the tokenizer encounters malformed input. Refactor commits that produce un-canonicalizable output fail loudly in pytest. No best-effort passthrough; no production/test mode flag.

### OPERATOR_REGISTRY dispatch (`scripts/kql/operators/*.py`, `scripts/kql/pipeline.py`)

- **D-05 — Registration mechanism:** **Decorator at operator module top.** `@register('extend')` above each operator function in `scripts/kql/operators/extend.py`. The decorator populates a module-level `OPERATOR_REGISTRY` dict at import time (operators package imports every module). Grep-able: `grep -r "@register(" scripts/kql/operators` lists every supported operator. Auto-discovery via `__init__.py` rejected (too magical for debugging missing operators); central explicit dict rejected (merge-conflict magnet in Phase 9).
- **D-06 — Operator function shape:** **Pure function** `def convert_<op>(stage: KqlStage, ctx: ConversionContext) -> StageResult`. Stateless. `StageResult` is a frozen dataclass holding `(fragments: tuple[str, ...], tier: Tier, skip_reasons: tuple[str, ...], new_aliases: tuple[str, ...])`. Class-with-lifecycle rejected (no current operator needs precheck/emit/tier separation); separate Logan-AST emitter pass rejected for Phase 6 (forces a deeper AST design now — defer to later phase if friction warrants it).
- **D-07 — Migration adapter:** **Legacy adapter pattern in registry.** Each not-yet-extracted operator gets a `@register('<op>')` thin adapter in `scripts/kql/operators/_legacy.py` that calls the corresponding legacy function in `scripts/convert_sentinel_kql.py`. Pipeline dispatch is uniform at all times; extraction happens one PR per operator family. Fallback if-chain rejected (two code paths drift); big-bang extraction rejected (un-reviewable single PR).
- **D-08 — ConversionContext shape:** **Frozen dataclasses, immutable context.** `@dataclass(frozen=True) class ConversionContext` carries `mapping`, `allowed_aliases: frozenset[str]`, `dictionary_fields: frozenset[str]`, `log_source_tables: tuple[str, ...]`. Operators return new state via `StageResult.new_aliases`; the pipeline accumulates into a new `ConversionContext` for the next stage. No hidden mutation; trivially testable in isolation. Mutable context and "match legacy signature" rejected.

### Golden fixture layout (`scripts/test_kql/fixtures/`)

- **D-09 — File layout:** **Paired files** under `scripts/test_kql/fixtures/kql/<name>.kql` + `scripts/test_kql/fixtures/expected/<name>.logan`. Diff-friendly in PR reviews. Optional sidecar `<name>.meta.json` only when metadata is needed (tier override, skip_reason, parser-readiness flag) — most entries have no sidecar. Single-JSON-envelope and subdirectory-per-query layouts rejected (less diff-friendly; deeper trees).
- **D-10 — Naming convention:** Promoted query fixtures use the **slug from `queries/sentinel/*.json`** (e.g., `m365_url_click_threats.kql`). Synthetic operator-coverage fixtures use **behavior tags** (e.g., `extend_iff_basic.kql`, `summarize_count_by.kql`). Two flat namespaces with no overlap; both live in the same `kql/` and `expected/` directories. Stable GUIDs and hierarchical operator-family directories rejected.
- **D-11 — Regeneration policy:** **Promoted fixtures regenerable; synthetic fixtures hand-edited.** `scripts/test_kql/regen_promoted.py` snapshots current converter output for the 8 promoted queries through `canonical()` into `expected/*.logan`; CI runs it (read-only) and fails on diff. Synthetic operator-coverage fixtures are intentional contracts written by hand. Fully-regenerable rejected (kills TDD path for Phase 9 ops); fully-hand-edited rejected (8 long Logan strings invite typos).
- **D-12 — Phase 6 fixture scope:** **8 promoted + ~10 synthetic** covering existing operator families (`where`, `summarize_count`, `project`, `extend_basic`, `sort`, `top`, `distinct`, `union_simple`, `let_scalar`, plus a `where_string_ops` for `like`/`contains`/`startswith`). ~18 fixtures total. Adds a regression anchor per operator family extracted in this phase. TIER-3 skip-reason synthetic fixtures deferred to Phase 9 (they belong with the operators that touch them).

### Behavior-preservation strategy

- **D-13 — Refactor sequence:** **Snapshot lock first, then iterative extraction.** PR-1 scaffolds `scripts/kql/` (empty operator modules, `canonical.py`, `pipeline.py` with legacy adapters), writes the 18 expected/*.logan snapshots through `canonical()`, wires pytest + hypothesis, lands the line-budget gate as `xfail(strict=True)`. PR-2..PR-N extract one operator family per PR; each PR keeps `scripts/test_sentinel_converter.py` green AND adds/refreshes its operator's synthetic fixture. Iterative-without-snapshot rejected (weaker safety net); big-bang rejected (un-reviewable).
- **D-14 — Line-budget gate:** **pytest gate lands in PR-1, exempted via `xfail(strict=True)` during migration.** `scripts/test_kql/test_module_size.py` asserts `wc -l scripts/convert_sentinel_kql.py <= 800`; PR-1 marks it xfail; the final extraction PR removes the xfail. `release_checklist.py` is NOT extended with the gate in this phase (Phase 11 owns release-gate evolution). Measurement is plain `wc -l` (no AST-based code-lines count) for simplicity and CI portability.
- **D-15 — Facade contract:** `scripts/convert_sentinel_kql.py` becomes a **facade that re-exports every currently-imported symbol** for backward compatibility. Tracked surface (from `grep -A 20 "from convert_sentinel_kql import"`): `ConversionResult, _clean_output_dir, _write_query_payload, build_conversion_report, classify_unsupported_kql, convert_candidate, convert_candidates, convert_kql_to_logan, load_mapping_config, rank_candidates, select_top_candidates, slugify_title, validate_logan_query_local`. The facade declares an `__all__` to stop further private-API leakage. Caller-side import rewrites and "keep private I/O helpers in legacy file" rejected (the goal is a clean cutover and a ≤800-line facade).
- **D-16 — TIER classifier integration:** **Per-operator return value, aggregated per candidate.** Each operator returns `StageResult.tier: Tier` (enum: `TIER_1`, `TIER_2`, `TIER_3`). The candidate's overall tier = `max(stage_tiers, default=TIER_1)` with severity order TIER-3 > TIER-2 > TIER-1. `queries/sentinel_conversion_report.json` gains a `tier_distribution: {tier_1: N, tier_2: M, tier_3: K}` block under `summary` AND a per-candidate `tier` field on every entry in `candidates[]`. Separate AST classifier pass and outcome-inferred classification rejected.

### Claude's Discretion

- **Hypothesis fuzz generator scope:** The user locked the idempotence property (D-03) but did not specify generator breadth. **Decision:** start narrow — generators emit Logan QL fragments composed of (a) random whitespace-padded `'<field>' = '<literal>'` clauses, (b) chained `and`/`or` of the above, (c) `fields <ident_list>`, (d) `| ` stage separators with random whitespace. Generators do NOT emit `eval`, `stats`, or aggregate forms in Phase 6 — those land alongside their operator extraction in Phase 9 and gain their own narrow generators then.
- **Tier enum location:** Place `class Tier(IntEnum): TIER_1 = 1; TIER_2 = 2; TIER_3 = 3` in `scripts/kql/types.py` alongside `ConversionContext` and `StageResult`. IntEnum so `max(...)` works for severity aggregation (D-16).
- **Legacy adapter file:** Use a single `scripts/kql/operators/_legacy.py` rather than one adapter file per not-yet-extracted operator. Adapters are throwaway code; PR-N (final extraction) deletes the file entirely.
- **`requirements-dev.txt` minimal scope:** Two lines exactly — `pytest>=8.3` and `hypothesis>=6.150`. No `coverage`, `pytest-cov`, `pytest-xdist`, or other transitive niceties. Phase 6 stays minimal; future test-tooling additions are their own decision.
- **AST nodes in Phase 6:** No Logan-AST nodes introduced this phase (D-06 chose pure function returning string fragments, not AST). `scripts/kql/ast_nodes.py` is created **but only holds KQL-side AST scaffolding** (`KqlStage`, `KqlPredicate`) needed for operator function signatures. Logan-side AST is deferred until evidence shows the string-fragment shape is causing friction.

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Phase-scoped requirements and roadmap
- `.planning/ROADMAP.md` — Phase 6 success criteria and exit conditions (lines around "### Phase 6: KQL Subpackage Extraction and Canonicalizer"). Authoritative.
- `.planning/REQUIREMENTS.md` — REF-01 through REF-05 (the five Phase 6 requirements).
- `.planning/STATE.md` — current milestone position; v2.0 decisions log (third-party parser rejected, runtime deps unchanged, promotion gate not relaxed).

### Project-level research informing Phase 6
- `.planning/research/SUMMARY.md` — Phase 6 rationale (P1, P7 anti-patterns) and research flags around canonicalizer design.
- `.planning/research/STACK.md` — Why no third-party KQL parser; hand-rolled stage pipeline rationale.
- `.planning/research/ARCHITECTURE.md` — Target subpackage tree (`lexer / ast_nodes / pipeline / mapping_loader / operators/<op> / functions/<fn> / emitter`).
- `.planning/research/PITFALLS.md` — P1 silent semantic loss, P7 brittle string-equality tests; both gated by Phase 6.

### Codebase orientation
- `.planning/codebase/ARCHITECTURE.md` — current converter shape and integration points.
- `.planning/codebase/CONVENTIONS.md` — repo coding conventions (file-size ceiling, generated artifact boundaries).
- `.planning/codebase/TESTING.md` — pytest/unittest conventions for `scripts/test_*.py`.
- `CLAUDE.md` — repo hard rules (no hand-authored content in `logandetectionqueries/`, dashboards via 12-column algorithm, README/STATUS reconciliation).

### Existing code being refactored (must be read before extraction)
- `scripts/convert_sentinel_kql.py` (1747 lines) — the file being split. Public API surface enumerated in D-15.
- `scripts/test_sentinel_converter.py` (774 lines, 35 test methods) — must stay green throughout the refactor.
- `scripts/sentinel_conversion_workflow.py` — top-level workflow driver; reuses public converter API.
- `scripts/sentinel_synthetic_logs.py` — imports `ConversionResult`, `_clean_output_dir`, `_write_query_payload`, `build_conversion_report`, `convert_candidate`, `load_mapping_config`, `select_top_candidates`, `slugify_title` (must continue to work).
- `scripts/sync_sentinel_kql.py` — imports `normalize_sentinel_rule`; check whether facade needs to re-export.
- `queries/sentinel/*.json` — the 8 promoted artifacts that drive the snapshot lock.
- `queries/sentinel_conversion_report.json` — the report that gains `tier_distribution` and per-candidate `tier` in this phase (D-16).
- `config/sentinel_oci_mapping.yaml` — current monolithic mapping (sharded in Phase 7, not here; just consumed read-only in Phase 6).

### External references (for canonicalizer and OCI semantics)
- Microsoft KQL language reference — for any tokenizer corner case (e.g., `''` escape inside string literals). Authoritative for input grammar.
- OCI Log Analytics Query Language docs — Logan QL field-name case sensitivity, quote semantics. Authoritative for output grammar.

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `_strip_string_literals` (scripts/convert_sentinel_kql.py:257) — strips quoted content for analysis. The canonicalizer mini-tokenizer (D-02) does NOT reuse this directly (chose mini-tokenizer over wrapper-reuse), but the function's existing escape handling logic is reference material for the new tokenizer.
- `_split_kql_stages` (scripts/convert_sentinel_kql.py:489) — already splits a KQL query into stages on top-level `|`. Moves into `scripts/kql/lexer.py` essentially unchanged.
- `classify_unsupported_kql` (scripts/convert_sentinel_kql.py:531) — current TIER-3-equivalent classifier; the new tiering layer (D-16) absorbs and extends this; the function is re-exported from the facade for backward compat.
- `ConversionResult` (scripts/convert_sentinel_kql.py:193) — already a dataclass; gains a `tier: Tier` field. `_clean_output_dir` and `_write_query_payload` move into `scripts/kql/io.py` or stay as facade-only helpers; either way the names re-export.
- `convert_kql_to_logan` (scripts/convert_sentinel_kql.py:1018) — the main entry. Becomes the public `scripts.kql.pipeline.convert` function; the facade re-exports under the legacy name.
- The 35-method `scripts/test_sentinel_converter.py` regression suite — the safety net the snapshot strategy (D-13) leans on.

### Established Patterns
- **800-line file ceiling** (CLAUDE.md, common/coding-style.md) — the entire reason Phase 6 exists. Enforced via the pytest gate in D-14.
- **Generated-artifact boundary** (CLAUDE.md: "No hand-authored content in `logandetectionqueries/` or `logandetectionrules/`") — Phase 6 must NOT touch promoted query bodies. The snapshot lock (D-13) writes only to `scripts/test_kql/fixtures/expected/`, not back to `queries/sentinel/`.
- **No placeholder fields** (CLAUDE.md) — every Sigma/Sentinel field must exist in `config/sentinel_oci_mapping.yaml` or `queries/log_source_field_dictionary.json`. Phase 6 does not add fields; it only adds the dispatch and canonicalizer layers, so this rule is satisfied by not regressing.
- **Live OCI parser as sole promotion gate** (PROJECT.md, REQUIREMENTS.md) — Phase 6 does NOT change this. The canonicalizer's safety claim (D-03) deliberately avoids live OCI dependence.
- **Test files import from converter via `from convert_sentinel_kql import (...)`** — the facade contract in D-15 preserves this.
- **Frozen-dataclass + IntEnum project style** — D-06, D-08, and the Tier enum (Claude discretion) follow project Python conventions consistent with `coding-style.md` immutability rule.

### Integration Points
- `scripts/convert_sentinel_kql.py` ↔ `scripts/sentinel_conversion_workflow.py`: workflow imports `convert_candidate`, `rank_candidates`, etc. Facade preserves names (D-15).
- `scripts/convert_sentinel_kql.py` ↔ `scripts/sentinel_synthetic_logs.py`: imports `_write_query_payload`, `_clean_output_dir`, `build_conversion_report`. Facade preserves names (D-15). Synthetic-logs script is NOT modified in Phase 6.
- `scripts/convert_sentinel_kql.py` ↔ `queries/sentinel_conversion_report.json`: report schema gains `tier_distribution` block and per-candidate `tier`. `scripts/sentinel_drift_check.py` does not exist yet (Phase 10); the new fields are additive and do not break Phase 8/10 baselines.
- `scripts/release_checklist.py` ↔ Phase 6: release checklist must still pass after Phase 6 lands (success criterion #4 in ROADMAP). The new pytest gate (D-14) is exercised by `release_checklist.py`'s test-suite invocation.
- `pyproject.toml` / `requirements.txt` / `requirements-dev.txt`: runtime requirements unchanged (locked in STATE decisions log). `requirements-dev.txt` is created/modified to include exactly `pytest>=8.3` and `hypothesis>=6.150` (Claude discretion above; consistent with REF-04).

</code_context>

<specifics>
## Specific Ideas

- Canonicalizer output **must round-trip the 8 currently-promoted query bodies into byte-identical canonical form** (success criterion #2). The 8 promoted slugs are the reference corpus and the source of truth for "no semantic loss."
- Logan QL quoting in the corpus is **uniform single-quote**: both field-names-with-spaces (`'Log Source'`) and string literals (`'Windows Security Events'`). The canonicalizer normalizes any double-quote variants encountered to single-quote.
- The CanonicalizationError exception (D-04) is named exactly `CanonicalizationError` (not `CanonicalError` / `KqlCanonicalError`) — matches the function name `canonical()` for easy grep.
- `Tier` enum members are exactly `TIER_1`, `TIER_2`, `TIER_3` (uppercase with underscore) so the report JSON uses `tier_1` / `tier_2` / `tier_3` keys after lowercase serialization — consistent with the project's snake_case JSON convention.
- Legacy adapter file is `scripts/kql/operators/_legacy.py` (leading underscore signals throwaway); deleted by the final extraction PR.

</specifics>

<deferred>
## Deferred Ideas

- **Commutative reorder in canonicalizer** — `a == b` ↔ `b == a` swap. Useful when Phase 9 operators emit literals on either side; revisit when concrete brittleness shows up in operator-coverage fixture diffs.
- **AND-chain sort in canonicalizer** — sort top-level AND clauses in a `where`. Requires filter-purity analysis; defer unless tests prove brittle.
- **Logan keyword case-folding** — lowercase `where`, `stats`, `eval`, `count` while preserving field-name case. Defer.
- **Logan-side AST + separate emitter pass** — D-06 chose string fragments. Revisit if multi-stage operators (Phase 9 `extend` chains, `bin → timestats`) make string composition painful.
- **TIER-3 skip-reason synthetic fixtures** — one per known unsupported feature (`parse_command_line`, `mv-expand`, `geo_*`, cross-table `join`, `evaluate plugin`). Belongs in Phase 9 alongside the operators that touch them.
- **Live OCI binding parity check** — confirming `canonical(promoted_body)` binds in OCI just like `promoted_body`. Belongs in Phase 9/10 alongside live-validation enhancements.
- **`release_checklist.py` line-budget gate** — Phase 11 owns release-gate evolution.
- **`coverage` / `pytest-cov` / `pytest-xdist` in requirements-dev.txt** — explicit Claude-discretion deferral; add if Phase 9 demands it.
- **AST-based code-lines measurement** — D-14 uses plain `wc -l`. Refine only if the simple measure causes false alarms.

</deferred>

---

*Phase: 6-kql-subpackage-extraction-and-canonicalizer*
*Context gathered: 2026-05-15*
