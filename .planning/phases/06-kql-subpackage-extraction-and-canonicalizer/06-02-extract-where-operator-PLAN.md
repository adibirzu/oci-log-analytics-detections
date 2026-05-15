---
phase: 06-kql-subpackage-extraction-and-canonicalizer
plan: 02
type: execute
wave: 2
depends_on: ["06-01"]
files_modified:
  - scripts/kql/operators/where_op.py
  - scripts/kql/operators/_legacy.py
  - scripts/kql/pipeline.py
  - scripts/test_kql/fixtures/kql/where_basic.kql
  - scripts/test_kql/fixtures/kql/where_string_ops.kql
  - scripts/test_kql/fixtures/expected/where_basic.logan
  - scripts/test_kql/fixtures/expected/where_string_ops.logan
  - scripts/test_kql/test_where_operator.py
autonomous: true
requirements:
  - REF-01
  - REF-05

must_haves:
  truths:
    - "scripts.kql.operators.where_op.convert_where is a pure function returning StageResult."
    - "OPERATOR_REGISTRY['where'] resolves to convert_where, NOT the legacy adapter shim."
    - "All 35 tests in scripts/test_sentinel_converter.py still pass after extraction."
    - "where_basic and where_string_ops fixtures round-trip through canonical() and match the snapshot."
  artifacts:
    - path: scripts/kql/operators/where_op.py
      provides: "convert_where(stage, ctx) -> StageResult"
      contains: "@register(\"where\")"
      min_lines: 30
    - path: scripts/test_kql/test_where_operator.py
      provides: "operator-level unit tests for where extraction"
  key_links:
    - from: scripts/kql/pipeline.py
      to: scripts/kql/operators/where_op.py
      via: "pipeline.convert dispatches 'where' stages through OPERATOR_REGISTRY"
      pattern: "OPERATOR_REGISTRY\\[.where.\\]"
---

<objective>
Extract the `where` operator (including string-op variants `like`, `contains`, `startswith`, `endswith`) from the inline legacy converter into a dedicated `scripts/kql/operators/where_op.py` module registered through `OPERATOR_REGISTRY`. Replace the `_legacy.py` adapter for `where` with a real implementation; keep every existing test green and the promoted query bodies byte-identical.

Purpose: First real operator extraction; sets the template for 06-03..06-09. Validates the registry dispatch path end-to-end against the existing 35-test regression suite and the where_basic/where_string_ops golden fixtures.

Output: New operator module, refreshed registry entry, operator-level test file, updated where_string_ops fixture if the extraction surfaces a missed edge case.
</objective>

<execution_context>
@$HOME/.claude/get-shit-done/workflows/execute-plan.md
@$HOME/.claude/get-shit-done/templates/summary.md
</execution_context>

<context>
@.planning/PROJECT.md
@.planning/ROADMAP.md
@.planning/STATE.md
@.planning/phases/06-kql-subpackage-extraction-and-canonicalizer/06-CONTEXT.md
@.planning/phases/06-kql-subpackage-extraction-and-canonicalizer/06-01-SUMMARY.md
@scripts/convert_sentinel_kql.py
@scripts/kql/operators/_legacy.py
@scripts/kql/pipeline.py
@scripts/kql/operators/__init__.py
@scripts/kql/types.py
</context>

<tasks>

<task type="auto">
  <name>Task 1: Implement scripts/kql/operators/where_op.py</name>
  <files>scripts/kql/operators/where_op.py</files>
  <read_first>scripts/convert_sentinel_kql.py, scripts/kql/types.py, scripts/kql/operators/_legacy.py</read_first>
  <action>
    Identify every `where`-related helper in `scripts/convert_sentinel_kql.py`: `convert_predicate` (line ~712), `_cleanup_boolean_expression` (~687), `_remove_time_filters` (~700), `_format_value`/`_literal_value`/`_format_value_for_field` (~651..683), `_strip_string_literals`/`_strip_single_quoted_literals` (~257..286). These functions are CALLED from where stages but most are shared across operators; the where_op module should IMPORT them from the facade (`from scripts import convert_sentinel_kql as _legacy`) rather than copy them. That keeps Phase 6 minimal — only the dispatch glue moves.

    Write `scripts/kql/operators/where_op.py`:
    ```
    from scripts.kql.operators import register
    from scripts.kql.types import KqlStage, ConversionContext, StageResult, Tier
    from scripts import convert_sentinel_kql as _legacy

    @register("where")
    def convert_where(stage: KqlStage, ctx: ConversionContext) -> StageResult:
        # stage.body is the post-"where" predicate text (e.g. "EventID == 4624 and Process =~ '.*\\\\\\\\powershell\\\\.exe'")
        errors: list[str] = []
        allowed = set(ctx.allowed_aliases)
        fragment = _legacy.convert_predicate(stage.body, ctx.mapping, errors, allowed)
        # Tier-1 if the predicate converted cleanly; Tier-3 if errors flagged it as unsupported.
        skip_reasons = tuple(errors)
        tier = Tier.TIER_3 if skip_reasons else Tier.TIER_1
        fragments = (f"where {fragment}",) if fragment else ()
        return StageResult(fragments=fragments, tier=tier, skip_reasons=skip_reasons, new_aliases=())
    ```
    String-ops (`like`, `contains`, `startswith`, `endswith`) flow through `convert_predicate` already; no separate function. Adjust the signature lookup if `convert_predicate` returns a different shape (`tuple[str, list[str]]` vs plain `str`) — read its actual return type and adapt.
  </action>
  <verify>python -c "from scripts.kql.operators import OPERATOR_REGISTRY; from scripts.kql.types import KqlStage, ConversionContext; ctx = ConversionContext(mapping={}, allowed_aliases=frozenset(), dictionary_fields=frozenset(), log_source_tables=()); r = OPERATOR_REGISTRY['where'](KqlStage(kind='where', body=\"EventID == 4624\"), ctx); print(r.fragments, r.tier)"</verify>
  <acceptance_criteria>
    - scripts/kql/operators/where_op.py contains "@register(\"where\")"
    - scripts/kql/operators/where_op.py contains "def convert_where("
    - scripts/kql/operators/where_op.py contains "StageResult"
    - scripts/kql/operators/where_op.py imports from scripts.kql.types AND scripts.kql.operators (register)
    - python -c "from scripts.kql.operators.where_op import convert_where; from scripts.kql.types import StageResult; assert callable(convert_where)" exits 0
  </acceptance_criteria>
  <done>convert_where exists as a pure function returning StageResult; registry dispatch points to it.</done>
</task>

<task type="auto">
  <name>Task 2: Remove the where legacy adapter; ensure registry points to the real function</name>
  <files>scripts/kql/operators/_legacy.py, scripts/kql/operators/__init__.py</files>
  <read_first>scripts/kql/operators/_legacy.py, scripts/kql/operators/__init__.py, scripts/kql/operators/where_op.py</read_first>
  <action>
    In `scripts/kql/operators/_legacy.py`, delete the `@register("where")` adapter function entirely. Add an import at the bottom of `scripts/kql/operators/__init__.py` (or whatever module imports `_legacy`) to ALSO import `where_op` so its `@register` runs at package import time: `from . import where_op  # noqa: F401`. Order matters: `where_op` must be imported AFTER `_legacy` so its `@register("where")` overwrites the legacy entry (or simpler: drop the legacy entry first, then where_op claims it cleanly). Verify the registry now points to the real `convert_where`:
    `python -c "from scripts.kql.operators import OPERATOR_REGISTRY; from scripts.kql.operators import where_op; assert OPERATOR_REGISTRY['where'] is where_op.convert_where"`
  </action>
  <verify>python -c "from scripts.kql.operators import OPERATOR_REGISTRY, where_op; assert OPERATOR_REGISTRY['where'] is where_op.convert_where"</verify>
  <acceptance_criteria>
    - scripts/kql/operators/_legacy.py does NOT contain "@register(\"where\")" any more
    - scripts/kql/operators/__init__.py contains "from . import where_op"
    - python -c "from scripts.kql.operators import OPERATOR_REGISTRY, where_op; assert OPERATOR_REGISTRY['where'] is where_op.convert_where" exits 0
  </acceptance_criteria>
  <done>Registry resolves 'where' to the real extracted function, not the legacy shim.</done>
</task>

<task type="auto">
  <name>Task 3: Operator-level tests + fixture validation</name>
  <files>scripts/test_kql/test_where_operator.py</files>
  <read_first>scripts/kql/operators/where_op.py, scripts/kql/canonical.py, scripts/test_kql/fixtures/kql/where_basic.kql, scripts/test_kql/fixtures/kql/where_string_ops.kql</read_first>
  <action>
    Write `scripts/test_kql/test_where_operator.py` with at least these tests:
    1. `test_simple_equality` — convert_where on `KqlStage(kind="where", body="EventID == 4624")` returns `StageResult.tier == Tier.TIER_1` and `fragments[0]` contains `"where"` and `"4624"`.
    2. `test_string_ops_like_contains_startswith` — convert_where on `"Process =~ '.*powershell.*' and CommandLine has 'invoke' and User startswith 'admin'"` returns `tier == Tier.TIER_1` (no skip_reasons).
    3. `test_unsupported_returns_tier3` — convert_where on a body using a clearly unsupported feature (e.g. `'parse_command_line(x)'` if classify_unsupported_kql flags it) returns `tier == Tier.TIER_3` with non-empty `skip_reasons`.
    4. `test_registry_resolves_to_extracted_fn` — `OPERATOR_REGISTRY['where']` is `where_op.convert_where` (regression-fence against accidental re-registration of legacy shim).
    5. `test_fixture_round_trip` — `canonical(open('scripts/test_kql/fixtures/kql/where_basic.kql').read())` equals `open('scripts/test_kql/fixtures/expected/where_basic.logan').read()`. Same for where_string_ops.
  </action>
  <verify>python -m pytest scripts/test_kql/test_where_operator.py -q</verify>
  <acceptance_criteria>
    - scripts/test_kql/test_where_operator.py contains "test_registry_resolves_to_extracted_fn"
    - scripts/test_kql/test_where_operator.py contains "test_fixture_round_trip"
    - scripts/test_kql/test_where_operator.py contains "Tier.TIER_1"
    - scripts/test_kql/test_where_operator.py contains "Tier.TIER_3"
    - python -m pytest scripts/test_kql/test_where_operator.py -q exits 0
  </acceptance_criteria>
  <done>Operator tests cover happy path + Tier-3 + registry binding + fixture round-trip; all green.</done>
</task>

<task type="auto">
  <name>Task 4: Full regression — legacy tests + new kql tests both green; promoted bodies byte-identical</name>
  <files>(verification only)</files>
  <read_first>scripts/test_sentinel_converter.py, queries/sentinel/, scripts/test_kql/</files>
  <action>
    1. `python -m pytest scripts/test_sentinel_converter.py scripts/test_kql/ -q` — must exit 0.
    2. `git diff --stat queries/sentinel/` — empty.
    3. `python scripts/release_checklist.py` — exits 0.
    If any test fails, the extraction broke behavior — revert the dispatch and diagnose before declaring complete.
  </action>
  <verify>python -m pytest scripts/test_sentinel_converter.py scripts/test_kql/ -q &amp;&amp; [ -z "$(git diff --stat queries/sentinel/)" ]</verify>
  <acceptance_criteria>
    - python -m pytest scripts/test_sentinel_converter.py scripts/test_kql/ -q exits 0
    - git diff queries/sentinel/ is empty
    - python scripts/release_checklist.py exits 0
  </acceptance_criteria>
  <done>Behavior-preserving extraction confirmed.</done>
</task>

</tasks>

<verification>
- [ ] `python -m pytest scripts/test_sentinel_converter.py scripts/test_kql/ -q` exits 0
- [ ] `git diff queries/sentinel/` is empty
- [ ] `OPERATOR_REGISTRY['where']` resolves to `where_op.convert_where`
- [ ] `python scripts/release_checklist.py` passes
</verification>

<success_criteria>
- where operator extracted to scripts/kql/operators/where_op.py
- Legacy adapter for 'where' removed from _legacy.py
- Registry dispatches to extracted function
- Operator-level tests pass; full regression green
- The 8 promoted query bodies unchanged
</success_criteria>

<output>
After completion, create `.planning/phases/06-kql-subpackage-extraction-and-canonicalizer/06-02-SUMMARY.md`
</output>
