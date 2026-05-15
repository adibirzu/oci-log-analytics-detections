---
phase: 06-kql-subpackage-extraction-and-canonicalizer
plan: 03
type: execute
wave: 2
depends_on: ["06-01"]
files_modified:
  - scripts/kql/operators/summarize_op.py
  - scripts/kql/operators/_legacy.py
  - scripts/kql/operators/__init__.py
  - scripts/test_kql/test_summarize_operator.py
autonomous: true
requirements:
  - REF-01
  - REF-05

must_haves:
  truths:
    - "scripts.kql.operators.summarize_op.convert_summarize is a pure function returning StageResult."
    - "OPERATOR_REGISTRY['summarize'] resolves to convert_summarize, not the legacy shim."
    - "All 35 tests in scripts/test_sentinel_converter.py still pass."
    - "summarize_count_by fixture round-trips through canonical() and matches the snapshot."
  artifacts:
    - path: scripts/kql/operators/summarize_op.py
      provides: "convert_summarize(stage, ctx) -> StageResult"
      contains: "@register(\"summarize\")"
      min_lines: 25
    - path: scripts/test_kql/test_summarize_operator.py
      provides: "operator-level unit tests"
  key_links:
    - from: scripts/kql/operators/__init__.py
      to: scripts/kql/operators/summarize_op.py
      via: "from . import summarize_op"
      pattern: "summarize_op"
---

<objective>
Extract the `summarize` operator (including count + by-clause variants) from inline legacy converter into `scripts/kql/operators/summarize_op.py`. Behavior-preserving — wraps the legacy `_convert_summarize` helper.
</objective>

<execution_context>
@$HOME/.claude/get-shit-done/workflows/execute-plan.md
@$HOME/.claude/get-shit-done/templates/summary.md
</execution_context>

<context>
@.planning/phases/06-kql-subpackage-extraction-and-canonicalizer/06-CONTEXT.md
@.planning/phases/06-kql-subpackage-extraction-and-canonicalizer/06-01-SUMMARY.md
@scripts/convert_sentinel_kql.py
@scripts/kql/operators/where_op.py
</context>

<tasks>

<task type="auto">
  <name>Task 1: Implement summarize_op.convert_summarize</name>
  <files>scripts/kql/operators/summarize_op.py</files>
  <read_first>scripts/convert_sentinel_kql.py, scripts/kql/operators/where_op.py, scripts/kql/types.py</read_first>
  <action>
    Mirror the where_op pattern. The legacy helper is `_convert_summarize(stage, mapping, errors, allowed_aliases)` at scripts/convert_sentinel_kql.py:920. Write:
    ```
    from scripts.kql.operators import register
    from scripts.kql.types import KqlStage, ConversionContext, StageResult, Tier
    from scripts import convert_sentinel_kql as _legacy

    @register("summarize")
    def convert_summarize(stage: KqlStage, ctx: ConversionContext) -> StageResult:
        errors: list[str] = []
        allowed = set(ctx.allowed_aliases)
        fragment = _legacy._convert_summarize(f"summarize {stage.body}", ctx.mapping, errors, allowed)
        skip_reasons = tuple(errors)
        tier = Tier.TIER_3 if skip_reasons else Tier.TIER_1
        fragments = (fragment,) if isinstance(fragment, str) and fragment else tuple(fragment or ())
        new_aliases = tuple(a for a in allowed if a not in ctx.allowed_aliases)
        return StageResult(fragments=fragments, tier=tier, skip_reasons=skip_reasons, new_aliases=new_aliases)
    ```
    Adapt the call shape after reading `_convert_summarize`'s actual signature and return type (the legacy function may take the full "summarize ..." string or just the body; check first ~30 lines of the function).
  </action>
  <verify>python -c "from scripts.kql.operators.summarize_op import convert_summarize; assert callable(convert_summarize)"</verify>
  <acceptance_criteria>
    - scripts/kql/operators/summarize_op.py contains "@register(\"summarize\")"
    - scripts/kql/operators/summarize_op.py contains "def convert_summarize("
    - scripts/kql/operators/summarize_op.py imports StageResult, Tier, KqlStage, ConversionContext
  </acceptance_criteria>
  <done>convert_summarize is callable and registered.</done>
</task>

<task type="auto">
  <name>Task 2: Remove the summarize legacy adapter; wire registry to extracted function</name>
  <files>scripts/kql/operators/_legacy.py, scripts/kql/operators/__init__.py</files>
  <read_first>scripts/kql/operators/_legacy.py, scripts/kql/operators/__init__.py</read_first>
  <action>
    Delete `@register("summarize")` adapter from `_legacy.py`. Add `from . import summarize_op  # noqa: F401` to `scripts/kql/operators/__init__.py` (place it AFTER the `from . import _legacy` line so `summarize_op` claims the registry slot cleanly).
  </action>
  <verify>python -c "from scripts.kql.operators import OPERATOR_REGISTRY, summarize_op; assert OPERATOR_REGISTRY['summarize'] is summarize_op.convert_summarize"</verify>
  <acceptance_criteria>
    - scripts/kql/operators/_legacy.py does NOT contain "@register(\"summarize\")"
    - scripts/kql/operators/__init__.py contains "from . import summarize_op"
    - OPERATOR_REGISTRY['summarize'] is summarize_op.convert_summarize
  </acceptance_criteria>
  <done>Registry dispatches summarize through extracted module.</done>
</task>

<task type="auto">
  <name>Task 3: Operator tests + fixture validation</name>
  <files>scripts/test_kql/test_summarize_operator.py</files>
  <read_first>scripts/kql/operators/summarize_op.py, scripts/test_kql/fixtures/kql/summarize_count_by.kql</read_first>
  <action>
    Tests: count happy path, count-by with alias, Tier-3 on unsupported aggregate (e.g. `percentile`), registry binding regression-fence, fixture round-trip for summarize_count_by.
  </action>
  <verify>python -m pytest scripts/test_kql/test_summarize_operator.py -q</verify>
  <acceptance_criteria>
    - scripts/test_kql/test_summarize_operator.py contains "summarize_op.convert_summarize"
    - scripts/test_kql/test_summarize_operator.py contains "fixtures/kql/summarize_count_by.kql"
    - python -m pytest scripts/test_kql/test_summarize_operator.py -q exits 0
  </acceptance_criteria>
  <done>Operator tests green.</done>
</task>

<task type="auto">
  <name>Task 4: Full regression</name>
  <files>(verification only)</files>
  <read_first>scripts/test_sentinel_converter.py</read_first>
  <action>Run `python -m pytest scripts/test_sentinel_converter.py scripts/test_kql/ -q` and confirm `git diff queries/sentinel/` is empty.</action>
  <verify>python -m pytest scripts/test_sentinel_converter.py scripts/test_kql/ -q &amp;&amp; [ -z "$(git diff --stat queries/sentinel/)" ]</verify>
  <acceptance_criteria>
    - python -m pytest scripts/test_sentinel_converter.py scripts/test_kql/ -q exits 0
    - git diff queries/sentinel/ is empty
  </acceptance_criteria>
  <done>Behavior preserved.</done>
</task>

</tasks>

<verification>
- [ ] All 35 converter tests still pass
- [ ] OPERATOR_REGISTRY['summarize'] resolves to summarize_op.convert_summarize
- [ ] Promoted bodies byte-identical
</verification>

<success_criteria>
- summarize extracted, registered, tested
- Behavior preserving
</success_criteria>

<output>
After completion, create `.planning/phases/06-kql-subpackage-extraction-and-canonicalizer/06-03-SUMMARY.md`
</output>
