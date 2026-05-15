---
phase: 06-kql-subpackage-extraction-and-canonicalizer
plan: 05
type: execute
wave: 2
depends_on: ["06-01"]
files_modified:
  - scripts/kql/operators/extend_op.py
  - scripts/kql/operators/_legacy.py
  - scripts/kql/operators/__init__.py
  - scripts/test_kql/test_extend_operator.py
autonomous: true
requirements:
  - REF-01
  - REF-05

must_haves:
  truths:
    - "scripts.kql.operators.extend_op.convert_extend is a pure function returning StageResult."
    - "OPERATOR_REGISTRY['extend'] resolves to convert_extend, not the legacy shim."
    - "convert_extend returns StageResult.new_aliases reflecting columns introduced by extend (downstream stages can reference them)."
    - "All 35 tests in scripts/test_sentinel_converter.py still pass."
    - "extend_iff_basic fixture round-trips through canonical() and matches the snapshot."
  artifacts:
    - path: scripts/kql/operators/extend_op.py
      provides: "convert_extend(stage, ctx) -> StageResult with new_aliases"
      contains: "@register(\"extend\")"
      min_lines: 30
    - path: scripts/test_kql/test_extend_operator.py
      provides: "operator-level tests including alias propagation"
---

<objective>
Extract `extend` (basic alias assignment, including `iff()`/conditional shapes already supported) into `scripts/kql/operators/extend_op.py`. Critical: `extend` introduces new column aliases that downstream `where`/`project`/`summarize` stages reference. The StageResult.new_aliases field MUST capture them so the pipeline can thread a fresh ConversionContext into the next stage (D-08).
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
  <name>Task 1: Implement extend_op.convert_extend with alias propagation</name>
  <files>scripts/kql/operators/extend_op.py</files>
  <read_first>scripts/convert_sentinel_kql.py, scripts/kql/types.py, scripts/kql/operators/where_op.py</read_first>
  <action>
    Legacy helper: `_convert_extend(stage, mapping, allowed_aliases)` at scripts/convert_sentinel_kql.py:993. Returns `tuple[list[str], list[str], set[str]]` per the existing signature — likely (fragments, errors, new_aliases). Read the function to confirm. Write:
    ```
    from scripts.kql.operators import register
    from scripts.kql.types import KqlStage, ConversionContext, StageResult, Tier
    from scripts import convert_sentinel_kql as _legacy

    @register("extend")
    def convert_extend(stage: KqlStage, ctx: ConversionContext) -> StageResult:
        allowed = set(ctx.allowed_aliases)
        fragments_list, errors, added_aliases = _legacy._convert_extend(f"extend {stage.body}", ctx.mapping, allowed)
        skip_reasons = tuple(errors)
        tier = Tier.TIER_3 if skip_reasons else Tier.TIER_1
        new_aliases = tuple(sorted(added_aliases - ctx.allowed_aliases))
        return StageResult(fragments=tuple(fragments_list), tier=tier, skip_reasons=skip_reasons, new_aliases=new_aliases)
    ```
    Adapt the destructuring to whatever `_convert_extend` actually returns.
  </action>
  <verify>python -c "from scripts.kql.operators.extend_op import convert_extend; assert callable(convert_extend)"</verify>
  <acceptance_criteria>
    - scripts/kql/operators/extend_op.py contains "@register(\"extend\")"
    - scripts/kql/operators/extend_op.py contains "new_aliases"
    - scripts/kql/operators/extend_op.py contains "def convert_extend("
  </acceptance_criteria>
  <done>convert_extend registered; propagates new_aliases on StageResult.</done>
</task>

<task type="auto">
  <name>Task 2: Remove extend legacy adapter; wire registry</name>
  <files>scripts/kql/operators/_legacy.py, scripts/kql/operators/__init__.py</files>
  <read_first>scripts/kql/operators/_legacy.py</read_first>
  <action>Delete `@register("extend")` from `_legacy.py`. Add `from . import extend_op  # noqa: F401` to operators/__init__.py.</action>
  <verify>python -c "from scripts.kql.operators import OPERATOR_REGISTRY, extend_op; assert OPERATOR_REGISTRY['extend'] is extend_op.convert_extend"</verify>
  <acceptance_criteria>
    - scripts/kql/operators/_legacy.py does NOT contain "@register(\"extend\")"
    - scripts/kql/operators/__init__.py contains "from . import extend_op"
    - OPERATOR_REGISTRY['extend'] is extend_op.convert_extend
  </acceptance_criteria>
  <done>Registry dispatches extend.</done>
</task>

<task type="auto">
  <name>Task 3: Operator tests + alias propagation + fixture round-trip</name>
  <files>scripts/test_kql/test_extend_operator.py</files>
  <read_first>scripts/kql/operators/extend_op.py, scripts/test_kql/fixtures/kql/extend_iff_basic.kql</read_first>
  <action>
    Tests: simple alias `extend Foo = ColumnA` produces `new_aliases == ('Foo',)`; `iff()` conditional produces Tier-1; Tier-3 on unsupported function (e.g. `extend X = bag_keys(Y)` if classify_unsupported flags bag_keys); registry binding regression-fence; fixture round-trip for extend_iff_basic.
  </action>
  <verify>python -m pytest scripts/test_kql/test_extend_operator.py -q</verify>
  <acceptance_criteria>
    - scripts/test_kql/test_extend_operator.py contains "new_aliases"
    - scripts/test_kql/test_extend_operator.py contains "extend_op.convert_extend"
    - python -m pytest scripts/test_kql/test_extend_operator.py -q exits 0
  </acceptance_criteria>
  <done>Operator tests green including alias propagation.</done>
</task>

<task type="auto">
  <name>Task 4: Full regression</name>
  <files>(verification only)</files>
  <read_first>scripts/test_sentinel_converter.py</read_first>
  <action>Run `python -m pytest scripts/test_sentinel_converter.py scripts/test_kql/ -q`; confirm `git diff queries/sentinel/` is empty.</action>
  <verify>python -m pytest scripts/test_sentinel_converter.py scripts/test_kql/ -q &amp;&amp; [ -z "$(git diff --stat queries/sentinel/)" ]</verify>
  <acceptance_criteria>
    - python -m pytest scripts/test_sentinel_converter.py scripts/test_kql/ -q exits 0
    - git diff queries/sentinel/ is empty
  </acceptance_criteria>
  <done>Behavior preserved.</done>
</task>

</tasks>

<verification>
- [ ] OPERATOR_REGISTRY['extend'] resolves to extend_op.convert_extend
- [ ] StageResult.new_aliases populated on extend stages
- [ ] All 35 converter tests still pass
- [ ] Promoted bodies byte-identical
</verification>

<success_criteria>
- extend extracted with alias propagation
- Behavior preserving
</success_criteria>

<output>
After completion, create `.planning/phases/06-kql-subpackage-extraction-and-canonicalizer/06-05-SUMMARY.md`
</output>
