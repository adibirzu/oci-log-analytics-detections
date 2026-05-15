---
phase: 06-kql-subpackage-extraction-and-canonicalizer
plan: 08
type: execute
wave: 2
depends_on: ["06-01"]
files_modified:
  - scripts/kql/operators/union_op.py
  - scripts/kql/operators/_legacy.py
  - scripts/kql/operators/__init__.py
  - scripts/test_kql/test_union_operator.py
autonomous: true
requirements:
  - REF-01
  - REF-05

must_haves:
  truths:
    - "scripts.kql.operators.union_op.convert_union is a pure function returning StageResult."
    - "OPERATOR_REGISTRY['union'] resolves to convert_union, not the legacy shim."
    - "convert_union returns Tier.TIER_3 for cross-table unions that the converter currently does NOT support (preserves legacy skip behavior)."
    - "All 35 tests in scripts/test_sentinel_converter.py still pass."
    - "union_simple fixture round-trips through canonical() and matches the snapshot."
  artifacts:
    - path: scripts/kql/operators/union_op.py
      provides: "convert_union(stage, ctx) -> StageResult"
      contains: "@register(\"union\")"
---

<objective>
Extract `union` (simple same-table union; cross-table unions remain Tier-3 SKIPPED per PROJECT scope — not unlocked in Phase 6). Confirms the tier dispatch path correctly threads skip_reasons up into the per-candidate report.
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
  <name>Task 1: Implement union_op.convert_union</name>
  <files>scripts/kql/operators/union_op.py</files>
  <read_first>scripts/convert_sentinel_kql.py, scripts/kql/operators/where_op.py</read_first>
  <action>
    Search `scripts/convert_sentinel_kql.py` for `union` handling — locate the branch in `convert_kql_to_logan` (~line 1018) that emits the same-table union or skips cross-table. Wrap per the where_op template. If the legacy path returns a non-empty `errors` list for unsupported cross-table unions, the wrapper returns `tier=Tier.TIER_3, skip_reasons=tuple(errors), fragments=()`. Otherwise Tier-1.
  </action>
  <verify>python -c "from scripts.kql.operators.union_op import convert_union; assert callable(convert_union)"</verify>
  <acceptance_criteria>
    - scripts/kql/operators/union_op.py contains "@register(\"union\")"
    - scripts/kql/operators/union_op.py contains "def convert_union("
    - scripts/kql/operators/union_op.py contains "Tier.TIER_3"
  </acceptance_criteria>
  <done>convert_union registered; TIER_3 path explicit for unsupported variants.</done>
</task>

<task type="auto">
  <name>Task 2: Remove union legacy adapter; wire registry</name>
  <files>scripts/kql/operators/_legacy.py, scripts/kql/operators/__init__.py</files>
  <read_first>scripts/kql/operators/_legacy.py</read_first>
  <action>Delete `@register("union")` from `_legacy.py`. Add `from . import union_op  # noqa: F401` to operators/__init__.py.</action>
  <verify>python -c "from scripts.kql.operators import OPERATOR_REGISTRY, union_op; assert OPERATOR_REGISTRY['union'] is union_op.convert_union"</verify>
  <acceptance_criteria>
    - scripts/kql/operators/_legacy.py does NOT contain "@register(\"union\")"
    - OPERATOR_REGISTRY['union'] is union_op.convert_union
  </acceptance_criteria>
  <done>Registry dispatches union.</done>
</task>

<task type="auto">
  <name>Task 3: Operator tests + Tier-3 skip path + fixture round-trip</name>
  <files>scripts/test_kql/test_union_operator.py</files>
  <read_first>scripts/kql/operators/union_op.py, scripts/test_kql/fixtures/kql/union_simple.kql</read_first>
  <action>Tests: same-table union returns Tier-1 with non-empty fragments; cross-table union (e.g. `union T1, T2`) returns Tier-3 with non-empty skip_reasons and empty fragments; registry binding regression-fence; fixture round-trip for union_simple.</action>
  <verify>python -m pytest scripts/test_kql/test_union_operator.py -q</verify>
  <acceptance_criteria>
    - scripts/test_kql/test_union_operator.py contains "union_op.convert_union"
    - scripts/test_kql/test_union_operator.py contains "TIER_3"
    - python -m pytest scripts/test_kql/test_union_operator.py -q exits 0
  </acceptance_criteria>
  <done>Operator tests cover both tiers.</done>
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
- [ ] OPERATOR_REGISTRY['union'] resolves to union_op.convert_union
- [ ] Cross-table union returns Tier-3
- [ ] All 35 converter tests still pass
- [ ] Promoted bodies byte-identical
</verification>

<success_criteria>
- union extracted with explicit Tier-3 path for unsupported variants
- Behavior preserving
</success_criteria>

<output>
After completion, create `.planning/phases/06-kql-subpackage-extraction-and-canonicalizer/06-08-SUMMARY.md`
</output>
