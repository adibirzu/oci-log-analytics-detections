---
phase: 06-kql-subpackage-extraction-and-canonicalizer
plan: 07
type: execute
wave: 2
depends_on: ["06-01"]
files_modified:
  - scripts/kql/operators/distinct_op.py
  - scripts/kql/operators/_legacy.py
  - scripts/kql/operators/__init__.py
  - scripts/test_kql/test_distinct_operator.py
autonomous: true
requirements:
  - REF-01
  - REF-05

must_haves:
  truths:
    - "scripts.kql.operators.distinct_op.convert_distinct is a pure function returning StageResult."
    - "OPERATOR_REGISTRY['distinct'] resolves to convert_distinct, not the legacy shim."
    - "All 35 tests in scripts/test_sentinel_converter.py still pass."
    - "distinct_basic fixture round-trips through canonical() and matches the snapshot."
  artifacts:
    - path: scripts/kql/operators/distinct_op.py
      provides: "convert_distinct(stage, ctx) -> StageResult"
      contains: "@register(\"distinct\")"
---

<objective>
Extract `distinct` into `scripts/kql/operators/distinct_op.py`. Logan QL maps `distinct A, B, C` to `dedup A, B, C` (or similar — confirm by reading the legacy path).
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
  <name>Task 1: Implement distinct_op.convert_distinct</name>
  <files>scripts/kql/operators/distinct_op.py</files>
  <read_first>scripts/convert_sentinel_kql.py, scripts/kql/operators/where_op.py</read_first>
  <action>
    Find the legacy distinct handling in `convert_kql_to_logan` (scripts/convert_sentinel_kql.py:1018) — search for the substring `"distinct"` to locate the branch (likely inline rather than its own helper). If inline, extract the field-list handling into a small helper `_format_distinct(body, mapping, allowed)` inside `distinct_op.py` rather than touching the legacy file. Wrap per the where_op template. Tier-1 if all fields are in the mapping/dictionary/aliases; Tier-3 if any field is unknown.
  </action>
  <verify>python -c "from scripts.kql.operators.distinct_op import convert_distinct; assert callable(convert_distinct)"</verify>
  <acceptance_criteria>
    - scripts/kql/operators/distinct_op.py contains "@register(\"distinct\")"
    - scripts/kql/operators/distinct_op.py contains "def convert_distinct("
  </acceptance_criteria>
  <done>convert_distinct registered.</done>
</task>

<task type="auto">
  <name>Task 2: Remove distinct legacy adapter; wire registry</name>
  <files>scripts/kql/operators/_legacy.py, scripts/kql/operators/__init__.py</files>
  <read_first>scripts/kql/operators/_legacy.py</read_first>
  <action>Delete `@register("distinct")` from `_legacy.py`. Add `from . import distinct_op  # noqa: F401` to operators/__init__.py.</action>
  <verify>python -c "from scripts.kql.operators import OPERATOR_REGISTRY, distinct_op; assert OPERATOR_REGISTRY['distinct'] is distinct_op.convert_distinct"</verify>
  <acceptance_criteria>
    - scripts/kql/operators/_legacy.py does NOT contain "@register(\"distinct\")"
    - OPERATOR_REGISTRY['distinct'] is distinct_op.convert_distinct
  </acceptance_criteria>
  <done>Registry dispatches distinct.</done>
</task>

<task type="auto">
  <name>Task 3: Operator tests + fixture round-trip</name>
  <files>scripts/test_kql/test_distinct_operator.py</files>
  <read_first>scripts/kql/operators/distinct_op.py, scripts/test_kql/fixtures/kql/distinct_basic.kql</read_first>
  <action>Tests: single-field distinct, multi-field distinct, Tier-3 on unknown field, registry binding regression-fence, fixture round-trip for distinct_basic.</action>
  <verify>python -m pytest scripts/test_kql/test_distinct_operator.py -q</verify>
  <acceptance_criteria>
    - scripts/test_kql/test_distinct_operator.py contains "distinct_op.convert_distinct"
    - python -m pytest scripts/test_kql/test_distinct_operator.py -q exits 0
  </acceptance_criteria>
  <done>Operator tests green.</done>
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
- [ ] OPERATOR_REGISTRY['distinct'] resolves to distinct_op.convert_distinct
- [ ] All 35 converter tests still pass
- [ ] Promoted bodies byte-identical
</verification>

<success_criteria>
- distinct extracted
- Behavior preserving
</success_criteria>

<output>
After completion, create `.planning/phases/06-kql-subpackage-extraction-and-canonicalizer/06-07-SUMMARY.md`
</output>
