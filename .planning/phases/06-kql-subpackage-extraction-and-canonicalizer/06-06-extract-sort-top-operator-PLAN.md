---
phase: 06-kql-subpackage-extraction-and-canonicalizer
plan: 06
type: execute
wave: 2
depends_on: ["06-01"]
files_modified:
  - scripts/kql/operators/sort_op.py
  - scripts/kql/operators/_legacy.py
  - scripts/kql/operators/__init__.py
  - scripts/test_kql/test_sort_top_operator.py
autonomous: true
requirements:
  - REF-01
  - REF-05

must_haves:
  truths:
    - "scripts.kql.operators.sort_op exposes convert_sort AND convert_top (kept together because Logan QL emits top as 'sort | head' or 'top' depending on legacy path)."
    - "OPERATOR_REGISTRY['sort'] resolves to convert_sort; OPERATOR_REGISTRY['order'] resolves to convert_sort (KQL alias)."
    - "OPERATOR_REGISTRY['top'] resolves to convert_top."
    - "All 35 tests in scripts/test_sentinel_converter.py still pass."
    - "sort_basic and top_basic fixtures round-trip through canonical() and match the snapshots."
  artifacts:
    - path: scripts/kql/operators/sort_op.py
      provides: "convert_sort + convert_top in one module"
      contains: "@register(\"sort\")"
---

<objective>
Extract `sort`/`order` and `top` together — both deal with ordering and are small (~10 lines each in the legacy converter). One module, two functions, three registry entries (sort, order, top).
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
  <name>Task 1: Implement sort_op with convert_sort + convert_top</name>
  <files>scripts/kql/operators/sort_op.py</files>
  <read_first>scripts/convert_sentinel_kql.py, scripts/kql/operators/where_op.py</read_first>
  <action>
    Legacy helpers: `_convert_sort` at scripts/convert_sentinel_kql.py:968 and `_convert_top` at :979. Wrap each per the where_op template. Register sort under both `"sort"` and `"order"` (KQL `order by` is a synonym for `sort by`). Register top under `"top"`.
    ```
    @register("sort")
    @register("order")
    def convert_sort(stage, ctx): ...

    @register("top")
    def convert_top(stage, ctx): ...
    ```
    Note: stacking two `@register` decorators on the same function works because both push the same callable into the registry under different keys. Verify the decorator returns the function (it does in the spec — see plan 06-01 Task 1).
  </action>
  <verify>python -c "from scripts.kql.operators.sort_op import convert_sort, convert_top; assert callable(convert_sort) and callable(convert_top)"</verify>
  <acceptance_criteria>
    - scripts/kql/operators/sort_op.py contains "@register(\"sort\")"
    - scripts/kql/operators/sort_op.py contains "@register(\"order\")"
    - scripts/kql/operators/sort_op.py contains "@register(\"top\")"
    - scripts/kql/operators/sort_op.py contains "def convert_sort(" AND "def convert_top("
  </acceptance_criteria>
  <done>convert_sort and convert_top registered under three keys.</done>
</task>

<task type="auto">
  <name>Task 2: Remove sort/order/top legacy adapters; wire registry</name>
  <files>scripts/kql/operators/_legacy.py, scripts/kql/operators/__init__.py</files>
  <read_first>scripts/kql/operators/_legacy.py</read_first>
  <action>Delete `@register("sort")`, `@register("order")` (if present), `@register("top")` from `_legacy.py`. Add `from . import sort_op  # noqa: F401` to operators/__init__.py.</action>
  <verify>python -c "from scripts.kql.operators import OPERATOR_REGISTRY, sort_op; assert OPERATOR_REGISTRY['sort'] is sort_op.convert_sort; assert OPERATOR_REGISTRY['top'] is sort_op.convert_top"</verify>
  <acceptance_criteria>
    - scripts/kql/operators/_legacy.py contains none of "@register(\"sort\")", "@register(\"top\")", "@register(\"order\")"
    - OPERATOR_REGISTRY['sort'] is sort_op.convert_sort
    - OPERATOR_REGISTRY['top'] is sort_op.convert_top
  </acceptance_criteria>
  <done>Registry dispatches all three.</done>
</task>

<task type="auto">
  <name>Task 3: Operator tests + fixtures</name>
  <files>scripts/test_kql/test_sort_top_operator.py</files>
  <read_first>scripts/kql/operators/sort_op.py, scripts/test_kql/fixtures/kql/sort_basic.kql, scripts/test_kql/fixtures/kql/top_basic.kql</read_first>
  <action>Tests: sort asc/desc, top with limit, top by alias, registry triple-binding regression-fence, fixture round-trip for both sort_basic and top_basic.</action>
  <verify>python -m pytest scripts/test_kql/test_sort_top_operator.py -q</verify>
  <acceptance_criteria>
    - scripts/test_kql/test_sort_top_operator.py contains "sort_op.convert_sort"
    - scripts/test_kql/test_sort_top_operator.py contains "sort_op.convert_top"
    - python -m pytest scripts/test_kql/test_sort_top_operator.py -q exits 0
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
- [ ] sort, order, top all dispatch through scripts.kql.operators.sort_op
- [ ] All 35 converter tests still pass
- [ ] Promoted bodies byte-identical
</verification>

<success_criteria>
- sort + order + top extracted into one cohesive module
- Behavior preserving
</success_criteria>

<output>
After completion, create `.planning/phases/06-kql-subpackage-extraction-and-canonicalizer/06-06-SUMMARY.md`
</output>
