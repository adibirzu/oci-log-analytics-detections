---
phase: 06-kql-subpackage-extraction-and-canonicalizer
plan: 04
type: execute
wave: 2
depends_on: ["06-01"]
files_modified:
  - scripts/kql/operators/project_op.py
  - scripts/kql/operators/_legacy.py
  - scripts/kql/operators/__init__.py
  - scripts/test_kql/test_project_operator.py
autonomous: true
requirements:
  - REF-01
  - REF-05

must_haves:
  truths:
    - "scripts.kql.operators.project_op.convert_project is a pure function returning StageResult."
    - "OPERATOR_REGISTRY['project'] resolves to convert_project, not the legacy shim."
    - "OPERATOR_REGISTRY['fields'] also resolves to convert_project (Logan QL emits 'fields' for KQL 'project')."
    - "All 35 tests in scripts/test_sentinel_converter.py still pass."
    - "project_basic fixture round-trips through canonical() and matches the snapshot."
  artifacts:
    - path: scripts/kql/operators/project_op.py
      provides: "convert_project(stage, ctx) -> StageResult"
      contains: "@register(\"project\")"
      min_lines: 25
    - path: scripts/test_kql/test_project_operator.py
      provides: "operator-level unit tests"
---

<objective>
Extract `project` (and the related `project-away`/`project-keep`/`fields` family) into `scripts/kql/operators/project_op.py`. The legacy helper is `_convert_fields_clause` at scripts/convert_sentinel_kql.py:833.
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
  <name>Task 1: Implement project_op.convert_project</name>
  <files>scripts/kql/operators/project_op.py</files>
  <read_first>scripts/convert_sentinel_kql.py, scripts/kql/operators/where_op.py</read_first>
  <action>
    Wrap `_legacy._convert_fields_clause` per the where_op template. Read the legacy function signature (~line 833) and adapt the call shape. Register BOTH `@register("project")` and `@register("fields")` on the same convert_project — Logan QL accepts both spellings and the registry should dispatch them identically. Tier-1 on success, Tier-3 if errors list is non-empty.
  </action>
  <verify>python -c "from scripts.kql.operators.project_op import convert_project; assert callable(convert_project)"</verify>
  <acceptance_criteria>
    - scripts/kql/operators/project_op.py contains "@register(\"project\")"
    - scripts/kql/operators/project_op.py contains "@register(\"fields\")"
    - scripts/kql/operators/project_op.py contains "def convert_project("
  </acceptance_criteria>
  <done>convert_project registered under both 'project' and 'fields'.</done>
</task>

<task type="auto">
  <name>Task 2: Remove project and fields legacy adapters; wire registry</name>
  <files>scripts/kql/operators/_legacy.py, scripts/kql/operators/__init__.py</files>
  <read_first>scripts/kql/operators/_legacy.py</read_first>
  <action>
    Delete `@register("project")` AND `@register("fields")` from `_legacy.py`. Add `from . import project_op  # noqa: F401` to `scripts/kql/operators/__init__.py`.
  </action>
  <verify>python -c "from scripts.kql.operators import OPERATOR_REGISTRY, project_op; assert OPERATOR_REGISTRY['project'] is project_op.convert_project; assert OPERATOR_REGISTRY['fields'] is project_op.convert_project"</verify>
  <acceptance_criteria>
    - scripts/kql/operators/_legacy.py contains neither "@register(\"project\")" nor "@register(\"fields\")"
    - OPERATOR_REGISTRY['project'] is project_op.convert_project
    - OPERATOR_REGISTRY['fields'] is project_op.convert_project
  </acceptance_criteria>
  <done>Registry dispatches both project and fields through extracted module.</done>
</task>

<task type="auto">
  <name>Task 3: Operator tests + fixture round-trip</name>
  <files>scripts/test_kql/test_project_operator.py</files>
  <read_first>scripts/kql/operators/project_op.py, scripts/test_kql/fixtures/kql/project_basic.kql</read_first>
  <action>
    Tests: simple project list, project with rename (e.g. `project NewName = OldName`), Tier-3 on a field not in mapping, dual-registry binding (project and fields both resolve to convert_project), fixture round-trip for project_basic.
  </action>
  <verify>python -m pytest scripts/test_kql/test_project_operator.py -q</verify>
  <acceptance_criteria>
    - scripts/test_kql/test_project_operator.py contains "project_op.convert_project"
    - scripts/test_kql/test_project_operator.py contains "OPERATOR_REGISTRY['fields']"
    - python -m pytest scripts/test_kql/test_project_operator.py -q exits 0
  </acceptance_criteria>
  <done>Operator tests green; registry double-binding verified.</done>
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
- [ ] OPERATOR_REGISTRY['project'] and ['fields'] both resolve to project_op.convert_project
- [ ] All 35 converter tests still pass
- [ ] Promoted bodies byte-identical
</verification>

<success_criteria>
- project + fields extracted under one function, registered twice
- Behavior preserving
</success_criteria>

<output>
After completion, create `.planning/phases/06-kql-subpackage-extraction-and-canonicalizer/06-04-SUMMARY.md`
</output>
