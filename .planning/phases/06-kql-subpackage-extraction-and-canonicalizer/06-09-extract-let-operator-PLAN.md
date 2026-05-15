---
phase: 06-kql-subpackage-extraction-and-canonicalizer
plan: 09
type: execute
wave: 2
depends_on: ["06-01"]
files_modified:
  - scripts/kql/operators/let_op.py
  - scripts/kql/operators/_legacy.py
  - scripts/kql/operators/__init__.py
  - scripts/test_kql/test_let_operator.py
autonomous: true
requirements:
  - REF-01
  - REF-05

must_haves:
  truths:
    - "scripts.kql.operators.let_op.convert_let is a pure function returning StageResult."
    - "OPERATOR_REGISTRY['let'] resolves to convert_let, not the legacy shim."
    - "convert_let returns Tier.TIER_1 for scalar let bindings (the only kind currently supported); Tier.TIER_3 for tabular let or function-shaped let."
    - "All 35 tests in scripts/test_sentinel_converter.py still pass."
    - "let_scalar fixture round-trips through canonical() and matches the snapshot."
  artifacts:
    - path: scripts/kql/operators/let_op.py
      provides: "convert_let(stage, ctx) -> StageResult"
      contains: "@register(\"let\")"
---

<objective>
Extract `let` (scalar bindings only; tabular and function-shaped lets remain Tier-3 SKIPPED). Wraps the legacy `_preprocess_simple_lets` (scripts/convert_sentinel_kql.py:434) and `_normalize_simple_let_expression` (~:353) into a registry-dispatched operator. Closes out the per-operator extraction wave before the facade cutover (06-10).
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
  <name>Task 1: Implement let_op.convert_let</name>
  <files>scripts/kql/operators/let_op.py</files>
  <read_first>scripts/convert_sentinel_kql.py, scripts/kql/operators/where_op.py, scripts/kql/types.py</read_first>
  <action>
    Re-read `_preprocess_simple_lets` and `_normalize_simple_let_expression`. `let` is special: it doesn't emit a stage fragment of its own — it rewrites downstream identifiers. The wrapper must reflect that: convert_let returns `StageResult(fragments=(), tier=TIER_1, skip_reasons=(), new_aliases=())` for a successful scalar binding, AND attaches the substitution as part of new_aliases or via a side-channel. For Phase 6 minimal scope: call `_legacy._normalize_simple_let_expression(f"let {stage.body}")` and check the return — if it returns a string (the normalized form), Tier-1 with `fragments=()`; if it returns None (unsupported), Tier-3 with skip_reasons=("let_unsupported_shape",). The actual substitution wiring stays in legacy `convert_kql_to_logan` for Phase 6 — this plan only extracts the dispatch surface. Document this in a module docstring: "Phase 6 dispatch shim. Substitution semantics still flow through legacy _preprocess_simple_lets; pipeline.convert delegates to legacy for end-to-end. Phase 7+ refactors substitution into ConversionContext."
  </action>
  <verify>python -c "from scripts.kql.operators.let_op import convert_let; assert callable(convert_let)"</verify>
  <acceptance_criteria>
    - scripts/kql/operators/let_op.py contains "@register(\"let\")"
    - scripts/kql/operators/let_op.py contains "def convert_let("
    - scripts/kql/operators/let_op.py contains "Phase 6 dispatch shim"
  </acceptance_criteria>
  <done>convert_let registered; documented as dispatch-only shim with substitution staying in legacy.</done>
</task>

<task type="auto">
  <name>Task 2: Remove let legacy adapter; wire registry</name>
  <files>scripts/kql/operators/_legacy.py, scripts/kql/operators/__init__.py</files>
  <read_first>scripts/kql/operators/_legacy.py</read_first>
  <action>Delete `@register("let")` from `_legacy.py`. Add `from . import let_op  # noqa: F401` to operators/__init__.py.</action>
  <verify>python -c "from scripts.kql.operators import OPERATOR_REGISTRY, let_op; assert OPERATOR_REGISTRY['let'] is let_op.convert_let"</verify>
  <acceptance_criteria>
    - scripts/kql/operators/_legacy.py does NOT contain "@register(\"let\")"
    - OPERATOR_REGISTRY['let'] is let_op.convert_let
  </acceptance_criteria>
  <done>Registry dispatches let.</done>
</task>

<task type="auto">
  <name>Task 3: Operator tests + fixture round-trip</name>
  <files>scripts/test_kql/test_let_operator.py</files>
  <read_first>scripts/kql/operators/let_op.py, scripts/test_kql/fixtures/kql/let_scalar.kql</read_first>
  <action>Tests: scalar let returns Tier-1; tabular let (e.g. `let T = SecurityEvent | where ...`) returns Tier-3; registry binding regression-fence; fixture round-trip for let_scalar.</action>
  <verify>python -m pytest scripts/test_kql/test_let_operator.py -q</verify>
  <acceptance_criteria>
    - scripts/test_kql/test_let_operator.py contains "let_op.convert_let"
    - scripts/test_kql/test_let_operator.py contains "TIER_3"
    - python -m pytest scripts/test_kql/test_let_operator.py -q exits 0
  </acceptance_criteria>
  <done>Operator tests cover scalar + tabular tiers.</done>
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
- [ ] OPERATOR_REGISTRY['let'] resolves to let_op.convert_let
- [ ] All 35 converter tests still pass
- [ ] Promoted bodies byte-identical
</verification>

<success_criteria>
- let extracted as dispatch shim; substitution semantics intentionally deferred to Phase 7+
- Behavior preserving
</success_criteria>

<output>
After completion, create `.planning/phases/06-kql-subpackage-extraction-and-canonicalizer/06-09-SUMMARY.md`
</output>
