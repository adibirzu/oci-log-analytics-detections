---
phase: 06-kql-subpackage-extraction-and-canonicalizer
plan: 10
type: execute
wave: 3
depends_on: ["06-02", "06-03", "06-04", "06-05", "06-06", "06-07", "06-08", "06-09"]
files_modified:
  - scripts/convert_sentinel_kql.py
  - scripts/kql/operators/_legacy.py
  - scripts/kql/operators/__init__.py
  - scripts/kql/pipeline.py
  - scripts/test_kql/test_module_size.py
  - STATUS.md
  - README.md
autonomous: false

requirements:
  - REF-01
  - REF-02
  - REF-03
  - REF-04
  - REF-05

must_haves:
  truths:
    - "scripts/convert_sentinel_kql.py is <= 800 lines."
    - "scripts/kql/operators/_legacy.py does NOT exist."
    - "scripts/test_kql/test_module_size.py does NOT contain @pytest.mark.xfail."
    - "scripts/kql/pipeline.py dispatches through OPERATOR_REGISTRY rather than delegating to legacy convert_kql_to_logan."
    - "All 35 tests in scripts/test_sentinel_converter.py still pass."
    - "All scripts/test_kql/ tests pass without xfail tolerance."
    - "The 8 promoted Sentinel query bodies are byte-identical to the prior commit (and to the pre-Phase-6 baseline)."
    - "STATUS.md and README.md counts reconcile with queries/catalog.json."
  artifacts:
    - path: scripts/convert_sentinel_kql.py
      provides: "facade re-exporting D-15 symbol set; legacy operator helpers removed"
      contains: "__all__"
    - path: scripts/kql/pipeline.py
      provides: "convert() dispatches through OPERATOR_REGISTRY (legacy delegation removed)"
      contains: "OPERATOR_REGISTRY"
    - path: scripts/test_kql/test_module_size.py
      provides: "line-budget gate, no longer xfailed"
  key_links:
    - from: scripts/kql/pipeline.py
      to: scripts/kql/operators/
      via: "pipeline.convert dispatches each stage through OPERATOR_REGISTRY[stage.kind]"
      pattern: "OPERATOR_REGISTRY\\["
---

<objective>
Close out Phase 6: shrink `scripts/convert_sentinel_kql.py` to a ≤800-line facade by deleting operator helpers that no longer have callers, delete `scripts/kql/operators/_legacy.py` entirely, rewire `scripts/kql/pipeline.py` to dispatch through the registry instead of delegating to legacy, remove the `xfail(strict=True)` from the module-size gate, run the full Phase 6 verification sequence including a byte-identical check on the 8 promoted artifacts, and reconcile STATUS.md / README.md counts.

Purpose: This is the moment the line-budget gate flips from xfail to PASS. After this plan, the next phase (07 mapping shards) can build on a clean subpackage with no legacy fallback path.

Output: Cleaned-up facade, deleted legacy adapters, registry-driven pipeline, removed xfail, reconciled docs, final regression evidence.
</objective>

<execution_context>
@$HOME/.claude/get-shit-done/workflows/execute-plan.md
@$HOME/.claude/get-shit-done/templates/summary.md
@$HOME/.claude/get-shit-done/references/checkpoints.md
</execution_context>

<context>
@.planning/PROJECT.md
@.planning/ROADMAP.md
@.planning/STATE.md
@.planning/REQUIREMENTS.md
@.planning/phases/06-kql-subpackage-extraction-and-canonicalizer/06-CONTEXT.md
@.planning/phases/06-kql-subpackage-extraction-and-canonicalizer/06-01-SUMMARY.md
@.planning/phases/06-kql-subpackage-extraction-and-canonicalizer/06-02-SUMMARY.md
@.planning/phases/06-kql-subpackage-extraction-and-canonicalizer/06-03-SUMMARY.md
@.planning/phases/06-kql-subpackage-extraction-and-canonicalizer/06-04-SUMMARY.md
@.planning/phases/06-kql-subpackage-extraction-and-canonicalizer/06-05-SUMMARY.md
@.planning/phases/06-kql-subpackage-extraction-and-canonicalizer/06-06-SUMMARY.md
@.planning/phases/06-kql-subpackage-extraction-and-canonicalizer/06-07-SUMMARY.md
@.planning/phases/06-kql-subpackage-extraction-and-canonicalizer/06-08-SUMMARY.md
@.planning/phases/06-kql-subpackage-extraction-and-canonicalizer/06-09-SUMMARY.md
@scripts/convert_sentinel_kql.py
@scripts/kql/pipeline.py
@scripts/kql/operators/__init__.py
</context>

<tasks>

<task type="auto">
  <name>Task 1: Rewire pipeline.convert to dispatch through OPERATOR_REGISTRY</name>
  <files>scripts/kql/pipeline.py</files>
  <read_first>scripts/kql/pipeline.py, scripts/kql/operators/__init__.py, scripts/convert_sentinel_kql.py</read_first>
  <action>
    Replace the legacy delegation in `pipeline.convert` with a real dispatch loop:
    1. Split the input via `scripts.kql.lexer.split_kql_stages(kql)`.
    2. Pre-process let bindings (still flows through legacy `_preprocess_simple_lets` for Phase 6 per plan 06-09).
    3. For each stage, parse the kind (first token: `where`, `summarize`, `project`, etc.) and the body (everything after).
    4. Build `KqlStage(kind=kind, body=body)`.
    5. Look up `OPERATOR_REGISTRY[kind]`; if missing, append a Tier-3 skip reason `f"unsupported_operator:{kind}"` and continue.
    6. Call the operator with the current `ConversionContext`; collect `fragments`, accumulate `skip_reasons`, fold `new_aliases` into a fresh ConversionContext for the next stage (D-08 immutability).
    7. Join collected fragments with ` | ` and prepend the source filter (existing helper `_legacy._source_filter_for_tables`).
    8. Return `(joined_logan_qql, mapping_used, all_errors)` matching the legacy `convert_kql_to_logan` signature.
    Cross-check: every promoted query must still convert to a byte-identical Logan QL body when run through the new pipeline. Compare BEFORE deleting any legacy code — write a one-shot script `scripts/test_kql/compare_promoted.py` that re-runs conversion on each promoted candidate via the new pipeline AND via legacy `convert_kql_to_logan`, asserting equality. Only proceed to Task 2 (deletion) after compare_promoted exits 0 for all 8 slugs.
  </action>
  <verify>python scripts/test_kql/compare_promoted.py &amp;&amp; python -m pytest scripts/test_sentinel_converter.py -q</verify>
  <acceptance_criteria>
    - scripts/kql/pipeline.py contains "OPERATOR_REGISTRY[" (or "OPERATOR_REGISTRY.get(")
    - scripts/kql/pipeline.py does NOT contain "convert_kql_to_logan" any more (no legacy delegation)
    - scripts/test_kql/compare_promoted.py exists and exits 0 (legacy vs new pipeline produce byte-identical output for all 8 promoted slugs)
    - python -m pytest scripts/test_sentinel_converter.py -q exits 0 (after pipeline rewire — convert_kql_to_logan inside the legacy module can now point to pipeline.convert or stay independent; tests must pass either way)
  </acceptance_criteria>
  <done>pipeline.convert dispatches through registry; behavior parity proven on the 8 promoted slugs.</done>
</task>

<task type="auto">
  <name>Task 2: Delete scripts/kql/operators/_legacy.py</name>
  <files>scripts/kql/operators/_legacy.py, scripts/kql/operators/__init__.py</files>
  <read_first>scripts/kql/operators/_legacy.py, scripts/kql/operators/__init__.py</read_first>
  <action>
    By this point every operator family (where, summarize, project/fields, extend, sort/order, top, distinct, union, let) has its own module under `scripts/kql/operators/`. The `_legacy.py` adapter file should now contain only the registrations for the never-extracted "unsupported" operators (take, count, limit, parse, evaluate, mv-expand, make-series, join, render). For those: instead of keeping `_legacy.py`, fold them into a single short `scripts/kql/operators/unsupported_op.py` module that registers each with a function returning `StageResult(fragments=(), tier=Tier.TIER_3, skip_reasons=("unsupported_in_phase_6",))`. Then delete `scripts/kql/operators/_legacy.py` entirely (`git rm`). Update `scripts/kql/operators/__init__.py` — replace `from . import _legacy` with `from . import unsupported_op`. The intent is enforced: `grep -r "from . import _legacy" scripts/kql/` returns nothing, and `find scripts/kql -name _legacy.py` returns nothing.
  </action>
  <verify>! test -e scripts/kql/operators/_legacy.py &amp;&amp; test -e scripts/kql/operators/unsupported_op.py &amp;&amp; python -c "from scripts.kql.operators import OPERATOR_REGISTRY; assert len(OPERATOR_REGISTRY) >= 9"</verify>
  <acceptance_criteria>
    - scripts/kql/operators/_legacy.py does NOT exist (git rm completed)
    - scripts/kql/operators/unsupported_op.py exists and contains "Tier.TIER_3" + "@register("
    - scripts/kql/operators/__init__.py does NOT contain "from . import _legacy"
    - scripts/kql/operators/__init__.py contains "from . import unsupported_op"
    - OPERATOR_REGISTRY contains entries for the unsupported-set operators (take, count, limit, parse, etc.) all returning Tier-3
  </acceptance_criteria>
  <done>Legacy adapter file deleted; unsupported operators consolidated into one short Tier-3 module.</done>
</task>

<task type="auto">
  <name>Task 3: Shrink scripts/convert_sentinel_kql.py to <=800 lines</name>
  <files>scripts/convert_sentinel_kql.py</files>
  <read_first>scripts/convert_sentinel_kql.py, scripts/kql/operators/, scripts/kql/pipeline.py</read_first>
  <action>
    Identify functions in `scripts/convert_sentinel_kql.py` that are now only called by `pipeline.convert` and the extracted operator modules — these helpers can move OUT of the facade into the appropriate kql subpackage modules. Candidate moves:
      - `_convert_summarize` (line ~920) → `scripts/kql/operators/summarize_op.py` (inline into convert_summarize as a private helper, no facade re-export needed)
      - `_convert_sort` (~968), `_convert_top` (~979) → `scripts/kql/operators/sort_op.py`
      - `_convert_extend` (~993) → `scripts/kql/operators/extend_op.py`
      - `_convert_fields_clause` (~833) → `scripts/kql/operators/project_op.py`
      - `convert_predicate` (~712), `_cleanup_boolean_expression` (~687), `_remove_time_filters` (~700) → `scripts/kql/operators/where_op.py` (kept private to the module)
      - `_split_kql_stages` (~489) → `scripts/kql/lexer.py` (real implementation, not a delegation)
      - `_strip_string_literals` (~257), `_strip_single_quoted_literals` (~262), `_strip_kql_comments` (~287), `_find_top_level_semicolon` (~327) → `scripts/kql/lexer.py` (shared low-level helpers)
      - `_preprocess_simple_lets` (~434), `_normalize_simple_let_expression` (~353), `_replace_unquoted_variables` (~393) → `scripts/kql/operators/let_op.py`
      - `_source_filter_for_tables` (~558), `_clean_table_name` (~537), `extract_source_tables` (~545) → `scripts/kql/pipeline.py` or a new `scripts/kql/source_filter.py`
    Re-export every name still listed in `__all__` so external callers (`sentinel_synthetic_logs.py`, `sentinel_conversion_workflow.py`) remain unbroken — the facade contains `from scripts.kql.pipeline import convert as convert_kql_to_logan` plus shim re-exports for the I/O helpers (`_write_query_payload`, `_clean_output_dir`, `build_conversion_report`) which can stay in the facade since they are not operator-related. After the moves, count lines: `wc -l scripts/convert_sentinel_kql.py` must be ≤ 800. If it is still over, identify the largest remaining function and move it. Do not delete `__all__` — keep the D-15 surface intact.
  </action>
  <verify>wc -l scripts/convert_sentinel_kql.py | awk '{exit !($1 <= 800)}' &amp;&amp; python -c "import sys; sys.path.insert(0,'scripts'); from convert_sentinel_kql import ConversionResult, _clean_output_dir, _write_query_payload, build_conversion_report, classify_unsupported_kql, convert_candidate, convert_candidates, convert_kql_to_logan, load_mapping_config, rank_candidates, select_top_candidates, slugify_title, validate_logan_query_local"</verify>
  <acceptance_criteria>
    - wc -l scripts/convert_sentinel_kql.py reports a value <= 800
    - scripts/convert_sentinel_kql.py still defines or re-exports every name in __all__
    - python imports of the D-15 symbol set from the facade still succeed
  </acceptance_criteria>
  <done>Facade is ≤ 800 lines and still satisfies the D-15 surface contract.</done>
</task>

<task type="auto">
  <name>Task 4: Remove xfail from test_module_size.py; verify the gate passes</name>
  <files>scripts/test_kql/test_module_size.py</files>
  <read_first>scripts/test_kql/test_module_size.py, scripts/convert_sentinel_kql.py</read_first>
  <action>
    Delete the `@pytest.mark.xfail(strict=True, reason="...")` decorator from `test_facade_under_line_limit`. The test must now pass cleanly. If it does NOT pass, Task 3 left the facade over 800 lines and must be re-done. Update the module docstring to reflect that migration is complete: "Module-size gate. Phase 6 migration is complete; xfail removed in plan 06-10."
  </action>
  <verify>! grep -q "@pytest.mark.xfail" scripts/test_kql/test_module_size.py &amp;&amp; python -m pytest scripts/test_kql/test_module_size.py -q</verify>
  <acceptance_criteria>
    - scripts/test_kql/test_module_size.py does NOT contain "@pytest.mark.xfail"
    - scripts/test_kql/test_module_size.py contains "Phase 6 migration is complete"
    - python -m pytest scripts/test_kql/test_module_size.py -q exits 0 (passes, not xfailed)
  </acceptance_criteria>
  <done>Line-budget gate is a plain PASS.</done>
</task>

<task type="auto">
  <name>Task 5: Byte-identical check on the 8 promoted artifacts</name>
  <files>(verification only)</files>
  <read_first>queries/sentinel/</files>
  <action>
    Compare every `queries/sentinel/*.json` to its content at the pre-Phase-6 baseline. Use the merge-base of `main` and the current Phase 6 branch (or the commit hash at the start of Phase 6 — the user can supply if branch is rebased). Specifically:
    `git diff <pre-phase-6-commit> -- queries/sentinel/ | head -200` must show ZERO functional changes to `query_body` fields. Whitespace-only diffs in metadata fields are tolerated, but the actual converted Logan QL bodies MUST be byte-identical. Also run `python scripts/test_kql/compare_promoted.py` once more (from Task 1) — it must still exit 0. If any drift surfaces here, Phase 6 has accidentally changed converter output; STOP and diagnose before declaring complete.
  </action>
  <verify>python scripts/test_kql/compare_promoted.py</verify>
  <acceptance_criteria>
    - python scripts/test_kql/compare_promoted.py exits 0
    - For every promoted slug, the canonical form of its current query_body equals the canonical form recorded in scripts/test_kql/fixtures/expected/<slug>.logan (i.e. no drift)
  </acceptance_criteria>
  <done>Promoted artifacts proven byte-identical through canonical equivalence.</done>
</task>

<task type="auto">
  <name>Task 6: Reconcile STATUS.md and README.md counts</name>
  <files>STATUS.md, README.md</files>
  <read_first>queries/catalog.json, STATUS.md, README.md, CATALOG.md, .planning/STATE.md</read_first>
  <action>
    Re-run `python scripts/generate_catalog.py` to refresh `queries/catalog.json` and `CATALOG.md`. Phase 6 should NOT change query counts (no new queries, no removed queries). Confirm by comparing `catalog.json` before vs after — `summary` block must be identical except for any timestamp field. Then read STATUS.md and README.md for any count strings (e.g. "X Sentinel queries promoted"); confirm they still match catalog.json. If they don't, the drift is a pre-existing issue unrelated to Phase 6 — note it in the SUMMARY but do NOT fix in this plan (out of scope; CLAUDE.md hard rule #6 reconciliation belongs to the team that introduces the drift). Run `python scripts/release_checklist.py` and confirm it passes.
  </action>
  <verify>python scripts/release_checklist.py</verify>
  <acceptance_criteria>
    - queries/catalog.json summary counts are unchanged from the pre-Phase-6 baseline
    - python scripts/release_checklist.py exits 0
    - STATUS.md and README.md counts match catalog.json (or pre-existing drift is documented in SUMMARY without being silently fixed)
  </acceptance_criteria>
  <done>Counts reconciled or pre-existing drift documented; release checklist green.</done>
</task>

<task type="auto">
  <name>Task 7: Final Phase 6 verification matrix</name>
  <files>(verification only)</files>
  <read_first>scripts/test_sentinel_converter.py, scripts/test_kql/</files>
  <action>
    Run the final Phase 6 verification matrix:
    1. `python -m pytest scripts/test_sentinel_converter.py scripts/test_kql/ -q` — exits 0 (35 + ~25 new tests all pass)
    2. `wc -l scripts/convert_sentinel_kql.py` — ≤ 800
    3. `[ ! -e scripts/kql/operators/_legacy.py ]` — file gone
    4. `! grep -q "@pytest.mark.xfail" scripts/test_kql/test_module_size.py` — no xfail
    5. `python -c "from scripts.kql.operators import OPERATOR_REGISTRY; assert len(OPERATOR_REGISTRY) >= 9"` — registry populated
    6. `python -c "import json; r = json.load(open('queries/sentinel_conversion_report.json')); assert 'tier_distribution' in r['summary']; assert all('tier' in c for c in r.get('candidates', []))"` — schema bumped
    7. `python scripts/release_checklist.py` — exits 0
    8. `python scripts/test_kql/compare_promoted.py` — exits 0 (byte-identical)
    9. `[ -z "$(git diff --stat queries/sentinel/)" ]` — promoted bodies unchanged on disk
    Any failure = Phase 6 not complete; fix in this plan or split a follow-up.
  </action>
  <verify>python -m pytest scripts/test_sentinel_converter.py scripts/test_kql/ -q &amp;&amp; python scripts/release_checklist.py &amp;&amp; python scripts/test_kql/compare_promoted.py &amp;&amp; [ -z "$(git diff --stat queries/sentinel/)" ]</verify>
  <acceptance_criteria>
    - All 9 verification commands above exit 0 / produce expected output
    - Phase 6 success criteria from .planning/ROADMAP.md are observably met
  </acceptance_criteria>
  <done>Phase 6 verification matrix fully green.</done>
</task>

<task type="checkpoint:human-verify" gate="blocking">
  <what-built>
    Phase 6 complete: scripts/convert_sentinel_kql.py is now a ≤800-line facade; scripts/kql/ subpackage holds all operators registered through OPERATOR_REGISTRY; canonical() + idempotence property + 18 fixture snapshots + module-size gate all green; 8 promoted artifacts byte-identical; tier_distribution + per-candidate tier in sentinel_conversion_report.json.
  </what-built>
  <how-to-verify>
    1. `wc -l scripts/convert_sentinel_kql.py` shows ≤ 800.
    2. `find scripts/kql -name _legacy.py` is empty.
    3. `python -m pytest scripts/test_sentinel_converter.py scripts/test_kql/ -q` exits 0.
    4. `git diff <pre-phase-6-commit> -- queries/sentinel/` shows no functional changes to promoted query bodies.
    5. Review the new subpackage structure under `scripts/kql/` and confirm it matches `.planning/research/ARCHITECTURE.md`.
  </how-to-verify>
  <resume-signal>Type "approved" or describe issues / drift.</resume-signal>
</task>

</tasks>

<verification>
- [ ] `wc -l scripts/convert_sentinel_kql.py` ≤ 800
- [ ] `scripts/kql/operators/_legacy.py` deleted
- [ ] `pipeline.convert` dispatches through OPERATOR_REGISTRY (no legacy delegation)
- [ ] `test_module_size.py` no longer marked xfail
- [ ] All 35 converter tests + all scripts/test_kql/ tests pass
- [ ] Promoted query bodies byte-identical (compare_promoted exits 0)
- [ ] `release_checklist.py` exits 0
- [ ] STATUS / README counts reconcile with `queries/catalog.json`
- [ ] User approves the checkpoint
</verification>

<success_criteria>
- All 7 tasks completed
- Checkpoint approved
- Phase 6 success criteria from ROADMAP.md observably met:
  1. `scripts/convert_sentinel_kql.py` is a thin facade over `scripts/kql/` (REF-01)
  2. Canonicalizer + idempotence test green (REF-02)
  3. Tier classifier in conversion report (REF-03)
  4. `requirements-dev.txt` adds pytest + hypothesis; `scripts/test_kql/` mirrors subpackage (REF-04)
  5. `scripts/test_sentinel_converter.py` stays green (REF-05)
- The 8 promoted Sentinel artifacts are byte-identical to the pre-Phase-6 baseline
</success_criteria>

<output>
After completion, create `.planning/phases/06-kql-subpackage-extraction-and-canonicalizer/06-10-SUMMARY.md`
</output>
