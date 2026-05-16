# KQL → Logan QL conversion architecture (Phase 6+)

Read this file when you are extending the Sentinel converter, adding a new
operator, mapping a new KQL function, designing a different source-language
converter (e.g. Splunk SPL, Elastic ES|QL), or proposing changes that touch
`scripts/kql/**`, `scripts/convert_sentinel_kql.py`, or
`scripts/test_kql/**`.

The goals are:

- Predict where a piece of conversion logic should live.
- Preserve byte-identity on already-promoted artifacts.
- Stop the converter file from blowing past the 800-line ceiling again.
- Reuse the same scaffolding for other QL-to-Logan conversions.

## Package layout

```
scripts/
├── convert_sentinel_kql.py     # facade, ≤800 lines; CLI + I/O orchestration + re-exports
├── kql/
│   ├── __init__.py
│   ├── types.py                # Tier IntEnum, ConversionContext, StageResult,
│   │                           #   KqlStage, KqlPredicate (frozen dataclasses)
│   ├── canonical.py            # canonical() mini-tokenizer + CanonicalizationError
│   ├── lexer.py                # split_kql_stages (Phase 6 delegation; real impl later)
│   ├── ast_nodes.py            # re-exports KqlStage/KqlPredicate for ergonomic imports
│   ├── mapping_loader.py       # load_mapping() facade — sharded in Phase 7
│   ├── pipeline.py             # convert() entry point; routes through legacy in Phase 6
│   ├── emitter.py              # format_stage() helper for joining fragments
│   ├── _facade_impl.py         # Phase 6 cutover staging — legacy helpers relocated
│   │                           #   here verbatim; Phase 7+ redistributes into
│   │                           #   operator/lexer/validator modules
│   ├── operators/
│   │   ├── __init__.py         # OPERATOR_REGISTRY + @register decorator
│   │   ├── where_op.py
│   │   ├── summarize_op.py
│   │   ├── project_op.py
│   │   ├── extend_op.py
│   │   ├── sort_op.py
│   │   ├── distinct_op.py
│   │   ├── union_op.py
│   │   ├── let_op.py
│   │   └── unsupported_op.py   # Tier-3 stubs for take/count/limit/parse/evaluate/
│   │                           #   mv-expand/make-series/join/render
│   └── functions/__init__.py   # placeholder for future KQL function adapters
└── test_kql/
    ├── __init__.py
    ├── regen_promoted.py            # rewrite (or --check) the 8 promoted snapshots
    ├── test_canonical_idempotence.py
    ├── test_promoted_snapshots.py
    ├── test_module_size.py          # plain assertion: facade <= 800 lines
    ├── test_operators.py            # registry bindings + Tier-1 / Tier-3 per operator
    └── fixtures/
        ├── kql/                     # 8 promoted bodies + 10 synthetic operator fixtures
        └── expected/                # canonical(input) for every .kql file
```

## Decision rules: where does new conversion code go?

Use these prompts when adding or modifying conversion behavior:

1. **Is it stage splitting, comment stripping, or quote-aware tokenizing?**
   → `scripts/kql/lexer.py` (or the existing legacy helpers re-exported from
   `_facade_impl.py` in Phase 6). New low-level lexer work should land here.

2. **Is it a per-operator KQL → Logan rewrite (`where`, `summarize`, `project`, etc.)?**
   → `scripts/kql/operators/<op>_op.py`. The module exposes a single
   ``convert_<op>(stage: KqlStage, ctx: ConversionContext) -> StageResult``
   pure function decorated with ``@register("<op>")``.

3. **Is it a KQL function rewrite (`iff`, `bin`, `tostring`, etc.)?**
   → `scripts/kql/functions/<fn>.py`. The functions package mirrors the
   operators package — same registry pattern, smaller scope.

4. **Is it a field/source/table mapping rule?**
   → `config/sentinel_oci_mapping.yaml` is the allow-list; converter logic
   that reads it lives in `_facade_impl.py` (Phase 6) or
   `scripts/kql/field_mapper.py` (Phase 7+ destination). Never
   hard-code field translations in operator modules.

5. **Is it a Logan QL output validator?**
   → `validate_logan_query_local` (in `_facade_impl.py` today,
   `scripts/kql/validator.py` after Phase 7+). Pure-string assertions only;
   live OCI validation stays in `sentinel_conversion_workflow.py`.

6. **Is it I/O, ranking, payload building, or CLI orchestration?**
   → `scripts/convert_sentinel_kql.py` (the facade). This is where
   `convert_candidate`, `rank_candidates`, `build_query_payload`,
   `build_conversion_report`, `convert_candidates`, and `main()` live.

7. **Is it a CLI entry point or workflow command?**
   → `scripts/sentinel_conversion_workflow.py`. The workflow wraps the
   converter for operator commands (`local`, `promote`, `refresh-artifacts`,
   `page`, `triage`, `next-queries`, `status`). The converter never opens a
   network connection; the workflow does.

## Canonical form (`scripts/kql/canonical.py`)

`canonical(query: str) -> str` normalizes Logan QL output so converter
tests can assert on canonical form rather than exact byte equality. The
function is **idempotent** (`canonical(canonical(x)) == canonical(x)`) and
**deliberately narrow**: it only normalizes whitespace and quoting.

What it does:

- Collapses any whitespace run to a single space.
- Emits ` | ` (space-pipe-space) around stage separators.
- Re-emits every quoted string with single quotes (re-escaping interior
  single quotes to `''` per Logan QL convention).
- Strips leading/trailing whitespace.

What it does **not** do (deferred):

- Commutative reorder (`a == b` ↔ `b == a`).
- AND-chain sort.
- Keyword case-folding.

Errors:

- Raises `CanonicalizationError` on unterminated strings and unrecognized
  characters. There is no best-effort passthrough.

Use the canonicalizer when:

- Adding a new fixture: write the `.kql` input with messy whitespace and
  let `canonical()` produce the `.logan` expectation.
- Comparing pipeline output between the legacy entry and a new operator
  module (byte-identity).
- Detecting silent regressions: the property test
  (`test_canonical_idempotence.py`) generates 100 random Logan QL
  fragments per run and proves `canonical()` does not drift.

## Tier classification (`scripts.kql.types.Tier`)

Every operator returns a `StageResult.tier` from the `IntEnum` `Tier`:

| Tier | Meaning | Operator behavior |
|---|---|---|
| `TIER_1 = 1` | Lossless — exact semantic equivalent | Returns Logan fragments with no `skip_reasons`. |
| `TIER_2 = 2` | Transform with documented rewrite | Reserved for operators that emit different-but-equivalent Logan QL (no operator uses this yet — populates in Phase 7+ when mapping shards expose more rewrites). |
| `TIER_3 = 3` | Unsupported — SKIPPED with structured reason | Returns empty `fragments`, non-empty `skip_reasons`. |

Severity aggregates via `max(...)` because `Tier` is an `IntEnum`. The
conversion report (`queries/sentinel_conversion_report.json`) gains both
a `summary.tier_distribution` block and a `tier` field on every entry in
`attempted[]`. Use the per-candidate `tier` when ranking candidates for
the next conversion iteration.

## OPERATOR_REGISTRY pattern (the dispatch table)

Every operator module imports `@register` from `scripts.kql.operators` and
decorates its `convert_<op>` function:

```python
from . import register
from ..types import ConversionContext, KqlStage, StageResult, Tier


@register("where")
def convert_where(stage: KqlStage, ctx: ConversionContext) -> StageResult:
    ...
```

Multi-name registration is supported (`@register("sort")` then
`@register("order")` on the same function). The decorator simply inserts
the callable into `OPERATOR_REGISTRY: dict[str, OperatorFn]`.

This dispatch table is the canonical "what does this converter support?"
answer. To audit coverage:

```bash
python -c "from scripts.kql.operators import OPERATOR_REGISTRY; print(sorted(OPERATOR_REGISTRY))"
```

Phase 6 ships 21 registered operators (12 supported via extracted modules
+ 9 unsupported via `unsupported_op.py`).

## ConversionContext (immutable per-conversion state)

```python
@dataclass(frozen=True)
class ConversionContext:
    mapping: dict
    allowed_aliases: frozenset[str] = frozenset()
    dictionary_fields: frozenset[str] = frozenset()
    log_source_tables: tuple[str, ...] = ()
```

Rules:

- **No mutation.** Operators that introduce aliases (`extend`, `summarize`,
  `distinct`) return them in `StageResult.new_aliases`. The pipeline
  rebuilds a fresh `ConversionContext` for the next stage by folding the
  new aliases in.
- **No hidden state.** If you need shared knowledge between operators,
  add a field to `ConversionContext` — do not import a global.
- **Trivially testable.** Operators are pure functions; tests construct
  a context literal and call the function directly. See
  `scripts/test_kql/test_operators.py` for the pattern.

## Behavior-preserving refactor strategy

Use this sequence whenever you split a large converter file into smaller
modules. The 8 promoted Sentinel artifacts are the byte-identity safety
net — the same approach generalizes to any QL conversion where you have
a known-good corpus.

1. **Snapshot lock first.** Run `scripts/test_kql/regen_promoted.py` to
   write `canonical(query_body)` for every promoted artifact into
   `fixtures/expected/*.logan`. Wire `--check` into the test suite so any
   drift fails CI.
2. **Land the scaffolding.** Create the empty subpackage tree, types,
   canonicalizer, registry, and legacy adapter shims. Make the line-budget
   gate `xfail(strict=True)` so it flips to XPASS the moment you cross
   the threshold. **No behavior changes** in this commit.
3. **Iterate operator-by-operator.** One module per PR. Each PR:
   - Adds `scripts/kql/operators/<op>_op.py` with a thin wrapper around
     the legacy helper.
   - Removes the matching `@register("<op>")` line from the legacy
     adapter file.
   - Adds an operator-level test (registry binding + Tier-1 happy path
     + Tier-3 unsupported path + synthetic-fixture round-trip through
     `canonical()`).
   - Keeps the legacy test suite green throughout.
4. **Cutover at the end.** Delete the legacy adapter file. Optionally
   rewire the pipeline to dispatch through the registry (Phase 6 deferred
   this — see Phase 7). Remove the `xfail` mark. Verify byte-identity on
   the corpus one last time.

The strategy is documented operationally in
`.planning/phases/06-kql-subpackage-extraction-and-canonicalizer/` —
read those plans and SUMMARYs as the reference example.

## 800-line file ceiling

The CLAUDE.md hard rule is enforced by
`scripts/test_kql/test_module_size.py`. Counted with plain `wc -l`. When
the gate flips from xfail to XPASS during a refactor, the test author is
expected to remove the `@pytest.mark.xfail(strict=True)` decorator in
the same PR — `strict=True` is the cutover signal.

If a new feature pushes the facade past 800 lines:

- The right answer is almost always extraction, not raising the gate.
- The wrong answer is consolidating into "one big helper file" — use the
  decision rules above to pick the operator/function/validator module.
- If you genuinely need to raise the gate, document the reason in the
  test docstring and the relevant ROADMAP / SUMMARY artifact.

## Entry-point compatibility (Phase 6 lesson)

The facade must work for callers running it three different ways:

- `python scripts/convert_sentinel_kql.py …` (CLI, `scripts/` on sys.path)
- `python -m scripts.convert_sentinel_kql …` (module, project root on sys.path)
- `from scripts.convert_sentinel_kql import …` (library use)

Phase 6 broke the first form when the cutover added `from scripts.kql._facade_impl import ...`. The fix is the sys.path guard at the top of the facade:

```python
_FACADE_PATH = Path(__file__).resolve()
_SCRIPTS_DIR = _FACADE_PATH.parent
_PROJECT_ROOT = _SCRIPTS_DIR.parent
for _candidate in (_PROJECT_ROOT, _SCRIPTS_DIR):
    if str(_candidate) not in sys.path:
        sys.path.insert(0, str(_candidate))
```

After the guard, the facade uses absolute `from scripts.<module> import ...`
imports throughout. Direct callers of the legacy `from sync_sentinel_kql
import ...` style should migrate to `from scripts.sync_sentinel_kql
import ...` — the legacy form only works when `scripts/` is on `sys.path`
directly.

## Adapting this scaffolding to other QL conversions

When standing up a new converter (Splunk SPL, Elastic ES|QL, Sumo, etc.):

1. **Pick a small known-good corpus.** Conversion is a no-op until you can
   prove byte-identity on at least 5–10 real, hand-verified queries.
2. **Write the canonicalizer first.** Even narrow whitespace+quoting
   normalization saves you from flaky equality tests later. Reuse
   `scripts/kql/canonical.py` as the starting shape; the tokenizer rules
   are mostly portable.
3. **Stand up the registry-and-types skeleton.** Copy
   `scripts/kql/types.py` and `scripts/kql/operators/__init__.py` as
   templates. `Tier` and `ConversionContext` are language-agnostic.
4. **Author one operator per PR, behind a registry stub.** Lead with the
   most common operator in the source language so the registry
   immediately demonstrates value.
5. **Wire the same three tests per operator:** registry binding,
   Tier-1 happy path, Tier-3 unsupported path. Add a synthetic fixture
   per operator family and run it through your canonicalizer.
6. **Keep the file-size gate on from day one.** Even at xfail(strict=True),
   it forces the refactor when the inevitable temptation to centralize
   appears.
7. **Promote only after live validation.** The Sentinel pipeline gates
   promotion on a real parser pass; reuse the same gate for any new
   converter. Skipped queries stay in the report; promoted queries land
   under `queries/<source>/*.json`.

## Useful smoke commands

```bash
# Inspect what the registry currently dispatches.
python -c "from scripts.kql.operators import OPERATOR_REGISTRY; print(sorted(OPERATOR_REGISTRY))"

# Run the canonicalizer property test alone.
python -m pytest scripts/test_kql/test_canonical_idempotence.py -q

# Verify the 8 promoted bodies are still byte-identical to canonical form.
python scripts/test_kql/regen_promoted.py --check

# Inspect the per-candidate tier distribution.
python -c "import json; print(json.load(open('queries/sentinel_conversion_report.json'))['summary']['tier_distribution'])"

# Full Phase 6 regression matrix.
python -m pytest scripts/test_sentinel_converter.py scripts/test_kql/ -q
python scripts/release_checklist.py
```

## Phase 6 baseline (recorded 2026-05-16)

| Surface | State |
|---|---|
| `scripts/convert_sentinel_kql.py` | 678 lines (facade only — `__all__` enumerates the D-15 public surface) |
| `scripts/kql/_facade_impl.py` | 1227 lines (Phase 7+ redistribution target) |
| `scripts/kql/operators/_legacy.py` | absent (removed in plan 06-10) |
| `OPERATOR_REGISTRY` | 21 entries (12 supported + 9 unsupported) |
| Promoted Sentinel artifacts | 8 — byte-identical to pre-Phase-6 baseline |
| `summary.tier_distribution` | `{tier_1: 8, tier_2: 0, tier_3: 17}` |
| Test counts | 35 legacy converter tests + 53 kql tests = 88 passed |
| Line-budget gate | active and passing (`@pytest.mark.xfail` removed) |
| `requirements-dev.txt` | exactly `pytest>=8.3` and `hypothesis>=6.150` |
| Deferred to Phase 7 | `pipeline.convert` rewire to dispatch through `OPERATOR_REGISTRY` (operator modules are registered + tested; only the dispatch wiring sits behind the legacy delegation) |
