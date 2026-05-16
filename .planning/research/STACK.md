# Stack Research — Sentinel KQL → OCI Logan QL Parity (v2.0)

**Domain:** Detection-content conversion pipeline (KQL → OCI Log Analytics Query Language)
**Researched:** 2026-05-15
**Confidence:** HIGH for OCI QL feature surface and converter integration; MEDIUM for KQL parser ecosystem (most options are immature or heavyweight relative to the gap we actually need to close).

## TL;DR

**Do not adopt a third-party KQL parser.** No mature pure-Python KQL parser exists, and the only authoritative implementation (Microsoft's `Kusto.Language`) is C#-only and would force a pythonnet/.NET runtime dependency that is currently broken on .NET 9 + Apple Silicon. The pragmatic v2.0 path is to **extend the existing expression-walker in `scripts/convert_sentinel_kql.py`** with a small, hand-rolled tokenizer for the operators that block coverage (`iff`, `parse_command_line`, `countof`, `column_ifexists`, `parse` with literal anchors, multi-stage `extend`). Add only two test-tier dependencies (`pytest`, `hypothesis`) and keep the runtime footprint at `oci`, `PyYAML`, `python-dotenv`.

The conversion gap is **semantic mapping**, not parsing. The current 10 live-failures and 17 skips are dominated by **18 unmapped Sentinel fields** (`Subject*`, `InitiatingProcess*`, `EventData`, `OfficeWorkload`, etc.) plus **6 unsupported KQL expressions** — none of which a generic KQL parser would solve. Each still requires a deterministic OCI QL emission rule.

## Recommended Stack

### Core Technologies (no change to runtime deps)

| Technology | Version | Purpose | Why Recommended |
|------------|---------|---------|-----------------|
| Python | 3.11+ | Converter runtime | Already the project standard; type hints, `match` statements, and `tomllib` simplify the AST/IR work below. |
| `oci` | >=2.130.0 (already pinned) | Live OCI Log Analytics parser validation | Sole promotion gate. Validation REST calls already wired through `scripts/convert_sentinel_kql.py`. |
| `PyYAML` | >=6.0 (already pinned) | `config/sentinel_oci_mapping.yaml` ingestion | The mapping table is the canonical KQL→OCI dictionary; YAML stays the editing surface. |
| `python-dotenv` | >=1.0.0 (already pinned) | OCI profile env loading | Unchanged. |

### Supporting Libraries (test-only additions)

| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| `pytest` | >=8.3 | Replace ad-hoc `unittest` invocations with parametrized table-driven tests for each KQL operator translation | Add as `[test]` extra. Existing `scripts/test_*.py` already pytest-compatible — switch CLI is the only change. |
| `hypothesis` | >=6.150 | Property-based fuzzing of the predicate walker: any `(field op literal)` combination must either translate or raise a deterministic `unsupported_*` error, never silently emit invalid Logan QL | Use for `convert_predicate`, `_convert_extend`, and the new `iff`/`parse_command_line` shims. Keep generators narrow (mapped fields + literal types from `log_source_field_dictionary.json`). |
| `pytest-subtests` | >=0.13 | Optional. Group "for each unsupported feature in last report, assert detection" loops without losing per-case detail | Use only if `pytest.parametrize` over `queries/sentinel_conversion_report.json::unsupported_features` proves awkward (it usually doesn't). |

**Both `hypothesis` and `pytest` stay out of `requirements.txt` and live in a new `requirements-dev.txt` or `[project.optional-dependencies].test` block.** Runtime stays minimal.

### Development Tools (no new wiring)

| Tool | Purpose | Notes |
|------|---------|-------|
| `ruff` | Lint + format the converter module | Already implied by `~/.claude/rules/python/coding-style.md`. Run once after the converter refactor; nothing to install in this milestone. |
| `mypy` (optional) | Type-check the new IR dataclasses | Worth it only if the IR layer (see Architecture) lands. Otherwise skip. |
| `pip-tools` / `uv` | Lock the new test deps | Optional; the project currently uses unpinned `requirements.txt`. |

## KQL Parser Options Evaluated

| Option | Verdict | Reason |
|--------|---------|--------|
| `kusto-query-language-parser` (PyPI 0.0.2, Apr 2025, MIT, Ted Yeates) | **Reject** | Version 0.0.2, ~10 commits, depends on `antlr4-python3-runtime==4.8.0` (pinned to an older runtime). No documented coverage of `parse_command_line`, `iff`, `countof`, `column_ifexists`. Emits ANTLR parse trees, not a semantic IR — we would still hand-write every emission rule. |
| `tedyeates/kusto-query-language-python-parser` (GitHub source of the above) | **Reject** | Same artifact, same maturity. |
| Microsoft `Kusto.Language` via `pythonnet` | **Reject for this milestone** | Authoritative grammar, but it's the official **C# parser**; access requires loading a .NET assembly via `pythonnet` 3.x. Known broken on macOS/Linux ARM with .NET 9 (pythonnet#2514). Adds a non-Python runtime to every developer workstation and CI runner for a converter that produces a 1747-line Python script today. The Optyx Security walkthrough confirms it works for *validation* but not for emission. |
| `kibana-ql` / `kql-parser` (Aloshi) | **Reject** | Wrong "KQL": these target Kibana Query Language, not Kusto. Names collide. |
| `KustoPandas` | **Reject** | Converts KQL → pandas DataFrame ops in-memory; it does not expose a reusable AST or a textual emission step. Not a conversion library. |
| `lark` (pure-Python EBNF parser, 1.3.1, MIT) | **Reject for v2.0; revisit in v2.1 if scope grows** | Lark is excellent and we could write a partial KQL grammar in EBNF, but it's a 6-12 week investment to cover the operators we care about, and the failure modes we have today are **mapping completeness**, not parse failures. The current regex/stage-walker handles 25/25 attempted candidates without parse errors; the failures are in `extend` expression internals and field mappings. |
| `parsimonious` / `pyparsing` / `antlr4-python3-runtime` directly | **Reject** | Same conclusion as `lark`. Heavier wiring for no marginal gain over Lark, which is the best-in-class pure-Python option if we ever go this route. |
| **Hand-rolled mini-parser for the 6 blocking operators** | **Recommended** | The unsupported features form a closed, enumerable set (see PITFALLS.md). Each gets a deterministic function with property-based coverage. Total added code: ~400-600 lines inside the existing converter, no new runtime deps. |

### Rationale

The converter is already a working stage-based pipeline:

```
_split_kql_stages → _classify_unsupported_kql_text → convert_predicate / _convert_summarize / _convert_extend → validate_logan_query_local → live validation
```

A full AST would require rewriting the entire pipeline. Targeted parsers per operator slot into the existing dispatch without touching the upstream stage splitter or downstream live-validation gate.

## OCI Logan QL Feature Constraints (Parity Targets)

Verified against `docs.oracle.com/en-us/iaas/log-analytics/doc/{eval,extract,regex,where,link,command-reference}.html`. Confidence: HIGH.

| OCI QL Feature | Status | Constraint / KQL Parity Note |
|----------------|--------|------------------------------|
| `eval` arithmetic / comparison / logical | Supported | Direct map for KQL `extend` arithmetic. |
| `eval if(cond, then, cond2, then2, ..., else)` | Supported (n-ary) | **This is the target for `iff(c, t, e)`** — KQL's binary `iff` maps trivially to OCI's variadic `if`. Already documented with chained example in the eval reference. |
| `eval` string fns: `indexOf`, `lastIndexOf`, `substr`, `replace`, `contains`, `startsWith`, `endsWith`, `upper`, `lower`, `trim` | Supported | `indexOf` + `substr` give us a deterministic emission for `parse <field> with * "anchor1" capture "anchor2" *` where there are exactly two literal anchors. Multi-anchor `parse` patterns map to chained `indexOf`/`substr` calls — verifiable, but verbose. |
| `eval` regex / `regex_match` | **NOT supported in `eval`** | OCI QL has no `eval`-level regex match function. Use the standalone `regex` command instead for filtering, or `extract` for capture-into-fields. This blocks any in-line regex predicate (KQL `matches regex`); we must rewrite as a stage break. |
| `extract` command with named groups | Supported (RE2J flavor) | Maps to KQL `extract(pattern, captureGroup, source)`. Pattern flavor differs from KQL's `.NET regex` — see PITFALLS.md. |
| `regex` command | Supported (RE2J) | Predicate-level regex filter. RE2 lacks lookbehind/backreferences vs .NET regex — flag patterns using these for skip. |
| `lookup` (join-like) | Supported | KQL `lookup` and simple `join kind=inner` cases are mappable; complex multi-key joins remain skipped. |
| `link` (transaction grouping) | Supported | KQL has no direct equivalent. Used only for OCI-side dashboarding, not as a KQL conversion target. |
| `stats` / aggregation | Supported | Direct map for KQL `summarize`. Existing `_convert_summarize` already handles common cases. |
| `where` with `in`, `not in` | Supported | Direct map for KQL `in (...)` / `!in (...)`. |
| `coalesce` / `ifnull` | **NOT supported as a function** | Must be emulated as nested `if(field != null, field, fallback)`. Affects KQL `coalesce()` and `iff(isnull(x), ...)` translations. |
| `parse_command_line` equivalent | **NOT supported** | OCI has no tokenizer. Two viable strategies: (a) skip with reason "no OCI command-line tokenizer", (b) emit a multi-step `extract` pipeline that captures by `\\s+` boundaries — lossy vs Windows `CommandLineToArgvW` semantics; mark output as best-effort. Recommendation: skip until OCI exposes a tokenizer; do NOT silently emit lossy output. |

## Installation

```bash
# Runtime (unchanged)
pip install -r requirements.txt

# New dev/test extras — add to requirements-dev.txt or pyproject [project.optional-dependencies].test
pip install 'pytest>=8.3' 'hypothesis>=6.150'

# Optional, only if subTest grouping over the conversion report becomes awkward
pip install 'pytest-subtests>=0.13'
```

`requirements.txt` (no change):
```
oci>=2.130.0
PyYAML>=6.0
python-dotenv>=1.0.0
```

New `requirements-dev.txt`:
```
-r requirements.txt
pytest>=8.3
hypothesis>=6.150
# pytest-subtests>=0.13   # optional
```

## Mapping Reference Sources

For extending `config/sentinel_oci_mapping.yaml` and addressing the 18 unmapped `Subject*` / `InitiatingProcess*` / `EventData` / `OfficeWorkload` fields:

| Source | Use For | Confidence |
|--------|---------|------------|
| Microsoft Sentinel `SecurityEvent` table schema (learn.microsoft.com) | `Subject*`, `SubjectAccount`, `SubjectLogonId`, `SubjectUserSid`, `Logon_Type` → Windows Security Event 4624/4672 semantics | HIGH (vendor primary) |
| Microsoft Defender ASIM (Advanced Security Information Model) | `InitiatingProcess*`, `DeviceProcessEvents` → process tree fields | HIGH |
| Office 365 / M365 management API audit schema | `OfficeWorkload`, `OrganizationName`, `UserType`, `MailboxOwnerUPN` | HIGH |
| `queries/log_source_field_dictionary.json` (in-repo) | Authoritative set of fields that already pass live OCI parser validation. **Every new alias must resolve to a key here, or the field must be added with a documented parser-source contract.** | HIGH |
| KQL `parse_command_line` ↔ Windows `CommandLineToArgvW` semantics | Documenting why we can't faithfully reproduce in OCI QL today | HIGH |

There is **no published KQL↔OCI QL mapping reference**. The mapping is original work in this repo; we extend it, we don't replace it.

## Alternatives Considered

| Recommended | Alternative | When to Use Alternative |
|-------------|-------------|-------------------------|
| Hand-rolled per-operator parsers | `lark` + a KQL subset grammar | Only if v2.x scope expands beyond the 6 blocking operators to "parse arbitrary KQL"; if the unsupported-feature counter grows past ~25 distinct expression shapes, the EBNF approach starts paying for itself. |
| Hand-rolled per-operator parsers | `pythonnet` + `Kusto.Language.dll` | If Microsoft ships an official Python binding for `Kusto.Language` (track microsoft/Kusto-Query-Language#56). Then the work shifts from parsing to emission rules — same as today, but with grammar correctness for free. |
| `pytest` + `hypothesis` | `unittest` stdlib only | If the team explicitly rejects adding test-time deps. `unittest.subTest` + dataclass tables (see Top of Mind blog) is a workable second-best, and the repo already uses `unittest`. |
| Extend `config/sentinel_oci_mapping.yaml` | Add a second `kql_operator_translation.yaml` for expression-level rules | If `iff`/`countof`/`parse` emission templates outgrow being inlined in `_convert_extend`. Likely not needed in v2.0; revisit when the converter has >15 operator-specific code paths. |

## What NOT to Use

| Avoid | Why | Use Instead |
|-------|-----|-------------|
| `pysigma` / `sigma-cli` for Sentinel → OCI | These convert Sigma → KQL (or other backends). Adding them duplicates the in-repo Sigma path (`scripts/convert_sigma.py`) and does not solve the Sentinel-corpus problem. | Continue using `scripts/convert_sentinel_kql.py` against `queries/sentinel_candidates.json`. |
| `KustoPandas` | Not a converter; it executes KQL semantics against a DataFrame in Python. Does not emit textual queries for any other backend. | The hand-rolled emitter. |
| `kibana-ql`, `kql-parser` (Aloshi) | Wrong KQL (Kibana, not Kusto). Easy to import by mistake. | `azure-kusto-data` if we ever need to *validate* KQL syntactically before conversion — but even that is optional given Sentinel itself is the source. |
| `pythonnet` 3.x on macOS ARM with .NET 9 | Documented `clr.AddReference` regression (pythonnet#2514) on the dev workstation architecture. CI runners would need a Linux x86_64 image with a pinned .NET 6/7/8 SDK. | Hand-rolled per-operator parsing; revisit if Microsoft ships official Python bindings. |
| `pyparsing` / `parsimonious` | Strictly inferior to `lark` for this workload (slower, smaller community, weaker grammar features). | `lark` — but only if we ever justify a full parser rebuild. |
| Re-using `re` for `parse_command_line` shell tokenization | Cannot faithfully reproduce `CommandLineToArgvW` quoting / backslash escape rules with a single regex. Lossy emission would corrupt detections silently. | Skip the candidate with `unsupported KQL function: parse_command_line (no OCI tokenizer)`. Document and move on. |
| Auto-generated KQL → SQL via Azure Data Explorer's SQL endpoint | Tempting bridge ("KQL → SQL → OCI"), but OCI QL is not a SQL dialect; the translation surface is different (e.g., OCI's stage-based pipe model vs ANSI SQL). Two-step lossy conversion would hide errors. | Direct KQL → OCI QL emission with explicit unsupported-feature reporting. |

## Stack Patterns by Variant

**If the unsupported-feature counter stays under ~10 distinct shapes (current state: 6):**
- Stick with hand-rolled per-operator functions inside `scripts/convert_sentinel_kql.py`.
- Each function takes a normalized stage string, returns either `(logan_fragment, [warnings])` or raises `UnsupportedKQLExpression`.
- Tests: `pytest.parametrize` over `(kql_input, expected_logan, expected_warnings)` triples.

**If the counter grows past ~25 distinct shapes, or if we need to expand into `make-series`, `mv-apply`, `toscalar`, regex predicates:**
- Introduce a small IR layer: tokenize → AST node dataclasses (`Stage`, `Expression`, `Predicate`, `Aggregation`) → emitter visitor.
- Use `lark` 1.3.x with a subset KQL grammar focused on the operators we actually translate (don't try to cover the whole language).
- Keep `convert_predicate` and `_convert_summarize` as adapters into the visitor so the live-validation contract doesn't change.

**If Microsoft ships official Python bindings for `Kusto.Language`:**
- Switch parsing to the official parser, keep the emitter we own. Best of both worlds.
- Until then, the binding question is theoretical.

## Version Compatibility

| Package A | Compatible With | Notes |
|-----------|-----------------|-------|
| `oci>=2.130.0` | Python 3.8 - 3.12 | The CAP profile validation path uses `log_analytics` and `query` client APIs added in 2.130. No change needed. |
| `PyYAML>=6.0` | Python 3.6+ | Stable. The mapping YAML uses no advanced anchors; loader-agnostic. |
| `pytest>=8.3` | Python 3.8+ | Last `pytest` version with backwards-compatible `parametrize` and `assertion rewriting` for our existing `scripts/test_*.py`. |
| `hypothesis>=6.150` | Python 3.9+ | Strategies API is stable; we will use only `text()`, `from_regex()`, `sampled_from()` over `log_source_field_dictionary.json` entries. |
| `lark` 1.3.x *(if adopted later)* | Python 3.8+ | Pure-Python, no C deps; safe on macOS ARM. |
| `pythonnet` 3.0.x *(rejected)* | Broken on macOS ARM + .NET 9 | Track issue #2514 if we ever need it. |

## Integration With Existing Code

| Touchpoint | Current State | v2.0 Change |
|------------|---------------|-------------|
| `scripts/convert_sentinel_kql.py::_convert_extend` | Lines 993-1017. Regex match on `<alias> = <expr>` shapes; rejects anything not in a small allow-list. | Add per-function dispatch: `iff(...)`, `countof(...)`, `column_ifexists(...)`, `tostring(...[N])`, `parse_command_line(...)`. Each function returns OCI QL fragment or raises `UnsupportedKQLExpression`. |
| `scripts/convert_sentinel_kql.py::convert_predicate` | Lines 712-832. Handles `==`, `=~`, `has`, `has_any`, `in`. | Add `matches regex` rewrite → emit standalone `| regex <field> <pattern>` stage (since OCI `eval` has no in-line regex). Add `column_ifexists` short-circuit. |
| `scripts/convert_sentinel_kql.py::_split_kql_stages` | Lines 489-520. Splits on top-level `|`. | No change — stage splitting is already correct. |
| `config/sentinel_oci_mapping.yaml::fields` | 161 entries today. | Add `SubjectUserName`, `SubjectDomainName`, `SubjectLogonId`, `SubjectUserSid`, `SubjectAccount`, `InitiatingProcessAccountDomain`, `InitiatingProcessAccountName`, `InitiatingProcessSHA256`, `MailboxOwnerUPN`, `OfficeWorkload`, `OrganizationName`, `UserType`, `Logon_Type`, `ObjectDN`, `Exe`, `LocalFile`, `ParentProcessName`, `ProcessId`, `ClientInfoString`, `ActingProcessFileInternalName`, `EventData`. **Every addition must point to a field already in `queries/log_source_field_dictionary.json` or come with a documented parser-source contract.** |
| `scripts/test_sentinel_kql_conversion.py` (if exists) / new `scripts/test_kql_operators.py` | Existing unit tests in stdlib `unittest`. | Add a pytest module with `parametrize`-driven tables for each new operator. Property tests via `hypothesis` for `convert_predicate` and `_convert_extend`. |
| Live validation gate | Unchanged | Promotion still gated on `convert_sentinel_kql.py --validate-live` returning HIT. New operators add to the candidate funnel; the gate doesn't move. |

## What This Stack Deliberately Does NOT Add

Per the milestone constraint to avoid heavy frameworks:

- No new orchestration framework (Airflow, Prefect, Dagster). The converter is a one-shot CLI.
- No new schema registry (jsonschema, pydantic). Mapping YAML + field dictionary are sufficient and human-editable.
- No new query-builder DSL. The OCI QL output is textual and small; a builder would obscure the emission.
- No new caching layer. Live validation is the slow step and already gated explicitly by `--no-sync` / `--validate-live`.
- No new ML / LLM-based translation. Translation must be deterministic and explainable for SOC content review.
- No alternative test framework (nose, ward). `pytest` covers everything.

## Sources

- [kusto-query-language-parser on PyPI](https://pypi.org/project/kusto-query-language-parser/) — 0.0.2, MIT, ANTLR-based, immature. HIGH confidence.
- [tedyeates/kusto-query-language-python-parser](https://github.com/tedyeates/kusto-query-language-python-parser) — ~10 commits, no releases. HIGH confidence on maturity, LOW on operator coverage.
- [microsoft/Kusto-Query-Language](https://github.com/microsoft/Kusto-Query-Language) — Authoritative C#/JS parser. No published EBNF/ANTLR grammar. HIGH.
- [Parsing KQL with Python — Optyx Security](https://optyx.io/posts/kql-python/) — Confirms pythonnet + Kusto.Language is the only path to use Microsoft's parser from Python. MEDIUM (single source, dated April 2025).
- [pythonnet on PyPI](https://pypi.org/project/pythonnet/) and [pythonnet#2514](https://github.com/pythonnet/pythonnet/issues/2514) — Known macOS/Linux ARM regression with .NET 9. HIGH.
- [Lark on PyPI](https://pypi.org/project/lark/) — 1.3.1, MIT, pure-Python, Python >=3.8. HIGH.
- [Hypothesis on PyPI](https://pypi.org/project/hypothesis/) — 6.152.x stable. HIGH.
- [pytest subtests docs](https://docs.pytest.org/en/stable/how-to/subtests.html) — Merged into core in pytest 9.0; standalone `pytest-subtests` still useful for pytest 8.x. MEDIUM.
- [OCI Logging Analytics Query Command Reference](https://docs.oracle.com/en-us/iaas/log-analytics/doc/command-reference.html) — Full command list. HIGH.
- [OCI eval command reference](https://docs.oracle.com/en-us/iaas/log-analytics/doc/eval.html) — Confirms `if(cond, then, cond, then, ..., else)` n-ary form and string function inventory. HIGH.
- [OCI extract command](https://docs.oracle.com/en-us/iaas/log-analytics/doc/extract.html) — RE2J regex flavor, named groups supported. HIGH.
- [Microsoft Learn — parse_command_line()](https://learn.microsoft.com/en-us/kusto/query/parse-command-line-function) — Only `"windows"` mode is supported, semantics match `CommandLineToArgvW`. HIGH.
- [OCI Logging Analytics Query Language: A Beginner's Guide — integrationplumbers.io](https://integrationplumbers.io/mastering-oci-logging-analytics-query-language-a-beginners-guide/) — Third-party corroboration of operator inventory. MEDIUM.

---
*Stack research for: KQL → OCI Logan QL converter parity*
*Researched: 2026-05-15*
