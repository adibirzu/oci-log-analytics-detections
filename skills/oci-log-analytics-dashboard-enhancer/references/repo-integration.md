# Repo integration

Use this file when the task needs concrete edits in this repository.

## Canonical content surfaces

- `rules/**`: source-of-truth Sigma or YAML detections
- `queries/*.json`: generated top-level OCI detections
- `queries/sentinel/*.json`: live-validated Microsoft Sentinel conversions only
- `queries/apps/*.json`: mixed source-derived browser detections and curated app analytics
- `queries/hunting/*.json`: curated hunting and advanced analytics
- `queries/sentinel_conversion_report.json`: generated Sentinel conversion report, not a saved search
- `scripts/deploy_dashboard.py`: dashboard inventory, widget placement, embedded saved searches

Do not add new workflow logic under `logandetectionqueries/` or `logandetectionrules/`; those directories are legacy and empty.

## Query artifact shape

Curated query JSON files in this repo typically contain:

- `title`
- `description`
- `query`
- `level`
- `tags`
- `logsource`
- `falsepositives`

Keep naming and metadata aligned with adjacent files in the same folder.

Dashboard-ready query JSON can also include a `dashboard` object:

- `visualizationType`: one of the types in `SUPPORTED_VISUALIZATION_TYPES`
- `visualizationOptions`: options passed to the Log Analytics saved-search UI config
- `timeSelection`: usually `{"timePeriod": "l24h"}` for demo dashboards or a longer hunt window such as `l21d`
- `layout`: optional `{"width": <1-12>, "height": <positive integer>}` tile dimensions
- `ask_ai_prompts`: short investigation prompts stored with the saved search tags

Use query-level dashboard metadata by default. Use widget-level overrides in
`DASHBOARDS` only when one query needs different visualization or layout behavior
in different dashboards.

For Link visualizations that use tile-in-link custom views, put the XML in
`dashboard.visualizationOptions.tileLayoutXml` and set
`dashboard.visualizationOptions.dashboardOptions` to include `Tiles` and
`Main Table`. The link query should define every tile field explicitly, usually
with `eventstats` after the `link` command, so the XML and query output stay in
sync.

## Dashboard deployment shape

`scripts/deploy_dashboard.py` currently:

- Defines dashboard inventory in `DASHBOARDS`
- Embeds saved searches directly into dashboard import JSON
- Uses a 12-column dashboard grid through `DASHBOARD_GRID_COLUMNS`
- Resolves visualization-aware default dimensions through `VISUALIZATION_LAYOUT_DEFAULTS`
- Merges query-level and widget-level UI metadata in `resolve_widget_ui_config()`
- Merges query-level and widget-level width/height metadata in `resolve_widget_layout()`
- Places tiles row-by-row in `build_dashboard_json()` and wraps when a row exceeds 12 columns
- Applies common dashboard parameters for log-group compartment, entity, and time
- Builds embedded saved searches with the resolved `visualizationType`, `visualizationOptions`, and `timeSelection`
- Exports dashboard/widget metadata with `build_dashboard_inventory()`
- Validates inventory drift with `validate_dashboard_inventory()`

Implications:

- Query-only changes are enough for most visualization, time-window, prompt, and width/height updates.
- Widget-level dashboard changes are appropriate when the same query should render differently on one dashboard.
- Full-width layouts are the safe default for wide investigation output; compact layouts should be reserved for KPI tiles and dense charts.
- If you change the saved-search payload shape, keep `scopeFilters`, `parametersMap`, and the embedded saved-search references intact.

## App/APM query contract

Application observability and Octo APM Demo widgets must use the supported
`SOC Application Logs` field contract instead of legacy raw OTel field names.

Use quoted Log Analytics fields such as:

- `'Trace ID'`
- `'Span ID'`
- `'Span Name'`
- `'Service Name'`
- `'APM Domain'`
- `'Workflow ID'`
- `'Workflow Step'`
- `'Run ID'`
- `'Metric Name'`
- `'Attack ID'`
- `'Attack Stage'`
- `'MITRE Technique ID'`
- `'Payment Redirect URL'`
- `'Compromised VM'`
- `'Host Name'`
- `'OSQuery Finding'`

Do not reintroduce blocked legacy tokens such as `service.name`, `trace_id`,
`http.status_code`, `http.response_time_ms`, or `security.attack.*`. The focused
contract test is `scripts/test_app_query_contract.py`.

Do not use unsupported LAQL colon placeholders in saved-search or dashboard
queries. The OCI Console parser rejects patterns such as `:attack_id`,
`:trace_id`, and `where (:attack_id = null or 'Attack ID' = :attack_id)` in
dashboard widgets. Saved searches must be executable as imported. If a runbook
needs analyst pivots, document copied Log Explorer filters with literal
placeholders, for example `'Attack ID' = '<ATTACK_ID>'`, rather than embedding
colon parameters in the saved search.

Latest Octo APM deployment facts to preserve:

- `OCI-DEMO: Octo APM Demo Dashboard` is the scoped detections-repo dashboard.
- It contains 17 widgets/saved searches and uses widget-level `l21d` time
  selection for workshop evidence.
- Live `emdemo` verification on 2026-05-12 showed 17/17 widget HITs and 5/5
  detection-rule query HITs over `24h` after fresh workshop data ingestion.
- Five Octo APM scheduled-search rules were `ACTIVE`, `READY`, and targeted to
  `MONITORING`.
- Do not include live OCIDs, namespaces, hostnames, IPs, or secrets in docs or
  generated artifacts; use variables and placeholders only.

For dashboard queries, keep `stats by` groupings to four fields or fewer. This
keeps the query compatible with OCI Log Analytics limits and prevents noisy,
high-cardinality widgets.

## Microsoft Sentinel conversion contract

The Sentinel converter has three layers as of Phase 6:

- `scripts/convert_sentinel_kql.py` is the **facade** (≤800 lines). It exposes the
  D-15 public surface declared in `__all__`, owns the CLI entry point + I/O
  orchestration (`build_query_payload`, `convert_candidate`, `convert_candidates`,
  `build_conversion_report`, `main()`), and re-exports the deterministic engine
  from `scripts.kql`.
- `scripts/kql/**` is the **subpackage** holding the deterministic engine:
  - `types.py` — `Tier` IntEnum (TIER_1 lossless / TIER_2 transform / TIER_3
    unsupported), `ConversionContext`, `StageResult`, `KqlStage`, `KqlPredicate`
    (all `@dataclass(frozen=True)`).
  - `canonical.py` — `canonical(query)` mini-tokenizer + `CanonicalizationError`.
    Normalizes whitespace + quoting only; idempotent;
    raises on malformed input.
  - `lexer.py`, `ast_nodes.py`, `mapping_loader.py`, `emitter.py`,
    `pipeline.py` — Phase 6 delegation shims that get fattened in later phases.
  - `operators/__init__.py` — `OPERATOR_REGISTRY` dict + `@register("<op>")`
    decorator. Each operator module (`where_op.py`, `summarize_op.py`,
    `project_op.py`, `extend_op.py`, `sort_op.py`, `distinct_op.py`,
    `union_op.py`, `let_op.py`) registers a pure `convert_<op>(stage, ctx) ->
    StageResult` function. `unsupported_op.py` covers `take`, `count`, `limit`,
    `parse`, `evaluate`, `mv-expand`, `make-series`, `join`, `render` as Tier-3
    structured skips.
  - `_facade_impl.py` — Phase 6 cutover staging area. Holds the relocated
    legacy converter helpers verbatim so the facade collapses below 800 lines
    without changing behavior. Phase 7+ redistributes these helpers into the
    operator/lexer/validator modules above.
- `scripts/sentinel_conversion_workflow.py` is the **operator wrapper** for
  local reports, live promotion, artifact refresh, triage, and static HTML
  reporting. The workflow is the only layer that touches OCI APIs.

Test harness sits under `scripts/test_kql/`:

- `test_canonical_idempotence.py` — Hypothesis property test (100 examples) that
  asserts `canonical(canonical(x)) == canonical(x)`.
- `test_promoted_snapshots.py` — 18 parametrized fixture round-trips through
  `canonical()` (8 promoted bodies + 10 synthetic operator-coverage fixtures)
  plus 3 negative tests for `CanonicalizationError`.
- `test_module_size.py` — line-budget gate; plain assertion that
  `wc -l scripts/convert_sentinel_kql.py <= 800`.
- `test_operators.py` — registry binding regression-fence + Tier-1 happy
  paths + Tier-3 skip paths + fixture round-trips per operator family.
- `regen_promoted.py` — script that rewrites or `--check`s the 8 promoted
  fixture snapshots from `queries/sentinel/*.json` through `canonical()`.

`requirements-dev.txt` lists exactly the two test-only deps the harness uses:
`pytest>=8.3` and `hypothesis>=6.150`. Runtime deps in `requirements.txt` are
unchanged.

When adding new conversion behavior, use the decision rules in
[kql-conversion-architecture.md](kql-conversion-architecture.md) — that file is
the canonical "where does this code live?" reference and includes adaptation
guidance for standing up other source-language converters with the same
scaffolding.

Keep Sentinel promotion conservative:

- Use only official `Azure/Azure-Sentinel` candidates from the local cache/export.
- Use `config/sentinel_oci_mapping.yaml` as an allow-list for supported Sentinel tables and fields.
- A Logan target field must resolve through `queries/log_source_field_dictionary.json` or the converter's built-in approved fields.
- Local-only conversion is not enough for promotion; checked-in query JSON under `queries/sentinel/` must have `live_validation_status: passed`.
- The workflow must not create alarms, Terraform resources, or OCI dashboards directly. It may regenerate query/catalog/dashboard-inventory artifacts and validate dashboard definitions.
- Failed live candidates remain in `queries/sentinel_conversion_report.json` with `live_validation_status: failed`; do not write them under `queries/sentinel/`.

Known converter guardrails from the latest promotion work:

- Drop Microsoft Sentinel entity-binding aliases such as `AccountCustomEntity`, `HostCustomEntity`, `IPCustomEntity`, `URLCustomEntity`, `DNSCustomEntity`, and `MalwareCustomEntity`.
- Remove explicit KQL time filters (`TimeGenerated`, `Timestamp`, `EventCreationTime`, and similar) and rely on OCI query/dashboard windows.
- Reject unresolved placeholder text (`{{...}}`, `GOES HERE`, `REPLACE_ME`, `CHANGE_ME`, `YOUR_VALUE`) and colon parameters.
- Reject KQL-only functions/operators that are not converted, including `join`, tabular `let`, `make-series`, `mv-expand`, `datatable`, watchlists, `externaldata`, regex extraction, JSON bag expansion, `strlen`, `toint`, and raw `int(...)`.
- Preserve source attribution, Sentinel IDs, source paths/URLs, required connectors, MITRE metadata, severity, original tables, and conversion status in every promoted query.

Use these commands for Sentinel changes:

```bash
python3 scripts/sentinel_conversion_workflow.py local
python3 scripts/sentinel_conversion_workflow.py promote --top all --timeout 20
python3 scripts/sentinel_conversion_workflow.py refresh-artifacts
python3 scripts/sentinel_conversion_workflow.py page
python3 scripts/sentinel_conversion_workflow.py triage
python3 scripts/sentinel_conversion_workflow.py next-queries --limit 10
python3 scripts/sentinel_conversion_workflow.py status --json --strict
python3 -m pytest scripts/test_sentinel_converter.py scripts/test_sentinel_conversion_workflow.py -q
python3 -m pytest scripts/test_kql/ -q                                # subpackage harness
python3 scripts/test_kql/regen_promoted.py --check                     # byte-identity gate
```

Both entry-point invocations must work — the facade carries a `sys.path` guard
so direct script execution and module execution both resolve the absolute
`scripts.*` imports:

```bash
python3 scripts/convert_sentinel_kql.py --help            # CLI form
python3 -m scripts.convert_sentinel_kql --help            # module form
```

For later/new Sentinel query development, start with `triage`, then use
`next-queries --work-type <type>` to select a small candidate queue. Treat
`field_mapping` and `table_mapping` as schema work: verify real OCI source and
field support before editing `config/sentinel_oci_mapping.yaml`. Treat
`live_environment` as an OCI auth/clock-skew rerun issue. Treat
`local_validation`, `live_validation`, and `kql_support` as converter work:
change deterministic conversion logic and tests, then promote only through the
live-gated workflow.

## Geographic dashboard note

The current geographic-health content uses explicit latitude and longitude fields in checked-in query JSON. Inspect those existing files before replacing them with `geostats`; the repo may already depend on a specific output shape.

## Validation path

Use the normal contributor loop after changes:

- `python3 scripts/deploy_dashboard.py --dry-run`
- `python3 scripts/deploy_dashboard.py --dry-run --dashboard-name "<target dashboard>"`
- `python3 scripts/deploy_dashboard.py --validate`
- `python3 -m unittest scripts.test_deploy_dashboard scripts.test_app_query_contract -q`
- `python3 -m unittest discover -s scripts -p 'test_*.py'`
- `python3 -m compileall scripts`

If the task touched `rules/**` or generated outputs, also run:

- `python3 scripts/convert_sigma.py`
- `python3 scripts/generate_catalog.py`
- `python3 scripts/export_for_multicloud.py --manifest-only`
