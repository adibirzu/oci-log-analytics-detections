---
name: oci-log-analytics-dashboard-enhancer
description: Use when enhancing Oracle Cloud Infrastructure Log Analytics dashboards, saved searches, visualizations, tile-in-link layouts, drilldowns, or detection-rule-backed alerting. Applies to choosing chart types, shaping LAQL queries, adding Log Explorer deep links, wiring dashboards in this repo, and designing scheduled-search or ingest-time detection rules.
---

# OCI Log Analytics Dashboard Enhancer

Use this skill when the task is to improve an OCI Log Analytics dashboard or saved search, add a new visualization, make a widget more actionable, or pair a dashboard view with a detection rule and alarm path.

## First decisions

Start by identifying the correct surface:

- Source-derived detection rule: `rules/**`
- Generated OCI query derived from Sigma: run `scripts/convert_sigma.py`
- Curated app telemetry analytic: `queries/apps/*.json`
- Curated hunting or dashboard analytic: `queries/hunting/*.json`
- Dashboard composition and widget wiring: `scripts/deploy_dashboard.py`

Then decide whether the ask is primarily:

- A KPI or summary view
- An investigative drilldown
- A relationship or anomaly view
- A geographic view
- A detection and alerting workflow

## Repo-specific rules

Read [repo-integration.md](references/repo-integration.md) before editing dashboards in this repository.

Key local constraints:

- Dashboard widgets are embedded saved searches created by `scripts/deploy_dashboard.py`.
- The current saved-search builder defaults every widget to `visualizationType: "table"` with empty `visualizationOptions`.
- If the request needs a non-table dashboard widget, extend the deployment path instead of assuming the repo already persists chart configuration.
- Keep new analytics in the right surface; do not add hand-authored content under `logandetectionqueries/` or `logandetectionrules/`.

## Visualization selection

Read [oracle-log-analytics-capabilities.md](references/oracle-log-analytics-capabilities.md) when you need command limits, URL parameters, tile XML, or detection-rule guardrails.

Use these defaults:

- `summary_table`: best default for KPI rollups and multi-field correlation.
- `tile`: single KPI, distinct count, or period-over-period metric.
- `records` or `table`: when analysts need raw rows.
- `records_histogram` or `table_histogram`: when fast drilldown from time buckets matters.
- `sunburst` or `treemap`: hierarchical composition across 2-3 grouping fields.
- `link`: transaction or relationship analysis across fields and time.
- `cluster` or `issues`: high-volume anomaly triage, not routine scorecards.
- `map`: spatial analysis. In this repo, inspect the existing geographic-health queries before changing shape.
- `tile` in `link`: compact executive summaries or hidden detail panes behind a single widget.

Default to the simplest visualization that answers the operator question. Do not force exotic charts onto routine SOC dashboards.

## Query design heuristics

For dashboard-friendly analytics:

- Prefer `stats` for summary widgets and tables.
- Prefer `timestats` for trends and service-health timelines.
- Use `link` when the analysis is about grouped transactions, sessions, entities, or multi-step activity.
- Use `compare` only for interactive link/time comparisons, not for scheduled-search detection rules.
- Use `geostats` only when the target view really needs map semantics; scheduled-search detection rules do not support it.

For widget output:

- Keep field names readable and stable.
- Alias the metric field intentionally.
- Limit cardinality before putting the result on a dashboard.
- If the chart is noisy, sort or reduce to top/bottom values before rendering.

## Drilldowns and navigation

When the user wants dashboards to feel more actionable:

- Prefer Log Explorer deep links over static prose.
- Use copied query URLs or encoded queries so the destination opens with the right query, filters, visualization, time range, and scope.
- For tile-in-link XML, use hidden tiles plus `show(id=...)` or expander patterns for layered drilldown.
- Keep deep links aligned with the dashboard time range and scope filters.

## Detection-rule path

Choose one mechanism:

- Ingest-time detection rule: for label-based matching in a known log source or entity type, where every matching record should emit a metric immediately.
- Scheduled-search detection rule: for LAQL logic that must run periodically and post a numeric metric plus optional dimensions.
- Template-based detection rule: when an Oracle-defined template already models the use case.

For scheduled-search detection rules:

- The query must produce a valid numeric metric.
- You can post up to three dimensions.
- If using `link` output as dimensions, end the query with `fields -*, dim1, dim2, dim3, metric1`.
- Account for late-arriving logs if the detection window is short.
- Avoid unsupported commands and expensive patterns listed in the reference file.

For ingest-time detection rules:

- The rule depends on labels defined in the source/parser layer.
- Validate that the label, log source, and entity filter are specific enough to avoid noisy metrics.

Detection rules are not alarms. The rule posts metrics to Monitoring; the alarm is configured separately on that metric.

## Working pattern in this repo

1. Inspect the target query JSON and the dashboard entry in `scripts/deploy_dashboard.py`.
2. Decide whether the dashboard improvement needs only query changes, only widget wiring, or both.
3. If a non-table visualization is required, update the dashboard deployment model to carry visualization metadata explicitly.
4. If the ask includes alerting, shape the query so it also works as a scheduled-search detection rule, or add the required label path for ingest-time rules.
5. Keep titles, descriptions, tags, and log-source metadata consistent with nearby content.
6. Regenerate derived artifacts only when the touched surface requires it.

## Validation

After edits, run the smallest relevant validation loop:

- `python3 scripts/deploy_dashboard.py --dry-run` for dashboard wiring
- `python3 -m unittest discover -s scripts -p 'test_*.py'`
- `python3 -m compileall scripts`

If you changed source-derived rules or catalogs, also run:

- `python3 scripts/convert_sigma.py`
- `python3 scripts/generate_catalog.py`
- `python3 scripts/export_for_multicloud.py --manifest-only`

## Output expectations

When using this skill, produce:

- The recommended visualization choice and why it fits the analyst task
- The exact repo surface to edit
- Any query-shape changes needed for charting or metrics
- Any dashboard deployment changes needed to persist the visualization
- Any detection-rule and alarm follow-up needed for alerting
