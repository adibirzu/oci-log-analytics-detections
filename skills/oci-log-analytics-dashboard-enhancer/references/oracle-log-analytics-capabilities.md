# Oracle Log Analytics capabilities

Use this file when the task depends on Oracle Log Analytics product behavior rather than repo structure.

## Visualization shortcuts

- `summary_table`: broad statistical rollups and multi-field grouping
- `tile`: headline count or distinct summary
- `records_histogram` / `table_histogram`: investigation with fast time-bucket drilldown
- `sunburst`: hierarchical grouping across multiple fields
- `treemap`: hierarchical plus fractional relationship analysis
- `link`: grouped transaction or relationship analysis with anomaly bubbles
- `map`: geographic visualization
- `cluster` / `issues`: machine-learning-assisted anomaly reduction

## Query commands that matter most

- `stats`: summary statistics with grouping; use for most KPI widgets
- `timestats`: time-bucketed trends; set `span` intentionally for longer ranges
- `link`: group logs into business-transaction style records
- `compare`: compare `link`-generated properties across prior windows
- `geostats`: geographic summaries for client, server, or custom coordinates

Useful reminders:

- `link` has a 500-group return limit for console, CLI, or SDK exports, though Oracle can process more internally.
- `link` supports at most 4 fields, or 5 when time is one of the link fields.
- `timestats` auto-adjusts `span` when the selected time range is too large.

## Tile-in-link XML

Use tile-in-link when you want one widget to replace many small tiles or to expose hidden detail panes.

Patterns to use:

- Wrap the layout in `<summary> ... </summary>`
- Use `<container>`, `<table>`, `<row>`, `<column>`, and `<tiles>`
- Use `hidden="true"` on detail tiles you only want to reveal on click
- Use link tiles with `href="show(id=some-tile-id)"` to reveal hidden content
- Use expander tiles when you want inline expansion instead of navigating away

This is a good fit for:

- executive overview widgets
- severity summaries with collapsible detail
- one-card KPI summaries with embedded sparkline or quick links

## Log Explorer deep links

Use Log Explorer URLs when a dashboard element should open a scoped investigation.

Important parameters:

- `viz`: default visualization, including `pie`, `bar`, `hbar`, `line`, `sunburst`, `treemap`, `cloud`, `map`, `records`, `table`, `records_histogram`, `table_histogram`, `distinct`, `cluster`, `link`, `tile`, and `summary_table`
- `search`: search clause
- `filters`: field/value/comparator filters
- `encodedQuery`: base64-encoded query string
- `startTime` and `endTime`: custom time range
- `timeNum` and `timeUnit`: relative time range
- `scopeFilters`: compartment, entity, log set, region, and related context

Prefer `encodedQuery` when special characters in the query may be blocked by network or firewall controls.

## Detection-rule choices

### Ingest-time detection rule

Choose this when:

- the condition is label-based
- the source and entity type are known
- you want a metric for each matching record as logs arrive

Requirements:

- create or reuse the right label in the source/parser layer
- filter by log source or entity type when possible
- select metric dimensions carefully to avoid cardinality spikes

### Scheduled-search detection rule

Choose this when:

- the logic requires LAQL, aggregation, correlation, or ratio calculation
- you want periodic evaluation and a metric in Monitoring

Query requirements:

- one numeric metric must be emitted
- up to 3 dimensions can be posted
- if dimensions come from `link`, end with `fields -*, dim1, dim2, dim3, metric1`

Guardrails:

- avoid wildcard search on `Original Log Content`
- avoid `regex` on large fields like `Message`
- `like`, `extract`, `jsonextract`, and `xmlextract` are not supported on large fields like `Message`
- `timestats` cannot be followed by `eval`, `extract`, `jsonextract`, `xmlextract`, or `lookup`
- unsupported scheduled-task commands include `cluster`, `clustercompare`, `clusterdetails`, `clustersplit`, `compare`, `createview`, `delta`, `fieldsummary`, `highlightgroups`, `geostats`, `linkdetails`, `map`, `nlp`, and `timecompare`

Limits:

- maximum 3 fields in `by`
- maximum 3 fields in `timestats`
- maximum 1 aggregate function for a scheduled-task query

Operational notes:

- account for late-arriving logs by adjusting the query time window
- keep metric columns numeric and dimensions low-cardinality
- if Monitoring shows invalid metric extraction, inspect both metric details and query output shape

### Template-based detection rule

Choose this when an Oracle-defined template already models the problem. Current Oracle-defined templates are saved-search-based.

## Alerts

Detection rules post metrics to OCI Monitoring. Alarms are configured separately in Monitoring against those emitted metrics.

You can create alarms for both ingest-time and scheduled-search detections. If the alarm fires, Oracle can open the event in Log Explorer using the alarm dimensions and time range.

## Practical patterns

- KPI card with period-over-period change: `tile` plus Show Change, usually powered by `compare`
- Timeline widget: `timestats span=<size> ...`
- Transaction outlier analysis: `link ... | stats ...`
- Geo dashboard: `geostats ...` or a repo-compatible latitude/longitude output
- Drilldown card: tile-in-link XML plus `show(id=...)` or a Log Explorer URL
