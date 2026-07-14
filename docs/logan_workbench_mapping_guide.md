# Logan Workbench Mapping Guide

This guide documents how Forge maps source query languages into OCI Log Analytics
QL. The generated artifacts remain the source of truth:

- `queries/logan_ql_reference_catalog.json`
- `queries/cross_ql_mapping_patterns.json`
- `queries/conversion_examples.json`
- `queries/ql_conversion_capability_matrix.json`

## Support Levels

`supported` means the emitted Logan QL preserves the source query's detection
semantics for the represented construct. `partial` means the core filter or
aggregation is preserved but advanced runtime behavior may need analyst review.
`lossy` means the conversion is useful for triage but drops source-platform
behavior such as lookup materialization or enrichment. `unsupported` means Forge
must block conversion rather than emit a weaker detection.

## Common Constructs

| Source construct | Logan QL mapping | Notes |
|---|---|---|
| Field equality / inequality | `'Field Name' = 'value'`, `'Field Name' != 'value'` | Display fields must exist in the field dictionary or approved built-ins. |
| Boolean filters | `and`, `or`, grouped predicates | Preserve parentheses when operator precedence matters. |
| Wildcard text search | `'Field Name' like '*value*'` | Use token-aware wildcards for multi-word phrases. |
| Time buckets | `timestats span=<duration>` | KQL `bin(TimeGenerated, 5m)` maps to a Logan time aggregation only when the time field is known. |
| Aggregation | `stats count as Count by <fields>` | KQL `summarize`, SPL `stats`, and Elastic `STATS` map here. |
| Projection | `fields <fields>` | KQL `project`, SPL `table`, Elastic `KEEP`. |
| Computed fields | `eval <alias> = <expression>` | KQL `extend` and SPL `eval`; unsupported scalar functions stay blocked. |
| Ordering and limits | `sort -Count | head 100` | KQL `top N by` may become `sort` plus `head` when ranking an existing aggregate. |
| Distinct values | `distinct <fields>` or `stats count as Count by <fields>` | Chosen by converter path and downstream dashboard needs. |
| Lookups / watchlists | `lookup <name> <field>` plus dependency metadata | Never silently invent lookup contents. |
| Correlation / sequence | `link` / `sequence` when entity and ordering are preserved | Cross-table joins remain unsupported unless the correlation can be faithfully modeled. |

## Language Notes

### Microsoft Sentinel KQL

Sentinel conversion uses the repository KQL pipeline and mapping shards under
`config/mapping/`. Supported operators include `where`, `summarize`, `extend`
with approved scalar functions, `project`, `project-away`, `top`, `sort`,
`distinct`, simple scalar `let`, `countif`, `column_ifexists`, and time bins
that can become `timestats`. Unsupported constructs such as cross-table joins,
watchlist expansion, `mv-expand`, JSON bag expansion, `evaluate`, ML/series
operators, and true regex matching remain skipped with structured reasons.

### Sigma YAML

Sigma conversion goes through `scripts/convert_sigma.py`. Field and logsource
mapping are controlled by repository mapping config, not by the UI. Unsafe YAML
tags are blocked. Aggregation and timeframe semantics are marked partial unless
the converter can preserve the detection as a Logan query.

### Splunk SPL

Forge supports a bounded SPL pipeline parser for the common command families
documented in the Splunk search reference and summarized by the StationX SPL
cheat sheet:

- Base search predicates: `index`, `sourcetype`, field equality/inequality,
  wildcard values, `IN (...)`, and raw search terms. `index` and `sourcetype`
  are used as source hints; they are not emitted as OCI fields.
- Simple `where`: equality/range predicates, `IN (...)`, `isnull(field)`, and
  `isnotnull(field)`.
- Aggregation and time series: `stats count/sum/dc/values by ...`, `timechart
  span=<duration> count by ...`, and `_time` `bin`/`bucket` followed by
  `stats`.
- Output shaping: `table`, `fields`, `rename`, `sort`, `head`, `top`, and
  `dedup`. `dedup` is marked lossy because SPL keeps the first event while
  Logan `distinct` only preserves unique field tuples.
- Extraction: named-capture `rex` becomes `eval <field> = extract(...)`, and
  `spath input=<field> path=<json.path> output=<alias>` becomes an `eval`
  JSON-path extraction. Both remain lossy until validated against the parser.
- Enrichment: `lookup` is emitted only as a dependency on a named OCI lookup
  table; Forge never invents lookup contents.
- Correlation: simple `transaction <field...>` becomes `link <field...>` with a
  lossy warning. SPL transaction duration, `maxpause`, starts/ends, and first/last
  event semantics are not treated as equivalent to Logan `link`.

Macros and dashboard tokens must be expanded before conversion. Subsearches are
modeled as staged dependencies or lookup dependencies instead of being inlined.
`streamstats`, `eventstats`, `mvexpand`, and similar runtime commands produce
warnings because they depend on parser/runtime state. `join`, `inputlookup`,
`outputlookup`, and `tstats` are blocked instead of being rewritten as weaker
detections.

Reference links:

- <https://help.splunk.com/en/splunk-enterprise/spl-search-reference/10.4/introduction/welcome-to-the-search-reference>
- <https://help.splunk.com/en/splunk-enterprise/search/spl-search-reference/10.4/quick-reference/splunk-spl-for-sql-users>
- <https://help.splunk.com/en/splunk-enterprise/search/spl-search-reference/10.4/quick-reference/splunk-quick-reference-guide>
- <https://www.stationx.net/splunk-cheat-sheet/>

The next expansion candidates are deterministic, single-pipeline commands whose
semantics can be represented by real OCI Log Analytics fields: a restricted
function allow-list for `eval`, simple `chart` aggregation, and `rare`/frequency
hunting patterns. Commands that depend on Splunk indexes, acceleration, mutable
lookup state, macros, or cross-dataset execution stay dependency-gated or
unsupported until an OCI-equivalent contract is validated.

### Elastic Lucene / KQL / EQL / ES|QL / TOML

Elastic conversion uses the shared query IR in `scripts/ql/`. Lucene and KQL
filters map to Logan predicates. EQL sequences map only when the grouping key
and ordered events can be represented through `link` and `sequence`. ES|QL
`WHERE`, `STATS`, `KEEP`, `SORT`, and `LIMIT` map to predicates and pipeline
commands. Elastic TOML metadata is treated as request-scoped input; third-party
rule bodies are not persisted into generated aggregate artifacts.

### OCI Logan QL Passthrough

OCI Logan QL input is returned unchanged after lightweight language-mix checks.
If an input looks like KQL or another source language, Forge warns the user to
select the correct source mode.

## Safety Rules

The converter must not silently weaken security detections. When a source
construct cannot be represented faithfully, the response must be `lossy` with
explicit warnings or `unsupported` with a blocking reason. Generated workbench
artifacts and examples must not contain credentials, OCIDs, public IPs, tenancy
names, or unredacted live payloads.
