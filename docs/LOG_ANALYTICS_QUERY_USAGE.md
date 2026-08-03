# Using OCI Log Analytics Queries

This guide explains how SOC analysts, operators, and content authors use the
queries shipped by this repository. It covers selecting a query, reading OCI
Log Analytics Query Language (OCL), running a query in Log Explorer, validating
queries from the repository, and promoting reviewed queries into saved searches
or dashboards.

Query execution is read-only. Creating or updating a saved search, scheduled
search, parser, source, or dashboard changes OCI state and must follow the
deployment and approval workflow.

## 1. Choose the right query artifact

Runnable query JSON is organized by purpose:

| Location | Purpose | How it is maintained |
| --- | --- | --- |
| `queries/*.json` | Sigma-derived OCI, Windows, Linux, WAF, and other detections | Regenerate from `rules/**` with `scripts/convert_sigma.py` |
| `queries/sentinel/*.json` | Promoted Microsoft Sentinel conversions | Regenerate and promote through the Sentinel conversion workflow |
| `queries/apps/*.json` | Application, browser, APM, and GenAI analytics | Mixed generated and curated content; app queries use `SOC Application Logs` |
| `queries/hunting/*.json` | Curated hunts, correlations, scoring, and anomaly queries | Hand-authored query JSON |
| `queries/catalog.json` | Searchable inventory and metadata | Generated; not itself a runnable query |
| `queries/dashboard_inventory.json` | Dashboard-to-query mapping | Generated from `scripts/deploy_dashboard.py` |

Use `queries/catalog.json` or `CATALOG.md` to search by title, source, severity,
MITRE technique, or use case. Do not copy a query from
`queries/detection_rule_specs.json`; that file is a generated downstream
representation. Use the query JSON named by its `query_file` property instead.

For example, inspect a query and print only its runnable OCL:

```bash
sed -n '1,100p' queries/oci_console_login_failure.json
jq -r '.query' queries/oci_console_login_failure.json
```

## 2. Understand the query JSON

A typical query artifact looks like this:

```json
{
  "title": "OCI Console Login Failure",
  "description": "Detects failed OCI Console login attempts.",
  "query": "'Log Source' = 'OCI Audit Logs' and Status = 'Failure'",
  "level": "medium",
  "tags": ["attack.initial_access", "attack.t1078"],
  "logsource": {
    "product": "oci",
    "service": "audit",
    "candidates": ["OCI Audit Logs"]
  },
  "falsepositives": ["Expired passwords or MFA issues"]
}
```

Only the value of `query` is pasted into Log Explorer. The other properties tell
the analyst why the query exists, which data source it expects, how serious a
match may be, and which benign activity to consider during triage.

Before running a query, read these fields:

1. `description` — the behavior the query is intended to find.
2. `logsource` and `logsource.candidates` — required native or custom sources.
3. `query` — the executable OCL expression.
4. `falsepositives` — expected benign explanations.
5. `dashboard` — optional visualization and drilldown metadata.

## 3. Read and modify OCL safely

OCL follows a search-then-pipeline model:

```text
<source and event filters> | <transform or aggregate> | <filter> | <sort or limit>
```

Example:

```text
'Log Source' = 'Windows Security Events' and 'Event ID' = '4625'
| stats count as Failures, distinctcount('Source Address') as Sources by User
| where Failures > 3
| sort -Failures
```

The pre-pipe expression limits the events scanned. Pipeline commands transform
the matching events or aggregate them for an analyst-facing result.

### Field and literal rules

| Rule | Correct example |
| --- | --- |
| Quote multi-word field names | `'Log Source'`, `'Event ID'`, `'Principal Name'` |
| Leave single-token fields unquoted | `User`, `Status`, `Action`, `msg` |
| Quote string-typed numeric values | `'Event ID' = '4625'`, `'Response Code' = '403'` |
| Do not quote true numeric values | `'Destination Port' = 443`, `'Bytes Sent' > 0` |
| Use `*` with `like` | `'Command Line' like '*mimikatz*'` |
| Use an anchored regex with `matches` | `'Query Name' matches '^[A-Za-z0-9]{30,}\.'` |
| Use `in` for exact alternatives | `'Event ID' in ('4728', '4732', '4756')` |
| Test nulls explicitly | `'Process Name' != null` |

OCL `like` does not use SQL `%` wildcards. The repository performance audit
rejects `like '%value%'` as invalid query syntax.

### Common pipeline commands

| Command | Use | Example |
| --- | --- | --- |
| `fields` | Select result columns | `fields Time, User, 'Source IP'` |
| `stats` | Aggregate across the selected window | `stats count as Events by User` |
| `timestats` | Aggregate into time buckets | `timestats span = 1h count as Events` |
| `where` | Filter computed or aggregate values | `where Events > 10` |
| `eval` | Create a calculated field | `eval score = blocks + (rules * 5)` |
| `sort` | Order results; prefix with `-` for descending | `sort -Events` |
| `head` | Limit displayed rows | `head 25` |
| `link` | Group and correlate related events | `link 'Host Name', 'Process Name'` |
| `eventstats` | Add aggregate context without collapsing rows | `eventstats count as Connections by 'Source IP'` |

Put a post-aggregation `where` before `sort` so Log Analytics sorts only the
rows that will be displayed:

```text
... | stats count as Events by User | where Events > 10 | sort -Events
```

### Safe customizations

The most common operator changes are:

- select a compatible source from `logsource.candidates`;
- change a detection threshold such as `where Failures > 3`;
- add or remove a grouping field after `by`;
- add `fields`, `sort`, or `head` for an investigation view;
- simplify a correlation query to its pre-pipe filter while troubleshooting.

Keep repository queries tenant-neutral. Do not commit real OCIDs, namespaces,
entity names, IP addresses, user names, or other customer values. If an analyst
temporarily filters a live query for a real value, keep that copy in the OCI
Console and redact it before sharing evidence.

## 4. Run a query in OCI Log Explorer

Use the OCI Console for interactive analysis:

1. Sign in with an identity that can read Log Analytics data in the intended
   tenancy and compartment.
2. Open **Observability & Management**, then **Log Analytics**, then
   **Log Explorer**.
3. Confirm the selected compartment and any child-compartment scope required by
   the investigation.
4. Select an appropriate time range. Start with a narrow window for an
   interactive investigation and widen it only when necessary.
5. Copy only the JSON artifact's `query` value into the query editor.
6. Run the query and inspect the result columns, total matches, and time range.
7. Compare the result with the artifact's description and false-positive notes.

The search time window is selected outside the query. Repository queries are
deliberately time-agnostic so that the same query works in Log Explorer, a saved
search, a dashboard widget, or the SDK. Do not add a fixed date or a relative
time expression to a committed query.

### Start simple, then add analysis

When adapting a query, build it in stages:

```text
'Log Source' = 'OCI Audit Logs'
```

Then add a typed event filter:

```text
'Log Source' = 'OCI Audit Logs' and Status = 'Failure'
```

Aggregate only after the raw event filter works:

```text
'Log Source' = 'OCI Audit Logs' and Status = 'Failure'
| stats count as Failures by 'User Name', 'Source IP'
```

Finally, add the threshold and ordering:

```text
'Log Source' = 'OCI Audit Logs' and Status = 'Failure'
| stats count as Failures by 'User Name', 'Source IP'
| where Failures > 3
| sort -Failures
```

This sequence distinguishes missing data or incorrect fields from errors in a
later aggregation step.

## 5. Configure repository-assisted live use

The repository's live helpers use the OCI SDK and the profile selected by
`OCI_PROFILE`. Supply tenant-specific values through environment variables or a
local, uncommitted `.env.local.<PROFILE>` overlay.

Minimum configuration is normally:

```bash
export OCI_PROFILE="PROFILE_NAME"
export OCI_COMPARTMENT_ID="COMPARTMENT_OCID"
```

The tenancy is resolved from the selected OCI config profile when possible. The
Log Analytics namespace is auto-discovered when `LA_NAMESPACE` is not supplied.
If an operator explicitly supplies it, keep it in the local environment or
profile overlay because it identifies the tenancy.

Before any live operation, verify the active OCI profile, region, tenancy, and
compartment. The repository scripts fail when required configuration cannot be
resolved, but the operator is still responsible for selecting the intended
target.

## 6. Validate queries from the repository

Use the validation level appropriate to the evidence you need.

### Offline structure and performance checks

These commands do not query OCI:

```bash
# Reject invalid wildcard syntax and avoidable filter-after-sort pipelines.
python3 scripts/query_performance_audit.py --strict

# Validate fields against the generated source/field contract.
python3 scripts/field_dictionary.py --validate-query-fields

# Run repository tests.
python3 -m pytest -q
```

Offline success proves repository consistency. It does not prove that a field or
source exists in a particular tenancy, that data is being collected, or that a
query returns events.

### Live parser validation

Validate every runnable artifact against the configured Log Analytics namespace
without executing the searches:

```bash
OCI_PROFILE="PROFILE_NAME" python3 scripts/parse_validate_all_queries.py \
  --json docs/health/parse-validate-all.json
```

This checks OCL grammar and resolves referenced fields and sources against live
Log Analytics metadata. A parser pass does not prove that matching rows exist.

### Execute selected queries

Run only the query or small set needed for the investigation:

```bash
OCI_PROFILE="PROFILE_NAME" python3 scripts/query_audit.py \
  --lookback 24h \
  --files queries/oci_console_login_failure.json \
  --json
```

Multiple paths or basenames can follow `--files`. Add `--eligible-only` to
restrict a broader audit to scheduled-search-compatible queries. Use `--out`
to write a redacted JSON evidence report.

For complete live-data coverage testing:

```bash
OCI_PROFILE="PROFILE_NAME" python3 scripts/smoke_test_all_queries.py \
  --lookback 21d \
  --json docs/health/smoke-test-all.json
```

The smoke runner normally evaluates the raw event-filter portion of aggregate
queries so it can distinguish source coverage from an aggregation threshold. Use
`--include-aggregations` only when the final widget result itself is the test.

## 7. Interpret validation results

| Result | What it proves | What it does not prove |
| --- | --- | --- |
| Offline tests pass | JSON, mappings, generators, and repository contracts are consistent | The target tenancy has the fields or data |
| Live parser passes | OCL syntax, source names, and field references resolve in the target namespace | The query returns rows |
| Live query returns rows | Matching data exists in the selected target and time window | The query covers every compartment or all historical data |
| Query returns zero rows | No rows matched that exact target, scope, and window | That the behavior never occurred or collection is healthy |
| Dashboard deploys | Saved-search and dashboard resources were accepted | Every widget has representative data |

An empty query result is inconclusive. Record the selected profile, compartment,
region, time window, query file, and row count when producing validation
evidence, but redact tenant identifiers before committing or sharing it.

## 8. Troubleshoot errors or zero rows

Work through these checks in order:

1. **Target:** confirm the OCI profile, region, tenancy, compartment, and
   child-compartment scope.
2. **Collection:** run only the `'Log Source' = '...'` predicate and confirm the
   source has recent events.
3. **Source name:** compare `logsource.candidates` with the source display names
   available in the target namespace.
4. **Field contract:** search `queries/log_source_field_dictionary.json` for the
   field and expected sources.
5. **Field type:** quote string event IDs and response codes, but not true numeric
   ports or byte fields.
6. **Time window:** widen the window and account for ingestion delay.
7. **Query stages:** run the pre-pipe filter, then add `eval`, aggregation,
   threshold, sorting, and limiting one stage at a time.
8. **Performance:** reduce leading-wildcard or raw-message predicates only when
   an equivalent parsed field exists.

Common mistakes:

| Symptom | Likely cause | Correction |
| --- | --- | --- |
| Parser error near a field name | Multi-word field is not quoted | Use `'Field Name'` |
| Valid query, unexpectedly no rows | String numeric literal was unquoted | Use `'Event ID' = '4625'` |
| `like` does not match | SQL `%` wildcard was used | Use `*`, for example `like '*value*'` |
| Native source has no results | Wrong compartment, time range, or source display name | Verify target and run the source-only filter |
| Query is slow | Too many leading-wildcard/raw-content terms or a broad source scope | Narrow by source and parsed fields; review the performance report |
| Aggregate query is empty | Threshold is too high for the selected window | Run the raw filter, then aggregation without `where` |

See [Query Performance Guide](QUERY_PERFORMANCE_GUIDE.md) and the generated
[Query Performance Report](QUERY_PERFORMANCE_REPORT.md) for the current static
hotspots.

## 9. Save or deploy a reviewed query

### Save an investigation in the Console

After a query returns the expected data in Log Explorer, use the Console's save
action to create a saved search in the intended compartment. Give it a clear
name and description, keep its query time-agnostic, and re-run the saved search
to confirm it uses the intended scope.

Saving or updating a search changes OCI state. Confirm the target before saving,
and do not overwrite a shared search without reviewing its current definition
and ownership.

### Deploy repository dashboards and saved searches

Dashboard placement and saved-search deployment are owned by
`scripts/deploy_dashboard.py`. Preview locally first:

```bash
python3 scripts/deploy_dashboard.py --dry-run --skip-live-validation
```

For a live target, validate and deploy only after explicit operator approval and
target preflight. A focused deployment can select one dashboard:

```bash
OCI_PROFILE="PROFILE_NAME" python3 scripts/deploy_dashboard.py \
  --validate \
  --dashboard-name "<DASHBOARD_NAME>"
```

Do not hand-author generated dashboard inventory or duplicate deployment logic
in the webapp. Change dashboard definitions in `scripts/deploy_dashboard.py`,
then regenerate `queries/dashboard_inventory.json`.

## 10. Author or change repository queries

Use the canonical source for the query surface:

- For a Sigma-derived detection, edit `rules/**`, then run
  `scripts/convert_sigma.py`; do not hand-edit its generated JSON.
- For a Sentinel conversion, update converter or mapping inputs and promote it
  through the Sentinel workflow; do not hand-edit `queries/sentinel/**`.
- For curated app analytics, edit `queries/apps/**` and keep the source on
  `SOC Application Logs`.
- For curated hunting content, edit `queries/hunting/**`.

After a source detection change, run the standard local workflow:

```bash
python3 scripts/convert_sigma.py
python3 scripts/generate_catalog.py
python3 scripts/export_for_multicloud.py --manifest-only
python3 scripts/audit_rule_quality.py --report docs/RULE_QUALITY_REPORT.md
python3 scripts/query_performance_audit.py --strict
python3 -m pytest -q
```

For app queries, also run:

```bash
python3 -m pytest scripts/test_app_query_contract.py -q
```

Never add placeholder fields merely to make a conversion compile. Every field
must be an approved OCI Log Analytics display field or part of a validated
custom parser contract.

## Further reading

- [OCI Log Analytics documentation](https://docs.oracle.com/en-us/iaas/log-analytics/home.htm)
- [Query Performance Guide](QUERY_PERFORMANCE_GUIDE.md)
- [Architecture](ARCHITECTURE.md)
- [Monitoring](MONITORING.md)
- [Threat Hunting Walkthrough](THREAT_HUNTING_WALKTHROUGH.md)
- [Contributing](../CONTRIBUTING.md)
