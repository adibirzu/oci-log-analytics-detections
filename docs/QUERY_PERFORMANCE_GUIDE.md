# OCI Log Analytics Query Performance Guide

This repository treats query performance as an evidence-backed release concern.
Static analysis identifies likely scan cost and avoidable pipeline work; OCI
parser validation and representative live timings remain the acceptance proof.
For the end-to-end analyst and operator workflow, see
[Using OCI Log Analytics Queries](LOG_ANALYTICS_QUERY_USAGE.md).

## What the Oracle ingestion guidance means here

Oracle's [Extended Field Extraction Expression guidance](https://docs.oracle.com/en-us/iaas/log-analytics/doc/write-performant-extended-field-extraction-expression.html)
requires extraction expressions to avoid leading or trailing match-all regex,
use no more than four match-all fragments, limit conditions or alternatives,
include static text, and pass the parser test function.

The custom sources in this repository use JSON-path field mappings in
`scripts/logsources/`, not Extended Field Extraction Expressions. Do not replace
those mappings with broad regular expressions. If a non-JSON source later needs
an extended extraction, validate it against all of Oracle's limits before adding
it to the source setup workflow.

Oracle's [SQL Query Guidelines](https://docs.oracle.com/en-us/iaas/log-analytics/doc/sql-query-guidelines.html)
apply to database log sources that periodically extract records with SQL. Such a
query must be read-only, run with least-privilege credentials, expose an indexed
monotonic timestamp or sequence column, and omit `ORDER BY` and cursor-field
`WHERE` clauses because Log Analytics applies them. This repository does not
currently configure a Log Analytics database SQL source. The SQL strings in
`config/osquery/packs/` are osquery endpoint telemetry and are not database-source
collection queries governed by that page.

## OCL performance contract

Run the tenant-neutral static audit:

```bash
python3 scripts/query_performance_audit.py --strict
```

The strict gate rejects SQL-style `%` wildcards (OCL `like` uses `*`) and a
post-aggregation `where` placed after `sort`, because filtering the aggregate
first preserves the result while reducing the rows that must be sorted. The
audit also inventories these advisory risks:

- `like '*value*'` predicates, especially queries containing many such terms;
- wildcard scans of `msg` or `'Original Log Content'` instead of parsed fields;
- regex predicates that require representative-data review.

Advisories do not fail the release gate. Some security detections are inherently
scan-bound, and rewriting them without an equivalent parsed field would reduce
coverage. Prefer exact equality, `in (...)`, prefix matching (`like 'value*'`),
or a typed parser field only when the source contract supports the same meaning.

For a review artifact:

```bash
python3 scripts/query_performance_audit.py \
  --json docs/health/query-performance.json \
  --markdown docs/QUERY_PERFORMANCE_REPORT.md
```

## Validation boundary

Static success proves only repository-level shape. Before calling a query
performant in a tenancy:

1. Parse-validate the query against the target Log Analytics namespace.
2. Execute it over representative data and the intended lookback window.
3. Compare elapsed time and result parity before and after the rewrite.
4. Treat an empty result as inconclusive, not proof that the query is correct or
   inexpensive.

Live OCI validation requires explicit operator direction and the repository's
normal profile and compartment preflight.
