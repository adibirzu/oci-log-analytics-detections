# Project Status

Date: 2026-05-03

## Current State

- Core scope: OCI Log Analytics query generation, synthetic log generation, query/dashboard validation, and OCI dashboard creation.
- Source Sigma/YAML rules: 454
- Sigma-derived OCI query artifacts: 486
  - 478 top-level detections in `queries/`
  - 8 browser/app telemetry detections in `queries/apps/`
- Curated analytics: 61
  - 16 app telemetry analytics
  - 45 hunting analytics
- Total query artifacts: 547
- Dashboards: 16
- Saved searches: 264
- Generated demo data: 14 NDJSON files / 2,904 events in the latest local `test_data/manifest.json`
- MITRE ATT&CK coverage: 211 techniques / 14 tactics
- STIG coverage: 24 detections / 12 controls

## Architecture Updates Shipped

- `rules/**` is now explicitly documented as the source authoring layer.
- `queries/catalog.json` is treated as the canonical machine-readable inventory.
- `queries/manifest.json` is treated as an export/integration artifact instead of the canonical inventory.
- Sigma-derived browser detections under `rules/web/browser_attacks/` publish into `queries/apps/`.
- Generated query paths are stabilized by `sigma_id`, which avoids filename churn when titles change.
- Catalog generation, rule quality auditing, and multicloud export now walk the full `queries/**` tree instead of assuming everything lives at the top level.
- Browser/app dashboards now run on `SOC Application Logs`, a custom JSON source that carries OpenTelemetry-shaped fields into OCI Log Analytics.
- Browser attack dashboards now include APM/WAF showcase widgets for attack volume, OWASP breakdown, trace correlation, and cross-tier WAF correlation.
- `queries/dashboard_inventory.json` is generated from `scripts/deploy_dashboard.py:DASHBOARDS` and is the dashboard-facing saved-search/widget inventory.
- Dashboard deployment now validates the generated inventory locally and validates every unique dashboard query in OCI Log Analytics before importing dashboards or embedded saved searches.
- Live query validation runs each query in an isolated child process so slow or hung queries become blocking validation failures instead of reaching dashboard import.
- Dashboard saved-search widgets now default to `l24h`, and the deploy-time OCI query validation default lookback is `24h`, matching the generated one-day security dataset.
- Dashboard contract tests now block unsupported live-validation query patterns such as `regexextract`, `countif`, `case`, unmapped Windows fields, and regex-match expressions before OCI import.
- BLUELIGHT (S0657 / APT37) APT dashboard now leads with 5 showcase widgets (Total Detections KPI tile, Top Affected Hosts summary, MITRE Tactics × Techniques sunburst, Kill Chain Timeline line chart, Attack Path link analysis) followed by the 17 per-stage detection widgets, presenting the full attack chain on a single canvas.
- WAF parser now extracts `Trace ID` so APM browser attacks correlate to upstream WAF blocks across `SOC Application Logs` and `SOC WAF Security Logs` via shared `traceId`.
- BLUELIGHT kill-chain test data is mirrored into both `windows_sysmon.jsonl` (SOC Windows Sysmon parser, 35 field maps) and `sysmon_operational.jsonl` (Sysmon Operational parser) so per-widget detections match through whichever parser route propagates first.
- All BLUELIGHT queries standardised on quoted `'Event ID' = 'N'` form — OCI LA returns HTTP 400 on unquoted numeric comparisons against String-typed fields, so the convention applies repo-wide for parser-string fields.
- `scripts/smoke_test_bluelight.py` — live OCI LA query runner reports HIT/MISS/ERROR per widget with row counts, used as the green-light gate before deploys.
- Synthetic OCI audit logs now expose operator-friendly `Status` labels and policy keywords needed by dashboard searches; Windows, Sysmon, Linux, and WAF datasets now include rare processes, named-pipe IOCs, DNS tunneling tools, Linux command lines, CORS attacks, and allowed SQLi cases so matching widgets populate from generated data.
- `test_data/manifest.json` is rebuilt from generated `*.jsonl` files rather than hand-maintained counts.
- Streaming pipeline reconciliation refreshes `config/streaming_config.json` against the active tenancy resources.
- `LoganSecurityDashboardv0` is documented as the companion operator UI and consumes this repo's catalog, dashboard inventory, and test-data artifacts instead of duplicating detection-generation logic.

## Branch and Worktree State

- Only `main`, `origin/main`, and `origin/HEAD -> origin/main` are present after `git fetch --all --prune`.
- The worktree was clean at the start of the 2026-05-03 scope cleanup pass.
- Optional runtime helpers remain in the repository for Log Analytics ingestion support, but the canonical surfaces are `rules/**`, `queries/**`, generated manifests, synthetic logs, and dashboard deployment scripts.

## Quality and Verification

Local scope-cleanup verification on 2026-05-03:

- `python3 -m pytest -q`: 129 passed, 5 skipped
- `python3 -m compileall -q scripts`: passed
- `python3 scripts/generate_test_logs.py --days 1 --validate`: 2,904 events across 14 files; 547 query files counted across query surfaces

Previous local and pre-flight verification on 2026-04-28 before the current catalog expansion:

- `python3 scripts/audit_rule_quality.py --report docs/RULE_QUALITY_REPORT.md`
  - 454 rules / 454 source-derived queries / 0 issues
- `python3 -m pytest -q`
  - 88 tests passed
- `python3 -m compileall scripts`
  - passed
- `python3 scripts/deploy_dashboard.py --validate`
  - OCID, CLI profile, namespace, compartment, and 515 query files passed
- `python3 scripts/deploy_dashboard.py --dry-run`
  - 16 dashboards / 264 saved searches resolved from generated inventory
- `python3 scripts/deploy_dashboard.py --cleanup`
  - 250/250 unique dashboard queries validated in OCI Log Analytics with 24-hour lookback
  - 67 validated query files returned no rows in that window
  - 16 dashboards imported with 264 embedded saved searches
- `python3 scripts/generate_test_logs.py --days 1 --validate`
  - 1,541 core security/app events generated and 515 query files counted across all query surfaces
- `python3 scripts/generate_geo_health_logs.py --duration 60 --interval 5`
  - 1,296 multicloud health events generated
- `python3 scripts/ingest_test_data.py --validate`
  - 14 datasets and log source mappings passed
- Targeted live OCI validation:
  - `python3 scripts/smoke_test_bluelight.py --lookback 24h`: 17/17 BLUELIGHT detection widgets HIT
  - Dashboard listing check: 16/16 dashboard display names found once after cleanup import

Previously live-verified on 2026-04-28 (eu-frankfurt-1):

- `python3 scripts/smoke_test_bluelight.py --lookback 24h`
  - 17/17 BLUELIGHT detection widgets HIT
  - 5/5 BLUELIGHT showcase widgets HIT
  - 13/13 APM browser-attack widgets HIT including cross-tier WAF correlation
- `python3 scripts/setup_log_sources.py`
  - 13 parsers OK
- `python3 scripts/ingest_test_data.py --mode direct`
  - 14/14 uploads completed

Previously live-verified on 2026-04-15:

- `python3 scripts/setup_log_sources.py`
  - succeeded
  - all parsers mapped cleanly, including `Logon ID` and `Integrity Level`
- `python3 scripts/setup_streaming_pipeline.py`
  - rewrote `config/streaming_config.json` for the active compartment/log group
  - 5 SOC connectors active
- `python3 scripts/validate_pipeline.py --e2e`
  - all checks passed
  - end-to-end publish and delivery verified through Log Analytics
- `python3 scripts/verify_caldera_detections.py --operation discovery --lookback 60d`
  - 3/3 discovery verification queries matched
- `python3 scripts/export_for_multicloud.py --manifest-only`
  - 454 Sigma-derived queries exported

## Current Runtime Notes

- `validate_pipeline.py` now derives expected streams/connectors from `config/streaming_config.json`, so the multicloud-health connector is validated alongside the core SOC pipeline.
- Redundant active connectors were removed from the compartment without affecting the SOC streaming path.
- `test_data/manifest.json` is current as of 2026-05-03 and reports 2,904 generated local events. `test_data/` is ignored by git and should be regenerated before a fresh ingest.

## Documentation Map

- `README.md` — public overview, quickstart, deployment, and dashboard inventory
- `docs/ARCHITECTURE.md` — source/generation/deployment architecture
- `CATALOG.md` — human-readable content catalog
- `queries/catalog.json` — canonical machine-readable inventory
- `queries/dashboard_inventory.json` — dashboard/widget/saved-search inventory for companion UIs
- `docs/INTEGRATION_SCHEMA.md` — generated artifact contract for downstream integrations
- `docs/DEMO_WORKFLOW.md` — demo/operator walkthrough
- `docs/RULE_QUALITY_REPORT.md` — latest quality audit output
- `CONTRIBUTING.md` — contributor workflow and validation expectations
- `../LoganSecurityDashboardv0/docs/ARCHITECTURE.md` — companion dashboard integration contract
- `docs/DASHBOARD_INTEGRATION_GAPS.md` — detections-owned export/schema/API gaps for the companion dashboard
- `../LoganSecurityDashboardv0/docs/CAPABILITY_CORRELATION.md` — dashboard-owned capability matrix and missing UI features

## Recommended Next Work

- Keep `queries/dashboard_inventory.json` regenerated with dashboard changes.
- Expand `DET-MISS-002` with a generated log-source field dictionary for parser fields and display labels.
- Expand live verification beyond Caldera discovery so credential-access, lateral-movement, collection, and exfiltration have deterministic demo data.
- Add sample ingestion/validation checks for the `test_data/` datasets to verify schemas alongside query generation.
- Expand source rule coverage only after log source mappings and test datasets exist for the new telemetry surface.
