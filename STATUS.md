# Project Status

Date: 2026-04-28

## Current State

- Source Sigma/YAML rules: 454
- Sigma-derived OCI queries: 454
  - 446 top-level detections in `queries/`
  - 8 browser/app telemetry detections in `queries/apps/`
- Curated analytics: 61
  - 16 app telemetry analytics
  - 45 hunting analytics
- Total query artifacts: 515
- Dashboards: 16
- Saved searches: 264
- Sample data: 14 NDJSON files / 146,632 events
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
- `test_data/manifest.json` is rebuilt from the checked-in `*.jsonl` files rather than hand-maintained counts.
- Streaming pipeline reconciliation refreshes `config/streaming_config.json` against the active tenancy resources.
- `LoganSecurityDashboardv0` is documented as the companion operator UI and should consume this repo's catalog, manifest, query, and test-data artifacts instead of duplicating detection-generation logic.

## Quality and Verification

Local verification on 2026-04-28:

- `python3 scripts/audit_rule_quality.py --report docs/RULE_QUALITY_REPORT.md`
  - 454 rules
  - 454 source-derived queries
  - 0 issues
- `python3 -m pytest -q`
  - 81 tests passed
- `python3 -m compileall scripts`
  - passed
- `python3 scripts/deploy_dashboard.py --dry-run`
  - 16 dashboards
  - 264 saved searches
- `python3 scripts/deploy_dashboard.py --validate`
  - 515 query files OK
- `python3 scripts/ingest_test_data.py --validate`
  - 14 datasets and log source mappings passed
- `python3 scripts/setup_log_sources.py --validate`
  - pre-flight validation passed

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
- `test_data/manifest.json` is current as of 2026-04-28 and reports 146,632 checked-in events, dominated by the 14-day multicloud health dataset.

## Documentation Map

- `README.md` — public overview, quickstart, deployment, and dashboard inventory
- `docs/ARCHITECTURE.md` — source/generation/deployment architecture
- `CATALOG.md` — human-readable content catalog
- `queries/catalog.json` — canonical machine-readable inventory
- `docs/DEMO_WORKFLOW.md` — demo/operator walkthrough
- `docs/RULE_QUALITY_REPORT.md` — latest quality audit output
- `CONTRIBUTING.md` — contributor workflow and validation expectations
- `../LoganSecurityDashboardv0/docs/ARCHITECTURE.md` — companion dashboard integration contract
- `docs/DASHBOARD_INTEGRATION_GAPS.md` — detections-owned export/schema/API gaps for the companion dashboard
- `../LoganSecurityDashboardv0/docs/CAPABILITY_CORRELATION.md` — dashboard-owned capability matrix and missing UI features

## Recommended Next Work

- Add `DET-MISS-001`: generate a machine-readable dashboard/widget inventory so the companion dashboard does not parse `scripts/deploy_dashboard.py`.
- Add smoke tests around dashboard/query references so widget regressions are caught before deployment.
- Publish `DET-MISS-002`: a versioned integration schema for catalog, dashboard inventory, saved searches, datasets, and log-source fields.
- Expand live verification beyond Caldera discovery so credential-access, lateral-movement, collection, and exfiltration have deterministic demo data.
- Add sample ingestion/validation checks for the `test_data/` datasets to verify schemas alongside query generation.
- Expand source rule coverage only after log source mappings and test datasets exist for the new telemetry surface.
