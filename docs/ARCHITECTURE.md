# OCI Log Analytics Detections Architecture

Date: 2026-05-03

## Purpose

This repository is organized around OCI Log Analytics query and dashboard creation:

1. Author portable detections as Sigma YAML under `rules/`
2. Convert source rules into OCI Log Analytics query JSON
3. Layer curated app, WAF, geographic health, and hunting analytics beside the generated detections
4. Generate synthetic logs that populate the Log Analytics dashboards
5. Validate every dashboard query before importing dashboards or embedded saved searches
6. Publish canonical inventory artifacts for companion UIs and downstream readers

The goal is to keep source authoring, generated content, and deployment metadata separate so the project stays maintainable as the catalog grows.

One important detail for the current shipping implementation: browser and application detections do not query native OCI APM entities directly. They run against `SOC Application Logs`, a custom OCI Log Analytics JSON source whose schema is intentionally shaped like OpenTelemetry/browser telemetry but expressed using OCI LA display names.

## Canonical Content Surfaces

| Path | Type | Count | Notes |
|------|------|-------|-------|
| `rules/**` | Source Sigma/YAML authoring layer | 454 | Source of truth for source-derived detections |
| `queries/*.json` | Generated top-level OCI detection queries | 478 | Produced by `scripts/convert_sigma.py` |
| `queries/apps/*.json` | App telemetry query surface | 24 | 8 Sigma-derived browser detections + 16 curated app analytics |
| `queries/hunting/*.json` | Curated hunting analytics | 45 | Frequency, anomaly, scoring, and correlation content |
| `queries/catalog.json` | Canonical machine-readable inventory | 1 | Use this for published counts and downstream tooling |
| `queries/dashboard_inventory.json` | Dashboard/widget inventory | 1 | Generated from `DASHBOARDS`; use this for dashboard UI mapping |
| `queries/manifest.json` | Export/integration manifest | 1 | Generated artifact for multicloud export, not the canonical inventory |

Important distinction:

- There are **486 Sigma-derived OCI query artifacts** in total.
- Those 486 are split across **478 top-level detections** in `queries/` and **8 browser/app telemetry detections** in `queries/apps/`.
- The repo also ships **61 curated analytics** that are not Sigma-derived: 16 app telemetry analytics and 45 hunting queries.

## Architecture Flow

```text
rules/** ------------------------------------------+
                                                   |
                                                   v
                                      scripts/convert_sigma.py
                                      - field/logsource mapping
                                      - stable filename reuse via sigma_id
                                      - browser rule routing to queries/apps/
                                      - metadata preservation for curated JSON
                                                   |
                         +-------------------------+-------------------------+
                         |                                                   |
                         v                                                   v
                 queries/*.json                               queries/apps/*.json
           478 generated detections                    8 Sigma-derived browser queries

queries/apps/*.json (16 curated app analytics) -------+
queries/hunting/*.json (45 curated analytics) --------+----> scripts/generate_catalog.py
                                                            - CATALOG.md
                                                            - queries/catalog.json
                                                            - inventory/coverage summary

queries/** -----------------------------------------------> scripts/export_for_multicloud.py
                                                            - queries/manifest.json
                                                            - downstream integration payload

queries/** -----------------------------------------------> scripts/deploy_dashboard.py
                                                            - 16 dashboards
                                                            - 264 embedded saved searches
                                                            - queries/dashboard_inventory.json
```

## Design Invariants

- `rules/**` is the authoring layer. Do not treat generated JSON as the primary source for source-derived detections.
- `sigma_id` is the durable identity for generated detections. Generated filenames should remain stable even if titles change.
- Rules under `rules/web/browser_attacks/` intentionally publish into `queries/apps/` because they execute against `SOC Application Logs`, a custom app/browser telemetry surface rather than the top-level server-side detection surface.
- `queries/catalog.json` is the canonical inventory for documentation, exports, and automation.
- `queries/dashboard_inventory.json` is the dashboard-facing contract generated from `scripts/deploy_dashboard.py:DASHBOARDS`.
- `queries/manifest.json` is an integration artifact. It should be regenerated from the current queries, but it is not the canonical source for published counts.
- Streaming, Service Connector Hub, Resource Manager, and manifest export scripts are runtime support. They should not become the source of truth for query, dashboard, or catalog state.
- `logandetectionqueries/` and `logandetectionrules/` are legacy empty directories and should not be consumed by tooling.

## Application Telemetry Surface

`scripts/setup_log_sources.py` creates the `SOC Application Logs` source and parser used by the browser/app dashboards. The parser maps OpenTelemetry-shaped JSON onto OCI Log Analytics fields such as:

- `Service Name`
- `Trace ID`
- `Request URL`
- `Response Code`
- `Span Name`
- `Span Attributes`
- `Referrer`

This keeps the query layer stable even when the raw event producer is browser JavaScript, an application service, or a generated synthetic NDJSON dataset under `test_data/`.

## Capability Inventory

- Source rule coverage:
  - Windows: 249
  - Cloud/OCI: 100
  - Linux: 67
  - Web/WAF: 38
- Combined query inventory:
  - 547 total query artifacts
  - 211 MITRE ATT&CK techniques across 14 tactics
  - 24 STIG-mapped detections across 12 controls
- Dashboard layer:
  - 16 dashboards
  - 264 widget-backed saved searches
  - 16 advanced visualization widgets (`tile`, `sunburst`, `summary_table`, `line`, `bar`, `link`, and `map`)
- Demo/test data:
  - 14 NDJSON files
  - 2,904 sample events in the latest generated local `test_data/manifest.json`
  - `test_data/` is ignored by git and should be regenerated before a fresh OCI ingest
- Streaming/runtime surface:
  - 5 configured SOC detection streams validated end-to-end
  - `soc-detection-multicloud-health` is active in the current environment

## Validation Pipeline

Use these commands as the baseline release/verification loop:

```bash
python3 scripts/setup_log_sources.py
python3 scripts/convert_sigma.py
python3 scripts/generate_catalog.py
python3 scripts/deploy_dashboard.py --export-inventory
python3 scripts/export_for_multicloud.py --manifest-only
python3 scripts/generate_test_logs.py --days 1 --validate
python3 scripts/generate_geo_health_logs.py --duration 60 --interval 5
python3 scripts/ingest_test_data.py --validate
python3 scripts/audit_rule_quality.py --report docs/RULE_QUALITY_REPORT.md
python3 scripts/deploy_dashboard.py --dry-run
python3 -m pytest -q
python3 -m compileall scripts
```

Use these live OCI checks when validating the deployed environment:

```bash
python3 scripts/setup_streaming_pipeline.py
python3 scripts/validate_pipeline.py --e2e
python3 scripts/verify_caldera_detections.py --operation discovery --lookback 60d
python3 scripts/smoke_test_bluelight.py --lookback 24h
```

Previous local verified state on 2026-04-28 before the current catalog expansion:

- Rule quality audit: 0 issues
- Unit tests: 88 passing
- Dashboard dry-run: 16 dashboards / 264 saved searches resolved
- Dashboard validation: 515 query files OK
- Dashboard cleanup deploy: 250/250 unique OCI queries validated, 16 dashboards imported, 264 embedded saved searches
- Ingest validation: 14 datasets and log source mappings passed
- Log-source pre-flight validation: passed
- BLUELIGHT live smoke test: 17/17 widgets returned rows with a 24-hour lookback

Previously live-verified on 2026-04-15:

- Pipeline E2E validation: passed
- Caldera discovery verification: 3/3 queries matched
- Log-source setup: parsers and sources aligned with no missing Windows Sysmon fields
- Streaming pipeline reconciliation: 5/5 SOC connectors active

Current runtime note:

- `validate_pipeline.py` derives expected streams and connector names from `config/streaming_config.json`, so the multicloud-health path is verified alongside the core SOC streams.
- Direct NDJSON ingestion and the SOC streaming pipeline are both operational.
- `deploy_dashboard.py` defaults dashboard widgets to `l24h` and validates dashboard queries with a 24-hour live OCI lookback before importing saved searches.

## Companion Dashboard

`../LoganSecurityDashboardv0` is the companion operator UI for this content library. This repository remains the canonical content source; the dashboard should consume generated artifacts through a stable export, API, or MCP boundary.

Capability correlation and missing-feature references are tracked in:

- `docs/DASHBOARD_INTEGRATION_GAPS.md` for detections-owned `DET-MISS-*` export/schema/API gaps
- `../../LoganSecurityDashboardv0/docs/CAPABILITY_CORRELATION.md` for dashboard-owned `DASH-MISS-*` UI/data-layer gaps

Supported dashboard-facing artifacts:

- `queries/catalog.json`
- `queries/dashboard_inventory.json`
- `queries/manifest.json`
- `queries/*.json`
- `queries/apps/*.json`
- `queries/hunting/*.json`
- `test_data/manifest.json`

The dashboard should not duplicate Sigma conversion, dashboard deployment, or query catalog generation.

## Contribution Model

Use the surface that matches the content you are adding:

- New source-derived detections:
  - Add Sigma YAML under `rules/**`
  - For browser-side detections, place the rule under `rules/web/browser_attacks/`
- New curated app analytics:
  - Add JSON under `queries/apps/`
  - Do not add a `sigma_id` unless the file is source-derived
- New hunting analytics:
  - Add JSON under `queries/hunting/`

After changes, regenerate the catalog and rerun the validation pipeline so published inventory and dashboard references stay aligned.
