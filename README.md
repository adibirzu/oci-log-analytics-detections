# OCI Log Analytics Detection Rules

A comprehensive STIG-compliant detection rules library for Oracle Cloud Infrastructure (OCI) Log Analytics. Converts industry-standard [Sigma](https://github.com/SigmaHQ/sigma) rules into OCI Log Analytics Query Language (OCL) with MITRE ATT&CK and STIG compliance mapping. Enhanced with advanced threat hunting queries, APT-specific detection (BLUELIGHT/APT37), and browser/application attack detection via `SOC Application Logs`, an OpenTelemetry-shaped custom JSON telemetry surface for OCI Log Analytics.

## Current Inventory
This repository ships both source authoring content and generated OCI query assets. Published counts should come from the generated catalog, not from hand-maintained release notes.

- **Source Sigma/YAML rules:** 454
- **Sigma-derived OCI queries:** 454
  - 446 top-level detections in `queries/*.json`
  - 8 browser/app telemetry detections in `queries/apps/*.json`
- **Curated analytics:** 61
  - 16 app telemetry analytics in `queries/apps/`
  - 45 hunting analytics in `queries/hunting/`
- **Total query artifacts:** 515
- **Source rule breakdown:** Windows (249), Cloud/OCI (100), Linux (67), Web/WAF (38)
- **Combined MITRE ATT&CK coverage:** 211 techniques across 14 tactics
- **STIG coverage:** 24 detections spanning 12 controls
- **Dashboard inventory:** 16 dashboards with 264 saved searches and 16 advanced visualization widgets
- **Sample data in repo:** 146,693 events across 14 NDJSON files
- **Target environment:** OCI-DEMO Landing Zone (`demo-observability` compartment)

Canonical inventory and supporting documentation:

- `queries/catalog.json` — canonical machine-readable inventory
- `queries/dashboard_inventory.json` — generated dashboard/widget/saved-search inventory
- `queries/manifest.json` — export artifact for downstream integrations
- `docs/ARCHITECTURE.md` — source/generation/deployment architecture
- `docs/INTEGRATION_SCHEMA.md` — generated artifact schema contract
- `CATALOG.md` — human-readable catalog
- `docs/DEMO_WORKFLOW.md` — operator/demo walkthrough
- `docs/RULE_QUALITY_REPORT.md` — latest quality audit report
- `docs/DASHBOARD_INTEGRATION_GAPS.md` — detections-side gaps blocking the companion dashboard
- `CONTRIBUTING.md` — contributor workflow and validation expectations

## Architecture

The repo is intentionally split into three content surfaces:

- `rules/**` — source Sigma/YAML authoring layer
- `queries/*.json` and source-derived files in `queries/apps/` — generated OCI detections
- `queries/apps/*.json` curated analytics and `queries/hunting/*.json` — hand-authored app and hunting content

The canonical architecture contract is documented in `docs/ARCHITECTURE.md`. The short version is:

```text
rules/** ------------------------------------------> scripts/convert_sigma.py
                                                        |
                                                        +--> queries/*.json
                                                        +--> queries/apps/*.json (8 Sigma-derived browser detections)

queries/apps/*.json (16 curated app analytics) --------+
queries/hunting/*.json (45 hunting analytics) ---------+--> scripts/generate_catalog.py
                                                             |
                                                             +--> CATALOG.md
                                                             +--> queries/catalog.json

queries/** -----------------------------------------------> scripts/export_for_multicloud.py --manifest-only
                                                             |
                                                             +--> queries/manifest.json

queries/** -----------------------------------------------> scripts/deploy_dashboard.py
                                                             |
                                                             +--> 16 dashboards / 264 saved searches
                                                             +--> queries/dashboard_inventory.json
```

### Data Flow

```
  Sysmon/Windows Events ─────┐
  Linux Syslog/Secure ───────┤
  OCI Audit Events ──────────┤──> OCI Streaming ──> Service Connector Hub ──> Log Analytics
  Cloud Guard Problems ──────┤                                                    |
  WAF/LB Access Logs ────────┤                                                    v
  App/Browser Telemetry JSON ─┘                                         SOC Dashboards (16)
                                                                        Saved Searches (264)
  Test Data (NDJSON) ──> Upload API ──> Log Analytics ──> Dashboard Verification
```

Browser and app dashboards currently run against `SOC Application Logs`, a custom OCI Log Analytics source created by `scripts/setup_log_sources.py`. The contract intentionally uses OCI LA display names such as `Service Name`, `Trace ID`, `Request URL`, `Response Code`, `Span Name`, `Span Attributes`, and `Referrer` so the queries remain valid against the deployed parser.

### Canonical Inventory Contract

Treat the following as the canonical output contract for downstream integrations such as `mcp-oci-logan-server` and `LoganSecurityDashboardv0`:

- `queries/catalog.json` for authoritative counts and inventory
- `queries/dashboard_inventory.json` for dashboard, widget, saved-search, visualization, and query-file mapping
- `queries/*.json` for generated top-level detection queries
- `queries/apps/*.json` for mixed app telemetry content
- `queries/hunting/*.json` for hunting queries
- `queries/manifest.json` as the generated export/integration artifact
- `test_data/manifest.json` for checked-in demo dataset counts

Notes:

- `rules/` is the source-of-truth authoring layer
- `sigma_id` identifies source-derived generated detections
- `queries/catalog.json` is canonical; `queries/manifest.json` is derivative
- `queries/dashboard_inventory.json` is generated from `scripts/deploy_dashboard.py:DASHBOARDS`
- `queries/apps/` contains both generated browser detections and curated app analytics
- `LoganSecurityDashboardv0` should consume these generated artifacts rather than duplicating detection-generation logic
- `logandetectionqueries/` and `logandetectionrules/` are legacy empty directories and should not be consumed

## OCI Log Analytics Dashboards

### SOC Detection Dashboards (16)
| Dashboard | Widgets | Purpose |
| :--- | :--- | :--- |
| SOC Overview Dashboard | 14 | Executive-level cross-domain security summary + hunting alerts |
| SOC: OCI STIG Compliance | 17 | STIG compliance: MFA, key rotation, vault secrets, audit config |
| SOC: OCI Audit Security | 22 | IAM, network, compute, storage, KMS, DB, bastion, discovery |
| SOC: Cloud Guard Security | 12 | Cloud Guard problem detection |
| SOC: Linux Security | 20 | SSH, sudo, persistence, container escape, injection, C2 |
| SOC: Linux Advanced Threats | 18 | Web shells, cryptominers, exfiltration, scanning, hidden files |
| SOC: Windows Security | 20 | Credential theft, encoded PS, LOLBins, lateral movement |
| SOC: Windows Advanced Threats | 18 | Kerberoasting, pass-the-hash, process hollowing, RATs |
| SOC: Threat Hunting | 16 | Cookbook-inspired: frequency, anomaly, scoring, multi-stage |
| SOC: Sysmon Network & Lateral | 17 | C2 beacons, SMB/WinRM/RDP lateral, DNS tunneling, pipes |
| SOC: Web Application Security | 30 | OWASP Top 10: SQLi, XSS, SSRF, path traversal, CORS, IDOR |
| SOC: Web Threat Hunting | 8 | WAF frequency, SQLi stacking, multi-attack scoring, geo anomaly |
| SOC: APT Detection | 22 | BLUELIGHT RAT (S0657/APT37) summary KPIs, kill chain, links, and YARA enrichment |
| SOC: Browser Attack Detection | 13 | SOC Application Logs: APM/WAF correlation, OWASP mix, XSS, SQLi, CSRF, session hijack |
| SOC: Geographic Health | 5 | Multicloud health visualization (OCI, Azure, AWS, GCP) |
| OCI-DEMO: Application 360 Monitoring | 12 | CRM + Drone Shop: trace telemetry, WAF correlation, DB perf |

### APT Detection: BLUELIGHT RAT (S0657/APT37)
Full kill chain detection for the North Korean BLUELIGHT Remote Access Trojan:

| Stage | Rule | MITRE Technique | Level |
| :--- | :--- | :--- | :--- |
| Initial Access | Drive-by Compromise (CVE-2020-1380, CVE-2021-26411) | T1189 | medium |
| Execution | Browser Spawning Suspicious Child Process | T1203 | high |
| Defense Evasion | Obfuscated Script Execution (XOR key 0xCF) | T1027 | high |
| C2 | Microsoft Graph API Communication | T1071.001 | medium |
| Discovery | WMI System Enumeration from Browser | T1082 | high |
| Discovery | Registry Enumeration of Security Products | T1012 | medium |
| Discovery | File Discovery from Browser Process | T1083 | medium |
| Collection | Periodic Screen Capture (.jpg) | T1113 | high |
| Credential Access | Browser Credential Memory Access (0x1fffff) | T1555.003 | critical |
| C2 | Executable Download via Graph API | T1105 | high |
| Exfiltration | Data Exfiltration via OneDrive | T1567.002 | high |
| **Hunting** | **Kill Chain Correlation** (3+ stages/host) | **Multi-technique** | **critical** |

The dashboard currently exposes 22 widgets: 5 BLUELIGHT summary/correlation widgets, 11 BLUELIGHT/SPL-derived detections, 5 YARA-backed confirmations, and 1 kill-chain hunting correlation.

Each rule includes `splunk_original` (SPL), `threat_intel` metadata, and validated OCL.

### Browser Attack Detection (`SOC Application Logs`)

These searches run on `SOC Application Logs`, not on native OCI APM objects. The log source accepts OpenTelemetry-shaped JSON emitted by browser instrumentation, app services, exporters, or checked-in demo data.

The browser dashboard now leads with 4 showcase widgets for total attack volume, OWASP attack mix by service, APM-to-WAF trace correlation, and link analysis across APM/WAF tiers.

| Rule | MITRE | OWASP |
| :--- | :--- | :--- |
| XSS Attack Detection | T1189, T1059.007 | A03, A07 |
| SQL Injection Detection | T1190 | A03 |
| CSRF Token Violation | T1185 | A01 |
| Session Hijacking | T1539, T1550.004 | A07 |
| Clickjacking Detection | T1185 | A05 |
| DOM-Based Attacks | T1059.007 | A03, A07 |
| Suspicious JavaScript Patterns | T1059.007, T1496 | - |
| Browser Fingerprinting | T1592.004 | A07 |

## Project Structure

```
rules/                          # Source detection rules (Sigma YAML)
  cloud/oci/                    # 100 OCI rules (STIG + security + discovery)
  linux/                        # 67 Linux rules (advanced attacks + hunting)
  windows/                      # 249 Windows rules (13 subdirectories)
    apt/                        # 16 BLUELIGHT/APT37 + YARA-backed detections
    process_creation/           # 56 process creation rules
    defense_evasion/            # 29 defense evasion rules
    credential_access/          # 25 credential access rules
    ...
  web/                          # 38 Web rules
    browser_attacks/            # 8 browser-side source rules compiled into queries/apps/
queries/                        # Generated OCL queries (JSON)
  apps/                         # 24 app telemetry queries (8 source-derived + 16 curated)
  hunting/                      # 45 advanced hunting queries
  catalog.json                  # Full rule catalog (machine-readable)
  dashboard_inventory.json      # Dashboard/widget/saved-search inventory for UI integrations
  manifest.json                 # Export/integration manifest
config/
  sigma_oci_mapping.yaml        # Field & log source mappings (including SOC Application Logs)
scripts/
  oci_config.py                 # Centralized config, client factories, validation
  convert_sigma.py              # Sigma -> OCL converter (with STIG metadata)
  deploy_dashboard.py           # OCI LA dashboard deployment (16 dashboards / 264 saved searches)
  generate_test_logs.py         # Core security simulation datasets for OCI LA
  generate_geo_health_logs.py   # Multicloud health dataset used by Geographic Health dashboard
  ingest_test_data.py           # Upload checked-in NDJSON test data to OCI LA
  setup_log_sources.py          # Create JSON parsers & custom OCI LA log sources
  generate_catalog.py           # Generate CATALOG.md and catalog.json
  setup_streaming_pipeline.py   # Production OCI Streaming pipeline (5 configured SOC streams in the current environment)
  export_for_multicloud.py      # Integration with multicloudoperations
test_data/                      # 14 NDJSON demo datasets (146,632 events checked in)
stack/                          # OCI Resource Manager (Terraform) stack
docs/                           # Additional documentation
```

## Deployment

### Target Environment
This project deploys to the **OCI-DEMO Landing Zone** MAIN compartments:
- **Dashboard/Search compartment:** `demo-observability`
- **Log group:** `oci-demo-log-group`
- **OCI Profile:** `cap` (configured in `.env.local`)

### Quick Deploy
```bash
# 1. Set up log sources and JSON parsers
python3 scripts/setup_log_sources.py

# 2. Generate and ingest test data
python3 scripts/generate_test_logs.py
python3 scripts/generate_geo_health_logs.py
python3 scripts/ingest_test_data.py

# 3. Optional: reconcile the Streaming -> SCH -> Log Analytics pipeline
python3 scripts/setup_streaming_pipeline.py
python3 scripts/validate_pipeline.py --e2e

# 4. Deploy 16 dashboards with 264 saved searches
#    The default path validates dashboard queries in OCI Log Analytics first.
#    Failed, slow, or timed-out query validation blocks dashboard import.
python3 scripts/deploy_dashboard.py

# 5. Regenerate inventory artifacts
python3 scripts/generate_catalog.py
python3 scripts/deploy_dashboard.py --export-inventory
python3 scripts/export_for_multicloud.py --manifest-only
```

### Pre-flight Validation
```bash
python3 scripts/deploy_dashboard.py --validate
python3 scripts/deploy_dashboard.py --dry-run
python3 scripts/deploy_dashboard.py --export-inventory
python3 scripts/ingest_test_data.py --validate
python3 scripts/setup_log_sources.py --validate
python3 scripts/validate_pipeline.py --e2e
```

Current environment note: `setup_streaming_pipeline.py` now reconciles 5 configured SOC streams, including `soc-detection-multicloud-health`, and `validate_pipeline.py` validates all configured SOC connectors from `config/streaming_config.json`.

### Converting Rules
```bash
python3 scripts/convert_sigma.py              # Convert all source YAML rules into generated OCI queries
python3 scripts/convert_sigma.py --validate   # Validate OCL syntax
python3 scripts/convert_sigma.py --stats      # Print rule statistics
python3 scripts/generate_catalog.py           # Regenerate canonical machine-readable inventory
python3 scripts/audit_rule_quality.py         # Audit source and generated content quality
```

## Adding New Rules

### Detection Rules
1. Create a YAML file in `rules/{platform}/{tactic}/`.
2. Follow Sigma specification. Add `version` and use `stig.*` tags for STIG rules.
3. If the rule targets browser-side telemetry, place it under `rules/web/browser_attacks/` so it publishes into `queries/apps/`.
4. Run `python3 scripts/convert_sigma.py`, `python3 scripts/generate_catalog.py`, and `python3 scripts/audit_rule_quality.py`.
5. Add or update sample events in `test_data/` or the generator scripts.
6. Add dashboard widgets to `deploy_dashboard.py` (max 30 per dashboard).

### Curated App Telemetry Queries
1. Create a JSON file in `queries/apps/`.
2. Reserve `sigma_id` for source-derived detections only.
3. Keep metadata aligned with the generated catalog fields.
4. Add the query reference to the appropriate dashboard in `deploy_dashboard.py`.

### Hunting Queries
1. Create a JSON file in `queries/hunting/` with hunting query schema.
2. Use OCL pipe operators (`| stats`, `| eval`, `| sort`, `| where`).
3. Add the query reference to the appropriate dashboard in `deploy_dashboard.py`.

### APT/Threat Intel Rules
1. Create YAML in `rules/windows/apt/` with `threat_intel` metadata.
2. Include `splunk_original` in the JSON query for SPL cross-reference.
3. Map the full kill chain with MITRE techniques.

## Integration

### OCI-DEMO
This project is component C17 of the OCI-DEMO platform. Dashboards deploy to the
MAIN `demo-observability` compartment alongside 53 other multicloud dashboards.

### MultiCloud Operations
```bash
python3 scripts/export_for_multicloud.py    # Export to ~/dev/multicloudoperations
```

### Logan Security Dashboard
`../LoganSecurityDashboardv0` is the companion operator UI. This repository remains the content and deployment source of truth; the dashboard should consume `queries/catalog.json`, `queries/dashboard_inventory.json`, `queries/manifest.json`, `queries/apps/*.json`, `queries/hunting/*.json`, and `test_data/manifest.json` through a static export, API, or MCP boundary.

Cross-project capability gaps are tracked in `docs/DASHBOARD_INTEGRATION_GAPS.md` and the dashboard-side report at `../LoganSecurityDashboardv0/docs/CAPABILITY_CORRELATION.md`. Use `DET-MISS-*` for detections-owned export/schema/API gaps and `DASH-MISS-*` for dashboard-owned UI/data-layer gaps.

## License
See [LICENSE](LICENSE) for details.
