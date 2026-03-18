# OCI Log Analytics Detection Rules

A comprehensive STIG-compliant detection rules library for Oracle Cloud Infrastructure (OCI) Log Analytics. Converts industry-standard [Sigma](https://github.com/SigmaHQ/sigma) rules into OCI Log Analytics Query Language (OCL) with MITRE ATT&CK and STIG compliance mapping. Enhanced with advanced threat hunting queries, APT-specific detection (BLUELIGHT/APT37), and browser attack detection via OCI APM/OpenTelemetry.

## Current Status
- **Total Rules:** 428 Sigma detection rules + 36 advanced hunting queries
- **Categories:** Windows Security (229), Cloud/OCI (100), Linux Security (67), Web/WAF (30), APT Detection (11), Browser Attacks (8)
- **Hunting Queries:** 36 analytics-based queries (frequency analysis, anomaly detection, scoring, kill chain correlation, browser attack frequency)
- **STIG Coverage:** 24 rules with DoD STIG control mappings (IA-2, IA-5, SC-7, SC-28, AU-11, AC-17, etc.)
- **MITRE ATT&CK:** 203 techniques across 14 tactics
- **Deployed:** 249 saved searches across 16 dashboards
- **Test Data:** 1,315 attack simulation events across 12 NDJSON files
- **Target Environment:** OCI-DEMO Landing Zone (`demo-observability` compartment)

## Architecture

```
                    +-----------------------+
                    |   Sigma YAML Rules    |
                    |   rules/{platform}/   |
                    +-----------+-----------+
                                |
                    +-----------v-----------+
                    |  convert_sigma.py     |
                    |  (Sigma -> OCL)       |
                    +-----------+-----------+
                                |
              +-----------------+------------------+
              |                                    |
   +----------v----------+            +-----------v-----------+
   |  OCL Query JSONs    |            |  Hunting Query JSONs  |
   |  queries/*.json     |            |  queries/hunting/*.json|
   |  queries/apps/*.json|            +----------+------------+
   +----------+----------+                       |
              |                                  |
              +----------------+-----------------+
                               |
                    +----------v----------+
                    |  deploy_dashboard.py |
                    |  (16 dashboards)     |
                    +----------+----------+
                               |
                    +----------v----------+
                    |  OCI Log Analytics   |
                    |  demo-observability  |
                    |  (MAIN compartment)  |
                    +---------------------+
```

### Data Flow

```
  Sysmon/Windows Events ─────┐
  Linux Syslog/Secure ───────┤
  OCI Audit Events ──────────┤──> OCI Streaming ──> Service Connector Hub ──> Log Analytics
  Cloud Guard Problems ──────┤                                                    |
  WAF/LB Access Logs ────────┤                                                    v
  APM/OpenTelemetry Spans ───┘                                          SOC Dashboards (16)
                                                                        Saved Searches (249)
  Test Data (NDJSON) ──> Upload API ──> Log Analytics ──> Dashboard Verification
```

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
| SOC: Windows Advanced Threats | 17 | Kerberoasting, pass-the-hash, process hollowing, RATs |
| SOC: Threat Hunting | 16 | Cookbook-inspired: frequency, anomaly, scoring, multi-stage |
| SOC: Sysmon Network & Lateral | 17 | C2 beacons, SMB/WinRM/RDP lateral, DNS tunneling, pipes |
| SOC: Web Application Security | 30 | OWASP Top 10: SQLi, XSS, SSRF, path traversal, CORS, IDOR |
| SOC: Web Threat Hunting | 8 | WAF frequency, SQLi stacking, multi-attack scoring, geo anomaly |
| SOC: APT Detection | 12 | BLUELIGHT RAT (S0657/APT37) full kill chain detection |
| SOC: Browser Attack Detection | 9 | APM/OpenTelemetry: XSS, SQLi, CSRF, session hijack, fingerprinting |
| SOC: Geographic Health | 5 | Multicloud health visualization (OCI, Azure, GCP) |
| OCI-DEMO: App 360 Monitoring | 12 | CRM + Drone Shop: APM traces, WAF correlation, DB perf |

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

Each rule includes `splunk_original` (SPL), `threat_intel` metadata, and validated OCL.

### Browser Attack Detection (APM/OpenTelemetry)
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
  windows/                      # 229 Windows rules (13 subdirectories)
    apt/                        # 11 APT-specific rules (BLUELIGHT/APT37)
    process_creation/           # 56 process creation rules
    defense_evasion/            # 29 defense evasion rules
    credential_access/          # 25 credential access rules
    ...
  web/                          # 38 Web rules
    browser_attacks/            # 8 APM/OpenTelemetry browser attack rules
queries/                        # Generated OCL queries (JSON)
  apps/                         # 20 APM application queries
  hunting/                      # 36 advanced hunting queries
  catalog.json                  # Full rule catalog (machine-readable)
config/
  sigma_oci_mapping.yaml        # Field & log source mappings (incl. APM/OTel)
scripts/
  oci_config.py                 # Centralized config, client factories, validation
  convert_sigma.py              # Sigma -> OCL converter (with STIG metadata)
  deploy_dashboard.py           # OCI LA dashboard deployment (16 dashboards)
  generate_test_logs.py         # Attack simulation data (1,315 events, OCI LA field names)
  ingest_test_data.py           # Upload test data to OCI LA (12 log sources)
  setup_log_sources.py          # Create JSON parsers & custom OCI LA log sources
  generate_catalog.py           # Generate CATALOG.md and catalog.json
  setup_streaming_pipeline.py   # Production OCI Streaming pipeline
  export_for_multicloud.py      # Integration with multicloudoperations
test_data/                      # Generated NDJSON test logs (12 files)
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
python3 scripts/ingest_test_data.py

# 3. Deploy 16 dashboards with 249 saved searches
python3 scripts/deploy_dashboard.py

# 4. Regenerate catalog
python3 scripts/generate_catalog.py
```

### Pre-flight Validation
```bash
python3 scripts/deploy_dashboard.py --validate
python3 scripts/deploy_dashboard.py --dry-run
python3 scripts/ingest_test_data.py --validate
python3 scripts/setup_log_sources.py --validate
```

### Converting Rules
```bash
python3 scripts/convert_sigma.py              # Convert all 428 rules
python3 scripts/convert_sigma.py --validate   # Validate OCL syntax
python3 scripts/convert_sigma.py --stats      # Print rule statistics
```

## Adding New Rules

### Detection Rules
1. Create a YAML file in `rules/{platform}/{tactic}/`.
2. Follow Sigma specification. Add `stig.*` tags for STIG rules.
3. Run `python3 scripts/convert_sigma.py --validate --stats`.
4. Add test events to `generate_test_logs.py`.
5. Add dashboard widgets to `deploy_dashboard.py` (max 30 per dashboard).

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

## License
See [LICENSE](LICENSE) for details.
