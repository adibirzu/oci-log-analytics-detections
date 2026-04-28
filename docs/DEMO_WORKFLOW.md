# OCI Log Analytics Advanced Detection — Demo Workflow

Date: 2026-04-28
Audience: Demo operators, SOC analysts, security architects, platform engineers

## Overview

This document provides a step-by-step demo workflow showcasing OCI Log Analytics advanced detection capabilities deployed as part of the OCI-DEMO platform. The demo covers five scenarios across 35-45 minutes, progressing from foundational SOC operations to advanced APT threat hunting and browser/application telemetry detection.

## Current Operator Shortcut

Before the demo, refresh the tenancy with the current one-command path:

```bash
python3 scripts/populate_dashboard_data_14d.py --validate
python3 scripts/query_audit.py --lookback 14d --eligible-only --out /tmp/eligible_query_audit_14d.json
```

Validated on `2026-04-23`:

- trailing `14d` dataset populated
- `164,766` synthetic events generated across `14` files
- `16` dashboards and `255` saved searches deployed
- live readiness checks green
- eligible query audit green: `51/51` with rows

Use this path instead of running the individual generator, ingest, and deploy scripts one by one unless you are debugging a specific stage.

## Prerequisites

| Requirement | Current State |
|-------------|---------------|
| OCI Console access | `https://console.eu-frankfurt-1.oraclecloud.com` |
| Demo Controls | `https://cp.octodemo.cloud` |
| Control Plane | `https://cp.octodemo.cloud` |
| Log Analytics | demo-observability compartment → Dashboards |
| Test data ingested | 164,766 events across 14 NDJSON datasets |
| Dashboards deployed | 16 SOC dashboards + 255 saved searches |

---

## Demo Scenario 1: SOC Security Overview (5 min)

**Objective:** Show executive-level cross-domain security posture in one view.

### Steps

1. **Open OCI Console** → Observability & Management → Log Analytics → Dashboards
2. **Select compartment:** `demo-observability`
3. **Open:** `SOC Overview Dashboard`

**Talking Points:**
- "This is a unified SOC overview pulling security events from OCI Audit, Windows Sysmon, Linux, Cloud Guard, and WAF — all in one dashboard."
- "Each widget represents a detection rule converted from industry-standard Sigma format into OCI Log Analytics Query Language."
- "The repo currently ships 454 source rules, 454 Sigma-derived OCI searches, and 211 MITRE ATT&CK techniques across 14 tactics."

4. **Click into** `SOC: Console Login Failures` — show the OCL query behind it
5. **Show** the hunting widget: `Hunt: SSH Brute Force` — highlight the frequency analysis pattern:
   ```
   | stats count as failed_attempts by 'Client Host'
   | where failed_attempts > 5
   | sort -failed_attempts
   ```

**Key Message:** "Every detection rule has full MITRE ATT&CK mapping, STIG compliance tagging, and validated OCL, and the generated catalog keeps the published inventory in sync with the code."

---

## Demo Scenario 2: Windows Endpoint Threat Detection (10 min)

**Objective:** Demonstrate real-time Windows Sysmon detection with MITRE ATT&CK correlation.

### Steps

1. **Open:** `SOC: Windows Security Dashboard`
   - Set time range to **Last 7 days**
   - Point out the widgets are now populated with detection data

2. **Walk through detections:**

   | Widget | What it detects | MITRE |
   |--------|----------------|-------|
   | Win: Encoded PowerShell | Base64-encoded commands hiding malicious payloads | T1059.001 |
   | Win: Credential Dump (LSASS) | procdump/comsvcs targeting LSASS memory | T1003.001 |
   | Win: Certutil Download | LOLBin abuse for payload download/decode | T1105 |
   | Win: Shadow Copy Deletion | Ransomware pre-encryption behavior | T1490 |

3. **Click into** `Win: Encoded PowerShell` → Show the matched events:
   ```
   Process Name: powershell.exe
   Command Line: powershell.exe -NoProfile -NonInteractive -EncodedCommand SQBFAFgA...
   Parent Process Name: cmd.exe
   ```

4. **Navigate to** `SOC: Windows Advanced Threats Dashboard`
   - Show Kerberoasting, Pass-the-Hash, Process Hollowing detections
   - "These cover advanced adversary techniques used in real breaches."

5. **Show** `SOC: Sysmon Network and Lateral Movement Dashboard`
   - C2 beacon detection (periodic outbound HTTPS)
   - SMB/WinRM lateral movement
   - DNS tunneling indicators
   - Named pipe activity (CobaltStrike, PsExec, Mimikatz)

**Key Message:** "Full MITRE ATT&CK coverage from initial access through lateral movement and exfiltration — 249 Windows source rules covering LOLBins, credential theft, persistence, defense evasion, and more."

---

## Demo Scenario 3: APT Threat Hunting — BLUELIGHT RAT (15 min)

**Objective:** Demonstrate APT-specific detection with kill chain correlation and cross-reference to Splunk/KQL queries.

### Background (30 seconds)

> "BLUELIGHT is a Remote Access Trojan attributed to APT37 (InkySquid), a North Korean threat actor. It exploits browser vulnerabilities (CVE-2020-1380, CVE-2021-26411) for initial access and uses Microsoft Graph API and OneDrive for command-and-control and data exfiltration. We've replicated the threat hunting report from markBH1510's research and converted every Splunk detection query into OCI Log Analytics."

### Steps

1. **Open:** `SOC: APT Detection Dashboard`
   - This is a dedicated BLUELIGHT kill chain dashboard with 17 widgets

2. **Walk the kill chain** (top to bottom):

   | Stage | Dashboard Widget | What to Show |
   |-------|-----------------|--------------|
   | **Initial Access** | APT37: Drive-by Compromise | IE connecting to non-Microsoft domains |
   | **Execution** | APT37: Browser Child Process | iexplore.exe spawning cmd.exe/powershell.exe |
   | **Defense Evasion** | APT37: Obfuscated Commandline | XOR key 0xCF, Base64, encoded commands |
   | **C2** | APT37: Graph API C2 | Non-standard processes connecting to graph.microsoft.com |
   | **Discovery** | APT37: WMI System Discovery | Win32_ComputerSystem enumeration from browser |
   | **Discovery** | APT37: Registry Enumeration | SecurityCenter2, AV product key queries |
   | **Collection** | APT37: Screen Capture | Rapid .jpg creation (>3/minute) |
   | **Credential Access** | APT37: Browser Credential Theft | PROCESS_ALL_ACCESS to browser memory |
   | **C2** | APT37: Ingress Tool Transfer | Executables dropped in Temp/AppData |
   | **Exfiltration** | APT37: OneDrive Exfiltration | Large uploads to graph.microsoft.com |

3. **Show the hunting correlation** — `Hunt: BLUELIGHT Kill Chain`:
   ```
   | stats count as TotalEvents, distinctcount('Event ID') as StageCount
     by 'Host Name (Server)'
   | where StageCount >= 3
   | sort -TotalEvents
   ```
   - "This query correlates multiple kill chain stages on the same host. If a host shows 3 or more BLUELIGHT stages within the time window, it's flagged as a potential compromise."

4. **Click into any rule** → Show the JSON query file:
   - `splunk_original` — the original Splunk SPL query
   - `query` — the converted and validated OCL query
   - `threat_intel` — malware family, MITRE software ID, threat actor, CVEs
   - `mitre_attack` — tactic and technique mapping

5. **Show the Sigma YAML** source rule (optional):
   - Navigate to `rules/windows/apt/bluelight_graph_api_c2.yaml`
   - "Every detection starts as a portable Sigma rule. Our converter handles field mapping, log source resolution, and OCL syntax generation automatically."

**Key Message:** "We took a real APT threat hunting report, converted the BLUELIGHT detection set into OCI Log Analytics, added YARA-backed confirmation logic and kill chain correlation, and deployed it as a production-ready dashboard — complete with Sigma YAML, SPL cross-reference, and threat intelligence metadata."

---

## Demo Scenario 4: Browser Attack Detection via `SOC Application Logs` (10 min)

**Objective:** Show client-side attack detection using the `SOC Application Logs` telemetry surface — a capability that WAF alone cannot provide.

### Steps

1. **Open:** `SOC: Browser Attack Detection Dashboard`

2. **Explain the architecture:**
   > "Traditional SIEMs only see server-side logs. In this demo, browser and application telemetry is normalized into `SOC Application Logs`, a custom OCI Log Analytics source with OpenTelemetry-shaped fields. That lets us detect client-side attacks that WAF can't see — DOM-based XSS, session hijacking, crypto mining scripts, and browser fingerprinting."

3. **Walk through detections:**

   | Widget | Attack Type | What it Detects |
   |--------|-------------|-----------------|
   | Browser: XSS Attack | Cross-Site Scripting | `<script>`, `javascript:`, event handlers in URLs |
   | Browser: SQL Injection | SQL Injection | UNION SELECT, OR 1=1, SLEEP(), INFORMATION_SCHEMA |
   | Browser: Session Hijacking | Session Hijacking | >5 distinct session IDs per source IP in 5 min |
   | Browser: DOM-Based Attacks | DOM XSS | document.cookie, eval(), innerHTML manipulation |
   | Browser: Suspicious JS | Cryptomining/Keylogger | coinhive, cryptonight, keydown event listeners |
   | Browser: Fingerprinting | Reconnaissance | Canvas, WebGL, AudioContext API abuse |

4. **Show the hunting query** — `Hunt: Browser Attack Frequency`:
   - Multi-vector attacker identification
   - "This finds source IPs that are attempting multiple attack types — XSS AND SQLi from the same IP indicates a coordinated attack, not a scanner."

5. **Connect to App 360** — Open `OCI-DEMO: Application 360 Monitoring Dashboard`:
   - Show how application trace telemetry correlates with security events
   - "The same trace ID that shows a slow request in the app telemetry view also shows a WAF block in the security dashboard."

**Key Message:** "Browser-side detection is a significant blind spot for most organizations. By normalizing browser and application telemetry into `SOC Application Logs`, we extend detection from the server all the way to the browser — covering OWASP Top 10 attack patterns that WAF alone cannot see."

---

## Demo Scenario 5: STIG Compliance & Hunting (5 min)

**Objective:** Show compliance monitoring and advanced threat hunting analytics.

### Steps

1. **Open:** `SOC: OCI STIG Compliance Dashboard`
   - "24 detection rules mapped to DoD STIG controls: IA-2 (MFA), SC-7 (network security), AU-11 (audit retention), AC-17 (remote access)."
   - Show `STIG: MFA Disabled`, `STIG: Vault Secret Deleted`, `STIG: Security List All Protocols`

2. **Open:** `SOC: Threat Hunting Dashboard`
   - Walk through hunting methodologies:

   | Method | Query | What It Finds |
   |--------|-------|---------------|
   | Frequency Analysis | SSH Brute Force | IPs with >5 failed SSH logins |
   | Rare Value Stacking | Windows Rare Process | Processes seen <3 times (anomalies) |
   | Anomaly Scoring | Defense Evasion Score | Hosts with multiple evasion techniques |
   | Time-Based | After-Hours IAM Activity | IAM changes outside business hours |
   | Multi-Stage Correlation | Linux Multi-Stage Attack | Hosts with 3+ attack indicators |

**Key Message:** "Compliance isn't just a checkbox — these rules run continuously against live telemetry. And the hunting dashboard uses analytics-driven queries inspired by the Threat Hunter's Cookbook to surface threats that signature-based detection misses."

---

## Quick Reference: Demo Commands

### Trigger Attack Simulation (via Control Plane API)
```bash
# Canonical 14-day refresh flow
python3 scripts/populate_dashboard_data_14d.py --validate

# Or run individual steps when debugging
python3 scripts/generate_dashboard_data.py --days 14 --validate
python3 scripts/ingest_test_data.py
python3 scripts/deploy_dashboard.py --cleanup
python3 scripts/demo_readiness.py --lookback 14d

# Or trigger via the canonical public Control Plane
curl -X POST https://cp.octodemo.cloud/api/demo-events/trigger \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"preset": "security_incident"}'
```

### Verify Dashboard Data
```bash
python3 scripts/demo_readiness.py --lookback 14d
python3 scripts/query_audit.py --lookback 14d --eligible-only --out /tmp/eligible_query_audit_14d.json
```

### Refresh Dashboards
```bash
python3 scripts/deploy_dashboard.py     # Redeploy all 16 dashboards
python3 scripts/generate_catalog.py     # Regenerate catalog
```

---

## Architecture Summary

```
┌──────────────────────────────────────────────────────────────────────┐
│                        OCI-DEMO Platform                             │
├──────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌────────────┐ │
│  │ GOAD AD Lab │  │ Caldera     │  │ OpenAEV     │  │ Kali       │ │
│  │ (8 Windows  │  │ (MITRE      │  │ (Attack     │  │ (HexStrike │ │
│  │  VMs)       │  │  ATT&CK)    │  │  Validation)│  │  Pentesting│ │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘  └─────┬──────┘ │
│         │                │                │                │        │
│         └────────────────┴────────────────┴────────────────┘        │
│                              │                                       │
│                    ┌─────────▼──────────┐                           │
│                    │  OCI Streaming +   │                           │
│                    │  Service Connector │                           │
│                    │  Hub               │                           │
│                    └─────────┬──────────┘                           │
│                              │                                       │
│              ┌───────────────┼───────────────┐                      │
│              │               │               │                      │
│    ┌─────────▼────┐ ┌───────▼───────┐ ┌─────▼──────┐              │
│    │ OCI Log      │ │ Splunk        │ │ ServiceNow │              │
│    │ Analytics    │ │ (External)    │ │ (Incidents)│              │
│    │ ┌──────────┐ │ └───────────────┘ └────────────┘              │
│    │ │16 SOC    │ │                                                │
│    │ │Dashboards│ │                                                │
│    │ │255 Saved │ │                                                │
│    │ │Searches  │ │                                                │
│    │ │506 Assets│ │                                                │
│    │ │211 MITRE │ │                                                │
│    │ └──────────┘ │                                                │
│    └──────────────┘                                                │
│                                                                      │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐                │
│  │ CRM Portal  │  │ Drone Shop  │  │ Seven       │                │
│  │ (crm.octo   │  │ (shop.octo  │  │ Kingdoms    │                │
│  │  demo.cloud)│  │  demo.cloud)│  │ Portal      │                │
│  └──────┬──────┘  └──────┬──────┘  └─────────────┘                │
│         │                │                                          │
│         └────────┬───────┘                                          │
│                  │                                                   │
│        ┌─────────▼──────────┐                                       │
│        │ SOC Application    │                                       │
│        │ Logs + OTel-shaped │──▶ Browser Attack Detection           │
│        │ telemetry JSON     │    (XSS, SQLi, CSRF, Fingerprinting) │
│        └────────────────────┘                                       │
│                                                                      │
│  ┌─────────────────────────────────────────────────┐                │
│  │ Control Plane (cp.octodemo.cloud)               │                │
│  │ ┌───────────┐ ┌──────────┐ ┌─────────────────┐ │                │
│  │ │ One-Click │ │ Stress   │ │ Event Presets   │ │                │
│  │ │ Controls  │ │ Tests    │ │ (P1/P2/P3/P4)   │ │                │
│  │ └───────────┘ └──────────┘ └─────────────────┘ │                │
│  └─────────────────────────────────────────────────┘                │
│                                                                      │
└──────────────────────────────────────────────────────────────────────┘
```

---

## Detection Coverage Matrix

| Content Surface | Count | Dashboards | What to Emphasize |
|----------------|-------|------------|-------------------|
| Source Sigma/YAML rules | 454 | 14 | Windows, OCI, Linux, web, BLUELIGHT, and browser-side detections |
| Sigma-derived OCI searches | 454 | 14 | 446 top-level detections + 8 browser/app telemetry detections |
| Curated app telemetry analytics | 12 | 2 | App 360 correlation, WAF-to-trace pivots, service health |
| Hunting analytics | 40 | 4 | Frequency, anomaly, scoring, multi-stage, kill-chain correlation |
| STIG-mapped detections | 24 | 1 | Continuous control monitoring for IAM, network, audit, and key management |
| Sample datasets | 14 files / 146,632 events | Demo enablement | Includes app telemetry and the 14-day multicloud geo-health data for the geographic dashboard |
| **Total shipped query artifacts** | **506** | **16** | **211 MITRE techniques across 14 tactics** |

---

## Demo Tips

1. **Set time range to "Last 7 days"** on all dashboards to see test data
2. **Use the Ops Portal** for one-click event generation — no SSH needed
3. **Start with Scenario 1** for executive audiences, skip to Scenario 3 for security teams
4. **The BLUELIGHT scenario** is the strongest differentiator — show the SPL→OCL conversion
5. **Browser attack detection** is powered by the custom `SOC Application Logs` telemetry surface, so explain the parser/source model rather than implying native OCI APM coverage
6. **If a dashboard is empty**, run `python3 scripts/ingest_test_data.py` to refresh test data
7. **Each query JSON includes** `splunk_original` for Splunk comparison during demos
