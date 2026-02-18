# Project Status Report

**Date:** February 12, 2026
**Topic:** OCI Log Analytics Detection Rules - Enhanced Deployment

## Achievements

### Infrastructure & Tooling
- **Project Structure:** Organized rules, queries, scripts, config, and test_data directories.
- **Sigma Converter:** `scripts/convert_sigma.py` supports complex Sigma conditions (NOT, nested OR/AND) and field modifiers (startswith, endswith, contains, regex).
- **Field Mappings:** `config/sigma_oci_mapping.yaml` covers OCI Audit, Cloud Guard, Linux Audit/Auth, and Windows Sysmon log sources.
- **Dashboard Deployment:** `scripts/deploy_dashboard.py` deploys 5 SOC dashboards with 58 saved searches.
- **Test Data Pipeline:** `scripts/generate_test_logs.py` + `scripts/ingest_test_data.py` for attack simulation and log ingestion.
- **Streaming Pipeline:** `scripts/setup_streaming_pipeline.py` for production OCI Streaming → SCH → Log Analytics pipeline.

### Content: 200 Detection Rules + 20 Hunting Queries
| Category | Count | Log Source | Description |
| :--- | :--- | :--- | :--- |
| **OCI Audit** | 80 | `OCI Audit Logs` | IAM, Network, Compute, Storage, WAF, KMS, DB, Bastion, Vault, STIG, Discovery |
| **OCI Cloud Guard** | 12 | `OCI Cloud Guard Logs` | High-severity security posture problems |
| **Linux Security** | 65 | `SOC Linux Syslog Logs` / `Linux Secure Logs` | GTFOBins, SSH, persistence, webshells, cryptominers, scanning, exfil, C2 |
| **Windows Security** | 55 | `SOC Windows Sysmon Logs` / `Windows Event Security Logs` | LOLBins, Mimikatz, Kerberoasting, discovery, phishing, keyloggers, RATs |
| **Hunting Queries** | 20 | Cross-platform | Analytics-based: frequency, anomaly, scoring, beaconing, entropy, time-series |

### New Rules Added (Feb 10, 2026)
| # | Rule | Severity | Detection Pattern |
| :--- | :--- | :--- | :--- |
| 1 | OCI Autonomous Database Terminated | high | Single event_type match |
| 2 | OCI KMS Key Scheduled for Deletion | critical | Single event_type match |
| 3 | OCI IAM Admin Policy - Manage All | high | event_type AND response_payload contains |
| 4 | OCI Console Login Failure | medium | event_type AND status match |
| 5 | OCI Network Load Balancer Deleted | high | Multi-value event_type OR list |
| 6 | Linux Reverse Shell Detected | critical | message contains 5-item OR list |
| 7 | Linux Crontab Modification | medium | Single process_name match |
| 8 | Linux SSH Authorized Keys Modified | high | message contains single value |
| 9 | Linux History File Cleared | medium | sel1 or sel2 multi-selection condition |
| 10 | Windows Certutil Download or Decode | high | process_name AND CommandLine contains list |
| 11 | Windows Encoded PowerShell Execution | high | process_name AND CommandLine contains list |
| 12 | Windows Service Creation via SC | medium | process_name AND CommandLine contains |
| 13 | Windows Credential Dumping via Procdump | critical | sel1 or sel2 multi-selection condition |

### OCI Log Analytics Deployment (Updated Feb 10, 2026)

#### Saved Searches Deployed: 58
| Category | Searches | Highlights |
| :--- | :--- | :--- |
| SOC Overview | 6 | Cross-domain critical alerts (login, KMS, reverse shell, LSASS) |
| OCI Audit | 14 | Console logins, IAM changes, KMS, DB, LB, WAF, NSG, routes |
| Cloud Guard | 12 | Public IPs, bucket exposure, port exposure, stale creds, policy issues |
| Linux | 12 | SSH, sudo, reverse shell, crontab, authorized_keys, history, GTFOBins |
| Windows | 12 | LSASS dump, encoded PS, certutil, sc create, LOLBins |

#### Dashboards Deployed: 5
| Dashboard | Widgets | Purpose |
| :--- | :--- | :--- |
| **SOC Overview Dashboard** | 6 | Executive-level cross-domain security summary |
| **SOC: OCI Audit Security Dashboard** | 14 | IAM, network, compute, storage, KMS, DB deep-dive |
| **SOC: Cloud Guard Security Dashboard** | 12 | Cloud Guard problem monitoring |
| **SOC: Linux Security Dashboard** | 12 | SSH, sudo, GTFOBins, reverse shells, persistence |
| **SOC: Windows Security Dashboard** | 12 | LOLBins, encoded PowerShell, credential dumping |

### Test Data Pipeline
- **Attack Simulation:** 279 events across 4 NDJSON files covering all 113 detection rules.
  - `oci_audit.jsonl` — 107 events (IAM, network, compute, storage, KMS, DB, WAF actions)
  - `cloud_guard.jsonl` — 36 events (12 Cloud Guard problem types × 3 variants)
  - `linux_syslog.jsonl` — 84 events (SSH, sudo, reverse shell, crontab, GTFOBins)
  - `windows_sysmon.jsonl` — 52 events (LOLBins, encoded PowerShell, credential dumping)
- **Direct Upload:** All 4 files uploaded via OCI Log Analytics Upload API to `soc-detection-test-logs` log group.
- **Streaming Support:** Optional OCI Streaming → Service Connector Hub → Log Analytics pipeline for production use.

### Key Fixes Applied
- **Log Source Mapping:** Fixed Cloud Guard, Linux, and Windows rules that previously all mapped to `OCI Audit Logs`.
- **Placeholder UUIDs:** Replaced 10 placeholder IDs with proper UUIDs.
- **Query Regeneration:** All 113 queries regenerated with corrected log source mappings.
- **Old File Cleanup:** Removed 62 legacy query files with colons in filenames.
- **Regex Modifier:** Added `|re` modifier support to Sigma converter for `REGEX MATCH` OCL syntax.
- **Dashboard Widget Fix:** Rewrote saved search creation to use `ui_config.queryString` with `scopeFilters` (matching OCI Log Analytics 3.0 provider format). Saved searches are now embedded directly in dashboard JSON for the `import_dashboard` API.
- **Test Data Format:** Converted all test logs from mixed formats (syslog, XML) to uniform NDJSON (.jsonl) for reliable OCI LA parser ingestion.
- **Custom Log Sources:** Created `setup_log_sources.py` that deploys 12 custom fields, 3 JSON parsers, and 3 log sources (`SOC Linux Syslog Logs`, `SOC Windows Sysmon Logs`, `SOC Cloud Guard Logs`) with proper field mappings for detection queries.
- **OCL Syntax Fix:** Changed converter from `| where field like '*x*'` (invalid) to search expression syntax `and field like '*x*'` (valid OCL). The `like` operator only works in the search expression, not in `WHERE` clauses.
- **Windows LOLBin Rules:** Changed 23 process detection rules from exact match to `endswith` modifier for path-aware matching (e.g., `'Process Name' like '*powershell.exe'`).
- **Query Verification:** All queries validated — 0 errors remaining.

### Enhancement Update (Feb 11, 2026)
- **STIG Compliance Rules:** Added 15 new OCI rules with DoD STIG control mappings (IA-2, IA-5, IA-8, AC-3, AC-6, AU-11, AU-12, SC-7, SC-12, SC-28, CP-9).
- **Advanced Linux Attack Rules:** Added 6 new rules (container escape T1611, LD_PRELOAD T1574.006, kernel module from /tmp T1547.006, passwd modification T1136.001, ptrace injection T1055.008, network redirect T1557).
- **Advanced Windows Attack Rules:** Added 6 new rules (shadow copy deletion T1490, AMSI bypass T1562.001, WMI persistence T1546.003, registry run key T1547.001, DLL side-loading T1574.002, bcdedit recovery disable T1490).
- **Enhanced Converter:** Fixed startswith/endswith list handling. Added STIG metadata extraction. Improved condition tokenizer for complex multi-selection rules. Added `--validate` and `--stats` modes.
- **Enhanced JSON Schema:** Query output now includes `level`, `stig_category`, `mitre_attack`, `logsource`, `stig_ids`, `compliance_frameworks`, and `falsepositives` fields.
- **New STIG Dashboard:** Added "SOC: OCI STIG Compliance Dashboard" with 14 widgets covering MFA, identity governance, key management, network security, and audit configuration.
- **Test Data Expansion:** 481 events (up from 279) covering all 181 rules.
- **Multicloud Integration:** Created `scripts/export_for_multicloud.py` for exporting rules and manifest to `~/dev/multicloudoperations`.
- **Field Mappings:** Added 12 new OCI LA field mappings (Resource Name, Region, Principal Name, Auth Type, Risk Level, Detector ID, Event ID, Provider, Channel, etc.).
- **Dashboards:** 6 dashboards (up from 5), 120 saved searches (up from 58).
- **Batch 2 Rules (20 new):** 7 OCI (vault secrets, password reset, bastion, console connection, notifications, log groups, secret keys), 7 Linux (systemd persistence, SSH tunneling, /tmp downloads, /dev/shm, sudoers, shell profiles, at-jobs), 6 Windows (Mimikatz, firewall rules, RDP, scheduled tasks, PS download cradles, LSASS access).
- **Batch 3 Rules (20 new):** 10 Linux (DNS tunneling, hosts file, /proc memory, webshells, cryptominers, log tampering, enumeration scripts, bind shells, suspicious cron, hidden files), 10 Windows (event log clearing, PsExec, UAC bypass, Kerberoasting, BITS persistence, MSBuild, pass-the-hash, process hollowing, WDigest, NTDS.dit).
- **MITRE Coverage:** 66 techniques across all 12 ATT&CK tactics (added discovery tactic).

### Threat Hunting Enhancement (Feb 11, 2026)
- **Cookbook Integration:** Applied Threat Hunter's Cookbook (Dr. Ryan Fetterman, Sydney Marrone / Splunk SURGe) methodologies to create 15 advanced hunting queries using OCL analytics operators.
- **Hunting Methods Applied:** Frequency analysis (brute force), rare value stacking (unusual processes), anomaly detection (destruction spikes, rapid IAM), grouping (lateral movement clusters, credential access), combined scoring (persistence score, defense evasion score), time-based anomaly (after-hours activity), field analysis (long command lines, unusual paths).
- **New Dashboard:** "SOC: Threat Hunting Dashboard" with 15 widgets covering all 5 cookbook methodology categories.
- **Enhanced SOC Overview:** Added 2 hunting widgets (SSH Brute Force, OCI Destruction Spike) to executive dashboard.
- **Test Data Expansion:** 563 events (up from 481) with high-volume hunting-specific events: 15 SSH failures from same IP, 8 OCI login failures, 12 rapid IAM changes, 8 resource deletions, multi-stage Linux attack chain on single host, lateral movement tool cluster, credential access cluster, defense evasion cluster.
- **Dashboards:** 7 dashboards (up from 6), 133 saved searches (up from 120).

### MITRE ATT&CK Expansion (Feb 11, 2026)
- **Batch 4 Rules (20 new):** Targeted the weakest MITRE ATT&CK tactics to achieve broad coverage.
  - **Discovery (6 rules):** Cloud infrastructure discovery (T1580), network scanning (T1046), system/user discovery (T1033), account discovery (T1087), share discovery (T1135), remote system discovery (T1018).
  - **Initial Access (3 rules):** Password spraying (T1110.003), external remote service abuse (T1133), spearphishing attachment execution (T1566.001).
  - **Exfiltration (3 rules):** Alt protocol exfiltration (T1048), data archiving (T1560.001), data staging (T1074.001).
  - **Collection (3 rules):** Keylogger indicators (T1056.001), screen capture (T1113), sensitive data collection (T1005).
  - **Command & Control (3 rules):** Remote access tools (T1219), proxy/tunneling (T1090), encrypted channel C2 (T1573).
  - **Privilege Escalation (2 rules):** SUID binary creation (T1548.001), access token manipulation (T1134).
- **MITRE Coverage:** 90 techniques across 12 tactics (up from 66). Key improvements: Discovery 1→7, Initial Access 1→4, Exfiltration 2→5, Collection 2→5, C2 5→8, Privilege Escalation 4→6.
- **Test Data Expansion:** 644 events (up from 563) with discovery scanning, password spraying, phishing execution, data staging, keylogger/screen capture, RAT activity, token manipulation events.
- **Dashboard Updates:** 153 saved searches (up from 133). Added 22 new widgets: 2 OCI Audit (discovery, spraying), 10 Linux (scanning, discovery, remote service, exfil, archive, data access, proxy, C2, SUID), 10 Windows (account/share/remote discovery, phishing, staging, keylogger, screen capture, RAT, token manipulation).

### Quality & Tooling Update (Feb 12, 2026)
- **Response Payload Fix:** Changed 4 rules using `'Response Payload' like` to `'Original Log Content' like` — resolves all OCL eval errors on nested JSON fields.
- **OCI Event Type Alignment:** Fixed 45 event type references across 20 rules and test data. Changed `com.oraclecloud.identity.*` to `com.oraclecloud.identitycontrolplane.*` per OCI Events API specification. Fixed `identity.authentication.login` to `consolesignon.login`. Fixed typo `uploadadikey` → `uploadapikey`.
- **Rule Catalog Generator:** New `scripts/generate_catalog.py` produces `CATALOG.md` (Markdown) and `queries/catalog.json` (machine-readable) with MITRE ATT&CK matrix, severity breakdown, STIG coverage, and full rule tables.
- **CI/CD Pipeline:** Added `.github/workflows/validate-rules.yml` — validates YAML syntax, converts all rules, checks OCL syntax, verifies rule counts, and detects deprecated event types on every push/PR.
- **Advanced Hunting Queries (5 new, 20 total):** DNS exfiltration entropy analysis, login time-series anomaly, C2 beaconing detection, OCI privilege escalation chain, Linux data staging/exfiltration indicators.
- **SigmaHQ Sync Script:** New `scripts/sync_sigmahq.py` clones/updates official SigmaHQ repository, identifies compatible rules (189 Linux, Windows process_creation, cloud), and imports with automatic logsource adaptation.
- **MITRE Coverage:** 100 techniques across 12 tactics (up from 90).

### OCI Resource Manager Stack (Feb 18, 2026)
- **Terraform Stack:** Created `stack/` directory with full ORM-compatible Terraform configuration for one-click deployment.
- **Resources Managed:**
  - 1 Log Analytics log group (`oci_log_analytics_log_analytics_log_group`)
  - 4 OCI Streaming streams via `for_each` (`soc-detection-oci-audit`, `soc-detection-cloud-guard`, `soc-detection-linux-audit`, `soc-detection-windows-sysmon`)
  - 4 Service Connector Hub connectors routing streams to Log Analytics
  - IAM policies for SCH (stream pull/push + LA upload)
  - 3 `null_resource` provisioners calling existing Python scripts (log sources, dashboards, test data)
- **ORM Schema:** `schema.yaml` with variable groups for General, Log Analytics, Streaming, and Provisioning options.
- **Build Script:** `build_stack.sh` packages all Terraform + project assets into `soc-detection-stack.zip` for ORM upload.
- **Validation:** `terraform init` and `terraform validate` pass cleanly (OCI provider v8.2.0, null provider v3.2.4).

## Next Steps
1. **Multicloud Full Sync:** Deploy OCI STIG rules into multicloudoperations as a shared detection module.
2. **SigmaHQ Rule Import:** Review and import highest-value rules from 189 available SigmaHQ Linux rules.
3. **JA3 Fingerprint Clustering:** Add JA3/JA3S TLS fingerprint hunting queries for C2 detection.
4. **Real-Time Alerting:** Configure OCI Events + Notifications for critical-severity detections.
5. **Dashboard v2:** Rebuild dashboards with corrected event types and expanded hunting widgets.
