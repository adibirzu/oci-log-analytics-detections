# Cross-SIEM Detection Catalog

This catalog maps familiar SIEM behavioral families to independently authored OCI Log Analytics (Logan) hunts. It does not reproduce third-party rule bodies or claim a vendor-neutral popularity ranking.

## Product libraries

| Product | Language | Repository/catalog | Logan integration |
| --- | --- | --- | --- |
| Splunk Enterprise Security | SPL | [Official content](https://github.com/splunk/security_content) | converter-backed |
| Microsoft Sentinel | KQL | [Official content](https://github.com/Azure/Azure-Sentinel) | converter-backed-with-live-promotion |
| IBM QRadar SIEM | AQL and CRE rules | [Official content](https://www.ibm.com/docs/en/qsip/7.4.0?topic=qradar-content-extensions) | reference-only |
| LogRhythm SIEM | AI Engine rules and Web Console search | [Official content](https://logrhythm.com/marketplace/) | reference-only |
| OpenText ArcSight | ESM filters and correlation rules | [Official content](https://www.opentext.com/products/arcsight-enterprise-security-manager) | reference-only |
| Elastic Security | KQL, Lucene, EQL, and ES|QL | [Official content](https://github.com/elastic/detection-rules) | converter-backed-user-input-only |

## Detection-family mappings

### Credential and identity abuse

MITRE ATT&CK: T1078, T1098, T1528

- `hunting/oci_console_brute_force.json` — OCI Console Login Brute Force (Frequency Analysis)
- `hunting/oci_multi_user_same_ip.json` — OCI Multiple Users from Same IP (Grouping)
- `hunting/cloud_identity_aitm_token_abuse.json` — Cloud Identity: AiTM Token Abuse
- `hunting/cloud_identity_control_plane_takeover.json` — Cloud Identity to Control-Plane Takeover

### Suspicious process and script execution

MITRE ATT&CK: T1059.001, T1218

- `hunting/clickfix_clipboard_powershell_execution.json` — ClickFix: Clipboard PowerShell Execution
- `hunting/clickfix_lolbin_payload_execution.json` — ClickFix: LOLBin Payload Execution
- `hunting/windows_rare_process.json` — Windows Rare Process Detection (Stacking)

### Remote access and lateral movement

MITRE ATT&CK: T1219, T1021

- `hunting/rmm_post_compromise_activity.json` — RMM: Post-Compromise Remote Access Activity
- `hunting/windows_lateral_movement_cluster.json` — Windows Lateral Movement Tool Cluster (Grouping)
- `hunting/win_lateral_movement_timeline.json` — Windows Lateral Movement Timeline

### Cloud discovery, collection, and exfiltration

MITRE ATT&CK: T1526, T1530, T1567

- `hunting/cloud_control_plane_discovery_burst.json` — Cloud Control-Plane Discovery Burst
- `hunting/cloud_secret_and_object_collection.json` — Cloud Secret and Object Collection
- `hunting/exfiltration_after_initial_access_2025_2026.json` — 2025-2026: Exfiltration After Initial Access

### Destructive activity and defense evasion

MITRE ATT&CK: T1070, T1485, T1489

- `hunting/oci_resource_deletion_wave.json` — OCI Resource Deletion Wave
- `hunting/oci_resource_destruction_spike.json` — OCI Resource Destruction Spike (Anomaly Detection)
- `hunting/windows_defense_evasion_score.json` — Windows Defense Evasion Score (Combined Methods)

### Web exploitation and web shells

MITRE ATT&CK: T1190, T1505.003

- `hunting/sharepoint_toolshell_exploitation.json` — SharePoint ToolShell: Exploitation Attempts
- `hunting/sharepoint_toolshell_webshell_post_exploit.json` — SharePoint ToolShell: Webshell Post-Exploit
- `hunting/web_owasp_multi_stage_attack.json` — OWASP Multi-Stage Web Attack Chain (Combined Methods)

## How to use this catalog

1. Choose the behavior, not a vendor rule name.
2. Open the mapped JSON and copy only its `query` value into Log Explorer.
3. Select a narrow time window and confirm the required log source.
4. Review false positives, then widen the time range or tune the threshold.
5. Validate parser and data matches before promoting a saved search or dashboard.

See [Using OCI Log Analytics Queries](LOG_ANALYTICS_QUERY_USAGE.md) for the full workflow.
