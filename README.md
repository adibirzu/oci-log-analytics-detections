# OCI Log Analytics Detection Rules

A comprehensive STIG-compliant detection rules library for Oracle Cloud Infrastructure (OCI) Log Analytics. Converts industry-standard [Sigma](https://github.com/SigmaHQ/sigma) rules into OCI Log Analytics Query Language (OCL) with MITRE ATT&CK and STIG compliance mapping. Enhanced with advanced threat hunting queries inspired by the Threat Hunter's Cookbook.

## Current Status
- **Total Rules:** 387 Sigma detection rules + 20 advanced hunting queries
- **Categories:** Windows Security (220), Cloud/OCI (100), Linux Security (67)
- **Hunting Queries:** 20 analytics-based queries (frequency analysis, anomaly detection, scoring)
- **STIG Coverage:** 22 rules with DoD STIG control mappings (IA-2, IA-5, SC-7, SC-28, AU-11, AC-17, etc.)
- **MITRE ATT&CK:** 90 techniques across 12 tactics (full MITRE coverage)
- **Deployed:** 153 saved searches across 7 dashboards
- **Test Data:** 644 attack simulation events across 4 NDJSON files

## OCI Log Analytics Dashboards
| Dashboard | Widgets | Purpose |
| :--- | :--- | :--- |
| SOC Overview Dashboard | 12 | Executive-level cross-domain security summary + key hunting alerts |
| **SOC: OCI STIG Compliance** | **17** | **STIG compliance: MFA, key rotation, vault secrets, audit config, identity** |
| SOC: OCI Audit Security | 22 | IAM, network, compute, storage, KMS, DB, bastion, log groups, discovery |
| SOC: Cloud Guard Security | 12 | Cloud Guard problem detection |
| SOC: Linux Security | 38 | SSH, sudo, persistence, webshells, cryptominers, scanning, exfiltration, C2 |
| SOC: Windows Security | 37 | Credential theft, lateral movement, discovery, phishing, keyloggers, RATs |
| **SOC: Threat Hunting** | **15** | **Cookbook-inspired analytics: frequency, anomaly, scoring, multi-stage** |

## Threat Hunting Dashboard (Cookbook-Enhanced)

Advanced hunting queries using OCL analytics operators (`| stats`, `| eval`, `| sort`, `| where`), inspired by the Threat Hunter's Cookbook methodologies:

| Hunting Query | Method | What It Finds |
| :--- | :--- | :--- |
| SSH Brute Force Detection | Frequency Analysis | IPs with >5 failed SSH logins |
| OCI Console Brute Force | Frequency Analysis | Users with >3 failed OCI login attempts |
| Windows Rare Process Detection | Rare Value Stacking | Processes seen fewer than 3 times |
| Linux Rare Process Detection | Rare Value Stacking | Rarely-seen Linux processes |
| Suspiciously Long Command Line | Field Analysis | Commands >500 chars (encoded payloads) |
| OCI IAM Rapid Changes | Anomaly Detection | Users making >10 IAM changes quickly |
| Lateral Movement Tool Cluster | Grouping | Hosts with multiple lateral movement tools |
| Linux Multi-Stage Attack | Combined Methods | Hosts with 3+ attack stage indicators |
| OCI Resource Destruction Spike | Anomaly Detection | Users performing >5 delete/terminate ops |
| Credential Access Tool Cluster | Grouping | Hosts with multiple credential theft techniques |
| Multiple Users from Same IP | Grouping | IPs authenticating as 3+ different users |
| Linux Persistence Score | Combined Scoring | Hosts with 3+ persistence mechanisms |
| Process from Unusual Path | Rare Value Analysis | Executables from Temp/Downloads/Public |
| After-Hours IAM Activity | Time-Based Anomaly | IAM changes outside 06:00-22:00 UTC |
| Defense Evasion Score | Combined Scoring | Hosts with multiple evasion techniques |

## New Detection Rules (v2.0)

### OCI STIG Compliance (15 rules)
| Rule | STIG Control | Severity |
| :--- | :--- | :--- |
| MFA Disabled | IA-2 | high |
| Identity Provider Created (Federation) | IA-8 | high |
| Dynamic Group Created | AC-6 | medium |
| Auth Token Created | IA-5 | medium |
| Compartment Deleted | AC-6 | critical |
| Cloud Shell Session Started | AU-12 | low |
| Security List All Protocols | SC-7 | high |
| Vault Key Rotation | SC-12 | medium |
| Function Invoked | AU-12 | low |
| Cross-Region Data Copy | SC-28 | high |
| DB System Terminated | CP-9 | critical |
| Audit Config Changed | AU-11 | high |
| Network Firewall Modified | SC-7 | high |
| VCN Peering Created | SC-7 | medium |
| Pre-Authenticated Request Created | AC-3 | high |
| Vault Secret Deleted | SC-28 | high |
| User Password Reset by Admin | IA-5 | high |
| Bastion Session Created | AC-17 | medium |
| Instance Console Connection | AC-17 | high |
| Notification Subscription Created | AU-12 | medium |
| Log Group Deleted | AU-11 | critical |
| Customer Secret Key Created | IA-5 | high |

### Advanced Linux Attacks (23 rules)
| Rule | MITRE Technique | Severity |
| :--- | :--- | :--- |
| Container Escape Attempt | T1611 | critical |
| LD_PRELOAD Library Hijacking | T1574.006 | high |
| Kernel Module from Temp Dir | T1547.006 | critical |
| Password File Direct Modification | T1136.001 | critical |
| Process Injection via Ptrace | T1055.008 | high |
| Suspicious Network Redirect | T1557 | high |
| Systemd Service Persistence | T1543.002 | medium |
| SSH Tunneling Detected | T1572 | high |
| Suspicious Download to /tmp | T1105 | high |
| Process Execution from /dev/shm | T1059 | critical |
| Sudoers File Modification | T1548.003 | high |
| Shell Profile Persistence | T1546.004 | medium |
| At Job Scheduled | T1053.002 | medium |
| DNS Tunneling Detected | T1071.004 | high |
| Hosts File Modification | T1565.001 | medium |
| Process Memory Access via /proc | T1003.007 | high |
| Web Shell File Creation | T1505.003 | critical |
| Cryptominer Activity Detected | T1496 | high |
| Log File Tampering | T1070.002 | high |
| Post-Exploitation Enumeration Script | T1082 | high |
| Bind Shell Listener | T1059.004 | critical |
| Suspicious Cron Job Content | T1053.003 | high |
| Hidden File/Dir in Suspicious Location | T1564.001 | medium |

### Advanced Windows Attacks (22 rules)
| Rule | MITRE Technique | Severity |
| :--- | :--- | :--- |
| Shadow Copy Deletion (Ransomware) | T1490 | critical |
| AMSI Bypass Attempt | T1562.001 | high |
| WMI Event Subscription Persistence | T1546.003 | high |
| Registry Run Key Modification | T1547.001 | high |
| DLL Side-Loading via Suspicious Path | T1574.002 | high |
| Boot Configuration Modified (Ransomware) | T1490 | critical |
| Mimikatz Execution Patterns | T1003.001 | critical |
| Firewall Rule Modification | T1562.004 | high |
| RDP Lateral Movement | T1021.001 | medium |
| Scheduled Task Creation (schtasks) | T1053.005 | medium |
| PowerShell Download Cradle | T1059.001 | high |
| LSASS Memory Access | T1003.001 | critical |
| Event Log Clearing | T1070.001 | high |
| PsExec Remote Execution | T1021.002 | high |
| UAC Bypass Attempt | T1548.002 | high |
| Kerberoasting Attack | T1558.003 | critical |
| BITS Job Persistence | T1197 | high |
| MSBuild Code Execution Bypass | T1127.001 | medium |
| Pass-the-Hash Indicators | T1550.002 | critical |
| Process Hollowing Indicators | T1055.012 | critical |
| WDigest Credential Harvesting | T1003.001 | high |
| NTDS.dit Database Extraction | T1003.003 | critical |

### Web Application Attack Detection (4 rules)
| Rule | Platform | MITRE Technique | Severity |
| :--- | :--- | :--- | :--- |
| SSRF to Cloud Metadata Endpoint (169.254.169.254) | Windows | T1552.005, T1190 | critical |
| Web Server Process Spawning Command Shell | Windows | T1059, T1190 | critical |
| SSRF to Cloud Instance Metadata Service | Linux | T1552.005, T1190 | critical |
| Web Server Process Spawning Shell with Injection Characters | Linux | T1059, T1190 | critical |

### MITRE ATT&CK Expansion (20 rules)
| Rule | Tactic | MITRE Technique | Severity |
| :--- | :--- | :--- | :--- |
| Cloud Infrastructure Discovery | Discovery | T1580 | medium |
| Network Service Scanning | Discovery | T1046 | medium |
| System Owner/User Discovery | Discovery | T1033 | low |
| Account Discovery Commands | Discovery | T1087.001, T1087.002 | medium |
| Network Share Discovery | Discovery | T1135 | medium |
| Remote System Discovery | Discovery | T1018 | medium |
| Password Spraying Attack | Initial Access | T1110.003 | high |
| External Remote Service Abuse | Initial Access | T1133 | medium |
| Spearphishing Attachment Execution | Initial Access | T1566.001 | high |
| Exfiltration Over Alt Protocol | Exfiltration | T1048 | high |
| Archive Collected Data | Exfiltration | T1560.001 | medium |
| Data Staging for Exfiltration | Exfiltration | T1074.001 | medium |
| Sensitive Data Collection | Collection | T1005 | medium |
| Keylogger Indicators | Collection | T1056.001 | high |
| Screen Capture Activity | Collection | T1113 | medium |
| Remote Access Tool Detected | Command & Control | T1219 | high |
| Proxy/Tunneling Tool | Command & Control | T1090 | high |
| Encrypted Channel C2 | Command & Control | T1573 | high |
| SUID Binary Creation | Privilege Escalation | T1548.001 | high |
| Access Token Manipulation | Privilege Escalation | T1134 | high |

## Project Structure

```
rules/                          # Source detection rules (Sigma YAML)
  cloud/oci/                    # 100 OCI rules (STIG + security + discovery)
    audit_events/               # 50 audit action tracking rules
    cloud_guard/                # 12 Cloud Guard problem rules
  linux/                        # 67 Linux rules (advanced attacks + hunting)
    suspicious_binaries/        # 27 suspicious binary detection rules
  windows/                      # 220 Windows rules (13 subdirectories)
    process_creation/           # 56 process creation rules
    defense_evasion/            # 29 defense evasion rules
    credential_access/          # 25 credential access rules
    persistence/                # 24 persistence rules
    execution/                  # 19 execution rules
    privilege_escalation/       # 14 privilege escalation rules
    network_connection/         # 11 network connection rules
    lateral_movement/           # 10 lateral movement rules
    impact/                     # 10 impact rules
    discovery/                  # 10 discovery rules
    collection/                 # 5 collection rules
    pipe_created/               # 4 pipe created rules
    dns_query/                  # 3 DNS query rules
queries/                        # Generated OCL queries (JSON)
  hunting/                      # 20 advanced hunting queries (cookbook-inspired)
  manifest.json                 # Cross-project integration manifest
config/
  sigma_oci_mapping.yaml        # Field & log source mappings
scripts/
  oci_config.py                 # Centralized config, client factories, validation
  convert_sigma.py              # Sigma -> OCL converter (with STIG metadata)
  deploy_dashboard.py           # OCI LA dashboard deployment (7 dashboards)
  generate_test_logs.py         # Attack simulation data (644 events)
  ingest_test_data.py           # Upload test data to OCI LA
  setup_log_sources.py          # Create custom OCI LA log sources
  setup_streaming_pipeline.py   # Production OCI Streaming pipeline
  export_for_multicloud.py      # Integration with multicloudoperations
test_data/                      # Generated NDJSON test logs
stack/                          # OCI Resource Manager (Terraform) stack
  schema.yaml                   # ORM variable UI definition
  variables.tf                  # Input variables
  provider.tf                   # OCI provider (ORM auto-injects auth)
  main.tf                       # Data sources (compartment, LA namespace)
  iam.tf                        # IAM policies for Service Connector Hub
  log_analytics.tf              # Log Analytics log group
  streaming.tf                  # 4 OCI Streaming streams
  service_connector.tf          # 4 SCH connectors (stream → LA)
  provisioners.tf               # null_resource calling Python scripts
  outputs.tf                    # Resource OCIDs and endpoints
  build_stack.sh                # Builds ORM-uploadable zip
```

## Deployment

### Option 1: OCI Resource Manager (One-Click)

Deploy the full SOC detection stack through ORM's web UI:

1. Build the stack zip:
   ```bash
   bash stack/build_stack.sh
   ```
2. In the OCI Console, go to **Resource Manager > Stacks > Create Stack**.
3. Upload `soc-detection-stack.zip`.
4. Fill in the form (compartment, log group name, toggle log sources/dashboards).
5. Click **Plan**, then **Apply**.

The stack creates: 1 Log Analytics log group, 4 streams, 4 Service Connector Hub pipelines, IAM policies, and optionally deploys log sources, dashboards, and test data via Python provisioners.

### Option 2: Terraform CLI

```bash
cd stack
terraform init
terraform plan -var="compartment_id=ocid1.compartment..." -var="tenancy_ocid=ocid1.tenancy..." -var="region=us-ashburn-1"
terraform apply
```

### Option 3: Manual (Scripts)

```bash
cp .env.local.example .env.local
# Edit .env.local with your OCI tenancy and compartment OCIDs
```

Configuration is resolved in priority order:
1. **Environment variables** (`OCI_TENANCY_ID`, `OCI_COMPARTMENT_ID`, `OCI_PROFILE`, `OCI_REGION`)
2. **`.env.local`** file in project root (git-ignored)
3. **Hardcoded defaults** in `scripts/oci_config.py`

### Pre-flight Validation
All deployment scripts support `--validate` to check configuration before making API calls:
```bash
python3 scripts/deploy_dashboard.py --validate   # Check OCIDs, CLI config, namespace, queries
python3 scripts/ingest_test_data.py --validate   # Check OCIDs, CLI config, namespace, test data
python3 scripts/setup_log_sources.py --validate  # Check OCIDs, CLI config, namespace, compartment
```

## Usage

### Generating Queries
```bash
python3 scripts/convert_sigma.py                # Convert all 387 rules
python3 scripts/convert_sigma.py --validate     # Validate OCL syntax
python3 scripts/convert_sigma.py --stats        # Print rule statistics
```

### Testing Rules with Attack Simulation
```bash
python3 scripts/generate_test_logs.py    # Generate 644 NDJSON events in test_data/
python3 scripts/ingest_test_data.py      # Upload to Log Analytics (direct mode)
python3 scripts/deploy_dashboard.py      # Deploy 7 dashboards + 153 saved searches
python3 scripts/deploy_dashboard.py --cleanup  # Clean up old content and redeploy
```

### Integration with MultiCloud Operations
```bash
python3 scripts/export_for_multicloud.py                 # Export to ~/dev/multicloudoperations
python3 scripts/export_for_multicloud.py --manifest-only  # Generate manifest only
python3 scripts/export_for_multicloud.py --dry-run        # Print plan
```

### JSON Query Schema (Enhanced)
Each generated query includes STIG and MITRE metadata:
```json
{
  "title": "OCI Cross-Region Data Copy",
  "description": "Detects cross-region copy operations...",
  "query": "'Log Source' = 'OCI Audit Logs' and (...)",
  "sigma_id": "d1a2b3c4-1010-4000-8000-000000000010",
  "level": "high",
  "stig_category": "CAT I",
  "tags": ["attack.exfiltration", "attack.t1537", "stig.SC-28"],
  "mitre_attack": {"tactics": ["exfiltration"], "techniques": ["T1537"]},
  "logsource": {"product": "oci", "service": "audit"},
  "stig_ids": ["SC-28"]
}
```

### Hunting Query Schema
Hunting queries include cookbook methodology metadata:
```json
{
  "title": "SSH Brute Force Detection (Frequency Analysis)",
  "description": "Identifies SSH brute force attacks...",
  "query": "'Log Source' = '...' and ... | stats count as failed_attempts by 'Client Host' | sort -failed_attempts | where failed_attempts > 5",
  "hunting_type": "frequency_analysis",
  "cookbook_method": "sorting_stacking",
  "level": "high",
  "mitre_attack": {"tactics": ["initial_access"], "techniques": ["T1110.001"]}
}
```

## Adding New Rules
1. Create a new YAML file in the appropriate `rules/` subdirectory.
2. Follow the Sigma specification. Add `stig.*` and `compliance.*` tags for STIG rules.
3. Run `python3 scripts/convert_sigma.py --validate --stats`.
4. Run `python3 scripts/generate_test_logs.py` (add test events for the new rule).
5. Run `python3 scripts/deploy_dashboard.py --dry-run` to verify dashboard plan.

## Adding Hunting Queries
1. Create a JSON file in `queries/hunting/` with the hunting query schema.
2. Use OCL pipe operators (`| stats`, `| eval`, `| sort`, `| where`) for analytics.
3. Add the query file reference to the Threat Hunting Dashboard in `deploy_dashboard.py`.
4. Add high-volume test events to `generate_test_logs.py` for aggregation testing.
