# OCI Log Analytics Detection Rules & Forge — Handover & Architecture Continuity Document

> **Audience**: AI Agents (Codex, Claude, Gemini, Copilot) and Human Platform Engineers.
> **Security & Portability Rule**: Zero raw OCIDs, real public IPs, tenancy namespaces, or credentials. Use standard placeholders (`<DNS_DOMAIN>`, `<TENANCY_OCID>`).

---

## 2026-10-27 — local ORM package closure repair

The [deployment package contract](docs/DEPLOYMENT.md#package-source-inventory-and-executable-closure)
owns selected-byte inventories, extracted entrypoint behavior, Git-free staging,
local verification and archive-scan triage. These are local source/package
receipts; provider, image, OCI-DEMO admission and release acceptance remain open.

## 1. Overview & Architectural Role

**OCI Log Analytics Detection Rules & Logan Forge** is the canonical detection-content, threat hunting query, and query translation repository for Oracle Cloud Infrastructure (OCI) Log Analytics. It compiles industry-standard Sigma rules and Microsoft Sentinel detections into OCI Log Analytics Query Language (OCL), and provides Logan Forge, an interactive webapp for QL translation and dashboard deployment.

- **Primary URLs**:
  - Forge Webapp: `https://forge.<DNS_DOMAIN>`
  - Static Detection Catalog: `https://obs.<DNS_DOMAIN>`
- **Runtime Target**: OKE Cluster (`observeai-dedicated-oke`), namespace `octodemo-apps`
- **Authentication**: OCI Identity Domains (IDCS) Single Sign-On (OIDC)

---

## 2. Newly Integrated Capabilities

### 2.1 1,400+ Sigma & Sentinel Detection Rules
- 545 top-level OCI Log Analytics detections in `queries/*.json`.
- 590 Microsoft Sentinel converted detections in `queries/sentinel/*.json`.
- 225 curated analytics (54 application telemetry analytics, 171 hunting analytics).

### 2.2 2026 Threat Hunting Reports & 7-Day Multi-Pillar Storyline
- Trellix SecondSight (Sept 2026) detection suite (`TRELLIX-2026-01..05`).
- CrowdStrike 2026 OverWatch behavioral detections (`CS-OVERWATCH-2026-01..04`).
- Hunt.io PEAK hunting playbooks (`PEAK-HUNT-2026-01..04`).
- 7-Day Multi-Pillar Threat Hunting Storyline (`STORYLINE-DAY-01..07`) correlating telemetry across Caldera, Active Directory, VCN flow logs, and Oracle Data Safe.

### 2.3 AC-Hunter Network Threat Hunting Pack
Located in `packs/ac_hunter_network_hunting/`:
- Brings Active Countermeasures (AC-Hunter / RITA) network behavioral threat hunting to OCI Log Analytics over VCN flow logs and proxy logs:
  1. `ac_hunter_01_c2_beaconing_rita_score.json`: Interval delta variance and duration variance scoring.
  2. `ac_hunter_02_long_connections_duration.json`: Long-lived low-throughput persistence connections (>3,600s).
  3. `ac_hunter_03_dns_beaconing_fqdn_entropy.json`: Shannon entropy analysis on queried domain names.
  4. `ac_hunter_04_client_signatures_ja3_user_agent.json`: Unusual JA3 hashes and client signature mismatches.
  5. `ac_hunter_05_strobe_port_scan_vcn_sweep.json`: Rapid horizontal subnet sweeps on sensitive ports.
  6. `ac_hunter_06_non_standard_port_protocol_mismatch.json`: TLS on non-standard ports (8080, 4444).
  7. `ac_hunter_07_threat_intel_safelist_correlation.json`: Egress traffic to malicious IPs with dynamic safelisting.
  8. `ac_hunter_08_multicloud_cross_csp_correlation.json`: Lateral movement between OCI VCN and external CSPs.
- **Unified Dashboard**: `dashboards/ac_hunter_and_multicloud_logan_dashboard.json`.

### 2.4 Logan Forge Web Application (`webapp/`)
- Webapp providing cross-QL translation (Sigma/Sentinel to OCL), log parsing simulation, and Resource Manager stack export.
- Deployed natively on OKE (`forge.<DNS_DOMAIN>`).

---

## 3. Kubernetes Deployment & ConfigMap Layout on OKE

### 3.1 Cluster Environment
- **Cluster**: `observeai-dedicated-oke` (Enhanced cluster, Kubernetes `v1.34.10`)
- **Namespace**: `octodemo-apps`
- **Service Name**: `logan-forge` (port 8080)
- **Cluster-Local URL**: `http://logan-forge.octodemo-apps.svc.cluster.local:8080`

### 3.2 Ingress Configuration
- Protected by OCI Ingress Load Balancer with IDCS SSO integration.

---

## 4. Verification & CLI Commands

```bash
# Validate query schemas and metadata:
python3 scripts/validate_rules.py

# Run detection and hunting test suite:
pytest tests/ -q

# Check AC-Hunter pack manifest:
python3 -c "import json; m = json.load(open('packs/ac_hunter_network_hunting/manifest.json')); print('AC-Hunter queries:', len(m['queries']))"

# Deploy AC-Hunter & Multi-Cloud Dashboard to OCI Log Analytics (dry-run):
python3 scripts/deploy_dashboard.py --dashboard dashboards/ac_hunter_and_multicloud_logan_dashboard.json --dry-run
```

---

## 5. Next Steps for Multi-Cloud Expansion

1. **Cross-CSP Flow Ingestion**: Pipe AWS VPC Flow Logs and Azure NSG Flow Logs through `multicloudoperations` to validate `ac_hunter_08_multicloud_cross_csp_correlation.json`.
2. **Sentinel Bi-Directional Sync**: Implement bi-directional sync converting newly created OCL queries back into Microsoft Sentinel KQL rule format.
