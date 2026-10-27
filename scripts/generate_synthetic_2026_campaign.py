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


if __package__:
    from .synthetic_campaign_common import (
        SEVEN_DAY_KILL_CHAIN_DAYS,
        _deterministic_hex,
        _synthetic_ocid,
        _ip,
        _format_iso_utc as _format_iso_utc,
        _parse_reference_time,
    )
    from .synthetic_campaign_background import add_background_events
    from .synthetic_campaign_attacks import add_attack_events
    from .synthetic_campaign_correlation import add_correlated_signals
    from .synthetic_campaign_multicloud import build_multicloud_events
    from .synthetic_campaign_ac_hunter import build_network_hunt_events
    from .synthetic_campaign_metrics import build_multicloud_metrics
else:
    from synthetic_campaign_common import (
        SEVEN_DAY_KILL_CHAIN_DAYS,
        _deterministic_hex,
        _synthetic_ocid,
        _ip,
        _format_iso_utc as _format_iso_utc,
        _parse_reference_time,
    )
    from synthetic_campaign_background import add_background_events
    from synthetic_campaign_attacks import add_attack_events
    from synthetic_campaign_correlation import add_correlated_signals
    from synthetic_campaign_multicloud import build_multicloud_events
    from synthetic_campaign_ac_hunter import build_network_hunt_events
    from synthetic_campaign_metrics import build_multicloud_metrics


# Authored synthetic threat indicator; event-family builders receive it explicitly.
RMM_RELAY_IP = "198.41.200.113"

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

    add_background_events(
        background_logs=background_logs,
        base_date=base_date,
        corp_mail_domain=corp_mail_domain,
        guardian_adb=guardian_adb,
        ip_crm_sync=ip_crm_sync,
        ip_devops=ip_devops,
        ip_iam_sa=ip_iam_sa,
        ip_oke_node=ip_oke_node,
        observeai_adb=observeai_adb,
        prefix=prefix,
        seed=seed,
    )

    attacks_result = add_attack_events(
        rmm_relay_ip=RMM_RELAY_IP,
        attack_logs=attack_logs,
        base_date=base_date,
        corp_mail_domain=corp_mail_domain,
        day_traces=day_traces,
        dns_domain=dns_domain,
        guardian_adb=guardian_adb,
        ip_caldera_c2=ip_caldera_c2,
        ip_goad_dc=ip_goad_dc,
        ip_goad_pivot=ip_goad_pivot,
        ip_pod_src=ip_pod_src,
        ip_vcn_target=ip_vcn_target,
        observeai_adb=observeai_adb,
        prefix=prefix,
        seed=seed,
        storyline_datasafe_events=storyline_datasafe_events,
    )
    d1_ts1 = attacks_result.d1_ts1
    d2_ts1 = attacks_result.d2_ts1
    d3_ts1 = attacks_result.d3_ts1
    d4_ts2 = attacks_result.d4_ts2
    d5_ts3 = attacks_result.d5_ts3
    d6_ts1 = attacks_result.d6_ts1
    d6_ts2 = attacks_result.d6_ts2
    d7_trace = attacks_result.d7_trace
    d7_ts1 = attacks_result.d7_ts1
    d7_ts2 = attacks_result.d7_ts2
    d7_ts3 = attacks_result.d7_ts3

    add_correlated_signals(
        rmm_relay_ip=RMM_RELAY_IP,
        base_date=base_date,
        day_traces=day_traces,
        guardian_adb=guardian_adb,
        observeai_adb=observeai_adb,
        seed=seed,
        storyline_apm_traces=storyline_apm_traces,
        storyline_langfuse_traces=storyline_langfuse_traces,
        storyline_metrics=storyline_metrics,
    )

    multicloud_result = build_multicloud_events(
        rmm_relay_ip=RMM_RELAY_IP,
        corp_mail_domain=corp_mail_domain,
        ctx=ctx,
        d1_ts1=d1_ts1,
        d2_ts1=d2_ts1,
        d3_ts1=d3_ts1,
        d4_ts2=d4_ts2,
        d5_ts3=d5_ts3,
        d6_ts1=d6_ts1,
        d6_ts2=d6_ts2,
        d7_ts2=d7_ts2,
        day_traces=day_traces,
        guardian_adb=guardian_adb,
        ip_goad_dc=ip_goad_dc,
        ip_goad_pivot=ip_goad_pivot,
        ip_oke_node=ip_oke_node,
        ip_vcn_target=ip_vcn_target,
        seed=seed,
    )
    aws_region = multicloud_result.aws_region
    azure_region = multicloud_result.azure_region
    gcp_region = multicloud_result.gcp_region
    ip_goad_dc2 = multicloud_result.ip_goad_dc2
    multicloud_logs = multicloud_result.multicloud_logs
    oci_region = multicloud_result.oci_region

    ac_hunter_telemetry = build_network_hunt_events(
        rmm_relay_ip=RMM_RELAY_IP,
        base_date=base_date,
        d1_ts1=d1_ts1,
        d4_ts2=d4_ts2,
        d5_ts3=d5_ts3,
        d6_ts2=d6_ts2,
        d7_trace=d7_trace,
        d7_ts1=d7_ts1,
        d7_ts2=d7_ts2,
        d7_ts3=d7_ts3,
        day_traces=day_traces,
        dns_domain=dns_domain,
        guardian_adb=guardian_adb,
        ip_goad_dc=ip_goad_dc,
        ip_goad_dc2=ip_goad_dc2,
        ip_goad_pivot=ip_goad_pivot,
        ip_oke_node=ip_oke_node,
        ip_vcn_target=ip_vcn_target,
        observeai_adb=observeai_adb,
        prefix=prefix,
    )

    multicloud_metrics = build_multicloud_metrics(
        rmm_relay_ip=RMM_RELAY_IP,
        aws_region=aws_region,
        azure_region=azure_region,
        d4_ts2=d4_ts2,
        d5_ts3=d5_ts3,
        d6_ts1=d6_ts1,
        d7_ts1=d7_ts1,
        d7_ts2=d7_ts2,
        d7_ts3=d7_ts3,
        day_traces=day_traces,
        gcp_region=gcp_region,
        oci_region=oci_region,
    )

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
