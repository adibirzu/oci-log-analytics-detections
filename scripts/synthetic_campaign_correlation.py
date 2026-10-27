"""Synthetic storyline correlation event family.

Explicit inputs preserve deterministic identities and caller-controlled event order.
"""
from __future__ import annotations

import datetime as dt
from typing import Any

if __package__:
    from .synthetic_campaign_common import (
        SEVEN_DAY_KILL_CHAIN_DAYS,
        _deterministic_hex,
        _format_iso_utc,
    )
else:
    from synthetic_campaign_common import (
        SEVEN_DAY_KILL_CHAIN_DAYS,
        _deterministic_hex,
        _format_iso_utc,
    )


def add_correlated_signals(
    *,
    rmm_relay_ip: str,
    base_date: dt.date,
    day_traces: dict[int, str],
    guardian_adb: str,
    observeai_adb: str,
    seed: str,
    storyline_apm_traces: list[dict[str, Any]],
    storyline_langfuse_traces: list[dict[str, Any]],
    storyline_metrics: list[dict[str, Any]],
) -> None:
    """Emit this event family using the supplied identities and timeline."""
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
                f"Isolated GOAD AD hosts kingslanding, winterfell, castelblack from C2 198.51.100.214 and RMM relay {rmm_relay_ip}",
                f"Applied Oracle Data Safe masking policy and revoked compromised CRM_APP session on {guardian_adb} & {observeai_adb}",
                f"Blocked 198.51.100.214/32 and {rmm_relay_ip}/32 across OCI WAF/NSG, AWS Security Groups, Azure NSG, and GCP Cloud Armor",
            ],
        },
        "spans": langfuse_spans,
    })
