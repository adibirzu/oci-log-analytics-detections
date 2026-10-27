"""Shared deterministic identities, timestamps and chronological storyline metadata."""
from __future__ import annotations

import datetime as dt
import hashlib


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
